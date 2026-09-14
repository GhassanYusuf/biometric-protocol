<?php

/*
 * This file is part of promoseven/biometric-protocol.
 *
 * Copyright (c) 2026 Promoseven. All rights reserved.
 *
 * Proprietary and confidential. Not open source. No licence to use, copy,
 * modify or distribute this file is granted except under a signed written
 * agreement with the copyright holder. See LICENSE.
 */

namespace Promoseven\Biometric\Service;

use Promoseven\Biometric\Client\DeviceClient;
use Promoseven\Biometric\Codec\UserCodec;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Value\EnrollmentResult;

/**
 * Live capture at the terminal: fingerprint and card.
 *
 * These are the only operations in the library that block on a HUMAN. The device
 * is put into capture mode and then pushes realtime events while somebody presses
 * a finger or taps a card. Nothing here returns quickly, and a host app should run
 * it on a queue rather than in a request.
 *
 * Both flows beep the device the moment the trigger lands. That is not decoration:
 * without it, a person standing at the terminal has no signal that the system is
 * waiting for them, and the capture times out for no visible reason.
 */
final class EnrollmentService
{
    public const DEFAULT_FINGER_TIMEOUT = 30;
    public const DEFAULT_CARD_TIMEOUT = 20;

    /** Card slot number used by the vendor SDK's StartEnroll for card capture. */
    private const CARD_ENROLL_SLOT = 11;

    public function __construct(private readonly DeviceClient $client)
    {
    }

    /**
     * Captures one fingerprint into a specific slot.
     *
     * The device must already hold a record for this user — a template attaches to
     * an existing user, it does not create one. Callers should ensure that first
     * (see UserService::ensureExists).
     *
     * Progress events are reported through $onProgress AND collected into the
     * result, so a queued job can persist them as an audit trail.
     *
     * @param \Closure(string):void|null $onProgress
     */
    public function captureFingerprint(
        string $userId,
        int $fingerIndex,
        ?\Closure $onProgress = null,
        int $timeoutSeconds = self::DEFAULT_FINGER_TIMEOUT,
    ): EnrollmentResult {
        if ($fingerIndex < 0 || $fingerIndex > 9) {
            throw new \InvalidArgumentException("Finger slot must be 0-9, got {$fingerIndex}.");
        }

        $events = [];
        $report = function (string $status) use (&$events, $onProgress): void {
            $events[] = $status;
            if ($onProgress !== null) {
                $onProgress($status);
            }
        };

        // Audible confirmation that the trigger actually reached the device.
        $this->client->beep();
        $report('beeped');

        // Stop normal verification mode so the enroll sequence can take over.
        $this->client->send(Command::CANCEL_CAPTURE);

        // Subscribe to realtime events: finger placed, sample score, final result.
        $this->client->send(Command::REG_EVENT, pack('V', Command::EF_ALL));

        $reply = $this->client->send(
            Command::START_ENROLL,
            Packet::buildEnrollRequest($userId, $fingerIndex),
        );

        if ($reply->command !== Command::ACK_OK) {
            throw new ProtocolException("Device refused to start enrollment ({$reply->commandName()}).", [
                'user_id' => $userId,
                'slot' => $fingerIndex,
            ]);
        }

        $report('waiting_for_finger');

        $reply = $this->client->send(Command::START_VERIFY);

        if ($reply->command !== Command::ACK_OK) {
            throw new ProtocolException("Device refused to enter capture mode ({$reply->commandName()}).");
        }

        return $this->awaitFingerprint($fingerIndex, $timeoutSeconds, $report, $events);
    }

    /**
     * Waits for the device's realtime enrollment events.
     *
     * Payload sizes carry the meaning here (CONFIRMED against hardware):
     *   0 bytes    a finger was placed — one sample taken
     *   <=4 bytes  a sample quality score
     *   >4 bytes   the final result: result(2) + fp size(2) + user id(9) + slot(1)
     *
     * @param \Closure(string):void $report
     * @param list<string>          $events
     */
    private function awaitFingerprint(
        int $fingerIndex,
        int $timeoutSeconds,
        \Closure $report,
        array &$events,
    ): EnrollmentResult {
        $deadline = microtime(true) + $timeoutSeconds;
        $samples = 0;

        while (microtime(true) < $deadline) {
            $data = $this->client->readRealtimeRaw(0.5);

            if ($data === null) {
                usleep(200_000);
                continue;
            }

            $length = strlen($data);

            if ($length === 0) {
                $samples++;
                $report("finger_placed_sample_{$samples}");
                continue;
            }

            if ($length <= 4) {
                $score = unpack('V', str_pad($data, 4, "\0"))[1];
                $report("sample_score_{$score}");
                continue;
            }

            $result = unpack('v', substr($data, 0, 2))[1];

            if ($result === 0) {
                $report('enrolled');

                return EnrollmentResult::fingerprint($fingerIndex, $events);
            }

            $report("enroll_failed_code_{$result}");

            return EnrollmentResult::rejected($result, $events);
        }

        $report('timeout');

        // A timeout is an OUTCOME, not a transport fault — nobody came to the
        // terminal. Callers distinguish it from a device error via the result.
        return EnrollmentResult::timeout($events);
    }

    /**
     * Captures the next card tapped and writes it onto the user's record.
     *
     * EXPERIMENTAL card-number parsing. Unlike fingerprint enrollment there is no
     * cross-vendor documented command for reading a raw card id, so the number is
     * a best-effort read of the realtime payload — first 4 bytes as a
     * little-endian uint32, the same width and order the card field uses on a user
     * record. If a written card number ever looks wrong, THIS is the parsing to
     * revisit.
     *
     * @param \Closure(string):void|null $onProgress
     */
    public function captureCard(
        int $uid,
        string $userId,
        string $name,
        int $privilege = 0,
        ?\Closure $onProgress = null,
        int $timeoutSeconds = self::DEFAULT_CARD_TIMEOUT,
    ): EnrollmentResult {
        $events = [];
        $report = function (string $status) use (&$events, $onProgress): void {
            $events[] = $status;
            if ($onProgress !== null) {
                $onProgress($status);
            }
        };

        $this->client->beep();
        $report('beeped');

        $this->client->send(Command::CANCEL_CAPTURE);
        $this->client->send(Command::REG_EVENT, pack('V', Command::EF_ALL));

        /*
         * START_ENROLL/START_VERIFY is what puts the device's own screen into a
         * prompt for fingerprints. There is no documented equivalent for cards, but
         * the vendor SDK's StartEnroll uses slots 0-9 for fingers and higher values
         * for other enrollment types (card is commonly 11). Try it in case this
         * firmware switches to a card prompt; if it refuses, that is fine — we
         * listen for the card either way.
         */
        try {
            $reply = $this->client->send(
                Command::START_ENROLL,
                Packet::buildEnrollRequest($userId, self::CARD_ENROLL_SLOT),
            );

            if ($reply->command === Command::ACK_OK) {
                $this->client->send(Command::START_VERIFY);
                $report('card_prompt_shown');
            }
        } catch (ProtocolException) {
            // Firmware did not accept the card-slot enroll attempt — proceed anyway.
            $report('card_prompt_unsupported');
        }

        $report('waiting_for_card');

        $deadline = microtime(true) + $timeoutSeconds;

        while (microtime(true) < $deadline) {
            $data = $this->client->readRealtimeRaw(0.5);

            if ($data === null || strlen($data) < 4) {
                usleep(200_000);
                continue;
            }

            $cardNumber = unpack('V', substr($data, 0, 4))[1];
            $report('card_detected');

            // Write it onto the EXISTING record, preserving name and privilege.
            $this->client->writeUser($uid, $userId, $name, $privilege, $cardNumber);

            // A second beep confirms the whole operation completed, not just the trigger.
            $this->client->beep();
            $report('enrolled');

            return EnrollmentResult::card($cardNumber, $events);
        }

        $report('timeout');

        return EnrollmentResult::timeout($events);
    }

    /** Cancels an in-progress capture, releasing the terminal for normal use. */
    public function cancel(): void
    {
        $this->client->send(Command::CANCEL_CAPTURE);
        $this->client->enableDevice();
    }

    /**
     * Clears the card on a user's record by rewriting it with card 0.
     *
     * There is no "delete card" command: the card is ONE field on the user record,
     * so removing it means rewriting that record. The uid is reused deliberately —
     * a new uid would orphan the user's fingerprint templates, which are keyed by
     * uid in a separate table.
     */
    public function clearCard(int $uid, string $userId, string $name, int $privilege = 0): void
    {
        $this->client->writeUser($uid, $userId, $name, $privilege, 0);
    }

    /** Convenience: resolve the user then capture a card for them. */
    public function captureCardForUser(
        string $userId,
        ?\Closure $onProgress = null,
        int $timeoutSeconds = self::DEFAULT_CARD_TIMEOUT,
    ): EnrollmentResult {
        $user = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($user === null) {
            throw new ProtocolException("User {$userId} is not on the device.", ['user_id' => $userId]);
        }

        return $this->captureCard(
            (int) $user['uid'],
            $userId,
            (string) ($user['name'] ?? ''),
            (int) ($user['privilege'] ?? 0),
            $onProgress,
            $timeoutSeconds,
        );
    }
}
