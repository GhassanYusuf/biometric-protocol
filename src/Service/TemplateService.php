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
use Promoseven\Biometric\Codec\TemplateCodec;
use Promoseven\Biometric\Codec\UserCodec;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\UnsupportedCommandException;
use Promoseven\Biometric\Exception\VerificationException;

/**
 * Fingerprint templates on the device.
 *
 * WHAT IS AND IS NOT SUPPORTED HERE — read this before relying on it.
 *
 *  READ WHICH SLOTS ARE FILLED     CONFIRMED on real hardware.
 *  DELETE ONE SLOT                 EXPERIMENTAL. Command and guard rails verified,
 *                                  but a successful delete was never observed —
 *                                  destroying a real person's finger was not an
 *                                  acceptable test.
 *  DOWNLOAD TEMPLATE BYTES         NOT IMPLEMENTED. See downloadTemplate().
 *  UPLOAD TEMPLATE BYTES           NOT IMPLEMENTED. See uploadTemplate().
 *
 * The consequence for a host app: biometric enrollment is DEVICE-SIDE. A finger
 * must be presented at a terminal; templates cannot currently be copied from one
 * device to another through this library. Architecture is ready for it (the
 * methods exist and throw a typed exception), so adding it later does not change
 * any caller's shape. See docs/device-capabilities.md.
 */
final class TemplateService
{
    public function __construct(private readonly DeviceClient $client)
    {
    }

    /**
     * Which finger slots each user has a template in, keyed by device user id.
     *
     * An EMPTY ARRAY means UNKNOWN — the table could not be decoded — and must
     * never be read as "nobody has fingerprints". A user present in the map with an
     * empty list genuinely has none.
     *
     * @return array<string,list<int>>
     */
    public function slotsByUserId(): array
    {
        $users = UserCodec::decode($this->client->readUsersRaw());

        return TemplateCodec::slotsByUserId(
            TemplateCodec::decode($this->client->readTemplatesRaw()),
            $users,
        );
    }

    /**
     * Filled slots for one user, or null when the table could not be decoded.
     *
     * @return list<int>|null
     */
    public function slotsFor(string $userId): ?array
    {
        $map = $this->slotsByUserId();

        if ($map === []) {
            return null; // unknown
        }

        return $map[$userId] ?? [];
    }

    /** Template count per user id. Null values mean unknown. */
    public function countsByUserId(): array
    {
        $map = $this->slotsByUserId();

        return array_map(static fn (array $slots) => count($slots), $map);
    }

    /**
     * Whether ONE slot holds a template, asked directly rather than inferred.
     *
     * CONFIRMED: answers PREPARE_DATA with the template's byte size when filled,
     * error 4993 when empty. This is the independent check that validated the bulk
     * table decoder — use it when a single authoritative answer matters more than
     * the cost of a round trip.
     */
    public function slotIsFilled(int $uid, int $fingerIndex): bool
    {
        return $this->client->probeTemplateSlot($uid, $fingerIndex)['exists'];
    }

    /**
     * Deletes one template, keeping the user and their other fingers.
     *
     * EXPERIMENTAL — see the class docblock.
     *
     * Reads the table BEFORE and AFTER: before, to refuse a delete we cannot verify
     * and to detect a slot that was never filled; after, to confirm the finger is
     * actually gone rather than trusting the acknowledgement. Refusing when the
     * table is unreadable is deliberate — a silent no-op on biometric data is worse
     * than an error.
     *
     * @return list<int> the user's remaining slots, confirmed by re-read
     */
    public function deleteSlot(string $userId, int $fingerIndex): array
    {
        if ($fingerIndex < 0 || $fingerIndex > 9) {
            throw new \InvalidArgumentException("Finger slot must be 0-9, got {$fingerIndex}.");
        }

        $users = UserCodec::decode($this->client->readUsersRaw());
        $user = UserCodec::find($users, $userId);

        if ($user === null) {
            throw new ProtocolException("User {$userId} is not on the device.", ['user_id' => $userId]);
        }

        $before = TemplateCodec::slotsByUserId(
            TemplateCodec::decode($this->client->readTemplatesRaw()),
            $users,
        );

        if ($before === []) {
            throw new UnsupportedCommandException(
                "This firmware's fingerprint table could not be read, so a delete cannot be verified.",
                ['user_id' => $userId, 'slot' => $fingerIndex],
            );
        }

        $beforeSlots = $before[$userId] ?? [];

        if (! in_array($fingerIndex, $beforeSlots, true)) {
            throw new ProtocolException(
                "Slot {$fingerIndex} is not enrolled for {$userId}, so there is nothing to delete.",
                ['user_id' => $userId, 'slot' => $fingerIndex, 'enrolled' => $beforeSlots],
            );
        }

        $this->client->deleteTemplate((int) $user['uid'], $fingerIndex);

        $after = TemplateCodec::slotsByUserId(
            TemplateCodec::decode($this->client->readTemplatesRaw()),
            UserCodec::decode($this->client->readUsersRaw()),
        );

        if ($after === []) {
            throw new VerificationException(
                'The delete was sent but the fingerprint table could not be re-read to confirm it.',
                ['user_id' => $userId, 'slot' => $fingerIndex],
            );
        }

        $afterSlots = $after[$userId] ?? [];

        if (in_array($fingerIndex, $afterSlots, true)) {
            throw new VerificationException(
                "The device still reports slot {$fingerIndex} as enrolled after the delete.",
                ['user_id' => $userId, 'slot' => $fingerIndex],
            );
        }

        return $afterSlots;
    }

    /**
     * Raw template table bytes, for archiving or calibrating a decoder.
     *
     * This is how the 22,066-byte fixture in tests/Fixtures was captured. Keep a
     * copy when supporting a new firmware — a decoder cannot be written against a
     * device you no longer have.
     */
    public function rawTable(): string
    {
        return $this->client->readTemplatesRaw();
    }

    /**
     * Downloads one template's bytes so it can be stored or copied to another
     * device.
     *
     * NOT IMPLEMENTED. The per-slot probe proves the device WILL send a template —
     * it answers PREPARE_DATA with a real byte size — so the read is feasible. What
     * is missing is a verified understanding of the template blob's own format
     * (vendor version, encoding) and of the matching upload command, without which
     * a stored template could not be reliably written back.
     *
     * Implementing this without both halves verified would produce templates that
     * appear to save and then fail to match a real finger, which is worse than not
     * offering it.
     */
    public function downloadTemplate(int $uid, int $fingerIndex): string
    {
        throw new UnsupportedCommandException(
            'Template download is not implemented. The per-slot read is feasible (the device '
            . 'reports a real template size) but the blob format and the matching upload command '
            . 'are unverified, so a downloaded template could not be trusted to work when written back. '
            . 'See docs/device-capabilities.md.',
            ['uid' => $uid, 'slot' => $fingerIndex, 'capability' => 'template.download'],
        );
    }

    /**
     * Uploads a stored template to a device.
     *
     * NOT IMPLEMENTED — the counterpart to downloadTemplate(). Until the blob format
     * is verified against hardware, enrollment remains device-side: a finger has to
     * be presented at the terminal.
     */
    public function uploadTemplate(int $uid, int $fingerIndex, string $template): void
    {
        throw new UnsupportedCommandException(
            'Template upload is not implemented. Biometric enrollment is device-side on this '
            . 'protocol implementation: a finger must be presented at the terminal. '
            . 'See docs/device-capabilities.md.',
            ['uid' => $uid, 'slot' => $fingerIndex, 'capability' => 'template.upload'],
        );
    }
}
