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

namespace Promoseven\Biometric\Capability;

use Promoseven\Biometric\Client\DeviceClient;
use Promoseven\Biometric\Codec\TemplateCodec;
use Promoseven\Biometric\Codec\UserCodec;

/**
 * Works out what a specific device can actually do, by asking it.
 *
 * Starts from CapabilitySet::defaults() — the honest baseline for this protocol —
 * and refines it with READ-ONLY probes. It never probes by attempting a write: you
 * cannot test "can I delete a fingerprint" without deleting somebody's fingerprint.
 *
 * Anything that can only be established by mutating the device stays at its
 * declared level and is documented as such. That is a deliberate limit, not an
 * oversight: a capability probe that damages data is worse than an unknown.
 */
final class CapabilityResolver
{
    /**
     * @param CapabilitySet|null $baseline the MODEL's own set (Model\TerminalModel,
     *        2.11.0) that probing refines; null = CapabilitySet::defaults(), the F18.
     */
    public function __construct(
        private readonly DeviceClient $client,
        private readonly ?CapabilitySet $baseline = null,
    )
    {
    }

    /**
     * Probes the device and returns a refined capability set.
     *
     * Every probe is individually guarded: one firmware refusing one command must
     * not abort the whole resolution and leave every capability unknown.
     */
    public function resolve(): CapabilitySet
    {
        $levels = [];

        // --- Liveness and clock (read-only) ---
        $levels[Capability::PING] = $this->probe(fn () => $this->client->getTime() !== null);
        $levels[Capability::GET_TIME] = $levels[Capability::PING];

        // --- Device info: a firmware string proves CMD_VERSION works ---
        $levels[Capability::DEVICE_INFO] = $this->probe(function () {
            $info = $this->client->getDeviceInfo();

            return ($info['firmware'] ?? '') !== '' || ($info['serial'] ?? '') !== '';
        });

        // --- User table (read-only) ---
        $users = [];
        $levels[Capability::USER_READ] = $this->probe(function () use (&$users) {
            $users = UserCodec::decode($this->client->readUsersRaw());

            // An empty device is legitimately empty; what matters is that the read
            // did not throw and the buffer decoded.
            return true;
        });

        // --- Card read: the card field lives in the user record ---
        $levels[Capability::CARD_READ] = $levels[Capability::USER_READ];

        // --- Template table (read-only, and the one most firmware-dependent) ---
        $levels[Capability::TEMPLATE_TABLE_READ] = $this->probe(function () use ($users) {
            $templates = TemplateCodec::decode($this->client->readTemplatesRaw());

            // [] means the table would not decode on this firmware — a real and
            // common outcome, and precisely what this capability exists to record.
            return $templates !== [] || $users === [];
        });

        // --- Per-slot probe: only meaningful if we have a uid to ask about ---
        if ($users !== []) {
            $firstUid = (int) ($users[0]['uid'] ?? 0);

            if ($firstUid > 0) {
                $levels[Capability::TEMPLATE_SLOT_PROBE] = $this->probe(function () use ($firstUid) {
                    // Slot 0 either exists or does not; either is a valid answer. We
                    // are testing that the device ANSWERS, not what it says.
                    $this->client->probeTemplateSlot($firstUid, 0);

                    return true;
                });
            }
        }

        // --- Attendance table (read-only) ---
        $levels[Capability::ATTENDANCE_READ] = $this->probe(function () {
            $this->client->readAttendanceRaw();

            return true;
        });

        return ($this->baseline ?? CapabilitySet::defaults())->with(array_filter($levels));
    }

    /**
     * Runs one probe and maps the outcome to a support level.
     *
     * A probe that throws yields UNKNOWN rather than NOT_IMPLEMENTED: a network
     * blip is not evidence about firmware, and recording it as a hard "no" would
     * permanently hide a feature the device actually has.
     */
    private function probe(\Closure $check): string
    {
        try {
            return $check() ? Capability::CONFIRMED : Capability::UNKNOWN;
        } catch (\Throwable) {
            return Capability::UNKNOWN;
        }
    }

    /**
     * Capabilities that cannot be probed without mutating the device, with the
     * reason. A host app should surface these verbatim rather than guessing.
     *
     * @return array<string,string>
     */
    public static function unprobeable(): array
    {
        return [
            Capability::USER_WRITE => 'Would create or modify a real user record.',
            Capability::USER_DELETE => 'Would delete a real user.',
            Capability::USER_RENUMBER => 'Would change the user id attendance is recorded under, and could cost fingerprints.',
            Capability::USER_DISABLE => 'Would clear a real card.',
            Capability::USER_PRIVILEGE => 'Would change who can open the terminal menu.',
            Capability::CARD_WRITE => 'Would overwrite a real card number.',
            // 2.14.1: was missing, so a re-probe overwrote a password.write level a host
            // app had recorded for one terminal after a real write test.
            Capability::PASSWORD_WRITE => 'Would change a real person\'s keypad password.',
            Capability::CARD_ENROLL => 'Requires a physical card tap at the terminal.',
            Capability::FINGERPRINT_ENROLL => 'Requires a finger at the terminal.',
            Capability::TEMPLATE_DELETE => 'Would destroy a real fingerprint template.',
            Capability::SET_TIME => 'Would change the clock every future punch is stamped with.',
            Capability::ATTENDANCE_CLEAR => 'Would irreversibly erase attendance on the device.',
            Capability::RESTART => 'Would take the terminal offline.',
            Capability::VERIFY_MODE => 'Not implemented; would change how staff authenticate.',
            Capability::ACCESS_SCHEDULES => 'Not implemented; no read command verified.',
            Capability::ANTI_PASSBACK => 'Not implemented; no read command verified.',
            Capability::DURESS => 'Not implemented; no read command verified.',
            Capability::RELAY => 'Not implemented; would actuate a door.',
        ];
    }
}
