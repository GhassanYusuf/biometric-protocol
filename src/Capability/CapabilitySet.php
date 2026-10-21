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

use Promoseven\Biometric\Exception\UnsupportedCommandException;

/**
 * What one device can do, as a queryable set.
 *
 * Immutable. A host app persists this per device and hands it to its UI so
 * unsupported actions are never offered — the alternative is a button that returns
 * a 502 and an operator who learns to distrust the whole screen.
 */
final class CapabilitySet
{
    /** @param array<string,string> $levels capability key => support level */
    public function __construct(private readonly array $levels = [])
    {
    }

    /**
     * Baseline for the ZKTeco standalone protocol as this library implements it.
     *
     * Every level here is an honest statement of what this project observed on a
     * real ZKTeco F18 at 192.168.7.62, not a vendor datasheet claim.
     */
    public static function defaults(): self
    {
        return new self([
            // Verified working — see docs/device-capabilities.md for the evidence.
            Capability::PING => Capability::CONFIRMED,
            Capability::DEVICE_INFO => Capability::CONFIRMED,
            Capability::GET_TIME => Capability::CONFIRMED,
            Capability::USER_READ => Capability::CONFIRMED,
            Capability::USER_WRITE => Capability::CONFIRMED,
            Capability::USER_DELETE => Capability::CONFIRMED,
            Capability::CARD_READ => Capability::CONFIRMED,
            Capability::CARD_WRITE => Capability::CONFIRMED,
            Capability::FINGERPRINT_ENROLL => Capability::CONFIRMED,
            Capability::TEMPLATE_TABLE_READ => Capability::CONFIRMED,
            Capability::TEMPLATE_SLOT_PROBE => Capability::CONFIRMED,
            Capability::ATTENDANCE_READ => Capability::CONFIRMED,

            /*
             * Keypad password, password(8)@3 (2.13.0). READ CONFIRMED on the F18 —
             * IT ROOM 192.168.7.62 and Camelot 87.237.196.60, 2026-10-12
             * (tools/zkprobe/traces-2026-10-12/user-passwords-02.json): each password the
             * host app held equalled the terminal's. WRITE CONFIRMED on the F18 2026-10-20
             * (2.15.0): a test user's password written and read back, twice, and kept
             * through a name write, on all three F18s — IT ROOM 192.168.7.62, Camelot
             * 87.237.196.60 and Good Wheels 46.184.163.106 (F18/ID, 2021 firmware)
             * (host app tools/zkprobe/traces-2026-10-20/user-password-write-01..04.json).
             */
            Capability::PASSWORD_READ => Capability::CONFIRMED,
            Capability::PASSWORD_WRITE => Capability::CONFIRMED,

            // Implemented, never confirmed succeeding on hardware.
            Capability::SET_TIME => Capability::IMPLEMENTED,
            Capability::TEMPLATE_DELETE => Capability::IMPLEMENTED,
            Capability::CARD_ENROLL => Capability::IMPLEMENTED,
            Capability::ATTENDANCE_REALTIME => Capability::IMPLEMENTED,
            /*
             * ATTENDANCE_CLEAR: AttendanceService::clearAll(), guarded since 2.14.0 by the
             * terminal's own record count before and after. Never run on hardware.
             */
            Capability::ATTENDANCE_CLEAR => Capability::IMPLEMENTED,
            /*
             * DEVICE_WIPE (2.16.0): UserService::deleteAll() — every user removed by
             * DELETE_USER (18, CONFIRMED on the F18), then the user table read back and
             * required to be empty. Not CLEAR_DATA (14), which is only DOCUMENTED. Never
             * run on hardware; first run planned on a test F18 (host app "IT-Office").
             */
            Capability::DEVICE_WIPE => Capability::IMPLEMENTED,
            /*
             * USER_PRIVILEGE: UserService::save() with an explicit privilege (0 / 14),
             * read back. The F18 KEEPS a privilege through save() (observed on IT Room,
             * 2026-10-11) and a re-added user got 14 back. CHANGING one CONFIRMED on the
             * F18 2026-10-20 (2.15.0): a test user made 14 then 0, each read back, name
             * and password kept, everyone else unchanged — twice on IT ROOM, Camelot and
             * Good Wheels (host app tools/zkprobe/traces-2026-10-20/
             * user-privilege-write-01.json, -02.json).
             */
            Capability::USER_PRIVILEGE => Capability::CONFIRMED,
            Capability::RESTART => Capability::IMPLEMENTED,
            // Approximated by clearing the card — the protocol has no suspend flag.
            Capability::USER_DISABLE => Capability::IMPLEMENTED,

            /*
             * CONFIRMED on the ZKTeco F18 @ 192.168.7.62 and the F22 @ 192.168.7.63,
             * 2026-09-15. The template table carries each blob after its 6-byte record
             * header; the codec had simply been stepping over them. No new command, no
             * extra round trip.
             *
             * PIN 261 slot 3 came back as the same 1,054 bytes from BOTH models, which
             * is what makes a digest usable as an identity signal: a vendor tool had
             * copied one enrolment to both terminals.
             */
            Capability::TEMPLATE_BLOB_READ => Capability::CONFIRMED,

            /*
             * TEMPLATE_DOWNLOAD is the per-slot command and is still not done; the
             * blobs come from the table instead (TEMPLATE_BLOB_READ above).
             *
             * TEMPLATE_UPLOAD = TemplateService::addTemplates() (SAVE_USERTEMPS, 2.10.0).
             * WRITE + READ-BACK OBSERVED on the ZKTeco F18 @ 192.168.7.62 (IT Room),
             * 2026-10-11: user 440105943 (uid 20, no fingers) was given slot 6 — a
             * 1,132-byte template read off the inBIO460 — and the table then held it
             * byte-identical; the other 17 users and 15 templates were unchanged.
             * IMPLEMENTED, not CONFIRMED, until that finger has MATCHED at the
             * terminal: a template that saves and does not match is the failure this
             * level exists to warn about. Never run on the F22, which inherits this
             * set — unknown there (rule 15).
             */
            Capability::TEMPLATE_DOWNLOAD => Capability::NOT_IMPLEMENTED,
            Capability::TEMPLATE_UPLOAD => Capability::IMPLEMENTED,

            /*
             * REFUSED BY THE F18 — observed 2026-09-23, IT Room @ 192.168.7.62, test user
             * uid 6: rewriting the uid under a new user id answered ACK_ERROR for
             * `000000005`, `5` and `10055`, record untouched each time (traces in the host app,
             * tools/zkprobe/traces-2026-09-23/renumber-itroom-01.json). Leading zeros were
             * therefore not the cause. UserService::renumber() stays for firmware that
             * accepts it; the level hides it here. The only other route, delete and
             * re-create, needs TEMPLATE_UPLOAD and would otherwise destroy fingerprints.
             */
            Capability::USER_RENUMBER => Capability::NOT_IMPLEMENTED,

            // Never probed. Access-control features may well exist on the hardware;
            // we have no evidence either way, so we claim nothing.
            Capability::VERIFY_MODE => Capability::UNKNOWN,
            Capability::ACCESS_SCHEDULES => Capability::UNKNOWN,
            Capability::ANTI_PASSBACK => Capability::UNKNOWN,
            Capability::DURESS => Capability::UNKNOWN,
            Capability::RELAY => Capability::UNKNOWN,
        ]);
    }

    public function level(string $capability): string
    {
        return $this->levels[$capability] ?? Capability::UNKNOWN;
    }

    /** Whether a UI should offer this action. */
    public function supports(string $capability): bool
    {
        return Capability::isUsable($this->level($capability));
    }

    /** Verified on hardware, as opposed to merely implemented. */
    public function isConfirmed(string $capability): bool
    {
        return $this->level($capability) === Capability::CONFIRMED;
    }

    /**
     * Guard for the top of a service method.
     *
     * Throws the typed exception rather than returning a plausible empty result, so
     * "this firmware cannot" can never be mistaken for "there is nothing there".
     */
    public function require(string $capability): void
    {
        if (! $this->supports($capability)) {
            throw new UnsupportedCommandException(
                "This device does not support {$capability}: " . Capability::describe($this->level($capability)),
                ['capability' => $capability, 'level' => $this->level($capability)],
            );
        }
    }

    /** Returns a new set with these levels overlaid — probing refines defaults. */
    public function with(array $levels): self
    {
        return new self([...$this->levels, ...$levels]);
    }

    /** @return array<string,string> */
    public function toArray(): array
    {
        return $this->levels;
    }

    /**
     * Shape the UI consumes: every capability with its level, usability and reason.
     *
     * @return array<string,array{level:string,usable:bool,confirmed:bool,description:string}>
     */
    public function forUi(): array
    {
        $out = [];

        foreach (Capability::all() as $key) {
            $level = $this->level($key);

            $out[$key] = [
                'level' => $level,
                'usable' => Capability::isUsable($level),
                'confirmed' => $level === Capability::CONFIRMED,
                'description' => Capability::describe($level),
            ];
        }

        return $out;
    }

    /** @param array<string,string> $levels */
    public static function fromArray(array $levels): self
    {
        return new self($levels);
    }
}
