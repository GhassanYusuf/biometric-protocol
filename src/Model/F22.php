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

namespace Promoseven\Biometric\Model;

use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * ZKTeco F22 (and F22/ID). Observed on one unit: On The Road, 192.168.7.63,
 * firmware "Ver 6.60 Apr 27 2017", platform ZLM60_TFT.
 *
 * Starts from the F18 set for what the two share at the protocol level, then
 * states on its own what has and has NOT been seen on an F22. Anything proven only
 * on the F18 that would WRITE something new to the terminal is UNKNOWN here until
 * it has run on an F22 (rule 15) — that is the point of this file.
 */
final class F22 implements TerminalModel
{
    public function name(): string
    {
        return 'F22';
    }

    public static function matches(string $name): bool
    {
        return preg_match('/^F22\b/i', trim($name)) === 1;
    }

    public function capabilities(): CapabilitySet
    {
        return CapabilitySet::defaults()->with([
            /*
             * Reads: CONFIRMED on the F22 2026-09-13/15 — info, users (push path; the
             * users table refuses WINDOWED reads with reply 4991), attendance
             * (windowed, 8,162 records), template table and blobs (PIN 261 slot 3
             * byte-identical to the F18's copy).
             */
            Capability::USER_READ => Capability::CONFIRMED,
            Capability::ATTENDANCE_READ => Capability::CONFIRMED,
            Capability::TEMPLATE_TABLE_READ => Capability::CONFIRMED,
            Capability::TEMPLATE_BLOB_READ => Capability::CONFIRMED,

            /*
             * User write and delete: CONFIRMED on the F22 2026-10-11 — a user deleted
             * (PIN 940) and verified gone by a roster read; a name written for PIN 654
             * and read back by saveUser().
             */
            Capability::USER_WRITE => Capability::CONFIRMED,
            Capability::USER_DELETE => Capability::CONFIRMED,

            // Card number: the same user-record write as the name. Card 7511517 was
            // written to ALI MOHAMED on On The Road and read back, 2026-10-11; one run,
            // so still offered with the warning.
            Capability::CARD_WRITE => Capability::IMPLEMENTED,

            /*
             * Keypad password: READ CONFIRMED on the F22 2026-10-12 — On The Road
             * 192.168.7.63, the one password the host app held equalled the terminal's
             * (traces-2026-10-12/user-passwords-02.json). WRITE CONFIRMED on the F22
             * 2026-10-20 (2.15.0) — On The Road: a test user's password written and read
             * back, twice, and kept through a name write (traces-2026-10-20/
             * user-password-write-03.json, -04.json).
             */
            Capability::PASSWORD_READ => Capability::CONFIRMED,
            Capability::PASSWORD_WRITE => Capability::CONFIRMED,

            /*
             * Fingerprint write (TemplateService::addTemplates, SAVE_USERTEMPS):
             * IMPLEMENTED on the F22 from 2026-10-11. On The Road: a stored template
             * written to a temporary user and read back byte-identical (users 10 and
             * templates 15 unchanged before/after), then a real move — ALI MOHAMED
             * re-added under a new user ID with fingers 6 and 7 written and read back.
             * Not CONFIRMED until a finger written this way has matched at the terminal.
             */
            Capability::TEMPLATE_UPLOAD => Capability::IMPLEMENTED,

            /*
             * NEVER RUN ON AN F22. Proven (or refused) on the F18 only, so no evidence
             * here either way:
             *   user.renumber   — in place; the F22 moves an ID by re-adding instead
             *   template.delete, card.enroll, fingerprint.enroll, user.disable
             */
            Capability::USER_RENUMBER => Capability::UNKNOWN,

            /*
             * RESTART stays IMPLEMENTED here, as it was by inheritance before 2.20.0. The
             * F18 set confirms it from a run on Camelot (2026-10-26); that run says
             * nothing about an F22 (rule 15), so the F22 does not inherit the CONFIRMED.
             */
            Capability::RESTART => Capability::IMPLEMENTED,
            Capability::TEMPLATE_DELETE => Capability::UNKNOWN,
            Capability::CARD_ENROLL => Capability::UNKNOWN,
            Capability::FINGERPRINT_ENROLL => Capability::UNKNOWN,
            Capability::USER_DISABLE => Capability::UNKNOWN,

            // Never run on any model (2.14.0); the F22 claims nothing the F18 has not
            // even shown. Set on its own once it has run here.
            Capability::ATTENDANCE_CLEAR => Capability::UNKNOWN,
            // A wipe is F18-first (2.16.0) and has never run on an F22 (rule 15).
            Capability::DEVICE_WIPE => Capability::UNKNOWN,
            /*
             * USER_PRIVILEGE: UNKNOWN until 2.15.0, now IMPLEMENTED — the F18's
             * UserService::setPrivilege() on the same USER_WRQ record, whose password
             * field at @3 was read back after writes on this F22 (On The Road,
             * 2026-10-20). CONFIRMED the same day: a test user made 14 then 0, each read
             * back, name and password kept, everyone else unchanged, twice
             * (traces-2026-10-20/user-privilege-write-01.json, -02.json).
             */
            Capability::USER_PRIVILEGE => Capability::CONFIRMED,
        ]);
    }
}
