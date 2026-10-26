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
 * ZKTeco UA300 (and UA300/ID). Observed on one unit: Catering, 192.168.7.120,
 * firmware "Ver 6.60 May 14 2018", platform ZMM200_TFT, serial CEG9194260020.
 *
 * Same standalone protocol family as the F18 (ZMM210) and the same firmware line, but
 * a different board, and a different model (rule 15). It starts from the generic set
 * — reads IMPLEMENTED, every write UNKNOWN — and promotes only what Catering itself
 * has done. No F18 write is inherited: the first write evidence already differs
 * (below). Research (2026-10-26) found nothing model-specific for the UA300 or the
 * ZMM200 in pyzk, pyzatt or php-zkteco, so its writes are learned on the terminal.
 * Password, privilege, ID move in place, clear and wipe have never run on one: UNKNOWN.
 */
final class UA300 implements TerminalModel
{
    public function name(): string
    {
        return 'UA300';
    }

    public static function matches(string $name): bool
    {
        return preg_match('/^UA300\b/i', trim($name)) === 1;
    }

    public function capabilities(): CapabilitySet
    {
        return (new GenericTerminal('UA300'))->capabilities()->with([
            /*
             * CONFIRMED on the UA300 2026-10-22 to 2026-10-26 (Catering): health checks
             * every 5 minutes; device.info (serial, firmware, platform, name); the clock
             * read; the user table, 21 users with cards; attendance, 2,101 → 2,115
             * records over eleven reads, none undecodable; 27 fingerprint templates
             * stored from it by the nightly roster read.
             */
            Capability::PING => Capability::CONFIRMED,
            Capability::DEVICE_INFO => Capability::CONFIRMED,
            Capability::GET_TIME => Capability::CONFIRMED,
            Capability::USER_READ => Capability::CONFIRMED,
            Capability::CARD_READ => Capability::CONFIRMED,
            Capability::ATTENDANCE_READ => Capability::CONFIRMED,
            Capability::TEMPLATE_BLOB_READ => Capability::CONFIRMED,

            /*
             * IMPLEMENTED, not CONFIRMED: the template TABLE would not decode on three
             * of five roster reads (2026-10-23, -24, -25 at 02:30 UTC: "this firmware's
             * fingerprint table could not be decoded"), and decoded on the other two.
             * Counts read from it are left unknown when it fails (rule 10).
             */
            Capability::TEMPLATE_TABLE_READ => Capability::IMPLEMENTED,

            /*
             * USER WRITE: CONFIRMED on the UA300 2026-10-26 (2.18.0). The owner-approved
             * write test (host app tools/zkprobe/ua300-write.php, trace
             * traces-2026-10-26/ua300-write-01.json) added and renamed a test user, each
             * read back. Before it, while the row wrongly said F18 (2026-10-25 13:19 to
             * 2026-10-26 07:45 UTC), the owner's merges re-added about 17 workers under
             * new user IDs through the app, each read back in the app (DC-032).
             */
            Capability::USER_WRITE => Capability::CONFIRMED,

            /*
             * USER DELETE: CONFIRMED on the UA300 2026-10-26 (2.18.1). The write test's
             * delete was verified gone with its finger, every other user, card and finger
             * unchanged; the owner's merges removed ~17 old IDs; and Riza (870876872),
             * resigned 07:30 UTC, was deleted at 07:31 even though the step after timed
             * out. 2.18.0 called her an unexplained loss ("record kept, finger and card
             * gone"); that was a misreading of her still-open link in the host app, not
             * the terminal, which a fresh read at 08:58 settled (DC-032).
             */
            Capability::USER_DELETE => Capability::CONFIRMED,

            /*
             * IMPLEMENTED, offered with a warning. Card: one test write read back, and 10
             * workers' cards on the terminal match the host app's. Fingerprint: the test
             * template read back byte-identical (1,444 bytes), and the merges' fingers are
             * present for every worker, but none written here has yet been seen to match
             * at the terminal.
             */
            Capability::CARD_WRITE => Capability::IMPLEMENTED,
            Capability::TEMPLATE_UPLOAD => Capability::IMPLEMENTED,

            /*
             * Clock write: UNKNOWN. While the device row wrongly said F18 (2026-10-25
             * 13:19 to 2026-10-26 07:45 UTC) the nightly clock job ran twice. 02:00 UTC:
             * the terminal ACKed the time, but the read-back straight after still showed
             * the old time, 96 s slow, so the command failed. By 07:00 the clock was
             * right, so the write took effect LATER than the read-back. An F18 applies
             * it at once. Not measured on the write test: the clock was already right, and
             * making it wrong on purpose would stamp workers' punches wrong. To be run with
             * --clock-only once it has drifted 30 s or more.
             */
            Capability::SET_TIME => Capability::UNKNOWN,
        ]);
    }
}
