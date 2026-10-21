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

namespace Promoseven\Biometric\C3\Model;

use Promoseven\Biometric\C3\Capability\C3Capabilities;
use Promoseven\Biometric\C3\Transport\C3TcpTransport;
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * ZKTeco inBIO460 — a four-door access-control panel.
 *
 * CONFIRMED @192.168.7.61, firmware "AC Ver 5.2.4 Apr 19 2016", 2026-09-14.
 *
 * THIS FIRMWARE REFUSES BOTH CONNECT FORMS AND NEEDS NEITHER:
 *   CONNECT_SESSION      (0x76) -> REPLY_ERROR, code -13 "command not available"
 *   CONNECT_SESSION_LESS (0x01) -> REPLY_ERROR, code -98
 *
 * Every reply CRC was valid, which is what revealed this as a semantic refusal
 * rather than a garbled link — the panel was answering, just saying no. GET_PARAM,
 * DATATABLE_CFG and GET_DATA all work with no session at all.
 *
 * The reference libraries (vwout/zkaccess-c3-py, -lua) always connect first, and
 * carrying that assumption over is what made this panel look dead for weeks. A
 * well-formed error is the device talking to you (rule 17).
 */
final class InBio460 implements PanelModel
{
    public function name(): string
    {
        return 'inBIO460';
    }

    public static function matches(string $name): bool
    {
        return str_contains(strtolower($name), 'inbio460');
    }

    /**
     * CONFIRMED @192.168.7.61, 2026-09-14: identity, catalogue, and a full
     * transaction read — 1,717,298 bytes in 337 chunks, CRC-32 verified, 87,756
     * rows, spanning 2000-10-04 to 2026-09-14.
     *
     * USER_READ stays at the family default (IMPLEMENTED, not CONFIRMED): the table
     * is in this panel's catalogue and the same code path would read it, but a
     * roster read has never actually been run here. Rule 10 — "the same code should
     * work" is not the same as "it worked".
     */
    public function capabilities(): CapabilitySet
    {
        return C3Capabilities::defaults()->with([
            Capability::PING => Capability::CONFIRMED,
            Capability::DEVICE_INFO => Capability::CONFIRMED,
            Capability::ATTENDANCE_READ => Capability::CONFIRMED,
            // Promoted 2026-09-14 after an actual roster read through the app's own
            // driver: 320 users, all named, 145 carrying a card. Until that ran it
            // was IMPLEMENTED — the table was in the catalogue and the code path
            // existed, which is not the same as having read it (rule 10).
            Capability::USER_READ => Capability::CONFIRMED,

            /*
             * CONFIRMED 2026-09-15 against this model at 192.168.7.61: the `templatev10`
             * table answered with 238 records — exactly the fingercount the vendor
             * software reports for it — across 196 people, templates of 564-1,618
             * bytes, every one carrying the ZKFinger `SS21` signature.
             *
             * It was declared not_implemented until that day because the table had
             * never been requested. What made it look unreadable once it was, was the
             * blob's TWO-byte length prefix where every other C3 field uses one.
             */
            Capability::TEMPLATE_TABLE_READ => Capability::CONFIRMED,
            Capability::TEMPLATE_BLOB_READ => Capability::CONFIRMED,

            /*
             * IMPLEMENTED 2026-09-24 (C3\Service\Personnel), offered with a warning.
             * What is proven on this panel (192.168.7.61, test user, 2026-09-24): SET_DATA adds a
             * user row, DELETE_DATA removes it, and templatev10 rows written under the
             * panel's UID read back byte-identical (traces-2026-09-24/c3-user-move-*).
             * NOT yet seen here: an edit of an existing row (SET_DATA as an update), a
             * card write, and a finger enrolled elsewhere matching at this panel.
             * Promote each to CONFIRMED only after tools/zkprobe/c3-personnel.php has run
             * on THIS model — a TF1700 result says nothing about an inBIO460 (rule 15).
             */
            Capability::USER_WRITE => Capability::IMPLEMENTED,
            Capability::USER_DELETE => Capability::IMPLEMENTED,
            Capability::CARD_WRITE => Capability::IMPLEMENTED,

            /*
             * Keypad password, the user table's Password field (2.13.0). READ CONFIRMED on
             * this model 2026-10-12 — Glass Door 192.168.7.61: all 4 passwords the host app held
             * equalled the panel's (traces-2026-10-12/user-passwords-02.json). WRITE
             * (Personnel::add/update) CONFIRMED 2026-10-20 (2.15.0) — Glass Door: a test
             * user's password written and read back, twice, and kept through a name
             * write; 315 users before and after (traces-2026-10-20/
             * user-password-write-05.json, -06.json).
             */
            Capability::PASSWORD_READ => Capability::CONFIRMED,
            Capability::PASSWORD_WRITE => Capability::CONFIRMED,
            Capability::TEMPLATE_UPLOAD => Capability::IMPLEMENTED,

            /*
             * Clock, CONFIRMED on this panel 2026-10-11 (192.168.7.61): GET_PARAM "DateTime"
             * read it 650 s slow; DATETIME (0x03) "DateTime=<packed>" (transcribed from
             * vwout/zkaccess-c3-py) set it, and a separate read showed it exact.
             */
            Capability::GET_TIME => Capability::CONFIRMED,
            Capability::SET_TIME => Capability::CONFIRMED,
        ]);
    }

    /**
     * No handshake at all. Not an omission — a finding.
     *
     * We do not send CONNECT and then ignore the refusal, because sending a command
     * we know this firmware rejects would put a guaranteed error in every trace and
     * teach the next reader that errors here are normal.
     *
     * MEASURED @192.168.7.61, 2026-09-14: all four connect sequences (none, 0x76,
     * 0x76 then 0x01, 0x01) produce an IDENTICAL result here — GET_PARAM 81 bytes,
     * catalogue 1085 bytes, GET_DATA staged. This panel is session-less and has no
     * other mode, which is the opposite of the TF1700 in the same family. See
     * Tf1700::establishSession() for the comparison that established both.
     */
    public function establishSession(C3TcpTransport $transport): void
    {
        $transport->useSession(sessionLess: true);
    }
}
