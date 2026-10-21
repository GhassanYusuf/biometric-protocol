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
use Promoseven\Biometric\C3\Protocol\Command;
use Promoseven\Biometric\C3\Transport\C3TcpTransport;
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * ZKTeco TF1700.
 *
 * CONFIRMED @192.168.7.60, firmware "Ver 6.64.0013 Oct 16 2018", 2026-09-14.
 *
 * IT IS SOLD AS A STANDALONE FINGERPRINT TERMINAL AND IT IS NOT ONE. It speaks
 * C3/PullSDK. This project spent weeks with it recorded as "TCP 4370 accepts but
 * the comm service answers nothing", having probed it with the standalone protocol
 * — the same mistake made with the inBIO460, repeated. The device was never silent.
 *
 * Independent evidence, both directions:
 *   - ZKAccess 3.5.5 stores it with DevSDKType = 1 (PullSDK), the same value as the
 *     inBIO460; the F18 and F22 are stored as 2 (standalone).
 *   - It answers our C3 probe on the first attempt.
 *
 * UNLIKE THE inBIO460, THIS FIRMWARE ACCEPTS A SESSION. Both CONNECT forms return
 * REPLY_OK. Same protocol, same vendor, opposite session behaviour — which is
 * exactly why this is a separate file and not a flag on a shared one (rule 15).
 */
final class Tf1700 implements PanelModel
{
    public function name(): string
    {
        return 'TF1700';
    }

    public static function matches(string $name): bool
    {
        return str_contains(strtolower($name), 'tf1700');
    }

    /**
     * CONFIRMED @192.168.7.60, 2026-09-14: identity, catalogue, and a full
     * transaction read — 367,768 bytes in 72 chunks, CRC-32 verified, 21,005 rows,
     * whose first record matches the vendor software's own earliest event for this
     * unit to the second.
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
             * CONFIRMED 2026-09-15 against this model at 192.168.7.60: the `templatev10`
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
             * What is proven on this panel (192.168.7.60, test user, 2026-09-24): SET_DATA adds a
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
             * this model 2026-10-12 — Entrance 192.168.7.60: all 4 passwords the host app held
             * equalled the panel's (traces-2026-10-12/user-passwords-02.json). WRITE
             * (Personnel::add/update) CONFIRMED 2026-10-20 (2.15.0) — Entrance: a test
             * user's password written and read back, twice, and kept through a name
             * write; 315 users before and after (traces-2026-10-20/
             * user-password-write-05.json, -06.json).
             */
            Capability::PASSWORD_READ => Capability::CONFIRMED,
            Capability::PASSWORD_WRITE => Capability::CONFIRMED,
            Capability::TEMPLATE_UPLOAD => Capability::IMPLEMENTED,

            /*
             * Clock, CONFIRMED on this panel 2026-10-11 (192.168.7.60): GET_PARAM "DateTime"
             * read it 649 s slow; DATETIME (0x03) "DateTime=<packed>" (transcribed from
             * vwout/zkaccess-c3-py) set it, and a separate read showed it exact.
             */
            Capability::GET_TIME => Capability::CONFIRMED,
            Capability::SET_TIME => Capability::CONFIRMED,
        ]);
    }

    /**
     * Sends CONNECT_SESSION_LESS (0x01), which this firmware REQUIRES.
     *
     * MEASURED @192.168.7.60, 2026-09-14, one variable at a time (rule 16):
     *
     *   connects sent   GET_PARAM   DATATABLE_CFG   GET_DATA
     *   --------------  ----------  --------------  ------------------
     *   none            56 B, junk  1180 B          0xC8, 10 B  (no data)
     *   0x76 only       56 B, junk  1180 B          0xC8, 10 B  (no data)
     *   0x76 then 0x01  80 B, good  1176 B          0x0D staged (works)
     *   0x01 only       80 B, good  1176 B          0x0D staged (works)
     *
     * Look at the catalogue: 1180 bytes against 1176. The difference is exactly
     * FOUR BYTES — the session prefix. This panel defaults to SESSION framing and
     * prefixes every reply with a session id and sequence; 0x01 is what switches it
     * off. Read session-less without it and every payload is shifted four bytes, so
     * ~SerialNumber vanishes and GET_DATA answers 0xC8 with ten useless bytes.
     *
     * THAT IS THE DANGEROUS PART, and the reason this is spelled out at length: the
     * misaligned read does not fail. It returns a well-formed 0xC8 and zero records
     * — a device that looks reachable, healthy and simply empty. An operator would
     * read that as "nobody clocked in". Rule 10 exists for exactly this shape of
     * bug, and only a controlled comparison against a panel known to hold 21,005
     * rows caught it.
     *
     * 0x76 is NOT sent. It is accepted here (it answers 0xC8 with a session id) but
     * it is not sufficient — the table above shows it leaves the panel in session
     * framing — and issuing a command whose success is misleading helps nobody.
     */
    public function establishSession(C3TcpTransport $transport): void
    {
        $transport->useSession(sessionLess: true);

        [$reply] = $transport->send(Command::CONNECT_SESSION_LESS, '', 6.0);

        if ($reply !== Command::REPLY_OK) {
            // A unit that refuses 0x01 is already session-less, which is how the
            // inBIO460 behaves. Supported state, not an error — and worth recording
            // if it ever happens on a TF1700, because this one does not.
            return;
        }
    }
}
