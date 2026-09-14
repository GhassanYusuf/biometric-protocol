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
