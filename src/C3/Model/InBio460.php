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
