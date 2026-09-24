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

namespace Promoseven\Biometric\C3\Protocol;

/**
 * C3 / PullSDK command and reply codes.
 *
 * THIS IS NOT THE ZKTECO STANDALONE PROTOCOL. Nothing in Promoseven\Biometric\Protocol
 * applies here: different transport (TCP, always), different frame, different
 * checksum, different session model. The two families share a port number and a
 * vendor, and nothing else. Do not carry a constant across.
 *
 * Spoken by ZKTeco access-control PANELS — the inBIO and C3 ranges — and, as this
 * project learned the hard way, by at least one device sold as a standalone
 * fingerprint terminal (the TF1700). A model name does not tell you the family;
 * only reading the device does.
 *
 * Confidence markers follow the same discipline as the standalone protocol:
 *   CONFIRMED    — exercised against real hardware in this project, model named
 *   DOCUMENTED   — from published references, not exercised here
 *   EXPERIMENTAL — implemented on reasonable inference, unverified
 *
 * References (rule 17 — transcribed, never invented):
 *   vwout/zkaccess-c3-py, vwout/zkaccess-c3-lua   frame, CRC, command numbers
 *   ZKAccess 3.5.5 plcommpro.dll                  the buffered read, and the write
 *                                                 and delete command numbers —
 *                                                 neither of which any public
 *                                                 implementation carries
 */
final class Command
{
    /** Frame delimiters. CONFIRMED inBIO460, TF1700. */
    public const START = 0xAA;

    public const END = 0x55;

    public const VERSION = 0x01;

    /*
     * Commands.
     */

    /** Opens a session. CONFIRMED TF1700 (accepted); CONFIRMED inBIO460 (refused, -13). */
    public const CONNECT_SESSION = 0x76;

    /** Session-less connect. CONFIRMED TF1700 (accepted); CONFIRMED inBIO460 (refused, -98). */
    public const CONNECT_SESSION_LESS = 0x01;

    /** CONFIRMED inBIO460, TF1700. */
    public const DISCONNECT = 0x02;

    /** Reads named parameters. CONFIRMED inBIO460, TF1700 — answers with no session. */
    public const GET_PARAM = 0x04;

    /**
     * The door relay.
     *
     * DOCUMENTED, never sent. This is a WRITE that physically unlocks a door, and
     * rule 16 puts it behind the owner's explicit authorization and a terminal out
     * of service. It is declared here so that nobody rediscovers the number by
     * sweeping for it against a live entrance.
     */
    public const CONTROL_DEVICE = 0x05;

    /** The data-table catalogue. CONFIRMED inBIO460 (12 tables), TF1700 (11 tables). */
    public const DATATABLE_CFG = 0x06;

    /**
     * WRITES rows to a table.
     *
     * CONFIRMED — recovered from the vendor's own plcommpro.dll on 2026-09-15, not
     * inferred and not carried over from any public reimplementation (none of them
     * has a write command at all; vwout/zkaccess-c3-py stops at GET_DATA). The
     * evidence is the SDK's own log string immediately followed by the constant it
     * sets:
     *
     *   .rdata 0x10038xxx  "SetDeviceData, ZEMBPRO_SENDCMDDATA Before !Cmd=CMD_SET_DATA, datalen=%d"
     *   .text  0x1000b7c2  movl $0x7,0x44(%esp)      ; the command
     *   .text  0x1000b7ca  movl $0x8000,0x40(%esp)   ; the send buffer
     *
     * The same extraction recovers 0x09 and 0x0A below, and independently reproduces
     * three command numbers already known from the references (0x03 DATETIME, 0x04
     * GET_PARAM, 0x06 DATATABLE_CFG) — which is what makes the method trustworthy
     * rather than a coincidence.
     *
     * NEVER SENT TO A DEVICE BY THIS LIBRARY YET. The command number is settled; the
     * PAYLOAD layout for a write is not (see docs/protocol-overview.md). Sending a
     * guessed payload to a panel would risk overwriting live enrolments, which rule
     * 16 forbids — so this constant exists to be built on deliberately, and so that
     * nobody rediscovers it by sweeping command numbers at a live door.
     */
    public const SET_DATA = 0x07;

    /** Reads rows from a table. CONFIRMED inBIO460, TF1700 — answers PREPARE_DATA. */
    public const GET_DATA = 0x08;

    /**
     * DELETES rows from a table.
     *
     * CONFIRMED from plcommpro.dll the same way — the constant sits inside
     * Process_DeleteDeviceData. Unsent, for the same reason as SET_DATA, and more so:
     * a wrong delete against a populated `user` table removes people's enrolments.
     */
    public const DELETE_DATA = 0x09;

    /**
     * Counts rows in a table without transferring them.
     *
     * CONFIRMED from plcommpro.dll — the constant sits inside
     * Process_GetDeviceDataCount. This one is READ-ONLY and therefore the safe place
     * to prove the extraction against real hardware before anything is written.
     */
    public const GET_DATA_COUNT = 0x0A;

    /**
     * Pulls one chunk of a staged buffer. Payload is a 4-byte LE offset, nothing else.
     *
     * CONFIRMED inBIO460 (337 chunks) and TF1700 (72 chunks), 2026-09-14, each with
     * the device's own CRC-32 verifying the assembled result.
     */
    public const BUFFER_READ = 0x0E;

    /**
     * Releases the staged buffer. No payload. Must be sent on EVERY exit path.
     *
     * CONFIRMED inBIO460, TF1700. The vendor SDK sends it from all five of its exit
     * paths including every error, because the staging area is device memory and
     * holding it starves the next read.
     */
    public const BUFFER_FREE = 0x0F;

    /** Broadcast discovery. CONFIRMED inBIO460. */
    public const DISCOVER = 0x14;

    /*
     * Replies.
     */

    /** CONFIRMED. */
    public const REPLY_OK = 0xC8;

    /** CONFIRMED — carries a negative error code in its payload. */
    public const REPLY_ERROR = 0xC9;

    /**
     * The staging handshake: the device has prepared an answer too large to inline.
     *
     * CONFIRMED inBIO460, TF1700. The public C3 reimplementations handle only
     * REPLY_OK here and therefore cannot read a populated table at all.
     */
    public const REPLY_PREPARE_DATA = 0x0D;

    /**
     * Error codes worth naming.
     *
     * The vendor ships these in Languages/language_en-US.xml rather than in the
     * DLLs, which return bare integers. Only the ones this project has actually
     * seen are listed; inventing the rest would be inventing facts.
     */
    public const ERROR_COMMAND_NOT_AVAILABLE = -13;

    public const ERROR_NOT_IN_AREA = -98;

    /** @var array<int,string> */
    public const ERRORS = [
        -13 => 'Command not available on this firmware',
        -98 => 'Refused: not in the specified area',
        -109 => 'Buffered read returned the wrong offset',
        -112 => 'Receiving buffer too small for the staged data',
    ];

    public static function describeError(int $code): string
    {
        return self::ERRORS[$code] ?? "Device refused with code {$code}";
    }
}
