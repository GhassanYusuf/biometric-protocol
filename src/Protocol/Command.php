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

namespace Promoseven\Biometric\Protocol;

/**
 * Command / constant table for the ZKTeco "standalone" device protocol — the
 * same wire protocol implemented by pyzk, node-zklib and zkteco-js.
 *
 * This is a plain binary protocol spoken by the device itself on port 4370.
 * Nothing here depends on a Windows DLL, OCX or COM component.
 *
 * Provenance markers used throughout this library:
 *   CONFIRMED    — exercised against real hardware in this project
 *   DOCUMENTED   — from published protocol references, not yet exercised here
 *   EXPERIMENTAL — implemented on reasonable inference, unverified
 */
final class Command
{
    // --- Session / handshake (CONFIRMED) ---
    public const CONNECT = 1000;
    public const EXIT = 1001;
    public const ENABLE_DEVICE = 1002;
    public const DISABLE_DEVICE = 1003;
    public const AUTH = 1102;

    // --- Acknowledgements (CONFIRMED) ---
    public const ACK_OK = 2000;
    public const ACK_ERROR = 2001;
    public const ACK_DATA = 2002;
    public const ACK_UNAUTH = 2005;

    // --- Bulk data transfer envelope (CONFIRMED) ---
    public const PREPARE_DATA = 1500;
    public const DATA = 1501;
    public const FREE_DATA = 1502;

    /*
     * --- Windowed ("buffered") bulk read (CONFIRMED on ZKTeco F22, 2026-09-13) ---
     *
     * The flow-controlled alternative to the free-running push above, and the only
     * way to read a large table reliably on this firmware. PREPARE_BUFFER stages
     * the table and answers with its size; READ_BUFFER then asks for ONE window at
     * a time, so the device never streams more than we asked for and the receive
     * buffer can never be outrun. FREE_DATA releases the staged copy.
     *
     * SUPPORT IS PER TABLE, NOT PER DEVICE — measured on the same F22 in one
     * sitting:
     *
     *   ATTLOG_RRQ (attendance) ... ACK_OK, size 326,124   supported
     *   DB_RRQ + FCT_FINGERTMP .... ACK_OK, size  18,486   supported
     *   USERTEMP_RRQ (users) ...... reply 4991             NOT supported
     *
     * So a caller must negotiate per read and fall back to the push path, never
     * assume the device as a whole does or does not do this. See BulkReader.
     */
    public const PREPARE_BUFFER = 1503;
    public const READ_BUFFER = 1504;

    // --- Data tables ---
    public const DB_RRQ = 7;              // CONFIRMED (with FCT_FINGERTMP)
    public const USER_WRQ = 8;            // CONFIRMED
    public const USERTEMP_RRQ = 9;        // CONFIRMED (users bulk, and per-slot template probe)
    public const ATTLOG_RRQ = 13;         // CONFIRMED
    public const CLEAR_DATA = 14;         // DOCUMENTED
    public const CLEAR_ATTLOG = 15;       // DOCUMENTED — destructive, never called by sync
    public const DELETE_USER = 18;        // CONFIRMED
    /** Deletes ONE fingerprint template: payload is (uint16 uid, uint8 finger slot). EXPERIMENTAL. */
    public const DELETE_USERTEMP = 19;

    // --- Device info / control ---
    public const WRITE_LCD = 66;          // DOCUMENTED
    public const CLEAR_LCD = 67;          // DOCUMENTED
    public const GET_TIME = 201;          // CONFIRMED
    public const SET_TIME = 202;          // DOCUMENTED
    public const VERSION = 1100;          // CONFIRMED
    public const DEVICE = 11;             // CONFIRMED (parameterised device info)
    public const GET_FREE_SIZES = 50;     // CONFIRMED
    public const REG_EVENT = 500;         // CONFIRMED (realtime subscription)
    public const REFRESH_DATA = 1013;     // CONFIRMED — required or writes silently do not persist
    public const TEST_VOICE = 1017;       // CONFIRMED (the enrollment beep)
    public const RESTART = 1004;          // DOCUMENTED — reboot, never called automatically

    // --- Fingerprint enrollment (CONFIRMED) ---
    public const START_VERIFY = 60;
    public const START_ENROLL = 61;
    public const CANCEL_CAPTURE = 62;

    /**
     * Realtime event bit flags, OR'd together and registered via REG_EVENT.
     */
    public const EF_ATTLOG = 1;
    public const EF_FINGER = 1 << 1;
    public const EF_ENROLL_USER = 1 << 2;
    public const EF_ENROLL_FINGER = 1 << 3;
    public const EF_BUTTON = 1 << 4;
    public const EF_UNLOCK = 1 << 5;
    public const EF_VERIFY = 1 << 7;
    public const EF_FPFTR = 1 << 8;
    public const EF_ALARM = 1 << 9;
    public const EF_ALL = 0xFFFF;

    /**
     * Data "function" selectors used alongside DB_RRQ to pick which table a bulk
     * read returns (pyzk's FCT_* constants).
     */
    public const FCT_FINGERTMP = 2;
    public const FCT_USER = 5;

    public const USHRT_MAX = 0xFFFF;

    /** Replies that mean "the device accepted this". */
    public const ACCEPTED = [self::ACK_OK, self::ACK_DATA];

    private function __construct()
    {
    }

    /** Human-readable name for a command code, for logs and error messages. */
    public static function name(int $command): string
    {
        static $names = null;

        if ($names === null) {
            $names = [];
            foreach ((new \ReflectionClass(self::class))->getConstants() as $constant => $value) {
                if (is_int($value) && ! isset($names[$value])) {
                    $names[$value] = $constant;
                }
            }
        }

        return $names[$command] ?? "UNKNOWN({$command})";
    }
}
