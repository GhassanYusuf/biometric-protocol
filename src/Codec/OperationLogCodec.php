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

namespace Promoseven\Biometric\Codec;

/**
 * The terminal's operation log (table FCT_OPLOG = 4, read through DB_RRQ): what was done AT the
 * terminal and when — start-ups, menu visits, enrolments, alarms, exit-button presses.
 *
 * LAYOUT — CONFIRMED 2026-11-18 on three F18s (IT ROOM 192.168.7.62, City One 46.184.207.245,
 * Gems 192.168.7.64; host app traces tools/zkprobe/traces-2026-11-1{7,8}/oplog-read-*.json): an
 * optional 4-byte length, then 16-byte records:
 *
 *   0–1  uint16  operator (the admin who did it; 0 = none)
 *   2    uint8   operation code (OPERATIONS below)
 *   3    uint8   —
 *   4–7  uint32  time, packed like a punch (Timestamp)
 *   8–15 uint16 ×4 parameters (first: the user acted on, or the alarm type for code 3)
 *
 * Checked against known events: this library's restart shows as code 150 then 0 at the right second;
 * the hotel's network change as 78/79. Research (rule 17): pyzk zk/const.py (FCT_OPLOG = 4); code
 * meanings from the vendor's operation-log list.
 *
 * NOT RECORDED (CONFIRMED on Gems, F18, 2026-11-10): a punch clear sent over the network.
 */
final class OperationLogCodec
{
    public const RECORD_BYTES = 16;

    /** Operation codes seen on our terminals, with the vendor's meaning. */
    public const OPERATIONS = [
        0 => 'start-up',
        1 => 'shut-down',
        3 => 'alarm',
        4 => 'menu opened',
        5 => 'settings changed',
        6 => 'fingerprint enrolled',
        7 => 'password enrolled',
        8 => 'card enrolled',
        9 => 'user deleted',
        10 => 'fingerprint deleted',
        12 => 'card deleted',
        13 => 'all data cleared',
        21 => 'clock set',
        23 => 'punches deleted',
        30 => 'new user',
        36 => 'user details changed',
        37 => 'holiday changed',
        70 => 'user name changed',
        71 => 'user permission changed',
        78 => 'network gateway changed',
        79 => 'network DNS changed',
        150 => 'restart sent over the network',
    ];

    /** Alarm types — the first parameter of a code 3 record. 53 and 55 CONFIRMED on IT ROOM (F18). */
    public const ALARMS = [
        53 => 'exit button pressed',
        54 => 'door sensor',
        55 => 'alarm',
    ];

    /**
     * @return list<array{operator:int, code:int, operation:string, time:?\DateTimeImmutable, params:list<int>, alarm:?string}>
     */
    public static function decode(string $raw, string $timezone = '+03:00'): array
    {
        if (strlen($raw) >= 4 && unpack('V', substr($raw, 0, 4))[1] === strlen($raw) - 4) {
            $raw = substr($raw, 4);
        }

        $out = [];
        $n = intdiv(strlen($raw), self::RECORD_BYTES);
        for ($i = 0; $i < $n; $i++) {
            $rec = substr($raw, $i * self::RECORD_BYTES, self::RECORD_BYTES);
            $code = ord($rec[2]);
            $params = array_values(unpack('v4', substr($rec, 8, 8)));
            $out[] = [
                'operator' => unpack('v', substr($rec, 0, 2))[1],
                'code' => $code,
                'operation' => self::OPERATIONS[$code] ?? "operation {$code}",
                'time' => Timestamp::decode(unpack('V', substr($rec, 4, 4))[1], $timezone),
                'params' => $params,
                'alarm' => $code === 3 ? (self::ALARMS[$params[0]] ?? "alarm type {$params[0]}") : null,
            ];
        }

        return $out;
    }
}
