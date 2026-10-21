<?php

/*
 * This file is part of promoseven/biometric-protocol.
 * Copyright (c) 2026 Promoseven. All rights reserved.
 * Proprietary and confidential. Not open source. No licence to use, copy,
 * modify or distribute this file is granted except under a signed written
 * agreement with the copyright holder. See LICENSE.
 */

namespace Promoseven\Biometric\Codec;

/**
 * The reply to CMD_GET_FREE_SIZES (50): the terminal's own counters of what its
 * tables hold, sent without transferring any table.
 *
 * Layout: little-endian int32s. Transcribed from fananimi/pyzk `zk/base.py`
 * read_sizes() — users [4], fingers [6], records [8], cards [12], finger capacity
 * [14], user capacity [15], record capacity [16].
 *
 * CONFIRMED 2026-10-18 on the ZKTeco F18 (IT Room 192.168.7.62, Camelot
 * 87.237.196.60), F18/ID (Good Wheels) and F22/ID (On The Road 192.168.7.63): the
 * `records` counter equalled the number of records a full attendance read returned
 * on all four (11,329 + 3 new punches / 42,352 / 11,938 / 8,430), and `users` the
 * user table. Traces: host app tools/zkprobe/traces-2026-10-18/free-sizes-*.json.
 * All four replies were 92 bytes.
 */
final class FreeSizesCodec
{
    private const FIELDS = [
        'users' => 4,
        'fingers' => 6,
        'records' => 8,
        'cards' => 12,
        'fingers_capacity' => 14,
        'users_capacity' => 15,
        'records_capacity' => 16,
    ];

    private function __construct()
    {
    }

    /**
     * Null when the reply is too short to carry the counters — a firmware that
     * answers differently tells us nothing, and a guessed 0 would read as "empty".
     *
     * @return array{users:int,fingers:int,records:int,cards:int,fingers_capacity:int,users_capacity:int,records_capacity:int}|null
     */
    public static function decode(string $data): ?array
    {
        if (strlen($data) < 17 * 4) {
            return null;
        }

        // Signed int32s; only the first 17 carry the counters read here.
        $ints = array_values(unpack('l*', substr($data, 0, 17 * 4)));
        $counts = [];

        foreach (self::FIELDS as $name => $index) {
            if ($ints[$index] < 0) {
                return null;
            }

            $counts[$name] = $ints[$index];
        }

        return $counts;
    }
}
