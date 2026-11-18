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

namespace Promoseven\Biometric\C3\Codec;

/**
 * A C3 panel's real-time log (RTLOG, 0x0B): its latest events, then — once caught up — its current door
 * and alarm status.
 *
 * Transcribed (rule 17) from vwout/zkaccess-c3-py c3/rtlog.py and c3/consts.py: 16-byte records; byte 10
 * is the event type. Type 255 is a door/alarm STATUS record — alarm flags in bytes 0–3 and door sensor
 * state in bytes 4–7 (low nibble), one byte per door; time in 12–15. Any other type is an EVENT — card
 * 0–3, user (pin) 4–7, verify mode 8, door 9, event 10, in/out 11, time 12–15. The reference's docstring
 * puts alarm and sensor the other way round; its code is transcribed here.
 *
 * Seen 2026-11-18 (host app trace tools/zkprobe/traces-2026-11-18/c3-rtlog-*.json): Glass Door (inBIO460)
 * sends events, then a status record every poll (doors 1–2); Entrance (TF1700) sent events once, then
 * nothing. Which byte group is the alarm and which the sensor is NOT yet settled on hardware — on Glass
 * Door both groups read 02 02 — so the status is IMPLEMENTED, not confirmed.
 */
final class RtLogCodec
{
    public const RECORD_BYTES = 16;

    public const STATUS = 255;

    /** InOutStatus (door sensor). */
    public const SENSOR = [0 => 'unknown', 1 => 'closed', 2 => 'open'];

    /** Door event types seen or named by the reference; others keep their number. */
    public const EVENTS = [
        0 => 'opened by a valid user',
        200 => 'door opened',
        201 => 'door closed',
        202 => 'opened by exit button',
    ];

    /**
     * @return array{status:?array{doors:array<int,array{sensor:string,alarm:bool,open_too_long:bool}>, time:?\DateTimeImmutable},
     *               events:list<array{event:int, meaning:string, door:int, pin:int, card:bool, verified:int, in_out:int, time:?\DateTimeImmutable}>}
     */
    public static function decode(string $payload, string $timezone = '+03:00'): array
    {
        $status = null;
        $events = [];

        foreach (str_split($payload, self::RECORD_BYTES) as $rec) {
            if (strlen($rec) < self::RECORD_BYTES) {
                continue;
            }
            $b = array_values(unpack('C*', $rec));
            $time = Timestamp::decode(unpack('V', substr($rec, 12, 4))[1], $timezone);

            if ($b[10] === self::STATUS) {
                $doors = [];
                for ($door = 1; $door <= 4; $door++) {
                    $doors[$door] = [
                        'sensor' => self::SENSOR[$b[3 + $door] & 0x0F] ?? 'unknown',
                        'alarm' => ($b[$door - 1] & 1) === 1,
                        'open_too_long' => ($b[$door - 1] & 2) === 2,
                    ];
                }
                $status = ['doors' => $doors, 'time' => $time];

                continue;
            }

            $events[] = [
                'event' => $b[10],
                'meaning' => self::EVENTS[$b[10]] ?? "event {$b[10]}",
                'door' => $b[9],
                'pin' => unpack('V', substr($rec, 4, 4))[1],
                // Whether a card was presented — never its number (it is a credential).
                'card' => unpack('V', substr($rec, 0, 4))[1] !== 0,
                'verified' => $b[8],
                'in_out' => $b[11],
                'time' => $time,
            ];
        }

        return ['status' => $status, 'events' => $events];
    }
}
