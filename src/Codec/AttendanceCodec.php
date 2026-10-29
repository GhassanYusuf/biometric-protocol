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
 * The device's attendance (punch) table.
 *
 * 4-byte byte-length header followed by fixed-width records. Record width varies
 * by firmware generation — 40 / 16 / 8 bytes are the ones documented across ZK
 * client implementations. The 40-byte layout is CONFIRMED against real hardware
 * (ZKTeco F18, 6,744 records); 16 and 8 are DOCUMENTED but unexercised here.
 *
 * A record whose timestamp does not decode is returned as raw hex rather than
 * dropped, so a caller can log and inspect it instead of silently losing punches.
 */
final class AttendanceCodec
{
    /** Record widths this codec understands, in preference order. */
    public const WIDTHS = [40, 16, 8];

    private function __construct()
    {
    }

    /**
     * @return list<array{uid:int|null,user_id:string,status:int,verify_method:int,timestamp:\DateTimeImmutable}|array{raw:string}>
     */
    public static function decode(string $raw, string $timezone = '+03:00'): array
    {
        $body = RecordBuffer::body($raw);

        if ($body === '') {
            return [];
        }

        $recordSize = RecordBuffer::detectRecordSize(strlen($body), self::WIDTHS);

        if ($recordSize <= 0) {
            return [];
        }

        $records = [];

        for ($offset = 0; $offset + $recordSize <= strlen($body); $offset += $recordSize) {
            $chunk = substr($body, $offset, $recordSize);

            $record = match ($recordSize) {
                40 => self::decode40Byte($chunk, $timezone),
                16 => self::decode16Byte($chunk, $timezone),
                8 => self::decode8Byte($chunk, $timezone),
                default => null,
            };

            $records[] = $record ?? ['raw' => bin2hex($chunk)];
        }

        return $records;
    }

    /**
     * 40-byte layout. CONFIRMED on real hardware.
     *
     * uid(2)@0, user_id(24)@2, verify_method(1)@26, timestamp(4)@27, status(1)@31.
     *
     * CONFIRMED: byte 26 is the meaningful verify method (values 1/3/4 observed,
     * matching the vendor CSL/HTTP export's verify_method column), and byte 31 is a
     * constant placeholder — 255 on every record read from this unit, matching that
     * same export's status column. Do not treat byte 31 as a punch direction.
     */
    private static function decode40Byte(string $chunk, string $timezone): ?array
    {
        if (strlen($chunk) < 40) {
            return null;
        }

        /*
         * A punch always carries a user id. A blank one means the 40 bytes are not a
         * record at all — the stream is misaligned. OBSERVED 2026-10-18 on Camelot
         * (F18, 87.237.196.60, internet link): 2,876 such "records" had passed this
         * decoder with stamps from 1999 to 2030, while the undecodable records of the
         * same read showed the next record starting part-way through the chunk. No
         * blank user id has ever been read from the LAN F18s or the F22. 2.14.0.
         */
        $userId = RecordBuffer::cString(substr($chunk, 2, 24));

        if ($userId === '') {
            return null;
        }

        /*
         * Nor is a user id that is not all digits. OBSERVED 2026-10-29 on Camelot (F18/ID,
         * 87.237.196.60): a full read decoded "records" with user ids "L", "Fl!",
         * "ERMISSION", "ption", "]" and stamps from 1999-2000 (host app casebook DC-036):
         * text from another buffer, read as punches, which then broke the host's insert.
         * Every user id ever stored from a ZKTeco standalone terminal in this project (F18,
         * F22, UA300; every punch, user mapping and roster entry, checked 2026-10-29) is
         * digits only; these terminals take ids on a numeric keypad. 2.21.0.
         */
        if (! ctype_digit($userId)) {
            return null;
        }

        $decoded = Timestamp::decode(unpack('V', substr($chunk, 27, 4))[1], $timezone);

        if ($decoded === null) {
            return null;
        }

        return [
            'uid' => unpack('v', substr($chunk, 0, 2))[1],
            'user_id' => $userId,
            'status' => ord($chunk[31]),
            'verify_method' => ord($chunk[26]),
            'timestamp' => $decoded,
        ];
    }

    /** 16-byte layout. DOCUMENTED, not exercised against hardware in this project. */
    private static function decode16Byte(string $chunk, string $timezone): ?array
    {
        if (strlen($chunk) < 16) {
            return null;
        }

        $decoded = Timestamp::decode(unpack('V', substr($chunk, 4, 4))[1], $timezone);

        if ($decoded === null) {
            return null;
        }

        return [
            'uid' => null,
            'user_id' => (string) unpack('V', substr($chunk, 0, 4))[1],
            'status' => ord($chunk[8]),
            'verify_method' => ord($chunk[9]),
            'timestamp' => $decoded,
        ];
    }

    /** 8-byte layout. DOCUMENTED, not exercised against hardware in this project. */
    private static function decode8Byte(string $chunk, string $timezone): ?array
    {
        if (strlen($chunk) < 8) {
            return null;
        }

        $decoded = Timestamp::decode(unpack('V', substr($chunk, 2, 4))[1], $timezone);

        if ($decoded === null) {
            return null;
        }

        return [
            'uid' => null,
            'user_id' => (string) unpack('v', substr($chunk, 0, 2))[1],
            'status' => ord($chunk[6]),
            'verify_method' => ord($chunk[7]),
            'timestamp' => $decoded,
        ];
    }

    /**
     * Decodes ONE realtime attendance push.
     *
     * EXPERIMENTAL — not verified against a real live punch as of writing.
     *
     * Realtime EF_ATTLOG pushes are commonly shaped like a single record from the
     * bulk table, so this tries one 40-byte record first (this device family's
     * confirmed width), then falls back to the full bulk framing (4-byte length
     * prefix + record) in case a firmware includes it even for a single push.
     *
     * If a live punch ever produces a wrong user id or timestamp, THIS is the
     * function to revisit. See docs/protocol-overview.md and the app's
     * ListenZkteco console command.
     *
     * @return array<string,mixed>|null
     */
    public static function decodeRealtime(string $data, string $timezone = '+03:00'): ?array
    {
        if (strlen($data) >= 40) {
            $record = self::decode40Byte(substr($data, 0, 40), $timezone);

            if ($record !== null) {
                return $record;
            }
        }

        foreach (self::decode($data, $timezone) as $record) {
            if (isset($record['timestamp'])) {
                return $record;
            }
        }

        return null;
    }
}
