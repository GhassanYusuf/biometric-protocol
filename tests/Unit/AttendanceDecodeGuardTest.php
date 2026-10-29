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

namespace Promoseven\Biometric\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Promoseven\Biometric\Codec\AttendanceCodec;

/**
 * 2.21.0: a 40-byte "record" whose user id is not all digits is undecodable (raw), not a
 * punch. Camelot's full read on 2026-10-29 decoded ids such as "ERMISSION" and "Fl!"
 * (host app casebook DC-036). Synthetic records; no real punch is in this file.
 */
final class AttendanceDecodeGuardTest extends TestCase
{
    /** One 40-byte record: uid(2), user id(24), verify(1), stamp(4), status(1), padding(8). */
    private static function record(string $userId, int $stamp = 0x3044C0C0): string
    {
        return pack('v', 7)
            .str_pad($userId, 24, "\0")
            .chr(1)
            .pack('V', $stamp)
            .chr(255)
            .str_repeat("\0", 8);
    }

    /** The table as the device sends it: a 4-byte byte length, then the records. */
    private static function table(string ...$records): string
    {
        $body = implode('', $records);

        return pack('V', strlen($body)).$body;
    }

    public function test_a_digit_user_id_still_decodes(): void
    {
        $records = AttendanceCodec::decode(self::table(self::record('930000001')));

        $this->assertCount(1, $records);
        $this->assertSame('930000001', $records[0]['user_id']);
        $this->assertArrayHasKey('timestamp', $records[0]);
    }

    public function test_text_and_control_bytes_are_undecodable_not_punches(): void
    {
        $records = AttendanceCodec::decode(self::table(
            self::record('ERMISSION'),
            self::record("Fl!\x01\x9c"),
            self::record('L'),
            self::record('12 34'),
            self::record('702'),
        ));

        $this->assertCount(5, $records);
        foreach (array_slice($records, 0, 4) as $record) {
            $this->assertArrayHasKey('raw', $record);
            $this->assertArrayNotHasKey('user_id', $record);
        }
        $this->assertSame('702', $records[4]['user_id']);
    }

    public function test_realtime_pushes_take_the_same_guard(): void
    {
        $this->assertNull(AttendanceCodec::decodeRealtime(self::record('ption')));
        $this->assertSame('5', AttendanceCodec::decodeRealtime(self::record('5'))['user_id']);
    }
}
