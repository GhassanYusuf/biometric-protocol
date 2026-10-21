<?php

/*
 * This file is part of promoseven/biometric-protocol.
 * Copyright (c) 2026 Promoseven. All rights reserved.
 * Proprietary and confidential. Not open source. No licence to use, copy,
 * modify or distribute this file is granted except under a signed written
 * agreement with the copyright holder. See LICENSE.
 */

namespace Promoseven\Biometric\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Promoseven\Biometric\Client\DeviceClient;
use Promoseven\Biometric\Codec\AttendanceCodec;
use Promoseven\Biometric\Codec\FreeSizesCodec;
use Promoseven\Biometric\Codec\Timestamp;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Service\AttendanceService;

/**
 * 2.14.0: the terminal's own record count (GET_FREE_SIZES), the guarded attendance
 * clear built on it, and the 40-byte decoder refusing a record with no user id.
 */
final class AttendanceClearTest extends TestCase
{
    public function test_free_sizes_decodes_the_real_f18_reply(): void
    {
        // IT Room (F18, 192.168.7.62), 2026-10-18 — 7 users, 10 fingers, 11,332 punches.
        $counts = FreeSizesCodec::decode(file_get_contents(__DIR__.'/../Fixtures/f18-free-sizes-itroom.bin'));

        $this->assertSame([
            'users' => 7,
            'fingers' => 10,
            'records' => 11332,
            'cards' => 2,
            'fingers_capacity' => 3000,
            'users_capacity' => 5000,
            'records_capacity' => 100000,
        ], $counts);
    }

    public function test_a_short_reply_is_unknown_not_zero(): void
    {
        $this->assertNull(FreeSizesCodec::decode(''));
        $this->assertNull(FreeSizesCodec::decode(str_repeat("\0", 40)));
    }

    public function test_a_record_with_no_user_id_is_undecodable(): void
    {
        $stamp = Timestamp::encode(new \DateTimeImmutable('2026-10-18 08:00:00', new \DateTimeZone('+03:00')));
        $good = pack('v', 5).str_pad('205', 24, "\0").chr(1).pack('V', $stamp).chr(255).str_repeat("\0", 8);
        $blank = pack('v', 5).str_repeat("\0", 24).chr(1).pack('V', $stamp).chr(255).str_repeat("\0", 8);
        $body = $good.$blank;

        $records = AttendanceCodec::decode(pack('V', strlen($body)).$body);

        $this->assertCount(2, $records);
        $this->assertSame('205', $records[0]['user_id']);
        $this->assertSame(['raw' => bin2hex($blank)], $records[1]);
    }

    public function test_clear_refuses_when_the_device_holds_more_than_was_stored(): void
    {
        $terminal = new ClearTerminal(records: 101);

        try {
            (new AttendanceService($terminal))->clearAll(100);
            $this->fail('Expected a refusal.');
        } catch (ProtocolException $e) {
            $this->assertStringContainsString('holds 101 records', $e->getMessage());
        }

        $this->assertSame(0, $terminal->clears);
        $this->assertSame(101, $terminal->records);
    }

    public function test_clear_refuses_when_the_count_does_not_decode(): void
    {
        $terminal = new ClearTerminal(records: 100, countsReadable: false);

        $this->expectException(ProtocolException::class);

        try {
            (new AttendanceService($terminal))->clearAll(100);
        } finally {
            $this->assertSame(0, $terminal->clears);
        }
    }

    public function test_clear_is_verified_by_the_count_afterwards(): void
    {
        $terminal = new ClearTerminal(records: 100);

        $this->assertSame(100, (new AttendanceService($terminal))->clearAll(100));
        $this->assertSame(1, $terminal->clears);
        $this->assertSame(0, $terminal->records);
    }

    public function test_an_acknowledged_clear_the_device_dropped_is_reported(): void
    {
        $terminal = new ClearTerminal(records: 100, dropClear: true);

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('still reports 100 records');

        (new AttendanceService($terminal))->clearAll(100);
    }
}

final class ClearTerminal extends DeviceClient
{
    public int $clears = 0;

    public function __construct(
        public int $records,
        private readonly bool $countsReadable = true,
        private readonly bool $dropClear = false,
    ) {
    }

    public function recordCounts(): ?array
    {
        if (! $this->countsReadable) {
            return null;
        }

        return [
            'users' => 1, 'fingers' => 0, 'records' => $this->records, 'cards' => 0,
            'fingers_capacity' => 3000, 'users_capacity' => 5000, 'records_capacity' => 100000,
        ];
    }

    public function clearAttendanceLog(): void
    {
        $this->clears++;

        if (! $this->dropClear) {
            $this->records = 0;
        }
    }
}
