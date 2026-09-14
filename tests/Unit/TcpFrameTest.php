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
use Promoseven\Biometric\Protocol\Packet;

/**
 * The 8-byte TCP transport frame.
 *
 * WHY THIS EXISTS, 2026-09-14. The frame's second magic word was being written as
 * zero, and a real device (F22 @ 192.168.7.63) rejected every such frame — it
 * closed the connection without a reply, so the whole TCP transport was dead on
 * arrival and no read over TCP could begin. Both magic words are required; this
 * pins the exact bytes so the regression cannot return unnoticed.
 */
final class TcpFrameTest extends TestCase
{
    public function test_the_frame_carries_both_magic_words_and_a_little_endian_length(): void
    {
        $packet = 'PKT-BODY'; // 8 bytes
        $frame = Packet::wrapTcp($packet);

        // 50 50 | 82 7d | 08 00 00 00 | payload — magic1, magic2, uint32 LE length.
        $this->assertSame('5050827d08000000', bin2hex(substr($frame, 0, 8)));
        $this->assertSame($packet, substr($frame, 8));
    }

    public function test_a_zeroed_second_word_is_exactly_the_bug_that_broke_tcp(): void
    {
        // Guard against a regression to `pack('vvV', 0x5050, 0, len)`, which a real
        // device rejects. The second word must be 0x7d82, never 0x0000.
        $frame = Packet::wrapTcp('x');

        $this->assertNotSame("\x50\x50\x00\x00", substr($frame, 0, 4));
        $this->assertSame("\x50\x50\x82\x7d", substr($frame, 0, 4));
    }

    public function test_unwrap_reads_back_the_declared_length(): void
    {
        $packet = str_repeat('A', 1234);
        $frame = Packet::wrapTcp($packet);

        [$length, $rest] = Packet::unwrapTcp($frame);

        $this->assertSame(1234, $length);
        $this->assertSame($packet, $rest);
    }

    public function test_unwrap_tolerates_a_runt_chunk(): void
    {
        [$length, $rest] = Packet::unwrapTcp("\x50\x50");

        $this->assertSame(0, $length);
        $this->assertSame("\x50\x50", $rest);
    }
}
