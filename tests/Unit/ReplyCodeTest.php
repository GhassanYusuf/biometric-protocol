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
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Protocol\ReplyCode;

/**
 * 2.20.0: a vendor error reply names its cause (ZKAccess 3.5.5's own dictionary) instead
 * of UNKNOWN(n). Camelot's 4995 read "Device rejected the user write (UNKNOWN(4995))."
 */
final class ReplyCodeTest extends TestCase
{
    public function test_the_replies_seen_on_this_hardware_are_named(): void
    {
        $this->assertSame('4995 Error inserting database', Command::name(4995));
        $this->assertSame('4994 Error updating database', Command::name(4994));
        $this->assertSame('4991 Operation database has no corresponding data', Command::name(4991));
    }

    public function test_commands_keep_their_names_and_the_rest_stay_unknown(): void
    {
        $this->assertSame('ACK_OK', Command::name(Command::ACK_OK));
        $this->assertSame('RESTART', Command::name(Command::RESTART));
        $this->assertSame('UNKNOWN(4242)', Command::name(4242));
        $this->assertNull(ReplyCode::meaning(4980));
    }

    public function test_the_table_is_exactly_the_vendor_block(): void
    {
        $this->assertSame(range(4999, 4981), array_keys(ReplyCode::MEANINGS));
    }
}
