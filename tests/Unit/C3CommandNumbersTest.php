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
use Promoseven\Biometric\C3\Protocol\Command;

/**
 * The C3 command numbers, pinned.
 *
 * A constant has no behaviour to test, so this is not testing logic — it is holding
 * recovered FACTS still. Every number here was either transcribed from a published
 * reference or extracted from the vendor's plcommpro.dll, and a silent edit to one
 * would send a different command to an access-control panel than the name promises.
 *
 * The write and delete numbers matter most: they came out of the DLL, no public
 * implementation carries them, and there is no second source to check them against.
 * If one is ever changed it should be because somebody re-read the DLL — and this
 * test is what makes that a deliberate act rather than a typo.
 */
final class C3CommandNumbersTest extends TestCase
{
    public function test_the_commands_confirmed_against_hardware_keep_their_numbers(): void
    {
        $this->assertSame(0x76, Command::CONNECT_SESSION);
        $this->assertSame(0x01, Command::CONNECT_SESSION_LESS);
        $this->assertSame(0x02, Command::DISCONNECT);
        $this->assertSame(0x04, Command::GET_PARAM);
        $this->assertSame(0x06, Command::DATATABLE_CFG);
        $this->assertSame(0x08, Command::GET_DATA);
        $this->assertSame(0x0E, Command::BUFFER_READ);
        $this->assertSame(0x0F, Command::BUFFER_FREE);
    }

    /** Recovered from plcommpro.dll on 2026-09-15 — see the Command docblock. */
    public function test_the_commands_recovered_from_the_vendor_sdk_keep_their_numbers(): void
    {
        $this->assertSame(0x07, Command::SET_DATA);
        $this->assertSame(0x09, Command::DELETE_DATA);
        $this->assertSame(0x0A, Command::GET_DATA_COUNT);
    }

    /**
     * No two commands share a number.
     *
     * Cheap, and it is exactly the mistake this set is exposed to: the numbers came
     * piecemeal from three sources, and a collision would mean one of them is wrong.
     */
    public function test_every_command_number_is_distinct(): void
    {
        $commands = [
            'CONNECT_SESSION' => Command::CONNECT_SESSION,
            'CONNECT_SESSION_LESS' => Command::CONNECT_SESSION_LESS,
            'DISCONNECT' => Command::DISCONNECT,
            'GET_PARAM' => Command::GET_PARAM,
            'CONTROL_DEVICE' => Command::CONTROL_DEVICE,
            'DATATABLE_CFG' => Command::DATATABLE_CFG,
            'SET_DATA' => Command::SET_DATA,
            'GET_DATA' => Command::GET_DATA,
            'DELETE_DATA' => Command::DELETE_DATA,
            'GET_DATA_COUNT' => Command::GET_DATA_COUNT,
            'BUFFER_READ' => Command::BUFFER_READ,
            'BUFFER_FREE' => Command::BUFFER_FREE,
            'DISCOVER' => Command::DISCOVER,
        ];

        $this->assertSame(
            count($commands),
            count(array_unique($commands)),
            'Two C3 commands share a number: '.implode(', ', array_keys($commands)),
        );
    }
}
