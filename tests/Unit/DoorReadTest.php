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
use Promoseven\Biometric\C3\Capability\C3Capabilities;
use Promoseven\Biometric\C3\Codec\RtLogCodec;
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Codec\OperationLogCodec;
use Promoseven\Biometric\Codec\Timestamp;
use Promoseven\Biometric\Model\TerminalModelFactory;

/** Doors (2.25.0): the F18 operation log, a C3 panel's real-time log, and who is offered either. */
final class DoorReadTest extends TestCase
{
    /** One operation-log record laid out as the three F18s store it. */
    private function oplog(int $code, \DateTimeImmutable $at, int $param = 0, int $operator = 0): string
    {
        return pack('vCC', $operator, $code, 0).pack('V', Timestamp::encode($at)).pack('v4', $param, 0, 0, 0);
    }

    public function test_the_f18_operation_log_decodes_exit_buttons_alarms_and_start_ups(): void
    {
        $t = new \DateTimeImmutable('2026-11-16 15:44:46');
        $body = $this->oplog(0, $t->modify('-1 hour'))
            .$this->oplog(3, $t->modify('-1 hour +4 seconds'), 55)
            .$this->oplog(3, $t, 53);
        $raw = pack('V', strlen($body)).$body; // with its own length, as the terminal sends it

        $log = OperationLogCodec::decode($raw, '+03:00');

        $this->assertCount(3, $log);
        $this->assertSame('start-up', $log[0]['operation']);
        $this->assertSame('alarm', $log[1]['alarm']);
        $this->assertSame('exit button pressed', $log[2]['alarm']);
        $this->assertSame('2026-11-16 15:44:46', $log[2]['time']->format('Y-m-d H:i:s'));
        $this->assertNull($log[0]['alarm'], 'only a code 3 record carries an alarm type');
    }

    public function test_glass_doors_real_status_record_decodes_both_doors(): void
    {
        // Glass Door (inBIO460, 192.168.7.61), 2026-11-18 — traces-2026-11-18/c3-rtlog-01.json.
        $rt = RtLogCodec::decode(hex2bin('0202000002020000c800ff00faef7e33'), '+03:00');

        $this->assertSame([], $rt['events']);
        $this->assertSame('open', $rt['status']['doors'][1]['sensor']);
        $this->assertTrue($rt['status']['doors'][1]['open_too_long']);
        $this->assertSame('open', $rt['status']['doors'][2]['sensor']);
        $this->assertSame('unknown', $rt['status']['doors'][3]['sensor'], 'doors 3–4 are not wired');
        $this->assertNotNull($rt['status']['time']);
    }

    public function test_an_event_never_keeps_the_card_number(): void
    {
        // Synthetic: card 1234567, user 0, door 1, event 202 (exit button).
        $rec = pack('V', 1234567).pack('V', 0).pack('CCCC', 200, 1, 202, 2).pack('V', 0);

        $rt = RtLogCodec::decode($rec);

        $this->assertNull($rt['status']);
        $this->assertSame('opened by exit button', $rt['events'][0]['meaning']);
        $this->assertSame(1, $rt['events'][0]['door']);
        $this->assertTrue($rt['events'][0]['card']);
        $this->assertArrayNotHasKey('card_number', $rt['events'][0]);
    }

    public function test_doors_are_offered_only_where_they_were_read(): void
    {
        $f18 = TerminalModelFactory::for('F18')->capabilities();
        $this->assertSame(Capability::CONFIRMED, $f18->level(Capability::DOOR_EVENTS));
        $this->assertSame(Capability::NOT_IMPLEMENTED, $f18->level(Capability::DOOR_STATUS));

        foreach (['F22/ID', 'UA300/ID', 'X999'] as $model) {
            $caps = TerminalModelFactory::for($model)->capabilities();
            $this->assertSame(Capability::UNKNOWN, $caps->level(Capability::DOOR_EVENTS), $model);
            $this->assertSame(Capability::UNKNOWN, $caps->level(Capability::DOOR_STATUS), $model);
        }

        $this->assertSame(Capability::IMPLEMENTED, C3Capabilities::forModel('inBIO460')->level(Capability::DOOR_STATUS));
        // 2.25.1: the TF1700 stopped answering after RTLOG (host casebook DC-050).
        $this->assertSame(Capability::UNKNOWN, C3Capabilities::forModel('TF1700')->level(Capability::DOOR_EVENTS));
        $this->assertSame(Capability::UNKNOWN, C3Capabilities::forModel('TF1700')->level(Capability::DOOR_STATUS));
    }
}
