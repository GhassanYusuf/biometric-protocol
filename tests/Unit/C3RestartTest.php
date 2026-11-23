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
use Promoseven\Biometric\C3\Client\Panel;
use Promoseven\Biometric\C3\Protocol\Command;
use Promoseven\Biometric\C3\Protocol\Frame;
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Value\DeviceConfig;

/** C3 restart (2.26.0): CONTROL_DEVICE operation 3, per vwout/zkaccess-c3-py. */
final class C3RestartTest extends TestCase
{
    public function test_the_restart_frame_is_control_device_operation_three(): void
    {
        $this->assertSame('0300000000', bin2hex(Command::restartPayload()));

        // Session-less, as the inBIO460 and TF1700 are spoken to: AA 01 05 | len 05 00 | 03 00 00 00 00 | crc | 55.
        $frame = bin2hex(Frame::build(Command::CONTROL_DEVICE, Command::restartPayload()));
        $this->assertStringStartsWith('aa010505000300000000', $frame);
        $this->assertStringEndsWith('55', $frame);
        $this->assertSame(26, strlen($frame), '13 bytes');
    }

    public function test_an_acknowledged_restart_returns_true_and_sends_no_disconnect(): void
    {
        [$server, $port] = $this->server();
        $panel = new Panel(new DeviceConfig(host: '127.0.0.1', port: $port, timeout: 2.0), 'inBIO460');
        $panel->open();
        $peer = stream_socket_accept($server, 2);
        fwrite($peer, Frame::build(Command::REPLY_OK)); // buffered before the request arrives

        $this->assertTrue($panel->restart());

        $sent = bin2hex(fread($peer, 64));
        $this->assertStringStartsWith('aa010505000300000000', $sent);
        $panel->close();
        stream_set_timeout($peer, 0, 200000);
        $this->assertSame('', (string) fread($peer, 64), 'nothing is sent to a rebooting panel');
    }

    public function test_a_dropped_link_is_not_an_acknowledgement(): void
    {
        [$server, $port] = $this->server();
        $panel = new Panel(new DeviceConfig(host: '127.0.0.1', port: $port, timeout: 2.0), 'inBIO460');
        $panel->open();
        fclose(stream_socket_accept($server, 2)); // the panel goes away without answering

        $this->assertFalse($panel->restart());
    }

    public function test_only_the_inbio460_offers_it_until_another_model_has_run_it(): void
    {
        $this->assertSame(Capability::IMPLEMENTED, C3Capabilities::forModel('inBIO460')->level(Capability::RESTART));
        $this->assertSame(Capability::UNKNOWN, C3Capabilities::forModel('TF1700')->level(Capability::RESTART));
        $this->assertSame(Capability::UNKNOWN, C3Capabilities::forModel('C3-400')->level(Capability::RESTART));
    }

    /** @return array{0:resource, 1:int} */
    private function server(): array
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $this->assertNotFalse($server, $errstr);
        $port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);

        return [$server, $port];
    }
}
