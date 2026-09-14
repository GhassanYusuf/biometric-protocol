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
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Transport\TcpTransport;
use Promoseven\Biometric\Value\DeviceConfig;

/**
 * TcpTransport's stream reassembly, with no device present.
 *
 * TCP is a byte stream: one read can return part of a frame or several frames at
 * once, so the risky new code is readExact/readFrame keeping frame boundaries. A
 * socket pair stands in for the device — the far end is written the exact bytes a
 * device would send, and the transport must reassemble them into whole packets.
 */
final class TcpTransportTest extends TestCase
{
    /** @return array{0:TcpTransport, 1:resource} [transport, farEnd] */
    private function pair(): array
    {
        $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
        [$near, $far] = $pair;

        $transport = new TcpTransport(new DeviceConfig(host: '127.0.0.1', transport: 'tcp'));
        $ref = new \ReflectionProperty(TcpTransport::class, 'socket');
        $ref->setAccessible(true);
        $ref->setValue($transport, $near);

        return [$transport, $far];
    }

    private function framedReply(int $command, string $data): string
    {
        // A device reply is a command packet (8-byte header + data) inside a TCP frame.
        $packet = pack('v4', $command, 0, 0, 1) . $data;

        return Packet::wrapTcp($packet);
    }

    public function test_it_reassembles_two_frames_arriving_in_one_read(): void
    {
        [$transport, $far] = $this->pair();

        // Both frames written back-to-back — the transport must return them one at a
        // time and buffer the surplus, not merge or drop the second.
        fwrite($far, $this->framedReply(Command::ACK_OK, 'FIRST') . $this->framedReply(Command::ACK_OK, 'SECOND'));

        $first = $transport->readUnsolicited(2.0);
        $second = $transport->readUnsolicited(2.0);

        $this->assertSame('FIRST', $first->data);
        $this->assertSame('SECOND', $second->data);
    }

    public function test_a_raw_payload_read_strips_the_command_header(): void
    {
        [$transport, $far] = $this->pair();

        fwrite($far, $this->framedReply(Command::DATA, 'PAYLOAD-BYTES'));

        $this->assertSame('PAYLOAD-BYTES', $transport->readRawPayload(2.0));
    }

    public function test_no_frame_within_the_poll_returns_null(): void
    {
        [$transport] = $this->pair();

        // Nothing written to the far end: a poll must time out to null, not hang or
        // invent a frame.
        $this->assertNull($transport->readUnsolicited(0.2));
    }

    public function test_a_send_frames_the_request_with_the_tcp_header(): void
    {
        [$transport, $far] = $this->pair();

        // Queue a reply so send() has something to read back.
        fwrite($far, $this->framedReply(Command::ACK_OK, ''));
        $transport->send(Command::CONNECT, '');

        // What the transport put on the wire must be a TCP-framed CONNECT.
        $sent = fread($far, 4096);
        $this->assertSame("\x50\x50\x82\x7d", substr($sent, 0, 4), 'Request was not TCP-framed with both magic words.');
        [$length, $packet] = Packet::unwrapTcp($sent);
        $this->assertSame($length, strlen($packet));
        $this->assertSame(Command::CONNECT, Packet::parse($packet)['command']);
    }
}
