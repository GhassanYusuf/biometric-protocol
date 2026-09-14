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

namespace Promoseven\Biometric\Transport;

use Promoseven\Biometric\Contracts\HasReceiveBuffer;
use Promoseven\Biometric\Contracts\SupportsRawDrain;
use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Exception\ConnectionException;
use Promoseven\Biometric\Exception\TimeoutException;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Value\DeviceConfig;
use Promoseven\Biometric\Value\Reply;

/**
 * TCP transport for the ZKTeco standalone protocol.
 *
 * Same command packets as {@see UdpTransport}, but each is additionally wrapped in
 * the protocol's 8-byte TCP frame (magic 0x5050, reserved, uint32 length — see
 * Packet::wrapTcp) and the reply is a byte STREAM, not one datagram per packet, so
 * every read is reassembled by the declared length.
 *
 * ==========================================================================
 *  WHY THIS EXISTS — CONFIRMED, 2026-09-13/14
 * ==========================================================================
 *
 * The UDP transport has no flow control: the device streams a whole table as fast
 * as the wire allows, and on a lossy or high-latency link (a device on a public
 * IP) a burst is lost or the device stalls, and the read cannot complete. The
 * windowed read plus resume in BulkReader makes UDP *possible* over such a link
 * but not reliable — a stall wedges the session and the device refuses rapid
 * reconnects.
 *
 * TCP removes the entire failure class: the kernel retransmits lost segments and
 * back-pressure stops the device outrunning the reader. MEASURED on an F22 LAN, a
 * full 326,084-byte read returned in 0.03 s, 3 of 3. This is the correct transport
 * for any device reached across the internet.
 *
 * The socket receive buffer that dominates the UDP path is irrelevant here — TCP
 * flow control is the buffer — so receiveBufferBytes() reports null and BulkReader
 * simply uses the windowed path, which is what a remote device wants anyway.
 */
final class TcpTransport implements Transport, HasReceiveBuffer, SupportsRawDrain
{
    /** @var resource|null */
    private $socket = null;

    /** Bytes read off the stream but not yet consumed by a framed read. */
    private string $rxBuffer = '';

    private int $sessionId = 0;

    private int $replyId = 0;

    public function __construct(private readonly DeviceConfig $config)
    {
    }

    public function open(): void
    {
        $errno = 0;
        $errstr = '';

        $socket = @stream_socket_client(
            "tcp://{$this->config->host}:{$this->config->port}",
            $errno,
            $errstr,
            $this->config->timeout,
        );

        if ($socket === false) {
            throw new ConnectionException(
                "Unable to reach device at {$this->config->endpoint()} ({$errstr})",
                ['host' => $this->config->host, 'port' => $this->config->port, 'errno' => $errno],
            );
        }

        $this->socket = $socket;
        $this->rxBuffer = '';
        $this->sessionId = 0;
        $this->replyId = 0;

        stream_set_timeout($this->socket, (int) ceil($this->config->timeout));
    }

    public function close(): void
    {
        $this->rxBuffer = '';

        if ($this->socket !== null) {
            fclose($this->socket);
            $this->socket = null;
        }
    }

    public function isOpen(): bool
    {
        return $this->socket !== null;
    }

    public function send(int $command, string $data = ''): Reply
    {
        if ($this->socket === null) {
            throw new ConnectionException('Not connected to device.');
        }

        [$packet, $this->replyId] = Packet::build($command, $this->sessionId, $this->replyId, $data);

        if (@fwrite($this->socket, Packet::wrapTcp($packet)) === false) {
            throw new ConnectionException('Failed to write to device socket.', ['command' => $command]);
        }

        $body = $this->readFrame($this->config->timeout);

        if ($body === null) {
            throw new TimeoutException('Device connection timed out or closed unexpectedly.', [
                'command' => $command,
                'endpoint' => $this->config->endpoint(),
            ]);
        }

        return Reply::fromArray(Packet::parse($body));
    }

    public function sendRaw(string $packet): void
    {
        if ($this->socket === null) {
            return;
        }

        @fwrite($this->socket, Packet::wrapTcp($packet));
    }

    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply
    {
        if ($this->socket === null) {
            throw new ConnectionException('Not connected to device.');
        }

        $body = $this->readFrame($pollSeconds);

        return $body === null ? null : Reply::fromArray(Packet::parse($body));
    }

    /**
     * Fast path for bulk reassembly: one framed packet's payload, no Reply built.
     *
     * Mirrors UdpTransport::readRawPayload — the 8-byte command header is stripped
     * and the payload returned. A framed packet shorter than that header yields ''
     * (the device spoke, so it is not silence), and no frame at all yields null.
     */
    public function readRawPayload(float $pollSeconds = 0.5): ?string
    {
        if ($this->socket === null) {
            throw new ConnectionException('Not connected to device.');
        }

        $body = $this->readFrame($pollSeconds);

        if ($body === null) {
            return null;
        }

        return strlen($body) >= 8 ? substr($body, 8) : '';
    }

    /**
     * Reads exactly one TCP-framed command packet, or null on timeout/EOF.
     *
     * The 8-byte transport header carries the length of the packet that follows.
     * Because TCP is a stream, one fread may return part of a frame or several at
     * once, so the header and body are each read to an exact length, and any
     * surplus is kept in $rxBuffer for the next call. Once the header has arrived
     * the body is given the full request timeout — the rest of a frame follows its
     * header immediately on a healthy connection.
     */
    private function readFrame(float $timeout): ?string
    {
        $header = $this->readExact(8, $timeout);

        if ($header === null) {
            return null;
        }

        $unpacked = unpack('vmagic/vreserved/Vlength', $header);
        $length = $unpacked['length'];

        if ($length <= 0) {
            return '';
        }

        return $this->readExact($length, max($timeout, $this->config->timeout));
    }

    /**
     * Reads exactly $n bytes within $timeout, or null if they do not all arrive.
     *
     * Serves from $rxBuffer first, then the socket. On a short read the bytes that
     * did arrive are kept in $rxBuffer so a later call can continue rather than
     * losing them mid-frame.
     */
    private function readExact(int $n, float $timeout): ?string
    {
        $out = '';

        if ($this->rxBuffer !== '') {
            $take = min($n, strlen($this->rxBuffer));
            $out = substr($this->rxBuffer, 0, $take);
            $this->rxBuffer = substr($this->rxBuffer, $take);
        }

        $deadline = microtime(true) + $timeout;

        while (strlen($out) < $n) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                break;
            }

            $seconds = (int) $remaining;
            stream_set_timeout($this->socket, $seconds, (int) round(($remaining - $seconds) * 1_000_000));

            $chunk = @fread($this->socket, $n - strlen($out));

            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($this->socket);
                if ($meta['timed_out'] ?? false) {
                    break;
                }
                break; // EOF / closed
            }

            $out .= $chunk;
        }

        if (strlen($out) < $n) {
            // Keep what arrived so the next read continues this frame, not loses it.
            $this->rxBuffer = $out . $this->rxBuffer;

            return null;
        }

        return $out;
    }

    /**
     * TCP flow control IS the buffer, so there is no SO_RCVBUF number worth
     * reporting. Null keeps BulkReader on the conservative reassembly path for the
     * rare push read; the windowed path a remote device uses does not consult this.
     */
    public function receiveBufferBytes(): ?int
    {
        return null;
    }

    public function grantedReceiveBufferBytes(): ?int
    {
        return null;
    }

    public function setReadTimeout(int $seconds, int $microseconds = 0): void
    {
        if ($this->socket !== null) {
            stream_set_timeout($this->socket, $seconds, $microseconds);
        }
    }

    public function resetReadTimeout(): void
    {
        $this->setReadTimeout((int) ceil($this->config->timeout));
    }

    public function sessionId(): int
    {
        return $this->sessionId;
    }

    public function setSessionId(int $sessionId): void
    {
        $this->sessionId = $sessionId;
    }

    public function config(): DeviceConfig
    {
        return $this->config;
    }

    /** @return resource|null The TCP socket, for stream_select() over several devices. */
    public function selectableStream()
    {
        return $this->socket;
    }

    public function __destruct()
    {
        $this->close();
    }
}
