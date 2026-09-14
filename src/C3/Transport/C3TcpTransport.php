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

namespace Promoseven\Biometric\C3\Transport;

use Promoseven\Biometric\C3\Protocol\Command;
use Promoseven\Biometric\C3\Protocol\Frame;
use Promoseven\Biometric\Exception\ConnectionException;
use Promoseven\Biometric\Exception\TimeoutException;

/**
 * The C3 link: plain TCP, one frame out, one frame back.
 *
 * Deliberately NOT an implementation of Promoseven\Biometric\Contracts\Transport.
 * That contract is shaped around the standalone protocol — session ids assigned by
 * a handshake, unsolicited datagrams, raw drains — and satisfying it here would
 * mean a pile of methods that throw. The two families do not share a transport
 * abstraction because they do not share a transport model; pretending otherwise is
 * how a shared file acquires a branch per vendor (rule 15).
 *
 * TCP, always. The panels answer nothing on UDP 4370 — the inBIO460 returns ICMP
 * port unreachable — which is precisely why probing them with the standalone
 * library's UDP transport made them look dead for weeks.
 */
final class C3TcpTransport
{
    /** @var resource|null */
    private $socket = null;

    private int $sessionId = 0xFEFE;

    private int $requestNr = 0xFEFE;

    /** Set by the model once it has established which dialect this panel accepts. */
    private bool $sessionLess = true;

    public function __construct(
        private readonly string $host,
        private readonly int $port = 4370,
        private readonly float $timeout = 8.0,
    ) {}

    public function open(): void
    {
        if ($this->socket !== null) {
            return;
        }

        $socket = @stream_socket_client(
            "tcp://{$this->host}:{$this->port}",
            $errno,
            $errstr,
            $this->timeout,
        );

        if ($socket === false) {
            throw new ConnectionException(
                "Could not reach {$this->host}:{$this->port} over TCP: {$errstr} ({$errno}).",
            );
        }

        $this->socket = $socket;
        $this->sessionId = 0xFEFE;
        $this->requestNr = 0xFEFE;
    }

    public function close(): void
    {
        if ($this->socket !== null) {
            @fclose($this->socket);
            $this->socket = null;
        }
    }

    public function isOpen(): bool
    {
        return $this->socket !== null;
    }

    public function useSession(bool $sessionLess, int $sessionId = 0xFEFE): void
    {
        $this->sessionLess = $sessionLess;
        $this->sessionId = $sessionId;
    }

    public function isSessionLess(): bool
    {
        return $this->sessionLess;
    }

    /**
     * Sends one command and returns [replyCode, payload].
     *
     * The reply code is returned rather than thrown on, because a refusal is
     * information: the whole session-less path was found by reading what the
     * inBIO460 said no with (rule 17). Callers decide which codes are fatal.
     *
     * @return array{0:int, 1:string}
     */
    public function send(int $command, string $data = '', ?float $timeout = null): array
    {
        if ($this->socket === null) {
            throw new ConnectionException('C3 transport used before open().');
        }

        $frame = Frame::build(
            $command,
            $data,
            $this->sessionLess ? null : $this->sessionId,
            $this->requestNr,
        );

        fwrite($this->socket, $frame);
        $this->requestNr = ($this->requestNr + 1) & 0xFFFF;

        return $this->receive($command, $timeout ?? $this->timeout);
    }

    /** @return array{0:int, 1:string} */
    private function receive(int $command, float $timeout): array
    {
        $seconds = (int) $timeout;
        stream_set_timeout($this->socket, $seconds, (int) (($timeout - $seconds) * 1e6));

        $header = $this->readExactly(5);

        if (strlen($header) < 5) {
            throw new TimeoutException(
                sprintf('No C3 reply to command 0x%02X from %s within %.1fs.', $command, $this->host, $timeout),
            );
        }

        $bytes = array_values(unpack('C*', $header));
        $size = $bytes[3] + ($bytes[4] * 256);

        // payload + crc(2) + end(1)
        $rest = $this->readExactly($size + 3);

        if (strlen($rest) < $size + 3) {
            throw new TimeoutException(
                sprintf(
                    'Truncated C3 reply to command 0x%02X from %s: %d of %d bytes.',
                    $command,
                    $this->host,
                    strlen($rest),
                    $size + 3,
                ),
            );
        }

        $parsed = Frame::parse($header, $rest, ! $this->sessionLess);

        return [$parsed['command'], $parsed['payload']];
    }

    private function readExactly(int $want): string
    {
        $buffer = '';

        while (strlen($buffer) < $want) {
            $chunk = fread($this->socket, $want - strlen($buffer));

            if ($chunk === false || $chunk === '') {
                break;
            }

            $buffer .= $chunk;
        }

        return $buffer;
    }

    public function __destruct()
    {
        $this->close();
    }
}
