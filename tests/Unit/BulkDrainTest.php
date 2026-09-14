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
use Promoseven\Biometric\Contracts\HasReceiveBuffer;
use Promoseven\Biometric\Contracts\SupportsRawDrain;
use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Session\Session;
use Promoseven\Biometric\Transport\BulkReader;
use Promoseven\Biometric\Value\DeviceConfig;
use Promoseven\Biometric\Value\Reply;

/**
 * How BulkReader drains chunks, and what it says when it comes up short.
 *
 * REGRESSION, 2026-09-13. A 326,084-byte attendance read on Debian 12 (unprivileged
 * LXC, net.core.rmem_max = 212,992 and unraisable from inside the container) failed
 * repeatedly at 188,416 and 203,776 bytes — both just under the real buffer ceiling.
 * The receive buffer could not hold the table, so the only lever left was draining
 * faster than the device sends.
 *
 * MEASURED against a sender running flat out on loopback, 1,024-byte datagrams,
 * the buffer pinned at that host's 212,992-byte ceiling:
 *
 *   set timeout per poll + Packet::parse + Reply .... 67-69% of bytes captured
 *   timeout cached, still Packet::parse + Reply ..... 75-77%
 *   timeout cached, raw payload drain .............. 100%, 9 runs of 9
 *
 * A socket cannot be raced deterministically in a unit test, so these tests pin the
 * BEHAVIOUR the fast path must preserve rather than the timing that motivated it:
 * identical bytes either way, silence and empty-payload kept distinct, and a
 * transport without the interface still working. The timing evidence is the table
 * above and the docblock on SupportsRawDrain.
 */
final class BulkDrainTest extends TestCase
{
    private const CHUNKS = ['aaaa', 'bbbb', 'cc'];

    private const TOTAL = 10;

    public function test_the_fast_path_and_the_reply_path_return_identical_bytes(): void
    {
        // The whole justification for a second drain path is that it changes only
        // the cost, never the answer. If these two ever diverge, the fast path is
        // a bug and not an optimisation.
        $this->assertSame(
            'aaaabbbbcc',
            $this->read(DrainTransport::make(self::TOTAL, self::CHUNKS, rawDrain: false)),
        );

        $this->assertSame(
            'aaaabbbbcc',
            $this->read(DrainTransport::make(self::TOTAL, self::CHUNKS, rawDrain: true)),
        );
    }

    public function test_a_transport_without_the_interface_still_drains(): void
    {
        // SupportsRawDrain is optional, exactly like HasReceiveBuffer. A consumer
        // with its own transport must keep working untouched.
        $transport = DrainTransport::make(self::TOTAL, self::CHUNKS, rawDrain: false);

        $this->assertNotInstanceOf(SupportsRawDrain::class, $transport);
        $this->assertSame('aaaabbbbcc', $this->read($transport));
    }

    public function test_an_empty_payload_is_not_treated_as_silence(): void
    {
        /*
         * The distinction that makes the fast path safe to swap in.
         *
         * null  = the poll timed out. The device has gone quiet and the reader
         *         counts it toward giving up.
         * ''    = a datagram arrived carrying nothing. The device is still talking,
         *         so the idle counter must RESET.
         *
         * Collapse the two and a chatty-but-empty stretch looks like silence, and a
         * transfer gets abandoned while the device is still mid-table.
         */
        $chunks = ['aaaa', '', '', 'bbbb', '', 'cc'];

        foreach ([false, true] as $rawDrain) {
            $this->assertSame(
                'aaaabbbbcc',
                $this->read(DrainTransport::make(self::TOTAL, $chunks, $rawDrain)),
                $rawDrain ? 'raw drain path' : 'Reply path',
            );
        }
    }

    public function test_a_short_transfer_reports_the_buffer_that_caused_it(): void
    {
        /*
         * "Incomplete transfer: got X of Y" alone cannot tell a dropped datagram
         * (retrying helps) from a buffer smaller than the table (retrying is
         * hopeless and takes five attempts to say so). The numbers that separate
         * them belong in the exception, not in somebody's head.
         */
        $transport = DrainTransport::make(self::TOTAL, ['aaaa'], rawDrain: true, buffer: 8);

        try {
            $this->read($transport);
            $this->fail('Expected a short transfer to throw.');
        } catch (ProtocolException $e) {
            $context = $e->context();

            $this->assertSame(self::TOTAL, $context['expected']);
            $this->assertSame(4, $context['received']);

            // The diagnosis: the buffer could never have held the table.
            $this->assertSame(8, $context['receive_buffer_usable']);
            $this->assertLessThan($context['expected'], $context['receive_buffer_usable']);
        }
    }

    private function read(Transport $transport): string
    {
        return (new BulkReader(new Session($transport, new DeviceConfig(host: '127.0.0.1'))))
            ->read(Command::ATTLOG_RRQ, operation: 'attendance');
    }
}

/**
 * A scripted transport that can answer chunks either way.
 *
 * $rawDrain picks which contract the instance advertises, so one test can drive
 * both of BulkReader's drain paths over identical scripted data. Nothing here
 * touches a network, which is the rule for every test in this package.
 */
class DrainTransport implements Transport, HasReceiveBuffer
{
    protected int $chunkIndex = 0;

    private bool $open = false;

    /** @param list<string|null> $chunks A null entry is a poll that found silence. */
    public function __construct(
        private readonly int $declaredSize,
        protected readonly array $chunks,
        private readonly ?int $receiveBuffer = null,
    ) {
    }

    /**
     * Builds whichever variant the flag asks for.
     *
     * The base class deliberately does NOT implement SupportsRawDrain — that is
     * what makes it exercise BulkReader's fallback path. The subclass is the
     * opt-in, so the choice is a type and cannot be fudged by a flag.
     *
     * @param list<string|null> $chunks
     */
    public static function make(int $size, array $chunks, bool $rawDrain, ?int $buffer = null): Transport
    {
        return $rawDrain
            ? new RawDrainTransport($size, $chunks, $buffer)
            : new self($size, $chunks, $buffer);
    }

    public function receiveBufferBytes(): ?int
    {
        return $this->receiveBuffer;
    }

    public function open(): void
    {
        $this->open = true;
    }

    public function close(): void
    {
        $this->open = false;
    }

    public function isOpen(): bool
    {
        return $this->open;
    }

    public function send(int $command, string $data = ''): Reply
    {
        if ($command === Command::CONNECT || $command === Command::EXIT) {
            return new Reply(Command::ACK_OK, 0, 1, 1, '');
        }

        // PREPARE_DATA carries the declared total in its first four bytes.
        $this->chunkIndex = 0;

        return new Reply(Command::PREPARE_DATA, 0, 1, 1, pack('V', $this->declaredSize));
    }

    public function sendRaw(string $packet): void
    {
    }

    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply
    {
        $chunk = $this->nextChunk();

        return $chunk === null ? null : new Reply(Command::DATA, 0, 1, 1, $chunk);
    }

    public function setReadTimeout(int $seconds, int $microseconds = 0): void
    {
    }

    public function sessionId(): int
    {
        return 1;
    }

    public function setSessionId(int $sessionId): void
    {
    }

    /** No socket here, so there is nothing for stream_select() to watch. */
    public function selectableStream()
    {
        return null;
    }

    /** Hands out the next scripted chunk, then silence for ever after. */
    protected function nextChunk(): ?string
    {
        return $this->chunks[$this->chunkIndex++] ?? null;
    }
}

/** The same script, offered over the no-allocation contract. */
class RawDrainTransport extends DrainTransport implements SupportsRawDrain
{
    public function readRawPayload(float $pollSeconds = 0.5): ?string
    {
        return $this->nextChunk();
    }
}
