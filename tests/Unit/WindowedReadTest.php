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
use Promoseven\Biometric\Contracts\ProgressListener;
use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\TimeoutException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Session\Session;
use Promoseven\Biometric\Transport\BulkReader;
use Promoseven\Biometric\Value\DeviceConfig;
use Promoseven\Biometric\Value\Progress;
use Promoseven\Biometric\Value\Reply;

/**
 * The flow-controlled read: PREPARE_BUFFER, then one READ_BUFFER window at a time.
 *
 * WHY IT EXISTS, 2026-09-13. On a ZKTeco F22 the free-running push path completed a
 * 326,124-byte attendance table only occasionally — typically 54-75% arrived and then
 * the device fell silent for four seconds. The kernel was NOT the culprit:
 * /proc/net/snmp counted three RcvbufErrors across a read that lost ~145,000 bytes,
 * so the device was simply not sending the rest. Requesting 16 KB at a time removed
 * the race: 5 of 5, then 6 of 6 across three window sizes, decoding to all 8,153
 * records. Via the library, 18 of 18 reads across three tables.
 *
 * Support is PER TABLE on that firmware — attendance and templates stage, users does
 * not — so the negotiation and its fallback are as load-bearing as the fast path, and
 * are tested here as such.
 */
final class WindowedReadTest extends TestCase
{
    public function test_a_table_is_read_one_window_at_a_time(): void
    {
        $table = str_repeat('abcdefgh', 6_000); // 48,000 bytes: three 16 KB windows
        $transport = new WindowedTransport($table);

        $this->assertSame($table, $this->read($transport));

        // Three full windows, and every one of them explicitly requested. If this
        // ever becomes one request, the device is free-running again and the bug
        // this path exists to fix is back.
        $this->assertSame(
            [[0, 16384], [16384, 16384], [32768, 15232]],
            $transport->windows,
        );
    }

    public function test_a_final_short_window_asks_only_for_what_remains(): void
    {
        // Over-asking past the end is what makes a device pad, or stall waiting to
        // send bytes it does not have.
        $transport = new WindowedTransport(str_repeat('x', 16_384 + 10));

        $this->read($transport);

        $this->assertSame([[0, 16384], [16384, 10]], $transport->windows);
    }

    public function test_the_staged_buffer_is_always_released(): void
    {
        $transport = new WindowedTransport(str_repeat('x', 100));

        $this->read($transport);

        // Leaving the device holding a staged copy is how the NEXT read inherits
        // this one's buffer.
        $this->assertTrue($transport->freed, 'FREE_DATA was never sent.');
    }

    public function test_it_is_released_even_when_a_window_stalls(): void
    {
        $transport = new WindowedTransport(str_repeat('x', 40_000), stallAtOffset: 16_384);

        try {
            $this->read($transport);
            $this->fail('Expected a stalled window to throw.');
        } catch (ProtocolException $e) {
            $this->assertStringContainsString('Windowed transfer stalled', $e->getMessage());
            $this->assertSame(16_384, $e->context()['window_offset']);
        }

        $this->assertTrue($transport->freed, 'A failed read must still release the buffer.');
    }

    public function test_a_stalled_window_never_returns_a_short_table(): void
    {
        /*
         * The rule this package is built around: a partial answer that looks whole
         * is worse than an error. A short attendance table silently drops punches.
         */
        $transport = new WindowedTransport(str_repeat('x', 40_000), stallAtOffset: 16_384);

        $this->expectException(ProtocolException::class);

        $this->read($transport);
    }

    public function test_a_device_that_will_not_stage_falls_back_to_the_push_path(): void
    {
        /*
         * CONFIRMED on an F22: attendance and templates stage, users answers 4991.
         * A refusal is a normal answer, not an error, and must cost nothing but the
         * one round trip it took to ask.
         */
        $transport = new WindowedTransport('irrelevant', stagingRefused: true);

        $this->assertSame('pushed-table', $this->read($transport));
        $this->assertSame([], $transport->windows, 'No window should have been requested.');
    }

    public function test_an_empty_staged_table_is_not_an_error(): void
    {
        $transport = new WindowedTransport('');

        $this->assertSame('', $this->read($transport));
        $this->assertTrue($transport->freed);
    }

    public function test_every_window_reports_progress(): void
    {
        /*
         * The push path has to ration progress events, because time in a listener is
         * time not spent draining a burst that will not wait. Here the device sends
         * nothing until asked, so reporting per window is free — and a caller with a
         * progress bar should see it move.
         */
        $events = [];
        $transport = new WindowedTransport(str_repeat('x', 40_000));

        $this->read($transport, $events);

        $readings = array_map(static fn (Progress $p) => $p->bytesRead, $events);

        // The declared total first, then one reading per window.
        $this->assertSame([0, 16_384, 32_768, 40_000], $readings);
        $this->assertSame(40_000, $events[0]->bytesTotal);
    }

    public function test_a_transient_window_stall_is_retried_and_the_table_completes(): void
    {
        /*
         * THE FIX FOR A LOSSY PUBLIC LINK — CONFIRMED, Camelot F18, 2026-09-14.
         *
         * The middle window stalls once, exactly as a dropped burst does over the
         * internet. The staged copy is still valid, so re-requesting that offset
         * completes it, and the whole 40 KB table arrives intact.
         */
        $table = str_repeat('abcdefgh', 5_000); // 40,000 bytes: three windows
        $transport = new WindowedTransport($table, transientStallAtOffset: 16_384);

        $this->assertSame($table, $this->read($transport));
    }

    public function test_a_retried_window_does_not_restart_the_transfer_from_zero(): void
    {
        /*
         * The distinction the whole fix turns on. A stall used to abort the read and
         * read() restaged from offset 0, throwing away everything already pulled.
         * Now the SAME offset is re-requested and earlier windows are kept — so
         * offset 0 is asked for exactly once, and the stalled offset twice.
         */
        $transport = new WindowedTransport(str_repeat('x', 40_000), transientStallAtOffset: 16_384);

        $this->read($transport);

        $starts = array_map(static fn (array $w) => $w[0], $transport->windows);
        $this->assertSame(1, count(array_filter($starts, static fn ($s) => $s === 0)),
            'Offset 0 was re-read — the transfer restarted instead of resuming.');
        $this->assertSame(2, count(array_filter($starts, static fn ($s) => $s === 16_384)),
            'The stalled window should have been requested exactly twice.');
    }

    public function test_with_retries_disabled_a_stall_restarts_from_zero(): void
    {
        /*
         * bulkWindowRetries: 0 is the pre-2.1 behaviour. A stalled window throws,
         * and only the whole-request retry saves it — restaging from offset 0 and
         * re-reading everything already pulled. This is precisely the waste the
         * default retry count removes, and the contrast with
         * test_a_retried_window_does_not_restart_the_transfer_from_zero is the
         * evidence that the fix does what it claims.
         */
        $transport = new WindowedTransport(str_repeat('x', 40_000), transientStallAtOffset: 16_384);

        $this->assertSame(str_repeat('x', 40_000), $this->read($transport, retries: 0));

        $starts = array_map(static fn (array $w) => $w[0], $transport->windows);
        $this->assertSame(2, count(array_filter($starts, static fn ($s) => $s === 0)),
            'With retries disabled the whole transfer should restart, re-reading offset 0.');
    }

    public function test_a_timed_out_window_request_is_retried(): void
    {
        /*
         * A stall does not only look like silent data — the READ_BUFFER request or
         * its acknowledgement can be lost outright, so send() times out. That is the
         * same "the window did not arrive" condition and must be resumed the same
         * way, not allowed to unwind the whole transfer.
         */
        $table = str_repeat('abcdefgh', 5_000); // 40,000 bytes
        $transport = new WindowedTransport($table, requestTimeoutAtOffset: 16_384);

        $this->assertSame($table, $this->read($transport));
    }

    public function test_a_session_wedged_by_a_stall_recovers_on_a_fresh_session(): void
    {
        /*
         * THE CAMELOT F18 BEHAVIOUR, 2026-09-14. A stalled window wedges the whole
         * staged session — every retry at that offset fails too — and only a reopen
         * recovers it. The reader must reconnect, re-stage, and RESUME from the
         * offset, not restart from zero. Without this the read dies at ~490 KB of a
         * 1.66 MB table however high bulkWindowRetries is set.
         */
        $table = str_repeat('abcdefgh', 5_000); // 40,000 bytes
        $transport = new WindowedTransport($table, wedgeUntilReopenAtOffset: 16_384);

        $this->assertSame($table, $this->read($transport));
        $this->assertGreaterThanOrEqual(1, $transport->opens, 'The session was never reopened to recover.');

        $starts = array_map(static fn (array $w) => $w[0], $transport->windows);
        $this->assertSame(1, count(array_filter($starts, static fn ($s) => $s === 0)),
            'Offset 0 was re-read — it restarted instead of resuming on the fresh session.');
    }

    public function test_a_completed_read_survives_a_free_data_timeout(): void
    {
        /*
         * Releasing the staged copy is advisory. Over a lossy link its ACK can be
         * lost, and a fully-read 1.66 MB table must not be thrown away because the
         * release timed out — the next read opens a fresh session regardless.
         */
        $table = str_repeat('x', 40_000);
        $transport = new WindowedTransport($table, freeDataTimesOut: true);

        $this->assertSame($table, $this->read($transport));
        $this->assertTrue($transport->freed, 'FREE_DATA was still attempted.');
    }

    /** @param list<Progress> $events */
    private function read(Transport $transport, array &$events = [], int $retries = 4): string
    {
        $listener = new class($events) implements ProgressListener {
            /** @param list<Progress> $events */
            public function __construct(private array &$events)
            {
            }

            public function onProgress(Progress $progress): void
            {
                $this->events[] = $progress;
            }
        };

        $config = new DeviceConfig(host: '127.0.0.1', bulkWindowRetries: $retries);

        return (new BulkReader(new Session($transport, $config), $listener))
            ->read(Command::ATTLOG_RRQ, operation: 'attendance');
    }
}

/**
 * A device that stages a table and hands out windows, as an F22 does.
 *
 * Models the shape that matters: PREPARE_BUFFER answers with a size, each
 * READ_BUFFER is answered with PREPARE_DATA and then exactly the requested bytes
 * split across datagrams, and FREE_DATA releases it. Nothing here touches a network.
 */
class WindowedTransport implements Transport
{
    /** @var list<array{0:int,1:int}> Every [start, size] the reader asked for. */
    public array $windows = [];

    public bool $freed = false;

    /** Payload datagrams still owed for the window currently being served. */
    private array $pending = [];

    private bool $open = false;

    /** Offsets whose one-time transient stall has already been spent. */
    private array $transientStallSpent = [];

    /** Offsets whose one-time READ_BUFFER request timeout has already fired. */
    private array $requestTimeoutSpent = [];

    /** Times the transport has been (re)opened — a reopen is close()+open(). */
    public int $opens = 0;

    /** Generation at which the wedge offset was first hit, or null if not yet. */
    private ?int $wedgeStartedGeneration = null;

    public function __construct(
        private readonly string $table,
        private readonly bool $stagingRefused = false,
        private readonly ?int $stallAtOffset = null,
        private readonly ?int $transientStallAtOffset = null,
        private readonly bool $freeDataTimesOut = false,
        private readonly ?int $requestTimeoutAtOffset = null,
        private readonly ?int $wedgeUntilReopenAtOffset = null,
    ) {
    }

    public function send(int $command, string $data = ''): Reply
    {
        if ($command === Command::CONNECT || $command === Command::EXIT) {
            return $this->ack('');
        }

        if ($command === Command::PREPARE_BUFFER) {
            // A refusal, as the F22 gives for the users table.
            return $this->stagingRefused
                ? new Reply(4991, 0, 1, 1, '')
                : $this->ack("\x00" . pack('V', strlen($this->table)));
        }

        if ($command === Command::FREE_DATA) {
            $this->freed = true;

            // A device that never acknowledges the release, as a lossy link does.
            if ($this->freeDataTimesOut) {
                throw new TimeoutException('FREE_DATA timed out', ['command' => $command]);
            }

            return $this->ack('');
        }

        if ($command === Command::READ_BUFFER) {
            ['start' => $start, 'size' => $size] = unpack('Vstart/Vsize', $data);
            $this->windows[] = [$start, $size];

            // The request (or its reply) lost outright, once, at this offset — the
            // device is silent and send() times out rather than returning a reply.
            if ($start === $this->requestTimeoutAtOffset && ! isset($this->requestTimeoutSpent[$start])) {
                $this->requestTimeoutSpent[$start] = true;

                throw new TimeoutException('READ_BUFFER timed out', ['command' => $command]);
            }

            /*
             * A window that never delivers its bytes, to prove a stall cannot be
             * mistaken for a complete read.
             *
             * Keyed to the OFFSET, not to a call counter: read() retries the whole
             * request five times, so a counter would stall only the first attempt
             * and the read would then quietly succeed — testing the opposite of
             * what this is here to test.
             */
            /*
             * A window that stalls the FIRST time it is asked for, then serves its
             * bytes on the next request — the shape of a lossy public link, where a
             * burst is dropped in transit but the staged copy is intact and a
             * re-request at the same offset succeeds. Spent per offset so the retry
             * completes rather than looping forever.
             */
            $transientStall = $start === $this->transientStallAtOffset
                && ! isset($this->transientStallSpent[$start]);

            /*
             * A window that wedges the whole SESSION: it stalls on first contact and
             * keeps stalling for every retry in the same session, and only a reopen
             * (a new generation) clears it. This is the Camelot F18's actual
             * behaviour — a stall wedges the staged session and only a fresh session
             * recovers.
             */
            $wedged = false;
            if ($start === $this->wedgeUntilReopenAtOffset) {
                $this->wedgeStartedGeneration ??= $this->opens;
                $wedged = $this->opens <= $this->wedgeStartedGeneration;
            }

            if ($transientStall || $wedged) {
                $this->transientStallSpent[$start] = true;
                $this->pending = [];
            } elseif ($start === $this->stallAtOffset) {
                $this->pending = [];
            } else {
                $this->pending = str_split(substr($this->table, $start, $size), 1024);
            }

            return new Reply(Command::PREPARE_DATA, 0, 1, 1, pack('V', $size));
        }

        // The push path's request, reached only when staging was refused.
        return new Reply(Command::DATA, 0, 1, 1, 'pushed-table');
    }

    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply
    {
        $chunk = array_shift($this->pending);

        return $chunk === null ? null : new Reply(Command::DATA, 0, 1, 1, $chunk);
    }

    private function ack(string $data): Reply
    {
        return new Reply(Command::ACK_OK, 0, 1, 1, $data);
    }

    public function open(): void
    {
        $this->open = true;
        $this->opens++;
    }

    public function close(): void
    {
        $this->open = false;
    }

    public function isOpen(): bool
    {
        return $this->open;
    }

    public function sendRaw(string $packet): void
    {
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

    public function selectableStream()
    {
        return null;
    }
}
