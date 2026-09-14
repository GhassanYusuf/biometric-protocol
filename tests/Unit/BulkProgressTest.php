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
use Promoseven\Biometric\Contracts\ProgressListener;
use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Session\Session;
use Promoseven\Biometric\Transport\BulkReader;
use Promoseven\Biometric\Value\DeviceConfig;
use Promoseven\Biometric\Value\Progress;
use Promoseven\Biometric\Value\Reply;

/**
 * Progress reporting for bulk transfers, with no device present.
 *
 * The behaviour worth pinning down is not "a number goes up" — it is that the
 * number is only ever something the device actually told us. A progress bar that
 * invents a total is the same class of lie as a "0 fingerprints" that means
 * "unknown" (rules 3 and 10), and it is just as unfalsifiable from the UI.
 */
class BulkProgressTest extends TestCase
{
    public function test_it_reports_the_declared_total_before_any_bytes_arrive(): void
    {
        $events = $this->readWith(totalBytes: 400, chunkSize: 100);

        // The first event exists so a caller learns the SCALE up front. Without it
        // the bar's first sighting is already part-way in and has to guess.
        $this->assertSame(0, $events[0]->bytesRead);
        $this->assertSame(400, $events[0]->bytesTotal);
        $this->assertSame(0, $events[0]->percent());
    }

    public function test_without_buffer_headroom_a_transfer_reports_only_start_and_end(): void
    {
        $events = $this->readWith(totalBytes: 400, chunkSize: 100);

        /*
         * NOT one event per chunk, and that is the point.
         *
         * MEASURED on a ZKTeco F18: reporting per chunk cost whole transfers.
         * This protocol has no flow control, so any work done while datagrams are
         * arriving overflows the socket buffer and the read fails with
         * "Incomplete transfer". A bar that ticks smoothly is not worth a sync that
         * loses punches. See BulkReader::emit().
         *
         * A transfer with no pauses therefore reports the total, then completion.
         */
        $this->assertSame([0, 400], array_map(fn (Progress $p) => $p->bytesRead, $events));
        $this->assertSame([0, 100], array_map(fn (Progress $p) => $p->percent(), $events));
        $this->assertTrue(end($events)->isComplete());
    }

    public function test_with_buffer_headroom_it_reports_every_chunk(): void
    {
        // The receive buffer can hold the whole transfer, so pausing to run a
        // listener cannot cost a datagram — the kernel keeps them for us. This is
        // the ext-sockets path, and it is the one that makes the bar smooth.
        $events = $this->readWith(totalBytes: 400, chunkSize: 100, receiveBuffer: 4 * 1024 * 1024);

        $this->assertSame([0, 100, 200, 300, 400], array_map(fn (Progress $p) => $p->bytesRead, $events));
        $this->assertSame([0, 25, 50, 75, 100], array_map(fn (Progress $p) => $p->percent(), $events));
    }

    public function test_a_buffer_smaller_than_the_transfer_falls_back_to_silence_only(): void
    {
        // 64KB of buffer against a 412KB table is the OS default, and the exact
        // condition under which per-chunk reporting was measured to destroy
        // transfers. Headroom must be compared against THIS transfer's size, not
        // merely be non-null.
        $events = $this->readWith(totalBytes: 400, chunkSize: 100, receiveBuffer: 128);

        $this->assertSame([0, 400], array_map(fn (Progress $p) => $p->bytesRead, $events));
    }

    public function test_an_unknown_buffer_is_treated_as_no_headroom(): void
    {
        // A build without ext-sockets reports null. Guessing generously here is how
        // punches get dropped, so null must take the cautious branch.
        $events = $this->readWith(totalBytes: 400, chunkSize: 100, receiveBuffer: null);

        $this->assertSame([0, 400], array_map(fn (Progress $p) => $p->bytesRead, $events));
    }

    public function test_a_stalled_transfer_reports_while_it_is_stalled(): void
    {
        // The case a progress bar actually exists for. A fast read needs no bar; a
        // read that pauses for seconds is the one an operator is staring at, and
        // sustained silence is exactly when it is safe to report.
        $transport = new FakeTransport(
            firstReply: $this->prepareReply(300),
            chunks: [str_repeat('x', 100), null, null, null, null, str_repeat('x', 200)],
        );

        $events = [];
        (new BulkReader($this->session($transport), $this->listener($events)))
            ->read(Command::ATTLOG_RRQ, operation: 'attendance');

        $reported = array_map(fn (Progress $p) => $p->bytesRead, $events);

        // 0 announced up front, 100 reported during the stall, 300 at completion.
        $this->assertSame([0, 100, 300], $reported);
    }

    public function test_percent_is_null_when_the_device_declared_no_total(): void
    {
        // Not 0, and not 100. "We were not told" is a third answer, and a caller
        // must be able to render it as indeterminate rather than as a real number.
        $progress = new Progress('attendance', bytesRead: 512, bytesTotal: 0);

        $this->assertNull($progress->percent());
        $this->assertNull($progress->fraction());
        $this->assertFalse($progress->isComplete());
    }

    public function test_an_overshooting_device_never_reports_more_than_one_hundred(): void
    {
        // CONFIRMED behaviour: this firmware keeps sending after the declared size
        // is satisfied. The reader stops, but a stray count must not yield 103%.
        $progress = new Progress('attendance', bytesRead: 4_120, bytesTotal: 4_000);

        $this->assertSame(100, $progress->percent());
        $this->assertSame(1.0, $progress->fraction());
    }

    public function test_an_inline_reply_reports_completion_rather_than_nothing(): void
    {
        // Small tables arrive whole, with no PREPARE_DATA and so no declared total.
        // A caller that saw no event at all would leave its bar stuck at zero
        // forever on a device with few records.
        $events = [];
        $transport = new FakeTransport(
            firstReply: new Reply(Command::DATA, 0, 1, 1, str_repeat('x', 80)),
            chunks: [],
        );

        (new BulkReader($this->session($transport), $this->listener($events)))
            ->read(Command::ATTLOG_RRQ, operation: 'attendance');

        $this->assertCount(1, $events);
        $this->assertTrue($events[0]->isComplete());
        $this->assertSame(80, $events[0]->bytesTotal);
    }

    public function test_the_operation_label_says_which_table_is_streaming(): void
    {
        $events = $this->readWith(totalBytes: 200, chunkSize: 200);

        $this->assertSame('attendance', $events[0]->operation);
    }

    public function test_a_listener_that_throws_never_fails_the_read(): void
    {
        // Progress is an aside. Losing a half-read attendance table because a UI
        // counter blew up would be far worse than a bar that stops moving.
        $transport = new FakeTransport(
            firstReply: $this->prepareReply(200),
            chunks: [str_repeat('x', 200)],
        );

        $listener = new class implements ProgressListener {
            public function onProgress(Progress $progress): void
            {
                throw new \RuntimeException('the UI exploded');
            }
        };

        $data = (new BulkReader($this->session($transport), $listener))
            ->read(Command::ATTLOG_RRQ, operation: 'attendance');

        $this->assertSame(200, strlen($data));
    }

    public function test_a_read_without_a_listener_still_works(): void
    {
        $transport = new FakeTransport(
            firstReply: $this->prepareReply(120),
            chunks: [str_repeat('x', 120)],
        );

        $data = (new BulkReader($this->session($transport)))->read(Command::ATTLOG_RRQ);

        $this->assertSame(120, strlen($data));
    }

    /* ------------------------------------------------------------------ helpers */

    /** @return list<Progress> */
    private function readWith(int $totalBytes, int $chunkSize, ?int $receiveBuffer = null): array
    {
        $chunks = str_split(str_repeat('x', $totalBytes), $chunkSize);
        $events = [];

        $transport = new FakeTransport($this->prepareReply($totalBytes), $chunks, $receiveBuffer);

        (new BulkReader($this->session($transport), $this->listener($events)))
            ->read(Command::ATTLOG_RRQ, operation: 'attendance');

        return $events;
    }

    /** PREPARE_DATA carries the total in its first 4 bytes. */
    private function prepareReply(int $size): Reply
    {
        return new Reply(Command::PREPARE_DATA, 0, 1, 1, pack('V', $size));
    }

    private function session(Transport $transport): Session
    {
        return new Session($transport, new DeviceConfig(host: '127.0.0.1'));
    }

    /** @param list<Progress> $events */
    private function listener(array &$events): ProgressListener
    {
        return new class($events) implements ProgressListener {
            /** @param list<Progress> $events */
            public function __construct(private array &$events)
            {
            }

            public function onProgress(Progress $progress): void
            {
                $this->events[] = $progress;
            }
        };
    }
}

/**
 * A transport that answers from a script instead of a socket.
 *
 * Enough to drive BulkReader: a handshake that succeeds, one reply to the table
 * request, then chunks handed out one poll at a time. Nothing here touches a
 * network, which is the rule for every test in this package.
 */
class FakeTransport implements Transport, HasReceiveBuffer
{
    private bool $open = false;

    private int $sessionId = 1;

    private int $chunkIndex = 0;

    /** @param list<string|null> $chunks A null entry is a poll that returned nothing. */
    public function __construct(
        private readonly Reply $firstReply,
        private readonly array $chunks,
        private readonly ?int $receiveBuffer = null,
    ) {
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
        // The handshake, and the goodbye BulkReader's reopen() sends first.
        if ($command === Command::CONNECT || $command === Command::EXIT) {
            return new Reply(Command::ACK_OK, 0, $this->sessionId, 1, '');
        }

        return $this->firstReply;
    }

    public function sendRaw(string $packet): void
    {
    }

    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply
    {
        if ($this->chunkIndex >= count($this->chunks)) {
            return null;
        }

        $chunk = $this->chunks[$this->chunkIndex++];

        // A null entry in the script is a poll that timed out with nothing on the
        // wire — how a real stall looks to the reassembler.
        if ($chunk === null) {
            return null;
        }

        return new Reply(Command::DATA, 0, $this->sessionId, 1, $chunk);
    }

    public function setReadTimeout(int $seconds, int $microseconds = 0): void
    {
    }

    public function selectableStream()
    {
        return null;
    }

    public function sessionId(): int
    {
        return $this->sessionId;
    }

    public function setSessionId(int $sessionId): void
    {
        $this->sessionId = $sessionId;
    }
}
