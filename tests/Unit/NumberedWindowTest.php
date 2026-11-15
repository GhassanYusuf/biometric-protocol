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
use Promoseven\Biometric\Contracts\TracksRequestIds;
use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Exception\TimeoutException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Session\Session;
use Promoseven\Biometric\Transport\BulkReader;
use Promoseven\Biometric\Value\DeviceConfig;
use Promoseven\Biometric\Value\Reply;

/**
 * The windowed read keeps only the current request's datagrams, each in its numbered place
 * (2.24.0; host app casebook DC-047).
 *
 * The device here answers the way four models did on 2026-11-15 (F18 ×2, F22, UA300, read-only
 * captures datagram-headers-01…04): READ_BUFFER → PREPARE_DATA, DATA datagrams numbered 0, 1, 2 …
 * in the session-id field, 1,024 bytes each, then ACK_OK — all carrying the request's reply id.
 *
 * The failure it fixes, seen on gems workshop (F18, internet): a window request goes unanswered
 * past the timeout, the reader asks again, and the FIRST request's answer then arrives after the
 * drain. Read in arrival order, that late answer filled the retry's window and left the retry's
 * own answer queued for the next request — every later window one behind. 16,276 of 16,276
 * punches decoded on one read, 819 on the next.
 */
final class NumberedWindowTest extends TestCase
{
    private const TABLE_BYTES = 40 * 1_500; // 60,000 bytes: four windows

    public function test_a_clean_read_returns_the_table(): void
    {
        $table = $this->table();

        $this->assertSame($table, $this->read(new NumberedDevice($table)));
    }

    public function test_a_late_answer_to_a_timed_out_request_does_not_shift_the_table(): void
    {
        $table = $this->table();
        $device = new NumberedDevice($table, lateAnswerAtOffset: 16_384);

        $this->assertSame($table, $this->read($device));
    }

    public function test_the_same_late_answer_breaks_a_read_that_ignores_the_headers(): void
    {
        /*
         * The evidence the headers are what fixes it: the same device, through a transport that
         * cannot say its request ids, takes the old arrival-order path and returns a table of the
         * right length with the wrong bytes in it — the shape gems workshop's 819-of-16,276 read had.
         */
        $table = $this->table();
        $device = new UnnumberedDevice($table, lateAnswerAtOffset: 16_384);

        $read = $this->read($device);
        $this->assertSame(strlen($table), strlen($read));
        $this->assertNotSame($table, $read);
    }

    public function test_reordered_and_repeated_datagrams_land_in_their_places(): void
    {
        $table = $this->table();
        $device = new NumberedDevice($table, shuffle: true, repeat: true);

        $this->assertSame($table, $this->read($device));
    }

    public function test_a_window_with_a_missing_datagram_is_asked_for_again(): void
    {
        /*
         * One datagram lost and another repeated: the byte count is reached, but the numbers have
         * a gap. That window is not these bytes in order, so it is refused and re-requested.
         */
        $table = $this->table();
        $device = new NumberedDevice($table, gapOnceAtOffset: 16_384);

        $this->assertSame($table, $this->read($device));
        $starts = array_column($device->windows, 0);
        $this->assertSame(2, count(array_keys($starts, 16_384)), 'The gapped window should be requested twice.');
    }

    public function test_a_slow_window_is_waited_for_not_asked_again(): void
    {
        /*
         * THE DC-047 FIX. On gems workshop a window request sometimes goes unanswered for just
         * over the 8 s timeout, and asking again makes the device serve the rest of the session
         * 20 bytes off. The reader waits for the first request's own answer, so the window is
         * requested once and the table is whole.
         */
        $table = $this->table();
        $device = new NumberedDevice($table, slowAnswerAtOffset: 16_384, shiftsAfterRepeat: true);

        $this->assertSame($table, $this->read($device));
        $this->assertSame([0, 16_384, 32_768, 49_152], array_column($device->windows, 0), 'No window may be requested twice.');
    }

    public function test_asking_again_for_a_slow_window_shifts_the_rest_on_this_firmware(): void
    {
        /*
         * The same device through a transport without request ids takes the 2.1.0 recovery — ask
         * again — and gets a table of the right length, shifted from that window on: the shape of
         * every bad gems workshop read (16,276 punches, 409 decodable).
         */
        $table = $this->table();
        $device = new UnnumberedDevice($table, slowAnswerAtOffset: 16_384, shiftsAfterRepeat: true);

        $read = $this->read($device);
        $this->assertSame(strlen($table), strlen($read));
        $this->assertSame(substr($table, 0, 16_384), substr($read, 0, 16_384));
        $this->assertNotSame($table, $read);
    }

    private function table(): string
    {
        $out = '';
        for ($i = 0; $i < self::TABLE_BYTES / 40; $i++) {
            $out .= str_pad((string) $i, 40, '.', STR_PAD_LEFT);
        }

        return $out;
    }

    private function read(Transport $transport): string
    {
        $config = new DeviceConfig(host: '127.0.0.1', bulkWindowRetries: 4);

        return (new BulkReader(new Session($transport, $config)))->read(Command::ATTLOG_RRQ, operation: 'attendance');
    }
}

/**
 * The same device through a transport with no request ids: BulkReader falls back to reading in
 * arrival order. Each send() answers with the first datagram queued, as a UDP socket does.
 */
class UnnumberedDevice implements Transport
{
    /** @var list<array{0:int,1:int}> */
    public array $windows = [];

    protected int $requestId = 0;

    /** @var list<Reply> datagrams waiting on the socket */
    private array $queue = [];

    /** @var list<Reply> an answer that will arrive with the next request, after any drain */
    private array $late = [];

    private array $spent = [];

    private int $shift = 0;

    public function __construct(
        private readonly string $table,
        private readonly ?int $lateAnswerAtOffset = null,
        private readonly bool $shuffle = false,
        private readonly bool $repeat = false,
        private readonly ?int $gapOnceAtOffset = null,
        /** Unanswered within the timeout, its answer arriving while the reader still listens. */
        private readonly ?int $slowAnswerAtOffset = null,
        /** The gems workshop firmware: once a window is asked for twice, it serves from 20 bytes on. */
        private readonly bool $shiftsAfterRepeat = false,
    ) {
    }

    public function send(int $command, string $data = ''): Reply
    {
        $id = ++$this->requestId;
        $this->queue = array_merge($this->queue, $this->late);
        $this->late = [];

        if ($command === Command::PREPARE_BUFFER) {
            $this->queue[] = new Reply(Command::ACK_OK, 0, 1, $id, "\x00".pack('V', strlen($this->table)));
        } elseif ($command === Command::READ_BUFFER) {
            ['start' => $start, 'size' => $size] = unpack('Vstart/Vsize', $data);
            if ($this->shiftsAfterRepeat && in_array($start, array_column($this->windows, 0), true)) {
                $this->shift = 20;
            }
            $this->windows[] = [$start, $size];
            $answer = $this->answer($id, $start, $size);

            if ($start === $this->slowAnswerAtOffset && ! isset($this->spent['slow'])) {
                // Unanswered within the timeout; the answer is on its way and arrives just after.
                $this->spent['slow'] = true;
                $this->queue = array_merge($this->queue, $answer);

                throw new TimeoutException('READ_BUFFER timed out', ['command' => $command]);
            }

            if ($start === $this->lateAnswerAtOffset && ! isset($this->spent['late'])) {
                // Unanswered within the timeout; the answer comes after the drain, with the retry.
                $this->spent['late'] = true;
                $this->late = $answer;

                throw new TimeoutException('READ_BUFFER timed out', ['command' => $command]);
            }
            $this->queue = array_merge($this->queue, $answer);
        } else {
            $this->queue[] = new Reply(Command::ACK_OK, 0, 1, $id, '');
        }

        return array_shift($this->queue);
    }

    /** @return list<Reply> PREPARE_DATA, the numbered DATA datagrams, ACK_OK */
    private function answer(int $id, int $start, int $size): array
    {
        $data = [];
        foreach (str_split(substr($this->table.str_repeat("\0", 40), $start + $this->shift, $size), 1024) as $seq => $chunk) {
            $data[] = new Reply(Command::DATA, 0, $seq, $id, $chunk);
        }
        if ($start === $this->gapOnceAtOffset && ! isset($this->spent['gap'])) {
            $this->spent['gap'] = true;
            $data[3] = $data[4]; // number 3 lost, number 4 arrives twice
        }
        if ($this->repeat) {
            $data[] = $data[0];
            $data[] = $data[count($data) - 2];
        }
        if ($this->shuffle) {
            mt_srand($start);
            shuffle($data);
        }

        return [new Reply(Command::PREPARE_DATA, 0, 1, $id, pack('VV', $size, 0)), ...$data,
            new Reply(Command::ACK_OK, 0, count($data), $id, '')];
    }

    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply
    {
        return array_shift($this->queue);
    }

    public function open(): void
    {
        $this->queue = [];
        $this->requestId = 0;
    }

    public function close(): void
    {
    }

    public function isOpen(): bool
    {
        return true;
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

/** A device that numbers its datagrams and echoes reply ids, through a transport that can say them. */
class NumberedDevice extends UnnumberedDevice implements TracksRequestIds
{
    public function lastRequestId(): int
    {
        return $this->requestId;
    }
}
