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
use Promoseven\Biometric\Contracts\ProgressListener;
use Promoseven\Biometric\Contracts\SupportsRawDrain;
use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Exception\DeviceException;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Session\Session;
use Promoseven\Biometric\Value\Progress;
use Promoseven\Biometric\Value\Reply;

/**
 * Reassembles a chunked bulk transfer (users, attendance, templates).
 *
 * ===========================================================================
 *  THE SINGLE MOST IMPORTANT BEHAVIOUR IN THIS LIBRARY — do not "optimise" it
 * ===========================================================================
 *
 * EVERY bulk read opens a FRESH session. Not just retries — every single read.
 *
 * A completed bulk transfer can leave the device still pushing chunks. Reusing
 * the session makes the NEXT request return those leftovers, and they arrive as a
 * perfectly well-formed CMD_DATA reply — so the read "succeeds" with the wrong
 * table instead of failing loudly.
 *
 * CONFIRMED on real hardware (ZKTeco F18): getUsers() immediately followed by a
 * template read returned 1024 bytes of the PREVIOUS transfer. It decoded to
 * nothing, which made every employee report "fingerprints unknown" — a silent
 * wrong answer, not an error. A diagnostic probe reusing one session reported
 * "0 users" on a 19-user device for the same reason.
 *
 * Reconnecting costs one handshake per bulk read. That is the price of a correct
 * answer, and reads never consume data on the device so it is always safe.
 */
final class BulkReader
{
    /**
     * Whole-request retries. UDP drops datagrams; retrying the entire request is
     * safe because reading never mutates the device.
     */
    private const MAX_ATTEMPTS = 5;

    /**
     * Consecutive empty polls before a reassembly is abandoned. At 200ms each this
     * is ~8 seconds of silence — long enough for a real gap between chunks, short
     * enough not to hang a request.
     */
    private const MAX_EMPTY_POLLS = 40;

    /**
     * Consecutive empty polls before progress is reported from inside the loop.
     *
     * Three polls is ~600ms of proven silence. Anything less and we are guessing
     * that the device has paused; at three we KNOW it has, so a listener can run
     * without competing with datagrams for the receive buffer. See emit().
     */
    private const IDLE_POLLS_BEFORE_REPORT = 3;

    /**
     * Bytes requested per READ_BUFFER window on the flow-controlled path.
     *
     * 16 KB because it is comfortably below any plausible socket receive buffer —
     * including the 64 KB platform default and the 208 KB ceiling of an
     * unprivileged container — so a window physically cannot outrun the buffer no
     * matter how fast the device sends it.
     *
     * MEASURED on an F22 with a 326,124-byte attendance table: 16 KB, 32 KB and
     * 64 KB windows all completed 100% of the time and all took 6.4-7.4 seconds,
     * so a larger window buys no speed and only narrows the safety margin. The
     * cost is per-window round trips, and the device's own staging time dominates
     * those.
     */
    private const WINDOW_BYTES = 16 * 1024;

    /**
     * Consecutive silent polls tolerated while draining ONE window.
     *
     * Much smaller than MAX_EMPTY_POLLS because a window is bounded and already
     * acknowledged: the device said it would send exactly this many bytes, so real
     * silence here means the window failed, not that the device is thinking.
     */
    private const MAX_EMPTY_POLLS_PER_WINDOW = 10;

    /**
     * Datagrams drained from the socket before a stalled window is re-requested.
     *
     * A stalled window is at most WINDOW_BYTES / smallest-datagram of stragglers,
     * comfortably under this. The bound only exists so a device that never pauses
     * cannot turn the drain into an unbounded read. See drainStaleDatagrams().
     */
    private const MAX_STALE_DRAIN = 64;

    /**
     * Hard ceiling on fresh-session re-stages during one windowed read.
     *
     * A device serving ~490 KB per session needs ~4 re-stages for a 1.66 MB table,
     * so 64 is generous headroom. The real guard is the progress check — a re-stage
     * that advances nothing is not retried — and this only stops a pathological
     * device that advances a sliver per session from reconnecting forever.
     */
    private const MAX_RESTAGES = 64;

    /**
     * Reconnect attempts, and the base backoff between them, when re-staging a
     * wedged windowed read on a fresh session.
     *
     * CONFIRMED on Camelot: the device refuses a session reopened immediately after
     * the previous one closed and its handshake times out, but recovers within a few
     * seconds. The backoff scales with the attempt (base × attempt).
     */
    private const RECONNECT_ATTEMPTS = 6;

    private const RECONNECT_BACKOFF_US = 3_000_000;

    private readonly Transport $transport;

    /**
     * Set for the duration of one read() so the reassembler can label its events
     * without threading the name through every private method.
     */
    private string $operation = 'bulk';

    /** Which whole-request attempt is running; a retry restarts the byte count. */
    private int $attempt = 1;

    /**
     * Last value handed to the listener, so the same reading is not sent twice.
     *
     * With buffer headroom the final chunk already reports completion, and the
     * post-loop emit would repeat it. Harmless on a bar, but a listener that
     * counts events or writes a row should not see phantom duplicates.
     */
    private ?int $lastEmitted = null;

    public function __construct(
        private readonly Session $session,
        private readonly ?ProgressListener $progress = null,
    ) {
        $this->transport = $session->transport();
    }

    /**
     * Requests a table and returns its raw bytes.
     *
     * @param int    $command     e.g. Command::USERTEMP_RRQ, Command::ATTLOG_RRQ
     * @param string $requestData selector payload, e.g. pack('C', Command::FCT_FINGERTMP)
     */
    public function read(int $command, string $requestData = '', string $operation = 'bulk'): string
    {
        $lastException = null;
        $this->operation = $operation;

        for ($attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
            $this->attempt = $attempt;
            $this->lastEmitted = null; // a retry restarts the count from zero

            try {
                // Fresh session for EVERY attempt, including the first. See the
                // class docblock — this is not defensive, it is load-bearing.
                $this->session->reopen();

                $data = $this->readOnce($command, $requestData);

                /*
                 * CONFIRMED: the device keeps sending after we have taken the bytes we
                 * asked for. We stop as soon as the declared size is satisfied, so
                 * trailing chunks stay queued in the socket.
                 *
                 * Mark the session dirty so the NEXT command reopens instead of
                 * reading one of those chunks as its own reply. Without this, a probe
                 * issued after a bulk read returns the PREVIOUS request's answer —
                 * observed as template slot 7 reporting slot 6's 1304-byte template.
                 */
                $this->session->markDirty();

                return $data;
            } catch (DeviceException $e) {
                $lastException = $e;
            }
        }

        throw $lastException ?? new ProtocolException('Bulk data transfer failed after retries.', [
            'command' => Command::name($command),
            'attempts' => self::MAX_ATTEMPTS,
        ]);
    }

    private function readOnce(int $command, string $requestData): string
    {
        /*
         * Prefer the flow-controlled path, and NEGOTIATE it per read.
         *
         * Support is per table rather than per device on this firmware family —
         * the same F22 stages attendance and templates but refuses users — so the
         * only correct test is to ask for the table we actually want and see what
         * comes back. Anything other than an acknowledgement means fall back.
         */
        $windowed = $this->readWindowed($command, $requestData);

        if ($windowed !== null) {
            return $windowed;
        }

        $reply = $this->transport->send($command, $requestData);

        // Success with nothing to send — a genuinely empty table.
        if ($reply->isAccepted() && $reply->length() === 0) {
            return '';
        }

        if (! $reply->isPreparingData() && ! $reply->isInlineData()) {
            throw new ProtocolException(
                "Unexpected reply {$reply->commandName()} while requesting bulk data.",
                ['command' => Command::name($command), 'reply' => $reply->command],
            );
        }

        // Small tables arrive whole in the first packet. There was never a
        // PREPARE_DATA and so never a declared total — report the transfer as done
        // with the size we actually received, rather than leaving a caller's bar
        // stuck at nothing because no chunk loop ever ran.
        if ($reply->isInlineData()) {
            $this->emit(strlen($reply->data), strlen($reply->data));

            return $reply->data;
        }

        $size = $reply->declaredSize();

        // Emit once at zero so a caller knows the TOTAL before any bytes arrive.
        // Without this the first event a UI sees is already part-way in, and the
        // bar has to guess its own scale.
        $this->emit(0, $size);

        // The request/reply timeout is seconds long, but here we are reassembling
        // many back-to-back chunks — a brief gap between them is normal and must
        // not cost a multi-second stall each time. Poll fast, restore afterwards.
        $this->transport->setReadTimeout(0, 200_000);

        try {
            $buffer = $this->reassemble($size);

            // The loop only reports during idle windows, so a transfer that never
            // paused has reported nothing since the initial zero. Close it out.
            $this->emit(strlen($buffer), $size);
        } finally {
            if ($this->transport instanceof UdpTransport) {
                $this->transport->resetReadTimeout();
            }
        }

        if (strlen($buffer) < $size) {
            /*
             * Carry the buffer figures into the exception.
             *
             * A short transfer has two common causes that look identical from the
             * message alone: a dropped datagram on a healthy link (retry fixes it),
             * and a receive buffer smaller than the table (retry NEVER fixes it, it
             * just burns all five attempts and takes five times as long to fail).
             *
             * The second is diagnosable only by comparing the usable buffer against
             * the declared size, so put both in the context rather than making the
             * next operator reproduce this by hand. 'receive_buffer_usable' below
             * 'expected' means raise net.core.rmem_max on the HOST — inside an
             * unprivileged container that file is read-only. A null means
             * ext-sockets is missing and the socket is on the platform default.
             */
            throw new ProtocolException(
                'Incomplete transfer: got ' . strlen($buffer) . " of {$size} bytes.",
                [
                    'command' => Command::name($command),
                    'expected' => $size,
                    'received' => strlen($buffer),
                    'receive_buffer_usable' => $this->receiveBufferBytes(),
                    'receive_buffer_granted' => $this->transport instanceof UdpTransport
                        ? $this->transport->grantedReceiveBufferBytes()
                        : null,
                ],
            );
        }

        return substr($buffer, 0, $size);
    }

    /**
     * Reads a table one explicitly-requested window at a time.
     *
     * ==========================================================================
     *  THE FIX FOR A DEVICE THAT STOPS MID-BURST — CONFIRMED, F22, 2026-09-13
     * ==========================================================================
     *
     * The push path below has no flow control: the device is asked once and then
     * streams the whole table as fast as the wire allows. On a 326,124-byte
     * attendance table that is a single ~33ms burst at close to line rate, and the
     * reader has to keep up for all of it or lose bytes that are never resent.
     *
     * MEASURED on that device, push path, 20 attempts: complete transfers were the
     * exception. Typical results were 54-75% of the table followed by four seconds
     * of total silence, with occasional clean 100% runs — the signature of a race,
     * not of a broken link.
     *
     * IMPORTANTLY, THE KERNEL WAS NOT THE ONE DROPPING IT. /proc/net/snmp counted
     * THREE RcvbufErrors across a read that lost ~145,000 bytes. A bigger socket
     * buffer was never going to fix this, which is why raising SO_RCVBUF and
     * draining faster both helped only marginally: the device simply stops sending.
     *
     * This path removes the race instead of trying to win it. PREPARE_BUFFER asks
     * the device to stage the table and report its size; READ_BUFFER then requests
     * ONE 16 KB window at a time, so the device never has more outstanding than we
     * asked for and there is nothing to outrun. Same device, same table: 5 of 5
     * complete, then 6 of 6 across three window sizes, decoding to all 8,153
     * records.
     *
     * Returns NULL — not an exception — when the device will not stage this table,
     * which is a normal answer and the caller's cue to use the push path.
     */
    private function readWindowed(int $command, string $requestData): ?string
    {
        $reply = $this->sendPrepareBuffer($command, $requestData);

        // Not an error worth raising: this device does not stage this table.
        if (! $reply->isAccepted() || strlen($reply->data) < 5) {
            return null;
        }

        // uint32 total, one byte into the acknowledgement's payload.
        $size = unpack('V', substr($reply->data, 1, 4))[1];

        if ($size === 0) {
            $this->emit(0, 0);
            $this->transport->send(Command::FREE_DATA);

            return '';
        }

        $this->emit(0, $size);

        $buffer = '';

        try {
            $retries = $this->session->config()->bulkWindowRetries;
            $restages = 0;
            $progressAtLastRestage = -1;

            while (strlen($buffer) < $size) {
                $offset = strlen($buffer);
                $want = min(self::WINDOW_BYTES, $size - $offset);
                $window = $this->readWindow($offset, $want);

                /*
                 * RESUME a stalled window instead of losing the whole transfer.
                 *
                 * The device has STAGED the table (PREPARE_BUFFER) and holds it
                 * until FREE_DATA, so READ_BUFFER can ask for the SAME offset again —
                 * the bytes already pulled stay in $buffer. Before each retry, drain
                 * any late datagrams from the failed window so the retry's reply is
                 * not confused with the previous window's stragglers.
                 */
                for ($retry = 1; $window === null && $retry <= $retries; $retry++) {
                    $this->drainStaleDatagrams();
                    $window = $this->readWindow($offset, $want);
                }

                /*
                 * RE-STAGE ON A FRESH SESSION when retries at one offset are spent.
                 *
                 * CONFIRMED on the Camelot F18 over a public IP (2026-09-14): a window
                 * that stalls wedges the whole STAGED SESSION — every retry at the
                 * same offset then fails too, and the read dies at ~490 KB of a 1.66
                 * MB table. Re-requesting inside the wedged session cannot recover it;
                 * a fresh session can. So reopen (re-handshake + auth), stage the
                 * table again — PREPARE_BUFFER always stages the whole table, and
                 * READ_BUFFER is offset-addressed — and resume from where we stopped.
                 * The device serves ~490 KB per session, so a 1.66 MB table completes
                 * in a handful of reconnects instead of never.
                 *
                 * Guarded two ways against an infinite loop: a re-stage that yields NO
                 * further progress before the next stall is not retried, and a hard
                 * ceiling caps the total. A LAN never reaches any of this.
                 */
                if ($window === null && $retries > 0 && $offset > $progressAtLastRestage && $restages < self::MAX_RESTAGES) {
                    $restages++;
                    $progressAtLastRestage = $offset;
                    $this->emit(strlen($buffer), $size); // record the resume point
                    $this->reopenAndRestage($command, $requestData, $size);

                    continue; // retry the same offset in the fresh session
                }

                if ($window === null) {
                    // Out of retries and re-stages. A window that will not complete is
                    // a failed read, not a reason to silently return a short table.
                    throw new ProtocolException(
                        'Windowed transfer stalled: got ' . strlen($buffer) . " of {$size} bytes"
                            . " after {$retries} window retries and {$restages} re-stages.",
                        [
                            'command' => Command::name($command),
                            'expected' => $size,
                            'received' => strlen($buffer),
                            'window_offset' => $offset,
                            'window_bytes' => $want,
                            'window_retries' => $retries,
                            'restages' => $restages,
                        ],
                    );
                }

                $buffer .= $window;

                /*
                 * Report on every window, unconditionally.
                 *
                 * The push path has to ration progress events because time spent in
                 * a listener is time not spent draining a burst that will not wait
                 * (see emit()). Here the device sends nothing until asked, so a
                 * listener can take as long as it likes between windows and cost
                 * exactly nothing. This is the one place in the library where a
                 * smooth progress bar is free.
                 */
                $this->emit(strlen($buffer), $size);
            }
        } finally {
            // Release the staged copy even when the read failed, so the next
            // attempt stages cleanly rather than inheriting this one's buffer.
            //
            // Best-effort: over a lossy link the FREE_DATA acknowledgement can
            // itself time out. That must NOT fail an otherwise-complete read, nor
            // (from a finally) mask a real exception the try block is already
            // throwing. The next read opens a fresh session regardless, so a
            // buffer left staged here is harmless — see this class's docblock.
            try {
                $this->transport->send(Command::FREE_DATA);
            } catch (DeviceException) {
                // swallow: releasing is advisory, the fresh-session rule covers it
            }
        }

        return substr($buffer, 0, $size);
    }

    /**
     * Requests one window and returns exactly its bytes, or null if it stalled.
     *
     * The device answers a READ_BUFFER either inline (small windows come back in
     * the reply itself) or with a PREPARE_DATA followed by datagrams, and both
     * shapes are normal. A trailing acknowledgement follows the datagram form; it
     * is consumed and discarded, because leaving it queued makes it the answer to
     * the NEXT request — the same class of bug the fresh-session rule in this
     * class's docblock exists to prevent.
     */
    private function readWindow(int $start, int $want): ?string
    {
        /*
         * A window request that gets no reply is a stall, not a fatal error.
         *
         * Over a lossy link the READ_BUFFER request or its acknowledgement can be
         * lost outright, and send() then times out. That is the same failure a
         * silent data phase is — the window did not arrive — so return null and let
         * the caller re-request the offset, rather than letting a TimeoutException
         * unwind the whole (resumable) transfer.
         */
        try {
            $reply = $this->transport->send(Command::READ_BUFFER, pack('VV', $start, $want));
        } catch (DeviceException) {
            return null;
        }

        if ($reply->isInlineData()) {
            return strlen($reply->data) >= $want ? substr($reply->data, 0, $want) : null;
        }

        if (! $reply->isPreparingData()) {
            return null;
        }

        $fastDrain = $this->transport instanceof SupportsRawDrain ? $this->transport : null;

        $this->transport->setReadTimeout(0, 200_000);

        try {
            $window = '';
            $emptyPolls = 0;

            while (strlen($window) < $want && $emptyPolls < self::MAX_EMPTY_POLLS_PER_WINDOW) {
                $chunk = $fastDrain !== null
                    ? $fastDrain->readRawPayload(0.2)
                    : $this->transport->readUnsolicited(0.2)?->data;

                if ($chunk === null) {
                    $emptyPolls++;

                    continue;
                }

                $emptyPolls = 0;
                $window .= $chunk;
            }
        } finally {
            if ($this->transport instanceof UdpTransport) {
                $this->transport->resetReadTimeout();
            }
        }

        if (strlen($window) < $want) {
            return null;
        }

        // The window's own acknowledgement. Absent on some replies, so a miss here
        // is not an error — only leaving it queued would be.
        $this->transport->readUnsolicited(0.2);

        return substr($window, 0, $want);
    }

    /**
     * Empties the socket of datagrams left over from a stalled window.
     *
     * A window that stalled part-way may still have datagrams arriving or already
     * queued. Before re-requesting that offset, they must be cleared, or the retry's
     * READ_BUFFER reply is read as one of the previous window's stragglers — the
     * same "answer to the last question" class of bug the fresh-session rule guards
     * against. Bounded so a device that streams without pause cannot spin here.
     */
    private function drainStaleDatagrams(): void
    {
        for ($i = 0; $i < self::MAX_STALE_DRAIN; $i++) {
            if ($this->transport->readUnsolicited(0.2) === null) {
                return;
            }
        }
    }

    /**
     * Sends PREPARE_BUFFER for a table and returns the raw reply.
     *
     * PREPARE_BUFFER payload: uint8(1), uint16(command), uint32(fct), uint32(ext).
     * The fct selector is how tables that share a command are told apart — DB_RRQ is
     * templates only because FCT_FINGERTMP says so — so it must be carried across or
     * the device stages the wrong table. This library encodes that selector as a
     * single leading byte, hence the width conversion rather than a pass-through.
     */
    private function sendPrepareBuffer(int $command, string $requestData): Reply
    {
        $fct = $requestData === '' ? 0 : ord($requestData[0]);

        return $this->transport->send(
            Command::PREPARE_BUFFER,
            pack('C', 1) . pack('v', $command) . pack('V', $fct) . pack('V', 0),
        );
    }

    /**
     * Reopens the session and stages the table again, to resume a wedged transfer.
     *
     * Releases the old staged copy (best effort — the wedged session may not answer),
     * re-handshakes, and re-stages. READ_BUFFER is offset-addressed and PREPARE_BUFFER
     * always stages the whole table, so the caller resumes from its current offset
     * against the fresh copy. A re-stage that is refused, or that reports a different
     * size, is a real error: the table changed under us or the device will no longer
     * serve it.
     */
    private function reopenAndRestage(int $command, string $requestData, int $expectedSize): void
    {
        try {
            $this->transport->send(Command::FREE_DATA);
        } catch (DeviceException) {
            // The wedged session may not answer; the reopen abandons it anyway.
        }

        /*
         * Reconnect with backoff.
         *
         * CONFIRMED on Camelot (2026-09-14): the device refuses a session opened
         * seconds after the previous one closed, and its handshake then times out
         * (command 1000). It recovers on its own within a few seconds, so a straight
         * reopen fails but a short wait and a second try succeeds. Without this the
         * reconnect-resume trades a wedged data phase for a refused handshake and the
         * transfer still dies.
         */
        $lastError = null;
        for ($attempt = 1; $attempt <= self::RECONNECT_ATTEMPTS; $attempt++) {
            try {
                $this->session->reopen();
                $lastError = null;
                break;
            } catch (DeviceException $e) {
                $lastError = $e;
                if ($attempt < self::RECONNECT_ATTEMPTS) {
                    usleep(self::RECONNECT_BACKOFF_US * $attempt);
                }
            }
        }

        if ($lastError !== null) {
            throw $lastError;
        }

        $reply = $this->sendPrepareBuffer($command, $requestData);

        if (! $reply->isAccepted() || strlen($reply->data) < 5) {
            throw new ProtocolException(
                'Re-staging refused while resuming a windowed transfer.',
                ['command' => Command::name($command)],
            );
        }

        $size = unpack('V', substr($reply->data, 1, 4))[1];

        if ($size !== $expectedSize) {
            throw new ProtocolException(
                "Staged size changed mid-transfer: was {$expectedSize}, now {$size}.",
                ['command' => Command::name($command), 'expected' => $expectedSize, 'restaged' => $size],
            );
        }
    }

    private function reassemble(int $size): string
    {
        $buffer = '';
        $emptyPolls = 0;

        /*
         * Can we afford to report on every chunk?
         *
         * Only if the kernel can hold the WHOLE remaining transfer while we are not
         * reading. When the receive buffer is at least the declared size, a pause
         * cannot cost a datagram — the buffer absorbs everything the device sends
         * meanwhile — so the listener may run freely and the bar is smooth.
         *
         * Otherwise we are back on the 64 KB default against a 412 KB table, where
         * any pause loses data permanently, and reporting falls back to proven
         * silence only. See emit().
         */
        // USABLE bytes, already corrected for the platform's reporting convention
        // (Linux reports double) — see HasReceiveBuffer::receiveBufferBytes(). This
        // comparison is the whole safety interlock, so it must never be fed a raw
        // SO_RCVBUF readback: that reads as headroom we do not have and costs the
        // transfer.
        $headroom = $this->receiveBufferBytes();
        $canReportFreely = $headroom !== null && $headroom >= $size;

        /*
         * Drain without building a Reply per datagram where the transport allows
         * it. Resolved ONCE, outside the loop: an instanceof per kilobyte is the
         * kind of cost this whole path exists to remove.
         *
         * This is not a micro-optimisation. On a receive buffer smaller than the
         * table — which is every host that cannot raise net.core.rmem_max, LXC
         * containers included — the per-datagram allocation is the difference
         * between a complete read and one that dies about two thirds in. See
         * SupportsRawDrain for the measured figures.
         */
        $fastDrain = $this->transport instanceof SupportsRawDrain ? $this->transport : null;

        while (strlen($buffer) < $size && $emptyPolls < self::MAX_EMPTY_POLLS) {
            // Both paths yield the payload bytes, or null for a poll that found
            // silence. readUnsolicited()'s Reply is discarded except for ->data,
            // which is precisely why the fast path can skip building it.
            $chunk = $fastDrain !== null
                ? $fastDrain->readRawPayload(0.2)
                : $this->transport->readUnsolicited(0.2)?->data;

            if ($chunk === null) {
                $emptyPolls++;

                // Proven silence: safe to report even with no buffer headroom.
                if ($emptyPolls === self::IDLE_POLLS_BEFORE_REPORT) {
                    $this->emit(strlen($buffer), $size);
                }

                continue;
            }

            $emptyPolls = 0;
            $buffer .= $chunk;

            // Per-chunk reporting ONLY with buffer headroom. Without it this line
            // is the difference between a smooth bar and a failed sync — see
            // emit(), which carries the measurements.
            if ($canReportFreely) {
                $this->emit(strlen($buffer), $size);
            }
        }

        return $buffer;
    }

    /**
     * Hands one progress event to the listener, if there is one.
     *
     * ==========================================================================
     *  CALLED ONLY FROM IDLE WINDOWS — CONFIRMED ON REAL HARDWARE (ZKTeco F18)
     * ==========================================================================
     *
     * The first version of this called emit() once per received chunk. That is the
     * obvious place for it and it is WRONG, because this transfer has no flow
     * control: the device streams UDP datagrams as fast as it can and anything not
     * read promptly overflows the socket receive buffer and is gone. Time spent
     * inside the loop is data lost.
     *
     * MEASURED on a 412,084-byte / 10,302-record attendance table, reading the same
     * device repeatedly:
     *
     *   no listener at all ......................... 4 of 4 transfers complete
     *   a listener doing nothing at all ............ 2 of 3 complete
     *   a listener doing one throttled DB UPDATE ... 0 of 3 complete
     *                                                ("Incomplete transfer: got
     *                                                 89,088 of 412,084 bytes")
     *
     * The failures were not a slow bar, they were a FAILED SYNC.
     *
     * THE ROOT CAUSE turned out to be the socket receive buffer: the OS default is
     * 64 KB against a 412 KB table, so the kernel discarded the overflow before PHP
     * ever saw it. With ext-sockets present, UdpTransport now asks for 4 MB and the
     * whole transfer fits. Re-running the same A/B with that in place:
     *
     *   12 of 12 transfers complete, writes enabled or not.
     *
     * So reporting is now ADAPTIVE, and the condition is exact rather than a guess:
     *
     *   - buffer >= declared size -> report on EVERY chunk. A pause cannot cost a
     *     datagram, because the kernel is holding everything the device sends while
     *     we are away. The bar is smooth.
     *   - otherwise (no ext-sockets, or a platform that clamped the request) ->
     *     report only after IDLE_POLLS_BEFORE_REPORT consecutive silent polls, plus
     *     once before and once after the loop. Coarse, but it cannot lose punches.
     *
     * Do not collapse those two branches. The unbuffered path is what a fresh
     * install without ext-sockets gets, and this project has already silently
     * discarded a third of its attendance once.
     *
     * Swallows anything the listener throws. Progress is an aside: a broken reporter
     * must never fail a read that was otherwise working.
     */
    /**
     * The socket receive buffer the OS granted, or null when unknown.
     *
     * Deliberately NOT on the Transport contract: it is a datagram concern, and a
     * stream or fixture transport has no equivalent. Unknown is treated as "no
     * headroom", which is the safe direction.
     */
    private function receiveBufferBytes(): ?int
    {
        return $this->transport instanceof HasReceiveBuffer
            ? $this->transport->receiveBufferBytes()
            : null;
    }

    private function emit(int $bytesRead, int $bytesTotal): void
    {
        if ($this->progress === null || $bytesRead === $this->lastEmitted) {
            return;
        }

        $this->lastEmitted = $bytesRead;

        try {
            $this->progress->onProgress(
                new Progress($this->operation, $bytesRead, $bytesTotal, $this->attempt),
            );
        } catch (\Throwable) {
            // Deliberately ignored — see the docblock.
        }
    }

    /** Acknowledges an unsolicited realtime push. */
    public static function acknowledge(Transport $transport, int $sessionId): void
    {
        $transport->sendRaw(Packet::buildRealtimeAck($sessionId));
    }
}
