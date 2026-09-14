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
 * UDP transport for the ZKTeco standalone protocol.
 *
 * CONFIRMED against real hardware (ZKTeco F18): despite this protocol commonly
 * being documented as TCP with an extra 8-byte transport wrapper, this device
 * family speaks it directly over UDP datagrams — one packet per datagram, no
 * wrapper. That is why nothing here calls Packet::wrapTcp().
 *
 * UDP has no delivery guarantee, so a bulk transfer can arrive short when a
 * datagram is dropped. This class does NOT retry individual datagrams; retrying
 * the whole request is simpler and safe, because reading from the device never
 * consumes or deletes anything. That retry lives in BulkReader.
 *
 * The other half of that defence is the socket receive buffer, raised from the
 * 64 KB default to hold a whole table — see enlargeReceiveBuffer(), which is the
 * single most effective fix for short transfers on this protocol.
 */
final class UdpTransport implements Transport, HasReceiveBuffer, SupportsRawDrain
{
    /** @var resource|null */
    private $socket = null;

    /**
     * The same socket as $socket, imported as an ext-sockets handle.
     *
     * Held as a property, not a local, ON PURPOSE. socket_import_stream() returns a
     * handle that SHARES the underlying descriptor; letting it fall out of scope
     * has historically closed the stream with it. Keeping it alive for the lifetime
     * of the connection avoids depending on which PHP version fixed that.
     */
    private ?\Socket $rawSocket = null;

    /** Raw SO_RCVBUF readback, exactly as the OS reported it, or null when unknown. */
    private ?int $grantedReceiveBuffer = null;

    /**
     * The part of that we can actually fill with payload, or null when unknown.
     *
     * Not the same number as $grantedReceiveBuffer on Linux. See
     * usableFromGranted() for why, and why the difference is a data-loss bug
     * rather than a cosmetic one.
     */
    private ?int $usableReceiveBuffer = null;

    /**
     * Read timeout currently applied to the socket, as [seconds, microseconds].
     *
     * Cached so setReadTimeout() can skip the stream_set_timeout() syscall when
     * nothing changed. That matters in exactly one place and matters a lot there:
     * the bulk reassembly loop asks for the same 200ms before EVERY datagram, so
     * without this the library pays one pointless syscall per kilobyte while
     * racing a device that does not wait. See SupportsRawDrain for the numbers.
     *
     * Null means "unknown" — set that way whenever the socket changes underneath
     * us, so the next request is always applied rather than assumed.
     */
    private ?array $readTimeout = null;

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
            "udp://{$this->config->host}:{$this->config->port}",
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
        $this->sessionId = 0;
        $this->replyId = 0;
        $this->readTimeout = null; // fresh descriptor, so nothing is applied yet

        $this->setReadTimeout((int) ceil($this->config->timeout));

        $this->enlargeReceiveBuffer();
    }

    /**
     * Asks the OS for a receive buffer big enough to hold a whole table.
     *
     * ==========================================================================
     *  THE MOST EFFECTIVE FIX AVAILABLE FOR "Incomplete transfer" — MEASURED
     * ==========================================================================
     *
     * The OS default is 64 KB. One attendance table on an F18 is 412 KB. This
     * protocol has no flow control and the device does not wait for us, so any
     * pause longer than it takes 64 KB to arrive drops datagrams permanently — the
     * kernel discards them before PHP ever sees them.
     *
     * With a 4 MB buffer the entire transfer fits, so a stall costs latency rather
     * than data, and the reader can afford to do work between chunks.
     *
     * BEST EFFORT, BY DESIGN:
     *
     *  - ext-sockets is a SUGGEST, not a require. Without it this returns silently
     *    and the library behaves exactly as it did before — correct, just more
     *    prone to short transfers. Never make this a hard dependency; the package
     *    is meant to install anywhere.
     *  - The size is a request. Linux DOUBLES what it stores and clamps the
     *    request to net.core.rmem_max — so a 4 MB ask on a host with the common
     *    212,992 default reads back as 425,984 while only 212,992 is fillable.
     *    Raise net.core.rmem_max if the granted value comes back small; on an
     *    unprivileged LXC container that file is read-only and the change must be
     *    made on the host. Windows grants the request outright. Read back what was
     *    actually given rather than assuming, which is why grantedReceiveBuffer
     *    exists — and convert it with usableFromGranted() before believing it.
     */
    private function enlargeReceiveBuffer(): void
    {
        $this->rawSocket = null;
        $this->grantedReceiveBuffer = null;

        if (! function_exists('socket_import_stream') || $this->config->receiveBufferBytes <= 0) {
            return;
        }

        $raw = @socket_import_stream($this->socket);

        if (! $raw instanceof \Socket) {
            return;
        }

        // Suppressed rather than thrown: a device we can talk to with a small
        // buffer is strictly better than one we refuse to talk to at all.
        @socket_set_option($raw, SOL_SOCKET, SO_RCVBUF, $this->config->receiveBufferBytes);

        $granted = @socket_get_option($raw, SOL_SOCKET, SO_RCVBUF);

        $this->rawSocket = $raw;
        $this->grantedReceiveBuffer = is_int($granted) ? $granted : null;
        $this->usableReceiveBuffer = self::usableFromGranted($this->grantedReceiveBuffer);
    }

    /**
     * Converts a raw SO_RCVBUF readback into bytes we can actually fill.
     *
     * ==========================================================================
     *  LINUX REPORTS DOUBLE — CONFIRMED, Debian 12, kernel 6.14, 2026-09-13
     * ==========================================================================
     *
     * setsockopt(SO_RCVBUF, n) on Linux stores 2n, and getsockopt reads that 2n
     * back. The second half is kernel bookkeeping (sk_buff overhead) and is NOT
     * available to payload. Windows and the BSDs return what they granted.
     *
     * Taking the readback at face value is not a rounding error, it loses data.
     * BulkReader decides whether it may pause to report progress by asking whether
     * the buffer can hold the whole transfer; a doubled answer says yes when the
     * truth is no, so it pauses during a burst that has no flow control and the
     * kernel drops the overflow.
     *
     * MEASURED on an unprivileged LXC container with net.core.rmem_max = 212992:
     * a 4 MB request read back as 425984, the 326,084-byte attendance table looked
     * like it fit, and the transfer died at 218,564 bytes — just past the real
     * 212,992 ceiling. Halving first makes that read take the conservative
     * report-on-silence path and complete.
     *
     * Halving on a platform that does not double is merely pessimistic: the reader
     * reports less often than it could. That is the correct direction to be wrong
     * in, and matches receiveBufferBytes()'s "assume none" rule for null.
     *
     * $osFamily is injectable ONLY so the doubling rule can be tested on a machine
     * that is not the platform under test. Production callers pass nothing.
     */
    private static function usableFromGranted(?int $granted, string $osFamily = PHP_OS_FAMILY): ?int
    {
        if ($granted === null) {
            return null;
        }

        return $osFamily === 'Linux'
            ? intdiv($granted, 2)
            : $granted;
    }

    /**
     * Receive buffer we can actually fill, or null if it could not be determined.
     *
     * This is the OS readback CORRECTED FOR PLATFORM — see usableFromGranted().
     * It is deliberately the usable figure and not the raw one, because the
     * contract asks what the OS "will buffer for this socket", and on Linux the
     * raw readback is twice that. Callers decide whether they may stop reading
     * based on this number; handing them the raw one drops datagrams.
     *
     * Null means ext-sockets is missing and the socket is on the platform default
     * — worth surfacing when diagnosing repeated short transfers, because it is the
     * difference between 64 KB and 4 MB of headroom.
     */
    public function receiveBufferBytes(): ?int
    {
        return $this->usableReceiveBuffer;
    }

    /**
     * The unmodified SO_RCVBUF readback, for diagnosis only.
     *
     * Never size a transfer decision off this. It exists so an operator staring at
     * a short-transfer log can see both numbers and tell a small rmem_max apart
     * from a missing ext-sockets.
     */
    public function grantedReceiveBufferBytes(): ?int
    {
        return $this->grantedReceiveBuffer;
    }

    public function close(): void
    {
        // Drop the imported handle first — it shares this descriptor, and holding
        // it past fclose() leaves a stale reference to a closed socket.
        $this->rawSocket = null;
        $this->grantedReceiveBuffer = null;
        $this->usableReceiveBuffer = null;
        $this->readTimeout = null;

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

        if (fwrite($this->socket, $packet) === false) {
            throw new ConnectionException('Failed to write to device socket.', [
                'command' => $command,
            ]);
        }

        $datagram = @fread($this->socket, 8192);

        if ($datagram === '' || $datagram === false) {
            $meta = stream_get_meta_data($this->socket);

            if ($meta['timed_out'] ?? false) {
                throw new TimeoutException('Device connection timed out or closed unexpectedly.', [
                    'command' => $command,
                    'endpoint' => $this->config->endpoint(),
                ]);
            }

            throw new ConnectionException('No response from device.', [
                'command' => $command,
                'endpoint' => $this->config->endpoint(),
            ]);
        }

        return Reply::fromArray(Packet::parse($datagram));
    }

    public function sendRaw(string $packet): void
    {
        if ($this->socket === null) {
            return;
        }

        @fwrite($this->socket, $packet);
    }

    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply
    {
        if ($this->socket === null) {
            throw new ConnectionException('Not connected to device.');
        }

        $seconds = (int) $pollSeconds;
        $this->setReadTimeout($seconds, (int) round(($pollSeconds - $seconds) * 1_000_000));

        $datagram = @fread($this->socket, 8192);

        if ($datagram === '' || $datagram === false) {
            return null;
        }

        return Reply::fromArray(Packet::parse($datagram));
    }

    /**
     * Fast path for bulk reassembly: one datagram's payload, no Reply built.
     *
     * Behaviourally identical to taking ->data off readUnsolicited()'s Reply — the
     * header is sliced off and discarded either way, because reassembly never
     * looked at it. The difference is an array and an object per kilobyte, which
     * on a 326 KB table is the difference between capturing all of it and
     * capturing two thirds. See SupportsRawDrain for the measurements.
     *
     * A runt datagram (under the 8-byte header) yields '' rather than null: the
     * device spoke, so it is not silence, and the caller's idle counter must not
     * treat it as such. Packet::parse() would have produced the same empty payload
     * from a short read, minus the bounds check.
     */
    public function readRawPayload(float $pollSeconds = 0.5): ?string
    {
        if ($this->socket === null) {
            throw new ConnectionException('Not connected to device.');
        }

        $seconds = (int) $pollSeconds;
        $this->setReadTimeout($seconds, (int) round(($pollSeconds - $seconds) * 1_000_000));

        $datagram = @fread($this->socket, 8192);

        if ($datagram === '' || $datagram === false) {
            return null;
        }

        return strlen($datagram) >= 8 ? substr($datagram, 8) : '';
    }

    public function setReadTimeout(int $seconds, int $microseconds = 0): void
    {
        if ($this->socket === null) {
            return;
        }

        // Idempotent by design: the reassembly loop re-requests the same timeout
        // for every datagram, and the syscall it would cost is time the device
        // spends overflowing the receive buffer.
        if ($this->readTimeout === [$seconds, $microseconds]) {
            return;
        }

        stream_set_timeout($this->socket, $seconds, $microseconds);
        $this->readTimeout = [$seconds, $microseconds];
    }

    /** Restores the configured request/reply timeout after a bulk reassembly. */
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

    /** @return resource|null The UDP socket, for stream_select() over several devices. */
    public function selectableStream()
    {
        return $this->socket;
    }

    public function __destruct()
    {
        $this->close();
    }
}
