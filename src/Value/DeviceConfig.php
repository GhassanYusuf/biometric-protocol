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

namespace Promoseven\Biometric\Value;

/**
 * Everything the library needs to reach one device.
 *
 * This value object is the seam that keeps the library framework-agnostic: the
 * old implementation had ZktecoDevice::fromModel(\App\Models\Device), which made
 * the protocol layer depend on Eloquent. A host app now maps its own model to
 * this object in its adapter instead.
 */
final class DeviceConfig
{
    public function __construct(
        public readonly string $host,
        public readonly int $port = 4370,
        public readonly int $commKey = 0,
        public readonly float $timeout = 8.0,
        /**
         * Wall-clock offset the device stamps records with.
         *
         * CONFIRMED against real hardware: the device stamps attendance with its
         * own LOCAL time, not UTC. Callers store UTC, so decoded timestamps must
         * be anchored to the device's real zone or every value is off by that
         * offset — and a browser then applies the viewer's offset on top, doubling
         * the error.
         *
         * A fixed offset rather than a named zone is deliberate for deployments
         * that do not observe DST; pass a named zone ('Europe/Berlin') where DST
         * applies.
         */
        public readonly string $timezone = '+03:00',

        /**
         * Socket receive buffer to ask the OS for, in bytes.
         *
         * MEASURED, and the single highest-leverage number in this class. The OS
         * default is 64 KB; one attendance table on an F18 is 412 KB. This protocol
         * has no flow control, so the moment the reader pauses — for a progress
         * callback, a GC cycle, a scheduler slice — the device keeps blasting and
         * anything past 64 KB is dropped by the kernel. That surfaces as
         * "Incomplete transfer: got 89,088 of 412,084 bytes", which then burns all
         * five whole-request retries.
         *
         * 4 MB holds a ~100,000-record table whole, so a stall costs latency
         * instead of data. It is a REQUEST, not a guarantee: platforms clamp it,
         * and the granted size is readable via receiveBufferBytes() for diagnosis.
         *
         * Requires ext-sockets. Without it the request is skipped silently and the
         * library still works exactly as before — see UdpTransport::open().
         */
        public readonly int $receiveBufferBytes = 4 * 1024 * 1024,

        /**
         * How many times a single stalled windowed-read window is re-requested
         * before the whole transfer is abandoned.
         *
         * The flow-controlled read (PREPARE_BUFFER/READ_BUFFER) pulls a table one
         * 16 KB window at a time from a copy the device has STAGED. That staged copy
         * stays valid until FREE_DATA, so a window that stalls can simply be asked
         * for again at the same offset — the progress already pulled is not lost. On
         * a LAN this never matters; a window never stalls. It is the whole game on a
         * high-latency or lossy link.
         *
         * MEASURED on the Camelot F18 over a public IP (2026-09-14): a 1,664,804-
         * byte attendance table stalled ~7 times per read. With no per-window retry
         * the reader threw away the entire transfer on the first stall and restarted
         * from zero, so across five whole-request attempts it read ~1/3 of the table
         * and never finished. Re-requesting the stalled window turns a stall from
         * "lose the table" into "re-read 16 KB".
         *
         * Zero disables per-window retry (the pre-2.1 behaviour). Raise it for
         * devices reached across the internet; the default suits a LAN and tolerates
         * an occasional remote hiccup.
         */
        public readonly int $bulkWindowRetries = 4,

        /**
         * Which transport to speak the protocol over: 'udp' or 'tcp'.
         *
         * Same command packets either way; TCP additionally wraps each in the
         * protocol's 8-byte frame and reassembles a stream instead of one datagram
         * per packet (see TcpTransport). UDP is the historical default and is proven
         * on LAN devices. TCP has flow control and retransmission and is the right
         * choice for a device reached across the internet, where UDP loses bursts
         * and stalls — MEASURED: a full read that UDP could not finish returns whole
         * over TCP.
         */
        public readonly string $transport = self::TRANSPORT_UDP,
    ) {
        if ($host === '') {
            throw new \InvalidArgumentException('Device host cannot be empty.');
        }
        if ($port < 1 || $port > 65535) {
            throw new \InvalidArgumentException("Device port must be 1-65535, got {$port}.");
        }
        if ($bulkWindowRetries < 0) {
            throw new \InvalidArgumentException("bulkWindowRetries cannot be negative, got {$bulkWindowRetries}.");
        }
        if ($transport !== self::TRANSPORT_UDP && $transport !== self::TRANSPORT_TCP) {
            throw new \InvalidArgumentException("transport must be 'udp' or 'tcp', got '{$transport}'.");
        }
    }

    public const TRANSPORT_UDP = 'udp';

    public const TRANSPORT_TCP = 'tcp';

    /** @param array{host:string,port?:int,comm_key?:int,timeout?:float,timezone?:string,receive_buffer_bytes?:int,bulk_window_retries?:int,transport?:string} $data */
    public static function fromArray(array $data): self
    {
        return new self(
            host: $data['host'],
            port: (int) ($data['port'] ?? 4370),
            commKey: (int) ($data['comm_key'] ?? 0),
            timeout: (float) ($data['timeout'] ?? 8.0),
            timezone: $data['timezone'] ?? '+03:00',
            receiveBufferBytes: (int) ($data['receive_buffer_bytes'] ?? 4 * 1024 * 1024),
            bulkWindowRetries: (int) ($data['bulk_window_retries'] ?? 4),
            transport: $data['transport'] ?? self::TRANSPORT_UDP,
        );
    }

    /** True when this config speaks the protocol over TCP rather than UDP. */
    public function usesTcp(): bool
    {
        return $this->transport === self::TRANSPORT_TCP;
    }

    public function endpoint(): string
    {
        return "{$this->host}:{$this->port}";
    }
}
