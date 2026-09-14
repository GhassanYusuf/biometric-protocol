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

namespace Promoseven\Biometric\Service;

use Promoseven\Biometric\Client\DeviceClient;
use Promoseven\Biometric\Codec\AttendanceCodec;

/**
 * Attendance records on the device.
 *
 * IMPORTANT LIMITATION OF THE PROTOCOL: the device cannot be asked for "punches
 * since X". ATTLOG_RRQ returns the WHOLE table, always. There is no server-side
 * filter, cursor or pagination in the standalone protocol.
 *
 * So "incremental sync" is necessarily a CLIENT-side concept: read the whole
 * table, then discard what is at or before a watermark the host app keeps. That
 * saves the database work and the dedupe scan, not the network transfer. Anyone
 * expecting an incremental read to be cheap on the wire will be disappointed, and
 * that is the protocol's fault, not this library's.
 *
 * A host app should therefore sync on a schedule sized to the table, not poll
 * aggressively, and should use the realtime listener for immediacy instead.
 */
final class AttendanceService
{
    public function __construct(private readonly DeviceClient $client)
    {
    }

    /**
     * Every attendance record on the device.
     *
     * Records whose timestamp could not be decoded come back as ['raw' => hex]
     * rather than being dropped, so a caller can preserve and inspect them instead
     * of silently losing punches.
     *
     * @return list<array<string,mixed>>
     */
    public function all(): array
    {
        return AttendanceCodec::decode(
            $this->client->readAttendanceRaw(),
            $this->client->config()->timezone,
        );
    }

    /**
     * Raw bytes of the attendance table, for preservation before parsing.
     *
     * A host app should store this alongside the parsed rows: if a decoder bug is
     * found later, reparsing an archived payload is possible; re-reading a device
     * whose log has since rolled over is not.
     */
    public function raw(): string
    {
        return $this->client->readAttendanceRaw();
    }

    /**
     * Records strictly after $since.
     *
     * Client-side filtering — see the class docblock. Undecodable raw records are
     * always included regardless of the watermark, because their timestamp is
     * unknown and dropping them would lose data silently.
     *
     * @return list<array<string,mixed>>
     */
    public function since(\DateTimeInterface $since): array
    {
        $records = [];

        foreach ($this->all() as $record) {
            if (! isset($record['timestamp'])) {
                $records[] = $record; // undecodable — never silently discarded
                continue;
            }

            if ($record['timestamp'] > $since) {
                $records[] = $record;
            }
        }

        return $records;
    }

    /**
     * The newest decodable timestamp on the device, or null.
     *
     * Useful for establishing an initial watermark without importing anything.
     */
    public function latestTimestamp(): ?\DateTimeImmutable
    {
        $latest = null;

        foreach ($this->all() as $record) {
            if (! isset($record['timestamp'])) {
                continue;
            }

            if ($latest === null || $record['timestamp'] > $latest) {
                $latest = $record['timestamp'];
            }
        }

        return $latest;
    }

    /**
     * Counts records without keeping them, for a cheap size check.
     *
     * Still transfers the whole table — see the class docblock.
     */
    public function count(): int
    {
        return count($this->all());
    }

    /** Subscribes to realtime punch events. */
    public function listen(int $eventMask = \Promoseven\Biometric\Protocol\Command::EF_ATTLOG): void
    {
        $this->client->beginRealtimeListening($eventMask);
    }

    /**
     * Reads the next realtime punch, or null if none arrived in the poll window.
     *
     * EXPERIMENTAL decoding — see AttendanceCodec::decodeRealtime().
     *
     * @return array<string,mixed>|null
     */
    public function nextRealtimePunch(float $pollSeconds = 0.5): ?array
    {
        $raw = $this->client->readRealtimeRaw($pollSeconds);

        if ($raw === null) {
            return null;
        }

        return AttendanceCodec::decodeRealtime($raw, $this->client->config()->timezone);
    }

    /**
     * Deletes ALL attendance records on the device.
     *
     * DESTRUCTIVE and irreversible. Never called by any sync flow in this library.
     * Only call this after confirming the records are safely imported, and never
     * automatically — a device whose log is cleared before a failed import has lost
     * that attendance permanently.
     */
    public function clearAll(): void
    {
        $this->client->clearAttendanceLog();
    }
}
