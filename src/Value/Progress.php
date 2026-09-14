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
 * How far a bulk transfer has got.
 *
 * Emitted in BYTES, deliberately, because bytes are the only thing the transport
 * actually knows while a transfer is in flight. The device declares a total size
 * before it starts streaming (CMD_PREPARE_DATA), and the reassembler counts what
 * has arrived — both are facts, neither is an estimate.
 *
 * Converting to "records" is the CALLER's job, because only the caller knows the
 * record width for the table it asked for, and in this protocol that width is
 * derived from the total length rather than announced. AttendanceCodec::WIDTHS
 * plus RecordBuffer::detectRecordSize() do it honestly from the declared total.
 * Doing it here would mean this class guessing on behalf of a codec it must not
 * depend on.
 */
final class Progress
{
    public function __construct(
        /** Which table is being read: 'attendance', 'users', 'templates'. */
        public readonly string $operation,
        /** Bytes reassembled so far. */
        public readonly int $bytesRead,
        /**
         * Total the device declared, or 0 when it declared none.
         *
         * Zero is a real, common case — a small table arrives inline in the first
         * packet with no PREPARE_DATA — and it must not be treated as "0% done".
         */
        public readonly int $bytesTotal,
        /**
         * Which whole-request attempt this is (1-based).
         *
         * A retry restarts the transfer from zero, so a bar that only watched
         * bytesRead would appear to run backwards. Callers should surface a retry
         * rather than hide it: the read genuinely did start over.
         */
        public readonly int $attempt = 1,
    ) {
    }

    /**
     * Completion 0.0–1.0, or NULL when the device never declared a total.
     *
     * Null, not zero and not 1.0. Rule 10: "we were not told" and "none" are
     * different answers, and a progress bar that invents a number is a lie the
     * operator has no way to check. Callers should show an indeterminate state.
     */
    public function fraction(): ?float
    {
        if ($this->bytesTotal <= 0) {
            return null;
        }

        // Clamped: a device that overshoots its own declared size (observed on
        // trailing chunks) must not produce 103%.
        return min(1.0, $this->bytesRead / $this->bytesTotal);
    }

    /** Whole percent 0–100, or null when the total is unknown. */
    public function percent(): ?int
    {
        $fraction = $this->fraction();

        return $fraction === null ? null : (int) round($fraction * 100);
    }

    public function isComplete(): bool
    {
        return $this->bytesTotal > 0 && $this->bytesRead >= $this->bytesTotal;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'operation' => $this->operation,
            'bytes_read' => $this->bytesRead,
            'bytes_total' => $this->bytesTotal,
            'percent' => $this->percent(),
            'attempt' => $this->attempt,
        ];
    }
}
