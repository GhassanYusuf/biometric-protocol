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

namespace Promoseven\Biometric\Codec;

/**
 * Shared helpers for reading the device's fixed-width record tables.
 *
 * Every table this library decodes follows the same envelope: a 4-byte
 * byte-length field, then records. What varies is the record width, which differs
 * by firmware generation — hence detectRecordSize().
 */
final class RecordBuffer
{
    private function __construct()
    {
    }

    /**
     * Truncates a fixed-width C-style string at its first NUL.
     *
     * Deliberately NOT a trailing rtrim(): devices leave stale non-NUL bytes after
     * the terminator when a field is edited to a shorter value without clearing the
     * old memory, and rtrim() would let that garbage leak into the decoded value.
     * CONFIRMED on real hardware.
     */
    public static function cString(string $raw): string
    {
        $nullPos = strpos($raw, "\0");

        return $nullPos === false ? $raw : substr($raw, 0, $nullPos);
    }

    /**
     * Picks whichever candidate record width evenly divides the buffer, preferring
     * the first match.
     *
     * Returns 0 for a buffer that divides by none of them — a truncated or
     * misaligned transfer, where guessing a width would produce confident garbage.
     *
     * @param list<int> $candidates widths in preference order
     */
    public static function detectRecordSize(int $bodyLength, array $candidates): int
    {
        if ($bodyLength <= 0) {
            return 0;
        }

        foreach ($candidates as $candidate) {
            if ($candidate > 0 && $bodyLength % $candidate === 0) {
                return $candidate;
            }
        }

        return 0;
    }

    /** Strips the leading 4-byte length field. Returns '' for a too-short buffer. */
    public static function body(string $raw): string
    {
        return strlen($raw) < 4 ? '' : substr($raw, 4);
    }

    /** The length the buffer claims to carry, for cross-checking a transfer. */
    public static function declaredLength(string $raw): int
    {
        if (strlen($raw) < 4) {
            return 0;
        }

        return unpack('V', substr($raw, 0, 4))[1];
    }
}
