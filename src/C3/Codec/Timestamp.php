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

namespace Promoseven\Biometric\C3\Codec;

/**
 * The C3 packed timestamp.
 *
 * NOT a unix epoch, and NOT seconds-since-2000 either — which is what the
 * standalone protocol in this same library uses, so the temptation to reuse that
 * decoder is real and wrong. The fields are packed in a mixed radix with a
 * **31-day month** and a 12-month year:
 *
 *     second = t % 60;  t /= 60
 *     minute = t % 60;  t /= 60
 *     hour   = t % 24;  t /= 24
 *     day    = t % 31;  t /= 31   (+1)
 *     month  = t % 12;  t /= 12   (+1)
 *     year   = t + 2000
 *
 * Transcribed literally from vwout/zkaccess-c3-py rather than derived (rule 17).
 *
 * CONFIRMED TF1700 @192.168.7.60, 2026-09-14: the first record of the pulled
 * transaction table decodes to 2025-08-10 17:28:11, which is to the second the
 * earliest TF1700 event in the vendor software's own database. Independent
 * agreement between our decoder and ZKTeco's.
 *
 * THE DEVICE STAMPS LOCAL TIME. There is nothing in the payload that says which
 * zone, so the caller must supply it; a value decoded without one is wrong by the
 * site's offset, and a browser will then apply the viewer's offset on top of that.
 * This is the bug that has already cost this project 6,432 duplicate rows and a
 * watermark three hours in the future.
 */
final class Timestamp
{
    /** The lowest value we will treat as a real stamp rather than an unset clock. */
    private const PLAUSIBLE_FROM_YEAR = 2000;

    /**
     * Decodes to a real instant, anchored in the device's own zone.
     *
     * Returns null when the value cannot be a date. Null means "would not decode"
     * and must never be rendered as an epoch or as midnight — the caller counts it
     * and keeps the raw bytes (rule 10).
     */
    public static function decode(int $packed, string $timezone = '+03:00'): ?\DateTimeImmutable
    {
        if ($packed <= 0) {
            return null;
        }

        $second = $packed % 60;
        $packed = intdiv($packed, 60);
        $minute = $packed % 60;
        $packed = intdiv($packed, 60);
        $hour = $packed % 24;
        $packed = intdiv($packed, 24);
        $day = $packed % 31 + 1;
        $packed = intdiv($packed, 31);
        $month = $packed % 12 + 1;
        $year = intdiv($packed, 12) + 2000;

        if ($year < self::PLAUSIBLE_FROM_YEAR || $year > 2100) {
            return null;
        }

        // The 31-day radix can address a day that the month does not have. That is
        // a device with an unset or corrupted clock, not a decode we should round
        // into something plausible.
        if (! checkdate($month, $day, $year)) {
            return null;
        }

        try {
            $zone = new \DateTimeZone($timezone);
        } catch (\Exception) {
            return null;
        }

        return new \DateTimeImmutable(
            sprintf('%04d-%02d-%02d %02d:%02d:%02d', $year, $month, $day, $hour, $minute, $second),
            $zone,
        );
    }

    /** The inverse, for building a filter or a write. */
    public static function encode(\DateTimeInterface $moment): int
    {
        $year = (int) $moment->format('Y') - 2000;
        $month = (int) $moment->format('n') - 1;
        $day = (int) $moment->format('j') - 1;

        $packed = ($year * 12 + $month) * 31 + $day;
        $packed = $packed * 24 + (int) $moment->format('G');
        $packed = $packed * 60 + (int) $moment->format('i');

        return $packed * 60 + (int) $moment->format('s');
    }
}
