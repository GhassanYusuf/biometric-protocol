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
 * The device's packed timestamp format.
 *
 * A single uint32 encoding Y/M/D/H/M/S by successive division. Note the month and
 * day fields use 31-day months regardless of the real calendar, so the encoding
 * space contains dates that do not exist.
 */
final class Timestamp
{
    private function __construct()
    {
    }

    /**
     * Decodes a packed device timestamp, anchored to the device's own timezone.
     *
     * Returns null — never a fabricated "now" — when the value does not decode to
     * a real calendar date.
     *
     * CONFIRMED on real hardware: this previously defaulted to the current time on
     * failure, which silently wrote dozens of garbage attendance rows on every
     * re-read of the same corrupted bytes. A dropped UDP datagram misaligns the
     * record stream and produces exactly this, so the null path is the common case
     * during a bad transfer, not a rarity.
     *
     * @param string $timezone Device wall-clock zone. The device stamps LOCAL time,
     *                         not UTC — see DeviceConfig::$timezone.
     */
    public static function decode(int $encoded, string $timezone = '+03:00'): ?\DateTimeImmutable
    {
        /*
         * A zeroed field means "no value", not midnight on 2000-01-01.
         *
         * Zero decodes arithmetically to a perfectly valid date, so without this
         * guard a padding run or a misaligned record produces a punch dated
         * 2000-01-01 00:00:00 that looks entirely real to every caller. No device
         * running this protocol can have stamped it — the platform did not exist —
         * so treating zero as undecodable costs nothing and closes the hole.
         */
        if ($encoded <= 0) {
            return null;
        }

        $second = $encoded % 60;
        $encoded = intdiv($encoded, 60);
        $minute = $encoded % 60;
        $encoded = intdiv($encoded, 60);
        $hour = $encoded % 24;
        $encoded = intdiv($encoded, 24);
        $day = ($encoded % 31) + 1;
        $encoded = intdiv($encoded, 31);
        $month = ($encoded % 12) + 1;
        $encoded = intdiv($encoded, 12);
        $year = $encoded + 2000;

        /*
         * ZERO-PADDED, with a strict format. Do not "simplify" this.
         *
         * CONFIRMED BUG THIS FIXES: the previous version passed unpadded components
         * to createFromFormat('Y-n-j-G-i-s', ...). The `i` and `s` tokens require TWO
         * digits, so any punch whose minute or second was under 10 failed to parse and
         * returned null — and null means "undecodable record" to every caller.
         *
         * On a real device that silently discarded 3,236 of 9,582 attendance records,
         * about 34%, for as long as the code existed. Nothing errored; the punches
         * simply never arrived. Two thirds of a working sync looks exactly like a
         * complete one unless you count what the device offered.
         */
        $date = \DateTimeImmutable::createFromFormat(
            'Y-m-d H:i:s',
            sprintf('%04d-%02d-%02d %02d:%02d:%02d', $year, $month, $day, $hour, $minute, $second),
            new \DateTimeZone($timezone),
        );

        if ($date === false) {
            return null;
        }

        // createFromFormat silently rolls invalid dates forward — "2026-2-30"
        // becomes March 2nd — instead of failing. Catch that by checking the parsed
        // components round-trip back to what we asked for.
        if ((int) $date->format('Y') !== $year
            || (int) $date->format('n') !== $month
            || (int) $date->format('j') !== $day) {
            return null;
        }

        return $date;
    }

    /** Encodes a date/time into the device's packed uint32 form. */
    public static function encode(\DateTimeInterface $dateTime): int
    {
        return ((((int) $dateTime->format('Y') - 2000) * 12 + ((int) $dateTime->format('n') - 1)) * 31
                + ((int) $dateTime->format('j') - 1)) * 24 * 60 * 60
                + (int) $dateTime->format('H') * 3600
                + (int) $dateTime->format('i') * 60
                + (int) $dateTime->format('s');
    }
}
