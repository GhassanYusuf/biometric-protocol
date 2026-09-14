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
 * The device's fingerprint-template table.
 *
 * ---------------------------------------------------------------------------
 *  CONTRACT: this codec either returns records you can trust, or it returns [].
 *  It must NEVER return a partial or plausible-looking miscount.
 * ---------------------------------------------------------------------------
 *
 * A wrong "0 fingerprints" tells an operator somebody is unenrolled when they are
 * not — worse than admitting we could not read the table. Callers treat [] as
 * "unknown", never as "none enrolled".
 *
 * Layout: a 4-byte total-length field, then variable-length records of
 * [uint16 record length][uint16 uid][uint8 finger slot][uint8 valid][template blob].
 *
 * CONFIRMED against real hardware (ZKTeco F18 @ 192.168.7.62): a 22,066-byte
 * table whose leading uint32 read 22,062, parsing consistently into 19 records
 * and consuming exactly 22,062 of 22,062 bytes. Cross-checked per-slot via
 * USERTEMP_RRQ: uid 8 answered only for slot 6, with a 1,304-byte template
 * matching that record's declared size. The captured table ships as a test
 * fixture — see tests/Fixtures/fingerprint-template-table.bin.
 */
final class TemplateCodec
{
    /** Header width: length(2) + uid(2) + slot(1) + valid(1). */
    private const HEADER_BYTES = 6;

    /** Valid finger slots. A value outside this means the layout does not match. */
    private const MAX_SLOT = 9;

    private function __construct()
    {
    }

    /**
     * @return list<array{uid:int,fid:int}> empty means "unknown", never "none"
     */
    public static function decode(string $raw): array
    {
        if (strlen($raw) < 4) {
            return [];
        }

        $body = substr($raw, 4);
        $length = strlen($body);
        $records = [];
        $offset = 0;

        while ($offset + self::HEADER_BYTES <= $length) {
            $recordSize = unpack('v', substr($body, $offset, 2))[1];

            // A record must be at least its own header and must not claim to run
            // past the end of the buffer — either means alignment is lost and
            // nothing decoded so far can be trusted.
            if ($recordSize < self::HEADER_BYTES || $offset + $recordSize > $length) {
                return [];
            }

            $uid = unpack('v', substr($body, $offset + 2, 2))[1];
            $fid = ord($body[$offset + 4]);

            if ($fid > self::MAX_SLOT) {
                return []; // not a real finger slot — layout does not match
            }

            $records[] = ['uid' => $uid, 'fid' => $fid];
            $offset += $recordSize;
        }

        // The walk must land EXACTLY on the end of the body. A real table does
        // (CONFIRMED: 22,062 of 22,062 across 19 records); trailing bytes mean the
        // buffer was truncated, and a partial decode would undercount fingers.
        if ($offset !== $length) {
            return [];
        }

        return $records;
    }

    /**
     * Groups decoded records into device uid => sorted finger slots.
     *
     * @param list<array{uid:int,fid:int}> $records
     * @return array<int,list<int>>
     */
    public static function slotsByUid(array $records): array
    {
        $slots = [];

        foreach ($records as $record) {
            // A device can hold more than one template per finger; the slot is what
            // matters to callers, so keep it unique.
            if (! in_array($record['fid'], $slots[$record['uid']] ?? [], true)) {
                $slots[$record['uid']][] = $record['fid'];
            }
        }

        foreach ($slots as $uid => $list) {
            sort($list);
            $slots[$uid] = array_values($list);
        }

        return $slots;
    }

    /**
     * Maps device uid => user id using the user table, so template slots can be
     * reported per person rather than per internal uid.
     *
     * @param list<array{uid:int,fid:int}>  $templates
     * @param list<array<string,mixed>>     $users
     * @return array<string,list<int>> user_id => sorted slots; empty when unknown
     */
    public static function slotsByUserId(array $templates, array $users): array
    {
        if ($templates === []) {
            return []; // unknown — do not synthesise an all-zero map
        }

        $codeByUid = [];
        foreach ($users as $user) {
            if (isset($user['uid'], $user['user_id']) && $user['user_id'] !== '') {
                $codeByUid[$user['uid']] = (string) $user['user_id'];
            }
        }

        // Every enrolled user starts empty. The table read succeeded, so "no
        // fingers" is now a real, trustworthy answer for anyone absent from it.
        $slots = array_fill_keys(array_values($codeByUid), []);

        foreach (self::slotsByUid($templates) as $uid => $fids) {
            $code = $codeByUid[$uid] ?? null;

            if ($code !== null) {
                $slots[$code] = $fids;
            }
        }

        return $slots;
    }
}
