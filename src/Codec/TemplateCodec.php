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
        return array_map(
            static fn (array $r) => ['uid' => $r['uid'], 'fid' => $r['fid']],
            self::decodeWithBlobs($raw),
        );
    }

    /**
     * The same walk, keeping the TEMPLATE BLOB each record carries.
     *
     * WHY THIS EXISTS. decode() returns only which slots are filled, because that is
     * all the enrollment UI needs, and for a long time the blobs were assumed not to
     * be obtainable at all — `template.download` is still declared `not_implemented`
     * for the separate per-slot command. That assumption was wrong about THIS table:
     * the blob has always been sitting in the record, immediately after the 6-byte
     * header, and was simply being stepped over.
     *
     * WHAT THE BLOB IS GOOD FOR, AND WHAT IT IS NOT. It is the device's own template
     * encoding. Treat it as an OPAQUE IDENTIFIER, not as a fingerprint:
     *
     *   - Two records with byte-identical blobs are the same enrolled template. That
     *     happens when a vendor tool copied one enrolment to several terminals, which
     *     is exactly how these estates are usually set up, and it is strong evidence
     *     that two device records are one person.
     *   - Two DIFFERENT blobs prove nothing either way. Re-presenting the same finger
     *     produces a different template every time; only a real matcher could compare
     *     them, and this library does not have one.
     *
     * Writing a blob back to a device is a SEPARATE and still-unverified problem —
     * see TemplateService::uploadTemplate(). Reading is safe; reading is all this does.
     *
     * CONFIRMED on the ZKTeco F18 @ 192.168.7.62 (2026-09-15) against the 22,066-byte
     * capture in tests/Fixtures: 19 records, blobs of 706-1,602 bytes, 21,948 bytes of
     * template data, the walk consuming exactly 22,062 of 22,062.
     *
     * @return list<array{uid:int,fid:int,valid:int,template:string}>
     */
    public static function decodeWithBlobs(string $raw): array
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

            $records[] = [
                'uid' => $uid,
                'fid' => $fid,
                'valid' => ord($body[$offset + 5]),
                // Everything after the header, for exactly the length the record
                // declares. A zero-length blob is possible and is not an error.
                'template' => substr($body, $offset + self::HEADER_BYTES, $recordSize - self::HEADER_BYTES),
            ];
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
     * True only for a table the device DECLARED empty. decode() returns [] for that
     * AND for an undecodable buffer; a caller that must tell "nobody has fingers" from
     * "could not read" asks this — the ONE definition, used by every read and write.
     *
     * Two forms (2.16.2):
     *   - a 4-byte header that says zero, nothing following;
     *   - NO BYTES AT ALL — BulkReader returns '' only for the device's own "nothing to
     *     send" (ACK_OK with no data, or a declared size of 0); a failed transfer
     *     throws. OBSERVED on the F18 IT-Office (192.168.7.64, 2026-10-21) after a
     *     wipe: the template read returned 0 bytes. Until 2.16.2 that read as
     *     undecodable, so addTemplates() refused to write a wiped or new terminal's
     *     first finger (host app casebook DC-027,
     *     tools/zkprobe/traces-2026-10-21/empty-template-table-01.json).
     */
    public static function isEmptyTable(string $raw): bool
    {
        return $raw === '' || (strlen($raw) === 4 && unpack('V', $raw)[1] === 0);
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
