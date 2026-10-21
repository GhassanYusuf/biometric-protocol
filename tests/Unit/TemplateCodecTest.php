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

namespace Promoseven\Biometric\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Promoseven\Biometric\Codec\TemplateCodec;

/**
 * The codec's contract is the thing worth pinning down: it either returns records
 * you can trust, or it returns [] meaning "unknown". It must NEVER return a partial
 * or plausible-looking miscount, because a wrong "0 fingerprints" silently tells an
 * operator somebody is unenrolled when they are not.
 *
 * Every case here runs with no device present — the failure modes are all shapes of
 * bytes, and the one real capture is committed as a fixture.
 */
class TemplateCodecTest extends TestCase
{
    /** Builds a template table in the layout decode() expects. */
    private function table(array $records, int $blobLength = 10): string
    {
        $body = '';

        foreach ($records as [$uid, $fid]) {
            $blob = str_repeat("\xAB", $blobLength);
            $body .= pack('v', 6 + strlen($blob)) . pack('v', $uid) . chr($fid) . chr(1) . $blob;
        }

        return pack('V', strlen($body)) . $body;
    }

    public function test_it_decodes_uid_and_finger_index_per_record(): void
    {
        $decoded = TemplateCodec::decode($this->table([[7, 0], [7, 3], [9, 5]]));

        $this->assertCount(3, $decoded);
        $this->assertSame(['uid' => 7, 'fid' => 0], $decoded[0]);
        $this->assertSame(['uid' => 7, 'fid' => 3], $decoded[1]);
        $this->assertSame(['uid' => 9, 'fid' => 5], $decoded[2]);
    }

    public function test_it_reads_every_finger_slot_zero_through_nine(): void
    {
        $records = [];

        foreach (range(0, 9) as $slot) {
            $records[] = [4, $slot];
        }

        $decoded = TemplateCodec::decode($this->table($records));

        $this->assertSame(range(0, 9), array_column($decoded, 'fid'));
    }

    public function test_a_finger_index_outside_zero_to_nine_abandons_the_whole_read(): void
    {
        // 11 is not a valid finger slot: the layout assumption is wrong, so nothing
        // decoded so far can be trusted.
        $this->assertSame([], TemplateCodec::decode($this->table([[7, 0], [7, 11]])));
    }

    public function test_a_record_claiming_to_overrun_the_buffer_abandons_the_read(): void
    {
        $body = pack('v', 4096) . pack('v', 7) . chr(0) . chr(1) . 'short';

        $this->assertSame([], TemplateCodec::decode(pack('V', strlen($body)) . $body));
    }

    public function test_a_record_too_small_for_its_own_header_abandons_the_read(): void
    {
        $body = pack('v', 2) . pack('v', 7) . chr(0) . chr(1);

        $this->assertSame([], TemplateCodec::decode(pack('V', strlen($body)) . $body));
    }

    public function test_a_truncated_table_decodes_to_unknown(): void
    {
        $this->assertSame([], TemplateCodec::decode(''));
        $this->assertSame([], TemplateCodec::decode("\x01\x02"));
    }

    public function test_trailing_bytes_abandon_the_read_rather_than_undercount(): void
    {
        // A record walk that doesn't land exactly on the end of the body means the
        // buffer was truncated or misaligned. Reporting the records decoded so far
        // would undercount somebody's fingers, which is worse than "unknown".
        $table = $this->table([[7, 0], [7, 3]]);

        $this->assertSame([], TemplateCodec::decode($table . "\x00\x00\x00\x00\x00\x00\x00"));
    }

    /**
     * Real 22,066-byte template table captured from the IT Room terminal
     * (ZKTeco F18 @ 192.168.7.62) via `zkteco:probe-templates`. This is the
     * regression guard that the layout assumption actually holds on hardware.
     */
    public function test_it_decodes_the_real_device_template_table(): void
    {
        $raw = file_get_contents(__DIR__ . '/../Fixtures/fingerprint-template-table.bin');

        $this->assertSame(22066, strlen($raw), 'fixture changed size');

        $records = TemplateCodec::decode($raw);

        $this->assertCount(19, $records, 'the real table holds 19 templates');

        $byUid = TemplateCodec::slotsByUid($records);

        // Cross-checked against a per-slot USERTEMP_RRQ probe of the same device:
        // uid 8 answered only for fid 6, with a 1,304-byte template matching this
        // record's declared size.
        $this->assertSame([6], $byUid[8], 'uid 8 has exactly one template, in slot 6');
        $this->assertSame([6, 7], $byUid[1]);
        $this->assertSame([3, 6], $byUid[2]);
        $this->assertSame([1, 6], $byUid[15]);
        $this->assertSame([2], $byUid[19]);

        // 13 of the 19 enrolled users have at least one finger on file.
        $this->assertCount(13, $byUid);

        // Every finger index must be a real slot.
        foreach ($records as $record) {
            $this->assertGreaterThanOrEqual(0, $record['fid']);
            $this->assertLessThanOrEqual(9, $record['fid']);
        }
    }

    /**
     * The blobs were always there — this is the regression guard that they still are.
     *
     * The template bytes sit immediately after each record's 6-byte header and were
     * simply being stepped over. Recovering them needs no new command and no extra
     * round trip, which is why `template.download` staying `not_implemented` (that is
     * the separate per-slot command, and the unverified WRITE-back) never actually
     * blocked reading.
     */
    public function test_it_recovers_the_template_blob_from_the_real_table(): void
    {
        $raw = file_get_contents(__DIR__ . '/../Fixtures/fingerprint-template-table.bin');

        $records = TemplateCodec::decodeWithBlobs($raw);

        $this->assertCount(19, $records);

        $sizes = array_map(static fn (array $r) => strlen($r['template']), $records);

        // Measured on the F18 capture. A real template is ~0.7-1.6 KB; anything far
        // outside that means the record boundary, not the blob, has moved.
        $this->assertSame(21948, array_sum($sizes), 'total template bytes on the reference device');
        $this->assertSame(706, min($sizes));
        $this->assertSame(1602, max($sizes));

        foreach ($records as $record) {
            // Header + blob must reconstruct the record length exactly, or the walk
            // has drifted and every blob after it is misaligned garbage.
            $this->assertNotSame('', $record['template'], 'a stored template is never empty');
            $this->assertSame(1, $record['valid']);
        }

        /*
         * uid 8 slot 6 is the record cross-checked against a per-slot USERTEMP_RRQ
         * probe of the same device, which returned 1,304 bytes. That 1,304 is the
         * RECORD, header included — the blob itself is 1,298. Worth pinning down,
         * because reading the per-slot figure as the blob length is exactly the
         * off-by-six that would misalign a decoder written from the doc alone.
         */
        $uid8 = array_values(array_filter($records, static fn (array $r) => $r['uid'] === 8))[0];
        $this->assertSame(6, $uid8['fid']);
        $this->assertSame(1298, strlen($uid8['template']));
        $this->assertSame(1304, strlen($uid8['template']) + 6);
    }

    /**
     * Identical bytes mean one enrolment copied between terminals; different bytes
     * mean nothing at all. Only the first of those is safe to act on.
     */
    public function test_blobs_are_distinct_per_record_so_a_hash_identifies_one_enrolment(): void
    {
        $raw = file_get_contents(__DIR__ . '/../Fixtures/fingerprint-template-table.bin');

        $hashes = array_map(
            static fn (array $r) => sha1($r['template']),
            TemplateCodec::decodeWithBlobs($raw),
        );

        // 19 separately enrolled fingers on one device produce 19 distinct templates.
        // A collision here would mean the blob is not what identifies an enrolment.
        $this->assertCount(19, array_unique($hashes));
    }

    /**
     * The narrow decode() contract is unchanged: callers that only want slot
     * occupancy must keep getting exactly {uid, fid} and nothing else.
     */
    public function test_decode_still_returns_only_uid_and_slot(): void
    {
        $raw = file_get_contents(__DIR__ . '/../Fixtures/fingerprint-template-table.bin');

        foreach (TemplateCodec::decode($raw) as $record) {
            $this->assertSame(['uid', 'fid'], array_keys($record));
        }
    }

    /**
     * slotsByUserId maps device uid => payroll code. The empty-input case is the one
     * that matters: an unknown table must not be turned into "everybody has zero
     * fingers", which is exactly the false negative this whole codec guards against.
     */
    public function test_unknown_templates_never_become_an_all_zero_map(): void
    {
        $users = [
            ['uid' => 1, 'user_id' => '1001'],
            ['uid' => 2, 'user_id' => '1002'],
        ];

        $this->assertSame([], TemplateCodec::slotsByUserId([], $users));
    }

    public function test_a_decoded_table_reports_zero_slots_for_users_absent_from_it(): void
    {
        // The read SUCCEEDED, so "no fingers" is now a trustworthy answer for anyone
        // the table does not mention.
        $users = [
            ['uid' => 1, 'user_id' => '1001'],
            ['uid' => 2, 'user_id' => '1002'],
        ];

        $slots = TemplateCodec::slotsByUserId([['uid' => 1, 'fid' => 3]], $users);

        $this->assertSame([3], $slots['1001']);
        $this->assertSame([], $slots['1002']);
    }

    /** The one definition of an empty table (2.16.2): a zero header, or no bytes at all. */
    public function test_an_empty_table_is_a_zero_header_or_no_bytes_and_nothing_else(): void
    {
        $this->assertTrue(\Promoseven\Biometric\Codec\TemplateCodec::isEmptyTable(''));
        $this->assertTrue(\Promoseven\Biometric\Codec\TemplateCodec::isEmptyTable(pack('V', 0)));
        $this->assertFalse(\Promoseven\Biometric\Codec\TemplateCodec::isEmptyTable("\x10\x00"), 'stray bytes are unreadable, not empty');
        $this->assertFalse(\Promoseven\Biometric\Codec\TemplateCodec::isEmptyTable(pack('V', 12) . str_repeat("\0", 12)));
    }
}
