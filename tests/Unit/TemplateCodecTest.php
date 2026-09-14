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
}
