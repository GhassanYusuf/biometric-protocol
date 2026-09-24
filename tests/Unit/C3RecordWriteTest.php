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
use Promoseven\Biometric\C3\Codec\Catalogue;
use Promoseven\Biometric\C3\Codec\RecordCodec;

/**
 * C3 SET_DATA / DELETE_DATA payloads, with no panel.
 *
 * 1. Against the reference: given the reference's OWN 7-field user schema, the
 *    encoder reproduces xub/zkaccess-c3-py main@a6b7b92c byte for byte (expected hex
 *    generated 2026-09-24 by running its set_user()/delete_user() code as written).
 * 2. Against OUR panel: given the TF1700's published schema, the same call yields
 *    the TF1700's field ids — the disagreement that makes hard-coded ids dangerous —
 *    and round-trips through decode().
 */
final class C3RecordWriteTest extends TestCase
{
    /** The reference's user table: CardNo 1, Pin 2, Password 3 (s), Group 4, StartTime 5, EndTime 6, SuperAuthorize 7. */
    private const FORK_USER = [
        'CardNo' => ['index' => 1, 'type' => 'i'], 'Pin' => ['index' => 2, 'type' => 'i'],
        'Password' => ['index' => 3, 'type' => 's'], 'Group' => ['index' => 4, 'type' => 'i'],
        'StartTime' => ['index' => 5, 'type' => 'i'], 'EndTime' => ['index' => 6, 'type' => 'i'],
        'SuperAuthorize' => ['index' => 7, 'type' => 'i'],
    ];

    private function tf1700(): Catalogue
    {
        return Catalogue::parse(file_get_contents(__DIR__.'/../Fixtures/c3-datatable-cfg-tf1700.txt'));
    }

    public function test_matches_the_reference_byte_for_byte_on_the_reference_schema(): void
    {
        $row = ['CardNo' => 777000000, 'Pin' => 999, 'Password' => '', 'Group' => 0, 'StartTime' => 0, 'EndTime' => 0, 'SuperAuthorize' => 0];

        $this->assertSame('010701020304050607044014502e02e703000100010001000100', bin2hex(RecordCodec::encode(1, self::FORK_USER, [$row])));
        $this->assertSame('01010202e703', bin2hex(RecordCodec::encodeDeleteKey(1, self::FORK_USER, 'Pin', 999)));
    }

    public function test_on_the_tf1700_the_same_fields_get_the_panel_s_own_ids(): void
    {
        $c = $this->tf1700();
        $payload = RecordCodec::encode($c->indexOf('user'), $c->fields('user'), [['CardNo' => 777000000, 'Pin' => 999]]);

        // table 1, 2 fields, ids 2 (CardNo) and 3 (Pin) — NOT the reference's 1 and 2.
        $this->assertSame('01020203', bin2hex(substr($payload, 0, 4)));

        // Delete by Pin resolves to id 3 here; the reference's id 2 would be CardNo.
        $this->assertSame('01010302e703', bin2hex(RecordCodec::encodeDeleteKey($c->indexOf('user'), $c->fields('user'), 'Pin', 999)));
    }

    public function test_round_trips_through_decode(): void
    {
        $c = $this->tf1700();
        $row = ['CardNo' => 0, 'Pin' => 99999991, 'Password' => '', 'Group' => 0, 'StartTime' => 0, 'EndTime' => 0, 'Name' => 'zk-test', 'Privilege' => 0, 'SuperAuthorize' => 0];
        $payload = RecordCodec::encode($c->indexOf('user'), $c->fields('user'), [$row]);

        $sent = $c->fields('user');
        unset($sent['UID']);
        $ids = array_values(array_map(fn ($f) => $f['index'], $sent));
        $decoded = RecordCodec::decode($payload, $c->indexOf('user'), $ids, $c->fields('user'));

        $this->assertSame([$row], $decoded);
    }

    public function test_refuses_blobs_unknown_fields_and_mixed_rows(): void
    {
        $c = $this->tf1700();

        foreach ([
            fn () => RecordCodec::encode($c->indexOf('templatev10'), $c->fields('templatev10'), [['Pin' => 1, 'Template' => 'x']]),
            fn () => RecordCodec::encode($c->indexOf('user'), $c->fields('user'), [['Nope' => 1]]),
            fn () => RecordCodec::encode($c->indexOf('user'), $c->fields('user'), [['Pin' => 1], ['CardNo' => 2]]),
            fn () => RecordCodec::encodeDeleteKey($c->indexOf('user'), $c->fields('user'), 'Nope', 1),
        ] as $call) {
            try {
                $call();
                $this->fail('Expected a refusal.');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_a_template_row_round_trips_with_a_two_byte_length_when_allowed(): void
    {
        $c = $this->tf1700();
        $blob = "\x00\x00SS21".str_repeat("\xAB", 700); // > 255, so a one-byte length could not carry it
        $row = ['Size' => strlen($blob), 'UID' => 296, 'Pin' => 99999992, 'FingerID' => 5, 'Valid' => 1, 'Template' => $blob, 'Resverd' => 0, 'EndTag' => 13];

        $payload = RecordCodec::encode($c->indexOf('templatev10'), $c->fields('templatev10'), [$row], allowBlobs: true);
        $decoded = RecordCodec::decode($payload, $c->indexOf('templatev10'), $c->fieldIndexes('templatev10'), $c->fields('templatev10'));

        $this->assertSame([$row], $decoded);
    }
}
