<?php

/*
 * This file is part of promoseven/biometric-protocol.
 *
 * Copyright (c) 2026 Promoseven. All rights reserved.
 */

namespace Promoseven\Biometric\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Promoseven\Biometric\C3\Codec\RecordCodec;

/**
 * The C3 `templatev10` table, and the one byte that made it look unreadable.
 *
 * The panel publishes the schema itself:
 *
 *   templatev10=10,Size=i1,UID=i2,Pin=i3,FingerID=i4,Valid=i5,Template=B6,Resverd=i7,EndTag=i8
 *
 * Every C3 field is length-prefixed. For most fields that prefix is ONE byte, which
 * tops out at 255 — and these templates run to 1,618. The blob's prefix is TWO bytes,
 * and reading it as one consumed 110 bytes of an 878-byte template, lost alignment
 * inside the first record, and turned every record after it into plausible-looking
 * nonsense. That is the failure rule 10 exists to prevent, and it is why this test
 * asserts on ALIGNMENT rather than on any single decoded value.
 *
 * THE FIXTURE IS SYNTHETIC ON PURPOSE. A real capture holds other people's
 * fingerprints; rule 16 says commit the structure and never the payload. The framing
 * is what matters and the framing is reproduced exactly.
 */
class C3TemplateTableTest extends TestCase
{
    private const TABLE_INDEX = 10;

    /** @return array<string,array{index:int,type:string}> */
    private function fields(): array
    {
        return [
            'Size' => ['index' => 1, 'type' => 'i'],
            'UID' => ['index' => 2, 'type' => 'i'],
            'Pin' => ['index' => 3, 'type' => 'i'],
            'FingerID' => ['index' => 4, 'type' => 'i'],
            'Valid' => ['index' => 5, 'type' => 'i'],
            'Template' => ['index' => 6, 'type' => 'b'],
            'Resverd' => ['index' => 7, 'type' => 'i'],
            'EndTag' => ['index' => 8, 'type' => 'i'],
        ];
    }

    private function decode(): array
    {
        $raw = file_get_contents(__DIR__ . '/../Fixtures/c3-templatev10-synthetic.bin');

        return RecordCodec::decode($raw, self::TABLE_INDEX, [1, 2, 3, 4, 5, 6, 7, 8], $this->fields());
    }

    public function test_every_record_decodes_and_the_walk_lands_exactly(): void
    {
        $rows = $this->decode();

        // Three records in, three records out. A one-byte blob prefix yields one
        // good record and then garbage, so the COUNT is the alignment assertion.
        $this->assertCount(3, $rows);
    }

    public function test_the_declared_size_matches_the_blob_on_every_record(): void
    {
        foreach ($this->decode() as $row) {
            // Belt and braces the panel itself provides: Size is carried as its own
            // field AND as the blob's two-byte prefix. They agreeing on every record
            // is what proves the walk never drifted.
            $this->assertSame($row['Size'], strlen($row['Template']));
        }
    }

    public function test_a_template_longer_than_one_length_byte_survives(): void
    {
        $rows = $this->decode();

        // 1,618 bytes — six times what a single length byte can express. This is the
        // record that used to destroy the read.
        $this->assertSame(1618, strlen($rows[2]['Template']));
        $this->assertSame(940, $rows[2]['Pin']);
        $this->assertSame(0, $rows[2]['FingerID']);
    }

    public function test_the_fixed_fields_are_not_disturbed_by_the_wider_prefix(): void
    {
        $rows = $this->decode();

        $this->assertSame([10, 225, 940], array_column($rows, 'Pin'));
        $this->assertSame([3, 6, 0], array_column($rows, 'FingerID'));
        $this->assertSame([1, 1, 1], array_column($rows, 'Valid'));
        // Trailing fields are the canary: if the blob over- or under-ran, these are
        // the first values to turn into huge nonsense.
        $this->assertSame([0, 0, 0], array_column($rows, 'EndTag'));
    }

    public function test_the_blob_carries_the_zkfinger_signature(): void
    {
        foreach ($this->decode() as $row) {
            // "SS21" at offset 2, as observed on every one of the 238 templates read
            // from each panel on 2026-09-15.
            $this->assertSame('SS21', substr($row['Template'], 2, 4));
        }
    }
}
