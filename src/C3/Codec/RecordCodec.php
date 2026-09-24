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
 * Decodes the panel's record stream into rows.
 *
 * Each record is a run of length-prefixed field values, in the field-index order
 * the panel echoes at the head of the reply. One byte of length, then that many
 * bytes of value. Integers are little-endian across whatever width the panel chose,
 * which varies by field and by table — so the width is read, never assumed.
 *
 * ONE EXCEPTION, and it is not optional: a BLOB field (type `b`/`B`, which in practice
 * means a fingerprint template) is prefixed with TWO length bytes. It has to be — a
 * single byte tops out at 255 and these templates run to 1,618. See the walk below.
 *
 * WHY THE HEADER IS DETECTED AND NOT ASSUMED: an inline REPLY_OK prefixes its
 * records with the table index and the field list. Whether a BUFFERED payload
 * repeats that header is documented nowhere — not in the reference libraries and
 * not in the vendor SDK's disassembly. Reading a record stream one byte out of
 * phase produces rows that look entirely real and are entirely wrong, which is
 * exactly the failure rule 10 exists to prevent. So we look, rather than assume.
 */
final class RecordCodec
{
    /**
     * @param  list<int>  $expectedFieldIndexes  ascending, as requested
     * @param  array<string,array{index:int,type:string}>  $fields
     * @return list<array<string,int|string>>
     */
    public static function decode(
        string $payload,
        int $tableIndex,
        array $expectedFieldIndexes,
        array $fields,
    ): array {
        if ($payload === '') {
            return [];
        }

        $bytes = array_values(unpack('C*', $payload));
        $offset = 0;
        $order = $expectedFieldIndexes;

        if (($bytes[0] ?? -1) === $tableIndex && ($bytes[1] ?? -1) === count($expectedFieldIndexes)) {
            $count = $bytes[1];
            $order = array_slice($bytes, 2, $count);
            $offset = 2 + $count;
        }

        $byIndex = [];

        foreach ($fields as $name => $meta) {
            $byIndex[$meta['index']] = ['name' => $name, 'type' => $meta['type']];
        }

        $rows = [];
        $data = array_slice($bytes, $offset);
        $total = count($data);
        $pos = 0;

        while ($pos < $total) {
            $row = [];
            $complete = true;

            foreach ($order as $fieldIndex) {
                if ($pos >= $total) {
                    // A trailing partial record. Stop rather than emit a row whose
                    // later fields would silently read as zero.
                    $complete = false;
                    break;
                }

                $field = $byIndex[$fieldIndex] ?? ['name' => "f{$fieldIndex}", 'type' => 's'];

                /*
                 * A BLOB FIELD IS LENGTH-PREFIXED WITH TWO BYTES, NOT ONE.
                 *
                 * CONFIRMED on the inBIO460 @ 192.168.7.61 and the TF1700 @
                 * 192.168.7.60, 2026-09-15. Every other field carries a single length
                 * byte, so it can hold at most 255 bytes — and a fingerprint template
                 * is 564-1,618. Reading one byte there consumed 110 of an 878-byte
                 * template and lost alignment inside the first record; every row after
                 * it decoded into plausible-looking nonsense, which is exactly the
                 * failure rule 10 exists to prevent.
                 *
                 * With two bytes the walk consumes 281,680 of 281,680 bytes on both
                 * panels, yielding 238 records — the figure the vendor's own
                 * Machines.fingercount reports for each — and the declared Size field
                 * equals the blob length on every single record.
                 */
                if ($field['type'] === 'b') {
                    if ($pos + 2 > $total) {
                        $complete = false;
                        break;
                    }

                    $size = $data[$pos] | ($data[$pos + 1] << 8);
                    $pos += 2;
                } else {
                    $size = $data[$pos++];
                }

                $raw = array_slice($data, $pos, $size);
                $pos += $size;

                if (count($raw) < $size) {
                    $complete = false;
                    break;
                }

                if ($field['type'] === 'i') {
                    $value = 0;

                    foreach (array_reverse($raw) as $byte) {
                        $value = ($value << 8) | $byte;
                    }

                    $row[$field['name']] = $value;
                } elseif ($field['type'] === 'b') {
                    // The blob itself. Callers that only want to know a template is
                    // there read its length; callers that need to compare enrolments
                    // hash it. Neither should print it (rule 16).
                    $row[$field['name']] = pack('C*', ...($raw ?: [0]));
                    if ($raw === []) {
                        $row[$field['name']] = '';
                    }
                } else {
                    $row[$field['name']] = rtrim(pack('C*', ...$raw), "\0");
                }
            }

            if (! $complete) {
                break;
            }

            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Builds a SET_DATA payload: the mirror of decode() for writes.
     *
     * Wire shape per xub/zkaccess-c3-py `main` @ a6b7b92c (`set_user()`), which is the
     * same record format decode() reads: `[table, field count, field ids...]`, then per
     * row, per field, `<1-byte length><value>`. Integers little-endian in the fewest
     * bytes, 0 as a single 0x00 (length 1); strings as their bytes, empty = length 0.
     *
     * FIELD IDS COME FROM THE PANEL'S OWN CATALOGUE, never from constants: the fork
     * hard-codes user = CardNo 1, Pin 2..., while the TF1700 publishes UID 1, CardNo 2,
     * Pin 3 (docs/device-capabilities.md). Only the fields named in $values are sent,
     * in catalogue order.
     *
     * BLOB fields (fingerprint templates) are refused unless $allowBlobs — only
     * Panel::moveUser() writes them, re-writing a person's OWN templates under a new
     * Pin. A blob carries a TWO-byte length, as on the read side (decode()).
     *
     * EXPERIMENTAL. CONFIRMED for `user` / `userauthorize` rows on the TF1700
     * (2026-09-24).
     *
     * @param array<string,array{index:int,type:string}> $fields   the table's catalogue entry
     * @param list<array<string,int|string>>             $rows     field name => value
     */
    public static function encode(int $tableIndex, array $fields, array $rows, bool $allowBlobs = false): string
    {
        if ($rows === []) {
            throw new \InvalidArgumentException('Nothing to write.');
        }

        $names = array_keys($rows[0]);
        foreach ($rows as $row) {
            if (array_keys($row) !== $names) {
                throw new \InvalidArgumentException('Every row must carry the same fields in the same order.');
            }
        }

        $send = [];
        foreach ($names as $name) {
            if (! isset($fields[$name])) {
                throw new \InvalidArgumentException("This panel's table has no field '{$name}'.");
            }
            if ($fields[$name]['type'] === 'b' && ! $allowBlobs) {
                throw new \InvalidArgumentException("Refusing to write blob field '{$name}'.");
            }
            $send[$name] = $fields[$name];
        }
        uasort($send, fn ($a, $b) => $a['index'] <=> $b['index']);

        $out = pack('C*', $tableIndex, count($send), ...array_map(fn ($f) => $f['index'], array_values($send)));

        foreach ($rows as $row) {
            foreach ($send as $name => $meta) {
                $out .= self::encodeValue($row[$name], $meta['type'], $name);
            }
        }

        return $out;
    }

    /** DELETE_DATA payload: `[table, 1, key field id]` + `<len><value>` (same fork, delete_user()). */
    public static function encodeDeleteKey(int $tableIndex, array $fields, string $keyField, int|string $value): string
    {
        if (! isset($fields[$keyField])) {
            throw new \InvalidArgumentException("This panel's table has no field '{$keyField}'.");
        }

        return pack('C*', $tableIndex, 1, $fields[$keyField]['index'])
            .self::encodeValue($value, $fields[$keyField]['type'], $keyField);
    }

    private static function encodeValue(int|string $value, string $type, string $name): string
    {
        if ($type === 'b') {
            $bytes = (string) $value;
            if (strlen($bytes) > 0xFFFF) {
                throw new \InvalidArgumentException("Blob field '{$name}' is longer than 65535 bytes.");
            }

            return pack('v', strlen($bytes)).$bytes;
        }

        if ($type === 'i') {
            $v = (int) $value;
            if ($v < 0) {
                throw new \InvalidArgumentException("Field '{$name}' cannot be negative.");
            }
            $bytes = '';
            do {
                $bytes .= chr($v & 0xFF);
                $v >>= 8;
            } while ($v > 0);

            return chr(strlen($bytes)).$bytes;
        }

        $bytes = (string) $value;
        if (strlen($bytes) > 255) {
            throw new \InvalidArgumentException("Field '{$name}' is longer than 255 bytes.");
        }

        return chr(strlen($bytes)).$bytes;
    }
}
