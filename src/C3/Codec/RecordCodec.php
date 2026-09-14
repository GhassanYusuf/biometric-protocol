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

                $size = $data[$pos++];
                $raw = array_slice($data, $pos, $size);
                $pos += $size;

                if (count($raw) < $size) {
                    $complete = false;
                    break;
                }

                $field = $byIndex[$fieldIndex] ?? ['name' => "f{$fieldIndex}", 'type' => 's'];

                if ($field['type'] === 'i') {
                    $value = 0;

                    foreach (array_reverse($raw) as $byte) {
                        $value = ($value << 8) | $byte;
                    }

                    $row[$field['name']] = $value;
                } elseif ($field['type'] === 'b') {
                    // A template blob. The library hands back its LENGTH and not its
                    // bytes at this layer: biometric data leaves here only through a
                    // caller that asked for it explicitly (rule 16).
                    $row[$field['name']] = '<'.$size.' bytes>';
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
}
