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

use Promoseven\Biometric\Exception\ProtocolException;

/**
 * The panel's data-table catalogue, as returned by DATATABLE_CFG (0x06).
 *
 * The panel describes its own schema, which is the single most useful thing about
 * this protocol: table indexes and field indexes are NOT constants to hard-code,
 * they are read from the device. The inBIO460 reports 12 tables and the TF1700
 * reports 11, on the same firmware family — so a hard-coded index would silently
 * address the wrong table on one of them.
 *
 * Wire format is one line per table, newline separated:
 *
 *     transaction=5,Cardno=i1,Pin=i2,Verified=i3,DoorID=i4,EventType=i5,InOutState=i6,Time_second=i7
 *
 * Field types seen: i = integer, s = string, b/B = blob (a biometric template).
 */
final class Catalogue
{
    /** @param array<string,array{index:int,fields:array<string,array{index:int,type:string}>}> $tables */
    private function __construct(private readonly array $tables) {}

    public static function parse(string $payload): self
    {
        $tables = [];

        foreach (explode("\x0a", $payload) as $line) {
            if (! preg_match('/^(\w+)=(\d+),(.*)$/', trim($line), $m)) {
                continue;
            }

            $fields = [];

            foreach (explode(',', $m[3]) as $pair) {
                if (preg_match('/^(\w+)=([isbB])(\d+)$/', $pair, $fm)) {
                    $fields[$fm[1]] = ['index' => (int) $fm[3], 'type' => strtolower($fm[2])];
                }
            }

            $tables[$m[1]] = ['index' => (int) $m[2], 'fields' => $fields];
        }

        if ($tables === []) {
            throw new ProtocolException('The panel returned a data-table catalogue we could not parse.');
        }

        return new self($tables);
    }

    public function has(string $table): bool
    {
        return isset($this->tables[$table]);
    }

    /** @return list<string> */
    public function tableNames(): array
    {
        return array_keys($this->tables);
    }

    public function indexOf(string $table): int
    {
        return $this->table($table)['index'];
    }

    /** @return array<string,array{index:int,type:string}> */
    public function fields(string $table): array
    {
        return $this->table($table)['fields'];
    }

    /**
     * The field indexes, ascending — the order a GET_DATA request asks for and the
     * order the panel answers in.
     *
     * @return list<int>
     */
    public function fieldIndexes(string $table): array
    {
        $indexes = array_map(static fn (array $f): int => $f['index'], $this->fields($table));
        sort($indexes);

        return array_values($indexes);
    }

    /** @return array{index:int,fields:array<string,array{index:int,type:string}>} */
    private function table(string $table): array
    {
        if (! isset($this->tables[$table])) {
            throw new ProtocolException(
                "This panel has no table '{$table}'. It offers: ".implode(', ', $this->tableNames()).'.',
            );
        }

        return $this->tables[$table];
    }
}
