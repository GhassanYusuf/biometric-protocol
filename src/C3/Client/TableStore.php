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

namespace Promoseven\Biometric\C3\Client;

use Promoseven\Biometric\C3\Codec\Catalogue;

/**
 * The four table operations a C3 panel offers: its schema, read, write, delete.
 *
 * Panel implements it over the wire. It exists as an interface so that the logic
 * built ON those operations — Personnel's add / edit / delete / fingerprint push,
 * with their read-backs and undo paths — can be tested against an in-memory panel
 * with no device present (rule 12), which is how every branch of an undo path gets
 * exercised before one runs on a live entrance.
 */
interface TableStore
{
    public function catalogue(): Catalogue;

    /** @return list<array<string,int|string>> */
    public function readTable(string $table, ?callable $onProgress = null): array;

    /** @param list<array<string,int|string>> $rows */
    public function writeRows(string $table, array $rows, bool $allowBlobs = false): void;

    public function deleteRows(string $table, string $keyField, int|string $value): void;
}
