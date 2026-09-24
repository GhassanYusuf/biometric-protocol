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
 * The device's user table.
 *
 * 4-byte byte-length header followed by fixed-width records — 72 bytes on the
 * iClock/U-series family (CONFIRMED on ZKTeco F18, 20 users read cleanly).
 *
 * Field layout: uid(2)@0, privilege(1)@2, password(8)@3, name(24)@11, card(4)@35,
 * group(1)@39, tz flags@40..47, user_id(9)@48, padding to 72.
 */
final class UserCodec
{
    /** Record widths this codec understands, in preference order. */
    public const WIDTHS = [72];

    private function __construct()
    {
    }

    /**
     * @return list<array{uid:int,user_id:string,name:string,privilege:int,card_number:int}|array{raw:string}>
     */
    public static function decode(string $raw): array
    {
        $body = RecordBuffer::body($raw);

        if ($body === '') {
            return [];
        }

        $recordSize = RecordBuffer::detectRecordSize(strlen($body), self::WIDTHS);

        if ($recordSize <= 0) {
            // Truncated / misaligned buffer, e.g. dropped UDP datagrams. Nothing
            // here is safe to decode, and a partial user list would be worse than
            // none — callers treat [] as "could not read", not "no users".
            return [];
        }

        $users = [];

        for ($offset = 0; $offset + $recordSize <= strlen($body); $offset += $recordSize) {
            $chunk = substr($body, $offset, $recordSize);

            if ($recordSize >= 72) {
                $uid = unpack('v', substr($chunk, 0, 2))[1];
                $privilege = ord($chunk[2]);
                $name = RecordBuffer::cString(substr($chunk, 11, 24));
                $cardNumber = unpack('V', substr($chunk, 35, 4))[1];
                $userId = RecordBuffer::cString(substr($chunk, 48, 9));

                $users[] = [
                    'uid' => $uid,
                    // Fall back to the uid when the device left the id field empty,
                    // so a record is never keyless.
                    'user_id' => $userId !== '' ? $userId : (string) $uid,
                    'name' => $name,
                    'privilege' => $privilege,
                    'card_number' => $cardNumber,
                ];
            } else {
                $users[] = ['raw' => bin2hex($chunk)];
            }
        }

        return $users;
    }

    /**
     * Finds one user by their device user id (the "PIN" / employee code).
     *
     * @param list<array<string,mixed>> $users
     * @return array<string,mixed>|null
     */
    public static function find(array $users, string $userId): ?array
    {
        foreach ($users as $user) {
            if ((string) ($user['user_id'] ?? '') === $userId) {
                return $user;
            }
        }

        return null;
    }

    /**
     * The device's own 72-byte record for one uid, untouched, or null.
     *
     * For writes that must carry fields this codec does not decode (password, time
     * zones) back to the device exactly — see Packet::withUserId().
     */
    public static function rawRecord(string $raw, int $uid): ?string
    {
        $body = RecordBuffer::body($raw);
        $recordSize = $body === '' ? 0 : RecordBuffer::detectRecordSize(strlen($body), self::WIDTHS);

        if ($recordSize !== 72) {
            return null;
        }

        for ($offset = 0; $offset + 72 <= strlen($body); $offset += 72) {
            $chunk = substr($body, $offset, 72);
            if (unpack('v', substr($chunk, 0, 2))[1] === $uid) {
                return $chunk;
            }
        }

        return null;
    }

    /**
     * Next unused device-internal uid.
     *
     * Currently max + 1 rather than gap-filling. Documented limitation: on a
     * terminal with a capped user count, heavy churn will eventually exhaust the
     * range even while low uids sit free. See docs/change-log-or-roadmap.md.
     *
     * @param list<array<string,mixed>> $users
     */
    public static function nextFreeUid(array $users): int
    {
        $max = 0;

        foreach ($users as $user) {
            $max = max($max, (int) ($user['uid'] ?? 0));
        }

        return $max + 1;
    }
}
