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

namespace Promoseven\Biometric\C3\Service;

use Promoseven\Biometric\C3\Client\TableStore;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;

/**
 * People on a C3 / PullSDK panel: add, edit, delete, and fingerprint push.
 *
 * WHAT A PERSON IS ON A C3 PANEL — three tables, keyed by Pin:
 *
 *   user           Pin, UID (the panel's own slot, assigned by the panel), CardNo,
 *                  Name, Password, Group, StartTime, EndTime, SuperAuthorize and, on
 *                  the TF1700 only, Privilege.
 *   userauthorize  one row per (time zone, door bitmask) the person may open.
 *                  WITHOUT A ROW HERE THE PERSON OPENS NO DOOR — a user row alone is
 *                  a name the panel knows and refuses.
 *   templatev10    one row per finger: Pin, UID (must be the user row's UID — 238 of
 *                  238 real rows on the TF1700 carry it, 2026-09-24), FingerID 0-9,
 *                  Valid, Size, Template (ZKFinger v10 blob), Resverd 0, EndTag 13.
 *
 * Order. ZKAccess adds user → userauthorize, with templatev10 as a separate command,
 * and deletes templatev10 → user → userauthorize (ZKAccess 3.5.5 IL, 2026-09-24,
 * draft/analysis/05). Here delete removes the door rows BEFORE the user row, so a
 * failure half-way never leaves a user with no doors that still looks enrolled.
 *
 * Duress: `Valid` 1 = normal finger, 3 = duress (ZKAccess's ValidType enum).
 *
 * EVERY WRITE IS READ BACK. SET_DATA's ACK means the panel parsed the frame, not
 * that it kept the row: the reference fork records that a malformed record is
 * silently ignored (xub/zkaccess-c3-py main@a6b7b92c). Nothing here reports success
 * on an acknowledgement (rule 10).
 *
 * FIELD NAMES, NEVER IDS. Every row is written by name and encoded through the
 * panel's own catalogue, and a field the panel's table does not carry is dropped
 * before the write (the inBIO460's `user` has no Privilege). That is the whole
 * lesson of the reference fork, whose hard-coded ids would write a TF1700's Pin
 * into its CardNo.
 *
 * EXPERIMENTAL as a whole: built on writeRows()/deleteRows(), which are CONFIRMED on
 * both panels (TF1700 .60 and inBIO460 .61, 2026-09-24, test user), but each
 * operation here is promoted per model only after it has run on that model.
 */
final class Personnel
{
    /**
     * Resverd and EndTag as every real templatev10 row carries them: 238 of 238 on
     * the TF1700 and the inBIO460, read 2026-09-24. CONFIRMED (both panels).
     */
    private const TEMPLATE_RESERVED = 0;

    private const TEMPLATE_END_TAG = 13;

    /**
     * ZKFinger v10 blobs carry `SS21` at offset 2 — every one of 476 panel rows.
     * Spelled in hex because DeviceModelIsolationTest reads "letters + digits" as a
     * device model (rule 15); this is a template format marker, not a model.
     */
    private const TEMPLATE_SIGNATURE = "\x53\x53\x32\x31";

    public function __construct(private readonly TableStore $panel) {}

    /** The person's `user` row, or null when the panel does not hold that Pin. */
    public function find(int $pin): ?array
    {
        $rows = $this->rows('user', $pin);

        if (count($rows) > 1) {
            throw new VerificationException(sprintf('The panel holds %d user rows under Pin %d; refusing to guess which is real.', count($rows), $pin));
        }

        return $rows[0] ?? null;
    }

    /**
     * The door permissions most people on this panel have — what a new person gets
     * when the caller does not say.
     *
     * Every person on both panels here had exactly one row, time zone 1 / door 1, on
     * 2026-09-24; this reads the panel rather than hard-coding that, so a panel set up
     * differently gives its own answer. Returns [] on a panel with nobody authorised,
     * and the caller decides what that means.
     *
     * @return list<array{AuthorizeTimezoneId:int, AuthorizeDoorId:int}>
     */
    public function commonAuthorization(): array
    {
        $byPin = [];
        foreach ($this->panel->readTable('userauthorize') as $r) {
            $byPin[(int) $r['Pin']][] = [(int) $r['AuthorizeTimezoneId'], (int) $r['AuthorizeDoorId']];
        }

        $tally = [];
        foreach ($byPin as $pairs) {
            sort($pairs);
            $key = json_encode($pairs);
            $tally[$key] = ($tally[$key] ?? 0) + 1;
        }

        if ($tally === []) {
            return [];
        }

        arsort($tally);

        return array_map(
            fn (array $p) => ['AuthorizeTimezoneId' => $p[0], 'AuthorizeDoorId' => $p[1]],
            json_decode((string) array_key_first($tally), true),
        );
    }

    /**
     * Adds a person: user row, then door permissions. EXPERIMENTAL.
     *
     * Refuses a Pin already in ANY of the three tables — including orphaned door or
     * fingerprint rows with no user row, which the new person would otherwise inherit.
     * UID is never sent: the panel assigns it (OBSERVED 287 on the TF1700 and the
     * inBIO460 alike, 2026-09-24) and the read-back reports it.
     *
     * If the door rows do not land, the user row is removed again, so a failure leaves
     * the panel as it was rather than holding a person who opens nothing.
     *
     * @param list<array{AuthorizeTimezoneId:int, AuthorizeDoorId:int}>|null $doors null = commonAuthorization()
     * @return array<string,int|string> the user row as read back
     */
    public function add(int $pin, string $name, int $cardNo = 0, ?array $doors = null, string $password = ''): array
    {
        $this->assertPin($pin);
        $this->assertPinFree($pin);

        $this->assertCardFree($cardNo, $pin);

        $doors ??= $this->commonAuthorization();

        $this->panel->writeRows('user', [$this->onlyKnown('user', [
            'CardNo' => $cardNo,
            'Pin' => $pin,
            // The keypad password (2.13.0); '' = none, as it always was before.
            'Password' => $password,
            'Group' => 0,
            'StartTime' => 0,
            'EndTime' => 0,
            'Name' => $this->name($name),
            'Privilege' => 0,
            'SuperAuthorize' => 0,
        ])]);

        $user = $this->find($pin);
        if ($user === null) {
            throw new VerificationException("The panel accepted Pin {$pin} but does not show it when read back.");
        }
        $this->assertFields($user, ['Name' => $this->name($name), 'CardNo' => $cardNo, 'Password' => $password], $pin);

        if ($doors !== [] && $this->panel->catalogue()->has('userauthorize')) {
            try {
                $this->panel->writeRows('userauthorize', array_map(fn (array $d) => [
                    'Pin' => $pin,
                    'AuthorizeTimezoneId' => (int) $d['AuthorizeTimezoneId'],
                    'AuthorizeDoorId' => (int) $d['AuthorizeDoorId'],
                ], $doors));

                if (count($this->rows('userauthorize', $pin)) !== count($doors)) {
                    throw new VerificationException("The panel accepted door permissions for Pin {$pin} but does not show them when read back.");
                }
            } catch (\Throwable $e) {
                $this->quietlyDelete(['userauthorize', 'user'], $pin);

                throw new VerificationException("Could not give Pin {$pin} its doors, so the new user was removed again: {$e->getMessage()}");
            }
        }

        return $user;
    }

    /**
     * Changes a person's name and/or card, keeping UID, doors and fingerprints.
     * EXPERIMENTAL. Null leaves a field as it is.
     *
     * HOW: SET_DATA of the existing row with only the changed fields replaced and
     * WITHOUT the UID — exactly ZKAccess's edit, which is the same SetDeviceData("User")
     * as its add, with no delete first; the panel upserts on Pin (ZKAccess 3.5.5
     * UserDal::Add / `update|user$`, read from its IL 2026-09-24, draft/analysis/05).
     *
     * AND THEN PROVES IT. Read back: exactly one row under the Pin, the same UID, the
     * new values, and the door and fingerprint rows unchanged. A panel that APPENDED a
     * second row instead of updating would show two rows under the Pin; that is
     * detected and reported, never "undone" with a delete by Pin, which would take the
     * original with it.
     *
     * @return array<string,int|string> the user row as read back
     */
    public function update(int $pin, ?string $name = null, ?int $cardNo = null, ?string $password = null): array
    {
        $before = $this->find($pin);
        if ($before === null) {
            throw new ProtocolException("Pin {$pin} is not on this panel.");
        }

        // Fingerprints left pointing at an old UID are re-linked first, even when
        // nothing else changes — a re-push is how an operator repairs it (2.11.1).
        $this->relinkFingerprints($pin);

        $want = [];
        if ($name !== null) {
            $want['Name'] = $this->name($name);
        }
        if ($cardNo !== null) {
            $want['CardNo'] = $cardNo;
        }
        // Null keeps the row's own Password, which the edit carries over (2.13.0).
        if ($password !== null) {
            $want['Password'] = $password;
        }
        if ($want === [] || array_intersect_assoc($want, $before) === $want) {
            return $before;
        }
        if (isset($want['CardNo'])) {
            $this->assertCardFree($want['CardNo'], $pin);
        }

        $doorsBefore = $this->digest($this->rows('userauthorize', $pin));
        $fingersBefore = $this->fingers($this->rows('templatev10', $pin));

        // UID is NOT sent: ZKAccess's edit is SetDeviceData("User") of the row without
        // it, and the panel upserts on Pin (draft/analysis/05, UserDal::Add, 2026-09-24).
        $row = array_replace($before, $want);
        unset($row['UID']);
        $this->panel->writeRows('user', [$this->onlyKnown('user', $row)]);

        $rows = $this->rows('user', $pin);
        if (count($rows) !== 1) {
            throw new VerificationException(sprintf(
                'After the edit the panel holds %d user rows under Pin %d, not one. Nothing was deleted; check this person in ZKAccess.',
                count($rows), $pin,
            ));
        }

        $after = $rows[0];
        if ((int) $after['UID'] !== (int) $before['UID']) {
            /*
             * The panel re-inserted the row under a NEW UID instead of updating it in
             * place. OBSERVED on the TF1700 @ 192.168.7.60, 2026-10-11: Pin 781054761
             * went UID 318 -> 51 right after another person (Pin 21) was deleted,
             * freeing 51; its fingerprints stayed under 318. Re-link them to the new
             * UID (verified, restored on failure) rather than leave the finger dead.
             */
            $this->relinkFingerprints($pin);
        }
        $this->assertFields($after, $want, $pin);

        if ($this->digest($this->rows('userauthorize', $pin)) !== $doorsBefore) {
            throw new VerificationException("Pin {$pin}'s door permissions changed during the edit.");
        }
        if ($this->fingers($this->rows('templatev10', $pin)) != $fingersBefore) {
            throw new VerificationException("Pin {$pin}'s fingerprints changed during the edit.");
        }

        return $after;
    }

    /**
     * Removes a person: fingerprints, then doors, then the user row, each read back.
     * EXPERIMENTAL. Returns rows removed per table. A Pin the panel does not hold is a
     * no-op that returns zeros, not an error — the end state asked for is reached.
     *
     * @return array<string,int>
     */
    public function delete(int $pin): array
    {
        $this->assertPin($pin);
        $removed = [];

        foreach (['templatev10', 'userauthorize', 'user'] as $table) {
            if (! $this->panel->catalogue()->has($table)) {
                continue;
            }

            $removed[$table] = count($this->rows($table, $pin));
            if ($removed[$table] === 0) {
                continue;
            }

            $this->panel->deleteRows($table, 'Pin', $pin);

            if ($this->rows($table, $pin) !== []) {
                throw new VerificationException("The panel accepted the delete but Pin {$pin} is still in '{$table}' when read back.");
            }
        }

        return $removed;
    }

    /**
     * The person's fingerprints as the panel holds them, slot => sha1.
     *
     * @return array<int,string>
     */
    public function fingerprints(int $pin): array
    {
        return $this->fingers($this->rows('templatev10', $pin));
    }

    /**
     * Writes fingerprint templates for a person the panel already holds. EXPERIMENTAL.
     *
     * ADD-ONLY: a slot the panel already fills is SKIPPED, never overwritten — the
     * operator asked to give somebody fingerprints they do not have, and replacing
     * an enrollment that works with a copy from elsewhere is not that. Returns the
     * slots actually written.
     *
     * Each template must be a ZKFinger v10 blob (the `SS21` signature at offset 2).
     * That is the format of every row on these panels and of an F18's templates —
     * byte-identical copies of one enrollment were seen on a standalone terminal and
     * on both panels (2026-09-15). A blob of any other shape is refused rather than
     * written, because the panel would accept it and then match nothing.
     *
     * VERIFIED PER FINGER, byte for byte, and under the person's UID. If anything
     * fails, the person's template rows are restored to exactly what they were: DELETE
     * by Pin (the only delete key proven), then the original rows re-written and
     * re-verified.
     *
     * @param list<array{fid:int, template:string, valid?:int}> $templates
     * @return list<int> slots written
     */
    public function addFingerprints(int $pin, array $templates): array
    {
        $user = $this->find($pin);
        if ($user === null) {
            throw new ProtocolException("Pin {$pin} is not on this panel; add the person before their fingerprints.");
        }
        if (! $this->panel->catalogue()->has('templatev10')) {
            throw new ProtocolException('This panel has no templatev10 table.');
        }

        $uid = (int) $user['UID'];
        $original = $this->rows('templatev10', $pin);
        $present = array_map(fn ($r) => (int) $r['FingerID'], $original);

        $rows = [];
        $seen = [];
        foreach ($templates as $t) {
            $fid = (int) $t['fid'];
            $blob = (string) $t['template'];

            if ($fid < 0 || $fid > 9) {
                throw new \InvalidArgumentException("Finger slot {$fid} is outside 0-9.");
            }
            if (substr($blob, 2, 4) !== self::TEMPLATE_SIGNATURE) {
                throw new \InvalidArgumentException("The template for finger {$fid} is not a ZKFinger v10 template.");
            }
            if (in_array($fid, $present, true) || isset($seen[$fid])) {
                continue;
            }
            $seen[$fid] = true;

            $rows[] = $this->onlyKnown('templatev10', [
                'Size' => strlen($blob),
                'UID' => $uid,
                'Pin' => $pin,
                'FingerID' => $fid,
                'Valid' => (int) ($t['valid'] ?? 1),
                'Template' => $blob,
                'Resverd' => self::TEMPLATE_RESERVED,
                'EndTag' => self::TEMPLATE_END_TAG,
            ]);
        }

        if ($rows === []) {
            return [];
        }

        $want = $this->fingers($original) + array_combine(
            array_map(fn ($r) => (int) $r['FingerID'], $rows),
            array_map(fn ($r) => sha1((string) $r['Template']), $rows),
        );
        ksort($want);

        try {
            $this->panel->writeRows('templatev10', $rows, allowBlobs: true);

            $now = $this->rows('templatev10', $pin);
            if ($this->fingers($now) != $want) {
                throw new VerificationException("The fingerprints under Pin {$pin} do not match what was written when read back.");
            }
            foreach ($now as $r) {
                if ((int) $r['UID'] !== $uid) {
                    throw new VerificationException("A fingerprint under Pin {$pin} carries UID {$r['UID']}, not the user's {$uid}.");
                }
            }
        } catch (\Throwable $e) {
            $this->restoreTemplates($pin, $original);

            throw new VerificationException("Could not add fingerprints to Pin {$pin}; its fingerprints were put back as they were. {$e->getMessage()}");
        }

        return array_map(fn ($r) => (int) $r['FingerID'], $rows);
    }

    /**
     * Points a person's fingerprint rows at the UID their `user` row has NOW. Returns
     * how many rows were re-linked (0 when all already match). 2.11.1.
     *
     * WHY: every `templatev10` row carries its owner's UID (238 of 238 on the TF1700,
     * 2026-09-24), and the panel can re-insert a user row under a new UID — then the
     * finger no longer belongs to the person (TF1700, 2026-10-11, Pin 781054761:
     * 318 -> 51). Same safety as addFingerprints(): delete by Pin (the proven key),
     * write the SAME templates with the new UID, verify byte for byte and the UID on
     * every row; on any failure the original rows are written back.
     */
    public function relinkFingerprints(int $pin): int
    {
        $user = $this->find($pin);
        if ($user === null || ! $this->panel->catalogue()->has('templatev10')) {
            return 0;
        }

        $uid = (int) $user['UID'];
        $original = $this->rows('templatev10', $pin);
        $stale = array_filter($original, fn ($r) => (int) $r['UID'] !== $uid);
        if ($stale === []) {
            return 0;
        }

        $rows = array_map(function (array $r) use ($uid) {
            $r['UID'] = $uid;

            return $r;
        }, $original);

        try {
            $this->panel->deleteRows('templatev10', 'Pin', $pin);
            $this->panel->writeRows('templatev10', $rows, allowBlobs: true);

            $now = $this->rows('templatev10', $pin);
            if ($this->fingers($now) != $this->fingers($original)) {
                throw new VerificationException('the fingerprints read back differ from the originals');
            }
            foreach ($now as $r) {
                if ((int) $r['UID'] !== $uid) {
                    throw new VerificationException("a fingerprint still carries UID {$r['UID']}");
                }
            }
        } catch (\Throwable $e) {
            $this->restoreTemplates($pin, $original);

            throw new VerificationException("Could not re-link Pin {$pin}'s fingerprints to UID {$uid}; they were put back as they were. {$e->getMessage()}");
        }

        return count($stale);
    }

    // ------------------------------------------------------------------ internals

    /** @param list<array<string,int|string>> $original */
    private function restoreTemplates(int $pin, array $original): void
    {
        try {
            if ($this->rows('templatev10', $pin) !== []) {
                $this->panel->deleteRows('templatev10', 'Pin', $pin);
            }
            if ($original !== []) {
                $this->panel->writeRows('templatev10', $original, allowBlobs: true);
            }
            if ($this->fingers($this->rows('templatev10', $pin)) != $this->fingers($original)) {
                throw new VerificationException('read-back differs');
            }
        } catch (\Throwable $e) {
            throw new VerificationException(
                "Adding fingerprints to Pin {$pin} failed AND restoring its original fingerprints failed ({$e->getMessage()}). "
                .'Its fingerprints on this panel may be incomplete; re-push them from the system copy.',
            );
        }
    }

    private function assertPinFree(int $pin): void
    {
        foreach (['user', 'userauthorize', 'templatev10'] as $table) {
            if ($this->panel->catalogue()->has($table) && $this->rows($table, $pin) !== []) {
                throw new ProtocolException("Pin {$pin} is already used in '{$table}' on this panel.");
            }
        }
    }

    /**
     * One card, one person. A card the panel already gives to somebody else would open
     * that person's doors under two names, and the panel would not refuse it.
     */
    private function assertCardFree(int $cardNo, int $pin): void
    {
        if ($cardNo <= 0) {
            return;
        }

        foreach ($this->panel->readTable('user') as $r) {
            if ((int) ($r['CardNo'] ?? 0) === $cardNo && (int) $r['Pin'] !== $pin) {
                throw new ProtocolException("Card {$cardNo} already belongs to Pin {$r['Pin']} on this panel.");
            }
        }
    }

    private function assertPin(int $pin): void
    {
        if ($pin <= 0) {
            throw new \InvalidArgumentException('A panel Pin must be a positive number.');
        }
    }

    /** @param array<string,int|string> $want */
    private function assertFields(array $row, array $want, int $pin): void
    {
        foreach ($want as $field => $value) {
            if (array_key_exists($field, $row) && (string) $row[$field] !== (string) $value) {
                // A password is a door credential: say THAT it differs, never what it is.
                throw new VerificationException($field === 'Password'
                    ? "The panel accepted the keypad password for Pin {$pin} but it does not read back as written."
                    : "The panel accepted {$field} for Pin {$pin} but reads back '{$row[$field]}', not '{$value}'.");
            }
        }
    }

    /**
     * Name as the panel can store it. The field is a one-byte-length string; 24 bytes
     * is what ZKAccess allows for a C3 name and what every real name here fits in.
     */
    private function name(string $name): string
    {
        $name = trim($name);

        return mb_strcut($name, 0, 24, 'UTF-8');
    }

    /**
     * Drops fields this panel's table does not carry (e.g. Privilege on the inBIO460).
     *
     * @param array<string,int|string> $row
     * @return array<string,int|string>
     */
    private function onlyKnown(string $table, array $row): array
    {
        return array_intersect_key($row, $this->panel->catalogue()->fields($table));
    }

    /** @return list<array<string,int|string>> */
    private function rows(string $table, int $pin): array
    {
        return array_values(array_filter(
            $this->panel->readTable($table),
            fn ($r) => (int) ($r['Pin'] ?? -1) === $pin,
        ));
    }

    /** @return array<int,string> slot => sha1, sorted */
    private function fingers(array $rows): array
    {
        $out = [];
        foreach ($rows as $r) {
            $out[(int) $r['FingerID']] = sha1((string) $r['Template']);
        }
        ksort($out);

        return $out;
    }

    private function digest(array $rows): string
    {
        $rows = array_map(fn ($r) => json_encode($r), $rows);
        sort($rows);

        return sha1(implode("\n", $rows));
    }

    /** @param list<string> $tables */
    private function quietlyDelete(array $tables, int $pin): void
    {
        foreach ($tables as $table) {
            try {
                if ($this->rows($table, $pin) !== []) {
                    $this->panel->deleteRows($table, 'Pin', $pin);
                }
            } catch (\Throwable) {
            }
        }
    }
}
