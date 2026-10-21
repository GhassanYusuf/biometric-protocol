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
use Promoseven\Biometric\C3\Client\TableStore;
use Promoseven\Biometric\C3\Codec\Catalogue;
use Promoseven\Biometric\C3\Service\Personnel;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;

/**
 * Personnel against an in-memory panel with the TF1700's real catalogue.
 *
 * The fake behaves as the panels were OBSERVED to on 2026-09-24: a `user` row
 * written without a UID gets the next UID; a row written with an existing Pin
 * replaces that Pin's row (the upsert this library relies on for edits — asserted
 * by the edit test, and by the hardware probe before anything is promoted).
 * Switches make it misbehave the ways real firmware might.
 */
final class C3PersonnelTest extends TestCase
{
    private function blob(string $seed, int $len = 700): string
    {
        return "\x00\x00SS21".substr(str_repeat(hash('sha256', $seed, true), (int) ceil($len / 32)), 0, $len - 6);
    }

    private function panel(): FakeC3Panel
    {
        $p = new FakeC3Panel(Catalogue::parse(file_get_contents(__DIR__.'/../Fixtures/c3-datatable-cfg-tf1700.txt')));
        $p->tables['user'] = [
            ['UID' => 1, 'CardNo' => 555, 'Pin' => 10, 'Password' => '', 'Group' => 0, 'StartTime' => 0, 'EndTime' => 0, 'Name' => 'alice', 'Privilege' => 0, 'SuperAuthorize' => 0],
        ];
        $p->tables['userauthorize'] = [
            ['Pin' => 10, 'AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 1],
        ];
        $p->tables['templatev10'] = [
            ['Size' => 700, 'UID' => 1, 'Pin' => 10, 'FingerID' => 3, 'Valid' => 1, 'Template' => $this->blob('a3'), 'Resverd' => 0, 'EndTag' => 13],
        ];
        $p->nextUid = 2;

        return $p;
    }

    public function test_add_writes_the_user_then_the_panel_s_common_doors(): void
    {
        $p = $this->panel();
        $row = (new Personnel($p))->add(20, 'bob', 777);

        $this->assertSame(2, $row['UID']);
        $this->assertSame('bob', $row['Name']);
        $this->assertSame(777, $row['CardNo']);
        $this->assertSame([['Pin' => 20, 'AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 1]], $p->byPin('userauthorize', 20));
        $this->assertArrayNotHasKey('UID', $p->writes[0]['rows'][0], 'UID is the panel\'s to assign');
    }

    public function test_add_refuses_a_pin_held_in_any_table_even_an_orphaned_door_row(): void
    {
        $p = $this->panel();
        $p->tables['userauthorize'][] = ['Pin' => 30, 'AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 1];

        $this->expectException(ProtocolException::class);
        (new Personnel($p))->add(30, 'carol');
    }

    public function test_add_drops_fields_the_panel_does_not_carry(): void
    {
        $p = $this->panel();
        $p->dropField('user', 'Privilege'); // the inBIO460's user table

        (new Personnel($p))->add(20, 'bob');

        $this->assertArrayNotHasKey('Privilege', $p->writes[0]['rows'][0]);
    }

    public function test_add_removes_the_user_again_when_the_doors_do_not_land(): void
    {
        $p = $this->panel();
        $p->ignoreWritesTo = 'userauthorize';

        try {
            (new Personnel($p))->add(20, 'bob');
            $this->fail('expected a verification failure');
        } catch (VerificationException) {
        }

        $this->assertSame([], $p->byPin('user', 20));
        $this->assertCount(1, $p->tables['user']);
    }

    public function test_add_that_the_panel_silently_drops_is_not_reported_as_success(): void
    {
        $p = $this->panel();
        $p->ignoreWritesTo = 'user';

        $this->expectException(VerificationException::class);
        (new Personnel($p))->add(20, 'bob');
    }

    public function test_a_name_edit_keeps_the_keypad_password_and_a_password_edit_is_verified(): void
    {
        $p = $this->panel();
        $p->tables['user'][0]['Password'] = '4321';
        $people = new Personnel($p);

        $this->assertSame('4321', $people->update(10, 'alice b')['Password'], 'a name edit must not erase the password');
        $this->assertSame('8765', $people->update(10, null, null, '8765')['Password']);
        $this->assertSame('1111', $people->add(21, 'carol', 0, null, '1111')['Password']);
    }

    public function test_edit_keeps_uid_doors_and_fingers(): void
    {
        $p = $this->panel();
        $row = (new Personnel($p))->update(10, 'alice b', 999);

        $this->assertSame(1, $row['UID']);
        $this->assertSame('alice b', $row['Name']);
        $this->assertSame(999, $row['CardNo']);
        $this->assertArrayNotHasKey('UID', $p->writes[0]['rows'][0], 'ZKAccess edits by Pin and never sends the UID');
        $this->assertCount(1, $p->byPin('templatev10', 10));
    }

    public function test_a_card_already_held_by_someone_else_is_refused(): void
    {
        $p = $this->panel();

        $this->expectException(ProtocolException::class);
        (new Personnel($p))->add(20, 'bob', 555);
    }

    public function test_edit_with_nothing_changed_writes_nothing(): void
    {
        $p = $this->panel();
        (new Personnel($p))->update(10, 'alice', 555);

        $this->assertSame([], $p->writes);
    }

    public function test_an_edit_the_panel_appends_instead_of_applying_is_caught_and_nothing_is_deleted(): void
    {
        $p = $this->panel();
        $p->appendInsteadOfUpsert = true;

        try {
            (new Personnel($p))->update(10, 'alice b');
            $this->fail('expected a verification failure');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('2 user rows', $e->getMessage());
        }

        $this->assertSame([], $p->deletes, 'a delete by Pin would take the original with it');
    }

    public function test_delete_goes_fingers_doors_user_and_reads_back(): void
    {
        $p = $this->panel();
        $removed = (new Personnel($p))->delete(10);

        $this->assertSame(['templatev10' => 1, 'userauthorize' => 1, 'user' => 1], $removed);
        $this->assertSame(['templatev10', 'userauthorize', 'user'], array_column($p->deletes, 'table'));
        $this->assertSame([], $p->tables['user']);
    }

    public function test_delete_of_an_absent_pin_is_a_no_op(): void
    {
        $p = $this->panel();
        $this->assertSame(['templatev10' => 0, 'userauthorize' => 0, 'user' => 0], (new Personnel($p))->delete(99));
        $this->assertSame([], $p->deletes);
    }

    public function test_delete_the_panel_ignores_is_reported(): void
    {
        $p = $this->panel();
        $p->ignoreDeletesTo = 'user';

        $this->expectException(VerificationException::class);
        (new Personnel($p))->delete(10);
    }

    /*
     * TF1700 @ 192.168.7.60, 2026-10-11: an edit re-inserted Pin 781054761 under UID 51
     * (it was 318) and left its fingerprints under 318 — the finger stopped belonging
     * to the person. The edit now re-links them.
     */
    public function test_an_edit_that_lands_under_a_new_uid_relinks_the_fingerprints(): void
    {
        $p = $this->panel();
        $p->reinsertUnderNewUid = true;

        $row = (new Personnel($p))->update(10, 'alice b');

        $this->assertSame(2, $row['UID']);
        $fingers = $p->byPin('templatev10', 10);
        $this->assertCount(1, $fingers);
        $this->assertSame(2, $fingers[0]['UID'], 'the finger follows the person to the new UID');
        $this->assertSame(sha1($this->blob('a3')), sha1($fingers[0]['Template']), 'the template itself is unchanged');
    }

    public function test_a_stale_link_is_repaired_by_a_push_that_changes_nothing_else(): void
    {
        $p = $this->panel();
        $p->tables['templatev10'][0]['UID'] = 99; // left behind by an earlier edit

        (new Personnel($p))->update(10, 'alice');

        $this->assertSame(1, $p->byPin('templatev10', 10)[0]['UID']);
    }

    public function test_a_relink_that_lands_wrong_puts_the_original_fingerprints_back(): void
    {
        $p = $this->panel();
        $p->tables['templatev10'][0]['UID'] = 99;
        $p->corruptNextTemplateWrite = true;

        try {
            (new Personnel($p))->relinkFingerprints(10);
            $this->fail('Expected the re-link to be refused.');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('put back as they were', $e->getMessage());
        }

        $back = $p->byPin('templatev10', 10);
        $this->assertCount(1, $back);
        $this->assertSame(sha1($this->blob('a3')), sha1($back[0]['Template']));
        $this->assertSame(99, $back[0]['UID'], 'exactly as it was, not half-moved');
    }

    public function test_fingerprints_are_added_under_the_users_uid_and_existing_slots_are_never_overwritten(): void
    {
        $p = $this->panel();
        $written = (new Personnel($p))->addFingerprints(10, [
            ['fid' => 3, 'template' => $this->blob('other3')],   // slot already filled: skipped
            ['fid' => 6, 'template' => $this->blob('a6', 1200)],
        ]);

        $this->assertSame([6], $written);
        $rows = $p->byPin('templatev10', 10);
        $this->assertCount(2, $rows);
        $six = array_values(array_filter($rows, fn ($r) => $r['FingerID'] === 6))[0];
        $this->assertSame(1, $six['UID']);
        $this->assertSame(1200, $six['Size']);
        $this->assertSame(13, $six['EndTag']);
        $this->assertSame(sha1($this->blob('a3')), sha1($p->byPin('templatev10', 10)[0]['Template']));
    }

    public function test_a_blob_that_is_not_zkfinger_v10_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new Personnel($this->panel()))->addFingerprints(10, [['fid' => 6, 'template' => str_repeat("\x01", 700)]]);
    }

    public function test_fingerprints_for_someone_not_on_the_panel_are_refused(): void
    {
        $this->expectException(ProtocolException::class);
        (new Personnel($this->panel()))->addFingerprints(42, [['fid' => 6, 'template' => $this->blob('x')]]);
    }

    public function test_a_corrupted_fingerprint_write_restores_the_original_fingers(): void
    {
        $p = $this->panel();
        $p->corruptNextTemplateWrite = true;

        try {
            (new Personnel($p))->addFingerprints(10, [['fid' => 6, 'template' => $this->blob('a6')]]);
            $this->fail('expected a verification failure');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('put back', $e->getMessage());
        }

        $rows = $p->byPin('templatev10', 10);
        $this->assertCount(1, $rows);
        $this->assertSame(3, $rows[0]['FingerID']);
        $this->assertSame(sha1($this->blob('a3')), sha1($rows[0]['Template']));
    }

    public function test_common_authorization_is_the_most_frequent_set(): void
    {
        $p = $this->panel();
        $p->tables['userauthorize'] = [
            ['Pin' => 1, 'AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 3],
            ['Pin' => 2, 'AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 3],
            ['Pin' => 3, 'AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 1],
        ];

        $this->assertSame([['AuthorizeTimezoneId' => 1, 'AuthorizeDoorId' => 3]], (new Personnel($p))->commonAuthorization());
    }
}

/** An in-memory C3 panel. Behaviour switches model the firmware failures we guard against. */
final class FakeC3Panel implements TableStore
{
    /** @var array<string,list<array<string,int|string>>> */
    public array $tables = ['user' => [], 'userauthorize' => [], 'templatev10' => []];

    public int $nextUid = 1;

    public ?string $ignoreWritesTo = null;

    public ?string $ignoreDeletesTo = null;

    public bool $appendInsteadOfUpsert = false;

    /** An edit re-inserts the user row under a NEW UID (TF1700, 2026-10-11). */
    public bool $reinsertUnderNewUid = false;

    /** The next templatev10 write lands mangled — a panel that truncates a blob. */
    public bool $corruptNextTemplateWrite = false;

    public array $writes = [];

    public array $deletes = [];

    public function __construct(private Catalogue $catalogue) {}

    public function dropField(string $table, string $field): void
    {
        $text = '';
        foreach ($this->catalogue->tableNames() as $t) {
            $fields = [];
            foreach ($this->catalogue->fields($t) as $name => $f) {
                if (! ($t === $table && $name === $field)) {
                    $fields[] = $name.'='.$f['type'].$f['index'];
                }
            }
            $text .= $t.'='.$this->catalogue->indexOf($t).','.implode(',', $fields)."\n";
        }
        $this->catalogue = Catalogue::parse($text);
    }

    public function catalogue(): Catalogue
    {
        return $this->catalogue;
    }

    public function readTable(string $table, ?callable $onProgress = null): array
    {
        return $this->tables[$table] ?? [];
    }

    public function writeRows(string $table, array $rows, bool $allowBlobs = false): void
    {
        foreach ($rows as $r) {
            foreach (array_keys($r) as $f) {
                if (! isset($this->catalogue->fields($table)[$f])) {
                    throw new \InvalidArgumentException("no field {$f}");
                }
            }
        }
        $this->writes[] = ['table' => $table, 'rows' => $rows];

        if ($this->ignoreWritesTo === $table) {
            return;
        }

        if ($table === 'templatev10' && $this->corruptNextTemplateWrite) {
            $this->corruptNextTemplateWrite = false;
            $rows = array_map(fn ($r) => ['Template' => substr((string) $r['Template'], 0, -10)] + $r, $rows);
        }

        foreach ($rows as $r) {
            if ($table === 'user') {
                $i = $this->indexOfPin('user', (int) $r['Pin']);
                if ($i !== null && $this->reinsertUnderNewUid) {
                    $this->tables['user'][$i] = ['UID' => $this->nextUid++] + array_replace($this->tables['user'][$i], $r);

                    continue;
                }
                if ($i !== null && ! $this->appendInsteadOfUpsert) {
                    $this->tables['user'][$i] = array_replace($this->tables['user'][$i], $r);

                    continue;
                }
                $r = ['UID' => $this->nextUid++] + $r;
            }
            $this->tables[$table][] = $r;
        }
    }

    public function deleteRows(string $table, string $keyField, int|string $value): void
    {
        $this->deletes[] = ['table' => $table, 'key' => $keyField, 'value' => $value];

        if ($this->ignoreDeletesTo === $table) {
            return;
        }

        $this->tables[$table] = array_values(array_filter(
            $this->tables[$table],
            fn ($r) => (string) $r[$keyField] !== (string) $value,
        ));
    }

    public function byPin(string $table, int $pin): array
    {
        return array_values(array_filter($this->tables[$table], fn ($r) => (int) $r['Pin'] === $pin));
    }

    private function indexOfPin(string $table, int $pin): ?int
    {
        foreach ($this->tables[$table] as $i => $r) {
            if ((int) $r['Pin'] === $pin) {
                return $i;
            }
        }

        return null;
    }
}
