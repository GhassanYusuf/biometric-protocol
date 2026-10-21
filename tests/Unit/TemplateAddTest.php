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
use Promoseven\Biometric\Client\DeviceClient;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\UnsupportedCommandException;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Service\TemplateService;

/**
 * TemplateService::addTemplates() against a terminal in memory, with no device.
 *
 * The terminal can model both readings of SAVE_USERTEMPS — the user's template set is
 * REPLACED by what was sent, or what was sent is MERGED in — because which one the
 * firmware does is not documented, and the method must be right under either.
 */
final class TemplateAddTest extends TestCase
{
    public function test_adds_a_finger_to_a_user_with_none_keeping_the_record(): void
    {
        $t = new AddTerminal();
        $t->addUser(20, '440105943', 'AKRAM', 7553651);
        $t->addUser(3, '12', 'other', 0);
        $t->templates = [[3, 1, 'B1']];
        $recordBefore = $t->records[20];

        $written = (new TemplateService($t))->addTemplates('440105943', [['fid' => 6, 'template' => 'A6']]);

        $this->assertSame([6], $written);
        $this->assertSame([[3, 1, 'B1'], [20, 6, 'A6']], $t->sortedTemplates());
        $this->assertSame($recordBefore, $t->records[20], 'the device\'s own record is written back unchanged');
    }

    /**
     * DC-027 (2026-10-21): the first finger on a terminal that holds none. IT-Office
     * answered its empty template table with no bytes, and the write refused it as
     * "would not decode" — so a wiped or new terminal could never be given a finger.
     */
    public function test_writes_the_first_finger_on_a_terminal_whose_empty_table_is_sent_as_nothing(): void
    {
        $t = new AddTerminal();
        $t->emptyTableSendsNothing = true;
        $t->addUser(1, '830108246', 'Ghassan', 7566580);

        $written = (new TemplateService($t))->addTemplates('830108246', [['fid' => 3, 'template' => 'G3'], ['fid' => 6, 'template' => 'G6']]);

        $this->assertSame([3, 6], $written);
        $this->assertSame([[1, 3, 'G3'], [1, 6, 'G6']], $t->sortedTemplates());
    }

    public function test_never_overwrites_a_slot_the_user_already_fills(): void
    {
        $t = new AddTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->templates = [[7, 6, 'ORIGINAL']];

        $written = (new TemplateService($t))->addTemplates('100', [
            ['fid' => 6, 'template' => 'COPY'],
            ['fid' => 3, 'template' => 'A3'],
        ]);

        $this->assertSame([3], $written);
        $this->assertSame([[7, 3, 'A3'], [7, 6, 'ORIGINAL']], $t->sortedTemplates());
    }

    public function test_keeps_existing_fingers_when_the_device_replaces_the_set(): void
    {
        $t = new AddTerminal();
        $t->replacesSet = true;
        $t->addUser(7, '100', 'a', 0);
        $t->templates = [[7, 1, 'A1'], [7, 2, 'A2']];

        $written = (new TemplateService($t))->addTemplates('100', [['fid' => 6, 'template' => 'A6']]);

        $this->assertSame([6], $written);
        $this->assertSame([[7, 1, 'A1'], [7, 2, 'A2'], [7, 6, 'A6']], $t->sortedTemplates());
    }

    public function test_nothing_new_means_no_write(): void
    {
        $t = new AddTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->templates = [[7, 6, 'A6']];

        $this->assertSame([], (new TemplateService($t))->addTemplates('100', [['fid' => 6, 'template' => 'X']]));
        $this->assertSame(0, $t->writes);
    }

    public function test_refuses_an_unknown_user_and_an_unreadable_table_without_writing(): void
    {
        $t = new AddTerminal();
        $t->addUser(7, '100', 'a', 0);

        try {
            (new TemplateService($t))->addTemplates('999', [['fid' => 6, 'template' => 'A6']]);
            $this->fail('Expected a refusal for a user the device does not hold.');
        } catch (ProtocolException $e) {
            $this->assertStringContainsString('not on the device', $e->getMessage());
        }

        $t->templateTableUnreadable = true;
        try {
            (new TemplateService($t))->addTemplates('100', [['fid' => 6, 'template' => 'A6']]);
            $this->fail('Expected a refusal for an unreadable template table.');
        } catch (UnsupportedCommandException $e) {
            $this->assertStringContainsString('Nothing was written', $e->getMessage());
        }

        $this->assertSame(0, $t->writes);
    }

    public function test_an_accepted_write_the_device_did_not_keep_is_not_a_success(): void
    {
        $t = new AddTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->dropNewTemplates = true;

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('did not keep any of them');

        (new TemplateService($t))->addTemplates('100', [['fid' => 6, 'template' => 'A6']]);
    }

    public function test_a_lost_existing_finger_is_put_back_and_reported(): void
    {
        $t = new AddTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->templates = [[7, 1, 'A1']];
        $t->loseExistingOnce = true;

        try {
            (new TemplateService($t))->addTemplates('100', [['fid' => 6, 'template' => 'A6']]);
            $this->fail('Expected a verification failure.');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('existing fingerprint slot(s) 1 changed or disappeared', $e->getMessage());
            $this->assertStringContainsString('were put back', $e->getMessage());
            $this->assertTrue($e->context()['restored']);
        }

        $this->assertContains([7, 1, 'A1'], $t->sortedTemplates());
    }
}

/** A terminal in memory: records as the device's 72-byte rows, templates as [uid, slot, blob]. */
final class AddTerminal extends DeviceClient
{
    /** @var array<int,string> */
    public array $records = [];
    /** @var list<array{0:int,1:int,2:string}> */
    public array $templates = [];
    public bool $templateTableUnreadable = false;
    /** An empty table is sent as no bytes at all, as the F18 IT-Office did (2026-10-21). */
    public bool $emptyTableSendsNothing = false;
    /** SAVE_USERTEMPS replaces the user's whole template set (otherwise it merges per slot). */
    public bool $replacesSet = false;
    /** Accepts the save but keeps none of the slots the user did not already have. */
    public bool $dropNewTemplates = false;
    /** The first save wipes the user's existing fingers. */
    public bool $loseExistingOnce = false;
    public int $writes = 0;

    public function __construct()
    {
    }

    public function addUser(int $uid, string $userId, string $name, int $card): void
    {
        $this->records[$uid] = Packet::buildUserRecord($uid, $userId, $name, 0, $card);
    }

    public function sortedTemplates(): array
    {
        $t = $this->templates;
        sort($t);

        return $t;
    }

    public function readUsersRaw(): string
    {
        $body = implode('', $this->records);

        return pack('V', strlen($body)) . $body;
    }

    public function readTemplatesRaw(): string
    {
        if ($this->templateTableUnreadable) {
            return "\x10\x00";
        }
        if ($this->emptyTableSendsNothing && $this->templates === []) {
            return '';
        }

        $body = '';
        foreach ($this->templates as [$uid, $fid, $blob]) {
            $body .= pack('v', 6 + strlen($blob)) . pack('v', $uid) . chr($fid) . chr(1) . $blob;
        }

        return pack('V', strlen($body)) . $body;
    }

    public function saveUserWithTemplates(string $record, array $templates): void
    {
        $this->writes++;
        Packet::buildUserTemplatesUpload($record, $templates); // the real encoder must accept it

        $uid = unpack('v', substr($record, 0, 2))[1];
        $had = array_map(fn ($t) => $t[1], array_filter($this->templates, fn ($t) => $t[0] === $uid));
        $this->records[$uid] = $record;

        if ($this->replacesSet || $this->loseExistingOnce) {
            $this->templates = array_values(array_filter($this->templates, fn ($t) => $t[0] !== $uid));
            if ($this->loseExistingOnce) {
                $this->loseExistingOnce = false;
                $had = [];
                $templates = array_filter($templates, fn ($t) => ! in_array($t['fid'], [1], true));
            }
        }

        foreach ($templates as $t) {
            if ($this->dropNewTemplates && ! in_array($t['fid'], $had, true)) {
                continue;
            }
            $this->templates = array_values(array_filter($this->templates, fn ($x) => ! ($x[0] === $uid && $x[1] === $t['fid'])));
            $this->templates[] = [$uid, $t['fid'], $t['template']];
        }
    }
}
