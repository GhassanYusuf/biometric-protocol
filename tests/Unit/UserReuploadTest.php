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
use Promoseven\Biometric\Codec\TemplateCodec;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Service\UserService;

/**
 * Renumber by delete + re-upload (SAVE_USERTEMPS), with no device.
 *
 * Two halves:
 *   - the WIRE BYTES, checked against what pyzk's own struct formats produce, so the
 *     transcription is proven rather than eyeballed;
 *   - the SAFETY of UserService::renumberByReupload() against a simulated terminal
 *     that accepts, refuses, or silently drops parts of the upload.
 */
final class UserReuploadTest extends TestCase
{
    /*
     * Expected bytes generated 2026-09-24 by running fananimi/pyzk's
     * HR_save_usertemplates format strings (commit f29709c1) in Python for uid 7,
     * fingers 5 (AA BB CC) and 6 (01 02 03 04).
     */
    private const PYZK_UPLOAD_HEX =
        '49000000100000000b000000' // head: 73, 16, 11
        . '0207000e0000000000000000616c692d6974320000000000000000000000000000000000a7ac2b00010000000000000000393630383032373937000000000000000000000000000000' // 0x02 + record
        . '02070015000000000207001605000000' // table
        . '0300aabbcc040001020304'; // fpack

    public function test_upload_buffer_matches_pyzk_byte_for_byte(): void
    {
        $record = Packet::buildUserRecord(7, '960802797', 'ali-it2', 14, 2862247);

        $buffer = Packet::buildUserTemplatesUpload($record, [
            ['fid' => 5, 'template' => "\xAA\xBB\xCC"],
            ['fid' => 6, 'template' => "\x01\x02\x03\x04"],
        ]);

        $this->assertSame(self::PYZK_UPLOAD_HEX, bin2hex($buffer));
        $this->assertSame('0c00000000000800', bin2hex(Packet::buildSaveUserTemplatesRequest()));
    }

    public function test_real_f18_templates_survive_the_upload_encoding(): void
    {
        // uid 8 on the captured F18 table: one real 1,304-byte template (slot 6).
        $all = TemplateCodec::decodeWithBlobs(file_get_contents(__DIR__ . '/../Fixtures/fingerprint-template-table.bin'));
        $mine = array_values(array_filter($all, fn ($t) => $t['uid'] === 8));
        $this->assertNotEmpty($mine);

        $buffer = Packet::buildUserTemplatesUpload(Packet::buildUserRecord(8, '8', 'x'), $mine);
        $u = unpack('V', substr($buffer, 0, 4))[1];
        $t = unpack('V', substr($buffer, 4, 4))[1];
        $fpack = substr($buffer, 12 + $u + $t);

        // Walk fpack by the table's offsets and get every blob back unchanged.
        foreach ($mine as $i => $template) {
            $entry = substr($buffer, 12 + $u + 8 * $i, 8);
            $offset = unpack('V', substr($entry, 4, 4))[1];
            $size = unpack('v', substr($fpack, $offset, 2))[1];
            $this->assertSame(0x10 + $template['fid'], ord($entry[3]));
            $this->assertSame($template['template'], substr($fpack, $offset + 2, $size));
        }
    }

    public function test_with_user_id_changes_only_the_id_field(): void
    {
        $record = Packet::buildUserRecord(7, '960802797', 'ali-it2', 14, 2862247);
        $record = substr_replace($record, '1234', 3, 4); // a password UserCodec never decodes

        $moved = Packet::withUserId($record, '5');

        $this->assertSame(substr($record, 0, 48), substr($moved, 0, 48));
        $this->assertSame(str_pad('5', 9, "\0"), substr($moved, 48, 9));
        $this->assertSame(substr($record, 57), substr($moved, 57), 'bytes 57..71 are carried over, not guessed');
    }

    public function test_moves_the_user_and_every_finger_and_snapshots_first(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '960802797', 'ali-it2', 2862247);
        $t->addUser(3, '12', 'other', 0);
        $t->templates = [[7, 5, 'A5'], [7, 6, 'A6'], [3, 1, 'B1']];
        $snap = null;

        $user = (new UserService($t))->renumberByReupload('960802797', '5', function (array $s) use (&$snap, $t) {
            $snap = $s;
            $this->assertSame(0, $t->writes, 'the snapshot must arrive before any write');
        });

        $this->assertSame('5', $user->userId);
        $this->assertSame(7, $user->uid);
        $this->assertSame(2862247, $user->cardNumber);
        $this->assertSame([5, 6], $user->fingerSlots);
        $this->assertSame([[3, 1, 'B1'], [7, 5, 'A5'], [7, 6, 'A6']], $t->sortedTemplates());
        $this->assertCount(2, $snap['templates']);
        $this->assertSame(72, strlen($snap['record']));
    }

    public function test_a_throwing_snapshot_callback_means_nothing_is_written(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->templates = [[7, 5, 'A5']];

        try {
            (new UserService($t))->renumberByReupload('100', '205', fn () => throw new \RuntimeException('disk full'));
            $this->fail('Expected the callback exception.');
        } catch (\RuntimeException) {
        }

        $this->assertSame(0, $t->writes);
    }

    public function test_refuses_to_start_when_fingers_cannot_be_read(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->templateTableUnreadable = true;

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('cannot be copied. Nothing was changed');

        try {
            (new UserService($t))->renumberByReupload('100', '205');
        } finally {
            $this->assertSame(0, $t->writes);
        }
    }

    public function test_refuses_an_occupied_target(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->addUser(8, '205', 'stranger', 0);

        $this->expectExceptionMessage('stranger');
        (new UserService($t))->renumberByReupload('100', '205');
    }

    public function test_a_refused_upload_puts_the_original_back(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '100', 'a', 42);
        $t->templates = [[7, 5, 'A5'], [7, 6, 'A6']];
        $t->refuseSavesFor = '205';

        try {
            (new UserService($t))->renumberByReupload('100', '205');
            $this->fail('Expected a failure.');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('100 was put back with the same card and 2 fingerprint(s)', $e->getMessage());
            $this->assertTrue($e->context()['restored'] ?? false);
        }

        $this->assertSame('100', $t->userIdOf(7));
        $this->assertSame([[7, 5, 'A5'], [7, 6, 'A6']], $t->sortedTemplates());
    }

    public function test_dropped_fingers_are_caught_and_the_original_restored(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->addUser(3, '12', 'other', 0);
        $t->templates = [[7, 5, 'A5'], [3, 1, 'B1']];
        $t->dropTemplatesFor = '205';

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('fingerprint slot(s) 5 did not come back');

        try {
            (new UserService($t))->renumberByReupload('100', '205');
        } finally {
            $this->assertSame('100', $t->userIdOf(7));
            $this->assertSame([[3, 1, 'B1'], [7, 5, 'A5']], $t->sortedTemplates());
        }
    }

    public function test_a_failed_restore_is_said_in_capitals(): void
    {
        $t = new ReuploadTerminal();
        $t->addUser(7, '100', 'a', 0);
        $t->templates = [[7, 5, 'A5']];
        $t->refuseSavesFor = '*';

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('RESTORING 100 ALSO FAILED');

        (new UserService($t))->renumberByReupload('100', '205');
    }
}

/**
 * A terminal in memory. Records are kept as the device's own 72-byte rows so the
 * raw-record path is exercised; templates as [uid, slot, blob].
 */
final class ReuploadTerminal extends DeviceClient
{
    /** @var array<int,string> uid => 72-byte record */
    public array $records = [];

    /** @var list<array{0:int,1:int,2:string}> */
    public array $templates = [];

    public bool $templateTableUnreadable = false;
    /** A user id whose save is refused ('*' = every save). */
    public ?string $refuseSavesFor = null;
    /** A user id whose save is accepted but whose templates are dropped. */
    public ?string $dropTemplatesFor = null;
    public int $writes = 0;
    /** deleteAll(): every DELETE_USER refused, or one uid's delete ACKed and dropped. */
    public bool $refuseDeletes = false;
    public ?int $ignoreDeleteOfUid = null;

    public function __construct()
    {
    }

    public function addUser(int $uid, string $userId, string $name, int $card): void
    {
        $this->records[$uid] = Packet::buildUserRecord($uid, $userId, $name, 0, $card);
    }

    public function userIdOf(int $uid): ?string
    {
        return isset($this->records[$uid]) ? rtrim(substr($this->records[$uid], 48, 9), "\0") : null;
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

        $body = '';
        foreach ($this->templates as [$uid, $fid, $blob]) {
            $body .= pack('v', 6 + strlen($blob)) . pack('v', $uid) . chr($fid) . chr(1) . $blob;
        }

        return pack('V', strlen($body)) . $body;
    }

    public function deleteUser(int $uid): void
    {
        $this->writes++;
        if ($this->refuseDeletes) {
            throw new ProtocolException('Device rejected the delete (ACK_ERROR).');
        }
        if ($this->ignoreDeleteOfUid === $uid) {
            return; // ACKed, dropped — the firmware family's known failure
        }
        unset($this->records[$uid]);
        $this->templates = array_values(array_filter($this->templates, fn ($t) => $t[0] !== $uid));
    }

    public function saveUserWithTemplates(string $record, array $templates): void
    {
        $this->writes++;
        // Exercise the real encoder, as the device would receive it.
        Packet::buildUserTemplatesUpload($record, $templates);

        $uid = unpack('v', substr($record, 0, 2))[1];
        $userId = rtrim(substr($record, 48, 9), "\0");

        if ($this->refuseSavesFor === '*' || $this->refuseSavesFor === $userId) {
            throw new ProtocolException('Device rejected the user+template save (ACK_ERROR).');
        }

        $this->records[$uid] = $record;
        ksort($this->records);

        if ($this->dropTemplatesFor === $userId) {
            return;
        }

        foreach ($templates as $t) {
            $this->templates[] = [$uid, $t['fid'], $t['template']];
        }
    }
}
