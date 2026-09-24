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
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Service\UserService;

/**
 * UserService::renumber() against a simulated terminal — no device.
 *
 * The behaviour that matters is the VERIFICATION, because whether real firmware keeps
 * templates when a uid's user id changes is unconfirmed (2026-09-23). Each firmware
 * behaviour the method must survive is simulated here: templates follow the uid (the
 * expected case), templates are dropped, and writes keyed by user id instead of uid.
 */
final class UserRenumberTest extends TestCase
{
    public function test_moves_the_same_uid_and_keeps_card_privilege_and_fingers(): void
    {
        $terminal = new RenumberTerminal();
        $terminal->users[7] = ['user_id' => '960802797', 'name' => 'ali-it2', 'privilege' => 14, 'card' => 2862247];
        $terminal->templates = [[7, 5], [7, 6], [3, 1]];
        $terminal->users[3] = ['user_id' => '12', 'name' => 'other', 'privilege' => 0, 'card' => 0];

        $user = (new UserService($terminal))->renumber('960802797', '205');

        $this->assertSame(7, $user->uid);
        $this->assertSame('205', $user->userId);
        $this->assertSame('ali-it2', $user->name);
        $this->assertSame(14, $user->privilege);
        $this->assertSame(2862247, $user->cardNumber);
        $this->assertSame([5, 6], $user->fingerSlots);
        $this->assertCount(2, $terminal->users);
    }

    public function test_refuses_a_target_id_someone_else_holds_and_writes_nothing(): void
    {
        $terminal = new RenumberTerminal();
        $terminal->users[7] = ['user_id' => '100', 'name' => 'a', 'privilege' => 0, 'card' => 0];
        $terminal->users[8] = ['user_id' => '205', 'name' => 'stranger', 'privilege' => 0, 'card' => 0];

        try {
            (new UserService($terminal))->renumber('100', '205');
            $this->fail('Expected a refusal.');
        } catch (ProtocolException $e) {
            $this->assertStringContainsString('stranger', $e->getMessage());
        }

        $this->assertSame(0, $terminal->writes);
    }

    public function test_reports_fingerprints_the_firmware_dropped(): void
    {
        $terminal = new RenumberTerminal();
        $terminal->dropTemplatesOnWrite = true;
        $terminal->users[7] = ['user_id' => '100', 'name' => 'a', 'privilege' => 0, 'card' => 0];
        // Someone else's finger keeps the table non-empty. A table that ends up
        // completely empty is indistinguishable from an undecodable one, and is
        // correctly reported as UNKNOWN rather than as a loss.
        $terminal->users[3] = ['user_id' => '12', 'name' => 'other', 'privilege' => 0, 'card' => 0];
        $terminal->templates = [[7, 5], [3, 1]];

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('fingerprint slot(s) 5 are no longer on the device');

        (new UserService($terminal))->renumber('100', '205');
    }

    public function test_reports_a_firmware_that_adds_a_second_record_instead(): void
    {
        $terminal = new RenumberTerminal();
        $terminal->keyWritesByUserId = true;
        $terminal->users[7] = ['user_id' => '100', 'name' => 'a', 'privilege' => 0, 'card' => 0];

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('100 is still on the device');

        (new UserService($terminal))->renumber('100', '205');
    }

    public function test_a_refused_write_says_whether_the_record_is_intact(): void
    {
        $terminal = new RenumberTerminal();
        $terminal->refuseWrites = true;
        $terminal->users[6] = ['user_id' => '960802797', 'name' => 'a', 'privilege' => 0, 'card' => 0];

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Nothing was changed: 960802797 is still on the device');

        (new UserService($terminal))->renumber('960802797', '000000005');
    }

    public function test_unknown_fingers_stay_unknown_rather_than_none(): void
    {
        $terminal = new RenumberTerminal();
        $terminal->templateTableUnreadable = true;
        $terminal->users[7] = ['user_id' => '100', 'name' => 'a', 'privilege' => 0, 'card' => 0];

        $user = (new UserService($terminal))->renumber('100', '205');

        $this->assertNull($user->fingerSlots);
    }
}

/**
 * A terminal held in memory. Overrides only the three calls renumber() makes; the
 * parent constructor is skipped because there is no session to open.
 */
final class RenumberTerminal extends DeviceClient
{
    /** @var array<int, array{user_id:string,name:string,privilege:int,card:int}> keyed by uid */
    public array $users = [];

    /** @var list<array{0:int,1:int}> [uid, finger slot] */
    public array $templates = [];

    public bool $dropTemplatesOnWrite = false;
    public bool $keyWritesByUserId = false;
    public bool $templateTableUnreadable = false;
    public bool $refuseWrites = false;
    public int $writes = 0;

    public function __construct()
    {
    }

    public function readUsersRaw(): string
    {
        $body = '';
        foreach ($this->users as $uid => $u) {
            $body .= Packet::buildUserRecord($uid, $u['user_id'], $u['name'], $u['privilege'], $u['card']);
        }

        return pack('V', strlen($body)) . $body;
    }

    public function readTemplatesRaw(): string
    {
        if ($this->templateTableUnreadable) {
            return '';
        }

        $body = '';
        foreach ($this->templates as [$uid, $fid]) {
            $blob = str_repeat("\xAB", 10);
            $body .= pack('v', 6 + strlen($blob)) . pack('v', $uid) . chr($fid) . chr(1) . $blob;
        }

        return pack('V', strlen($body)) . $body;
    }

    public function writeUser(int $uid, string $userId, string $name, int $privilege = 0, int $cardNumber = 0): void
    {
        $this->writes++;

        if ($this->refuseWrites) {
            throw new ProtocolException('Device rejected the user write (ACK_ERROR).');
        }

        if ($this->keyWritesByUserId) {
            $uid = max(array_keys($this->users)) + 1;
        }

        $this->users[$uid] = ['user_id' => $userId, 'name' => $name, 'privilege' => $privilege, 'card' => $cardNumber];

        if ($this->dropTemplatesOnWrite) {
            $this->templates = array_values(array_filter($this->templates, fn ($t) => $t[0] !== $uid));
        }
    }
}
