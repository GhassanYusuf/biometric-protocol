<?php

/*
 * This file is part of promoseven/biometric-protocol.
 * Copyright (c) 2026 Promoseven. All rights reserved.
 * Proprietary and confidential. Not open source. No licence to use, copy,
 * modify or distribute this file is granted except under a signed written
 * agreement with the copyright holder. See LICENSE.
 */

namespace Promoseven\Biometric\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Service\UserService;

/**
 * UserService::setPrivilege() (2.14.0): admin / normal user on an existing record,
 * everything else on the record kept, the privilege itself read back.
 */
final class UserPrivilegeTest extends TestCase
{
    private function terminal(): RenumberTerminal
    {
        $t = new RenumberTerminal();
        $t->users[7] = ['user_id' => '205', 'name' => 'ali', 'privilege' => 0, 'card' => 777, 'password' => '4321'];

        return $t;
    }

    public function test_makes_a_user_an_administrator_keeping_name_card_and_password(): void
    {
        $t = $this->terminal();

        $user = (new UserService($t))->setPrivilege('205', UserService::PRIVILEGE_ADMIN);

        $this->assertSame(14, $user->privilege);
        $this->assertSame(['user_id' => '205', 'name' => 'ali', 'privilege' => 14, 'card' => 777, 'password' => '4321'], $t->users[7]);
    }

    public function test_demotes_an_administrator(): void
    {
        $t = $this->terminal();
        $t->users[7]['privilege'] = 14;

        $this->assertSame(0, (new UserService($t))->setPrivilege('205', UserService::PRIVILEGE_USER)->privilege);
    }

    public function test_refuses_a_user_not_on_the_device_and_writes_nothing(): void
    {
        $t = $this->terminal();

        try {
            (new UserService($t))->setPrivilege('999', 14);
            $this->fail('Expected a refusal.');
        } catch (ProtocolException $e) {
            $this->assertStringContainsString('999', $e->getMessage());
        }

        $this->assertSame(0, $t->writes);
    }

    public function test_refuses_a_privilege_value_it_does_not_write(): void
    {
        $this->expectException(ProtocolException::class);

        (new UserService($this->terminal()))->setPrivilege('205', 6);
    }

    public function test_an_acknowledged_change_the_device_dropped_is_reported(): void
    {
        $t = $this->terminal();
        $t->dropPrivileges = true;

        $this->expectException(VerificationException::class);
        $this->expectExceptionMessage('reads back 0, not 14');

        (new UserService($t))->setPrivilege('205', 14);
    }
}
