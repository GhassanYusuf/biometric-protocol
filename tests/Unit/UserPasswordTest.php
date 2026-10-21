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
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Capability\CapabilityResolver;
use Promoseven\Biometric\Codec\UserCodec;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Service\UserService;

/**
 * The keypad password, password(8)@3 of the 72-byte user record (2.13.0).
 *
 * Until 2.13.0 the record was rebuilt with the field zeroed, so every name push and
 * card write erased the password a person had set at the keypad (OBSERVED 2026-10-12
 * on IT ROOM, F18). These pin the fix: the password is decoded, written, KEPT when the
 * caller does not give one, and verified on read-back without ever being printed.
 */
final class UserPasswordTest extends TestCase
{
    private function terminal(string $password = ''): RenumberTerminal
    {
        $t = new RenumberTerminal();
        $t->users[7] = ['user_id' => '205', 'name' => 'ali', 'privilege' => 0, 'card' => 777, 'password' => $password];

        return $t;
    }

    public function test_the_password_is_decoded_from_offset_3(): void
    {
        $record = Packet::buildUserRecord(7, '205', 'ali', 0, 777, 1, '4321');
        $this->assertSame('4321', substr($record, 3, 4));
        $this->assertSame('ali', UserCodec::decode(pack('V', 72).$record)[0]['name'], 'the name field is untouched');
        $this->assertSame('4321', UserCodec::decode(pack('V', 72).$record)[0]['password']);
    }

    public function test_a_password_longer_than_the_field_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Packet::buildUserRecord(7, '205', 'ali', 0, 0, 1, '123456789');
    }

    public function test_a_name_write_keeps_the_password_the_device_holds(): void
    {
        $t = $this->terminal('4321');
        $user = (new UserService($t))->save('205', 'ali mohamed');

        $this->assertSame('4321', $t->users[7]['password']);
        $this->assertSame('4321', $user->password);
        $this->assertTrue($user->hasPassword());
        $this->assertArrayNotHasKey('password', $user->toArray(), 'the value never leaves through toArray()');
    }

    public function test_a_card_write_keeps_the_password_too(): void
    {
        $t = $this->terminal('4321');
        (new UserService($t))->setCard('205', 999);

        $this->assertSame('4321', $t->users[7]['password']);
        $this->assertSame(999, $t->users[7]['card']);
    }

    public function test_a_given_password_is_written_and_an_empty_one_clears_it(): void
    {
        $t = $this->terminal('4321');
        $users = new UserService($t);

        $users->save('205', 'ali', null, null, '8765');
        $this->assertSame('8765', $t->users[7]['password']);

        $users->save('205', 'ali', null, null, '');
        $this->assertSame('', $t->users[7]['password']);
    }

    public function test_a_device_that_drops_the_password_is_caught_without_printing_it(): void
    {
        $t = new RenumberTerminal();
        $t->dropPasswords = true;
        $t->users[7] = ['user_id' => '205', 'name' => 'ali', 'privilege' => 0, 'card' => 0, 'password' => ''];

        try {
            (new UserService($t))->save('205', 'ali', null, null, '8765');
            $this->fail('a dropped password must not pass as written');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('keypad password does not read back', $e->getMessage());
            $this->assertStringNotContainsString('8765', $e->getMessage());
        }
    }

    public function test_password_write_is_never_probed_so_a_level_earned_on_one_terminal_survives(): void
    {
        // A host app keeps unprobeable levels a terminal earned by a real write test
        // across re-probes; password.write must be one of them (2.14.1).
        $this->assertArrayHasKey(Capability::PASSWORD_WRITE, CapabilityResolver::unprobeable());
        $this->assertArrayNotHasKey(Capability::PASSWORD_READ, CapabilityResolver::unprobeable(), 'a read is probeable');
    }
}
