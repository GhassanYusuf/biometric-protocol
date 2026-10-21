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
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Capability\CapabilitySet;
use Promoseven\Biometric\C3\Capability\C3Capabilities;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Model\F22;
use Promoseven\Biometric\Model\GenericTerminal;
use Promoseven\Biometric\Service\UserService;

/**
 * UserService::deleteAll() (2.16.0, DEVICE_WIPE): every user removed, and the empty
 * table read back — an acknowledgement alone proves nothing on this firmware family.
 *
 * Uses the in-memory ReuploadTerminal from UserReuploadTest.
 */
final class UserDeleteAllTest extends TestCase
{
    private function terminal(): ReuploadTerminal
    {
        $t = new ReuploadTerminal();
        $t->addUser(1, '48', 'first', 0);
        $t->addUser(2, '21', 'second', 7511517);
        $t->addUser(3, '279', 'third', 0);
        $t->templates = [[1, 0, str_repeat("\x01", 40)], [2, 6, str_repeat("\x02", 40)]];

        return $t;
    }

    public function test_removes_every_user_and_their_fingerprints(): void
    {
        $t = $this->terminal();

        $this->assertSame(3, (new UserService($t))->deleteAll());

        $this->assertSame([], $t->records);
        $this->assertSame([], $t->templates);
    }

    public function test_an_empty_terminal_is_zero_and_no_writes(): void
    {
        $t = new ReuploadTerminal();

        $this->assertSame(0, (new UserService($t))->deleteAll());
        $this->assertSame(0, $t->writes);
    }

    public function test_a_delete_the_device_dropped_is_reported_not_counted_as_done(): void
    {
        $t = $this->terminal();
        $t->ignoreDeleteOfUid = 2;

        try {
            (new UserService($t))->deleteAll();
            $this->fail('Expected the read-back to catch the dropped delete.');
        } catch (VerificationException $e) {
            $this->assertStringContainsString('still holds 1 user', $e->getMessage());
            $this->assertSame(['21'], $e->context()['remaining']);
        }
    }

    public function test_a_refused_delete_says_how_far_it_got(): void
    {
        $t = $this->terminal();
        $t->refuseDeletes = true;

        try {
            (new UserService($t))->deleteAll();
            $this->fail('Expected a refusal.');
        } catch (ProtocolException $e) {
            $this->assertSame(0, $e->context()['deleted']);
            $this->assertSame(3, $e->context()['total']);
        }
        $this->assertCount(3, $t->records, 'Nothing removed when the first delete is refused.');
    }

    /** Rule 15: F18-first. Every other model must say so on its own, not inherit it. */
    public function test_only_the_f18_set_offers_a_wipe(): void
    {
        $this->assertSame(Capability::IMPLEMENTED, CapabilitySet::defaults()->level(Capability::DEVICE_WIPE));
        $this->assertSame(Capability::UNKNOWN, (new F22())->capabilities()->level(Capability::DEVICE_WIPE));
        $this->assertSame(Capability::UNKNOWN, (new GenericTerminal())->capabilities()->level(Capability::DEVICE_WIPE));
        $this->assertSame(Capability::NOT_IMPLEMENTED, C3Capabilities::forModel(null)->level(Capability::DEVICE_WIPE));
    }
}
