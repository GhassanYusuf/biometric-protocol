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
use Promoseven\Biometric\Service\UserService;

/**
 * UserService::all(withFingerprints: true) — the three answers kept apart (2.16.1):
 * fingers known, "none" (the table is empty), and unknown (it would not decode).
 * Until 2.16.1 an empty table was reported as unknown for everyone, so a terminal with
 * no fingerprints could never be given its first one.
 */
final class UserFingerSlotsTest extends TestCase
{
    private function terminal(): ReuploadTerminal
    {
        $t = new ReuploadTerminal();
        $t->addUser(1, '830108246', 'Ghassan', 7566580);
        $t->addUser(2, '205', 'Ali', 0);

        return $t;
    }

    public function test_an_empty_table_sent_as_nothing_means_no_fingers_for_everyone(): void
    {
        $t = $this->terminal();
        $t->templateTableSendsNothing = true;

        foreach ((new UserService($t))->all(true) as $user) {
            $this->assertSame([], $user->fingerSlots, "{$user->userId}: empty table is a real 'none'");
        }
    }

    public function test_an_empty_table_with_a_zero_length_prefix_means_no_fingers(): void
    {
        $t = $this->terminal(); // no templates: the fake sends pack('V', 0)

        foreach ((new UserService($t))->all(true) as $user) {
            $this->assertSame([], $user->fingerSlots);
        }
    }

    public function test_a_table_that_will_not_decode_stays_unknown(): void
    {
        $t = $this->terminal();
        $t->templateTableUnreadable = true;

        foreach ((new UserService($t))->all(true) as $user) {
            $this->assertNull($user->fingerSlots, 'garbage is not "none" (rule 10)');
        }
    }

    public function test_fingers_on_the_table_are_reported_and_others_are_none(): void
    {
        $t = $this->terminal();
        $t->templates = [[1, 6, str_repeat("\x06", 40)], [1, 3, str_repeat("\x03", 40)]];

        $slots = [];
        foreach ((new UserService($t))->all(true) as $user) {
            $slots[$user->userId] = $user->fingerSlots;
        }
        sort($slots['830108246']);

        $this->assertSame([3, 6], $slots['830108246']);
        $this->assertSame([], $slots['205']);
    }
}
