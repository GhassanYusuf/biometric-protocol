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

namespace Promoseven\Biometric\Model;

use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * A standalone terminal whose model this library has no file for (or that was never
 * identified). It speaks the family protocol, so the READ levels of the family
 * apply as IMPLEMENTED; every write is UNKNOWN until the model gets its own file
 * from a real run (rule 15, rule 16). Identify the model first (device.info).
 */
final class GenericTerminal implements TerminalModel
{
    public function __construct(private readonly string $name = 'unknown terminal')
    {
    }

    public function name(): string
    {
        return $this->name;
    }

    public static function matches(string $name): bool
    {
        return false;
    }

    public function capabilities(): CapabilitySet
    {
        $levels = [];
        foreach (CapabilitySet::defaults()->toArray() as $capability => $level) {
            $levels[$capability] = $level === Capability::CONFIRMED ? Capability::IMPLEMENTED : $level;
        }

        foreach ([
            Capability::USER_WRITE, Capability::USER_DELETE, Capability::USER_RENUMBER,
            Capability::USER_DISABLE, Capability::USER_PRIVILEGE, Capability::CARD_WRITE, Capability::CARD_ENROLL, Capability::PASSWORD_WRITE,
            Capability::FINGERPRINT_ENROLL, Capability::TEMPLATE_DELETE,
            Capability::TEMPLATE_UPLOAD, Capability::SET_TIME, Capability::ATTENDANCE_CLEAR,
            Capability::RESTART,
        ] as $write) {
            $levels[$write] = Capability::UNKNOWN;
        }

        return CapabilitySet::fromArray($levels);
    }
}
