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

use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * ZKTeco F18 (and F18/ID). The reference model: every level in
 * CapabilitySet::defaults() was observed on one — IT Room, 192.168.7.62, firmware
 * "Ver 6.60 Apr 26 2016", platform ZMM210_TFT. Camelot (87.237.196.60) is the same
 * model and firmware but needs the AUTH exchange; Good Wheels (46.184.163.106) is an
 * F18/ID on "Ver 6.60 Oct 12 2021" — newer firmware, writes never run there.
 */
final class F18 implements TerminalModel
{
    public function name(): string
    {
        return 'F18';
    }

    public static function matches(string $name): bool
    {
        return preg_match('/^F18\b/i', trim($name)) === 1;
    }

    public function capabilities(): CapabilitySet
    {
        return CapabilitySet::defaults();
    }
}
