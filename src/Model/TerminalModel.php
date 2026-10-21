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
 * One model of ZKTeco STANDALONE terminal (the UDP/TCP binary protocol), 2.11.0.
 *
 * The standalone family used to share one capability set, CapabilitySet::defaults(),
 * which describes the F18. Every other model inherited the F18's levels — so a
 * method proven on the F18 (a fingerprint upload, say) was silently offered on the
 * F22 too, where it had never run. The owner's rule (host CLAUDE.md rule 21): each
 * model has its own method for each action, and fixing one model must never change
 * another. This is the C3 family's PanelModel pattern applied to the standalone family.
 */
interface TerminalModel
{
    public function name(): string;

    /**
     * Whether this implementation is the one for a device's model name. The match
     * lives in the file named for the model (rule 15), never in the factory.
     */
    public static function matches(string $name): bool;

    /**
     * What this model can do, at the four levels of rule 9. A level CONFIRMED on one
     * model is not evidence about another (rule 15).
     */
    public function capabilities(): CapabilitySet;
}
