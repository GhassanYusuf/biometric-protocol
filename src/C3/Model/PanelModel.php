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

namespace Promoseven\Biometric\C3\Model;

use Promoseven\Biometric\Capability\CapabilitySet;
use Promoseven\Biometric\C3\Transport\C3TcpTransport;

/**
 * What differs between one C3 panel and another.
 *
 * Rule 15: the moment a model needs different behaviour, that behaviour gets its
 * own file named for the model. This interface is the seam that makes that
 * possible — the implementation is chosen ONCE, when the panel is constructed, and
 * everything downstream speaks this interface and never learns which model it got.
 *
 * There is deliberately no `if ($model === ...)` anywhere below this line. A
 * conditional in the middle of a read loop is precisely the failure rule 15 exists
 * to prevent.
 */
interface PanelModel
{
    /** The model name this implementation is written for. */
    public function name(): string;

    /**
     * Whether this implementation is the one for a given device name.
     *
     * The match lives HERE, in the file named for the model, and not in a table in
     * the factory. That is rule 15 taken literally: a model identifier may appear in
     * executable code only inside a file named for that model, and it means the
     * factory can grow without ever learning a model name.
     */
    public static function matches(string $name): bool;

    /**
     * What this model can do, at the four levels of rule 9.
     *
     * Per model, never shared: a level CONFIRMED on one panel is UNKNOWN on another
     * until that panel has answered (rule 10 applied to hardware).
     */
    public function capabilities(): CapabilitySet;

    /**
     * Establishes whatever session this model needs on an already-open transport.
     *
     * Implementations configure the transport and return. A model that needs no
     * session says so by configuring a session-less transport — NOT by throwing,
     * because "this panel refuses CONNECT" is normal operation on some firmware and
     * a hard failure on none.
     */
    public function establishSession(C3TcpTransport $transport): void;
}
