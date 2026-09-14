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

use Promoseven\Biometric\C3\Capability\C3Capabilities;
use Promoseven\Biometric\C3\Protocol\Command;
use Promoseven\Biometric\C3\Transport\C3TcpTransport;
use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * The fallback for a C3 panel this library has never been run against.
 *
 * Session-less, because that is the only behaviour CONFIRMED to work on every panel
 * seen so far: the inBIO460 requires it, and the TF1700 tolerates it. Starting from
 * the behaviour that works everywhere is the safe default for an unknown unit.
 *
 * A panel that ends up here is NOT "supported". It is "we tried the thing most
 * likely to work". The moment one is actually read, it gets its own file named for
 * the model (rule 15) and its findings go in docs/device-capabilities.md — a
 * finding on the inBIO460 says nothing about a C3-400 until a C3-400 has answered.
 */
final class GenericPanel implements PanelModel
{
    public function __construct(private readonly string $name = 'unknown C3 panel') {}

    public function name(): string
    {
        return $this->name;
    }

    /**
     * Never matches. This class is the fallback the factory reaches when nothing
     * else claimed the name; it does not compete for one.
     */
    public static function matches(string $name): bool
    {
        return false;
    }

    /**
     * The family baseline, with nothing promoted to CONFIRMED.
     *
     * A panel we have never read gets no confirmations — not even PING, which would
     * be a claim about a device that has not answered us.
     */
    public function capabilities(): CapabilitySet
    {
        return C3Capabilities::defaults();
    }

    /**
     * Asks for session-less framing and tolerates a refusal.
     *
     * Measured safe on BOTH panels this project has (2026-09-14): the TF1700
     * requires 0x01 and the inBIO460 refuses it harmlessly with -98. Two data
     * points, not one plus a guess — which is what rule 15 asks for before a
     * behaviour is shared rather than split.
     *
     * A panel reaching this class is still not "supported". It is "we tried the
     * thing proven to work on everything we have read".
     */
    public function establishSession(C3TcpTransport $transport): void
    {
        $transport->useSession(sessionLess: true);

        try {
            $transport->send(Command::CONNECT_SESSION_LESS, '', 6.0);
        } catch (\Throwable) {
            // A panel that will not answer the request at all is still worth trying
            // to read; the commands that matter are tested next.
        }
    }
}
