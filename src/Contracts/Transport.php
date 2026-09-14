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

namespace Promoseven\Biometric\Contracts;

use Promoseven\Biometric\Value\Reply;

/**
 * Byte-level link to a device.
 *
 * Everything above this interface is protocol logic; everything below is sockets.
 * Swapping UDP for TCP, or for a recorded fixture in tests, happens here and
 * nowhere else.
 *
 * Implementations own the session id / reply id counters, because the reply id
 * increments per request and the session id is assigned by the device during the
 * handshake — both are properties of a live link, not of the protocol.
 */
interface Transport
{
    /** Opens the link. Resets session state. */
    public function open(): void;

    /** Closes the link. Safe to call when already closed. */
    public function close(): void;

    public function isOpen(): bool;

    /** Sends one command and waits for its reply. */
    public function send(int $command, string $data = ''): Reply;

    /**
     * Sends raw pre-built bytes without waiting for a reply — used for realtime
     * acknowledgements, which the device does not answer.
     */
    public function sendRaw(string $packet): void;

    /**
     * Reads the next unsolicited datagram, or null if none arrived within the
     * poll window. Used by the realtime event listener.
     */
    public function readUnsolicited(float $pollSeconds = 0.5): ?Reply;

    /** Overrides the read timeout for the duration of a bulk reassembly. */
    public function setReadTimeout(int $seconds, int $microseconds = 0): void;

    /**
     * The underlying stream, for readiness selection across several devices.
     *
     * Returns null when this transport cannot be selected on — a recorded fixture,
     * or any future request/response transport with no persistent socket. Callers
     * MUST handle null by falling back to polling each link in turn; it is not an
     * error, just an absent optimisation.
     *
     * WHY THIS IS ON THE CONTRACT: a realtime listener watching several terminals
     * has to block on all of them at once. Without this it would either need one
     * process per device (no pcntl on Windows) or a busy-poll loop whose latency
     * grows with the number of devices. The alternative — reaching past the
     * contract for UdpTransport's private socket — is what makes a transport
     * abstraction decorative.
     *
     * @return resource|null
     */
    public function selectableStream();

    public function sessionId(): int;

    public function setSessionId(int $sessionId): void;
}
