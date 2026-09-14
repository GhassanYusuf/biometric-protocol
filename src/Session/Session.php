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

namespace Promoseven\Biometric\Session;

use Promoseven\Biometric\Contracts\Transport;
use Promoseven\Biometric\Exception\ConnectionException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Value\DeviceConfig;

/**
 * One authenticated conversation with one device.
 *
 * Lifecycle: open() → handshake (→ comm-key auth if challenged) → commands →
 * close(). The device assigns the session id during the handshake; every
 * subsequent packet must carry it.
 *
 * A session is cheap and disposable by design — BulkReader deliberately discards
 * and re-establishes one per bulk read. See that class for why.
 */
final class Session
{
    private bool $authenticated = false;

    /**
     * True when the device may still be streaming data we did not consume.
     *
     * CONFIRMED HAZARD: a reply of PREPARE_DATA means the device is about to push
     * chunks. If those are left in the socket buffer, the NEXT request reads one of
     * them instead of its own reply — and because they are well-formed packets, the
     * caller gets a confident wrong answer rather than an error.
     *
     * Observed on real hardware: probing template slots 0/3/6/7 for one user on a
     * dirty session returned answers SHIFTED BY ONE REQUEST — slot 7 reported the
     * 1304-byte template that actually belongs to slot 6. On a clean session the
     * same probes answered correctly.
     *
     * Anything that leaves a transfer un-drained must call markDirty(); the next
     * command then transparently reopens.
     */
    private bool $dirty = false;

    public function __construct(
        private readonly Transport $transport,
        private readonly DeviceConfig $config,
    ) {
    }

    /**
     * Opens the link and completes the handshake.
     *
     * The device may answer CONNECT with ACK_UNAUTH, meaning a comm key is set. We
     * then send the scrambled ticket. CONFIRMED with commKey = 0 (disabled); the
     * non-zero path follows the published algorithm but is unexercised here.
     */
    public function open(): void
    {
        $this->transport->open();

        $reply = $this->transport->send(Command::CONNECT);
        $this->transport->setSessionId($reply->sessionId);

        if ($reply->isUnauthorised()) {
            $ticket = Packet::makeCommKey($this->config->commKey, $reply->sessionId);
            $authReply = $this->transport->send(Command::AUTH, $ticket);

            if (! $authReply->isAccepted()) {
                $this->transport->close();

                throw new ConnectionException('Device rejected authentication (check the comm key).', [
                    'endpoint' => $this->config->endpoint(),
                    'reply' => $authReply->commandName(),
                ]);
            }

            $this->authenticated = true;

            return;
        }

        if (! $reply->isAccepted()) {
            $this->transport->close();

            throw new ConnectionException('Device refused the connection handshake.', [
                'endpoint' => $this->config->endpoint(),
                'reply' => $reply->commandName(),
            ]);
        }

        $this->authenticated = true;
    }

    /** Best-effort graceful close: tells the device to drop the session, then closes. */
    public function close(): void
    {
        if (! $this->transport->isOpen()) {
            return;
        }

        try {
            $this->transport->send(Command::EXIT);
        } catch (\Throwable) {
            // Best-effort — a device that has already gone away needs no goodbye.
        }

        $this->transport->close();
        $this->authenticated = false;
    }

    /** Re-establishes the session from scratch. Clears the dirty flag. */
    public function reopen(): void
    {
        $this->transport->close();
        $this->open();
        $this->dirty = false;
    }

    /** Records that the device may still be streaming data we did not consume. */
    public function markDirty(): void
    {
        $this->dirty = true;
    }

    public function isDirty(): bool
    {
        return $this->dirty;
    }

    /**
     * Reopens only if the session is dirty. Cheap no-op otherwise.
     *
     * Called before every command so a caller never has to know which of its
     * previous calls left a transfer hanging.
     */
    public function ensureClean(): void
    {
        if ($this->dirty) {
            $this->reopen();
        }
    }

    public function isOpen(): bool
    {
        return $this->transport->isOpen() && $this->authenticated;
    }

    public function transport(): Transport
    {
        return $this->transport;
    }

    public function config(): DeviceConfig
    {
        return $this->config;
    }

    public function id(): int
    {
        return $this->transport->sessionId();
    }
}
