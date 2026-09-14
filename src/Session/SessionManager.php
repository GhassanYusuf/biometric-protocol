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

use Promoseven\Biometric\Transport\TcpTransport;
use Promoseven\Biometric\Transport\UdpTransport;
use Promoseven\Biometric\Value\DeviceConfig;

/**
 * Holds sessions for several devices at once, keyed by endpoint.
 *
 * Needed for two real cases: a fleet-wide operation (sync every terminal), and a
 * multi-device realtime listener that stream_select()s across sockets. Callers
 * that only ever touch one device can ignore this and build a Session directly.
 *
 * Sessions are NOT shared across bulk reads — BulkReader re-establishes its own.
 * This manager tracks liveness and cleanup, not reuse of an in-flight transfer.
 */
final class SessionManager
{
    /** @var array<string,Session> */
    private array $sessions = [];

    /** @var array<string,DeviceConfig> */
    private array $configs = [];

    /** Registers a device without connecting to it. */
    public function register(DeviceConfig $config): void
    {
        $this->configs[$config->endpoint()] = $config;
    }

    /**
     * Returns an open session for a device, opening one if needed.
     *
     * A session that has died since last use is transparently reopened, so callers
     * do not have to distinguish "never connected" from "connection dropped".
     */
    public function session(DeviceConfig $config): Session
    {
        $key = $config->endpoint();
        $this->configs[$key] = $config;

        $session = $this->sessions[$key] ?? null;

        if ($session !== null && $session->isOpen()) {
            return $session;
        }

        $transport = $config->usesTcp() ? new TcpTransport($config) : new UdpTransport($config);
        $session = new Session($transport, $config);
        $session->open();

        $this->sessions[$key] = $session;

        return $session;
    }

    /** @return list<DeviceConfig> */
    public function registered(): array
    {
        return array_values($this->configs);
    }

    /** @return array<string,Session> keyed by endpoint */
    public function openSessions(): array
    {
        return array_filter($this->sessions, static fn (Session $s) => $s->isOpen());
    }

    public function closeOne(DeviceConfig $config): void
    {
        $key = $config->endpoint();

        if (isset($this->sessions[$key])) {
            $this->sessions[$key]->close();
            unset($this->sessions[$key]);
        }
    }

    /** Closes everything. Safe to call repeatedly. */
    public function closeAll(): void
    {
        foreach ($this->sessions as $session) {
            $session->close();
        }

        $this->sessions = [];
    }

    public function __destruct()
    {
        $this->closeAll();
    }
}
