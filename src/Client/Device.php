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

namespace Promoseven\Biometric\Client;

use Promoseven\Biometric\Capability\CapabilityResolver;
use Promoseven\Biometric\Capability\CapabilitySet;
use Promoseven\Biometric\Contracts\ProgressListener;
use Promoseven\Biometric\Service\AttendanceService;
use Promoseven\Biometric\Service\EnrollmentService;
use Promoseven\Biometric\Service\TemplateService;
use Promoseven\Biometric\Service\UserService;
use Promoseven\Biometric\Value\DeviceConfig;

/**
 * The library's front door.
 *
 * One object per device, grouping the services by what they act on:
 *
 *     $device = Device::open(new DeviceConfig('192.168.7.62'));
 *     try {
 *         $users = $device->users()->all(withFingerprints: true);
 *         $punches = $device->attendance()->since($watermark);
 *     } finally {
 *         $device->close();
 *     }
 *
 * Or, preferably, let the library manage the session:
 *
 *     $users = Device::run($config, fn (Device $d) => $d->users()->all());
 *
 * Nothing here is Laravel-aware. A host app maps its own model to DeviceConfig in
 * its own adapter; see docs/integration-laravel.md.
 */
final class Device
{
    private ?UserService $users = null;
    private ?AttendanceService $attendance = null;
    private ?EnrollmentService $enrollment = null;
    private ?TemplateService $templates = null;
    private ?CapabilitySet $capabilities = null;

    public function __construct(
        private readonly DeviceClient $client,
        ?CapabilitySet $capabilities = null,
    ) {
        $this->capabilities = $capabilities;
    }

    /** Opens a session. The caller owns closing it. */
    public static function open(DeviceConfig $config, ?CapabilitySet $capabilities = null): self
    {
        return new self(DeviceClient::connect($config), $capabilities);
    }

    /**
     * Opens a session, runs the callback, always closes — the idiomatic entry point.
     *
     * @template T
     * @param \Closure(self):T $callback
     * @return T
     */
    public static function run(DeviceConfig $config, \Closure $callback, ?CapabilitySet $capabilities = null): mixed
    {
        $device = self::open($config, $capabilities);

        try {
            return $callback($device);
        } finally {
            $device->close();
        }
    }

    public function close(): void
    {
        $this->client->disconnect();
    }

    public function config(): DeviceConfig
    {
        return $this->client->config();
    }

    /** Low-level command surface, for anything the services do not cover. */
    public function client(): DeviceClient
    {
        return $this->client;
    }

    /**
     * Watches bulk transfers on this device.
     *
     * ->onProgress($listener)->attendance()->all() reports byte counts as the table
     * streams in, which is the only honest basis for a progress bar: the device
     * declares the total up front and the reassembler counts what arrived.
     *
     * Pass null to stop watching. Attach BEFORE the read — see
     * DeviceClient::onProgress().
     */
    public function onProgress(?ProgressListener $listener): self
    {
        $this->client->onProgress($listener);

        return $this;
    }

    public function users(): UserService
    {
        return $this->users ??= new UserService($this->client);
    }

    public function attendance(): AttendanceService
    {
        return $this->attendance ??= new AttendanceService($this->client);
    }

    public function enrollment(): EnrollmentService
    {
        return $this->enrollment ??= new EnrollmentService($this->client);
    }

    public function templates(): TemplateService
    {
        return $this->templates ??= new TemplateService($this->client);
    }

    /**
     * The link's stream, for waiting on several devices in one process.
     *
     * Only meaningful on a session held open for realtime listening — see
     * AttendanceService::listen(). Null means the transport cannot be selected on,
     * and the caller should poll nextRealtimePunch() instead.
     *
     * @return resource|null
     */
    public function selectableStream()
    {
        return $this->client->selectableStream();
    }

    /**
     * What this device can do.
     *
     * Uses the declared baseline unless a set was injected or probe() has run —
     * probing costs several round trips, so it is never implicit.
     */
    public function capabilities(): CapabilitySet
    {
        return $this->capabilities ??= CapabilitySet::defaults();
    }

    /** Probes the device read-only and caches the refined capability set. */
    public function probeCapabilities(): CapabilitySet
    {
        return $this->capabilities = (new CapabilityResolver($this->client))->resolve();
    }

    // --- Pass-throughs for whole-device concerns ---

    /** @return array{alive:bool, device_time:?\DateTimeImmutable, latency_ms:float} */
    public function ping(): array
    {
        return $this->client->ping();
    }

    /** @return array<string,mixed> */
    public function info(): array
    {
        return $this->client->getDeviceInfo();
    }

    public function time(): ?\DateTimeImmutable
    {
        return $this->client->getTime();
    }

    /** Sets the device clock. Capability-gated: IMPLEMENTED, not confirmed. */
    public function syncTime(?\DateTimeInterface $to = null): void
    {
        $this->capabilities()->require(\Promoseven\Biometric\Capability\Capability::SET_TIME);

        $this->client->setTime($to ?? new \DateTimeImmutable('now', new \DateTimeZone($this->config()->timezone)));
    }

    /** Reboots the device. Capability-gated and never automatic. */
    public function restart(): void
    {
        $this->capabilities()->require(\Promoseven\Biometric\Capability\Capability::RESTART);

        $this->client->restart();
    }
}
