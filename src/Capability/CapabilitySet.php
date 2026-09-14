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

namespace Promoseven\Biometric\Capability;

use Promoseven\Biometric\Exception\UnsupportedCommandException;

/**
 * What one device can do, as a queryable set.
 *
 * Immutable. A host app persists this per device and hands it to its UI so
 * unsupported actions are never offered — the alternative is a button that returns
 * a 502 and an operator who learns to distrust the whole screen.
 */
final class CapabilitySet
{
    /** @param array<string,string> $levels capability key => support level */
    public function __construct(private readonly array $levels = [])
    {
    }

    /**
     * Baseline for the ZKTeco standalone protocol as this library implements it.
     *
     * Every level here is an honest statement of what this project observed on a
     * real ZKTeco F18 at 192.168.7.62, not a vendor datasheet claim.
     */
    public static function defaults(): self
    {
        return new self([
            // Verified working — see docs/device-capabilities.md for the evidence.
            Capability::PING => Capability::CONFIRMED,
            Capability::DEVICE_INFO => Capability::CONFIRMED,
            Capability::GET_TIME => Capability::CONFIRMED,
            Capability::USER_READ => Capability::CONFIRMED,
            Capability::USER_WRITE => Capability::CONFIRMED,
            Capability::USER_DELETE => Capability::CONFIRMED,
            Capability::CARD_READ => Capability::CONFIRMED,
            Capability::CARD_WRITE => Capability::CONFIRMED,
            Capability::FINGERPRINT_ENROLL => Capability::CONFIRMED,
            Capability::TEMPLATE_TABLE_READ => Capability::CONFIRMED,
            Capability::TEMPLATE_SLOT_PROBE => Capability::CONFIRMED,
            Capability::ATTENDANCE_READ => Capability::CONFIRMED,

            // Implemented, never confirmed succeeding on hardware.
            Capability::SET_TIME => Capability::IMPLEMENTED,
            Capability::TEMPLATE_DELETE => Capability::IMPLEMENTED,
            Capability::CARD_ENROLL => Capability::IMPLEMENTED,
            Capability::ATTENDANCE_REALTIME => Capability::IMPLEMENTED,
            Capability::ATTENDANCE_CLEAR => Capability::IMPLEMENTED,
            Capability::RESTART => Capability::IMPLEMENTED,
            // Approximated by clearing the card — the protocol has no suspend flag.
            Capability::USER_DISABLE => Capability::IMPLEMENTED,

            // This library does not do these.
            Capability::TEMPLATE_DOWNLOAD => Capability::NOT_IMPLEMENTED,
            Capability::TEMPLATE_UPLOAD => Capability::NOT_IMPLEMENTED,

            // Never probed. Access-control features may well exist on the hardware;
            // we have no evidence either way, so we claim nothing.
            Capability::VERIFY_MODE => Capability::UNKNOWN,
            Capability::ACCESS_SCHEDULES => Capability::UNKNOWN,
            Capability::ANTI_PASSBACK => Capability::UNKNOWN,
            Capability::DURESS => Capability::UNKNOWN,
            Capability::RELAY => Capability::UNKNOWN,
        ]);
    }

    public function level(string $capability): string
    {
        return $this->levels[$capability] ?? Capability::UNKNOWN;
    }

    /** Whether a UI should offer this action. */
    public function supports(string $capability): bool
    {
        return Capability::isUsable($this->level($capability));
    }

    /** Verified on hardware, as opposed to merely implemented. */
    public function isConfirmed(string $capability): bool
    {
        return $this->level($capability) === Capability::CONFIRMED;
    }

    /**
     * Guard for the top of a service method.
     *
     * Throws the typed exception rather than returning a plausible empty result, so
     * "this firmware cannot" can never be mistaken for "there is nothing there".
     */
    public function require(string $capability): void
    {
        if (! $this->supports($capability)) {
            throw new UnsupportedCommandException(
                "This device does not support {$capability}: " . Capability::describe($this->level($capability)),
                ['capability' => $capability, 'level' => $this->level($capability)],
            );
        }
    }

    /** Returns a new set with these levels overlaid — probing refines defaults. */
    public function with(array $levels): self
    {
        return new self([...$this->levels, ...$levels]);
    }

    /** @return array<string,string> */
    public function toArray(): array
    {
        return $this->levels;
    }

    /**
     * Shape the UI consumes: every capability with its level, usability and reason.
     *
     * @return array<string,array{level:string,usable:bool,confirmed:bool,description:string}>
     */
    public function forUi(): array
    {
        $out = [];

        foreach (Capability::all() as $key) {
            $level = $this->level($key);

            $out[$key] = [
                'level' => $level,
                'usable' => Capability::isUsable($level),
                'confirmed' => $level === Capability::CONFIRMED,
                'description' => Capability::describe($level),
            ];
        }

        return $out;
    }

    /** @param array<string,string> $levels */
    public static function fromArray(array $levels): self
    {
        return new self($levels);
    }
}
