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

namespace Promoseven\Biometric\Value;

/**
 * Outcome of a live capture at the terminal.
 *
 * Deliberately a value object rather than a bare bool: a capture has three
 * distinct endings and collapsing any two loses information the caller needs.
 *
 *   SUCCESS   the device captured and stored it
 *   REJECTED  the device answered with an error code (bad read, duplicate finger)
 *   TIMEOUT   nobody interacted with the terminal
 *
 * REJECTED is the device's verdict and is not retryable by itself; TIMEOUT is.
 */
final class EnrollmentResult
{
    public const SUCCESS = 'success';
    public const REJECTED = 'rejected';
    public const TIMEOUT = 'timeout';

    private function __construct(
        public readonly string $outcome,
        public readonly ?int $fingerIndex = null,
        public readonly ?int $cardNumber = null,
        public readonly ?int $errorCode = null,
        /** @var list<string> Ordered progress events, for an audit trail. */
        public readonly array $events = [],
    ) {
    }

    /** @param list<string> $events */
    public static function fingerprint(int $fingerIndex, array $events = []): self
    {
        return new self(self::SUCCESS, fingerIndex: $fingerIndex, events: $events);
    }

    /** @param list<string> $events */
    public static function card(int $cardNumber, array $events = []): self
    {
        return new self(self::SUCCESS, cardNumber: $cardNumber, events: $events);
    }

    /** @param list<string> $events */
    public static function rejected(int $errorCode, array $events = []): self
    {
        return new self(self::REJECTED, errorCode: $errorCode, events: $events);
    }

    /** @param list<string> $events */
    public static function timeout(array $events = []): self
    {
        return new self(self::TIMEOUT, events: $events);
    }

    public function succeeded(): bool
    {
        return $this->outcome === self::SUCCESS;
    }

    public function didTimeOut(): bool
    {
        return $this->outcome === self::TIMEOUT;
    }

    /** Whether re-running the same capture could plausibly succeed. */
    public function isRetryable(): bool
    {
        return $this->outcome === self::TIMEOUT;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'outcome' => $this->outcome,
            'success' => $this->succeeded(),
            'finger_index' => $this->fingerIndex,
            'card_number' => $this->cardNumber,
            'error_code' => $this->errorCode,
            'events' => $this->events,
        ];
    }
}
