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

namespace Promoseven\Biometric\Exception;

/**
 * Base for every failure raised by this library.
 *
 * Callers that only care "did it work" catch this. Callers that need to react
 * differently — retry a timeout, surface an unsupported command as a UI hint,
 * escalate a verification failure — catch the specific subclass.
 */
class DeviceException extends \RuntimeException
{
    /** @var array<string,mixed> Structured context for logs, never for end users. */
    protected array $context = [];

    /** @param array<string,mixed> $context */
    public function __construct(string $message, array $context = [], int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    /** @return array<string,mixed> */
    public function context(): array
    {
        return $this->context;
    }

    /**
     * Whether retrying the same operation could plausibly succeed. Transport and
     * timeout problems are transient; a rejected command or an unsupported
     * feature will fail identically forever.
     */
    public function isRetryable(): bool
    {
        return false;
    }
}
