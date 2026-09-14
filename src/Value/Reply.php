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

use Promoseven\Biometric\Protocol\Command;

/** One decoded reply from the device. */
final class Reply
{
    public function __construct(
        public readonly int $command,
        public readonly int $checksum,
        public readonly int $sessionId,
        public readonly int $replyId,
        public readonly string $data,
    ) {
    }

    /** @param array{command:int,checksum:int,sessionId:int,replyId:int,data:string} $parsed */
    public static function fromArray(array $parsed): self
    {
        return new self(
            $parsed['command'],
            $parsed['checksum'],
            $parsed['sessionId'],
            $parsed['replyId'],
            $parsed['data'],
        );
    }

    /** The device accepted the request (ACK_OK or ACK_DATA). */
    public function isAccepted(): bool
    {
        return in_array($this->command, Command::ACCEPTED, true);
    }

    public function isError(): bool
    {
        return $this->command === Command::ACK_ERROR;
    }

    public function isUnauthorised(): bool
    {
        return $this->command === Command::ACK_UNAUTH;
    }

    /** Starts a chunked bulk transfer whose total size is in the first 4 bytes. */
    public function isPreparingData(): bool
    {
        return $this->command === Command::PREPARE_DATA;
    }

    /** Carries the whole payload inline — small tables arrive this way. */
    public function isInlineData(): bool
    {
        return $this->command === Command::DATA;
    }

    public function length(): int
    {
        return strlen($this->data);
    }

    /** Declared total byte length of an incoming bulk transfer. */
    public function declaredSize(): int
    {
        if ($this->length() < 4) {
            return 0;
        }

        return unpack('V', substr($this->data, 0, 4))[1];
    }

    public function commandName(): string
    {
        return Command::name($this->command);
    }
}
