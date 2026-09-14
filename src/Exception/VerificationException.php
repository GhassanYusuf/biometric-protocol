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
 * A write was acknowledged but did not survive being read back.
 *
 * This firmware family genuinely does this: it returns CMD_ACK_OK and then
 * silently drops the change. Every write in this library reads back and confirms,
 * and raises this when the device's own tables disagree with what it accepted.
 */
class VerificationException extends DeviceException
{
    public function isRetryable(): bool
    {
        return true;
    }
}
