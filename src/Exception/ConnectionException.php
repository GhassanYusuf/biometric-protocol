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

/** The device could not be reached, or refused the handshake / comm key. */
class ConnectionException extends DeviceException
{
    public function isRetryable(): bool
    {
        return true;
    }
}
