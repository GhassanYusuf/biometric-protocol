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
 * The device did not answer in time.
 *
 * Distinct from ConnectionException: the socket was fine, the device simply did
 * not reply — which is also the normal outcome of an enrollment nobody attended.
 */
class TimeoutException extends DeviceException
{
    public function isRetryable(): bool
    {
        return true;
    }
}
