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
 * The device answered with something this implementation cannot interpret: an
 * unexpected command code, a malformed record table, a truncated bulk transfer.
 *
 * Not retryable by default — a firmware whose layout we misread will misread
 * identically next time. Bulk transfers retry at the transport level instead,
 * where a dropped UDP datagram is the actual cause.
 */
class ProtocolException extends DeviceException
{
    /**
     * context()['reason'] when a write is refused because the user number is already taken
     * on the device (2.22.0). With it: 'pin' and 'table'. A host can then offer to free the
     * number instead of showing only the message (host app casebook DC-038).
     */
    public const PIN_IN_USE = 'pin_in_use';

}
