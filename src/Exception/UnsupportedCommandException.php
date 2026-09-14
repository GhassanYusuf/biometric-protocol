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
 * The device or its firmware does not implement this operation.
 *
 * Thrown instead of returning a plausible-looking empty result, so a caller can
 * never mistake "this firmware cannot tell me" for "there is nothing there".
 * Surface it to the UI as a disabled action, not as an error.
 */
class UnsupportedCommandException extends DeviceException
{
}
