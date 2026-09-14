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

namespace Promoseven\Biometric\Contracts;

use Promoseven\Biometric\Value\Progress;

/**
 * Receives progress while a bulk transfer is reassembling.
 *
 * An interface rather than a bare callable so an implementation can hold state —
 * throttling, a last-emitted timestamp, a database row — without the library
 * caring what any of that is. It stays framework-agnostic: this package never
 * knows whether the other end is a Laravel model, a CLI progress bar, or nothing.
 *
 * CONTRACT FOR IMPLEMENTERS:
 *
 *  - onProgress() is called ONCE PER CHUNK. A 400 KB attendance table arrives in
 *    hundreds of chunks, so an implementation that writes to a database or a
 *    socket on every call will cost more than the transfer it is measuring.
 *    THROTTLE. See App\Services\Devices\SyncProgressRecorder for how.
 *
 *  - It MUST NOT throw. Reporting progress is an aside; a listener that throws
 *    would fail a read that was working. BulkReader swallows what escapes, but do
 *    not rely on that to hide a broken implementation.
 *
 *  - It MUST NOT be slow. It runs inside the reassembly loop, between polls, on
 *    the same thread as the socket reads.
 */
interface ProgressListener
{
    public function onProgress(Progress $progress): void;
}
