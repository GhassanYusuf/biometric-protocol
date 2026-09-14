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

/**
 * A transport that can hand back a chunk's payload WITHOUT building a Reply.
 *
 * ==========================================================================
 *  A SPEED CONTRACT, NOT A CONVENIENCE — MEASURED, 2026-09-13
 * ==========================================================================
 *
 * This exists for exactly one caller: BulkReader's reassembly loop. That loop is
 * the only place in the library where PHP is racing a device that has no flow
 * control, and where the cost of one datagram's bookkeeping is paid ~320 times in
 * a row. Everywhere else, a Reply is the right currency and the allocation is
 * free in context.
 *
 * WHY IT IS WORTH A SEPARATE INTERFACE. Reassembly already ignores everything a
 * Reply carries except ->data: it does not check the command, the session id or
 * the reply id of a chunk, because a bulk stream is a byte stream and the header
 * is the same on every datagram. So parsing the header into an array and wrapping
 * it in an object produces four values, discards three, and does it once per
 * kilobyte.
 *
 * MEASURED draining a 326,084-byte table in 1,024-byte datagrams, sender running
 * flat out on loopback, receive buffer at this host's 212,992-byte ceiling:
 *
 *   set timeout per poll + Packet::parse + Reply .... 67-69% of bytes captured
 *   timeout cached, still Packet::parse + Reply ..... 75-77%
 *   timeout cached, raw payload (this interface) ... 100%, 9 runs of 9
 *
 * The bytes not captured are not late, they are GONE — the kernel discarded them
 * while PHP was allocating. That is the same silent-loss failure the rest of this
 * package is built to avoid, so the fast path is not an optimisation to be traded
 * away for tidiness.
 *
 * OPTIONAL, LIKE HasReceiveBuffer. A transport that does not implement this still
 * works: BulkReader falls back to readUnsolicited() and behaves exactly as before.
 * Only implementations where a pause LOSES data have any reason to bother, which
 * in practice means datagram transports.
 */
interface SupportsRawDrain
{
    /**
     * Reads one datagram and returns its payload — the bytes after the 8-byte
     * command header — or NULL when the poll found nothing.
     *
     * The three return cases must be kept distinct, because the reassembly loop
     * reads them differently:
     *
     *   null  the poll timed out. Silence. The caller counts it toward giving up.
     *   ''    a datagram arrived carrying no payload. NOT silence — the device is
     *         still talking, so the caller's idle counter must reset.
     *   bytes the payload, appended verbatim.
     *
     * Deliberately performs NO validation of the header. Reassembly does not
     * validate it either (see the interface docblock), so validating here would
     * change behaviour rather than preserve it, and would reintroduce the per-
     * datagram cost this interface exists to remove.
     */
    public function readRawPayload(float $pollSeconds = 0.5): ?string;
}
