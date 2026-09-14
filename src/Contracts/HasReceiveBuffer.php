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
 * A transport that can say how much the OS will hold for it while nobody reads.
 *
 * Separate from Transport because it is a datagram concern. A stream transport has
 * flow control and needs no such question; a fixture transport reading from disk
 * has no answer to give. Only implementations where a pause can LOSE data need to
 * report headroom, so only those implement this.
 *
 * BulkReader uses it to decide how often it may report progress: with enough
 * headroom to hold the whole transfer it can report per chunk, and without it must
 * wait for proven silence. See BulkReader::emit().
 */
interface HasReceiveBuffer
{
    /**
     * Bytes the OS will buffer for this socket, or NULL when it cannot be
     * determined.
     *
     * USABLE BYTES, NOT THE RAW SO_RCVBUF READBACK. Implementations must correct
     * for platform before returning: Linux stores and reports twice what it will
     * actually let you fill, and an implementation that forwards that number
     * unchanged tells callers they may pause when they may not. See
     * UdpTransport::usableFromGranted().
     *
     * Null must be read as "assume none" — the safe direction. It is what a build
     * without ext-sockets reports, and guessing generously there is how datagrams
     * get dropped. When in doubt, under-report: the cost is a coarser progress
     * bar, and the cost of over-reporting is a failed transfer.
     */
    public function receiveBufferBytes(): ?int;
}
