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
 * A transport that can say which reply id its last request went out with.
 *
 * WHY, 2026-11-15 (host app casebook DC-047). Over a lossy public link a READ_BUFFER window
 * sometimes goes unanswered for just over the request timeout. The 2.1.0 recovery asked for it
 * again — and on gems workshop (F18, internet) a repeated request makes the device serve that
 * window and every later one in the session 16 or 20 bytes off, so a 16,276-punch read decoded
 * 409. Knowing the request id lets the reader wait for that request's OWN late answer instead of
 * asking twice (BulkReader::awaitLateReply), and refuse datagrams that answer anything else.
 *
 * What makes it fixable is in the headers. CONFIRMED 2026-11-15, read-only, on four
 * models — F18 (gems workshop, internet, 320 windows; IT ROOM, LAN, 30), F22 (On The
 * Road, 22), UA300 (Catering, 6) — over UDP:
 *
 *   - READ_BUFFER's PREPARE_DATA reply, every DATA datagram of the window and the
 *     closing ACK_OK all carry the REQUEST's reply id;
 *   - in a DATA datagram the header's session-id field is a SEQUENCE NUMBER, 0, 1, 2 …
 *     within the window, 1,024 bytes each except the last.
 *
 * So BulkReader, given this, waits for a slow window's own answer, keeps only the current
 * request's datagrams and places each by its number (BulkReader::readNumberedWindow). Only
 * UdpTransport implements it: TCP delivers in order and retransmits, and the numbering has not
 * been seen over TCP.
 */
interface TracksRequestIds
{
    /** The reply id carried by the request most recently sent. A reply to it carries the same. */
    public function lastRequestId(): int;
}
