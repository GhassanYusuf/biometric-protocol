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

namespace Promoseven\Biometric\C3\Protocol;

use Promoseven\Biometric\C3\Transport\C3TcpTransport;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Value\Progress;

/**
 * The staged read: PREPARE_DATA (0x0D) -> DATA (0x0E)* -> FREE_DATA (0x0F).
 *
 * GET_DATA on a populated table does not answer with rows. It answers with a
 * 17-byte staging header, and the rows are then pulled a chunk at a time. These
 * three are the standalone family's 1500/1501/1502 renumbered for the panel
 * dialect, and no public C3 reimplementation carries this path — vwout/zkaccess-c3-py
 * and -lua both handle only the inline REPLY_OK case, which is why neither can read
 * a table that has anything in it.
 *
 * Recovered 2026-09-14 from the vendor's own plcommpro.dll (ZKAccess 3.5.5):
 * dispatch at 0x10002be0, pull loop at 0x100029b0, cross-checked against the
 * managed DevComm layer, then verified byte for byte against live captures from
 * an inBIO460 and a TF1700.
 *
 * THE HEADER, 17 bytes, little-endian, packed, no padding:
 *
 *   offset 0   1 byte   compression flag, 0 = raw
 *   offset 1   4 bytes  datalen     bytes staged on the device
 *   offset 5   4 bytes  oriLen      length after decompression
 *   offset 9   4 bytes  crc32       CRC-32/ISO-HDLC over the assembled payload
 *   offset 13  4 bytes  packageLen  most the device will put in one reply
 *
 * THE CRC IS THE POINT. It makes this read self-verifying: a pull loop that is
 * wrong produces a checksum mismatch rather than a plausible half-table. That is
 * rule 10 enforced by the protocol itself, and it is why this code can return
 * "would not read" instead of quietly returning fewer rows than the device holds.
 */
final class BufferedReader
{
    /**
     * Guards against a device that never advances. Sized from the worst real case
     * seen (337 chunks for a 1.7 MB table) with room for an order of magnitude.
     */
    private const MAX_CHUNKS = 20000;

    public function __construct(private readonly C3TcpTransport $transport) {}

    /** True when this reply is a staging header rather than inline rows. */
    public static function isStaged(int $replyCode): bool
    {
        return $replyCode === Command::REPLY_PREPARE_DATA;
    }

    /**
     * @return array{flag:int, datalen:int, oriLen:int, checksum:int, packageLen:int}
     */
    public static function parseHeader(string $payload): array
    {
        if (strlen($payload) < 17) {
            throw new ProtocolException(
                'C3 staging header is '.strlen($payload).' bytes, expected 17. '
                .'Refusing to guess at the staged size.',
            );
        }

        /** @var array{flag:int, datalen:int, oriLen:int, checksum:int, packageLen:int} $header */
        $header = unpack('Cflag/Vdatalen/VoriLen/Vchecksum/VpackageLen', substr($payload, 0, 17));

        return $header;
    }

    /**
     * Pulls the whole staged payload and verifies it.
     *
     * FREE_DATA is sent on every exit path, success or failure, exactly as the
     * vendor SDK does from all five of its own exits: the staging area is device
     * memory and holding it starves the next read.
     *
     * @param  ?callable(Progress):void  $onProgress
     */
    public function pull(string $stagingHeader, string $operation = 'table', ?callable $onProgress = null): string
    {
        $header = self::parseHeader($stagingHeader);

        try {
            $data = $this->pullChunks($header, $operation, $onProgress);
        } finally {
            // Never let a failure to release mask the real error.
            try {
                $this->transport->send(Command::BUFFER_FREE, '', 6.0);
            } catch (\Throwable) {
                // The panel drops the buffer when the socket closes anyway.
            }
        }

        if ($header['flag'] !== 0) {
            // The compressor lives in a plce.dll the vendor does not ship with the
            // SDK, and neither panel here has ever answered with a non-zero flag.
            // Saying so is better than returning bytes we have not decompressed.
            throw new ProtocolException(
                "This panel staged a COMPRESSED payload (flag {$header['flag']}), which this library "
                .'cannot decompress. No panel seen so far does this; please report the model and firmware.',
            );
        }

        if (strlen($data) !== $header['datalen']) {
            throw new ProtocolException(sprintf(
                'Staged read incomplete: got %d of %d bytes.',
                strlen($data),
                $header['datalen'],
            ));
        }

        if (crc32($data) !== $header['checksum']) {
            throw new ProtocolException(sprintf(
                'Staged read failed its checksum: device declared CRC-32 %08x, assembled %08x. '
                .'The data is NOT usable and is being discarded rather than decoded.',
                $header['checksum'],
                crc32($data),
            ));
        }

        return $data;
    }

    /**
     * @param  array{flag:int, datalen:int, oriLen:int, checksum:int, packageLen:int}  $header
     * @param  ?callable(Progress):void  $onProgress
     */
    private function pullChunks(array $header, string $operation, ?callable $onProgress): string
    {
        $data = '';
        $offset = 0;
        $chunks = 0;

        while ($offset < $header['datalen']) {
            if (++$chunks > self::MAX_CHUNKS) {
                throw new ProtocolException(
                    "Staged read did not finish within ".self::MAX_CHUNKS." chunks; abandoning at {$offset} bytes.",
                );
            }

            // The request is the offset and NOTHING else. No length, no token, no
            // echo of the header: packageLen is never transmitted, because the
            // device chooses the chunk size and the client only says where to start.
            [$reply, $payload] = $this->transport->send(Command::BUFFER_READ, pack('V', $offset), 20.0);

            if ($reply !== Command::REPLY_OK) {
                throw new ProtocolException(sprintf(
                    'Staged read refused at offset %d with reply 0x%02X%s.',
                    $offset,
                    $reply,
                    $reply === Command::REPLY_ERROR
                        ? ': '.Command::describeError(Frame::errorCode($payload))
                        : '',
                ));
            }

            if (strlen($payload) < 4) {
                throw new ProtocolException("Staged read returned an empty chunk at offset {$offset}.");
            }

            // The first four bytes echo the offset we asked for. The vendor SDK
            // treats a mismatch as fatal (its error -109) and so do we: a silently
            // misordered buffer is worse than no buffer at all.
            $echo = unpack('V', substr($payload, 0, 4))[1];

            if ($echo !== $offset) {
                throw new ProtocolException(
                    "Staged read went out of order: asked for offset {$offset}, device answered {$echo}.",
                );
            }

            $chunk = substr($payload, 4);

            if ($chunk === '') {
                throw new ProtocolException("Staged read stalled with no data at offset {$offset}.");
            }

            $data .= $chunk;
            // Advanced by bytes ACTUALLY received, never by a fixed step: the
            // offset is a running byte count and not a chunk index.
            $offset += strlen($chunk);

            if ($onProgress !== null) {
                $onProgress(new Progress($operation, $offset, $header['datalen']));
            }
        }

        return $data;
    }
}
