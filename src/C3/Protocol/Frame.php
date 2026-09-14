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

use Promoseven\Biometric\Exception\ProtocolException;

/**
 * The C3 wire frame, and its checksum.
 *
 * LAYOUT
 *   AA 01 <cmd> <len_lo> <len_hi> [ses_lo ses_hi req_lo req_hi] <data...> <crc_lo> <crc_hi> 55
 *
 * The four session bytes are present only when the panel accepted a session. The
 * inBIO460 refuses both connect forms and runs entirely without them; the TF1700
 * accepts one. That difference is a PROPERTY OF THE MODEL and is decided once, by
 * the model class, never by a conditional in here (rule 15).
 *
 * The declared length counts the session bytes and the data, but NOT the version,
 * command or length bytes themselves, and not the CRC or the end byte.
 */
final class Frame
{
    /**
     * CRC-16/ARC — polynomial 0xA001 (reflected 0x8005), initial value 0x0000, no
     * final XOR, computed over every byte between the start and the CRC itself.
     *
     * Transcribed literally from vwout/zkaccess-c3-py rather than derived from a
     * generic CRC table, per rule 17: when a panel disagrees with us the difference
     * must be a fact about the panel, not an error in our arithmetic.
     *
     * NOTE this is NOT the checksum that guards a staged payload. A buffered read
     * is additionally covered by a CRC-32/ISO-HDLC carried in the PREPARE_DATA
     * header — a second, independent check at a different layer. See BufferedReader.
     *
     * @param  list<int>  $bytes
     */
    public static function crc(array $bytes): int
    {
        $crc = 0x0000;

        foreach ($bytes as $byte) {
            $value = ($crc & 0xFF) ^ ($byte & 0xFF);
            $poly = 0;

            for ($i = 0; $i < 8; $i++) {
                $poly = (($poly ^ $value) & 1) === 1
                    ? (($poly >> 1) ^ 0xA001)
                    : ($poly >> 1);

                $value >>= 1;
            }

            $crc = (($crc >> 8) & 0xFF) ^ $poly;
        }

        return $crc & 0xFFFF;
    }

    /** Builds one frame ready for the wire. */
    public static function build(
        int $command,
        string $data = '',
        ?int $sessionId = null,
        int $requestNr = 0,
    ): string {
        $payload = array_values(unpack('C*', $data) ?: []);
        $withSession = $sessionId !== null;
        $length = count($payload) + ($withSession ? 4 : 0);

        $body = [
            Command::VERSION,
            $command & 0xFF,
            $length & 0xFF,
            ($length >> 8) & 0xFF,
        ];

        if ($withSession) {
            $body[] = $sessionId & 0xFF;
            $body[] = ($sessionId >> 8) & 0xFF;
            $body[] = $requestNr & 0xFF;
            $body[] = ($requestNr >> 8) & 0xFF;
        }

        $body = [...$body, ...$payload];
        $crc = self::crc($body);

        return pack('C*', Command::START, ...$body, ...[$crc & 0xFF, ($crc >> 8) & 0xFF, Command::END]);
    }

    /**
     * Splits a received frame into its reply code and payload.
     *
     * $hasSession must match what was SENT: a session-less reply carries no session
     * prefix to strip, and stripping four bytes that are not there silently shifts
     * every field in the payload. That is the kind of error that produces rows which
     * look real and are not, so it is checked rather than guessed.
     *
     * @return array{command:int, payload:string}
     */
    public static function parse(string $header, string $rest, bool $hasSession): array
    {
        if (strlen($header) < 5) {
            throw new ProtocolException('C3 reply truncated: '.strlen($header).' header bytes, expected 5.');
        }

        $bytes = array_values(unpack('C*', $header));

        if ($bytes[0] !== Command::START) {
            throw new ProtocolException(sprintf('C3 reply does not start with 0xAA (got 0x%02X).', $bytes[0]));
        }

        $command = $bytes[2];
        $size = $bytes[3] + ($bytes[4] * 256);
        $payload = substr($rest, 0, $size);

        if ($hasSession) {
            $payload = strlen($payload) > 4 ? substr($payload, 4) : '';
        }

        return ['command' => $command, 'payload' => $payload];
    }

    /**
     * The negative code inside an error reply.
     *
     * The panel answers a refusal with a well-formed frame whose payload is a signed
     * little-endian integer. A well-formed error is the device TALKING to you
     * (rule 17) — it is how the session-less path was found — so it is decoded
     * rather than collapsed into a generic failure.
     */
    public static function errorCode(string $payload): int
    {
        if (strlen($payload) < 4) {
            return 0;
        }

        $value = unpack('V', substr($payload, 0, 4))[1];

        return $value >= 0x80000000 ? $value - 0x100000000 : $value;
    }
}
