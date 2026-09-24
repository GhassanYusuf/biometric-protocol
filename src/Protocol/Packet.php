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

namespace Promoseven\Biometric\Protocol;

/**
 * Packet encoding and decoding — the only place in the library that knows the
 * byte layout of a request or reply.
 *
 * Wire format (little-endian throughout):
 *
 *   offset 0  uint16  command
 *   offset 2  uint16  checksum
 *   offset 4  uint16  session id   (0 on the initial CONNECT; assigned by device)
 *   offset 6  uint16  reply id     (incremented per request, wraps at USHRT_MAX)
 *   offset 8  ...     payload
 *
 * Over TCP the whole thing is additionally wrapped in an 8-byte transport header:
 * two magic uint16s (0x5050, 0x7d82) then a uint32 length, all little-endian.
 * CONFIRMED against real hardware: the F18-class device also speaks this protocol
 * directly over UDP datagrams — one packet per datagram, no wrapper — so
 * UdpTransport never wraps; TcpTransport does.
 */
final class Packet
{
    /**
     * The two little-endian uint16 magic words that open the 8-byte TCP frame.
     *
     * CONFIRMED against real hardware (F22 @ 192.168.7.63, 2026-09-14): BOTH words
     * are required. A frame sent with the second word zeroed is rejected — the
     * device closes the connection without a reply. These are pyzk's
     * MACHINE_PREPARE_DATA_1 (0x5050) and _2 (0x7d82).
     */
    public const TCP_MAGIC = 0x5050;

    public const TCP_MAGIC_2 = 0x7d82;

    private function __construct()
    {
    }

    /**
     * Builds a request packet, including the protocol's checksum.
     *
     * The checksum is computed over the body with the checksum field zeroed, then
     * spliced in — which is why the body is packed twice here.
     *
     * @return array{0:string,1:int} [rawPacket, nextReplyId]
     */
    public static function build(int $command, int $sessionId, int $replyId, string $data = ''): array
    {
        $body = pack('v4', $command, 0, $sessionId, $replyId) . $data;
        $checksum = self::checksum($body);

        $replyId++;
        if ($replyId >= Command::USHRT_MAX) {
            $replyId -= Command::USHRT_MAX;
        }

        $packet = pack('v4', $command, $checksum, $sessionId, $replyId) . $data;

        return [$packet, $replyId];
    }

    /**
     * Parses the 8-byte command header at the start of a reply.
     *
     * @return array{command:int,checksum:int,sessionId:int,replyId:int,data:string}
     */
    public static function parse(string $payload): array
    {
        $header = unpack('vcommand/vchecksum/vsessionId/vreplyId', substr($payload, 0, 8));

        return [
            'command' => $header['command'],
            'checksum' => $header['checksum'],
            'sessionId' => $header['sessionId'],
            'replyId' => $header['replyId'],
            'data' => substr($payload, 8),
        ];
    }

    /** Wraps a command packet in the 8-byte TCP transport header. */
    public static function wrapTcp(string $packet): string
    {
        return pack('vvV', self::TCP_MAGIC, self::TCP_MAGIC_2, strlen($packet)) . $packet;
    }

    /**
     * Strips the TCP transport header from bytes read off a stream socket.
     *
     * @return array{0:int,1:string} [declaredPayloadLength, remainingBytes]
     */
    public static function unwrapTcp(string $chunk): array
    {
        if (strlen($chunk) < 8) {
            return [0, $chunk];
        }

        $header = unpack('vmagic/vreserved/Vlength', substr($chunk, 0, 8));

        return [$header['length'], substr($chunk, 8)];
    }

    /**
     * The protocol's checksum: a 16-bit ones'-complement-style sum, mirroring the
     * algorithm every known ZK client library uses.
     */
    public static function checksum(string $payload): int
    {
        $length = strlen($payload);
        $checksum = 0;
        $i = 0;

        while ($length > 1) {
            $word = ord($payload[$i]) | (ord($payload[$i + 1]) << 8);
            $checksum += $word;
            if ($checksum > Command::USHRT_MAX) {
                $checksum -= Command::USHRT_MAX;
            }
            $i += 2;
            $length -= 2;
        }

        if ($length === 1) {
            $checksum += ord($payload[$i]);
        }

        while ($checksum > Command::USHRT_MAX) {
            $checksum -= Command::USHRT_MAX;
        }

        $checksum = ~$checksum;
        while ($checksum < 0) {
            $checksum += Command::USHRT_MAX;
        }

        return $checksum & Command::USHRT_MAX;
    }

    /**
     * The standard ZK "comm key" scrambling algorithm, as documented by
     * long-standing open-source ZK implementations.
     *
     * CONFIRMED working against real hardware with commKey = 0 (comm key
     * disabled). Non-zero keys follow the same published algorithm but have not
     * been exercised in this project — see docs/protocol-overview.md.
     */
    public static function makeCommKey(int $key, int $sessionId, int $ticks = 50): string
    {
        $k = 0;
        for ($i = 0; $i < 32; $i++) {
            $k = (($key & (1 << $i)) ? (($k << 1) | 1) : ($k << 1)) & 0xFFFFFFFF;
        }
        $k = ($k + $sessionId) & 0xFFFFFFFF;

        $b = array_values(unpack('C4', pack('V', $k)));
        $xored = [$b[0] ^ 0x5A, $b[1] ^ 0x4B, $b[2] ^ 0x53, $b[3] ^ 0x4F]; // 'Z','K','S','O'
        $h = array_values(unpack('v2', pack('C4', ...$xored)));
        $swapped = array_values(unpack('C4', pack('v2', $h[1], $h[0])));

        $B = $ticks & 0xFF;

        return pack('C4', $swapped[0] ^ $B, $swapped[1] ^ $B, $B, $swapped[3] ^ $B);
    }

    /**
     * A user record with only its user id replaced — every other byte (password,
     * group, time zones, card, privilege, uid) exactly as the device had it.
     *
     * Patching the device's own record, rather than rebuilding one from decoded
     * fields, is deliberate: UserCodec does not decode the password or the time-zone
     * block, and a rebuilt record would silently reset them.
     *
     * Only the documented 9-byte id field at offset 48 is written. pyzk writes 24
     * bytes there; bytes 57..71 have read as zero on every F18 record, but whether
     * they are the id's tail is unresolved (docs/device-capabilities.md), so they are
     * carried over as read rather than overwritten on a guess.
     */
    public static function withUserId(string $record, string $userId): string
    {
        if (strlen($record) !== 72) {
            throw new \InvalidArgumentException('A user record is 72 bytes, got ' . strlen($record) . '.');
        }
        if (strlen($userId) < 1 || strlen($userId) > 9) {
            throw new \InvalidArgumentException("A user id is 1 to 9 bytes, got '{$userId}'.");
        }

        return substr_replace($record, str_pad($userId, 9, "\0"), 48, 9);
    }

    /**
     * The buffer SAVE_USERTEMPS commits: one user record plus their templates.
     *
     * TRANSCRIBED LITERALLY from fananimi/pyzk zk/base.py `HR_save_usertemplates`
     * (commit f29709c1), so that a mismatch on hardware is a finding about the
     * device and not about our arithmetic:
     *
     *   head   = pack("III", len(upack), len(table), len(fpack))    12 bytes
     *   upack  = 0x02 + the 72-byte user record                      73 bytes (User.repack73)
     *   table  = per template pack("<bHbI", 2, uid, 0x10 + fid, tstart)   8 bytes each
     *   fpack  = per template pack("<H%is", len(template), template)
     *
     * `tstart` is the offset of that template inside fpack. pyzk writes 0x10 + slot
     * and does NOT carry the record's `valid` byte; the meaning of 0x10 is not stated
     * there. That is transcribed as-is and is one of the things the first hardware
     * run must settle (docs/device-capabilities.md).
     *
     * EXPERIMENTAL — never run against hardware in this project.
     *
     * @param list<array{fid:int,template:string}> $templates
     */
    public static function buildUserTemplatesUpload(string $record, array $templates): string
    {
        if (strlen($record) !== 72) {
            throw new \InvalidArgumentException('A user record is 72 bytes, got ' . strlen($record) . '.');
        }

        $uid = unpack('v', substr($record, 0, 2))[1];
        $upack = "\x02" . $record;
        $table = '';
        $fpack = '';

        foreach ($templates as $t) {
            $fid = (int) $t['fid'];
            if ($fid < 0 || $fid > 9) {
                throw new \InvalidArgumentException("Finger slot must be 0-9, got {$fid}.");
            }
            $table .= pack('C', 2) . pack('v', $uid) . pack('C', 0x10 + $fid) . pack('V', strlen($fpack));
            $fpack .= pack('v', strlen($t['template'])) . $t['template'];
        }

        return pack('V3', strlen($upack), strlen($table), strlen($fpack)) . $upack . $table . $fpack;
    }

    /** SAVE_USERTEMPS payload, transcribed from pyzk: pack('<IHH', 12, 0, 8). */
    public static function buildSaveUserTemplatesRequest(): string
    {
        return pack('V', 12) . pack('v', 0) . pack('v', 8);
    }

    /**
     * Builds a 72-byte user record for USER_WRQ.
     *
     * Field layout per the documented ZK protocol (adrobinoga/zk-protocol, "Set
     * User Info"): uid(2)@0, permission(1)@2, password(8)@3, name(24)@11,
     * card(4)@35, group(1)@39, user-tz-flag(2)@40, tz1/tz2/tz3(2 each)@42/44/46,
     * user id(9)@48, zeros(15)@57.
     *
     * CONFIRMED: group must be >= 1 — the device rejects writes with group 0.
     */
    public static function buildUserRecord(
        int $uid,
        string $userId,
        string $name,
        int $privilege = 0,
        int $cardNumber = 0,
        int $group = 1,
    ): string {
        $record = str_repeat("\0", 72);
        $record = substr_replace($record, pack('v', $uid), 0, 2);
        $record = substr_replace($record, chr($privilege & 0xFF), 2, 1);
        $record = substr_replace($record, str_pad(substr($name, 0, 24), 24, "\0"), 11, 24);
        $record = substr_replace($record, pack('V', $cardNumber), 35, 4);
        $record = substr_replace($record, chr($group & 0xFF), 39, 1);
        $record = substr_replace($record, str_pad(substr($userId, 0, 9), 9, "\0"), 48, 9);

        return $record;
    }

    /**
     * Payload for START_ENROLL.
     *
     * 26-byte structure per the documented protocol: user id (9 bytes) + zero
     * padding to offset 24 + finger slot (1 byte) + fingerprint flag (1 byte,
     * 1 = valid fingerprint). CONFIRMED against real hardware.
     *
     * The user id is truncated to 9 bytes deliberately — that is the device's own
     * field width, the same one buildUserRecord() writes at offset 48.
     */
    public static function buildEnrollRequest(string $userId, int $fingerIndex): string
    {
        $record = str_repeat("\0", 26);
        $record = substr_replace($record, str_pad(substr($userId, 0, 9), 9, "\0"), 0, 9);
        $record = substr_replace($record, chr($fingerIndex & 0xFF), 24, 1);
        $record = substr_replace($record, chr(1), 25, 1);

        return $record;
    }

    /**
     * Acknowledgement for an unsolicited realtime push.
     *
     * CONFIRMED: these are acknowledged with a bare ACK_OK carrying reply number
     * 0, not the usual incrementing counter.
     */
    public static function buildRealtimeAck(int $sessionId): string
    {
        $body = pack('v4', Command::ACK_OK, 0, $sessionId, 0);

        return pack('v4', Command::ACK_OK, self::checksum($body), $sessionId, 0);
    }
}
