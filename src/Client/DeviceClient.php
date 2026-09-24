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

namespace Promoseven\Biometric\Client;

use Promoseven\Biometric\Codec\RecordBuffer;
use Promoseven\Biometric\Codec\Timestamp;
use Promoseven\Biometric\Exception\ConnectionException;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Protocol\Command;
use Promoseven\Biometric\Protocol\Packet;
use Promoseven\Biometric\Session\Session;
use Promoseven\Biometric\Contracts\ProgressListener;
use Promoseven\Biometric\Transport\BulkReader;
use Promoseven\Biometric\Transport\TcpTransport;
use Promoseven\Biometric\Transport\UdpTransport;
use Promoseven\Biometric\Value\DeviceConfig;
use Promoseven\Biometric\Value\Reply;

/**
 * Low-level command surface for one device: raw table reads, raw writes, device
 * info, realtime subscription.
 *
 * This class speaks commands and bytes. It does NOT interpret record tables
 * (that's Codec/) and does NOT orchestrate multi-step workflows (that's Service/).
 * Keeping those apart is what lets a caller decode a captured table with no device
 * present, and what lets a new firmware variant be supported by swapping a codec.
 *
 * Two disciplines are enforced here and must not be relaxed:
 *
 *  1. Every bulk read runs on a FRESH session (delegated to BulkReader).
 *  2. Every write is followed by REFRESH_DATA, and callers must read back and
 *     confirm. This firmware family ACKs writes it then silently drops.
 */
class DeviceClient
{
    private ?BulkReader $bulkReader = null;

    private ?ProgressListener $progress = null;

    public function __construct(private readonly Session $session)
    {
    }

    /**
     * Attaches a listener that receives byte counts while bulk tables stream in.
     *
     * Optional by design: every existing caller keeps working untouched and pays
     * nothing, because BulkReader::emit() returns immediately when this is null.
     *
     * Must be set BEFORE the first bulk read — the reader is built once and cached,
     * so attaching afterwards would silently do nothing. Setting it discards any
     * cached reader so the listener always takes effect.
     */
    public function onProgress(?ProgressListener $listener): self
    {
        $this->progress = $listener;
        $this->bulkReader = null;

        return $this;
    }

    /** Convenience constructor for the common single-device case. */
    public static function connect(DeviceConfig $config): self
    {
        $transport = $config->usesTcp() ? new TcpTransport($config) : new UdpTransport($config);
        $session = new Session($transport, $config);
        $session->open();

        return new self($session);
    }

    public function config(): DeviceConfig
    {
        return $this->session->config();
    }

    public function session(): Session
    {
        return $this->session;
    }

    public function disconnect(): void
    {
        $this->session->close();
    }

    /**
     * Opens a session, runs the callback, always closes.
     *
     * The idiomatic entry point — leaking a session leaves the device holding a
     * conversation it will not free until it times out.
     */
    public static function run(DeviceConfig $config, \Closure $callback): mixed
    {
        $client = self::connect($config);

        try {
            return $callback($client);
        } finally {
            $client->disconnect();
        }
    }

    // ---------------------------------------------------------------- liveness

    /**
     * Round-trips a cheap command to prove the device is reachable and answering.
     *
     * Uses GET_TIME rather than a bare CONNECT so a "healthy" verdict means the
     * device is actually serving commands, not merely completing a handshake.
     *
     * @return array{alive:bool, device_time:?\DateTimeImmutable, latency_ms:float}
     */
    public function ping(): array
    {
        $startedAt = microtime(true);
        $time = $this->getTime();

        return [
            'alive' => true,
            'device_time' => $time,
            'latency_ms' => round((microtime(true) - $startedAt) * 1000, 1),
        ];
    }

    public function getTime(): ?\DateTimeImmutable
    {
        $reply = $this->send(Command::GET_TIME);

        if ($reply->length() < 4) {
            return null;
        }

        return Timestamp::decode(
            unpack('V', substr($reply->data, 0, 4))[1],
            $this->config()->timezone,
        );
    }

    /**
     * Sets the device clock.
     *
     * DOCUMENTED, not exercised against hardware here. The device stamps punches
     * with this clock, so a wrong value silently corrupts every future timestamp —
     * callers should read the time back and compare before trusting it.
     */
    public function setTime(\DateTimeInterface $time): void
    {
        $reply = $this->send(Command::SET_TIME, pack('V', Timestamp::encode($time)));

        if (! $reply->isAccepted()) {
            throw new ProtocolException("Device rejected the time write ({$reply->commandName()}).");
        }

        $this->refreshData();
    }

    // ------------------------------------------------------------- device info

    /**
     * Free-text device info fields. Each is a separate command; a firmware that
     * does not implement one returns empty rather than failing the whole read.
     *
     * @return array{firmware:string, serial:string, platform:string, free_sizes:string, device_time:?\DateTimeImmutable}
     */
    public function getDeviceInfo(): array
    {
        return [
            'firmware' => $this->safeString(fn () => $this->send(Command::VERSION)->data),
            'serial' => $this->safeString(fn () => $this->deviceParameter('~SerialNumber')),
            'platform' => $this->safeString(fn () => $this->deviceParameter('~Platform')),
            'device_name' => $this->safeString(fn () => $this->deviceParameter('~DeviceName')),
            'mac' => $this->safeString(fn () => $this->deviceParameter('MAC')),
            'free_sizes' => $this->safeString(fn () => $this->send(Command::GET_FREE_SIZES)->data),
            'device_time' => $this->getTime(),
        ];
    }

    /**
     * Reads one named device parameter via CMD_DEVICE.
     *
     * The device answers "Name=Value"; we return just the value.
     */
    public function deviceParameter(string $name): string
    {
        $reply = $this->send(Command::DEVICE, $name);
        $value = RecordBuffer::cString($reply->data);

        $equals = strpos($value, '=');

        return $equals === false ? trim($value) : trim(substr($value, $equals + 1));
    }

    // --------------------------------------------------------------- raw reads

    /** Raw bytes of the user table. */
    public function readUsersRaw(): string
    {
        return $this->bulk()->read(Command::USERTEMP_RRQ, operation: 'users');
    }

    /** Raw bytes of the attendance table. */
    public function readAttendanceRaw(): string
    {
        return $this->bulk()->read(Command::ATTLOG_RRQ, operation: 'attendance');
    }

    /**
     * Raw bytes of the fingerprint-template table.
     *
     * CONFIRMED framing: DB_RRQ with a single-byte FCT_FINGERTMP selector. The
     * device answers PREPARE_DATA with the total size (22,066 bytes observed) and
     * then streams chunks.
     */
    public function readTemplatesRaw(): string
    {
        return $this->bulk()->read(Command::DB_RRQ, pack('C', Command::FCT_FINGERTMP), 'templates');
    }

    /**
     * Probes whether ONE specific template slot holds data.
     *
     * CONFIRMED: PREPARE_DATA (with the template's byte size) when the slot is
     * filled, error 4993 when empty. This is the independent cross-check that
     * validated the bulk table decoder.
     *
     * @return array{exists:bool, size:int, reply:int}
     */
    public function probeTemplateSlot(int $uid, int $fingerIndex): array
    {
        $reply = $this->send(Command::USERTEMP_RRQ, pack('v', $uid) . pack('C', $fingerIndex));

        $exists = $reply->isPreparingData() || $reply->isInlineData();

        /*
         * A filled slot answers PREPARE_DATA — meaning the device now starts
         * streaming the template we are not going to read. send() has already
         * marked the session dirty for us, so the next command reopens rather than
         * reading this template's chunks as its own reply.
         *
         * Without that, probing slots 0/3/6/7 in sequence returned answers shifted
         * by one request on real hardware.
         */
        return [
            'exists' => $exists,
            'size' => $reply->isPreparingData() ? $reply->declaredSize() : $reply->length(),
            'reply' => $reply->command,
        ];
    }

    // -------------------------------------------------------------- raw writes

    /**
     * Writes (creates or updates) a user record.
     *
     * CONFIRMED: the device must be DISABLED around the write and told to
     * REFRESH_DATA afterwards — writes were being silently rejected without this
     * exact sequence.
     *
     * Callers MUST read back and confirm. This method reports what the device
     * accepted, which is not the same as what it kept.
     */
    public function writeUser(
        int $uid,
        string $userId,
        string $name,
        int $privilege = 0,
        int $cardNumber = 0,
    ): void {
        $this->withDeviceDisabled(function () use ($uid, $userId, $name, $privilege, $cardNumber) {
            $reply = $this->send(
                Command::USER_WRQ,
                Packet::buildUserRecord($uid, $userId, $name, $privilege, $cardNumber),
            );

            if (! $reply->isAccepted()) {
                throw new ProtocolException("Device rejected the user write ({$reply->commandName()}).", [
                    'uid' => $uid,
                    'user_id' => $userId,
                ]);
            }
        });
    }

    /** Deletes an entire user record — takes their templates and card with it. */
    public function deleteUser(int $uid): void
    {
        $this->withDeviceDisabled(function () use ($uid) {
            $reply = $this->send(Command::DELETE_USER, pack('v', $uid));

            if (! $reply->isAccepted()) {
                throw new ProtocolException("Device rejected the user delete ({$reply->commandName()}).", [
                    'uid' => $uid,
                ]);
            }
        });
    }

    /**
     * Writes one user record AND their fingerprint templates in a single commit.
     *
     * Sequence transcribed from fananimi/pyzk zk/base.py (commit f29709c1):
     * `_send_with_buffer` (FREE_DATA, PREPARE_DATA with the uint32 size, then DATA
     * in 1,024-byte chunks, each acknowledged) followed by SAVE_USERTEMPS and
     * REFRESH_DATA. Run with the device disabled, as every write here is — that part
     * is CONFIRMED necessary for USER_WRQ on the F18 and assumed to apply here.
     *
     * EXPERIMENTAL — never run against hardware in this project. Callers MUST read
     * back: this reports what the device accepted, not what it kept.
     *
     * @param string                                  $record    72-byte user record
     * @param list<array{fid:int,template:string}>    $templates
     */
    public function saveUserWithTemplates(string $record, array $templates): void
    {
        $buffer = Packet::buildUserTemplatesUpload($record, $templates);

        $this->withDeviceDisabled(function () use ($buffer) {
            $this->sendBuffer($buffer);

            $reply = $this->send(Command::SAVE_USERTEMPS, Packet::buildSaveUserTemplatesRequest());

            if (! $reply->isAccepted()) {
                throw new ProtocolException("Device rejected the user+template save ({$reply->commandName()}).", [
                    'bytes' => strlen($buffer),
                ]);
            }
        });
    }

    /** pyzk `_send_with_buffer`: stage $buffer on the device for the next command. */
    private function sendBuffer(string $buffer): void
    {
        // Clears any staged buffer. Not checked: with nothing staged some firmware
        // answers ACK_ERROR, which says nothing about the upload that follows.
        $this->send(Command::FREE_DATA);

        $reply = $this->send(Command::PREPARE_DATA, pack('V', strlen($buffer)));
        if (! $reply->isAccepted()) {
            throw new ProtocolException("Device refused to prepare for {$reply->commandName()} upload.", [
                'bytes' => strlen($buffer),
            ]);
        }

        foreach (str_split($buffer, 1024) as $i => $chunk) {
            $reply = $this->send(Command::DATA, $chunk);
            if (! $reply->isAccepted()) {
                throw new ProtocolException("Device refused upload chunk {$i} ({$reply->commandName()}).", [
                    'bytes' => strlen($buffer),
                    'chunk' => $i,
                ]);
            }
        }
    }

    /**
     * Deletes ONE fingerprint template, keeping the user and their other fingers.
     *
     * EXPERIMENTAL: DELETE_USERTEMP with (uint16 uid, uint8 slot). The command and
     * payload follow the documented protocol and the guard rails around it are
     * verified, but a successful delete has not been observed on hardware in this
     * project — deleting a real person's finger was not an acceptable test.
     */
    public function deleteTemplate(int $uid, int $fingerIndex): void
    {
        if ($fingerIndex < 0 || $fingerIndex > 9) {
            throw new \InvalidArgumentException("Finger slot must be 0-9, got {$fingerIndex}.");
        }

        $this->withDeviceDisabled(function () use ($uid, $fingerIndex) {
            $reply = $this->send(
                Command::DELETE_USERTEMP,
                pack('v', $uid) . pack('C', $fingerIndex),
            );

            if (! $reply->isAccepted()) {
                throw new ProtocolException("Device rejected the fingerprint delete ({$reply->commandName()}).", [
                    'uid' => $uid,
                    'slot' => $fingerIndex,
                ]);
            }
        });
    }

    /**
     * Deletes ALL attendance records.
     *
     * Irreversible on the device and never called by any sync flow. Exposed only
     * for explicit, deliberate operator action.
     */
    public function clearAttendanceLog(): void
    {
        $reply = $this->send(Command::CLEAR_ATTLOG);

        if (! $reply->isAccepted()) {
            throw new ProtocolException("Device rejected the attendance clear ({$reply->commandName()}).");
        }

        $this->refreshData();
    }

    /**
     * Reboots the device.
     *
     * DOCUMENTED, never exercised here. Drops the session and any in-flight
     * transfer; the device is unreachable for however long it takes to come back.
     */
    public function restart(): void
    {
        $this->send(Command::RESTART);
        $this->session->transport()->close();
    }

    // ----------------------------------------------------------------- signals

    /**
     * Makes the device play its confirmation sound.
     *
     * CONFIRMED. Used as audible proof that a remote trigger actually reached the
     * unit — without it, someone standing at the terminal has no idea the system is
     * waiting for them.
     */
    public function beep(): void
    {
        $this->send(Command::TEST_VOICE, pack('V', 0));
    }

    public function enableDevice(): void
    {
        $this->send(Command::ENABLE_DEVICE);
    }

    public function disableDevice(): void
    {
        $this->send(Command::DISABLE_DEVICE);
    }

    /**
     * Tells the device to reload its data tables.
     *
     * CONFIRMED REQUIRED: this firmware acknowledges writes immediately but does
     * not commit them until told to reload. Writes reported success and did not
     * appear in a subsequent read without this call.
     */
    public function refreshData(): void
    {
        $this->send(Command::REFRESH_DATA);
    }

    // ---------------------------------------------------------------- realtime

    /**
     * Subscribes to the device's realtime event stream.
     *
     * After this the device pushes unsolicited packets; each must be acknowledged.
     * The session stays open for as long as you listen.
     */
    public function beginRealtimeListening(int $eventMask = Command::EF_ATTLOG): void
    {
        $reply = $this->send(Command::REG_EVENT, pack('V', $eventMask));

        if (! $reply->isAccepted()) {
            throw new ProtocolException("Device refused the realtime subscription ({$reply->commandName()}).");
        }
    }

    /**
     * Reads the next pending realtime push, or null if none arrived.
     *
     * Acknowledges every push, because an unacknowledged device stops sending.
     */
    public function readRealtimeRaw(float $pollSeconds = 0.5): ?string
    {
        $reply = $this->session->transport()->readUnsolicited($pollSeconds);

        if ($reply === null) {
            return null;
        }

        BulkReader::acknowledge($this->session->transport(), $reply->sessionId);

        if ($reply->command !== Command::REG_EVENT) {
            return null; // not a realtime push
        }

        return $reply->data;
    }

    /**
     * The link's stream, so a caller listening to several devices can block on all
     * of them at once instead of polling each in turn. Null when the transport is
     * not selectable — poll with readRealtimeRaw() in that case.
     *
     * @return resource|null
     */
    public function selectableStream()
    {
        return $this->session->transport()->selectableStream();
    }

    // ------------------------------------------------------------------ plumbing

    /** Sends one command on the live session. */
    public function send(int $command, string $data = ''): Reply
    {
        if (! $this->session->isOpen()) {
            throw new ConnectionException('Session is not open.', [
                'endpoint' => $this->config()->endpoint(),
            ]);
        }

        // A previous call may have left the device streaming. Reopening is a no-op
        // unless that happened; skipping it yields replies shifted by one request.
        $this->session->ensureClean();

        $reply = $this->session->transport()->send($command, $data);

        // This reply announces a transfer. Unless the caller drains it (BulkReader
        // does), the session is now dirty and the next command must not trust it.
        if ($reply->isPreparingData()) {
            $this->session->markDirty();
        }

        return $reply;
    }

    /**
     * DIAGNOSTIC: issues an arbitrary command and reports the raw reply.
     *
     * Exists because the template-table framing had to be calibrated against real
     * firmware rather than assumed. Read-only by convention — pass a read command.
     *
     * @return array{command:int, name:string, length:int, hex:string}
     */
    public function probe(int $command, string $data = ''): array
    {
        $reply = $this->send($command, $data);

        return [
            'command' => $reply->command,
            'name' => $reply->commandName(),
            'length' => $reply->length(),
            'hex' => bin2hex(substr($reply->data, 0, 48)),
        ];
    }

    /** DIAGNOSTIC: buffered read of an arbitrary table. */
    public function probeBuffered(int $command, string $data = ''): string
    {
        return $this->bulk()->read($command, $data);
    }

    /**
     * Runs a write with the device disabled, then refreshes and re-enables.
     *
     * Re-enabling is in a finally block: a device left disabled by a failed write
     * stops accepting punches from real people.
     */
    private function withDeviceDisabled(\Closure $write): void
    {
        $this->disableDevice();

        try {
            $write();
            $this->refreshData();
        } finally {
            $this->enableDevice();
        }
    }

    private function bulk(): BulkReader
    {
        return $this->bulkReader ??= new BulkReader($this->session, $this->progress);
    }

    /** Runs an info read, returning '' rather than failing the whole info sweep. */
    private function safeString(\Closure $read): string
    {
        try {
            $value = $read();

            return is_string($value) ? RecordBuffer::cString($value) : '';
        } catch (\Throwable) {
            return '';
        }
    }
}
