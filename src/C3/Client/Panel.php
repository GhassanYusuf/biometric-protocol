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

namespace Promoseven\Biometric\C3\Client;

use Promoseven\Biometric\C3\Codec\Catalogue;
use Promoseven\Biometric\C3\Codec\RecordCodec;
use Promoseven\Biometric\C3\Codec\Timestamp;
use Promoseven\Biometric\C3\Model\PanelModel;
use Promoseven\Biometric\C3\Model\PanelModelFactory;
use Promoseven\Biometric\C3\Protocol\BufferedReader;
use Promoseven\Biometric\C3\Protocol\Command;
use Promoseven\Biometric\C3\Protocol\Frame;
use Promoseven\Biometric\C3\Transport\C3TcpTransport;
use Promoseven\Biometric\Exception\DeviceException;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Value\DeviceConfig;

/**
 * A C3 / PullSDK access-control panel.
 *
 * The counterpart of Promoseven\Biometric\Client\Device for the OTHER protocol
 * family. It is a separate class and not a mode of that one, because the two share
 * no transport, no frame and no session model — folding them together would mean a
 * branch per vendor inside every method (rule 15).
 *
 * READ-ONLY BY CONSTRUCTION. There is no write method on this class at all. Every
 * C3 write — enrollment, SetDeviceData, and the door relay CONTROL_DEVICE (0x05) —
 * is unbuilt and unprobed, and rule 16 requires the owner's explicit go-ahead and a
 * terminal out of service before any of it is even attempted. A door relay is not
 * something to discover by accident.
 *
 * USAGE
 *
 *     $panel = new Panel(new DeviceConfig(host: '192.168.7.61'), 'inBIO460');
 *     $panel->open();
 *     try {
 *         $info = $panel->info();
 *         $rows = $panel->readTable('transaction');
 *     } finally {
 *         $panel->close();
 *     }
 */
final class Panel
{
    private C3TcpTransport $transport;

    private PanelModel $model;

    private ?Catalogue $catalogue = null;

    private bool $open = false;

    public function __construct(
        private readonly DeviceConfig $config,
        ?string $model = null,
    ) {
        $this->transport = new C3TcpTransport($config->host, $config->port, $config->timeout);
        // Selection happens exactly once, here. Nothing below branches on a model.
        $this->model = PanelModelFactory::for($model);
    }

    public function modelName(): string
    {
        return $this->model->name();
    }

    public function open(): void
    {
        if ($this->open) {
            return;
        }

        $this->transport->open();
        $this->model->establishSession($this->transport);
        $this->open = true;
    }

    public function close(): void
    {
        if (! $this->open) {
            $this->transport->close();

            return;
        }

        try {
            $this->transport->send(Command::DISCONNECT, '', 3.0);
        } catch (\Throwable) {
            // A panel that will not acknowledge a disconnect is not a failure worth
            // surfacing: we are closing the socket regardless.
        }

        $this->transport->close();
        $this->open = false;
        $this->catalogue = null;
    }

    /**
     * Identity and capacity, as the panel reports them.
     *
     * @return array<string,string>
     */
    public function info(): array
    {
        [$reply, $payload] = $this->command(Command::GET_PARAM, $this->parameterRequest());

        if ($reply !== Command::REPLY_OK) {
            throw $this->refusal('read parameters', $reply, $payload);
        }

        $values = [];

        foreach (preg_split('/[,\t\n\r]+/', $payload) ?: [] as $pair) {
            if (preg_match('/^([~\w]+)=(.*)$/', trim($pair), $m)) {
                $values[$m[1]] = $m[2];
            }
        }

        return $values;
    }

    /** The panel's own description of its schema. Cached for the life of the session. */
    public function catalogue(): Catalogue
    {
        if ($this->catalogue !== null) {
            return $this->catalogue;
        }

        [$reply, $payload] = $this->command(Command::DATATABLE_CFG);

        if ($reply !== Command::REPLY_OK) {
            throw $this->refusal('read the data-table catalogue', $reply, $payload);
        }

        return $this->catalogue = Catalogue::parse($payload);
    }

    /**
     * Reads every row of one table.
     *
     * Handles both answers: a small table arrives inline with REPLY_OK, a populated
     * one is staged and pulled. Callers do not need to know which happened — that is
     * the whole point of putting it here rather than in a driver.
     *
     * @param  ?callable(\Promoseven\Biometric\Value\Progress):void  $onProgress
     * @return list<array<string,int|string>>
     */
    public function readTable(string $table, ?callable $onProgress = null): array
    {
        $catalogue = $this->catalogue();
        $indexes = $catalogue->fieldIndexes($table);

        $request = pack('C*', $catalogue->indexOf($table), count($indexes), ...$indexes, ...[0, 0]);

        [$reply, $payload] = $this->command(Command::GET_DATA, $request, 20.0);

        if (BufferedReader::isStaged($reply)) {
            $payload = (new BufferedReader($this->transport))->pull($payload, $table, $onProgress);
        } elseif ($reply !== Command::REPLY_OK) {
            throw $this->refusal("read table '{$table}'", $reply, $payload);
        }

        return RecordCodec::decode($payload, $catalogue->indexOf($table), $indexes, $catalogue->fields($table));
    }

    /**
     * The transaction table, decoded into the shape the host application wants.
     *
     * Every record keeps its own `raw` payload. That is what lets a decoder fix be
     * replayed later over events the panel has since rolled over, and a record whose
     * timestamp would not decode is returned WITHOUT a timestamp rather than dropped
     * — the caller counts and archives it. Dropping it is the failure that silently
     * discarded a third of this project's attendance once already (rule 10).
     *
     * @param  ?callable(\Promoseven\Biometric\Value\Progress):void  $onProgress
     * @return list<array{user_id?:string,timestamp?:\DateTimeInterface,verify_method?:int,status?:int,door_id?:int,event_type?:int,card_no?:int,raw:string}>
     */
    public function readAttendance(?callable $onProgress = null): array
    {
        $records = [];

        foreach ($this->readTable('transaction', $onProgress) as $row) {
            $raw = json_encode($row, JSON_UNESCAPED_UNICODE) ?: '';
            $pin = (string) ($row['Pin'] ?? '');
            $moment = Timestamp::decode((int) ($row['Time_second'] ?? 0), $this->config->timezone);

            $record = [
                'verify_method' => (int) ($row['Verified'] ?? 0),
                'status' => (int) ($row['InOutState'] ?? 0),
                'door_id' => (int) ($row['DoorID'] ?? 0),
                'event_type' => (int) ($row['EventType'] ?? 0),
                'card_no' => (int) ($row['Cardno'] ?? 0),
                'raw' => $raw,
            ];

            // A panel logs door events with no person attached — an exit button, a
            // relay, a device restart. Those carry Pin 0 and are NOT attendance.
            // They are returned anyway, without a user, so the caller can count them
            // rather than wonder where the rows went.
            if ($pin !== '' && $pin !== '0') {
                $record['user_id'] = $pin;
            }

            if ($moment !== null) {
                $record['timestamp'] = $moment;
            }

            $records[] = $record;
        }

        return $records;
    }

    /**
     * Round-trips a command, opening the session lazily.
     *
     * @return array{0:int, 1:string}
     */
    private function command(int $command, string $data = '', ?float $timeout = null): array
    {
        if (! $this->open) {
            $this->open();
        }

        return $this->transport->send($command, $data, $timeout);
    }

    /**
     * The parameter names to ask for.
     *
     * GET_PARAM answers only what it is asked for, so an empty request returns
     * nothing useful. These are the ones CONFIRMED to answer on both the inBIO460
     * and the TF1700; a panel that does not know one simply omits it from the reply,
     * which is why asking for all of them is safe.
     */
    private function parameterRequest(): string
    {
        return implode(',', [
            '~SerialNumber',
            '~DeviceName',
            'FirmVer',
            'IPAddress',
            'MAC',
            'LockCount',
            'ReaderCount',
            'AuxInCount',
            'AuxOutCount',
            'MaxUserCount',
            'MaxAttLogCount',
            'DeviceID',
        ]);
    }

    private function refusal(string $what, int $reply, string $payload): DeviceException
    {
        if ($reply === Command::REPLY_ERROR) {
            $code = Frame::errorCode($payload);

            return new DeviceException(
                "The panel refused to {$what}: ".Command::describeError($code)." (code {$code}).",
            );
        }

        return new ProtocolException(sprintf('Unexpected reply 0x%02X while trying to %s.', $reply, $what));
    }
}
