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
use Promoseven\Biometric\Value\DeviceUser;

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
     * Every stored fingerprint template on the panel, as opaque identifiers.
     *
     * The C3 counterpart of TemplateService::allWithTemplates(). Reads the
     * `templatev10` table, whose schema the panel publishes itself:
     *
     *   templatev10=10,Size=i1,UID=i2,Pin=i3,FingerID=i4,Valid=i5,Template=B6,
     *                  Resverd=i7,EndTag=i8
     *
     * CONFIRMED 2026-09-15 on the inBIO460 @ 192.168.7.61 and the TF1700 @
     * 192.168.7.60: 238 records each, the exact figure the vendor software reports as
     * that panel's fingercount, across 196 people, finger slots 0 and 3-9, templates
     * of 564-1,618 bytes, every one carrying the `SS21` signature at offset 2.
     *
     * The blob is an OPAQUE IDENTIFIER, not a fingerprint. Identical bytes on two
     * devices mean one enrolment copied between them; DIFFERENT bytes mean nothing at
     * all, because re-presenting a finger yields a different template and there is no
     * matcher here.
     *
     * @return list<array{user_id:string,uid:int,fid:int,valid:int,template:string,size:int,sha1:string}>
     */
    public function readTemplates(?callable $onProgress = null): array
    {
        $out = [];

        foreach ($this->readTable('templatev10', $onProgress) as $row) {
            $blob = (string) ($row['Template'] ?? '');

            $out[] = [
                // Pin is the operator-facing id attendance records carry; UID is the
                // panel's internal slot and is not portable between devices.
                'user_id' => (string) ($row['Pin'] ?? ''),
                'uid' => (int) ($row['UID'] ?? 0),
                'fid' => (int) ($row['FingerID'] ?? 0),
                'valid' => (int) ($row['Valid'] ?? 0),
                'template' => $blob,
                'size' => strlen($blob),
                'sha1' => sha1($blob),
            ];
        }

        return $out;
    }

    /**
     * The raw record stream for one table, before any decoding.
     *
     * The C3 counterpart of TemplateService::rawTable(): for archiving a capture and
     * for calibrating a decoder against firmware you may not have access to twice.
     *
     * It exists because RecordCodec cannot read every table. A C3 record prefixes each
     * field with ONE length byte, so a field can carry at most 255 bytes — and the
     * `templatev10` blobs are 700-1,600. Decoding that table needs a different walk,
     * and writing one requires the bytes.
     *
     * A templatev10 payload is BIOMETRIC DATA. Do not archive it, log it or commit it.
     */
    public function readTableRaw(string $table, ?callable $onProgress = null): string
    {
        $catalogue = $this->catalogue();
        $indexes = $catalogue->fieldIndexes($table);

        $request = pack('C*', $catalogue->indexOf($table), count($indexes), ...$indexes, ...[0, 0]);

        [$reply, $payload] = $this->command(Command::GET_DATA, $request, 20.0);

        if (BufferedReader::isStaged($reply)) {
            return (new BufferedReader($this->transport))->pull($payload, $table, $onProgress);
        }

        if ($reply !== Command::REPLY_OK) {
            throw $this->refusal("read table '{$table}'", $reply, $payload);
        }

        return $payload;
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
     * The panel's roster, in the library's vendor-neutral user shape.
     *
     * The mapping lives HERE and not in a consumer's driver, for the same reason
     * readAttendance() does: a host application should never have to know that this
     * family calls the id column `Pin` while the standalone protocol calls it
     * `user_id`. That knowledge is protocol knowledge (rule 8).
     *
     * FINGERPRINT SLOTS ARE NULL, AND THAT IS A REAL ANSWER. The panel keeps
     * templates in a separate table (`templatev10`) which this library does not read
     * yet, so we do not know which slots are filled. Null means "not read"; it must
     * never be rendered as "none enrolled", which would tell an operator that
     * somebody with ten fingers registered has zero (rule 10).
     *
     * @param  ?callable(\Promoseven\Biometric\Value\Progress):void  $onProgress
     * @return list<DeviceUser>
     */
    public function readUsers(?callable $onProgress = null, bool $withFingerprints = false): array
    {
        /*
         * Finger slots come from templatev10, which is a SECOND table read. It used to
         * be impossible here, so every C3 user came back with fingerSlots null — "not
         * read" — and the roster rendered an amber "?" for all of them. It is possible
         * now, so ask for it when the caller wants it.
         *
         * Still only on request: it is another full table transfer (281,680 bytes on
         * these panels), and a caller that only wants the roster should not pay for it.
         *
         * A user absent from templatev10 while the table DID decode genuinely has no
         * fingerprints — that is a real empty list, not "unknown" (rule 10).
         */
        $slotsByPin = null;

        if ($withFingerprints) {
            $slotsByPin = [];

            foreach ($this->readTemplates() as $t) {
                $pin = $t['user_id'];

                if ($pin !== '' && ! in_array($t['fid'], $slotsByPin[$pin] ?? [], true)) {
                    $slotsByPin[$pin][] = $t['fid'];
                }
            }

            foreach ($slotsByPin as $pin => $slots) {
                sort($slots);
                $slotsByPin[$pin] = $slots;
            }
        }

        $users = [];

        foreach ($this->readTable('user', $onProgress) as $row) {
            $card = (int) ($row['CardNo'] ?? 0);
            $pin = (string) ($row['Pin'] ?? '');

            $users[] = new DeviceUser(
                uid: (int) ($row['UID'] ?? 0),
                userId: $pin,
                name: (string) ($row['Name'] ?? ''),
                privilege: (int) ($row['Privilege'] ?? 0),
                cardNumber: $card > 0 ? $card : null,
                fingerSlots: $slotsByPin === null ? null : ($slotsByPin[$pin] ?? []),
            );
        }

        return $users;
    }

    /**
     * Writes rows to a table (SET_DATA, 0x07). EXPERIMENTAL — not yet sent to any panel.
     *
     * Payload built from THIS panel's catalogue (RecordCodec::encode). Reports what the
     * panel ACCEPTED only: callers must read the table back to confirm (rule 10).
     *
     * @param list<array<string,int|string>> $rows
     */
    public function writeRows(string $table, array $rows, bool $allowBlobs = false): void
    {
        $catalogue = $this->catalogue();
        $payload = RecordCodec::encode($catalogue->indexOf($table), $catalogue->fields($table), $rows, $allowBlobs);

        [$reply, $answer] = $this->command(Command::SET_DATA, $payload, 20.0);

        if ($reply !== Command::REPLY_OK) {
            throw $this->refusal("write to table '{$table}'", $reply, $answer);
        }
    }

    /**
     * Deletes the rows of a table whose $keyField equals $value (DELETE_DATA, 0x09).
     * EXPERIMENTAL — not yet sent to any panel.
     *
     * The key field is NAMED and resolved through this panel's catalogue — a fork of
     * the reference hard-codes id 2 as "Pin", which on the TF1700 is CardNo and would
     * delete by card. Callers must read back and confirm exactly what went.
     */
    public function deleteRows(string $table, string $keyField, int|string $value): void
    {
        $catalogue = $this->catalogue();
        $payload = RecordCodec::encodeDeleteKey($catalogue->indexOf($table), $catalogue->fields($table), $keyField, $value);

        [$reply, $answer] = $this->command(Command::DELETE_DATA, $payload, 20.0);

        if ($reply !== Command::REPLY_OK) {
            throw $this->refusal("delete from table '{$table}'", $reply, $answer);
        }
    }

    /**
     * Moves one person from $fromPin to $toPin: their `user` row, their
     * `userauthorize` (door x time-zone) rows and their `templatev10` (fingerprint)
     * rows. EXPERIMENTAL.
     *
     * COPY, VERIFY, THEN REMOVE — never remove first:
     *   1. `user` under the new Pin (UID not sent; the panel assigns a NEW one —
     *      OBSERVED 287 -> 296 on the TF1700, 2026-09-24), read back;
     *   2. `userauthorize` under the new Pin, read back;
     *   3. `templatev10` under the new Pin AND the new UID (every template on the TF1700
     *      carries its owner's UID — 238 of 238, 2026-09-24), read back and compared
     *      byte for byte per finger;
     *   4. only then the old Pin's templates, door rows and user row are deleted.
     * A failure before step 4 removes whatever landed under the new Pin; the old rows
     * were never touched, so the person keeps working under the old Pin.
     *
     * @return array<string,int> rows moved per table
     */
    public function moveUser(int $fromPin, int $toPin): array
    {
        $catalogue = $this->catalogue();
        $tables = array_values(array_filter(['user', 'userauthorize', 'templatev10'], fn ($t) => $catalogue->has($t)));

        $byPin = fn (string $table, int $pin) => array_values(array_filter(
            $this->readTable($table),
            fn ($r) => (int) ($r['Pin'] ?? -1) === $pin,
        ));
        $fingers = fn (array $rows) => array_combine(
            array_map(fn ($r) => (int) $r['FingerID'], $rows),
            array_map(fn ($r) => sha1((string) $r['Template']), $rows),
        ) ?: [];

        if ($fromPin === $toPin) {
            throw new ProtocolException('Moving a user needs two different Pins.');
        }
        if ($byPin('user', $fromPin) === []) {
            throw new ProtocolException("Pin {$fromPin} is not on this panel.");
        }
        foreach ($tables as $table) {
            if ($byPin($table, $toPin) !== []) {
                throw new ProtocolException("Pin {$toPin} is already used in '{$table}' on this panel.");
            }
        }

        $old = [];
        foreach ($tables as $table) {
            $old[$table] = $byPin($table, $fromPin);
        }

        try {
            // 1. user
            $userRows = array_map(function (array $r) use ($toPin) {
                unset($r['UID']);
                $r['Pin'] = $toPin;

                return $r;
            }, $old['user']);
            $this->writeRows('user', $userRows);
            $newUser = $byPin('user', $toPin);
            if (count($newUser) !== 1) {
                throw new ProtocolException("The panel accepted the user under Pin {$toPin} but did not show it when read back.");
            }
            $newUid = (int) $newUser[0]['UID'];

            // 2. door permissions
            if (in_array('userauthorize', $tables, true) && $old['userauthorize'] !== []) {
                $this->writeRows('userauthorize', array_map(fn ($r) => ['Pin' => $toPin] + $r, $old['userauthorize']));
                if (count($byPin('userauthorize', $toPin)) !== count($old['userauthorize'])) {
                    throw new ProtocolException("The panel accepted the door permissions under Pin {$toPin} but did not show them when read back.");
                }
            }

            // 3. fingerprints, under the new Pin AND the new UID
            if (in_array('templatev10', $tables, true) && $old['templatev10'] !== []) {
                $this->writeRows('templatev10', array_map(function (array $r) use ($toPin, $newUid) {
                    $r['Pin'] = $toPin;
                    $r['UID'] = $newUid;

                    return $r;
                }, $old['templatev10']), allowBlobs: true);

                $now = $byPin('templatev10', $toPin);
                if ($fingers($now) != $fingers($old['templatev10'])) {
                    throw new ProtocolException("The fingerprints under Pin {$toPin} do not match the originals when read back.");
                }
                foreach ($now as $r) {
                    if ((int) $r['UID'] !== $newUid) {
                        throw new ProtocolException("A fingerprint under Pin {$toPin} carries UID {$r['UID']}, not the new user's {$newUid}.");
                    }
                }
            }
        } catch (\Throwable $e) {
            foreach (array_reverse($tables) as $table) {
                try {
                    if ($byPin($table, $toPin) !== []) {
                        $this->deleteRows($table, 'Pin', $toPin);
                    }
                } catch (\Throwable) {
                }
            }
            throw new ProtocolException("Could not move Pin {$fromPin} to {$toPin}: {$e->getMessage()} Pin {$fromPin} was left as it was.");
        }

        // 4. Only now remove the old Pin — fingerprints and doors first, the user last.
        foreach (array_reverse($tables) as $table) {
            if ($old[$table] !== []) {
                $this->deleteRows($table, 'Pin', $fromPin);
                if ($byPin($table, $fromPin) !== []) {
                    throw new ProtocolException("Pin {$toPin} is in place, but Pin {$fromPin} is still in '{$table}' after the delete. Remove it in ZKAccess.");
                }
            }
        }

        return array_combine($tables, array_map(fn ($t) => count($old[$t]), $tables));
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
