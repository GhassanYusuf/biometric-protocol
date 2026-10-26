# Changelog

All notable changes to `promoseven/biometric-protocol`.

Versions before 2.1.0 predate this file; the library is consumed as `@dev` until
it is given its own git repository and tags (a known blocker recorded in the host
app's `docs/PROJECT-STATE.md`). `2.3.0` is the tag to cut when that happens.

## 2.17.0 — 2026-10-26

### Added — the UA300 model (`Model\UA300`)

- Matched by `UA300` / `UA300/ID`. Observed on one unit: Catering, 192.168.7.120,
  "Ver 6.60 May 14 2018", ZMM200_TFT. Before this it got `GenericTerminal`.
- Starts from the generic set (no write offered) and confirms only what that unit has
  done, 2026-10-22 to 2026-10-26: ping, info, clock read, users, cards, attendance
  (2,101 → 2,115 records, none undecodable), fingerprint blobs (27).
- `template.table.read` stays IMPLEMENTED: the table would not decode on three of five
  nightly roster reads.
- `device.time.write` stays UNKNOWN: on its one run the terminal ACKed, the immediate
  read-back still showed the old time, and the clock was right some hours later. An F18
  applies it at once.
- Research found nothing UA300- or ZMM200-specific in pyzk, pyzatt or php-zkteco.
- Test: `TerminalModelTest::test_the_ua300_confirms_its_reads_and_claims_no_write`.

## 2.16.2 — 2026-10-21

### Fixed — the first finger on an empty terminal could not be WRITTEN

- 2.16.1 fixed the read; the write still refused. `TemplateService::addTemplates()`
  reads the table first so it never overwrites a finger, and asked
  `TemplateCodec::isEmptyTable()`, which knew only the 4-byte zero header — so the
  0-byte reply of an empty F18 table read as "would not decode" and the write threw
  `UnsupportedCommandException`. Observed: Ghassan pushed to the F18 IT-Office
  (192.168.7.64) — card written, no finger.
- `TemplateCodec::isEmptyTable()` now also accepts no bytes at all, and is the ONE
  definition: `UserService::all()` (2.16.1's own check) uses it too, as do the two ID-move
  paths. Reproduced in a second read-only run (host app
  `tools/zkprobe/traces-2026-10-21/empty-template-table-02.json`): IT-Office 0 bytes,
  empty; Good Wheels, Camelot (F18) and On The Road (F22) non-empty and unchanged.
- Tests: `TemplateAddTest::test_writes_the_first_finger_on_a_terminal_whose_empty_table_is_sent_as_nothing`,
  `TemplateCodecTest::test_an_empty_table_is_a_zero_header_or_no_bytes_and_nothing_else`.

## 2.16.1 — 2026-10-21

### Fixed — an empty template table is "no fingers", not "unknown"

- `UserService::all(withFingerprints: true)` reported every user's fingers as unknown
  (`null`) whenever the template table decoded to no records — so a terminal holding
  no fingerprints at all (wiped, or new) could never be given its first one: callers
  rightly refuse to write fingers where they cannot read them. An empty table is now
  `[]` for everyone; bytes that decode to nothing stay `null`.
- Empty = what the device declares: `''` from the bulk reader (its own "nothing to
  send") or a 4-byte length of 0. OBSERVED on the F18 IT-Office (192.168.7.64,
  2026-10-21): the template read returned 0 bytes after a wipe; control Good Wheels
  (F18/ID) 28,610 bytes, 33 templates (host app
  `tools/zkprobe/traces-2026-10-21/empty-template-table-01.json`).
- Re-confirmed read-only on Good Wheels (F18/ID), Camelot (F18) and On The Road (F22):
  every user's finger slots identical to the host app's previous read.
- Tests: `UserFingerSlotsTest` (empty as nothing, empty as a zero length, garbage,
  fingers present).

## 2.16.0 — 2026-10-21

### Added — `device.wipe`, `UserService::deleteAll()`

- `Capability::DEVICE_WIPE` (`device.wipe`). F18 (`CapabilitySet::defaults()`):
  IMPLEMENTED, never run on hardware. F22: UNKNOWN (rule 15 — not inherited from the
  F18). `GenericTerminal`: UNKNOWN. C3 panels: NOT_IMPLEMENTED.
- `UserService::deleteAll(): int` — every user removed by `DELETE_USER` (18, the per-user
  delete CONFIRMED on the F18), then the user table read back and required empty
  (`VerificationException` with `context()['remaining']` otherwise). Refuses before
  deleting anything when any user record would not decode (no uid to address); a
  refused delete mid-way reports `context()['deleted']`. `CLEAR_DATA` (14) is not used:
  DOCUMENTED only, effect on this firmware never observed.
- Tests: `UserDeleteAllTest` (in-memory terminal; the dropped-delete and refused-delete
  cases; every model's level).

## 2.15.0 — 2026-10-20

### Changed — `password.write` CONFIRMED on all four models

- F18 (`CapabilitySet::defaults()`), F22, inBIO460 and TF1700: IMPLEMENTED → CONFIRMED.
  Evidence: the host app's `tools/zkprobe/user-password-write.php` on every terminal of
  each model — IT ROOM, Camelot, Good Wheels (F18), On The Road (F22), Glass Door
  (inBIO460), Entrance (TF1700) — twice each on 2026-10-20: a temporary test user's
  passwords 1357 and 2468 written and read back equal, a name write with no password
  kept it, the test user deleted and the roster unchanged.

### Changed — `user.privilege` CONFIRMED on the F18 and F22

- F18: IMPLEMENTED → CONFIRMED. F22: UNKNOWN → CONFIRMED (same `USER_WRQ` record and
  `UserService::setPrivilege()` as the F18). Evidence: the host app's
  `tools/zkprobe/user-privilege-write.php` on IT ROOM, Camelot, Good Wheels and On The
  Road, twice each on 2026-10-20: a test user made administrator (14) then normal user
  (0), each read back, name and password kept, every other user's privilege unchanged.
  C3 panels stay not_implemented: their user table has no terminal-menu administrator.

## 2.14.1 — 2026-10-20

### Fixed — `password.write` is unprobeable

- `CapabilityResolver::unprobeable()` now lists `Capability::PASSWORD_WRITE` ("Would
  change a real person's keypad password"). Without it a host app that stored a
  per-terminal `password.write` level after a real write test lost it on the next
  re-probe, which fell back to the model's level. No probe ever wrote a password; this
  only changes which stored levels a re-probe keeps.
- `password.write` on the F18 (`CapabilitySet::defaults()`) stays IMPLEMENTED. The write
  read back on IT ROOM (F18, 192.168.7.62) twice on 2026-10-20 — name write kept it too
  — but one terminal does not confirm a model whose other units run other firmware
  (Good Wheels, F18/ID, 2021 firmware, never written).

## 2.14.0 — 2026-10-18

### Added — the terminal's own record counts

- `Codec\FreeSizesCodec` decodes the `GET_FREE_SIZES` (50) reply: users, fingers,
  attendance records, cards and capacities, as little-endian int32s at pyzk's indices.
  CONFIRMED 2026-10-18: `records` equalled a full attendance read on three F18s and an
  F22. Fixture `tests/Fixtures/f18-free-sizes-itroom.bin`.
- `DeviceClient::recordCounts()`, `AttendanceService::deviceCount()` — null when the
  reply does not decode, never a guessed 0.

### Changed — `AttendanceService::clearAll()` is guarded

- `clearAll(?int $expectedRecords = null): int`. With a count, refuses (nothing sent)
  when the terminal holds a different number; after `CLEAR_ATTLOG` the count must read 0,
  or `VerificationException`. Returns the number held before. Still never called by any
  sync flow, still never run on hardware.

### Added — `UserService::setPrivilege()`

- Administrator (`PRIVILEGE_ADMIN` = 14) or normal user (`PRIVILEGE_USER` = 0) on an
  existing record, name / card / password kept, privilege verified on read-back.
  `Capability::USER_PRIVILEGE` (`user.privilege`): IMPLEMENTED in `defaults()`, UNKNOWN
  on the F22 and generic terminals, NOT_IMPLEMENTED on C3.

### Fixed — a 40-byte attendance record with no user id decoded as a punch

- `AttendanceCodec` returns it as `['raw' => hex]`. OBSERVED on Camelot (F18,
  87.237.196.60): misaligned transfers yielded 2,876 such "punches" dated 1999–2030.

### Changed — F22 levels

- `attendance.clear` and `user.privilege` are UNKNOWN on the F22 rather than inherited
  from the F18 set; neither has run on either model.

## 2.13.0 — 2026-10-12

### Fixed — every standalone user write erased the keypad password

- `Packet::buildUserRecord()` left password(8)@3 zero, and `UserService::save()` rebuilt
  the record from name, card and privilege only. So every name push and every
  `setCard()` ERASED a password set at the terminal keypad. OBSERVED 2026-10-12: IT ROOM
  (F18, 192.168.7.62) lacked a password the host app still held.
- `save()` now keeps the device's password when `$password` is null, writes it when
  given, clears it with `''`, and verifies it on read-back (`VerificationException`
  that never prints the value). `setCard()` keeps it through `save()`.

### Added — the keypad password, read and written

- `Capability::PASSWORD_READ` (`password.read`), `Capability::PASSWORD_WRITE`
  (`password.write`).
- `UserCodec::decode()` returns `password`; `DeviceUser::$password` ('' none, null not
  read) and `hasPassword()`. `toArray()` carries only `has_password`, never the value.
- `Packet::buildUserRecord(..., string $password = '')`, `DeviceClient::writeUser(...,
  string $password = '')` — refused over 8 bytes.
- C3: `Panel::readUsers()` fills `password` from the `user` table's `Password` field;
  `Personnel::add(..., string $password = '')`, `Personnel::update(..., ?string
  $password = null)` (null keeps the row's own). A mismatch on read-back never prints it.
- Levels: `password.read` CONFIRMED on the F18, F22, inBIO460 and TF1700 — 2026-10-12
  every password the host app held equalled the terminal's (host app
  `tools/zkprobe/traces-2026-10-12/user-passwords-02.json`). `password.write` IMPLEMENTED
  on those four (the generic panel: not implemented; any other terminal: unknown).
- Tests: `UserPasswordTest`, `C3PersonnelTest::test_a_name_edit_keeps_the_keypad_password…`.

## 2.12.0 — 2026-10-11

### Added — the C3 panel clock

- `C3\Protocol\Command::DATETIME` (0x03), transcribed from vwout/zkaccess-c3-py
  (`consts.py`, `core.py` set_device_datetime).
- `C3\Client\Panel::readClock($timezone)` — GET_PARAM "DateTime", decoded with the
  transaction-stamp format (`Timestamp`); null when not reported.
- `Panel::setClock($local, $timezone)` — DATETIME "DateTime=<packed>", then read back.
- `InBio460`, `Tf1700`: `device.time.read` / `device.time.write` CONFIRMED —
  2026-10-11 both panels read ~650 s slow, set, and read back exact.

## 2.11.1 — 2026-10-11

### Fixed — a C3 edit could cut a person's fingerprints off their record

- OBSERVED on the TF1700 @ 192.168.7.60: editing Pin 781054761's `user` row (sent
  without UID, as ZKAccess does) re-inserted it under UID 51 — freed moments earlier by
  another delete — instead of 318. Its `templatev10` rows stayed on UID 318, so the
  finger no longer belonged to the person. The inBIO460 kept the UID for the same edit.
- `C3\Service\Personnel::relinkFingerprints($pin)`: rewrites a person's template rows
  under their current UID; delete by Pin, write, verify byte for byte and the UID on
  every row, restore the originals on any failure.
- `Personnel::update()` re-links before every edit (a re-push repairs an old break) and
  after one that changed the UID, instead of only refusing.
- Tests: `C3PersonnelTest` (UID re-insert, stale link, failed re-link restored).

## 2.11.0 — 2026-10-11

### Added — one capability set per standalone MODEL

The standalone family shared `CapabilitySet::defaults()` (the F18), so a level proven
on the F18 was claimed for every model. Now, as the C3 family already did:
- `Model\TerminalModel`, `Model\F18` (= `defaults()`, unchanged), `Model\F22` (its own
  evidence: reads, user write and delete CONFIRMED; template upload, renumber,
  template delete, enrolment UNKNOWN; card write IMPLEMENTED), `Model\GenericTerminal`
  (a model with no file: reads IMPLEMENTED, every write UNKNOWN),
  `Model\TerminalModelFactory::for($model)` (discovers model files, names none).
- `CapabilityResolver` and `Device::probeCapabilities()` take an optional baseline, so
  a probe refines the model's own set.
- Tests: `tests/Unit/TerminalModelTest.php`.

## 2.10.0 — 2026-10-11

### Added — put stored fingerprints on a standalone terminal

- `TemplateService::addTemplates($userId, $templates)`: add-only, via
  `SAVE_USERTEMPS` with the device's own record and the user's existing templates
  plus the new slots (correct whether the firmware replaces or merges the set).
  Refuses before writing on a missing user, an unisolatable record or an undecodable
  table; verifies existing fingers byte-for-byte afterwards and writes the original
  back if one changed; returns only slots read back byte-identical.
- `CapabilitySet::defaults()`: `template.upload` `not_implemented` → `implemented`.
  2026-10-11, F18 @ 192.168.7.62: slot 6 (1,132 bytes, read off an inBIO460) added to
  uid 20 and read back identical; every other user and template unchanged. A real
  finger scan has not been observed yet.
- Tests: `tests/Unit/TemplateAddTest.php` (in-memory terminal, both replace and merge
  semantics, dropped writes, lost existing fingers).

## 2.9.0 — 2026-09-24

### Added — C3 table writes (EXPERIMENTAL; CONFIRMED on the TF1700 for `user`)

- `RecordCodec::encode()` / `encodeDeleteKey()`: SET_DATA / DELETE_DATA payloads built
  from the PANEL'S catalogue (the xub/zkaccess-c3-py fork's hard-coded field ids are
  wrong for the TF1700). Blob fields refused. Byte-checked against the fork on its own
  schema, and round-tripped on the TF1700's (`tests/Unit/C3RecordWriteTest.php`).
- `Panel::writeRows()` / `Panel::deleteRows()` (key field by name).
- `Panel::moveUser($fromPin, $toPin)`: user + userauthorize + templatev10 (under the
  panel's NEW UID), copy-verify-then-remove, undo on failure. Blob fields encode with
  a two-byte length when explicitly allowed. Verified on the TF1700 and the inBIO460
  with a test user and a placeholder template.
- 2026-09-24, TF1700 @ 192.168.7.60: add + read back + delete of a test user, every
  other row unchanged. Capability levels unchanged.

## 2.8.0 — 2026-09-24

### Added — renumber by delete + re-upload (EXPERIMENTAL)

The F18 refuses `renumber()` (ACK_ERROR on in-place user-id change, 2026-09-23).
- `UserService::renumberByReupload($from, $to, $onSnapshot)`: snapshot (handed to
  the caller before any write) → delete → re-upload record + templates under the new
  id on the same uid → verify → restore the original on any failure.
- `DeviceClient::saveUserWithTemplates()` and `Command::SAVE_USERTEMPS` (110):
  FREE_DATA / PREPARE_DATA / DATA×n / SAVE_USERTEMPS / REFRESH_DATA, transcribed
  from fananimi/pyzk commit f29709c1.
- `Packet::buildUserTemplatesUpload()`, `Packet::buildSaveUserTemplatesRequest()`,
  `Packet::withUserId()` (rewrites only the 9-byte id field).
- `UserCodec::rawRecord()`, `TemplateCodec::isEmptyTable()`.

Capability levels unchanged: `user.renumber` and `template.upload` stay
`not_implemented` in `defaults()` until a hardware run succeeds. Tests:
`tests/Unit/UserReuploadTest.php` (wire bytes vs pyzk, real F18 fixture blobs,
snapshot-before-write, refusal, dropped fingers, restore, failed restore).

## 2.7.0 — 2026-09-23

### Added — `UserService::renumber()` and `Capability::USER_RENUMBER` (EXPERIMENTAL)

Moves a user to a different user id by rewriting the same uid, keeping name,
privilege, card and — because templates are keyed by uid — fingerprints. Verified
by read-back of both the user table and the template table; any lost finger, a
second record, or a record on the wrong uid throws `VerificationException`.
`user.renumber` is `implemented` in `CapabilitySet::defaults()` (never yet run on
hardware), `not_implemented` for C3, and listed in `CapabilityResolver::unprobeable()`.
Tests: `tests/Unit/UserRenumberTest.php` against a simulated terminal.

## 2.6.0 — 2026-09-15

### Added — the C3 write, delete and count command numbers (NOT yet sendable)

- **`Command::SET_DATA = 0x07`, `DELETE_DATA = 0x09`, `GET_DATA_COUNT = 0x0A`**,
  recovered from the vendor's own `plcommpro.dll`. **No public C3 reimplementation
  has a write command at all** — `vwout/zkaccess-c3-py`'s command set stops at
  `GET_DATA`, and its own README says the protocol is undocumented and everything
  rests on reverse engineering. So this could not be transcribed from a reference;
  it came out of the DLL.

  The evidence is the SDK's own log string followed immediately by the constant it
  sets:

  ```
  .rdata  "SetDeviceData, ZEMBPRO_SENDCMDDATA Before !Cmd=CMD_SET_DATA, datalen=%d"
  .text   1000b7c2:  movl $0x7,0x44(%esp)      ; the command
  .text   1000b7ca:  movl $0x8000,0x40(%esp)   ; the send buffer
  ```

  `0x09` sits inside `Process_DeleteDeviceData` and `0x0A` inside
  `Process_GetDeviceDataCount`. The same extraction independently reproduces three
  command numbers already known from the references — `0x03` DATETIME, `0x04`
  GET_PARAM, `0x06` DATATABLE_CFG — which is what makes it a method rather than a
  coincidence.

### NOT added — the write itself

- **The command number is settled. The PAYLOAD layout for a write is not.** The read
  request is `[tableIndex][fieldCount][fieldIndexes…][0,0]` and the DLL is seen
  tokenising the caller's field list on `','`, so a write almost certainly mirrors
  it — but "almost certainly" is not a basis for sending bytes to a panel that holds
  320 live enrolments and controls a door. A malformed write to `user` overwrites
  people whose fingerprints cannot be restored from any backup.

  Left as a **narrow, named gap** rather than guessed at, per the host app's rules 16
  and 17. Closing it needs either a capture of ZKAccess 3.5.5 writing one user, or
  more DLL work on the payload builder between `0x1000af68` and `0x1000b7c2`.

## 2.3.0 — 2026-09-14

### Fixed — a growing table no longer aborts a windowed read

- **`BulkReader` treated any change in the re-staged size as fatal**, which made a
  full read impossible on a terminal still in service across a slow link. CONFIRMED
  on an F18 over a public IP: a 1,665,484-byte attendance table needs several
  re-stages, somebody badged mid-read, the size grew to 1,665,524 — exactly one
  40-byte record — and the transfer threw after fourteen minutes.

  Growth and shrinkage now mean opposite things. A **larger** table is append-only
  growth: the read continues to the size it committed to and the new records arrive
  on the next read. A **smaller** table was cleared or rolled over, so the offsets
  held address different records and the transfer is still abandoned — continuing
  would return rows that look real and are not.

  A read that later fails carries `grew_bytes` in its exception context, so "the
  terminal was in use while we read it" is recorded rather than inferred.

  Re-confirmed on the F18 reference (10,531 records) and the F22 (8,162) before
  landing, both with zero undecodable records.

### Added — the roster on the driver contract

- **`C3\Client\Panel::readUsers()`** maps the panel's `user` table onto `DeviceUser`,
  so a consumer never has to know this family calls the id column `Pin`. Finger slots
  are always **null**, meaning "not read" — templates live in a separate
  `templatev10` table this library does not read. Null must never be rendered as
  "none enrolled".

- `USER_READ` is **confirmed** on the inBIO460 and TF1700: 320 users read from each,
  all named, 145 carrying a card.

### Added — a SECOND protocol family

- **`Promoseven\Biometric\C3`** — the ZKTeco **C3 / PullSDK** protocol, spoken by
  access-control panels (inBIO and C3 ranges). This is a separate family, not a
  dialect: TCP only, an `AA 01 … 55` frame, CRC-16/ARC, and a session model the
  standalone protocol does not have. Nothing under `Promoseven\Biometric\Protocol`
  applies to it and no constant is shared.

  The package name stops being aspirational with this release: it now speaks two
  biometric protocols rather than one.

  - `C3\Client\Panel` — open, `info()`, `catalogue()`, `readTable()`,
    `readAttendance()`. **Read-only by construction**: there is no write method.
  - `C3\Transport\C3TcpTransport`, `C3\Protocol\Frame`, `C3\Protocol\Command`.
  - `C3\Codec\Catalogue` — the panel describes its own schema, so table and field
    indexes are read from the device and never hard-coded. The inBIO460 reports 12
    tables and the TF1700 reports 11.
  - `C3\Codec\RecordCodec`, `C3\Codec\Timestamp`.
  - `C3\Capability\C3Capabilities` — four-level sets, per model.
  - `C3\Model\*` — per-model behaviour, selected once by `PanelModelFactory`.

- **`C3\Protocol\BufferedReader` — the `0x0D` → `0x0E` → `0x0F` staged read.**
  `GET_DATA` on a populated table does not return rows; it stages them behind a
  17-byte header and they are pulled a chunk at a time. **No public C3
  reimplementation carries this path** — `vwout/zkaccess-c3-py` and `-lua` both
  handle only the inline reply, which is why neither can read a table that has
  anything in it.

  The header carries a **CRC-32/ISO-HDLC**, which makes the read self-verifying: a
  wrong pull loop produces a checksum mismatch rather than a plausible half-table.
  CONFIRMED against an inBIO460 (1,717,298 bytes, 337 chunks, 87,756 rows) and a
  TF1700 (367,768 bytes, 72 chunks, 21,005 rows).

### Findings that consumers need

- **A model name does not tell you the protocol family.** The **TF1700** is sold as
  a standalone fingerprint terminal and speaks C3/PullSDK. Probed with the
  standalone protocol it accepts TCP and answers nothing, which reads as a dead
  device. Identify by reading the panel, not by the name on the case.

- **The TF1700 requires `CONNECT_SESSION_LESS` (0x01); the inBIO460 refuses it.**
  Without `0x01` the TF1700 prefixes every reply with four session bytes, so a
  session-less reader is shifted four bytes on every payload — `GET_DATA` then
  answers a well-formed `0xC8` with ten useless bytes. **It does not error; it
  returns zero records.** A panel holding 21,005 rows looks reachable, healthy and
  empty. This is why the two models have separate classes.

- **Panels stamp LOCAL time** with nothing in the payload saying so. Pass
  `DeviceConfig::$timezone`; `C3\Codec\Timestamp` anchors to it and returns `null`
  — never an epoch, never midnight — for anything that will not decode.

- **There is no cursor.** `readAttendance()` reads everything the panel holds, every
  time. Watermarking and dedupe belong to the consumer.

## 2.2.0 — 2026-09-14

### Added

- **`TcpTransport`** — speaks the protocol over TCP instead of UDP, selected by
  `DeviceConfig::$transport` (`'udp'` default, `'tcp'`; `DeviceConfig::usesTcp()`).
  TCP has flow control and retransmission, which removes the loss/stall failure
  class that dogs UDP on a device reached across the internet. `fromArray()` accepts
  `transport`.

### Fixed

- **`Packet::wrapTcp()` wrote the TCP frame's second magic word as zero**, and a real
  device rejects such a frame — it closes the connection without replying, so the
  TCP path was dead on arrival. Both words are required (`0x5050`, `0x7d82`).
  CONFIRMED reading an F22 whole over TCP after the fix (8,162 records). New
  `Packet::TCP_MAGIC_2`, and `TcpFrameTest` pins the exact bytes.

### Notes

- UDP remains the default. TCP is proven on a LAN device (F22) but has **not yet
  completed a read on the problem device it was built for** (Camelot F18, public IP)
  — that device is flaky at session setup and staging, independent of transport.
  Left opt-in until proven there. `TcpTransportTest` covers the stream reassembly.

## 2.1.0 — 2026-09-14

### Added

- `DeviceConfig::$bulkWindowRetries` (default `4`): how many times a stalled
  windowed-read window is re-requested before the whole transfer is abandoned.
  Also accepted by `DeviceConfig::fromArray()` as `bulk_window_retries`.

### Fixed

- **Windowed reads now RESUME a stalled window instead of losing the whole
  transfer.** The flow-controlled read stages the table with `PREPARE_BUFFER` and
  pulls it one 16 KB window at a time; that staged copy stays valid until
  `FREE_DATA`, so a window that stalls is now re-requested at the same offset with
  the bytes already pulled kept in place. Previously any single stalled window
  threw, and the whole request restaged from offset 0 — fine on a LAN (a window
  never stalls) but fatal on a lossy or high-latency link.

  MEASURED on the Camelot F18 over a public IP (2026-09-14): a 1,664,804-byte
  attendance table stalled ~7 times per read. Under the old behaviour every read
  pulled ~1/3 of the table and then restarted from zero, exhausting all five
  whole-request attempts without ever finishing. A packet capture confirmed the
  cause was NOT the receive buffer (`RcvbufErrors` delta 0, socket rx-queue max 0)
  nor corruption (`InErrors` delta 0) — the device simply went silent mid-window,
  and the reader discarded everything on the first silence.

  Set `bulkWindowRetries` to `0` for the pre-2.1.0 behaviour (a stall aborts the
  windowed read immediately and only the whole-request retry can save it).

### Notes

- LAN reads are unaffected: a LAN window does not stall, so the retry path is
  never entered. Re-confirmed against the reference F18 (`192.168.7.62`) after the
  change.
- This also records the first CONFIRMED evidence that the **F18 supports windowed
  reads** (Camelot staged the table and served 16 KB windows), previously an open
  question in `docs/protocol-overview.md`.
