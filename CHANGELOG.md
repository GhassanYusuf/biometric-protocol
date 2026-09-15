# Changelog

All notable changes to `promoseven/biometric-protocol`.

Versions before 2.1.0 predate this file; the library is consumed as `@dev` until
it is given its own git repository and tags (a known blocker recorded in the host
app's `docs/PROJECT-STATE.md`). `2.3.0` is the tag to cut when that happens.

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
