# promoseven/biometric-protocol

Framework-agnostic PHP library for biometric terminals and access-control panels,
over plain UDP/TCP, with **no vendor DLL, OCX or SDK runtime** and no Windows
dependency.

It speaks **two unrelated protocol families**:

| Family | Namespace | Devices | Transport |
|---|---|---|---|
| ZKTeco **standalone** | `Promoseven\Biometric\Protocol` | F18, F22, F-/K-series terminals | UDP or TCP 4370 |
| ZKTeco **C3 / PullSDK** | `Promoseven\Biometric\C3` | inBIO and C3 access panels — **and the TF1700** | TCP 4370 only |

They share a vendor and a port number and nothing else — different frame,
checksum, session model and command set. Pick the family by reading the device,
**never by the model name**: the TF1700 is sold as a standalone fingerprint
terminal and speaks C3.

The standalone family reads attendance, users, fingerprint templates and cards,
and drives enrollment. The C3 family is **read-only** in this release: identity,
schema and the transaction table.

> **Proprietary software.** Not open source. See [LICENSE](LICENSE) — possession
> of a copy grants no licence to use it.

## Requirements

- PHP **8.2+**
- No runtime dependencies at all
- `ext-sockets` strongly recommended — see [Buffer size](#three-things-that-will-bite-you)
- **On Linux, `net.core.rmem_max` must be larger than your biggest table.** The
  common default of 212,992 bytes is smaller than one full attendance table and
  will truncate reads. See below.

## Install

```bash
composer require promoseven/biometric-protocol
```

Licensees are given credentials for a private Composer registry. The package is
not on Packagist.

## Usage

The whole library is reached through one entry point. `Device::run()` opens a
session, runs your callback, and always closes:

```php
use Promoseven\Biometric\Client\Device;
use Promoseven\Biometric\Value\DeviceConfig;

$config = new DeviceConfig(
    host: '192.168.7.62',
    port: 4370,
    commKey: 0,
    timezone: 'Asia/Bahrain',   // the zone the DEVICE stamps records in
);

$punches = Device::run($config, fn (Device $d) => $d->attendance()->all());
```

Four services hang off the session:

```php
Device::run($config, function (Device $d) {
    $d->users()->all();                      // user records on the terminal
    $d->attendance()->all();                 // punches
    $d->templates()->countsByUserId();       // fingerprint slots per user
    $d->enrollment()->captureFingerprint(userId: '654', slot: 6);
    $d->info();                              // firmware, serial, capacities
    $d->syncTime();                          // set the device clock
});
```

## Capabilities

Support is declared at four levels, not two, because "it might work" is a real
state for undocumented firmware:

| Level | Meaning | What a UI should do |
|---|---|---|
| `confirmed` | Exercised against real hardware | Offer it |
| `implemented` | Written from protocol docs, never seen succeed | Offer with a warning |
| `not_implemented` | This library does not do it | Hide it |
| `unknown` | Never probed on this device | Hide it |

```php
$caps = $device->capabilities();
$caps->require(Capability::TEMPLATE_READ);   // throws UnsupportedCommandException
```

`probeCapabilities()` is **read-only by design** — you cannot test "can I delete
a fingerprint" without destroying somebody's fingerprint. A probe that throws
yields `unknown`, never `not_implemented`; a network blip is not evidence about
firmware.

## Four things that will bite you

**A short bulk read is not always the buffer.** The library prefers a
flow-controlled *windowed* read — `CMD_PREPARE_BUFFER` stages the table, then one
16 KB `CMD_READ_BUFFER` window at a time — and falls back to the free-running push
transfer when the device will not stage it. This is negotiated **per read**, and
support is **per table**: the same F22 stages attendance (326,124 bytes) and
templates (18,486) but refuses users. You do not have to do anything to get it,
but two things follow.

First, do not cache "this device supports windowed reads" — it is not a property
of the device. Second, when a push-path read still comes up short, check whether
the kernel is actually dropping anything before you go buying buffer:

```bash
awk '/^Udp:/{getline; print "RcvbufErrors", $5}' /proc/net/snmp   # before and after
```

On the F22 a read that lost ~145,000 bytes produced a delta of **three**. The
kernel was innocent; the device had stopped sending, and only the windowed read
fixed it. `ProtocolException::context()` carries `receive_buffer_usable` and
`receive_buffer_granted` for exactly this triage.

**Over a lossy or high-latency link, a single window will stall.** The windowed
read stages the whole table once and pulls it 16 KB at a time, so a stalled window
is re-requested at the same offset — the bytes already pulled are kept, not thrown
away. `DeviceConfig::$bulkWindowRetries` (default 4) is how many times a window is
retried before the transfer is abandoned; a `ProtocolException` from a genuinely
dead window carries `window_offset` and `window_retries`. On a LAN this path is
never entered. Reaching a device across the internet, raise it:

```php
$config = new DeviceConfig(host: '87.237.196.60', bulkWindowRetries: 8);
```

MEASURED on an F18 over a public IP: a 1.66 MB attendance table stalled ~7 times
per read. With `bulkWindowRetries: 0` (the pre-2.1.0 behaviour) every read pulled
~1/3 of the table and restarted from zero, never finishing; with the resume it
completes, re-reading only the stalled 16 KB windows. This also confirmed the
**F18 supports windowed reads**, not only the F22.

**Buffer size.** The OS default receive buffer is 64 KB. One attendance table on
an F18 is 412 KB. The protocol has no flow control, so the moment your reader
pauses the device keeps transmitting and the kernel drops everything past the
buffer — surfacing as `Incomplete transfer: got 89088 of 412084 bytes`. Install
`ext-sockets` and let `DeviceConfig::$receiveBuffer` raise it.

On **Linux** that is not sufficient on its own, and the failure is easy to
misread:

- The request is clamped to `net.core.rmem_max`, whose common default is
  **212,992 bytes** — already smaller than one attendance table. Raise it:

  ```bash
  sysctl -w net.core.rmem_max=16777216      # and persist in /etc/sysctl.d/
  ```

- Linux then stores **twice** what you asked for and reports that doubled figure
  back from `getsockopt(SO_RCVBUF)`. The second half is kernel bookkeeping and
  cannot hold payload. `receiveBufferBytes()` returns the **usable** number, with
  the platform correction already applied; `grantedReceiveBufferBytes()` returns
  the raw readback for diagnosis. Do not size transfer decisions off the raw one.

- Inside an **unprivileged LXC container** `/proc/sys/net/core/rmem_max` is
  read-only. The change must be made on the host; setting it in the container
  fails with `Invalid argument`.

**Device time is LOCAL, not UTC.** The terminal stamps records in its own wall
clock. Pass the device's real zone as `DeviceConfig::$timezone` and convert to
UTC before you store. Getting this wrong is silent: it produces duplicate rows
at a fixed offset, and watermarks in the future that skip real punches.

**One session per terminal.** The protocol is stateful per session. Two
concurrent sessions to one device interleave replies and *both* answers become
wrong. Serialise per device — a queue lock, a mutex, a lockfile, whatever your
platform offers. The library does not do this for you.

## Fingerprint templates

`templates()->slotsByUserId()` answers *which fingers are enrolled*. `allWithTemplates()`
answers the same question **and hands back each template's bytes**:

```php
foreach ($device->templates()->allWithTemplates() as $t) {
    // $t['user_id'], $t['fid'] (slot), $t['size'], $t['sha1'], $t['template']
}
```

No extra command and no extra round trip — the blobs have always been carried in the
table `slotsByUserId()` already reads, immediately after each record's 6-byte header.

**Treat the blob as an opaque identifier, never as a fingerprint.**

| | |
|---|---|
| Identical bytes on two devices | one enrolment, copied between terminals by a vendor tool. Strong evidence the two records are the same person. |
| Different bytes | **proves nothing.** Re-presenting the same finger yields a different template every time, and this library has no matcher. Never read a mismatch as "different people". |

CONFIRMED on a ZKTeco F18 (192.168.7.62) and F22 (192.168.7.63), 2026-09-15: user
id 261 slot 3 returned the same 1,054 bytes from both models.

Writing a template back to a device is a **separate, unverified** problem —
`downloadTemplate()` and `uploadTemplate()` still throw. If you only need to know
whether two records are one human, you do not need either: hash what you read.

Templates are biometric data. Prefer storing the digest over the bytes.

## What the library deliberately does not do

| Concern | Why it is yours |
|---|---|
| Retries | read `DeviceException::isRetryable()`, apply your own backoff |
| Persistence | it returns values; storing them is a host decision |
| Logging | no logger is injected — wrap the calls |
| Scheduling | no timers, no daemon |
| Per-device serialisation | see above; not optional |
| UTC conversion | it returns device-local time |

This is what keeps it framework-agnostic. A Laravel bridge that supplies all of
the above is available separately.

## Errors

Six typed exceptions, all extending `DeviceException`:

`ConnectionException`, `TimeoutException`, `ProtocolException`,
`UnsupportedCommandException`, `VerificationException`.

Each carries `context()` — structured detail such as the command, byte offsets
and counts — and `isRetryable()`. **`context()` is an array, not a string**; if
you render it in a UI, format it, do not interpolate it.

`VerificationException` matters more than it looks: this firmware family
acknowledges writes it then silently drops, so writes are read back and confirmed
rather than trusted on the ack.

## Tests

```bash
composer install
vendor/bin/phpunit
```

Codec tests run against captured fixtures with **no device present**, including a
22,066-byte real template table from an F18. Note the current scope honestly:
the suite covers the template codec and bulk-read progress. Transport, sessions
and the four services are exercised in production against real hardware, not by
unit tests.

## Reading a C3 / PullSDK panel

```php
use Promoseven\Biometric\C3\Client\Panel;
use Promoseven\Biometric\Value\DeviceConfig;

// The model selects the session behaviour ONCE, here. Nothing downstream branches.
$panel = new Panel(new DeviceConfig(host: '192.168.7.61', timezone: '+03:00'), 'inBIO460');
$panel->open();

try {
    $info = $panel->info();                 // serial, firmware, MAC, door counts
    $tables = $panel->catalogue()->tableNames();
    $punches = $panel->readAttendance(fn ($p) => printf("%d/%d\n", $p->bytesRead, $p->bytesTotal));
} finally {
    $panel->close();
}
```

Three things to know before you rely on it:

- **There is no cursor.** `readAttendance()` returns everything the panel holds,
  every time — 87,756 rows on a four-door inBIO460 in use since 2021. Watermarking
  and dedupe are yours.
- **Rows without a person are normal.** A panel logs exit buttons, relays and
  restarts. Those come back with no `user_id` rather than being dropped, so you can
  count them instead of wondering where they went.
- **The read is CRC-verified by the protocol.** A checksum mismatch throws. You will
  never be handed a short table that looks complete.

## Compatibility

Developed and confirmed against ZKTeco-protocol terminals (**F18** and **F22**,
and reseller-branded equivalents) and C3/PullSDK panels (**inBIO460**, **TF1700**).
Other models and firmware revisions are expected to work but are `implemented`,
not `confirmed` — the capability system exists so you can tell the difference at
runtime.

Confirmed models already differ in ways that matter, within each family:

- **F18 vs F22** — the F18 reads bulk tables over the push envelope; the F22 does
  not and needs the windowed read.
- **inBIO460 vs TF1700** — the TF1700 *requires* `CONNECT_SESSION_LESS` and the
  inBIO460 *refuses* it. Get this wrong on a TF1700 and every reply is shifted four
  bytes, so a panel holding 21,000 records reports zero without erroring.

Assume firmware variation is the norm rather than the exception, and prefer
negotiating a behaviour over assuming it.

"ZKTeco" is a trademark of its respective owner, used here only to describe the
hardware and protocol this library interoperates with. No affiliation or
endorsement is claimed.
