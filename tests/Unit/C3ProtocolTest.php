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

namespace Promoseven\Biometric\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\C3\Codec\Catalogue;
use Promoseven\Biometric\C3\Codec\RecordCodec;
use Promoseven\Biometric\C3\Codec\Timestamp;
use Promoseven\Biometric\C3\Model\GenericPanel;
use Promoseven\Biometric\C3\Model\InBio460;
use Promoseven\Biometric\C3\Model\PanelModelFactory;
use Promoseven\Biometric\C3\Model\Tf1700;
use Promoseven\Biometric\C3\Protocol\BufferedReader;
use Promoseven\Biometric\C3\Protocol\Command;
use Promoseven\Biometric\C3\Protocol\Frame;
use Promoseven\Biometric\Exception\ProtocolException;

/**
 * The C3 / PullSDK protocol, against captured bytes and no device.
 *
 * Two of the fixtures are REAL captures from the owner's own hardware, chosen
 * because they carry no personal data: a staging header (five integers) and a table
 * catalogue (a schema). The record stream is SYNTHETIC with real structure —
 * a real one is full of card numbers and PINs, and rule 16 forbids committing that.
 */
final class C3ProtocolTest extends TestCase
{
    private function fixture(string $name): string
    {
        return file_get_contents(__DIR__.'/../Fixtures/'.$name);
    }

    /*
     * ---- Frame and checksum -------------------------------------------------
     */

    /**
     * The CRC-16/ARC, pinned against a frame this project actually put on the wire
     * and that two panels accepted. Transcribed, not derived (rule 17) — so if a
     * panel ever disagrees, the difference is a fact about the panel.
     */
    public function test_the_crc_matches_a_frame_two_real_panels_accepted(): void
    {
        // GET_DATA for table 5 (transaction), fields 1..7 — byte for byte what the
        // probe sent to 192.168.7.60 and .61 on 2026-09-14.
        $sent = Frame::build(Command::GET_DATA, pack('C*', 5, 7, 1, 2, 3, 4, 5, 6, 7, 0, 0));

        $this->assertSame('aa01080b000507010203040506070000b1d155', bin2hex($sent));
    }

    public function test_a_session_frame_carries_four_extra_bytes_and_a_longer_length(): void
    {
        $sessionLess = Frame::build(Command::GET_PARAM, 'x');
        $withSession = Frame::build(Command::GET_PARAM, 'x', sessionId: 0xFEFE, requestNr: 0x1234);

        $this->assertSame(strlen($sessionLess) + 4, strlen($withSession));

        // The declared length counts the session bytes and the data, nothing else.
        $this->assertSame(1, unpack('C', $sessionLess[3])[1]);
        $this->assertSame(5, unpack('C', $withSession[3])[1]);
    }

    /**
     * Stripping four session bytes that are not there shifts every field in the
     * payload, which produces rows that look real and are not. So the caller states
     * which framing it used, and parse() honours it.
     */
    public function test_parse_only_strips_the_session_prefix_when_there_was_one(): void
    {
        $header = pack('C*', Command::START, Command::VERSION, Command::REPLY_OK, 8, 0);
        $rest = pack('C*', 0xFE, 0xFE, 0x01, 0x00).'ABCD'.pack('C*', 0, 0, Command::END);

        $this->assertSame('ABCD', Frame::parse($header, $rest, hasSession: true)['payload']);
        $this->assertSame("\xFE\xFE\x01\x00ABCD", Frame::parse($header, $rest, hasSession: false)['payload']);
    }

    public function test_a_refusal_decodes_to_the_negative_code_the_panel_meant(): void
    {
        // CONFIRMED inBIO460: CONNECT_SESSION answers -13, CONNECT_SESSION_LESS -98.
        $this->assertSame(-13, Frame::errorCode(pack('V', 0xFFFFFFF3)));
        $this->assertSame(-98, Frame::errorCode(pack('V', 0xFFFFFF9E)));
        $this->assertStringContainsString('not available', Command::describeError(-13));
    }

    /*
     * ---- The staging header -------------------------------------------------
     */

    /**
     * The real 17 bytes the TF1700 answered with on 2026-09-14, decoded against the
     * layout recovered from the vendor SDK. This is the fixture that proves the
     * whole buffered read, because every other number in it follows from these.
     */
    public function test_the_real_tf1700_staging_header_decodes(): void
    {
        $header = BufferedReader::parseHeader($this->fixture('c3-prepare-data-tf1700.bin'));

        $this->assertSame(0, $header['flag'], 'Both panels stage RAW; a compressed flag is unhandled on purpose.');
        $this->assertSame(367768, $header['datalen']);
        $this->assertSame(367768, $header['oriLen'], 'datalen == oriLen is what flag=0 means.');
        $this->assertSame(0x031eaee7, $header['checksum']);
        $this->assertSame(5108, $header['packageLen']);
    }

    public function test_a_short_staging_header_is_refused_rather_than_guessed_at(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('expected 17');

        BufferedReader::parseHeader("\x00\x01\x02");
    }

    public function test_only_prepare_data_counts_as_staged(): void
    {
        $this->assertTrue(BufferedReader::isStaged(Command::REPLY_PREPARE_DATA));
        $this->assertFalse(BufferedReader::isStaged(Command::REPLY_OK));
        $this->assertFalse(BufferedReader::isStaged(Command::REPLY_ERROR));
    }

    /**
     * The CRC-32 in the header is what makes a staged read self-verifying, so the
     * fixture pair must actually agree. If this ever fails, the fixture generator
     * and the reader have drifted apart and no staged read can be trusted.
     */
    public function test_the_synthetic_fixture_pair_agrees_on_its_checksum(): void
    {
        $payload = $this->fixture('c3-transaction-records-synthetic.bin');
        $header = BufferedReader::parseHeader($this->fixture('c3-prepare-data-synthetic.bin'));

        $this->assertSame(strlen($payload), $header['datalen']);
        $this->assertSame(crc32($payload), $header['checksum']);
    }

    /*
     * ---- The catalogue ------------------------------------------------------
     */

    public function test_the_real_catalogue_parses_into_tables_and_field_indexes(): void
    {
        $catalogue = Catalogue::parse($this->fixture('c3-datatable-cfg-tf1700.txt'));

        $this->assertTrue($catalogue->has('transaction'));
        $this->assertSame(5, $catalogue->indexOf('transaction'));
        $this->assertSame([1, 2, 3, 4, 5, 6, 7], $catalogue->fieldIndexes('transaction'));
        $this->assertSame(['index' => 7, 'type' => 'i'], $catalogue->fields('transaction')['Time_second']);

        // A template field is a blob, and the codec must know that before it decodes.
        $this->assertSame('b', $catalogue->fields('templatev10')['Template']['type']);
    }

    /**
     * Table indexes are READ, never hard-coded: the inBIO460 reports 12 tables and
     * the TF1700 reports 11, so a constant would address the wrong table on one.
     */
    public function test_asking_for_a_table_the_panel_does_not_have_says_what_it_does_have(): void
    {
        $catalogue = Catalogue::parse($this->fixture('c3-datatable-cfg-tf1700.txt'));

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('transaction');

        $catalogue->fields('fingervein');
    }

    /*
     * ---- Records ------------------------------------------------------------
     */

    public function test_records_decode_with_the_inline_header_present(): void
    {
        $catalogue = Catalogue::parse($this->fixture('c3-datatable-cfg-tf1700.txt'));

        $rows = RecordCodec::decode(
            $this->fixture('c3-transaction-records-synthetic.bin'),
            $catalogue->indexOf('transaction'),
            $catalogue->fieldIndexes('transaction'),
            $catalogue->fields('transaction'),
        );

        $this->assertCount(5, $rows);
        $this->assertSame(
            ['Cardno', 'Pin', 'Verified', 'DoorID', 'EventType', 'InOutState', 'Time_second'],
            array_keys($rows[0]),
        );
        $this->assertSame(11111111, $rows[1]['Cardno']);
        $this->assertSame(1001, $rows[1]['Pin']);
    }

    /**
     * Whether a STAGED payload repeats the inline header is documented nowhere, so
     * the codec detects it. Reading a record stream one byte out of phase produces
     * rows that look entirely real, which is the exact failure rule 10 is about.
     */
    public function test_records_decode_identically_with_the_header_absent(): void
    {
        $catalogue = Catalogue::parse($this->fixture('c3-datatable-cfg-tf1700.txt'));
        $whole = $this->fixture('c3-transaction-records-synthetic.bin');

        $withHeader = RecordCodec::decode(
            $whole,
            5,
            $catalogue->fieldIndexes('transaction'),
            $catalogue->fields('transaction'),
        );
        $headerless = RecordCodec::decode(
            substr($whole, 9),
            5,
            $catalogue->fieldIndexes('transaction'),
            $catalogue->fields('transaction'),
        );

        $this->assertSame($withHeader, $headerless);
    }

    /** A truncated final record is dropped, never emitted with zeroed tail fields. */
    public function test_a_partial_trailing_record_is_not_emitted(): void
    {
        $catalogue = Catalogue::parse($this->fixture('c3-datatable-cfg-tf1700.txt'));
        $whole = $this->fixture('c3-transaction-records-synthetic.bin');

        $rows = RecordCodec::decode(
            substr($whole, 0, strlen($whole) - 3),
            5,
            $catalogue->fieldIndexes('transaction'),
            $catalogue->fields('transaction'),
        );

        $this->assertCount(4, $rows);
    }

    /*
     * ---- Timestamps ---------------------------------------------------------
     */

    /**
     * The value the TF1700 actually returned as its first transaction record, and
     * the date ZKTeco's own software recorded for that same event. Two independent
     * decoders agreeing to the second is what makes this CONFIRMED.
     */
    public function test_the_real_first_tf1700_record_decodes_to_the_date_the_vendor_recorded(): void
    {
        $moment = Timestamp::decode(823109291, '+03:00');

        $this->assertNotNull($moment);
        $this->assertSame('2025-08-10 17:28:11', $moment->format('Y-m-d H:i:s'));
        $this->assertSame('+03:00', $moment->format('P'), 'Device LOCAL time, anchored by the caller.');
    }

    public function test_a_timestamp_round_trips(): void
    {
        $moment = new \DateTimeImmutable('2026-09-14 14:46:03', new \DateTimeZone('+03:00'));

        $this->assertSame(
            '2026-09-14 14:46:03',
            Timestamp::decode(Timestamp::encode($moment), '+03:00')->format('Y-m-d H:i:s'),
        );
    }

    /**
     * Rule 10: "would not decode" must never render as an epoch or as midnight. The
     * 31-day radix can address a day the month does not have, which is a device with
     * an unset clock — not something to round into a plausible date.
     */
    public function test_an_undecodable_stamp_returns_null_rather_than_a_plausible_date(): void
    {
        $this->assertNull(Timestamp::decode(0));
        $this->assertNull(Timestamp::decode(-1));

        // 31 February, reachable in this encoding and real on a panel with a bad clock.
        $impossible = ((2026 - 2000) * 12 + 1) * 31 + 30;
        $this->assertNull(Timestamp::decode(((($impossible * 24) + 9) * 60) * 60));
    }

    /*
     * ---- Model selection (rule 15) ------------------------------------------
     */

    /**
     * Selection happens once, by model, at construction. Nothing downstream branches
     * on a model again — which is the whole reason these classes exist separately.
     */
    public function test_each_known_model_selects_its_own_implementation(): void
    {
        $this->assertInstanceOf(InBio460::class, PanelModelFactory::for('inBIO460'));
        $this->assertInstanceOf(Tf1700::class, PanelModelFactory::for('TF1700'));

        // Operator-entered names carry suffixes and casing.
        $this->assertInstanceOf(Tf1700::class, PanelModelFactory::for('tf1700/ID'));
        $this->assertInstanceOf(InBio460::class, PanelModelFactory::for('ZKTeco inBio460 Pro'));
    }

    /**
     * An unknown panel is not "supported" — it gets the behaviour proven safe on
     * every panel we have read, and keeps its own name so a trace says what it was.
     */
    public function test_an_unknown_panel_falls_back_without_pretending_to_be_known(): void
    {
        $model = PanelModelFactory::for('C3-400');

        $this->assertInstanceOf(GenericPanel::class, $model);
        $this->assertSame('C3-400', $model->name());
        $this->assertSame('unknown C3 panel', PanelModelFactory::for(null)->name());
    }

    /*
     * ---- Capability honesty (rules 9 and 10) --------------------------------
     */

    /**
     * A panel nobody has read confirms NOTHING — not even that it answers a ping,
     * which would be a claim about a device that has never replied to us.
     *
     * Rule 10 applied to hardware: a level confirmed on the inBIO460 says nothing
     * about a C3-400 until a C3-400 has answered.
     */
    public function test_an_unread_panel_confirms_nothing(): void
    {
        $levels = PanelModelFactory::for('C3-400')->capabilities()->toArray();

        $this->assertNotContains(
            Capability::CONFIRMED,
            $levels,
            'A panel this library has never been run against must not confirm anything.',
        );
    }

    /**
     * A panel we HAVE read confirms only what was actually exercised.
     *
     * Reading the transaction table does not confirm reading the roster, even
     * though the same code path would do it — "the same code should work" is not
     * the same as "it worked".
     */
    public function test_a_read_panel_confirms_only_what_was_actually_exercised(): void
    {
        foreach ([PanelModelFactory::for('inBIO460'), PanelModelFactory::for('TF1700')] as $model) {
            $caps = $model->capabilities();

            $this->assertSame(Capability::CONFIRMED, $caps->level(Capability::PING), $model->name());
            $this->assertSame(Capability::CONFIRMED, $caps->level(Capability::DEVICE_INFO), $model->name());
            $this->assertSame(Capability::CONFIRMED, $caps->level(Capability::ATTENDANCE_READ), $model->name());

            // Never run against either panel.
            $this->assertSame(Capability::IMPLEMENTED, $caps->level(Capability::USER_READ), $model->name());
        }
    }

    /**
     * Every write stays hidden.
     *
     * Rule 9: the UI hides anything that is not confirmed or implemented, and rule
     * 16 forbids probing a write against a live entrance. The door relay in
     * particular must never drift up to a level the UI would offer — that is a
     * button that opens a real door.
     */
    public function test_no_write_capability_is_ever_offered(): void
    {
        $writes = [
            Capability::USER_WRITE,
            Capability::USER_DELETE,
            Capability::FINGERPRINT_ENROLL,
            Capability::TEMPLATE_UPLOAD,
            Capability::TEMPLATE_DELETE,
            Capability::ATTENDANCE_CLEAR,
            Capability::RELAY,
        ];

        foreach ([PanelModelFactory::for('inBIO460'), PanelModelFactory::for('TF1700'), PanelModelFactory::for(null)] as $model) {
            foreach ($writes as $write) {
                $this->assertNotSame(
                    Capability::CONFIRMED,
                    $model->capabilities()->level($write),
                    "{$model->name()} must not confirm the write capability {$write}.",
                );
                $this->assertNotSame(
                    Capability::IMPLEMENTED,
                    $model->capabilities()->level($write),
                    "{$model->name()} must not offer the write capability {$write}.",
                );
            }
        }
    }
}
