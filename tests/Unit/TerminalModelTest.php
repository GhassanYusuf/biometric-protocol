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
use Promoseven\Biometric\Capability\CapabilitySet;
use Promoseven\Biometric\Model\F18;
use Promoseven\Biometric\Model\F22;
use Promoseven\Biometric\Model\GenericTerminal;
use Promoseven\Biometric\Model\TerminalModelFactory;
use Promoseven\Biometric\Model\UA300;

/**
 * Per-model capability sets for the standalone family (2.11.0): a method proven on
 * one model is never offered on another by inheritance.
 */
final class TerminalModelTest extends TestCase
{
    public function test_each_model_is_selected_by_its_own_file(): void
    {
        $this->assertInstanceOf(F18::class, TerminalModelFactory::for('F18'));
        $this->assertInstanceOf(F18::class, TerminalModelFactory::for('F18/ID'));
        $this->assertInstanceOf(F22::class, TerminalModelFactory::for('F22/ID'));
        $this->assertInstanceOf(UA300::class, TerminalModelFactory::for('UA300/ID'));
        $this->assertInstanceOf(GenericTerminal::class, TerminalModelFactory::for(null));
        $this->assertInstanceOf(GenericTerminal::class, TerminalModelFactory::for('K40'));
        $this->assertInstanceOf(GenericTerminal::class, TerminalModelFactory::for('F180'));
    }

    public function test_the_f18_set_is_the_reference_baseline_unchanged(): void
    {
        $this->assertSame(CapabilitySet::defaults()->toArray(), (new F18)->capabilities()->toArray());
    }

    public function test_writes_proven_only_on_the_f18_are_not_offered_on_the_f22(): void
    {
        $f22 = (new F22)->capabilities();

        foreach ([Capability::USER_RENUMBER, Capability::TEMPLATE_DELETE,
            Capability::CARD_ENROLL, Capability::FINGERPRINT_ENROLL] as $capability) {
            $this->assertFalse($f22->supports($capability), "{$capability} must not be offered on the F22 until it runs there");
        }

        // Run on the F22 itself 2026-10-11 (On The Road): offered, not yet confirmed.
        $this->assertSame(Capability::IMPLEMENTED, $f22->level(Capability::TEMPLATE_UPLOAD));

        // What the F22 has actually done stays available.
        $this->assertTrue($f22->isConfirmed(Capability::USER_WRITE));
        $this->assertTrue($f22->isConfirmed(Capability::USER_DELETE));
        $this->assertTrue($f22->isConfirmed(Capability::TEMPLATE_BLOB_READ));
    }

    /**
     * The UA300 (Catering) inherits no F18 write. 2.17.0 offered none; 2.18.0 offers the
     * ones its write test ran, and still none of the others.
     */
    public function test_the_ua300_offers_only_the_writes_run_on_it(): void
    {
        $ua300 = (new UA300)->capabilities();

        // 2.18.0, the write test on Catering 2026-10-26.
        $this->assertTrue($ua300->isConfirmed(Capability::USER_WRITE));
        foreach ([Capability::USER_DELETE, Capability::CARD_WRITE, Capability::TEMPLATE_UPLOAD] as $write) {
            $this->assertSame(Capability::IMPLEMENTED, $ua300->level($write), "{$write} ran once, with one unexplained loss");
        }

        foreach ([Capability::USER_PRIVILEGE, Capability::PASSWORD_WRITE, Capability::SET_TIME,
            Capability::ATTENDANCE_CLEAR, Capability::DEVICE_WIPE] as $write) {
            $this->assertFalse($ua300->supports($write), "{$write} must not be offered on the UA300 until it runs there");
        }

        foreach ([Capability::USER_READ, Capability::CARD_READ, Capability::ATTENDANCE_READ, Capability::TEMPLATE_BLOB_READ] as $read) {
            $this->assertTrue($ua300->isConfirmed($read), "{$read} ran on Catering");
        }

        // Decoded on two of five roster reads only.
        $this->assertSame(Capability::IMPLEMENTED, $ua300->level(Capability::TEMPLATE_TABLE_READ));
    }

    public function test_an_unknown_model_claims_no_write_and_confirms_nothing(): void
    {
        $set = TerminalModelFactory::for('K40')->capabilities();

        foreach ([Capability::USER_WRITE, Capability::USER_DELETE, Capability::CARD_WRITE, Capability::TEMPLATE_UPLOAD] as $write) {
            $this->assertFalse($set->supports($write));
        }
        $this->assertTrue($set->supports(Capability::USER_READ));
        $this->assertFalse($set->isConfirmed(Capability::USER_READ));
    }
}
