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

namespace Promoseven\Biometric\C3\Capability;

use Promoseven\Biometric\Capability\Capability;
use Promoseven\Biometric\C3\Model\PanelModelFactory;
use Promoseven\Biometric\Capability\CapabilitySet;

/**
 * What a C3 / PullSDK panel can do, per model.
 *
 * Rule 9: four levels, and the UI HIDES anything that is not confirmed or
 * implemented. Rule 15: defaults() describes a panel family baseline and is NOT
 * edited to make room for a model — a model that differs gets its own factory
 * method here and, where behaviour differs, its own class under C3\Model.
 *
 * Rule 10 applied to hardware: a level confirmed on the inBIO460 is UNKNOWN on any
 * other panel until that panel has answered. Nothing here is promoted by analogy.
 *
 * NOTE the whole write half is NOT_IMPLEMENTED rather than UNKNOWN. That is a
 * deliberate distinction: we have read the vendor SDK and we know exactly which
 * commands would do it — the write vocabulary, the field lists, even the teardown
 * order. We have simply not built or probed any of it, and rule 16 forbids probing
 * a write against a live entrance without the owner's go-ahead. "This library does
 * not do it" is the honest level; "never probed" would be false.
 */
final class C3Capabilities
{
    /**
     * The family baseline: what any C3 panel is assumed to do until it is read.
     *
     * Everything readable is IMPLEMENTED rather than CONFIRMED here, because the
     * baseline describes the family and confirmation is per unit.
     */
    public static function defaults(): CapabilitySet
    {
        return CapabilitySet::fromArray([
            Capability::PING => Capability::IMPLEMENTED,
            Capability::DEVICE_INFO => Capability::IMPLEMENTED,
            Capability::ATTENDANCE_READ => Capability::IMPLEMENTED,
            Capability::USER_READ => Capability::IMPLEMENTED,

            // Built and understood, but never exercised against hardware.
            /*
             * The panel publishes a `templatev10` table and this library now reads it
             * — but a level is CONFIRMED per MODEL, never per family (rule 10). The
             * inBIO460 and the TF1700 promote these in their own files; a panel nobody
             * has run against inherits IMPLEMENTED and claims nothing.
             */
            Capability::TEMPLATE_TABLE_READ => Capability::IMPLEMENTED,
            Capability::TEMPLATE_BLOB_READ => Capability::IMPLEMENTED,

            // Deliberately unbuilt. See the class note: known, not guessed at.
            Capability::USER_WRITE => Capability::NOT_IMPLEMENTED,
            Capability::USER_DELETE => Capability::NOT_IMPLEMENTED,
            Capability::USER_RENUMBER => Capability::NOT_IMPLEMENTED,
            // The C3 `user` table has a Privilege field; nothing writes it (2.14.0).
            Capability::USER_PRIVILEGE => Capability::NOT_IMPLEMENTED,
            Capability::USER_DISABLE => Capability::NOT_IMPLEMENTED,
            Capability::CARD_WRITE => Capability::NOT_IMPLEMENTED,
            Capability::PASSWORD_WRITE => Capability::NOT_IMPLEMENTED,
            Capability::CARD_ENROLL => Capability::NOT_IMPLEMENTED,
            Capability::FINGERPRINT_ENROLL => Capability::NOT_IMPLEMENTED,
            Capability::TEMPLATE_DELETE => Capability::NOT_IMPLEMENTED,
            Capability::TEMPLATE_DOWNLOAD => Capability::NOT_IMPLEMENTED,
            Capability::TEMPLATE_UPLOAD => Capability::NOT_IMPLEMENTED,
            Capability::TEMPLATE_SLOT_PROBE => Capability::NOT_IMPLEMENTED,
            Capability::ATTENDANCE_CLEAR => Capability::NOT_IMPLEMENTED,
            Capability::DEVICE_WIPE => Capability::NOT_IMPLEMENTED,
            Capability::SET_TIME => Capability::NOT_IMPLEMENTED,
            Capability::RESTART => Capability::NOT_IMPLEMENTED,

            // The panel pushes nothing this library listens for. The vendor polls
            // GetRTLog on a one-second thread; we have not built that.
            Capability::ATTENDANCE_REALTIME => Capability::NOT_IMPLEMENTED,

            // The panel plainly HAS these — it is an access-control panel with
            // timezone, holiday and authorisation tables, and a door relay. We have
            // never exercised them, and a door relay is not something to probe on a
            // live entrance (rule 16). Unknown is the truthful level, and the UI
            // hides it.
            Capability::CARD_READ => Capability::UNKNOWN,
            // The user table's Password field; read with every roster read, but a
            // panel nobody has compared against claims nothing more (2.13.0).
            Capability::PASSWORD_READ => Capability::IMPLEMENTED,
            Capability::GET_TIME => Capability::UNKNOWN,
            Capability::VERIFY_MODE => Capability::UNKNOWN,
            Capability::ACCESS_SCHEDULES => Capability::UNKNOWN,
            Capability::ANTI_PASSBACK => Capability::UNKNOWN,
            Capability::DURESS => Capability::UNKNOWN,
            Capability::RELAY => Capability::UNKNOWN,
        ]);
    }

    /**
     * The set for a named model.
     *
     * Delegates to the model's own class, because a capability level is a claim
     * about one piece of hardware and belongs in the file named for it (rule 15).
     * There is deliberately no match statement on model names here — that is what
     * the factory is for, and duplicating it would give a model two places to
     * disagree with itself.
     */
    public static function forModel(?string $model): CapabilitySet
    {
        return PanelModelFactory::for($model)->capabilities();
    }
}
