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

namespace Promoseven\Biometric\Capability;

/**
 * The catalogue of things a device might be able to do, and how sure we are.
 *
 * Support levels are deliberately four, not two. "Supported / unsupported" cannot
 * express the state most of this protocol is actually in, and pretending otherwise
 * is how a UI ends up offering a button that returns a 502.
 */
final class Capability
{
    // --- Identity and liveness ---
    public const PING = 'device.ping';
    public const DEVICE_INFO = 'device.info';
    public const GET_TIME = 'device.time.read';
    public const SET_TIME = 'device.time.write';
    public const RESTART = 'device.restart';

    // --- Users ---
    public const USER_READ = 'user.read';
    public const USER_WRITE = 'user.write';
    public const USER_DELETE = 'user.delete';
    public const USER_DISABLE = 'user.disable';
    /** Move a user to a different user id (PIN), keeping uid, card and templates. */
    public const USER_RENUMBER = 'user.renumber';
    /**
     * Set a user's privilege on the terminal — on the ZKTeco standalones, normal user
     * (0) or administrator (14), who may open the terminal's menu. 2.14.0.
     */
    public const USER_PRIVILEGE = 'user.privilege';

    // --- Cards ---
    public const CARD_READ = 'card.read';
    public const CARD_WRITE = 'card.write';
    public const CARD_ENROLL = 'card.enroll';

    // The keypad password (2.13.0). A door credential like the card, so it is read and
    // written as one, and never printed.
    public const PASSWORD_READ = 'password.read';
    public const PASSWORD_WRITE = 'password.write';

    // --- Fingerprints ---
    public const FINGERPRINT_ENROLL = 'fingerprint.enroll';
    public const TEMPLATE_TABLE_READ = 'template.table.read';
    public const TEMPLATE_SLOT_PROBE = 'template.slot.probe';
    public const TEMPLATE_DELETE = 'template.delete';
    /**
     * Reads every stored template's BYTES out of the template table.
     *
     * Distinct from TEMPLATE_DOWNLOAD, which is the separate per-slot command. This
     * one needs no new command at all: the blobs have always ridden along in the table
     * TEMPLATE_TABLE_READ already fetches.
     */
    public const TEMPLATE_BLOB_READ = 'template.blob.read';

    public const TEMPLATE_DOWNLOAD = 'template.download';
    public const TEMPLATE_UPLOAD = 'template.upload';

    // --- Attendance ---
    public const ATTENDANCE_READ = 'attendance.read';
    public const ATTENDANCE_REALTIME = 'attendance.realtime';
    public const ATTENDANCE_CLEAR = 'attendance.clear';

    // --- Access control ---
    public const VERIFY_MODE = 'access.verify_mode';
    public const ACCESS_SCHEDULES = 'access.schedules';
    public const ANTI_PASSBACK = 'access.anti_passback';
    public const DURESS = 'access.duress';
    public const RELAY = 'access.relay';

    /**
     * CONFIRMED — exercised against real hardware in this project. Safe to expose.
     */
    public const CONFIRMED = 'confirmed';

    /**
     * IMPLEMENTED — code exists and follows a documented protocol, but success was
     * never observed on hardware. Expose behind a warning; expect failures.
     */
    public const IMPLEMENTED = 'implemented';

    /**
     * NOT IMPLEMENTED — this library does not do it yet. Hide the action.
     */
    public const NOT_IMPLEMENTED = 'not_implemented';

    /**
     * UNKNOWN — never probed on this device. Hide until resolved.
     */
    public const UNKNOWN = 'unknown';

    private function __construct()
    {
    }

    /** @return list<string> every capability key */
    public static function all(): array
    {
        $keys = [];

        foreach ((new \ReflectionClass(self::class))->getConstants() as $name => $value) {
            if (is_string($value) && str_contains($value, '.')) {
                $keys[] = $value;
            }
        }

        return $keys;
    }

    /**
     * Human-readable explanation of a support level, for operator-facing UI.
     */
    public static function describe(string $level): string
    {
        return match ($level) {
            self::CONFIRMED => 'Verified working on this device family.',
            self::IMPLEMENTED => 'Implemented from protocol documentation but never confirmed on hardware — may fail.',
            self::NOT_IMPLEMENTED => 'Not implemented by this library.',
            default => 'Not yet probed on this device.',
        };
    }

    /** Whether a UI should offer the action at all. */
    public static function isUsable(string $level): bool
    {
        return $level === self::CONFIRMED || $level === self::IMPLEMENTED;
    }
}
