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

namespace Promoseven\Biometric\Value;

/** One user record as the device holds it. */
final class DeviceUser
{
    public function __construct(
        /** Device-internal slot number. Stable per device, not portable between devices. */
        public readonly int $uid,
        /** The "PIN" / user id the operator sees — what attendance records key on. */
        public readonly string $userId,
        public readonly string $name,
        public readonly int $privilege = 0,
        /**
         * A ZKTeco user record holds exactly ONE card field, so there is no such
         * thing as a second card for a user. Null when unset.
         */
        public readonly ?int $cardNumber = null,
        /** Filled finger slots, or null when the template table could not be read. */
        public readonly ?array $fingerSlots = null,
        /**
         * The keypad password: '' when the device holds none, null when this read did
         * not carry the field (2.13.0). A door credential — deliberately left out of
         * toArray(), which says only whether there is one.
         */
        public readonly ?string $password = null,
    ) {
    }

    public function hasPassword(): ?bool
    {
        return $this->password === null ? null : $this->password !== '';
    }

    /** @param array<string,mixed> $record decoded by UserCodec */
    public static function fromRecord(array $record, ?array $fingerSlots = null): self
    {
        $card = (int) ($record['card_number'] ?? 0);

        return new self(
            uid: (int) $record['uid'],
            userId: (string) $record['user_id'],
            name: (string) ($record['name'] ?? ''),
            privilege: (int) ($record['privilege'] ?? 0),
            cardNumber: $card > 0 ? $card : null,
            fingerSlots: $fingerSlots,
            password: array_key_exists('password', $record) ? (string) $record['password'] : null,
        );
    }

    public function hasCard(): bool
    {
        return $this->cardNumber !== null;
    }

    /**
     * 0xFFFFFFFF — all bits set.
     *
     * OBSERVED on real hardware: one user carried 4294967295. On many firmwares
     * that is the "no card" marker rather than a real number, so callers should
     * surface it as suspect rather than trusting it.
     */
    public function cardLooksLikeSentinel(): bool
    {
        return $this->cardNumber === 0xFFFFFFFF;
    }

    public function fingerprintCount(): ?int
    {
        return $this->fingerSlots === null ? null : count($this->fingerSlots);
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'uid' => $this->uid,
            'user_id' => $this->userId,
            'name' => $this->name,
            'privilege' => $this->privilege,
            'card_number' => $this->cardNumber,
            'has_card' => $this->hasCard(),
            'card_suspect' => $this->cardLooksLikeSentinel(),
            'finger_slots' => $this->fingerSlots,
            'fingerprint_count' => $this->fingerprintCount(),
            'has_password' => $this->hasPassword(),
        ];
    }
}
