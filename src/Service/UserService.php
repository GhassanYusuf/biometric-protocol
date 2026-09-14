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

namespace Promoseven\Biometric\Service;

use Promoseven\Biometric\Client\DeviceClient;
use Promoseven\Biometric\Codec\TemplateCodec;
use Promoseven\Biometric\Codec\UserCodec;
use Promoseven\Biometric\Exception\ProtocolException;
use Promoseven\Biometric\Exception\VerificationException;
use Promoseven\Biometric\Value\DeviceUser;

/**
 * User records on the device: read, create, update, delete.
 *
 * Every write here reads back and confirms. That is not belt-and-braces — this
 * firmware family is CONFIRMED to answer ACK_OK and then silently drop the change.
 * A method that returned on the acknowledgement alone would report success for
 * writes that never happened.
 */
final class UserService
{
    public function __construct(private readonly DeviceClient $client)
    {
    }

    /**
     * Every user on the device.
     *
     * @param bool $withFingerprints also read the template table so each user
     *                               carries their filled slots. One extra bulk
     *                               read; slots come back null if it cannot be
     *                               decoded, never as an empty list.
     * @return list<DeviceUser>
     */
    public function all(bool $withFingerprints = false): array
    {
        $records = UserCodec::decode($this->client->readUsersRaw());

        $slotsByUserId = [];
        if ($withFingerprints) {
            $slotsByUserId = TemplateCodec::slotsByUserId(
                TemplateCodec::decode($this->client->readTemplatesRaw()),
                $records,
            );
        }

        $users = [];
        foreach ($records as $record) {
            if (! isset($record['uid'])) {
                continue; // undecodable raw record
            }

            $userId = (string) $record['user_id'];

            $users[] = DeviceUser::fromRecord(
                $record,
                $withFingerprints ? ($slotsByUserId[$userId] ?? ($slotsByUserId === [] ? null : [])) : null,
            );
        }

        return $users;
    }

    /** One user by their device user id, or null. */
    public function find(string $userId, bool $withFingerprints = false): ?DeviceUser
    {
        foreach ($this->all($withFingerprints) as $user) {
            if ($user->userId === $userId) {
                return $user;
            }
        }

        return null;
    }

    public function exists(string $userId): bool
    {
        return UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId) !== null;
    }

    /**
     * Creates or updates a user, then confirms by reading back.
     *
     * Preserves the card and privilege already on the device unless explicitly
     * overridden. CONFIRMED HAZARD: writing a user record with the default card 0
     * silently WIPES an existing card and demotes an admin to a plain user, because
     * both live in the same record. Callers that only mean to change a name must
     * not have to know that.
     */
    public function save(
        string $userId,
        string $name,
        ?int $privilege = null,
        ?int $cardNumber = null,
    ): DeviceUser {
        $records = UserCodec::decode($this->client->readUsersRaw());
        $existing = UserCodec::find($records, $userId);

        $uid = $existing['uid'] ?? UserCodec::nextFreeUid($records);
        $keepPrivilege = $privilege ?? (int) ($existing['privilege'] ?? 0);
        $keepCard = $cardNumber ?? (int) ($existing['card_number'] ?? 0);

        $this->client->writeUser($uid, $userId, $name, $keepPrivilege, $keepCard);

        $confirmed = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($confirmed === null) {
            throw new VerificationException(
                "The device accepted the write for {$userId} but the record did not appear when read back. "
                . 'This firmware intermittently drops writes — retry, and if it persists the device may need a power cycle.',
                ['user_id' => $userId, 'uid' => $uid],
            );
        }

        return DeviceUser::fromRecord($confirmed);
    }

    /**
     * Guarantees a record exists, creating one if needed, and returns it.
     *
     * This is the precondition for any capture: a template or card attaches to an
     * EXISTING record, so enrolling for somebody the device has never heard of is
     * refused. Calling this first turns that two-step dance into one operation.
     */
    public function ensureExists(string $userId, string $name, ?int $cardNumber = null): DeviceUser
    {
        $existing = $this->find($userId);

        if ($existing !== null) {
            return $existing;
        }

        return $this->save($userId, $name, 0, $cardNumber);
    }

    /**
     * Deletes a user entirely — record, templates and card together.
     *
     * Confirms by reading back, for the same reason as save().
     */
    public function delete(string $userId): void
    {
        $existing = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($existing === null) {
            throw new ProtocolException("User {$userId} is not on the device.", ['user_id' => $userId]);
        }

        $this->client->deleteUser((int) $existing['uid']);

        $stillThere = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($stillThere !== null) {
            throw new VerificationException(
                "The device accepted the delete for {$userId} but the record is still there when read back. "
                . 'This firmware intermittently drops writes — retry, and if it persists the device may need a power cycle.',
                ['user_id' => $userId],
            );
        }
    }

    /**
     * Sets a user's card number, keeping their name, privilege and templates.
     *
     * @param int|null $cardNumber null clears the card
     */
    public function setCard(string $userId, ?int $cardNumber): DeviceUser
    {
        $existing = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($existing === null) {
            throw new ProtocolException("User {$userId} is not on the device.", ['user_id' => $userId]);
        }

        return $this->save(
            $userId,
            (string) ($existing['name'] ?? ''),
            (int) ($existing['privilege'] ?? 0),
            $cardNumber ?? 0,
        );
    }

    /**
     * Disables a user without deleting them.
     *
     * NOT SUPPORTED as a first-class device feature: the standalone protocol has no
     * "suspend" flag on a user record. The honest options are deleting the record
     * (losing their templates) or removing their credentials while keeping the
     * record — this does the latter by clearing the card, which stops badge access
     * but does NOT stop fingerprint access.
     *
     * Callers that need real suspension should delete templates too, and should
     * treat suspension as an app-level concept enforced on import rather than a
     * device capability. See docs/device-capabilities.md.
     */
    public function softDisable(string $userId): DeviceUser
    {
        return $this->setCard($userId, null);
    }
}
