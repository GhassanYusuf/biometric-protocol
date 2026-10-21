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
use Promoseven\Biometric\Protocol\Packet;
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
    /** ZKTeco standalone privilege values: a normal user, and an administrator. */
    public const PRIVILEGE_USER = 0;
    public const PRIVILEGE_ADMIN = 14;

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
        ?string $password = null,
    ): DeviceUser {
        $records = UserCodec::decode($this->client->readUsersRaw());
        $existing = UserCodec::find($records, $userId);

        $uid = $existing['uid'] ?? UserCodec::nextFreeUid($records);
        $keepPrivilege = $privilege ?? (int) ($existing['privilege'] ?? 0);
        $keepCard = $cardNumber ?? (int) ($existing['card_number'] ?? 0);
        /*
         * The keypad password, kept like the card (2.13.0). Before this the record was
         * rebuilt with it zeroed, so every name push and card write ERASED a password
         * set at the terminal — OBSERVED 2026-10-12: IT ROOM (F18) lacked one the host
         * app still held. Null keeps the device's; '' clears it.
         */
        $keepPassword = $password ?? (string) ($existing['password'] ?? '');

        $this->client->writeUser($uid, $userId, $name, $keepPrivilege, $keepCard, $keepPassword);

        $confirmed = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($confirmed === null) {
            throw new VerificationException(
                "The device accepted the write for {$userId} but the record did not appear when read back. "
                . 'This firmware intermittently drops writes — retry, and if it persists the device may need a power cycle.',
                ['user_id' => $userId, 'uid' => $uid],
            );
        }

        // Never the value in the message: it is a door credential.
        if (($confirmed['password'] ?? '') !== $keepPassword) {
            throw new VerificationException(
                "The device accepted the write for {$userId} but its keypad password does not read back as written.",
                ['user_id' => $userId, 'uid' => $uid],
            );
        }

        return DeviceUser::fromRecord($confirmed);
    }

    /**
     * Sets an EXISTING user's privilege — 0 normal user, 14 administrator (may open
     * the terminal's menu) — keeping name, card and keypad password, then confirms the
     * privilege on read-back: save() itself only checks the record and the password.
     *
     * IMPLEMENTED 2.14.0, never run on hardware (Capability::USER_PRIVILEGE). Refuses a
     * user that is not on the device rather than creating one.
     */
    public function setPrivilege(string $userId, int $privilege): DeviceUser
    {
        if (! in_array($privilege, [self::PRIVILEGE_USER, self::PRIVILEGE_ADMIN], true)) {
            throw new ProtocolException("Privilege {$privilege} is not one this library writes (0 or 14).", ['user_id' => $userId]);
        }

        $existing = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $userId);

        if ($existing === null) {
            throw new ProtocolException("User {$userId} is not on the device.", ['user_id' => $userId]);
        }

        $user = $this->save($userId, (string) $existing['name'], $privilege);

        if ($user->privilege !== $privilege) {
            throw new VerificationException(
                "The device accepted the privilege change for {$userId} but reads back {$user->privilege}, not {$privilege}.",
                ['user_id' => $userId, 'uid' => $user->uid],
            );
        }

        return $user;
    }

    /**
     * Moves an existing user to a different user id ("PIN"), keeping the record.
     *
     * HOW: the SAME uid is rewritten with the new user id, name, privilege and card
     * carried over from the record just read. Templates are keyed by uid in the
     * template table (TemplateCodec::slotsByUid), so on the data model they follow the
     * record — nothing is deleted and nothing is re-uploaded. Delete-and-recreate is
     * not an option: template upload is NOT_IMPLEMENTED, so it would destroy every
     * fingerprint.
     *
     * EXPERIMENTAL — written 2026-09-23, never yet confirmed on hardware. Whether a
     * firmware keeps templates when a uid's user id changes is exactly what is
     * unproven, so this VERIFIES IT rather than assuming it:
     *
     *   1. the old id must exist and the new id must be free on the device;
     *   2. after the write, the new id must be on the SAME uid and the old id gone —
     *      a firmware that keys writes by user id would instead add a second record,
     *      and that is reported, not hidden;
     *   3. when the template table decoded before the write, every slot that was
     *      filled must still be filled under the new id afterwards. If one is not,
     *      this throws — the operator must know at once, because only the employee
     *      presenting the finger again can repair it.
     *
     * When the template table would not decode beforehand, the fingers cannot be
     * checked; the returned user's fingerSlots is then null, never [] (unknown is
     * not "none").
     */
    public function renumber(string $fromUserId, string $toUserId): DeviceUser
    {
        if ($fromUserId === $toUserId) {
            throw new ProtocolException('Renumber needs two different user ids.', ['user_id' => $fromUserId]);
        }

        $records = UserCodec::decode($this->client->readUsersRaw());
        $existing = UserCodec::find($records, $fromUserId);

        if ($existing === null) {
            throw new ProtocolException("User {$fromUserId} is not on the device.", ['user_id' => $fromUserId]);
        }

        if (($occupant = UserCodec::find($records, $toUserId)) !== null) {
            throw new ProtocolException(
                "User id {$toUserId} is already held by " . ($occupant['name'] ?? 'someone') . ' on this device.',
                ['from' => $fromUserId, 'to' => $toUserId, 'occupant_uid' => $occupant['uid'] ?? null],
            );
        }

        $uid = (int) $existing['uid'];
        $before = TemplateCodec::slotsByUserId(TemplateCodec::decode($this->client->readTemplatesRaw()), $records);
        $slotsBefore = $before === [] ? null : ($before[$fromUserId] ?? []);

        try {
            $this->client->writeUser(
                $uid,
                $toUserId,
                (string) ($existing['name'] ?? ''),
                (int) ($existing['privilege'] ?? 0),
                (int) ($existing['card_number'] ?? 0),
            );
        } catch (ProtocolException $refused) {
            /*
             * OBSERVED 2026-09-23, ZKTeco F18 @ 192.168.7.62: uid 6, 960802797 →
             * 000000005 answered ACK_ERROR and the record was left exactly as it was.
             * Read back so the operator is told the truth about the record, not just
             * that the device said no.
             */
            $still = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $fromUserId);
            $intact = $still !== null && (int) $still['uid'] === $uid;

            throw new ProtocolException(
                "The device refused to change user id {$fromUserId} to {$toUserId} ({$refused->getMessage()}). "
                . ($intact
                    ? "Nothing was changed: {$fromUserId} is still on the device with its card and fingerprints."
                    : "Read the terminal's users before retrying — {$fromUserId} is no longer where it was."),
                ['from' => $fromUserId, 'to' => $toUserId, 'uid' => $uid, 'intact' => $intact],
            );
        }

        $after = UserCodec::decode($this->client->readUsersRaw());
        $moved = UserCodec::find($after, $toUserId);
        $stale = UserCodec::find($after, $fromUserId);

        if ($moved === null || (int) $moved['uid'] !== $uid || $stale !== null) {
            throw new VerificationException(
                "The device accepted moving {$fromUserId} to {$toUserId} but the read-back does not show it: "
                . ($moved === null ? "no record under {$toUserId}. " : '')
                . ($moved !== null && (int) $moved['uid'] !== $uid ? "{$toUserId} landed on uid {$moved['uid']}, not {$uid}. " : '')
                . ($stale !== null ? "{$fromUserId} is still on the device. " : '')
                . "Read the terminal's users before retrying.",
                ['from' => $fromUserId, 'to' => $toUserId, 'uid' => $uid],
            );
        }

        $slotsAfter = null;

        if ($slotsBefore !== null) {
            $map = TemplateCodec::slotsByUserId(TemplateCodec::decode($this->client->readTemplatesRaw()), $after);
            $slotsAfter = $map === [] ? null : ($map[$toUserId] ?? []);

            if ($slotsAfter === null && $slotsBefore !== []) {
                throw new VerificationException(
                    "Moved {$fromUserId} to {$toUserId}, but the fingerprint table would not decode afterwards, so it is "
                    . 'UNKNOWN whether their ' . count($slotsBefore) . ' fingerprint(s) survived. Check at the terminal.',
                    ['from' => $fromUserId, 'to' => $toUserId, 'uid' => $uid, 'slots_before' => $slotsBefore],
                );
            }

            $lost = $slotsAfter === null ? [] : array_values(array_diff($slotsBefore, $slotsAfter));

            if ($lost !== []) {
                throw new VerificationException(
                    "Moved {$fromUserId} to {$toUserId}, but fingerprint slot(s) " . implode(', ', $lost)
                    . ' are no longer on the device. The employee must enrol those fingers again at the terminal.',
                    ['from' => $fromUserId, 'to' => $toUserId, 'uid' => $uid, 'slots_before' => $slotsBefore, 'slots_after' => $slotsAfter],
                );
            }
        }

        return DeviceUser::fromRecord($moved, $slotsAfter);
    }

    /**
     * Moves a user to a different user id by DELETING the record and RE-UPLOADING it,
     * with every fingerprint template, under the new id.
     *
     * WHY THIS EXISTS. renumber() rewrites the same uid in place, and the F18 refuses
     * that outright (ACK_ERROR, 2026-09-23, IT Room — docs/device-capabilities.md).
     * The only other route is delete and re-create, which destroys fingerprints unless
     * the templates are written back. The template table already carries the blobs
     * (TemplateCodec::decodeWithBlobs, CONFIRMED on the F18), and pyzk documents the
     * command that writes a user and their templates together (SAVE_USERTEMPS). This
     * joins the two.
     *
     * EXPERIMENTAL — never run against hardware in this project. So it is built to
     * fail safe at every step:
     *
     *   1. Refuses before writing anything if the old id is missing, the new id is
     *      taken, the raw record cannot be isolated, or the template table would not
     *      decode (a copy that might be missing fingers is not a copy).
     *   2. Hands the complete snapshot — the device's own 72-byte record and every
     *      template — to $onSnapshot BEFORE the first write. If that callback throws,
     *      nothing is written. The caller keeps the snapshot until this returns.
     *   3. Deletes, re-uploads under the new id on the SAME uid, and reads back: the
     *      new id must be present on that uid, the old id gone, and every finger slot
     *      that was filled must be filled again.
     *   4. On any failure after the delete, re-uploads the ORIGINAL record and
     *      templates and verifies that, then throws saying which of the two happened.
     *
     * @param callable(array{uid:int,user_id:string,record:string,templates:list<array{fid:int,valid:int,template:string,sha1:string}>}):void|null $onSnapshot
     */
    public function renumberByReupload(string $fromUserId, string $toUserId, ?callable $onSnapshot = null): DeviceUser
    {
        if ($fromUserId === $toUserId) {
            throw new ProtocolException('Renumber needs two different user ids.', ['user_id' => $fromUserId]);
        }
        if (! preg_match('/^\d{1,9}$/', $toUserId)) {
            throw new ProtocolException("A user id must be 1 to 9 digits, got '{$toUserId}'.", ['to' => $toUserId]);
        }

        $rawUsers = $this->client->readUsersRaw();
        $records = UserCodec::decode($rawUsers);
        $existing = UserCodec::find($records, $fromUserId);

        if ($existing === null) {
            throw new ProtocolException("User {$fromUserId} is not on the device.", ['user_id' => $fromUserId]);
        }
        if (($occupant = UserCodec::find($records, $toUserId)) !== null) {
            throw new ProtocolException(
                "User id {$toUserId} is already held by " . ($occupant['name'] ?? 'someone') . ' on this device.',
                ['from' => $fromUserId, 'to' => $toUserId, 'occupant_uid' => $occupant['uid'] ?? null],
            );
        }

        $uid = (int) $existing['uid'];
        $record = UserCodec::rawRecord($rawUsers, $uid);

        if ($record === null) {
            throw new ProtocolException(
                "Could not isolate {$fromUserId}'s record in the user table; nothing was changed.",
                ['user_id' => $fromUserId, 'uid' => $uid],
            );
        }

        $rawTemplates = $this->client->readTemplatesRaw();
        $all = TemplateCodec::decodeWithBlobs($rawTemplates);

        if ($all === [] && ! TemplateCodec::isEmptyTable($rawTemplates)) {
            throw new ProtocolException(
                "The fingerprint table would not decode, so {$fromUserId}'s fingerprints cannot be copied. Nothing was changed.",
                ['user_id' => $fromUserId, 'uid' => $uid],
            );
        }

        $templates = array_values(array_map(
            static fn (array $t) => ['fid' => $t['fid'], 'valid' => $t['valid'], 'template' => $t['template'], 'sha1' => sha1($t['template'])],
            array_filter($all, static fn (array $t) => $t['uid'] === $uid),
        ));
        $slotsBefore = self::slotsOf($templates);

        if ($onSnapshot !== null) {
            $onSnapshot(['uid' => $uid, 'user_id' => $fromUserId, 'record' => $record, 'templates' => $templates]);
        }

        try {
            $this->client->deleteUser($uid);
        } catch (ProtocolException $refused) {
            $still = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $fromUserId);
            throw new ProtocolException(
                "The device refused to remove {$fromUserId} ({$refused->getMessage()}). "
                . ($still !== null ? 'Nothing was changed.' : "Read the terminal's users before retrying."),
                ['from' => $fromUserId, 'to' => $toUserId, 'uid' => $uid, 'intact' => $still !== null],
            );
        }

        $failure = null;
        try {
            $this->client->saveUserWithTemplates(Packet::withUserId($record, $toUserId), $templates);
            $failure = $this->reuploadMismatch($uid, $toUserId, $fromUserId, $slotsBefore);
        } catch (ProtocolException $e) {
            $failure = $e->getMessage();
        }

        if ($failure === null) {
            $after = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $toUserId);

            return DeviceUser::fromRecord($after, $slotsBefore);
        }

        // Put back exactly what was there: the original record, original id, same uid.
        $restored = null;
        try {
            $current = UserCodec::find(UserCodec::decode($this->client->readUsersRaw()), $toUserId);
            if ($current !== null) {
                $this->client->deleteUser((int) $current['uid']);
            }
            $this->client->saveUserWithTemplates($record, $templates);
            $restored = $this->reuploadMismatch($uid, $fromUserId, $toUserId, $slotsBefore) === null;
        } catch (ProtocolException) {
            $restored = false;
        }

        throw new VerificationException(
            "Could not move {$fromUserId} to {$toUserId}: {$failure} "
            . ($restored
                ? "{$fromUserId} was put back with the same card and " . count($slotsBefore) . ' fingerprint(s).'
                : "RESTORING {$fromUserId} ALSO FAILED. Use the saved snapshot to put them back before anyone re-enrolls."),
            ['from' => $fromUserId, 'to' => $toUserId, 'uid' => $uid, 'restored' => $restored, 'slots_before' => $slotsBefore],
        );
    }

    /**
     * Null when $expectId sits on $uid with every slot in $slots and $goneId is
     * absent; otherwise what is wrong, in words.
     *
     * @param list<int> $slots
     */
    private function reuploadMismatch(int $uid, string $expectId, string $goneId, array $slots): ?string
    {
        $rawUsers = $this->client->readUsersRaw();
        $users = UserCodec::decode($rawUsers);
        $here = UserCodec::find($users, $expectId);

        if ($here === null) {
            return "no record under {$expectId} when read back.";
        }
        if ((int) $here['uid'] !== $uid) {
            return "{$expectId} landed on uid {$here['uid']}, not {$uid}.";
        }
        if (UserCodec::find($users, $goneId) !== null) {
            return "{$goneId} is still on the device.";
        }

        $rawTemplates = $this->client->readTemplatesRaw();
        $all = TemplateCodec::decodeWithBlobs($rawTemplates);

        if ($all === [] && ! TemplateCodec::isEmptyTable($rawTemplates)) {
            return $slots === [] ? null : 'the fingerprint table would not decode afterwards, so the fingerprints could not be checked.';
        }

        $now = self::slotsOf(array_values(array_filter($all, static fn (array $t) => $t['uid'] === $uid)));
        $lost = array_values(array_diff($slots, $now));

        return $lost === [] ? null : 'fingerprint slot(s) ' . implode(', ', $lost) . ' did not come back.';
    }

    /**
     * @param list<array{fid:int}> $templates
     * @return list<int>
     */
    private static function slotsOf(array $templates): array
    {
        $slots = array_values(array_unique(array_map(static fn (array $t) => (int) $t['fid'], $templates)));
        sort($slots);

        return $slots;
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
