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

namespace Promoseven\Biometric\Protocol;

/**
 * What a standalone terminal's error replies mean, so a refusal names its cause instead
 * of "UNKNOWN(4995)" (2.20.0).
 *
 * DOCUMENTED, transcribed literally (rule 17) from ZKTeco's own dictionary: ZKAccess
 * 3.5.5, `Languages/language_en-US.xml`, block `<SDKError_StandAlone>`, entries -4981 to
 * -4999. The SDK reports a device reply N as error -N; the wire carries N. Seen on this
 * project's hardware as replies: 4991 (F22 On The Road, windowed user read, 2026-09-13),
 * 4994 (F18 Camelot, user write, 2026-09-24), 4995 (F18 Camelot, user insert,
 * 2026-10-25/26, cleared by a restart). The rest are transcribed, never observed.
 *
 * The SDK's -2000 range mirrors replies Command already names (2000 ACK_OK, 2001
 * ACK_ERROR, 2005 ACK_UNAUTH), so it is not repeated here.
 */
final class ReplyCode
{
    public const MEANINGS = [
        4999 => 'Read error',
        4998 => 'Write error',
        4997 => 'Error passing in data length',
        4996 => 'There was an error in the parameters of the reference data',
        4995 => 'Error inserting database',
        4994 => 'Error updating database',
        4993 => 'Error reading database',
        4992 => 'Error deleting database',
        4991 => 'Operation database has no corresponding data',
        4990 => 'The database is out of capacity',
        4989 => 'The session buffer is empty',
        4988 => 'The session buffer size is negative',
        4987 => 'Session buffer address error',
        4986 => 'File does not exist',
        4985 => 'File read error',
        4984 => 'File writing error',
        4983 => 'Error in data hash validation',
        4982 => 'Device malloc memory error',
        4981 => 'Version information of the biological template does not correspond',
    ];

    private function __construct()
    {
    }

    /** The vendor's meaning of an error reply, or null when it has none. */
    public static function meaning(int $reply): ?string
    {
        return self::MEANINGS[$reply] ?? null;
    }
}
