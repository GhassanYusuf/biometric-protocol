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

namespace Promoseven\Biometric\C3\Model;

/**
 * The one place a model name becomes an implementation.
 *
 * Rule 15's seam: selection happens HERE, once, and nothing downstream branches on
 * a model again. Adding a panel means adding a class and one entry to this list —
 * it does not mean editing a read loop, a transport, or a codec.
 *
 * NOTE THAT NO MODEL NAME APPEARS IN THIS FILE. The match lives inside each model
 * class, which is the only file rule 15 permits it in, and this list holds class
 * references rather than strings. That is not pedantry: it is what stops a second
 * spelling of a model name drifting apart from the first.
 */
final class PanelModelFactory
{
    /**
     * Order matters only if two models could claim the same name; none do today.
     *
     * @var list<class-string<PanelModel>>
     */
    private const MODELS = [
        InBio460::class,
        Tf1700::class,
    ];

    public static function for(?string $model): PanelModel
    {
        $name = trim((string) $model);

        if ($name !== '') {
            foreach (self::MODELS as $class) {
                if ($class::matches($name)) {
                    return new $class;
                }
            }
        }

        return new GenericPanel($name !== '' ? $name : 'unknown C3 panel');
    }

    /**
     * The models with a dedicated implementation, named by the classes themselves.
     *
     * @return list<string>
     */
    public static function known(): array
    {
        return array_map(static fn (string $class): string => (new $class)->name(), self::MODELS);
    }
}
