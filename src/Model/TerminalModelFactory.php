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

namespace Promoseven\Biometric\Model;

/**
 * Picks the model implementation for a standalone terminal — the ONE place the
 * choice is made (rule 15: the seam is selection, not branching). No model name
 * appears here; each model's file says what it matches.
 */
final class TerminalModelFactory
{
    /**
     * Every model file in this directory, found rather than listed: a list here would
     * be a second place naming models (rule 15). A new model is a new file and nothing
     * else.
     *
     * @return list<class-string<TerminalModel>>
     */
    private static function models(): array
    {
        static $models = null;

        if ($models === null) {
            $models = [];
            foreach (glob(__DIR__.'/*.php') ?: [] as $file) {
                $class = __NAMESPACE__.'\\'.basename($file, '.php');
                if (class_exists($class) && is_subclass_of($class, TerminalModel::class)
                    && $class !== GenericTerminal::class) {
                    $models[] = $class;
                }
            }
            sort($models);
        }

        return $models;
    }

    public static function for(?string $model): TerminalModel
    {
        $name = trim((string) $model);

        if ($name !== '') {
            foreach (self::models() as $class) {
                if ($class::matches($name)) {
                    return new $class;
                }
            }
        }

        return new GenericTerminal($name !== '' ? $name : 'unknown terminal');
    }

    /** @return list<string> */
    public static function known(): array
    {
        return array_map(static fn (string $class): string => (new $class)->name(), self::models());
    }
}
