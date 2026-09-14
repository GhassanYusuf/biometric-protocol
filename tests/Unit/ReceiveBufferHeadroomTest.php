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
use Promoseven\Biometric\Transport\UdpTransport;
use ReflectionMethod;

/**
 * The SO_RCVBUF readback is not the usable size on every platform.
 *
 * REGRESSION, 2026-09-13. A 326,084-byte attendance read failed at 218,564 bytes
 * on Debian 12 (unprivileged LXC, net.core.rmem_max = 212,992). The 4 MB request
 * read back as 425,984 — Linux stores double — so BulkReader compared 425,984
 * against 326,084, concluded the whole transfer would fit, and reported progress
 * per chunk during a burst that has no flow control. The real ceiling was 212,992
 * and the kernel dropped everything past it.
 *
 * These tests pin the conversion. No device and no socket are involved.
 */
final class ReceiveBufferHeadroomTest extends TestCase
{
    private function usable(?int $granted, string $osFamily): ?int
    {
        $m = new ReflectionMethod(UdpTransport::class, 'usableFromGranted');
        $m->setAccessible(true);

        return $m->invoke(null, $granted, $osFamily);
    }

    public function test_linux_reports_double_so_half_of_it_is_usable(): void
    {
        $this->assertSame(212_992, $this->usable(425_984, 'Linux'));
    }

    public function test_platforms_that_do_not_double_are_taken_at_face_value(): void
    {
        $this->assertSame(4_194_304, $this->usable(4_194_304, 'Windows'));
        $this->assertSame(4_194_304, $this->usable(4_194_304, 'BSD'));
        $this->assertSame(4_194_304, $this->usable(4_194_304, 'Darwin'));
    }

    public function test_an_undeterminable_buffer_stays_undeterminable(): void
    {
        // Null means "assume none". It must never become a number, on any platform
        // — a build without ext-sockets has no headroom evidence to offer.
        $this->assertNull($this->usable(null, 'Linux'));
        $this->assertNull($this->usable(null, 'Windows'));
    }

    /**
     * The exact numbers from the failure, asserted as the interlock sees them.
     *
     * This is the whole point of the fix: the raw readback clears the bar and the
     * usable figure does not, so the reader takes the conservative path instead of
     * pausing mid-burst.
     */
    public function test_the_failing_transfer_no_longer_looks_like_it_fits(): void
    {
        $tableBytes = 326_084;
        $rawReadback = 425_984;

        $this->assertGreaterThanOrEqual(
            $tableBytes,
            $rawReadback,
            'precondition: the raw readback is what fooled the old check',
        );

        $usable = $this->usable($rawReadback, 'Linux');

        $this->assertLessThan(
            $tableBytes,
            $usable,
            'the corrected headroom must fail the >= $size test that gates per-chunk reporting',
        );
        $this->assertSame(212_992, $usable);
    }

    public function test_an_odd_readback_rounds_down_rather_than_up(): void
    {
        // Rounding up would re-introduce the bug in miniature: claiming one byte
        // more of headroom than exists is the same class of error as claiming
        // double.
        $this->assertSame(512, $this->usable(1025, 'Linux'));
    }
}
