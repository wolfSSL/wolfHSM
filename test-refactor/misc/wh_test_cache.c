/*
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * test-refactor/misc/wh_test_cache.c
 *
 * Cache line coverage of wh_Utils_CacheFlush and wh_Utils_CacheInvalidate,
 * the default XCACHEFLUSHBLK and XCACHEINVLDBLK. The test config
 * (WOLFHSM_CFG_TEST_CACHE_RECORD) routes XCACHEFLUSH and XCACHEINVLD to
 * whTest_CacheRecord, which records each line address without touching it,
 * so the ranges are synthetic addresses, up to the top of the address space.
 * Needs no client, server, or port fixture.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_TEST_CACHE_RECORD

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define CACHE_RECORD_MAX 8

static int       _cacheRecording;
static int       _cacheCount;
static int       _cacheOps[CACHE_RECORD_MAX];
static uintptr_t _cacheLines[CACHE_RECORD_MAX];

/* XCACHEFLUSH and XCACHEINVLD in this build. Only records while a check below
 * runs, so the cache operations of the transports in other tests stay no-ops.
 * Counts one call past CACHE_RECORD_MAX so too many calls fail the check. */
void whTest_CacheRecord(int invalidate, uintptr_t addr)
{
    if (_cacheRecording == 0) {
        return;
    }
    if (_cacheCount < CACHE_RECORD_MAX) {
        _cacheOps[_cacheCount]   = invalidate;
        _cacheLines[_cacheCount] = addr;
        _cacheCount++;
    }
    else {
        _cacheCount = CACHE_RECORD_MAX + 1;
    }
}

/* Run the flush or invalidate helper over [p, p + n) and check that it
 * visited count lines in order, starting at the line address first */
static int _whTest_CacheCheck(int invalidate, uintptr_t p, size_t n,
                              uintptr_t first, int count)
{
    const void* ret;
    int         i;

    _cacheCount     = 0;
    _cacheRecording = 1;
    if (invalidate != 0) {
        ret = wh_Utils_CacheInvalidate((const void*)p, n);
    }
    else {
        ret = wh_Utils_CacheFlush((void*)p, n);
    }
    _cacheRecording = 0;

    WH_TEST_ASSERT_RETURN(ret == (const void*)p);
    if (_cacheCount != count) {
        WH_ERROR_PRINT("%s(%p, %lu) visited %d lines, expected %d\n",
                       (invalidate != 0) ? "invalidate" : "flush", (void*)p,
                       (unsigned long)n, _cacheCount, count);
        return WH_TEST_FAIL;
    }
    for (i = 0; i < count; i++) {
        WH_TEST_ASSERT_RETURN(_cacheOps[i] == invalidate);
        WH_TEST_ASSERT_RETURN(_cacheLines[i] ==
                              first + (uintptr_t)i * XCACHELINE);
    }
    return WH_ERROR_OK;
}

/* Check one range with both helpers */
static int _whTest_CacheRange(uintptr_t p, size_t n, uintptr_t first, int count)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheCheck(0, p, n, first, count));
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheCheck(1, p, n, first, count));
    return WH_ERROR_OK;
}

int whTest_CacheHelpers(void* ctx)
{
    const uintptr_t line = XCACHELINE;
    /* Any line aligned address, nothing is dereferenced */
    const uintptr_t base = 1024 * line;
    /* Start of the last line of the address space */
    const uintptr_t top = UINTPTR_MAX - (UINTPTR_MAX % line);

    (void)ctx;

    /* Aligned start, exact multiple of the line size */
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheRange(base, 3 * line, base, 3));
    /* Unaligned start, the range spills one byte into the next line */
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheRange(base + 1, line, base, 2));
    /* n == 0 visits nothing */
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheRange(base, 0, 0, 0));
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheRange(base + 1, 0, 0, 0));
    /* n == 1 at the last byte of a line visits only that line */
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheRange(base + line - 1, 1, base, 1));

    /* A range reaching the top of the address space stops at its last line:
     * ending exactly at the top, ending inside the last line (rounding the
     * end up would wrap), running past the top, and the very last byte */
    WH_TEST_RETURN_ON_FAIL(
        _whTest_CacheRange(top - line, 2 * line, top - line, 2));
    WH_TEST_RETURN_ON_FAIL(
        _whTest_CacheRange(top - line + 1, line, top - line, 2));
    WH_TEST_RETURN_ON_FAIL(
        _whTest_CacheRange(top - line, 3 * line, top - line, 2));
    WH_TEST_RETURN_ON_FAIL(_whTest_CacheRange(UINTPTR_MAX, 1, top, 1));

    WH_TEST_PRINT("Cache line helpers SUCCESS\n");
    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_TEST_CACHE_RECORD */
