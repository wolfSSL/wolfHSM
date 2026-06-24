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
 * test-refactor/client-server/wh_test_counter.c
 *
 * NVM monotonic counter round-trips routed through the server. Covers
 * reset/init/increment/read/destroy, increment saturation at the uint32_t
 * max, and slot reuse across more counters than the NVM directory holds.
 *
 * The counter API is carried by dedicated counter messages, not the
 * cryptocb, so it is identical across the DMA and non-DMA builds. The
 * WOLFHSM_CFG_DMA build option is covered by compiling and running this
 * test under that configuration, not by toggling the client DMA mode.
 */

#include <stdint.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Increment well past the NVM directory size to confirm a single counter
 * reuses one slot rather than leaking an object per increment. */
#define WH_TEST_COUNTER_INCREMENTS (2 * WOLFHSM_CFG_NVM_OBJECT_COUNT)

/* Reads the current count of free NVM objects, failing on a server error. */
static int _whTest_CounterAvailObjects(whClientContext* ctx,
                                       whNvmId*         outAvailObjects)
{
    int32_t  serverRc       = 0;
    uint32_t availSize       = 0;
    uint32_t reclaimSize     = 0;
    whNvmId  availObjects     = 0;
    whNvmId  reclaimObjects   = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &serverRc, &availSize, &availObjects, &reclaimSize,
        &reclaimObjects));
    WH_TEST_ASSERT_RETURN(serverRc == WH_ERROR_OK);

    *outAvailObjects = availObjects;
    return WH_ERROR_OK;
}

/* Reset, increment past the directory size, and saturate a single counter. */
static int _whTest_CounterIncrement(whClientContext* ctx)
{
    const whNvmId  counterId       = 1;
    const uint32_t maxCounterVal   = 0xFFFFFFFF;
    size_t         i               = 0;
    uint32_t       counter         = 0;

    /* A fresh counter starts at zero. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterReset(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    /* Each increment advances by one and read-back matches, with no object
     * leak across more increments than the directory could hold. */
    for (i = 0; i < WH_TEST_COUNTER_INCREMENTS; i++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterIncrement(ctx, counterId, &counter));
        WH_TEST_ASSERT_RETURN(counter == i + 1);

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterRead(ctx, counterId, &counter));
        WH_TEST_ASSERT_RETURN(counter == i + 1);
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterReset(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    /* Init near the max and confirm increments saturate instead of rolling. */
    counter = maxCounterVal;
    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterInit(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == maxCounterVal);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterIncrement(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == maxCounterVal);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterIncrement(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == maxCounterVal);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterRead(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == maxCounterVal);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterReset(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterDestroy(ctx, counterId));

    return WH_ERROR_OK;
}

/* Create and destroy counters across many ids, confirming destroy frees the
 * slot and a destroyed counter can no longer be read. */
static int _whTest_CounterDestroy(whClientContext* ctx)
{
    size_t   i       = 0;
    uint32_t counter = 0;

    for (i = 1; i < WH_TEST_COUNTER_INCREMENTS; i++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterReset(ctx, (whNvmId)i, &counter));
        WH_TEST_ASSERT_RETURN(counter == 0);

        WH_TEST_RETURN_ON_FAIL(wh_Client_CounterDestroy(ctx, (whNvmId)i));

        /* A destroyed counter must not be readable. */
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_NOTFOUND ==
            wh_Client_CounterRead(ctx, (whNvmId)i, &counter));
    }

    return WH_ERROR_OK;
}

/*
 * NVM counter API test. Brackets the sub-tests with an NVM object census so
 * the no-leak guarantee holds regardless of any objects other tests left
 * behind in the shared server.
 */
int whTest_Counter(whClientContext* ctx)
{
    whNvmId baselineObjects = 0;
    whNvmId finalObjects    = 0;

    WH_TEST_PRINT("Testing NVM counters...\n");

    WH_TEST_RETURN_ON_FAIL(
        _whTest_CounterAvailObjects(ctx, &baselineObjects));

    WH_TEST_RETURN_ON_FAIL(_whTest_CounterIncrement(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CounterDestroy(ctx));

    /* Reset and destroy must not leak NVM objects. */
    WH_TEST_RETURN_ON_FAIL(_whTest_CounterAvailObjects(ctx, &finalObjects));
    WH_TEST_ASSERT_RETURN(finalObjects == baselineObjects);

    return WH_ERROR_OK;
}
