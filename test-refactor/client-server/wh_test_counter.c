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
 * Exercise the persistent NVM counter API: init/reset,
 * sequential increment past WOLFHSM_CFG_NVM_OBJECT_COUNT (catches
 * slot leaks), saturate-on-overflow at UINT32_MAX, and
 * reset+destroy across many slots.
 */

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"


/*
 * Verify counter can update more than WOLFHSM_CFG_NVM_OBJECT_COUNT times.
 * Each increment should reuse the same slot.
 */
static int _whTest_CounterSequentialIncrement(whClientContext* ctx)
{
    const whNvmId counterId      = 1;
    const size_t  NUM_INCREMENTS = 2u * WOLFHSM_CFG_NVM_OBJECT_COUNT;
    size_t        i;
    uint32_t      counter        = 0;

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterReset(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    for (i = 0; i < NUM_INCREMENTS; i++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterIncrement(ctx, counterId, &counter));
        WH_TEST_ASSERT_RETURN(counter == (uint32_t)(i + 1));

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterRead(ctx, counterId, &counter));
        WH_TEST_ASSERT_RETURN(counter == (uint32_t)(i + 1));
    }

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterReset(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterDestroy(ctx, counterId));

    return WH_ERROR_OK;
}


/*
 * Verify the counter saturates at UINT32_MAX and does not wrap.
 */
static int _whTest_CounterSaturate(whClientContext* ctx)
{
    const whNvmId  counterId   = 1;
    const uint32_t MAX_COUNTER = 0xFFFFFFFFu;
    uint32_t       counter     = MAX_COUNTER;

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterInit(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterIncrement(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterIncrement(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterRead(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterReset(ctx, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterDestroy(ctx, counterId));

    return WH_ERROR_OK;
}


/*
 * Reset+destroy across many slots: catches leaks in the destroy
 * path and confirms that a destroyed counter reads back as
 * NOTFOUND.
 */
static int _whTest_CounterDestroyMany(whClientContext* ctx)
{
    const size_t NUM_SLOTS = 2u * WOLFHSM_CFG_NVM_OBJECT_COUNT;
    size_t       i;
    uint32_t     counter;

    for (i = 1; i < NUM_SLOTS; i++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterReset(ctx, (whNvmId)i, &counter));
        WH_TEST_ASSERT_RETURN(counter == 0);

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterDestroy(ctx, (whNvmId)i));

        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
            wh_Client_CounterRead(ctx, (whNvmId)i, &counter));
    }

    return WH_ERROR_OK;
}


int whTest_Counter(whClientContext* ctx)
{
    int32_t  server_rc       = 0;
    uint32_t client_id       = 0;
    uint32_t server_id       = 0;
    uint32_t avail_size      = 0;
    uint32_t reclaim_size    = 0;
    whNvmId  avail_objects   = 0;
    whNvmId  reclaim_objects = 0;
    whNvmId  baseline        = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmInit(
        ctx, &server_rc, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &server_rc, &avail_size, &avail_objects,
        &reclaim_size, &reclaim_objects));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    baseline = avail_objects;

    WH_TEST_RETURN_ON_FAIL(_whTest_CounterSequentialIncrement(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CounterSaturate(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CounterDestroyMany(ctx));

    /* No object slots leaked: available count is back where we
     * started before the test ran. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &server_rc, &avail_size, &avail_objects,
        &reclaim_size, &reclaim_objects));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == baseline);

    return WH_ERROR_OK;
}
