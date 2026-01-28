/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * test/wh_test_timeout.c
 *
 */

#include <stdint.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_timeout.h"
#include "wolfhsm/wh_error.h"

#include "wh_test_common.h"
#include "wh_test_timeout.h"

static void whTest_TimeoutCb(void* ctx)
{
    int* counter = (int*)ctx;
    if (counter != NULL) {
        (*counter)++;
    }
}

int whTest_Timeout(void)
{
    int cb_count = 0;
    whTimeoutConfig cfg;
    whTimeoutCtx timeout[1];

    cfg.timeoutUs = 1;
    cfg.expiredCb = whTest_TimeoutCb;
    cfg.cbCtx = &cb_count;

    wh_Timeout_Init(timeout, &cfg);
    WH_TEST_ASSERT_RETURN(timeout->startUs == 0);
    WH_TEST_ASSERT_RETURN(timeout->timeoutUs == cfg.timeoutUs);
    WH_TEST_ASSERT_RETURN(timeout->expiredCb == cfg.expiredCb);
    WH_TEST_ASSERT_RETURN(timeout->cbCtx == cfg.cbCtx);

    wh_Timeout_Start(timeout);
    WH_TEST_ASSERT_RETURN(timeout->timeoutUs > 0);

    wh_Timeout_Stop(timeout);
    WH_TEST_ASSERT_RETURN(timeout->startUs == 0);
    WH_TEST_ASSERT_RETURN(timeout->timeoutUs == 0);

    /* No expiration when disabled */
    WH_TEST_ASSERT_RETURN(wh_Timeout_Expired(timeout) == 0);

    WH_TEST_ASSERT_RETURN(wh_Timeout_Init(0, 0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Set(0, 0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Start(0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Stop(0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Expired(0) == 0);

    return 0;
}
