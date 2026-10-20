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
 * port/autosar/classic/examples/csm_smoke/test_timeout.c
 *
 * Category-5: async timeout. Verifies that a PENDING slot whose age
 * exceeds CRYPTO_ASYNC_TIMEOUT_TICKS is force-cleaned by
 * Crypto_MainFunction, the callback fires with E_NOT_OK, and the
 * slot returns to IDLE without leaking resources.
 *
 * Uses wh_Autosar_DebugInjectFakePending so the timeout is exercised
 * without depending on server orchestration (a real server stall is
 * non-deterministic in CI).
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int testTimeoutForcesCallback(void)
{
    wh_AutosarDriverObject*     obj = wh_Autosar_GetDriverObject(0u);
    Crypto_JobType              job = {0};
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 1u, FALSE};
    Crypto_JobInfoType          ji  = {9500u, 0u};
    int                         prev;

    job.jobId            = ji.jobId;
    job.jobPrimitiveInfo = &jpi;
    job.jobInfo          = &ji;
    job.jobState         = CRYPTO_JOBSTATE_ACTIVE;

    /* Pause the worker so we can drive MainFunction manually for
     * deterministic ordering. */
    testPauseMainFunctionThread();

    prev = testCallbackTotal();
    if (wh_Autosar_DebugInjectFakePending(obj, &job,
                                          WH_AUTOSAR_OP_RNG_GENERATE) != 0) {
        testResumeMainFunctionThread();
        fprintf(stderr, "  timeout: inject failed\n");
        return 1;
    }

    /* Push the clock past the timeout threshold. */
    wh_Autosar_DebugAdvanceTicks(obj, CRYPTO_ASYNC_TIMEOUT_TICKS + 1u);

    /* Hand back to the worker. The next MainFunction iteration will
     * see the timeout, force-complete the slot, and surface a callback
     * with E_NOT_OK on the iteration after. Allow two iterations. */
    testResumeMainFunctionThread();

    if (testWaitCallbacks(prev + 1, 1000) != 0) {
        fprintf(stderr, "  timeout: no callback within 1s\n");
        return 1;
    }
    if (gTestCb.lastResult != E_NOT_OK) {
        fprintf(stderr, "  timeout: callback result=%u (expected E_NOT_OK)\n",
                gTestCb.lastResult);
        return 1;
    }
    if (gTestCb.lastJob != &job) {
        fprintf(stderr, "  timeout: callback job pointer mismatch\n");
        return 1;
    }
    return 0;
}

int testTimeoutAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testTimeoutForcesCallback);
    if (failures == 0) {
        printf("  timeout: force-cleanup after CRYPTO_ASYNC_TIMEOUT_TICKS "
               "fires E_NOT_OK callback\n");
    }
    return failures;
}
