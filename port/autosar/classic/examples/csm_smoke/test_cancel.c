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
 * port/autosar/classic/examples/csm_smoke/test_cancel.c
 *
 * Crypto_CancelJob on queued, pending and unknown jobs.
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static void msleep(int ms)
{
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}

static int testCancelQueued(void)
{
    /* Pause MainFunction so the submitted job stays QUEUED. */
    testPauseMainFunctionThread();

    Crypto_PrimitiveInfoType    pi  = {CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, CRYPTO_PROCESSING_ASYNC};
    uint8                       out[32];
    uint32                      outLen          = sizeof(out);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 9101u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;

    int baselineCb = testCallbacksForJob(&job);

    if (testCryIfProcessJob(0u, &job) != E_OK) {
        testResumeMainFunctionThread();
        return 1;
    }
    if (Crypto_CancelJob(0u, &job) != E_OK) {
        testResumeMainFunctionThread();
        return 1;
    }
    testResumeMainFunctionThread();

    msleep(50);
    if (testCallbacksForJob(&job) - baselineCb != 0) {
        fprintf(stderr, "  cancel-queued: callback fired despite cancel\n");
        return 1;
    }
    return 0;
}

static int testCancelPending(void)
{
    /* Races MainFunction: either the cancel wins and no callback fires, or
     * the job completes first, CancelJob fails and one callback fires. */
    Crypto_PrimitiveInfoType    pi  = {CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, CRYPTO_PROCESSING_ASYNC};
    uint8                       out[32];
    uint32                      outLen = sizeof(out);
    Crypto_JobType              job    = {0};
    Std_ReturnType              cancelRc;
    int                         cbForJob;
    job.jobId                                   = 9101u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;

    int baselineCb = testCallbacksForJob(&job);

    if (testCryIfProcessJob(0u, &job) != E_OK)
        return 1;
    cancelRc = Crypto_CancelJob(0u, &job);

    /* Give MainFunction time for any late Response to drain. */
    msleep(200);

    cbForJob = testCallbacksForJob(&job) - baselineCb;
    if (cancelRc == E_OK) {
        if (cbForJob != 0) {
            fprintf(stderr,
                    "  cancel-pending: cancel=OK but %d callback(s) fired\n",
                    cbForJob);
            return 1;
        }
    }
    else {
        if (cbForJob != 1) {
            fprintf(stderr,
                    "  cancel-pending: cancel=NOT_OK and %d callback(s) "
                    "(expected 1)\n",
                    cbForJob);
            return 1;
        }
    }
    return 0;
}

static int testCancelIdempotent(void)
{
    Crypto_JobType job = {0};
    if (Crypto_CancelJob(0u, &job) != E_NOT_OK) {
        fprintf(stderr, "  cancel-unknown: expected E_NOT_OK\n");
        return 1;
    }
    return 0;
}

int testCancelAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testCancelQueued);
    TEST_RUN(failures, testCancelPending);
    TEST_RUN(failures, testCancelIdempotent);
    if (failures == 0) {
        printf("  cancel: queued / pending / unknown-job paths OK\n");
    }
    return failures;
}
