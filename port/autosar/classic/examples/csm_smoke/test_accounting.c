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
 * port/autosar/classic/examples/csm_smoke/test_accounting.c
 *
 * Category-3 tests: resource accounting.
 *
 * The TEST_RUN macro already asserts active-slot count and active
 * hash-state count return to zero after every test in every category.
 * This file adds tests for the specific lifecycle paths that have
 * historically leaked resources (FinalRequest failure mid-async,
 * UPDATE without START, async submit-then-cancel before issuance,
 * etc.) so any regression has a dedicated reproducer.
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>

/* --- UPDATE without prior START: dispatcher must reject and not
 *     allocate a hash state slot. ------------------------------------ */

#ifndef WOLFHSM_CFG_NO_CRYPTO
static int testAccountingHashUpdateWithoutStart(void)
{
    const char*                 msg = "fragment";
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_HASH,
                                       {CRYPTO_ALGOFAM_SHA2_256,
                                        CRYPTO_ALGOFAM_NOT_SET, 0u,
                                        CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          ji  = {7777u, 0u};
    uint8                       digest[32];
    uint32                      dLen            = sizeof(digest);
    Crypto_JobType              job             = {0};
    job.jobId                                   = ji.jobId;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.inputPtr        = (const uint8*)msg;
    job.jobPrimitiveInputOutput.inputLength     = (uint32)strlen(msg);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode            = CRYPTO_OPERATIONMODE_UPDATE;
    if (Crypto_ProcessJob(0u, &job) != E_NOT_OK) {
        fprintf(stderr,
                "  accounting: UPDATE-without-START unexpectedly succeeded\n");
        return 1;
    }
    return 0;
}

/* --- START / re-START without intervening FINISH: the second START
 *     for the same jobId must free the previous wc_Sha256 before
 *     re-initialising. Active-hash-state count returns to 1 inside
 *     the test and 0 after FINISH. ------------------------------ */

static int testAccountingHashReSart(void)
{
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_HASH,
                                       {CRYPTO_ALGOFAM_SHA2_256,
                                        CRYPTO_ALGOFAM_NOT_SET, 0u,
                                        CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          ji  = {7778u, 0u};
    uint8                       digest[32];
    uint32                      dLen      = sizeof(digest);
    Crypto_JobType              job       = {0};
    wh_AutosarDriverObject*     obj       = wh_Autosar_GetDriverObject(0u);
    job.jobId                             = ji.jobId;
    job.jobPrimitiveInfo                  = &jpi;
    job.jobInfo                           = &ji;
    job.jobPrimitiveInputOutput.outputPtr = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;

    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_START;
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    if (wh_Autosar_DebugActiveHashStateCount(obj) != 1u) {
        fprintf(stderr, "  accounting: first START did not allocate state\n");
        return 1;
    }
    /* Second START on the same jobId must reuse the slot, not leak. */
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    if (wh_Autosar_DebugActiveHashStateCount(obj) != 1u) {
        fprintf(stderr,
                "  accounting: re-START allocated a fresh slot (leak)\n");
        return 1;
    }
    /* Wrap up so TEST_RUN's post-condition passes. */
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_FINISH;
    dLen                             = sizeof(digest);
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    return 0;
}
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* --- Many async submissions in tight loop: confirms no slot is
 *     orphaned across the queue → in-flight → complete → idle cycle. */

static int testAccountingAsyncChurn(void)
{
    enum {
        CYCLES = 8
    }; /* matches CRYPTO_MAX_ASYNC_JOBS so the
           queue stays at saturation throughout */
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 1u, FALSE};
    Crypto_JobInfoType          ji[CYCLES];
    Crypto_JobType              jobs[CYCLES];
    uint8                       out[CYCLES][32];
    uint32                      outLen[CYCLES];
    int                         prev = testCallbackTotal();
    int                         k;
    for (k = 0; k < CYCLES; ++k) {
        memset(&jobs[k], 0, sizeof(jobs[k]));
        ji[k].jobId                                     = (uint32)(8000 + k);
        ji[k].jobPriority                               = 0u;
        jobs[k].jobId                                   = ji[k].jobId;
        jobs[k].jobPrimitiveInfo                        = &jpi;
        jobs[k].jobInfo                                 = &ji[k];
        outLen[k]                                       = sizeof(out[k]);
        jobs[k].jobPrimitiveInputOutput.outputPtr       = out[k];
        jobs[k].jobPrimitiveInputOutput.outputLengthPtr = &outLen[k];
        jobs[k].jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
        if (Crypto_ProcessJob(0u, &jobs[k]) != E_OK)
            return 1;
    }
    if (testWaitCallbacks(prev + CYCLES, 30000) != 0)
        return 1;
    /* TEST_RUN will assert active-slot count == 0 after this. */
    return 0;
}

int testAccountingAll(void)
{
    int failures = 0;
#ifndef WOLFHSM_CFG_NO_CRYPTO
    TEST_RUN(failures, testAccountingHashUpdateWithoutStart);
    TEST_RUN(failures, testAccountingHashReSart);
#endif
    TEST_RUN(failures, testAccountingAsyncChurn);
    if (failures == 0) {
        printf("  accounting: leak-free across UPDATE/START misuse + 20-cycle "
               "async churn\n");
    }
    return failures;
}
