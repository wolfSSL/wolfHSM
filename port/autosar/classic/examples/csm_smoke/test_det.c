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
 * port/autosar/classic/examples/csm_smoke/test_det.c
 *
 * Category-2 tests: DET coverage. Calls each Crypto_* entry point with
 * the canonical "bad inputs" and asserts that Det_ReportError fires
 * with the SWS-defined (apiId, errorId) tuple.
 *
 * Catches regressions where:
 *   - a parameter check is silently dropped,
 *   - the wrong DET errorId is reported,
 *   - the wrong service id (apiId) is reported,
 *   - the dispatcher fails-silent on bad input without DET reporting.
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>

static int expectDet(uint8 apiId, uint8 errorId, const char* label)
{
    int n = testDetCount(apiId, errorId);
    if (n == 0) {
        fprintf(stderr,
                "  det: %s — expected (api=0x%02x, err=0x%02x) not reported\n",
                label, apiId, errorId);
        return 1;
    }
    return 0;
}

/* --- Crypto_ProcessJob -------------------------------------------- */

static int testDetProcessJobNullJob(void)
{
    testDetReset();
    if (Crypto_ProcessJob(0u, NULL) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER,
                     "ProcessJob(NULL)");
}

static int testDetProcessJobNullPrimitiveInfo(void)
{
    Crypto_JobPrimitiveInfoType jpi = {0u, NULL, 0u, 0u, 0u, FALSE};
    Crypto_JobType              job = {0};
    job.jobPrimitiveInfo            = &jpi;
    testDetReset();
    if (Crypto_ProcessJob(0u, &job) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER,
                     "ProcessJob(NULL primitiveInfo)");
}

static int testDetProcessJobBadObjectId(void)
{
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          ji  = {9001u, 0u};
    uint8                       out[32];
    uint32                      outLen          = sizeof(out);
    Crypto_JobType              job             = {0};
    job.jobId                                   = ji.jobId;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    testDetReset();
    /* CRYPTO_DRIVER_OBJECT_COUNT is 1 in the smoke; id 99 is out-of-range. */
    if (Crypto_ProcessJob(99u, &job) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_HANDLE,
                     "ProcessJob(bad objectId)");
}

/* --- Crypto_GetVersionInfo --------------------------------------- */

static int testDetGetVersionInfoNull(void)
{
    testDetReset();
    Crypto_GetVersionInfo(NULL);
    return expectDet(CRYPTO_GETVERSIONINFO_SID, CRYPTO_E_PARAM_POINTER,
                     "GetVersionInfo(NULL)");
}

/* --- Crypto_CancelJob -------------------------------------------- */

static int testDetCancelJobBadObjectId(void)
{
    Crypto_JobType job = {0};
    testDetReset();
    if (Crypto_CancelJob(99u, &job) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_CANCELJOB_SID, CRYPTO_E_PARAM_HANDLE,
                     "CancelJob(bad objectId)");
}

static int testDetCancelJobNullJob(void)
{
    testDetReset();
    if (Crypto_CancelJob(0u, NULL) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_CANCELJOB_SID, CRYPTO_E_PARAM_HANDLE,
                     "CancelJob(NULL)");
}

/* --- Crypto_KeyElementSet ---------------------------------------- */

static int testDetKeyElementSetNullKey(void)
{
    testDetReset();
    if (Crypto_KeyElementSet(0u, 1u, NULL, 32u) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_POINTER,
                     "KeyElementSet(NULL key)");
}

static int testDetKeyElementSetBadLength(void)
{
    uint8 k[1] = {0};
    testDetReset();
    if (Crypto_KeyElementSet(0u, 1u, k, 0u) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_VALUE,
                     "KeyElementSet(keyLength=0)");
}

static int testDetKeyElementSetBadKeyId(void)
{
    uint8 k[8] = {0};
    testDetReset();
    /* cryptoKeyId 0x100 is outside our 8-bit composition range; the
     * dispatcher rejects with CRYPTO_E_PARAM_KEY. */
    if (Crypto_KeyElementSet(0x100u, 1u, k, sizeof(k)) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_KEY,
                     "KeyElementSet(out-of-range cryptoKeyId)");
}

/* --- Crypto_KeyElementGet ---------------------------------------- */

static int testDetKeyElementGetNullPtrs(void)
{
    uint8  buf[8];
    uint32 len = sizeof(buf);
    testDetReset();
    if (Crypto_KeyElementGet(0u, 1u, NULL, &len) != E_NOT_OK)
        return 1;
    if (expectDet(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_POINTER,
                  "KeyElementGet(NULL result)") != 0)
        return 1;
    testDetReset();
    if (Crypto_KeyElementGet(0u, 1u, buf, NULL) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_POINTER,
                     "KeyElementGet(NULL resultLength)");
}

/* --- Entrypoint -------------------------------------------------- */

int testDetAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testDetProcessJobNullJob);
    TEST_RUN(failures, testDetProcessJobNullPrimitiveInfo);
    TEST_RUN(failures, testDetProcessJobBadObjectId);
    TEST_RUN(failures, testDetGetVersionInfoNull);
    TEST_RUN(failures, testDetCancelJobBadObjectId);
    TEST_RUN(failures, testDetCancelJobNullJob);
    TEST_RUN(failures, testDetKeyElementSetNullKey);
    TEST_RUN(failures, testDetKeyElementSetBadLength);
    TEST_RUN(failures, testDetKeyElementSetBadKeyId);
    TEST_RUN(failures, testDetKeyElementGetNullPtrs);
    if (failures == 0) {
        printf(
            "  DET: 10 parameter-check paths fire correct (apiId, errorId)\n");
    }
    return failures;
}
