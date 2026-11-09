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
 * port/autosar/classic/examples/csm_smoke/test_limits.c
 *
 * Full async slot, hash state and key state tables, and failed hash streams.
 */

#include "test_helpers.h"

#define LIMIT_FIRST_KEY 200u

static int testAsyncSlotsFull(void)
{
    uint8                       out[CRYPTO_MAX_ASYNC_JOBS + 1u][16];
    uint32                      outLen[CRYPTO_MAX_ASYNC_JOBS + 1u];
    Crypto_PrimitiveInfoType    pi[CRYPTO_MAX_ASYNC_JOBS + 1u];
    Crypto_JobPrimitiveInfoType jpi[CRYPTO_MAX_ASYNC_JOBS + 1u];
    Crypto_JobType              job[CRYPTO_MAX_ASYNC_JOBS + 1u];
    uint32                      i;
    uint32                      accepted = 0u;
    Std_ReturnType              extra    = E_OK;
    int                         base;

    for (i = 0u; i <= CRYPTO_MAX_ASYNC_JOBS; ++i) {
        outLen[i] = sizeof(out[i]);
        testBuildJob(&job[i], &jpi[i], &pi[i], CRYPTO_RANDOMGENERATE,
                     CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOMODE_NOT_SET, 0u,
                     CRYPTO_PROCESSING_ASYNC, 8000u + i);
        job[i].jobPrimitiveInputOutput.outputPtr       = out[i];
        job[i].jobPrimitiveInputOutput.outputLengthPtr = &outLen[i];
    }
    base = testCallbackTotal();
    testPauseMainFunctionThread();
    for (i = 0u; i < CRYPTO_MAX_ASYNC_JOBS; ++i) {
        if (testCryIfProcessJob(0u, &job[i]) == E_OK) {
            accepted++;
        }
    }
    if (accepted == CRYPTO_MAX_ASYNC_JOBS) {
        extra = testCryIfProcessJob(0u, &job[CRYPTO_MAX_ASYNC_JOBS]);
    }
    testResumeMainFunctionThread();
    if (testWaitCallbacks(base + (int)accepted, 10000) != 0) {
        fprintf(stderr, "  slots: queued jobs did not complete\n");
        return 1;
    }
    if (accepted != CRYPTO_MAX_ASYNC_JOBS || extra != E_NOT_OK) {
        fprintf(stderr, "  slots: %u accepted, extra job returned %u\n",
                accepted, extra);
        return 1;
    }
    if (testCryIfProcessJob(0u, &job[CRYPTO_MAX_ASYNC_JOBS]) != E_OK ||
        testWaitCallbacks(base + (int)accepted + 1, 5000) != 0) {
        fprintf(stderr, "  slots: no slot free after the drain\n");
        return 1;
    }
    printf("  slots: job %u rejected while all %u slots are queued\n",
           (unsigned)CRYPTO_MAX_ASYNC_JOBS + 1u,
           (unsigned)CRYPTO_MAX_ASYNC_JOBS);
    return 0;
}

#ifndef WOLFHSM_CFG_NO_CRYPTO
static Std_ReturnType hashStep(Crypto_JobType*          job,
                               Crypto_OperationModeType mode)
{
    job->jobPrimitiveInputOutput.mode = mode;
    return testCryIfProcessJob(0u, job);
}

static int testHashStatesFull(void)
{
    static const uint8          msg[3] = {'a', 'b', 'c'};
    uint8                       digest[WH_AUTOSAR_HASH_SLOTS_PER_OBJ + 1u][32];
    uint32                      dLen[WH_AUTOSAR_HASH_SLOTS_PER_OBJ + 1u];
    Crypto_PrimitiveInfoType    pi[WH_AUTOSAR_HASH_SLOTS_PER_OBJ + 1u];
    Crypto_JobPrimitiveInfoType jpi[WH_AUTOSAR_HASH_SLOTS_PER_OBJ + 1u];
    Crypto_JobType              job[WH_AUTOSAR_HASH_SLOTS_PER_OBJ + 1u];
    uint8                       want[32];
    uint32                      i;
    int                         rc = 0;

    if (testHexDecode("ba7816bf8f01cfea414140de5dae2223"
                      "b00361a396177a9cb410ff61f20015ad",
                      want, sizeof(want)) != 32) {
        return 1;
    }
    for (i = 0u; i <= WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
        dLen[i] = sizeof(digest[i]);
        testBuildJob(&job[i], &jpi[i], &pi[i], CRYPTO_HASH,
                     CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_NOT_SET, 0u,
                     CRYPTO_PROCESSING_SYNC, 8100u + i);
        job[i].jobPrimitiveInputOutput.inputPtr        = msg;
        job[i].jobPrimitiveInputOutput.inputLength     = sizeof(msg);
        job[i].jobPrimitiveInputOutput.outputPtr       = digest[i];
        job[i].jobPrimitiveInputOutput.outputLengthPtr = &dLen[i];
    }
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ && rc == 0; ++i) {
        if (hashStep(&job[i], CRYPTO_OPERATIONMODE_START) != E_OK) {
            fprintf(stderr, "  hash states: START %u rejected\n", i);
            rc = 1;
        }
    }
    if (rc == 0 && hashStep(&job[WH_AUTOSAR_HASH_SLOTS_PER_OBJ],
                            CRYPTO_OPERATIONMODE_START) != E_NOT_OK) {
        fprintf(stderr, "  hash states: START past the table accepted\n");
        rc = 1;
    }
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ && rc == 0; ++i) {
        if (hashStep(&job[i], CRYPTO_OPERATIONMODE_UPDATE) != E_OK ||
            hashStep(&job[i], CRYPTO_OPERATIONMODE_FINISH) != E_OK ||
            dLen[i] != 32u || memcmp(digest[i], want, 32u) != 0) {
            fprintf(stderr, "  hash states: stream %u after the full table\n",
                    i);
            rc = 1;
        }
    }
    if (rc == 0 && hashStep(&job[WH_AUTOSAR_HASH_SLOTS_PER_OBJ],
                            CRYPTO_OPERATIONMODE_SINGLECALL) != E_OK) {
        fprintf(stderr, "  hash states: no state free after FINISH\n");
        rc = 1;
    }
    if (rc == 0) {
        printf("  hash states: START %u rejected, open streams still finish\n",
               (unsigned)WH_AUTOSAR_HASH_SLOTS_PER_OBJ + 1u);
    }
    return rc;
}

/* Marks the open hash stream of jobId as failed, as a failed UPDATE does. */
static int markStreamErrored(uint32 jobId)
{
    wh_AutosarDriverObject* obj = wh_Autosar_GetDriverObject(0u);
    uint32                  i;
    int                     found = 0;

    wh_Autosar_LockSlots(obj);
    for (i = 0u; i < WH_AUTOSAR_HASH_SLOTS_PER_OBJ; ++i) {
        if (obj->hashStates[i].inUse && obj->hashStates[i].jobId == jobId) {
            obj->hashStates[i].errored = TRUE;
            found                      = 1;
        }
    }
    wh_Autosar_UnlockSlots(obj);
    return found;
}

static int testHashStreamErrored(void)
{
    static const uint8          msg[3] = {'a', 'b', 'c'};
    uint8                       digest[32];
    uint32                      dLen = sizeof(digest);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    wh_AutosarDriverObject*     obj = wh_Autosar_GetDriverObject(0u);

    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_SYNC, 8200u);
    job.jobPrimitiveInputOutput.inputPtr        = msg;
    job.jobPrimitiveInputOutput.inputLength     = sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    if (hashStep(&job, CRYPTO_OPERATIONMODE_STREAMSTART) != E_OK ||
        !markStreamErrored(job.jobId)) {
        fprintf(stderr, "  hash error: START\n");
        return 1;
    }
    if (hashStep(&job, CRYPTO_OPERATIONMODE_UPDATE) != E_NOT_OK ||
        wh_Autosar_DebugActiveHashStateCount(obj) != 1u) {
        fprintf(stderr, "  hash error: UPDATE after a failed UPDATE\n");
        return 1;
    }
    if (hashStep(&job, CRYPTO_OPERATIONMODE_FINISH) != E_NOT_OK ||
        wh_Autosar_DebugActiveHashStateCount(obj) != 0u ||
        job.jobState != CRYPTO_JOBSTATE_IDLE) {
        fprintf(stderr, "  hash error: FINISH did not release the stream\n");
        return 1;
    }
    if (hashStep(&job, CRYPTO_OPERATIONMODE_SINGLECALL) != E_OK) {
        fprintf(stderr, "  hash error: job id unusable after FINISH\n");
        return 1;
    }
    printf("  hash error: failed stream rejects UPDATE, FINISH frees it\n");
    return 0;
}
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/* Revoked entries fill most of the table so the server key cache stays free. */
#define LIMIT_WRITTEN_KEYS 4u

static int testKeyStateTableFullBody(void)
{
    static const uint8 k[16] = {0x6c};
    uint32             i;
    uint32             id;
    Std_ReturnType     ret;

    for (i = 0u; i < CRYPTO_MAX_INVALID_KEYS; ++i) {
        id = LIMIT_FIRST_KEY + i;
        if (i < LIMIT_WRITTEN_KEYS) {
            ret = Crypto_KeyElementSet(id, 1u, k, sizeof(k));
        }
        else {
            ret = Crypto_KeySetInvalid(id);
        }
        if (ret != E_OK) {
            fprintf(stderr, "  key table: key %u of %u rejected\n", i + 1u,
                    (unsigned)CRYPTO_MAX_INVALID_KEYS);
            return 1;
        }
    }
    id = LIMIT_FIRST_KEY + CRYPTO_MAX_INVALID_KEYS;
    if (Crypto_KeyElementSet(id, 1u, k, sizeof(k)) != CRYPTO_E_KEY_WRITE_FAIL ||
        Crypto_KeySetInvalid(id) != E_NOT_OK) {
        fprintf(stderr, "  key table: write past a full table accepted\n");
        return 1;
    }
    if (Crypto_KeySetValid(LIMIT_FIRST_KEY) != E_OK ||
        Crypto_KeyElementSet(id, 1u, k, sizeof(k)) != E_OK) {
        fprintf(stderr, "  key table: no entry free after KeySetValid\n");
        return 1;
    }
    printf("  key table: write %u rejected with CRYPTO_E_KEY_WRITE_FAIL\n",
           (unsigned)CRYPTO_MAX_INVALID_KEYS + 1u);
    return 0;
}

static int testKeyStateTableFull(void)
{
    uint32 keys[CRYPTO_MAX_INVALID_KEYS + 1u];
    uint32 i;

    for (i = 0u; i <= CRYPTO_MAX_INVALID_KEYS; ++i) {
        keys[i] = LIMIT_FIRST_KEY + i;
    }
    return testWithKeys(testKeyStateTableFullBody, keys,
                        sizeof(keys) / sizeof(keys[0]));
}

int testLimitsAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testAsyncSlotsFull);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    TEST_RUN(failures, testHashStatesFull);
    TEST_RUN(failures, testHashStreamErrored);
#endif
    TEST_RUN(failures, testKeyStateTableFull);
    return failures;
}
