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
 * DET coverage: bad parameters report the SWS (apiId, errorId).
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>

static int expectDet(uint8 apiId, uint8 errorId, const char* label)
{
    int n = testDetCount(apiId, errorId);
    if (n == 0) {
        fprintf(stderr,
                "  det: %s - expected (api=0x%02x, err=0x%02x) not reported\n",
                label, apiId, errorId);
        return 1;
    }
    return 0;
}

static int testDetProcessJobNullJob(void)
{
    testDetReset();
    if (testCryIfProcessJob(0u, NULL) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER,
                     "ProcessJob(NULL)");
}

static int testDetProcessJobNullPrimitiveInfo(void)
{
    Crypto_JobPrimitiveInfoType jpi = {0u, NULL, 0u, CRYPTO_PROCESSING_SYNC};
    Crypto_JobType              job = {0};
    job.jobPrimitiveInfo            = &jpi;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER,
                     "ProcessJob(NULL primitiveInfo)");
}

static int testDetProcessJobBadObjectId(void)
{
    Crypto_PrimitiveInfoType    pi  = {CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, CRYPTO_PROCESSING_SYNC};
    uint8                       out[32];
    uint32                      outLen          = sizeof(out);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 9001u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    testDetReset();
    /* CRYPTO_DRIVER_OBJECT_COUNT is 1 in the smoke; id 99 is out-of-range. */
    if (testCryIfProcessJob(99u, &job) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_HANDLE,
                     "ProcessJob(bad objectId)");
}

static int testDetGetVersionInfoNull(void)
{
    testDetReset();
    Crypto_GetVersionInfo(NULL);
    return expectDet(CRYPTO_GETVERSIONINFO_SID, CRYPTO_E_PARAM_POINTER,
                     "GetVersionInfo(NULL)");
}

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
    return expectDet(CRYPTO_CANCELJOB_SID, CRYPTO_E_PARAM_POINTER,
                     "CancelJob(NULL)");
}

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
    /* cryptoKeyId 0x100 is outside the 8-bit key id range. */
    if (Crypto_KeyElementSet(0x100u, 1u, k, sizeof(k)) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_HANDLE,
                     "KeyElementSet(out-of-range cryptoKeyId)");
}

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

static int testDetKeyElementGetZeroLength(void)
{
    uint8  buf[8];
    uint32 len = 0u;
    testDetReset();
    if (Crypto_KeyElementGet(0x10u, 1u, buf, &len) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_VALUE,
                     "KeyElementGet(*resultLength=0)");
}

static int testDetKeyElementIdsGet(void)
{
    uint32 ids[4];
    uint32 len = 4u;
    testDetReset();
    if (Crypto_KeyElementIdsGet(0x10u, NULL, &len) != E_NOT_OK ||
        Crypto_KeyElementIdsGet(0x10u, ids, NULL) != E_NOT_OK ||
        testDetCount(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_PARAM_POINTER) !=
            2) {
        fprintf(stderr, "  det: KeyElementIdsGet(NULL)\n");
        return 1;
    }
    if (Crypto_KeyElementIdsGet(0x100u, ids, &len) != E_NOT_OK ||
        expectDet(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_PARAM_HANDLE,
                  "KeyElementIdsGet(bad cryptoKeyId)") != 0) {
        return 1;
    }
    len = 0u;
    if (Crypto_KeyElementIdsGet(0x10u, ids, &len) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_SMALL_BUFFER,
                     "KeyElementIdsGet(*len=0)");
}

static int testDetKeyElementCopy(void)
{
    testDetReset();
    if (Crypto_KeyElementCopy(0x100u, 1u, 0x10u, 1u) != E_NOT_OK ||
        Crypto_KeyElementCopy(0x10u, 1u, 0x11u, 5u) != E_NOT_OK ||
        testDetCount(CRYPTO_KEYELEMENTCOPY_SID, CRYPTO_E_PARAM_HANDLE) != 2) {
        fprintf(stderr, "  det: KeyElementCopy(bad source / target)\n");
        return 1;
    }
    return 0;
}

static int testDetKeyElementCopyPartial(void)
{
    testDetReset();
    if (Crypto_KeyElementCopyPartial(0x10u, 1u, 0u, 0u, 8u, 0x100u, 1u) !=
            E_NOT_OK ||
        expectDet(CRYPTO_KEYELEMENTCOPYPARTIAL_SID, CRYPTO_E_PARAM_HANDLE,
                  "KeyElementCopyPartial(bad target)") != 0) {
        return 1;
    }
    /* Zero length, length over the copy buffer, target offset overflow. */
    testDetReset();
    if (Crypto_KeyElementCopyPartial(0x10u, 1u, 0u, 0u, 0u, 0x11u, 1u) !=
            E_NOT_OK ||
        Crypto_KeyElementCopyPartial(0x10u, 1u, 0u, 0u, 513u, 0x11u, 1u) !=
            E_NOT_OK ||
        Crypto_KeyElementCopyPartial(0x10u, 1u, 0u, 0xFFFFFFF8u, 16u, 0x11u,
                                     1u) != E_NOT_OK ||
        testDetCount(CRYPTO_KEYELEMENTCOPYPARTIAL_SID, CRYPTO_E_PARAM_VALUE) !=
            3) {
        fprintf(stderr, "  det: KeyElementCopyPartial(bad length/offset)\n");
        return 1;
    }
    return 0;
}

static int testDetKeyState(void)
{
    Crypto_KeyStatusType st;
    testDetReset();
    if (Crypto_KeySetValid(0x100u) != E_NOT_OK ||
        expectDet(CRYPTO_KEYSETVALID_SID, CRYPTO_E_PARAM_HANDLE,
                  "KeySetValid(bad cryptoKeyId)") != 0 ||
        Crypto_KeySetInvalid(0x100u) != E_NOT_OK ||
        expectDet(CRYPTO_KEYSETINVALID_SID, CRYPTO_E_PARAM_HANDLE,
                  "KeySetInvalid(bad cryptoKeyId)") != 0 ||
        Crypto_KeyGetStatus(0x10u, NULL) != E_NOT_OK ||
        expectDet(CRYPTO_KEYGETSTATUS_SID, CRYPTO_E_PARAM_POINTER,
                  "KeyGetStatus(NULL)") != 0 ||
        Crypto_KeyGetStatus(0x100u, &st) != E_NOT_OK) {
        return 1;
    }
    return expectDet(CRYPTO_KEYGETSTATUS_SID, CRYPTO_E_PARAM_HANDLE,
                     "KeyGetStatus(bad cryptoKeyId)");
}

static int testDetProcessJobBuffers(void)
{
    static const uint8          in[32] = {0};
    uint8                       out[32];
    uint32                      outLen = 16u;
    Crypto_VerifyResultType     ver;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_SYNC, 9010u);
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = sizeof(in);
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK ||
        expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_SMALL_BUFFER,
                  "ProcessJob(16-byte SHA-256 digest buffer)") != 0) {
        return 1;
    }
    outLen                               = sizeof(out);
    job.jobPrimitiveInputOutput.inputPtr = NULL;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK ||
        expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER,
                  "ProcessJob(NULL input, non-zero length)") != 0) {
        return 1;
    }
    /* Validation fails before the key is read. */
    testBuildJob(&job, &jpi, &pi, CRYPTO_ENCRYPT, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_ECB, 0x10u, CRYPTO_PROCESSING_SYNC, 9011u);
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = 15u;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK ||
        expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_VALUE,
                  "ProcessJob(15-byte ECB input)") != 0) {
        return 1;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_CMAC, 0x10u, CRYPTO_PROCESSING_SYNC, 9012u);
    job.jobPrimitiveInputOutput.inputPtr             = in;
    job.jobPrimitiveInputOutput.inputLength          = 16u;
    job.jobPrimitiveInputOutput.secondaryInputPtr    = in;
    job.jobPrimitiveInputOutput.secondaryInputLength = 32u;
    job.jobPrimitiveInputOutput.verifyPtr            = &ver;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK ||
        expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_VALUE,
                  "ProcessJob(32-bit CMAC verify)") != 0) {
        return 1;
    }
    job.jobPrimitiveInputOutput.verifyPtr = NULL;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK)
        return 1;
    return expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_POINTER,
                     "ProcessJob(verify without verifyPtr)");
}

int testDetBeforeInit(void)
{
    uint8                       out[16];
    uint32                      outLen = sizeof(out);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    int                         failures = 0;

    testBuildJob(&job, &jpi, &pi, CRYPTO_RANDOMGENERATE, CRYPTO_ALGOFAM_RNG,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_SYNC, 9020u);
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    testDetReset();
    if (testCryIfProcessJob(0u, &job) != E_NOT_OK ||
        Crypto_CancelJob(0u, &job) != E_NOT_OK ||
        expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_UNINIT,
                  "ProcessJob before Init") != 0 ||
        expectDet(CRYPTO_CANCELJOB_SID, CRYPTO_E_UNINIT,
                  "CancelJob before Init") != 0) {
        failures++;
    }
    /* main() runs the real Crypto_Init afterwards. */
    gTestFailClientConfig = 1;
    testDetReset();
    Crypto_Init(NULL);
    gTestFailClientConfig = 0;
    if (expectDet(CRYPTO_INIT_SID, CRYPTO_E_INIT_FAILED, "Init(hook fails)") !=
            0 ||
        testCryIfProcessJob(0u, &job) != E_NOT_OK ||
        expectDet(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_HANDLE,
                  "ProcessJob on a failed object") != 0 ||
        Crypto_KeyElementSet(0x10u, 1u, out, sizeof(out)) != E_NOT_OK ||
        expectDet(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_UNINIT,
                  "KeyElementSet without a keystore client") != 0) {
        failures++;
    }
    if (failures == 0) {
        printf("  DET: UNINIT before Init, INIT_FAILED and its fallout\n");
    }
    return failures;
}

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
    TEST_RUN(failures, testDetKeyElementGetZeroLength);
    TEST_RUN(failures, testDetKeyElementIdsGet);
    TEST_RUN(failures, testDetKeyElementCopy);
    TEST_RUN(failures, testDetKeyElementCopyPartial);
    TEST_RUN(failures, testDetKeyState);
    TEST_RUN(failures, testDetProcessJobBuffers);
    if (failures == 0) {
        printf("  DET: parameter checks report the SWS (apiId, errorId)\n");
    }
    return failures;
}
