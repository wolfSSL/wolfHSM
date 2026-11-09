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
 * port/autosar/classic/examples/csm_smoke/test_policy.c
 *
 * Key validity, key exchange policy, cancel windows and verify results.
 */

#include "test_helpers.h"

#include <stdlib.h>

#define POL_KEY 144u

static const uint8 kPolKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                  0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                  0x09, 0xcf, 0x4f, 0x3c};

static int installKey(uint32 keyId)
{
    return (Crypto_KeyElementSet(keyId, 1u, kPolKey, sizeof(kPolKey)) == E_OK &&
            Crypto_KeySetValid(keyId) == E_OK)
               ? 0
               : 1;
}

static void ecbJob(Crypto_JobType* job, Crypto_JobPrimitiveInfoType* jpi,
                   Crypto_PrimitiveInfoType* pi, uint32 keyId,
                   Crypto_ProcessingType pt, const uint8* in, uint8* out,
                   uint32* outLen)
{
    testBuildJob(job, jpi, pi, CRYPTO_ENCRYPT, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_ECB, keyId, pt, 7900u);
    job->jobPrimitiveInputOutput.inputPtr        = in;
    job->jobPrimitiveInputOutput.inputLength     = 16u;
    job->jobPrimitiveInputOutput.outputPtr       = out;
    job->jobPrimitiveInputOutput.outputLengthPtr = outLen;
}

static Std_ReturnType lastResultFor(const Crypto_JobType* job)
{
    Std_ReturnType ret = E_NOT_OK;
    pthread_mutex_lock(&gTestCb.lock);
    if (gTestCb.lastJob == job) {
        ret = gTestCb.lastResult;
    }
    pthread_mutex_unlock(&gTestCb.lock);
    return ret;
}

static int testAsyncKeyValidityBody(void)
{
    static const uint8          in[16]  = {0};
    static const uint8          mac[16] = {0};
    uint8                       out[16];
    uint32                      outLen = sizeof(out);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Crypto_VerifyResultType     ver = CRYPTO_E_VER_OK;
    int                         base;
    Std_ReturnType              ret;

    if (installKey(POL_KEY) != 0 || Crypto_KeySetInvalid(POL_KEY) != E_OK) {
        return 1;
    }
    /* Rejected at submission. */
    ecbJob(&job, &jpi, &pi, POL_KEY, CRYPTO_PROCESSING_ASYNC, in, out, &outLen);
    if (testCryIfProcessJob(0u, &job) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  validity: async job on invalid key accepted\n");
        return 1;
    }
    /* A failed verify leaves NOT_OK even though CRYPTO_E_VER_OK is 0. */
    testBuildJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_CMAC, POL_KEY, CRYPTO_PROCESSING_SYNC, 7901u);
    job.jobPrimitiveInputOutput.inputPtr             = in;
    job.jobPrimitiveInputOutput.inputLength          = 16u;
    job.jobPrimitiveInputOutput.secondaryInputPtr    = mac;
    job.jobPrimitiveInputOutput.secondaryInputLength = 128u;
    job.jobPrimitiveInputOutput.verifyPtr            = &ver;
    if (testCryIfProcessJob(0u, &job) != CRYPTO_E_KEY_NOT_VALID ||
        ver != CRYPTO_E_VER_NOT_OK) {
        fprintf(stderr, "  validity: verify result not preset to NOT_OK\n");
        return 1;
    }
    /* Invalidated while queued: rejected at promotion. */
    if (Crypto_KeySetValid(POL_KEY) != E_OK) {
        return 1;
    }
    ecbJob(&job, &jpi, &pi, POL_KEY, CRYPTO_PROCESSING_ASYNC, in, out, &outLen);
    base = testCallbackTotal();
    testPauseMainFunctionThread();
    ret = testCryIfProcessJob(0u, &job);
    if (ret == E_OK) {
        ret = Crypto_KeySetInvalid(POL_KEY);
    }
    testResumeMainFunctionThread();
    if (ret != E_OK || testWaitCallbacks(base + 1, 5000) != 0 ||
        lastResultFor(&job) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  validity: key invalidated while queued was used\n");
        return 1;
    }
    printf("  validity: async submit and promotion checks, verify preset\n");
    return 0;
}

static int testAsyncKeyValidity(void)
{
    static const uint32 keys[] = {POL_KEY};
    return testWithKeys(testAsyncKeyValidityBody, keys, 1);
}

static int testCancelPending(void)
{
    static const uint8          msg[16] = {'p', 'e', 'n', 'd'};
    uint8                       digest[32];
    uint32                      dLen = sizeof(digest);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    wh_AutosarDriverObject*     obj = wh_Autosar_GetDriverObject(0u);
    int                         before;
    Std_ReturnType              cancel = E_NOT_OK;
    uint32                      i;

    memset(digest, 0xA5, sizeof(digest));
    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_ASYNC, 7910u);
    job.jobPrimitiveInputOutput.inputPtr        = msg;
    job.jobPrimitiveInputOutput.inputLength     = sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    before                                      = testCallbacksForJob(&job);
    testPauseMainFunctionThread();
    /* One MainFunction promotes the job: its request is now on the wire. */
    if (testCryIfProcessJob(0u, &job) == E_OK) {
        wh_Autosar_MainFunctionObject(obj);
        cancel = Crypto_CancelJob(0u, &job);
    }
    testResumeMainFunctionThread();
    if (cancel != E_OK || testWaitDrain(2000) != 0) {
        fprintf(stderr, "  cancel: in-flight job not cancelled\n");
        return 1;
    }
    for (i = 0u; i < sizeof(digest); ++i) {
        if (digest[i] != 0xA5u) {
            fprintf(stderr, "  cancel: cancelled job wrote its output\n");
            return 1;
        }
    }
    if (testCallbacksForJob(&job) != before) {
        fprintf(stderr, "  cancel: callback for a cancelled job\n");
        return 1;
    }
    printf("  cancel: in-flight job drained without output or callback\n");
    return 0;
}

static int testCopyPartialUnreadableBody(void)
{
    static const uint8          in[16] = {0x11};
    uint8                       before[16];
    uint8                       after[16];
    uint32                      len = sizeof(before);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    if (installKey(150u) != 0 || installKey(151u) != 0) {
        return 1;
    }
    ecbJob(&job, &jpi, &pi, 151u, CRYPTO_PROCESSING_SYNC, in, before, &len);
    if (testCryIfProcessJob(0u, &job) != E_OK) {
        return 1;
    }
    /* 151 is non-exportable, so the bytes outside the copy are unknown. */
    if (Crypto_KeyElementCopyPartial(150u, 1u, 0u, 0u, 8u, 151u, 1u) !=
        CRYPTO_E_KEY_READ_FAIL) {
        fprintf(stderr, "  copy: partial copy into unreadable target\n");
        return 1;
    }
    len = sizeof(after);
    ecbJob(&job, &jpi, &pi, 151u, CRYPTO_PROCESSING_SYNC, in, after, &len);
    if (Crypto_KeySetValid(151u) != E_OK ||
        testCryIfProcessJob(0u, &job) != E_OK ||
        memcmp(before, after, sizeof(before)) != 0) {
        fprintf(stderr, "  copy: unreadable target was modified\n");
        return 1;
    }
    printf("  copy: partial copy refuses a target it cannot read\n");
    return 0;
}

static int testCopyPartialUnreadable(void)
{
    static const uint32 keys[] = {150u, 151u};
    return testWithKeys(testCopyPartialUnreadableBody, keys, 2);
}

static int testKeyExchangePolicyBody(void)
{
    uint8  pubA[64];
    uint8  pubB[64];
    uint8  priv[64];
    uint32 lenA    = sizeof(pubA);
    uint32 lenB    = sizeof(pubB);
    uint32 privLen = sizeof(priv);

    if (Crypto_KeyGenerate(120u) != E_OK) {
        fprintf(stderr, "  kex: KeyGenerate on an ECDH key\n");
        return 1;
    }
    if (Crypto_KeyExchangeCalcPubVal(120u, pubA, &lenA) != E_OK ||
        Crypto_KeyExchangeCalcPubVal(121u, pubB, &lenB) != E_OK) {
        fprintf(stderr, "  kex: CalcPubVal\n");
        return 1;
    }
    if (Crypto_KeyElementGet(120u, 1u, priv, &privLen) !=
        CRYPTO_E_KEY_READ_FAIL) {
        fprintf(stderr, "  kex: ephemeral private key readable\n");
        return 1;
    }
    if (Crypto_KeySetInvalid(120u) != E_OK ||
        Crypto_KeyExchangeCalcSecret(120u, pubB, lenB) !=
            CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  kex: CalcSecret on an invalidated key\n");
        return 1;
    }
    if (Crypto_KeyExchangeCalcSecret(121u, pubA, lenA) != E_OK) {
        fprintf(stderr, "  kex: CalcSecret\n");
        return 1;
    }
    printf("  kex: ECDH keygen, private key hidden, revoked key refused\n");
    return 0;
}

static int testKeyExchangePolicy(void)
{
    static const uint32 keys[] = {120u, 121u};
    return testWithKeys(testKeyExchangePolicyBody, keys, 2);
}

static int testAesKeyGenerateBody(void)
{
    static const uint8          in[16] = {0};
    uint8                       out[16];
    uint32                      outLen = sizeof(out);
    uint8                       buf[16];
    uint32                      bufLen = sizeof(buf);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    ecbJob(&job, &jpi, &pi, 126u, CRYPTO_PROCESSING_SYNC, in, out, &outLen);
    if (Crypto_KeyGenerate(126u) != E_OK || Crypto_KeySetValid(126u) != E_OK ||
        testCryIfProcessJob(0u, &job) != E_OK ||
        Crypto_KeyElementGet(126u, 1u, buf, &bufLen) !=
            CRYPTO_E_KEY_READ_FAIL) {
        fprintf(stderr, "  keygen: server-generated AES key\n");
        return 1;
    }
    printf("  keygen: AES key generated on the server\n");
    return 0;
}

static int testAesKeyGenerate(void)
{
    static const uint32 keys[] = {126u};
    return testWithKeys(testAesKeyGenerateBody, keys, 1);
}

static Std_ReturnType cmacGen(Crypto_ProcessingType pt, const uint8* in,
                              uint32 inLen, uint8* mac, uint32* macLen)
{
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;
    Std_ReturnType              ret;

    testBuildJob(&job, &jpi, &pi, CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_CMAC, POL_KEY, pt, 7920u);
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = inLen;
    job.jobPrimitiveInputOutput.outputPtr       = mac;
    job.jobPrimitiveInputOutput.outputLengthPtr = macLen;
    if (pt == CRYPTO_PROCESSING_SYNC) {
        return testCryIfProcessJob(0u, &job);
    }
    ret = testRunAsync(&job, &res);
    return (ret == E_OK) ? res : ret;
}

static int testAsyncCmacSizesBody(void)
{
    static const uint8 empty[1] = {0};
    uint8*             big;
    uint8              macS[16];
    uint8              macA[16];
    uint32             lenS = sizeof(macS);
    uint32             lenA = sizeof(macA);
    int                rc   = 0;

    if (installKey(POL_KEY) != 0) {
        return 1;
    }
    if (cmacGen(CRYPTO_PROCESSING_SYNC, empty, 0u, macS, &lenS) != E_OK ||
        cmacGen(CRYPTO_PROCESSING_ASYNC, empty, 0u, macA, &lenA) != E_OK ||
        memcmp(macS, macA, 16u) != 0) {
        fprintf(stderr, "  cmac: async empty message\n");
        return 1;
    }
    big = (uint8*)calloc(16384u, 1u);
    if (big == NULL) {
        return 1;
    }
    lenS = sizeof(macS);
    lenA = sizeof(macA);
    if (cmacGen(CRYPTO_PROCESSING_SYNC, big, 16384u, macS, &lenS) != E_OK ||
        cmacGen(CRYPTO_PROCESSING_ASYNC, big, 16384u, macA, &lenA) != E_OK ||
        memcmp(macS, macA, 16u) != 0) {
        fprintf(stderr, "  cmac: async 16 KiB message\n");
        rc = 1;
    }
    free(big);
    if (rc == 0) {
        printf("  cmac: async empty and 16 KiB messages match sync\n");
    }
    return rc;
}

static int testAsyncCmacSizes(void)
{
    static const uint32 keys[] = {POL_KEY};
    return testWithKeys(testAsyncCmacSizesBody, keys, 1);
}

static int testRejectedInputs(void)
{
    static const uint8          raw[3] = {'a', 'b', 'c'};
    uint8                       out[72];
    uint32                      outLen = sizeof(out);
    uint8                       tag[16];
    uint32                      tagLen = 8u;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    int                         pt;

    for (pt = 0; pt < 2; ++pt) {
        Crypto_ProcessingType p =
            pt ? CRYPTO_PROCESSING_ASYNC : CRYPTO_PROCESSING_SYNC;
        Std_ReturnType res = E_NOT_OK;
        Std_ReturnType ret;

        /* A 3-byte input is not a digest. */
        testBuildJob(&job, &jpi, &pi, CRYPTO_SIGNATUREGENERATE,
                     CRYPTO_ALGOFAM_ECCNIST, CRYPTO_ALGOMODE_NOT_SET, 101u, p,
                     7930u);
        job.jobPrimitiveInputOutput.inputPtr        = raw;
        job.jobPrimitiveInputOutput.inputLength     = sizeof(raw);
        job.jobPrimitiveInputOutput.outputPtr       = out;
        job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
        ret = pt ? testRunAsync(&job, &res) : testCryIfProcessJob(0u, &job);
        if (ret == E_OK && (!pt || res == E_OK)) {
            fprintf(stderr, "  inputs: ECDSA signed a raw message\n");
            return 1;
        }
    }
    /* GCM tags shorter than CRYPTO_AEAD_MIN_TAG_LEN. */
    testBuildJob(&job, &jpi, &pi, CRYPTO_AEADENCRYPT, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_GCM, POL_KEY, CRYPTO_PROCESSING_SYNC, 7931u);
    job.jobPrimitiveInputOutput.inputPtr                 = raw;
    job.jobPrimitiveInputOutput.inputLength              = sizeof(raw);
    job.jobPrimitiveInputOutput.outputPtr                = out;
    job.jobPrimitiveInputOutput.outputLengthPtr          = &outLen;
    job.jobPrimitiveInputOutput.secondaryOutputPtr       = tag;
    job.jobPrimitiveInputOutput.secondaryOutputLengthPtr = &tagLen;
    if (testCryIfProcessJob(0u, &job) == E_OK) {
        fprintf(stderr, "  inputs: 8-byte GCM tag accepted\n");
        return 1;
    }
    /* Key management jobs check their key id. */
    testDetReset();
    testBuildJob(&job, &jpi, &pi, CRYPTO_KEYSETINVALID, CRYPTO_ALGOFAM_NOT_SET,
                 CRYPTO_ALGOMODE_NOT_SET, 300u, CRYPTO_PROCESSING_SYNC, 7932u);
    if (testCryIfProcessJob(0u, &job) == E_OK ||
        testDetCount(CRYPTO_PROCESSJOB_SID, CRYPTO_E_PARAM_HANDLE) != 1) {
        fprintf(stderr, "  inputs: KEYSETINVALID job on unmapped key id\n");
        return 1;
    }
    printf("  inputs: raw ECDSA input, short GCM tag, key-job key id\n");
    return 0;
}

int testPolicyAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testAsyncKeyValidity);
    TEST_RUN(failures, testCancelPending);
    TEST_RUN(failures, testCopyPartialUnreadable);
    TEST_RUN(failures, testKeyExchangePolicy);
    TEST_RUN(failures, testAesKeyGenerate);
    TEST_RUN(failures, testAsyncCmacSizes);
    TEST_RUN(failures, testRejectedInputs);
    return failures;
}
