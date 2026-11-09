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
 * port/autosar/classic/examples/csm_smoke/test_edge.c
 *
 * Parameter checks and edge cases of the job dispatcher and key handling.
 */

#include "test_helpers.h"

#include "wolfhsm/wh_client.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/kdf.h"

#define EDGE_KEY 144u

static const uint8 kKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

static int installEdgeKey(uint32 keyId)
{
    return (Crypto_KeyElementSet(keyId, 1u, kKey, sizeof(kKey)) == E_OK &&
            Crypto_KeySetValid(keyId) == E_OK)
               ? 0
               : 1;
}

static Std_ReturnType runJob(Crypto_JobType* job)
{
    Std_ReturnType res = E_NOT_OK;
    Std_ReturnType ret;

    if (job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_SYNC) {
        return testCryIfProcessJob(0u, job);
    }
    ret = testRunAsync(job, &res);
    return (ret == E_OK) ? res : ret;
}

static Std_ReturnType cmacJob(uint32 keyId, Crypto_ServiceInfoType svc,
                              Crypto_ProcessingType pt, uint8* mac,
                              uint32* macLen, Crypto_VerifyResultType* ver)
{
    static const uint8          msg[16] = {0x6b, 0xc1, 0xbe, 0xe2};
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, svc, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOMODE_CMAC,
                 keyId, pt, 7800u);
    job.jobPrimitiveInputOutput.inputPtr    = msg;
    job.jobPrimitiveInputOutput.inputLength = sizeof(msg);
    if (svc == CRYPTO_MACGENERATE) {
        job.jobPrimitiveInputOutput.outputPtr       = mac;
        job.jobPrimitiveInputOutput.outputLengthPtr = macLen;
    }
    else {
        job.jobPrimitiveInputOutput.secondaryInputPtr    = mac;
        job.jobPrimitiveInputOutput.secondaryInputLength = *macLen;
        job.jobPrimitiveInputOutput.verifyPtr            = ver;
    }
    return runJob(&job);
}

static int testCmacTruncatedBody(void)
{
    static const uint32     bits[3] = {128u, 100u, 64u};
    uint8                   mac[16];
    uint32                  macLen = 8u;
    uint32                  n;
    int                     i, pt;
    Crypto_VerifyResultType rejVer = CRYPTO_E_VER_OK;

    if (installEdgeKey(EDGE_KEY) != 0 ||
        cmacJob(EDGE_KEY, CRYPTO_MACGENERATE, CRYPTO_PROCESSING_SYNC, mac,
                &macLen, NULL) != E_OK ||
        macLen != 8u) {
        fprintf(stderr, "  cmac: truncated generate\n");
        return 1;
    }
    macLen = sizeof(mac);
    if (cmacJob(EDGE_KEY, CRYPTO_MACGENERATE, CRYPTO_PROCESSING_ASYNC, mac,
                &macLen, NULL) != E_OK ||
        macLen != 16u) {
        fprintf(stderr, "  cmac: async generate\n");
        return 1;
    }
    for (i = 0; i < 3; ++i) {
        for (pt = 0; pt < 2; ++pt) {
            Crypto_ProcessingType p =
                pt ? CRYPTO_PROCESSING_ASYNC : CRYPTO_PROCESSING_SYNC;
            Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;
            uint8                   bad[16];

            n = bits[i];
            if (cmacJob(EDGE_KEY, CRYPTO_MACVERIFY, p, mac, &n, &ver) != E_OK ||
                ver != CRYPTO_E_VER_OK) {
                fprintf(stderr, "  cmac: %u-bit verify (%s)\n", bits[i],
                        pt ? "async" : "sync");
                return 1;
            }
            /* Flip the last bit inside the compared length. */
            memcpy(bad, mac, sizeof(bad));
            bad[(bits[i] - 1u) / 8u] ^= (uint8)(0x80u >> ((bits[i] - 1u) % 8u));
            ver = CRYPTO_E_VER_OK;
            if (cmacJob(EDGE_KEY, CRYPTO_MACVERIFY, p, bad, &n, &ver) != E_OK ||
                ver != CRYPTO_E_VER_NOT_OK) {
                fprintf(stderr, "  cmac: %u-bit tamper (%s)\n", bits[i],
                        pt ? "async" : "sync");
                return 1;
            }
        }
    }
    /* Below CRYPTO_CMAC_MIN_VERIFY_BITS; the result must stay NOT_OK. */
    n = 28u;
    if (cmacJob(EDGE_KEY, CRYPTO_MACVERIFY, CRYPTO_PROCESSING_SYNC, mac, &n,
                &rejVer) == E_OK ||
        rejVer != CRYPTO_E_VER_NOT_OK) {
        fprintf(stderr, "  cmac: 28-bit verify accepted\n");
        return 1;
    }
    printf("  cmac: 128/100/64-bit verify and truncated generate, sync + "
           "async\n");
    return 0;
}

static int testCmacTruncated(void)
{
    static const uint32 keys[] = {EDGE_KEY};
    return testWithKeys(testCmacTruncatedBody, keys, 1);
}

static int testDerivedKeyUsableBody(void)
{
    static const uint8 ikm[32] = {0x0b, 0x0b, 0x0b};
    uint8              mac[16];
    uint32             macLen = sizeof(mac);

    if (Crypto_KeyElementSet(134u, 1u, ikm, sizeof(ikm)) != E_OK ||
        Crypto_KeySetValid(134u) != E_OK ||
        Crypto_KeyDerive(134u, 124u) != E_OK ||
        Crypto_KeySetValid(124u) != E_OK) {
        fprintf(stderr, "  derive: setup\n");
        return 1;
    }
    if (cmacJob(124u, CRYPTO_MACGENERATE, CRYPTO_PROCESSING_SYNC, mac, &macLen,
                NULL) != E_OK) {
        fprintf(stderr, "  derive: derived key rejected for CMAC\n");
        return 1;
    }
    printf("  derive: HKDF output usable as a CMAC key\n");
    return 0;
}

static int testDerivedKeyUsable(void)
{
    static const uint32 keys[] = {134u, 124u};
    return testWithKeys(testDerivedKeyUsableBody, keys, 2);
}

static Std_ReturnType aesJob(Crypto_ServiceInfoType   svc,
                             Crypto_AlgorithmModeType mode, uint32 keyId,
                             Crypto_ProcessingType pt, const uint8* in,
                             uint32 inLen, uint8* out, uint32* outLen)
{
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, svc, CRYPTO_ALGOFAM_AES, mode, keyId, pt,
                 7810u);
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = inLen;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = outLen;
    return runJob(&job);
}

static int testJobChecksBody(void)
{
    static const uint8 iv[16] = {0};
    uint8              in[32] = {0};
    uint8              out[48];
    uint32             outLen;
    int                pt;

    if (installEdgeKey(EDGE_KEY) != 0) {
        return 1;
    }
    for (pt = 0; pt < 2; ++pt) {
        Crypto_ProcessingType p =
            pt ? CRYPTO_PROCESSING_ASYNC : CRYPTO_PROCESSING_SYNC;

        /* Output buffer smaller than the input. */
        memset(out, 0xA5, sizeof(out));
        outLen = 16u;
        if (aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_ECB, EDGE_KEY, p, in, 32u,
                   out, &outLen) == E_OK ||
            out[16] != 0xA5u) {
            fprintf(stderr, "  checks: small output accepted\n");
            return 1;
        }
        /* Zero length and a partial block. */
        outLen = sizeof(out);
        if (aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_ECB, EDGE_KEY, p, in, 0u,
                   out, &outLen) == E_OK ||
            aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_ECB, EDGE_KEY, p, in, 15u,
                   out, &outLen) == E_OK) {
            fprintf(stderr, "  checks: bad ECB length accepted\n");
            return 1;
        }
        /* Unmapped key id. */
        if (aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_ECB, 300u, p, in, 16u, out,
                   &outLen) == E_OK) {
            fprintf(stderr, "  checks: unmapped key id accepted\n");
            return 1;
        }
        /* The IV is consumed by one job. */
        if (Crypto_KeyElementSet(EDGE_KEY, 5u, iv, sizeof(iv)) != E_OK ||
            aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_CBC, EDGE_KEY, p, in, 16u,
                   out, &outLen) != E_OK ||
            aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_CBC, EDGE_KEY, p, in, 16u,
                   out, &outLen) == E_OK) {
            fprintf(stderr, "  checks: IV reused\n");
            return 1;
        }
    }
    printf("  checks: buffer, length, key id and IV checks\n");
    return 0;
}

static int testJobChecks(void)
{
    static const uint32 keys[] = {EDGE_KEY};
    return testWithKeys(testJobChecksBody, keys, 1);
}

static int testVerifyAndHashChecksBody(void)
{
    uint8                       in[32] = {0};
    uint8                       out[48];
    uint32                      outLen = sizeof(out);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    uint8                       sig[16] = {0};
    uint8                       digest[32];
    uint32                      dLen = 16u;

    if (installEdgeKey(EDGE_KEY) != 0) {
        return 1;
    }

    /* Verify without verifyPtr. */
    testBuildJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_CMAC, EDGE_KEY, CRYPTO_PROCESSING_SYNC, 7820u);
    job.jobPrimitiveInputOutput.inputPtr             = in;
    job.jobPrimitiveInputOutput.inputLength          = 16u;
    job.jobPrimitiveInputOutput.secondaryInputPtr    = sig;
    job.jobPrimitiveInputOutput.secondaryInputLength = 128u;
    if (testCryIfProcessJob(0u, &job) == E_OK) {
        fprintf(stderr, "  checks: verify without verifyPtr accepted\n");
        return 1;
    }
    /* Unsupported signature hash family. */
    testBuildJob(&job, &jpi, &pi, CRYPTO_SIGNATUREGENERATE,
                 CRYPTO_ALGOFAM_ECCNIST, CRYPTO_ALGOMODE_NOT_SET, 101u,
                 CRYPTO_PROCESSING_SYNC, 7821u);
    pi.algorithm.secondaryFamily                = CRYPTO_ALGOFAM_SHA1;
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = 16u;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    if (testCryIfProcessJob(0u, &job) == E_OK) {
        fprintf(stderr, "  checks: unknown hash family accepted\n");
        return 1;
    }
    /* Async hash into a too-small digest buffer, then a normal job. */
    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_ASYNC, 7822u);
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = 16u;
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    if (testCryIfProcessJob(0u, &job) == E_OK) {
        fprintf(stderr, "  checks: small digest buffer accepted\n");
        return 1;
    }
    dLen = sizeof(digest);
    if (runJob(&job) != E_OK || dLen != 32u) {
        fprintf(stderr, "  checks: hash after rejected job\n");
        return 1;
    }
    printf("  checks: verifyPtr, hash family and digest size checks\n");
    return 0;
}

static int testVerifyAndHashChecks(void)
{
    static const uint32 keys[] = {EDGE_KEY};
    return testWithKeys(testVerifyAndHashChecksBody, keys, 1);
}

static int testKeyStateEdgesBody(void)
{
    whClientContext*     ctx = NULL;
    uint8                buf[16];
    uint32               len = sizeof(buf);
    uint8                out[16];
    uint32               outLen = sizeof(out);
    Crypto_KeyStatusType st;

    /* Non-exportable key material cannot be read back. */
    if (installEdgeKey(145u) != 0 ||
        Crypto_KeyElementGet(145u, 1u, buf, &len) != CRYPTO_E_KEY_READ_FAIL) {
        fprintf(stderr, "  keystate: non-exportable key read back\n");
        return 1;
    }
    /* A committed key that left the cache can be set valid again. */
    if (wh_Autosar_KeystoreBegin(&ctx) != E_OK) {
        return 1;
    }
    (void)wh_Client_KeyEvict(ctx, wh_Autosar_ComposeKeyId(145u, 1u));
    wh_Autosar_KeystoreEnd(ctx);
    if (Crypto_KeySetInvalid(145u) != E_OK ||
        Crypto_KeySetValid(145u) != E_OK ||
        Crypto_KeyGetStatus(145u, &st) != E_OK ||
        st != CRYPTO_KEYSTATUS_VALID ||
        aesJob(CRYPTO_ENCRYPT, CRYPTO_ALGOMODE_ECB, 145u,
               CRYPTO_PROCESSING_SYNC, kKey, 16u, out, &outLen) != E_OK) {
        fprintf(stderr, "  keystate: NVM-only key not re-validated\n");
        return 1;
    }
    printf("  keystate: read protection, re-validating an NVM-only key\n");
    return 0;
}

static int testKeyStateEdges(void)
{
    static const uint32 keys[] = {145u};
    return testWithKeys(testKeyStateEdgesBody, keys, 1);
}

static int testCancelStreamedHash(void)
{
    static const uint8          msg[4] = {'a', 'b', 'c', 'd'};
    uint8                       digest[32];
    uint32                      dLen = sizeof(digest);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_SYNC, 7830u);
    job.jobPrimitiveInputOutput.mode        = CRYPTO_OPERATIONMODE_STREAMSTART;
    job.jobPrimitiveInputOutput.inputPtr    = msg;
    job.jobPrimitiveInputOutput.inputLength = sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr   = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    if (testCryIfProcessJob(0u, &job) != E_OK ||
        wh_Autosar_DebugActiveHashStateCount(wh_Autosar_GetDriverObject(0u)) !=
            1u ||
        Crypto_CancelJob(0u, &job) != E_OK ||
        wh_Autosar_DebugActiveHashStateCount(wh_Autosar_GetDriverObject(0u)) !=
            0u) {
        fprintf(stderr, "  cancel: streamed hash state not released\n");
        return 1;
    }
    printf("  cancel: streamed hash state released\n");
    return 0;
}

static int testLargeAsyncRng(void)
{
    static uint8                out[2000];
    uint32                      outLen = sizeof(out);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;

    testBuildJob(&job, &jpi, &pi, CRYPTO_RANDOMGENERATE, CRYPTO_ALGOFAM_RNG,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_ASYNC, 7840u);
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    if (testRunAsync(&job, &res) != E_OK || res != E_OK ||
        outLen != sizeof(out)) {
        fprintf(stderr, "  rng: 2000-byte async RandomGenerate\n");
        return 1;
    }
    printf("  rng: 2000-byte async RandomGenerate OK\n");
    return 0;
}

static int testDeriveSaltBody(void)
{
    static const uint8 ikm[32]  = {0x0b, 0x0b, 0x0b, 0x01};
    static const uint8 salt[16] = {'s', 'a', 'l', 't', '-', '0', '1', '2',
                                   '3', '4', '5', '6', '7', '8', '9', 'a'};
    uint8              want[32];
    uint8              got[32];
    uint32             gotLen = sizeof(got);
    uint32             ids[4];
    uint32             nIds = 4u;

    if (Crypto_KeyElementSet(134u, 1u, ikm, sizeof(ikm)) != E_OK ||
        Crypto_KeyElementSet(134u, 13u, salt, sizeof(salt)) != E_OK ||
        Crypto_KeySetValid(134u) != E_OK ||
        Crypto_KeyElementIdsGet(134u, ids, &nIds) != E_OK || nIds != 2u ||
        ids[1] != 13u) {
        fprintf(stderr, "  salt: setup\n");
        return 1;
    }
    if (Crypto_KeyDerive(134u, 124u) != E_OK ||
        Crypto_KeyElementGet(124u, 1u, got, &gotLen) != E_OK || gotLen != 32u ||
        wc_HKDF(WC_SHA256, ikm, sizeof(ikm), salt, sizeof(salt), NULL, 0u, want,
                32u) != 0 ||
        memcmp(got, want, 32u) != 0) {
        fprintf(stderr, "  salt: HKDF output differs from software\n");
        return 1;
    }
    gotLen = sizeof(got);
    if (Crypto_KeyDerive(134u, 125u) != E_OK ||
        Crypto_KeyElementGet(125u, 1u, got, &gotLen) != E_OK || gotLen != 16u ||
        wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), ikm, sizeof(ikm), NULL, 0u,
                                want, 16u, NULL, INVALID_DEVID) != 0 ||
        memcmp(got, want, 16u) != 0) {
        fprintf(stderr, "  salt: CMAC-KDF output differs from software\n");
        return 1;
    }
    printf("  salt: HKDF and CMAC-KDF use the salt element\n");
    return 0;
}

static int testDeriveSalt(void)
{
    static const uint32 keys[] = {134u, 124u, 125u};
    return testWithKeys(testDeriveSaltBody, keys, 3);
}

/* Builds an async CBC encrypt job on EDGE_KEY. */
static void cbcAsyncJob(Crypto_JobType* job, Crypto_JobPrimitiveInfoType* jpi,
                        Crypto_PrimitiveInfoType* pi, uint32 jobId,
                        const uint8* in, uint8* out, uint32* outLen)
{
    testBuildJob(job, jpi, pi, CRYPTO_ENCRYPT, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_CBC, EDGE_KEY, CRYPTO_PROCESSING_ASYNC, jobId);
    job->jobPrimitiveInputOutput.inputPtr        = in;
    job->jobPrimitiveInputOutput.inputLength     = 16u;
    job->jobPrimitiveInputOutput.outputPtr       = out;
    job->jobPrimitiveInputOutput.outputLengthPtr = outLen;
}

static int testAsyncIvCaptureBody(void)
{
    static const uint8          in[16]  = {0x6b, 0xc1, 0xbe, 0xe2};
    static const uint8          iv1[16] = {0x01};
    static const uint8          iv2[16] = {0x02};
    uint8                       out1[16];
    uint8                       out2[16];
    uint8                       want[16];
    uint32                      len1 = sizeof(out1);
    uint32                      len2 = sizeof(out2);
    Crypto_PrimitiveInfoType    pi1, pi2;
    Crypto_JobPrimitiveInfoType jpi1, jpi2;
    Crypto_JobType              job1, job2;
    Aes                         aes;
    int                         base;
    int                         rc = 1;

    if (installEdgeKey(EDGE_KEY) != 0) {
        return 1;
    }
    cbcAsyncJob(&job1, &jpi1, &pi1, 7850u, in, out1, &len1);
    cbcAsyncJob(&job2, &jpi2, &pi2, 7851u, in, out2, &len2);
    base = testCallbackTotal();
    testPauseMainFunctionThread();
    if (Crypto_KeyElementSet(EDGE_KEY, 5u, iv1, sizeof(iv1)) == E_OK &&
        testCryIfProcessJob(0u, &job1) == E_OK &&
        Crypto_KeyElementSet(EDGE_KEY, 5u, iv2, sizeof(iv2)) == E_OK &&
        testCryIfProcessJob(0u, &job2) == E_OK) {
        rc = 0;
    }
    testResumeMainFunctionThread();
    if (rc != 0 || testWaitCallbacks(base + 2, 5000) != 0) {
        fprintf(stderr, "  iv: async submit\n");
        return 1;
    }
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return 1;
    }
    if (wc_AesSetKey(&aes, kKey, sizeof(kKey), iv1, AES_ENCRYPTION) != 0 ||
        wc_AesCbcEncrypt(&aes, want, in, 16u) != 0 ||
        memcmp(want, out1, 16u) != 0 ||
        wc_AesSetKey(&aes, kKey, sizeof(kKey), iv2, AES_ENCRYPTION) != 0 ||
        wc_AesCbcEncrypt(&aes, want, in, 16u) != 0 ||
        memcmp(want, out2, 16u) != 0) {
        rc = 1;
    }
    wc_AesFree(&aes);
    if (rc != 0) {
        fprintf(stderr, "  iv: queued job did not keep its own IV\n");
        return 1;
    }
    printf("  iv: async jobs keep the IV set at submission\n");
    return 0;
}

static int testAsyncIvCapture(void)
{
    static const uint32 keys[] = {EDGE_KEY};
    return testWithKeys(testAsyncIvCaptureBody, keys, 1);
}

static int testStreamJobState(void)
{
    static const uint8          msg[4] = {'a', 'b', 'c', 'd'};
    static const uint8          iv[16] = {0};
    uint8                       digest[32];
    uint32                      dLen = sizeof(digest);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_SYNC, 7860u);
    job.jobPrimitiveInputOutput.inputPtr        = msg;
    job.jobPrimitiveInputOutput.inputLength     = sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_STREAMSTART;
    if (testCryIfProcessJob(0u, &job) != E_OK ||
        job.jobState != CRYPTO_JOBSTATE_ACTIVE) {
        fprintf(stderr, "  jobstate: not ACTIVE after START\n");
        return 1;
    }
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_FINISH;
    if (testCryIfProcessJob(0u, &job) != E_OK ||
        job.jobState != CRYPTO_JOBSTATE_IDLE) {
        fprintf(stderr, "  jobstate: not IDLE after FINISH\n");
        return 1;
    }
    pi.algorithm.family              = CRYPTO_ALGOFAM_SHA2_224;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &job) == E_OK) {
        fprintf(stderr, "  jobstate: SHA-224 job accepted\n");
        return 1;
    }
    testDetReset();
    if (Crypto_KeyElementSet(300u, 5u, iv, sizeof(iv)) == E_OK ||
        testDetCount(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_HANDLE) != 1) {
        fprintf(stderr, "  jobstate: IV accepted for an unmapped key\n");
        return 1;
    }
    printf("  jobstate: stream state, SHA-224 and IV key id checks\n");
    return 0;
}

int testEdgeAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testCmacTruncated);
    TEST_RUN(failures, testDerivedKeyUsable);
    TEST_RUN(failures, testJobChecks);
    TEST_RUN(failures, testVerifyAndHashChecks);
    TEST_RUN(failures, testKeyStateEdges);
    TEST_RUN(failures, testCancelStreamedHash);
    TEST_RUN(failures, testLargeAsyncRng);
    TEST_RUN(failures, testDeriveSalt);
    TEST_RUN(failures, testAsyncIvCapture);
    TEST_RUN(failures, testStreamJobState);
    return failures;
}
