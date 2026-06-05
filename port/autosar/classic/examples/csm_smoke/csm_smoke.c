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
 * port/autosar/classic/examples/csm_smoke/csm_smoke.c
 *
 * Stand-alone test runner for the wolfHSM AUTOSAR Crypto Driver.
 * Owns the platform hooks (TCP transport), the key descriptor table,
 * the existing "basic" tests, and the main() that drives the
 * per-category test files (test_kat.c, test_det.c, ...).
 */

#include "test_helpers.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"
#include "port/posix/posix_transport_tcp.h"
#include "wolfssl/wolfcrypt/ecc.h"

#define SMOKE_CLIENT_ID 7u

/* --- Platform hook --------------------------------------------------- */

static posixTransportTcpClientContext s_tcpCtx[CRYPTO_DRIVER_OBJECT_COUNT];
static posixTransportTcpConfig        s_tcpCfg[CRYPTO_DRIVER_OBJECT_COUNT];
static whCommClientConfig             s_commCfg[CRYPTO_DRIVER_OBJECT_COUNT];
static whClientConfig                 s_clientCfg[CRYPTO_DRIVER_OBJECT_COUNT];
static whTransportClientCb            s_tcpCb       = PTT_CLIENT_CB;
static int                            s_nextHookIdx = 0;

int wh_Autosar_PlatformClientConfig(whClientContext* client)
{
    int idx = s_nextHookIdx++;
    if (idx >= (int)(sizeof(s_tcpCtx) / sizeof(s_tcpCtx[0]))) {
        return WH_ERROR_BADARGS;
    }
    memset(&s_tcpCtx[idx], 0, sizeof(s_tcpCtx[idx]));
    memset(&s_tcpCfg[idx], 0, sizeof(s_tcpCfg[idx]));
    s_tcpCfg[idx].server_ip_string = "127.0.0.1";
    s_tcpCfg[idx].server_port      = 23456;
    memset(&s_commCfg[idx], 0, sizeof(s_commCfg[idx]));
    s_commCfg[idx].transport_cb      = &s_tcpCb;
    s_commCfg[idx].transport_context = &s_tcpCtx[idx];
    s_commCfg[idx].transport_config  = &s_tcpCfg[idx];
    s_commCfg[idx].client_id         = (uint8_t)(SMOKE_CLIENT_ID + idx);
    memset(&s_clientCfg[idx], 0, sizeof(s_clientCfg[idx]));
    s_clientCfg[idx].comm = &s_commCfg[idx];
    return wh_Client_Init(client, &s_clientCfg[idx]);
}

/* --- Strong override of the weak descriptor table. ------------------ */
/* Smoke harness keys: cryptoKeyId 100 = AES-256, 101 = ECC P-256. */

static const Crypto_KeyDescriptorType s_keyDescriptors[] = {
    {100u, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOMODE_NOT_SET, 256u, 0, 0},
    {101u, CRYPTO_ALGOFAM_ECCNIST, CRYPTO_ALGOMODE_ECDSA, 256u, ECC_SECP256R1,
     0},
    {102u, CRYPTO_ALGOFAM_ED25519, CRYPTO_ALGOMODE_NOT_SET, 256u, 0, 0},
    {103u, CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5, 2048u, 0, 0}};

const Crypto_KeyDescriptorType* const Crypto_KeyDescriptorTable =
    s_keyDescriptors;
const uint32 Crypto_KeyDescriptorCount =
    sizeof(s_keyDescriptors) / sizeof(s_keyDescriptors[0]);

/* --- Existing "basic" tests (kept for regression coverage) ---------- */

static int testRngSync(void)
{
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          ji  = {1u, 0u};
    uint8                       out[32];
    uint32                      outLen          = sizeof(out);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 1u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    return (Crypto_ProcessJob(0u, &job) == E_OK && outLen == 32u) ? 0 : 1;
}

static int testRngAsync(void)
{
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 1u, FALSE};
    Crypto_JobInfoType          ji  = {2u, 0u};
    uint8                       out[32];
    uint32                      outLen          = sizeof(out);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 2u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    int prev                         = testCallbackTotal();
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    if (testWaitCallbacks(prev + 1, 3000) != 0)
        return 1;
    return (gTestCb.lastResult == E_OK && outLen == 32u) ? 0 : 1;
}

#ifndef WOLFHSM_CFG_NO_CRYPTO
static int testSha256Sync(void)
{
    const char*                 msg = "hello wolfHSM AUTOSAR";
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_HASH,
                                       {CRYPTO_ALGOFAM_SHA2_256,
                                        CRYPTO_ALGOFAM_NOT_SET, 0u,
                                        CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          ji  = {3u, 0u};
    uint8                       digest[32];
    uint32                      dLen            = sizeof(digest);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 3u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.inputPtr        = (const uint8*)msg;
    job.jobPrimitiveInputOutput.inputLength     = (uint32)strlen(msg);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    return (Crypto_ProcessJob(0u, &job) == E_OK && dLen == 32u) ? 0 : 1;
}

static int testSha256AsyncStream(void)
{
    const char*                 msg = "hello wolfHSM AUTOSAR";
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_HASH,
                                       {CRYPTO_ALGOFAM_SHA2_256,
                                        CRYPTO_ALGOFAM_NOT_SET, 0u,
                                        CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 1u, FALSE};
    Crypto_JobInfoType          ji  = {4u, 0u};
    uint8                       digest[32];
    uint32                      dLen            = sizeof(digest);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 4u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.inputPtr        = (const uint8*)msg;
    job.jobPrimitiveInputOutput.inputLength     = (uint32)strlen(msg);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    int prev                         = testCallbackTotal();
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    if (testWaitCallbacks(prev + 1, 5000) != 0)
        return 1;
    return (gTestCb.lastResult == E_OK && dLen == 32u) ? 0 : 1;
}

static int testSha256AsyncLargeChunked(void)
{
    enum { BIG = 8192 };
    static uint8 input[BIG];
    for (int i = 0; i < BIG; ++i)
        input[i] = (uint8)(i * 7 + 3);

    Crypto_PrimitiveInfoType    pi       = {32u,
                                            CRYPTO_HASH,
                                            {CRYPTO_ALGOFAM_SHA2_256,
                                             CRYPTO_ALGOFAM_NOT_SET, 0u,
                                             CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpiAsync = {0u, &pi, 0u, 0u, 1u, FALSE};
    Crypto_JobInfoType          ji       = {41u, 0u};
    uint8                       dA[32];
    uint32                      lA              = sizeof(dA);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 41u;
    job.jobPrimitiveInfo                        = &jpiAsync;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.inputPtr        = input;
    job.jobPrimitiveInputOutput.inputLength     = BIG;
    job.jobPrimitiveInputOutput.outputPtr       = dA;
    job.jobPrimitiveInputOutput.outputLengthPtr = &lA;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    int prev                         = testCallbackTotal();
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    if (testWaitCallbacks(prev + 1, 10000) != 0 || gTestCb.lastResult != E_OK) {
        return 1;
    }

    Crypto_JobPrimitiveInfoType jpiSync = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          jiS     = {42u, 0u};
    uint8                       dS[32];
    uint32                      lS               = sizeof(dS);
    Crypto_JobType              sync             = {0};
    sync.jobId                                   = 42u;
    sync.jobPrimitiveInfo                        = &jpiSync;
    sync.jobInfo                                 = &jiS;
    sync.jobPrimitiveInputOutput.inputPtr        = input;
    sync.jobPrimitiveInputOutput.inputLength     = BIG;
    sync.jobPrimitiveInputOutput.outputPtr       = dS;
    sync.jobPrimitiveInputOutput.outputLengthPtr = &lS;
    sync.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (Crypto_ProcessJob(0u, &sync) != E_OK)
        return 1;
    return (memcmp(dA, dS, 32) == 0) ? 0 : 1;
}

static int testSha256MultiCall(void)
{
    const char*                 p1  = "hello wolfHSM ";
    const char*                 p2  = "AUTOSAR";
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_HASH,
                                       {CRYPTO_ALGOFAM_SHA2_256,
                                        CRYPTO_ALGOFAM_NOT_SET, 0u,
                                        CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 0u, FALSE};
    Crypto_JobInfoType          ji  = {5u, 0u};
    uint8                       digest[32];
    uint32                      dLen            = sizeof(digest);
    Crypto_JobType              job             = {0};
    job.jobId                                   = 5u;
    job.jobPrimitiveInfo                        = &jpi;
    job.jobInfo                                 = &ji;
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode            = CRYPTO_OPERATIONMODE_START;
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    job.jobPrimitiveInputOutput.mode        = CRYPTO_OPERATIONMODE_UPDATE;
    job.jobPrimitiveInputOutput.inputPtr    = (const uint8*)p1;
    job.jobPrimitiveInputOutput.inputLength = (uint32)strlen(p1);
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    job.jobPrimitiveInputOutput.inputPtr    = (const uint8*)p2;
    job.jobPrimitiveInputOutput.inputLength = (uint32)strlen(p2);
    if (Crypto_ProcessJob(0u, &job) != E_OK)
        return 1;
    job.jobPrimitiveInputOutput.mode        = CRYPTO_OPERATIONMODE_FINISH;
    job.jobPrimitiveInputOutput.inputPtr    = NULL;
    job.jobPrimitiveInputOutput.inputLength = 0u;
    dLen                                    = sizeof(digest);
    return (Crypto_ProcessJob(0u, &job) == E_OK && dLen == 32u) ? 0 : 1;
}

static int testKeystoreRoundtrip(void)
{
    uint8  in[32], out[64];
    uint32 outLen = sizeof(out);
    for (int i = 0; i < 32; ++i)
        in[i] = (uint8)i;
    if (Crypto_KeyElementSet(0xCAu, 1u, in, sizeof(in)) != E_OK)
        return 1;
    if (Crypto_KeyElementGet(0xCAu, 1u, out, &outLen) != E_OK)
        return 1;
    return (outLen == sizeof(in) && memcmp(in, out, sizeof(in)) == 0) ? 0 : 1;
}

static int testKeystoreNoCollision(void)
{
    uint8  a[8] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    uint8  b[8] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};
    uint8  out[8];
    uint32 outLen;
    if (Crypto_KeyElementSet(0x10u, 1u, a, 8) != E_OK ||
        Crypto_KeyElementSet(0x11u, 1u, b, 8) != E_OK)
        return 1;
    outLen = sizeof(out);
    if (Crypto_KeyElementGet(0x10u, 1u, out, &outLen) != E_OK || outLen != 8u ||
        memcmp(out, a, 8) != 0)
        return 1;
    outLen = sizeof(out);
    if (Crypto_KeyElementGet(0x11u, 1u, out, &outLen) != E_OK || outLen != 8u ||
        memcmp(out, b, 8) != 0)
        return 1;
    return 0;
}

static int testAsyncQueuedJobs(void)
{
    enum { N = 3 };
    Crypto_PrimitiveInfoType    pi  = {32u,
                                       CRYPTO_RANDOMGENERATE,
                                       {CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET,
                                        0u, CRYPTO_ALGOMODE_NOT_SET}};
    Crypto_JobPrimitiveInfoType jpi = {0u, &pi, 0u, 0u, 1u, FALSE};
    Crypto_JobInfoType          ji[N];
    uint8                       out[N][32];
    uint32                      outLen[N];
    Crypto_JobType              jobs[N];
    int                         prev = testCallbackTotal();
    for (int k = 0; k < N; ++k) {
        memset(&jobs[k], 0, sizeof(jobs[k]));
        ji[k].jobId                                     = (uint32)(60 + k);
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
    if (testWaitCallbacks(prev + N, 10000) != 0)
        return 1;
    for (int k = 0; k < N; ++k) {
        if (outLen[k] != 32u)
            return 1;
    }
    return 0;
}
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

int main(void)
{
    int                 failures = 0;
    Std_VersionInfoType vi       = {0};

    Crypto_Init();
    Crypto_GetVersionInfo(&vi);
    printf("wolfHSM AUTOSAR Crypto Driver v%u.%u.%u (vendor=%u, module=%u)\n",
           vi.sw_major_version, vi.sw_minor_version, vi.sw_patch_version,
           vi.vendorID, vi.moduleID);

    testStartMainFunctionThread();

    /* --- Existing regression tests --- */
    printf("[basic]\n");
    TEST_RUN(failures, testRngSync);
    TEST_RUN(failures, testRngAsync);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    TEST_RUN(failures, testSha256Sync);
    TEST_RUN(failures, testSha256AsyncStream);
    TEST_RUN(failures, testSha256AsyncLargeChunked);
    TEST_RUN(failures, testSha256MultiCall);
    TEST_RUN(failures, testKeystoreRoundtrip);
    TEST_RUN(failures, testKeystoreNoCollision);
    TEST_RUN(failures, testAsyncQueuedJobs);
#endif

    /* --- Category-1 KAT vectors --- */
    printf("[kat]\n");
    failures += testKatAll();

    /* --- Category-2 DET coverage --- */
    printf("[det]\n");
    failures += testDetAll();

    /* --- Category-3 Resource accounting --- */
    printf("[accounting]\n");
    failures += testAccountingAll();

    /* --- Category-6 Cancel-during-pending --- */
    printf("[cancel]\n");
    failures += testCancelAll();

    /* --- Category-5 Timeout --- */
    printf("[timeout]\n");
    failures += testTimeoutAll();

    /* --- Category-4 Concurrency stress (longest) --- */
    printf("[concurrency]\n");
    failures += testConcurrencyAll();

    testStopMainFunctionThread();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("csm_smoke: all tests passed\n");
    return 0;
}
