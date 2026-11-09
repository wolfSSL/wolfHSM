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
 * port/autosar/classic/examples/csm_smoke/test_keymgmt.c
 *
 * Key state, key element APIs and job-based key management.
 */

#include "test_helpers.h"

#include "wolfhsm/wh_client.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#ifdef HAVE_CURVE25519
#include "wolfssl/wolfcrypt/curve25519.h"
#endif

static Std_ReturnType aesCbcEncrypt(uint32 keyId, uint8 out[16])
{
    static const uint8          iv[16] = {0};
    static const uint8          pt[16] = {1, 2, 3, 4};
    uint32                      outLen = 16u;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    if (Crypto_KeyElementSet(keyId, 5u, iv, sizeof(iv)) != E_OK) {
        return E_NOT_OK;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_ENCRYPT, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_CBC, keyId, CRYPTO_PROCESSING_SYNC, 7100u);
    job.jobPrimitiveInputOutput.inputPtr        = pt;
    job.jobPrimitiveInputOutput.inputLength     = 16u;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    return testCryIfProcessJob(0u, &job);
}

static int testKeyStatusBody(void)
{
    static const uint8   k[16] = {0x11, 0x22, 0x33};
    uint8                ct[16];
    Crypto_KeyStatusType st = CRYPTO_KEYSTATUS_VALID;

    if (Crypto_KeyElementSet(130u, 1u, k, sizeof(k)) != E_OK ||
        Crypto_KeyGetStatus(130u, &st) != E_OK ||
        st != CRYPTO_KEYSTATUS_INVALID) {
        fprintf(stderr, "  keystatus: not invalid after KeyElementSet\n");
        return 1;
    }
    if (aesCbcEncrypt(130u, ct) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  keystatus: job on invalid key not rejected\n");
        return 1;
    }
    if (Crypto_KeySetValid(130u) != E_OK ||
        Crypto_KeyGetStatus(130u, &st) != E_OK ||
        st != CRYPTO_KEYSTATUS_VALID || aesCbcEncrypt(130u, ct) != E_OK) {
        fprintf(stderr, "  keystatus: KeySetValid did not enable the key\n");
        return 1;
    }
    if (Crypto_KeySetInvalid(130u) != E_OK ||
        aesCbcEncrypt(130u, ct) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  keystatus: KeySetInvalid did not disable the key\n");
        return 1;
    }
    printf("  keystatus: Set -> invalid, SetValid -> valid, SetInvalid OK\n");
    return 0;
}

static int testKeyStatus(void)
{
    static const uint32 keys[] = {130u};
    return testWithKeys(testKeyStatusBody, keys, 1);
}

static int testKeyElementIdsAndCopyPartialBody(void)
{
    uint8  src[32];
    uint8  got[64];
    uint32 gotLen = sizeof(got);
    uint32 ids[4];
    uint32 idsLen = 4u;
    int    i;

    for (i = 0; i < 32; ++i)
        src[i] = (uint8)(0xA0 + i);
    if (Crypto_KeyElementIdsGet(131u, ids, &idsLen) != E_OK || idsLen != 1u ||
        ids[0] != 1u) {
        fprintf(stderr, "  keyelem: KeyElementIdsGet\n");
        return 1;
    }
    if (Crypto_KeyElementSet(131u, 1u, src, sizeof(src)) != E_OK ||
        Crypto_KeyElementCopyPartial(131u, 1u, 8u, 4u, 16u, 132u, 1u) != E_OK ||
        Crypto_KeyElementGet(132u, 1u, got, &gotLen) != E_OK) {
        fprintf(stderr, "  keyelem: KeyElementCopyPartial\n");
        return 1;
    }
    if (gotLen != 20u || got[0] != 0u || got[3] != 0u ||
        memcmp(got + 4, src + 8, 16) != 0) {
        fprintf(stderr, "  keyelem: partial copy content (len=%u)\n", gotLen);
        return 1;
    }
    printf("  keyelem: KeyElementIdsGet + KeyElementCopyPartial OK\n");
    return 0;
}

static int testKeyElementIdsAndCopyPartial(void)
{
    static const uint32 keys[] = {131u, 132u};
    return testWithKeys(testKeyElementIdsAndCopyPartialBody, keys, 2);
}

static int testBusyWhileInFlightBody(void)
{
    static const uint8          k[16] = {0};
    uint8                       outA[16];
    uint8                       outS[16];
    uint32                      lenA = sizeof(outA);
    uint32                      lenS = sizeof(outS);
    Crypto_PrimitiveInfoType    piA, piS;
    Crypto_JobPrimitiveInfoType jpiA, jpiS;
    Crypto_JobType              jobA, jobS;
    Std_ReturnType              busyJob, busyKey;
    int                         prev;

    testBuildJob(&jobA, &jpiA, &piA, CRYPTO_RANDOMGENERATE, CRYPTO_ALGOFAM_RNG,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_ASYNC, 7200u);
    jobA.jobPrimitiveInputOutput.outputPtr       = outA;
    jobA.jobPrimitiveInputOutput.outputLengthPtr = &lenA;
    testBuildJob(&jobS, &jpiS, &piS, CRYPTO_RANDOMGENERATE, CRYPTO_ALGOFAM_RNG,
                 CRYPTO_ALGOMODE_NOT_SET, 0u, CRYPTO_PROCESSING_SYNC, 7201u);
    jobS.jobPrimitiveInputOutput.outputPtr       = outS;
    jobS.jobPrimitiveInputOutput.outputLengthPtr = &lenS;

    testPauseMainFunctionThread();
    prev = testCallbackTotal();
    if (testCryIfProcessJob(0u, &jobA) != E_OK) {
        testResumeMainFunctionThread();
        return 1;
    }
    Crypto_MainFunction();
    busyJob = testCryIfProcessJob(0u, &jobS);
    busyKey = Crypto_KeyElementSet(133u, 1u, k, sizeof(k));
    testResumeMainFunctionThread();
    if (testWaitCallbacks(prev + 1, 5000) != 0) {
        fprintf(stderr, "  busy: async job never completed\n");
        return 1;
    }
    if (busyJob != CRYPTO_E_BUSY || busyKey != CRYPTO_E_BUSY) {
        fprintf(stderr, "  busy: job=%u key=%u (expected CRYPTO_E_BUSY)\n",
                busyJob, busyKey);
        return 1;
    }
    if (testCryIfProcessJob(0u, &jobS) != E_OK) {
        fprintf(stderr, "  busy: sync job failed after drain\n");
        return 1;
    }
    printf("  busy: sync job + key API return CRYPTO_E_BUSY while in flight\n");
    return 0;
}

static int testBusyWhileInFlight(void)
{
    static const uint32 keys[] = {133u};
    return testWithKeys(testBusyWhileInFlightBody, keys, 1);
}

static Std_ReturnType pubValJob(uint32 keyId, uint8* pub, uint32* pubLen,
                                Crypto_AlgorithmFamilyType fam)
{
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, CRYPTO_KEYEXCHANGECALCPUBVAL, fam,
                 CRYPTO_ALGOMODE_NOT_SET, keyId, CRYPTO_PROCESSING_SYNC, 7300u);
    job.jobPrimitiveInputOutput.outputPtr       = pub;
    job.jobPrimitiveInputOutput.outputLengthPtr = pubLen;
    return testCryIfProcessJob(0u, &job);
}

static int testKeyExchangeJobsEcdhBody(void)
{
    uint8                       pubA[64], pubB[64];
    uint32                      lenA = sizeof(pubA), lenB = sizeof(pubB);
    uint8                       secA[66], secB[66];
    uint32                      sLenA = sizeof(secA), sLenB = sizeof(secB);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;

    if (pubValJob(120u, pubA, &lenA, CRYPTO_ALGOFAM_ECDH) != E_OK ||
        pubValJob(121u, pubB, &lenB, CRYPTO_ALGOFAM_ECDH) != E_OK ||
        lenA != 64u || lenB != 64u) {
        fprintf(stderr, "  ecdh: CalcPubVal job (lenA=%u lenB=%u)\n", lenA,
                lenB);
        return 1;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_KEYEXCHANGECALCSECRET,
                 CRYPTO_ALGOFAM_ECDH, CRYPTO_ALGOMODE_NOT_SET, 120u,
                 CRYPTO_PROCESSING_SYNC, 7301u);
    job.jobPrimitiveInputOutput.inputPtr    = pubB;
    job.jobPrimitiveInputOutput.inputLength = lenB;
    if (testCryIfProcessJob(0u, &job) != E_OK) {
        fprintf(stderr, "  ecdh: CalcSecret sync job\n");
        return 1;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_KEYEXCHANGECALCSECRET,
                 CRYPTO_ALGOFAM_ECDH, CRYPTO_ALGOMODE_NOT_SET, 121u,
                 CRYPTO_PROCESSING_ASYNC, 7302u);
    job.jobPrimitiveInputOutput.inputPtr    = pubA;
    job.jobPrimitiveInputOutput.inputLength = lenA;
    if (testRunAsync(&job, &res) != E_OK || res != E_OK) {
        fprintf(stderr, "  ecdh: CalcSecret async job\n");
        return 1;
    }
    if (Crypto_KeyElementGet(120u, 1u, secA, &sLenA) != E_OK ||
        Crypto_KeyElementGet(121u, 1u, secB, &sLenB) != E_OK || sLenA != 32u ||
        sLenA != sLenB || memcmp(secA, secB, sLenA) != 0) {
        fprintf(stderr, "  ecdh: shared values differ\n");
        return 1;
    }
    printf("  ecdh: CalcPubVal/CalcSecret jobs (sync + async) agree\n");
    return 0;
}

static int testKeyExchangeJobsEcdh(void)
{
    static const uint32 keys[] = {120u, 121u};
    return testWithKeys(testKeyExchangeJobsEcdhBody, keys, 2);
}

#ifdef HAVE_CURVE25519
static int testX25519DirectBody(void)
{
    uint8  pubA[32], pubB[32], secA[32], secB[32];
    uint32 lenA = sizeof(pubA), lenB = sizeof(pubB);
    uint32 sLenA = sizeof(secA), sLenB = sizeof(secB);

    if (Crypto_KeyExchangeCalcPubVal(122u, pubA, &lenA) != E_OK ||
        Crypto_KeyExchangeCalcPubVal(123u, pubB, &lenB) != E_OK ||
        lenA != 32u || lenB != 32u) {
        fprintf(stderr, "  x25519: CalcPubVal\n");
        return 1;
    }
    if (Crypto_KeyExchangeCalcSecret(122u, pubB, lenB) != E_OK ||
        Crypto_KeyExchangeCalcSecret(123u, pubA, lenA) != E_OK) {
        fprintf(stderr, "  x25519: CalcSecret\n");
        return 1;
    }
    if (Crypto_KeyElementGet(122u, 1u, secA, &sLenA) != E_OK ||
        Crypto_KeyElementGet(123u, 1u, secB, &sLenB) != E_OK || sLenA != 32u ||
        sLenB != 32u || memcmp(secA, secB, 32) != 0) {
        fprintf(stderr, "  x25519: shared values differ\n");
        return 1;
    }
    printf("  x25519: CalcPubVal/CalcSecret agree\n");
    return 0;
}

static int testX25519Direct(void)
{
    static const uint32 keys[] = {122u, 123u};
    return testWithKeys(testX25519DirectBody, keys, 2);
}
#endif

static int testKeyDeriveBody(void)
{
    static const uint8   ikm[32] = {0x0b, 0x0b, 0x0b};
    uint8                out[64];
    uint32               outLen = sizeof(out);
    Crypto_KeyStatusType st;

    if (Crypto_KeyElementSet(134u, 1u, ikm, sizeof(ikm)) != E_OK ||
        Crypto_KeyDerive(134u, 124u) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  derive: invalid source key not rejected\n");
        return 1;
    }
    if (Crypto_KeySetValid(134u) != E_OK ||
        Crypto_KeyDerive(134u, 124u) != E_OK ||
        Crypto_KeyElementGet(124u, 1u, out, &outLen) != E_OK || outLen != 32u ||
        Crypto_KeyGetStatus(124u, &st) != E_OK ||
        st != CRYPTO_KEYSTATUS_INVALID) {
        fprintf(stderr, "  derive: HKDF (len=%u)\n", outLen);
        return 1;
    }
#ifdef HAVE_CMAC_KDF
    outLen = sizeof(out);
    if (Crypto_KeyDerive(134u, 125u) != E_OK ||
        Crypto_KeyElementGet(125u, 1u, out, &outLen) != E_OK || outLen != 16u) {
        fprintf(stderr, "  derive: CMAC-KDF (len=%u)\n", outLen);
        return 1;
    }
#endif
    printf("  derive: HKDF%s from a valid source OK\n",
#ifdef HAVE_CMAC_KDF
           " + CMAC-KDF"
#else
           ""
#endif
    );
    return 0;
}

static int testKeyDerive(void)
{
    static const uint32 keys[] = {134u, 124u, 125u};
    return testWithKeys(testKeyDeriveBody, keys, 3);
}

static int testKeyGenerateAndSetValidJobsBody(void)
{
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;
    Crypto_KeyStatusType        st  = CRYPTO_KEYSTATUS_VALID;
    uint8                       ct[16];

    testBuildJob(&job, &jpi, &pi, CRYPTO_KEYGENERATE, CRYPTO_ALGOFAM_AES,
                 CRYPTO_ALGOMODE_NOT_SET, 126u, CRYPTO_PROCESSING_ASYNC, 7400u);
    if (testRunAsync(&job, &res) != E_OK || res != E_OK ||
        Crypto_KeyGetStatus(126u, &st) != E_OK ||
        st != CRYPTO_KEYSTATUS_INVALID) {
        fprintf(stderr, "  keygen: async KEYGENERATE job\n");
        return 1;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_KEYSETVALID, CRYPTO_ALGOFAM_NOT_SET,
                 CRYPTO_ALGOMODE_NOT_SET, 126u, CRYPTO_PROCESSING_SYNC, 7401u);
    if (testCryIfProcessJob(0u, &job) != E_OK ||
        aesCbcEncrypt(126u, ct) != E_OK) {
        fprintf(stderr, "  keygen: KEYSETVALID job / use of generated key\n");
        return 1;
    }
    printf("  keygen: async KEYGENERATE + KEYSETVALID jobs OK\n");
    return 0;
}

static int testKeyGenerateAndSetValidJobs(void)
{
    static const uint32 keys[] = {126u};
    return testWithKeys(testKeyGenerateAndSetValidJobsBody, keys, 1);
}

#ifdef HAVE_ED25519
static int testEd25519AsyncBody(void)
{
    static const uint8          msg[16] = {1, 2, 3};
    uint8                       sig[64];
    uint32                      sigLen = sizeof(sig);
    Crypto_VerifyResultType     ver    = CRYPTO_E_VER_NOT_OK;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;

    if (Crypto_KeyGenerate(127u) != E_OK || Crypto_KeySetValid(127u) != E_OK) {
        fprintf(stderr, "  ed25519 async: keygen\n");
        return 1;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_SIGNATUREGENERATE,
                 CRYPTO_ALGOFAM_ED25519, CRYPTO_ALGOMODE_NOT_SET, 127u,
                 CRYPTO_PROCESSING_ASYNC, 7500u);
    job.jobPrimitiveInputOutput.inputPtr        = msg;
    job.jobPrimitiveInputOutput.inputLength     = sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr       = sig;
    job.jobPrimitiveInputOutput.outputLengthPtr = &sigLen;
    if (testRunAsync(&job, &res) != E_OK || res != E_OK || sigLen != 64u) {
        fprintf(stderr, "  ed25519 async: sign\n");
        return 1;
    }
    testBuildJob(&job, &jpi, &pi, CRYPTO_SIGNATUREVERIFY,
                 CRYPTO_ALGOFAM_ED25519, CRYPTO_ALGOMODE_NOT_SET, 127u,
                 CRYPTO_PROCESSING_ASYNC, 7501u);
    job.jobPrimitiveInputOutput.inputPtr             = msg;
    job.jobPrimitiveInputOutput.inputLength          = sizeof(msg);
    job.jobPrimitiveInputOutput.secondaryInputPtr    = sig;
    job.jobPrimitiveInputOutput.secondaryInputLength = sigLen;
    job.jobPrimitiveInputOutput.verifyPtr            = &ver;
    if (testRunAsync(&job, &res) != E_OK || res != E_OK ||
        ver != CRYPTO_E_VER_OK) {
        fprintf(stderr, "  ed25519 async: verify\n");
        return 1;
    }
    printf("  ed25519: async sign + verify through MainFunction OK\n");
    return 0;
}

static int testEd25519Async(void)
{
    static const uint32 keys[] = {127u};
    return testWithKeys(testEd25519AsyncBody, keys, 1);
}
#endif

static Std_ReturnType keyJob(Crypto_ServiceInfoType svc, uint32 keyId,
                             uint32 targetKeyId, Crypto_ProcessingType pt)
{
    static const uint8          seed[16] = {0x5e, 0xed};
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;

    testBuildJob(&job, &jpi, &pi, svc, CRYPTO_ALGOFAM_NOT_SET,
                 CRYPTO_ALGOMODE_NOT_SET, keyId, pt, 7700u);
    job.jobPrimitiveInputOutput.targetCryIfKeyId = targetKeyId;
    if (svc == CRYPTO_RANDOMSEED) {
        job.jobPrimitiveInputOutput.inputPtr    = seed;
        job.jobPrimitiveInputOutput.inputLength = sizeof(seed);
    }
    if (pt == CRYPTO_PROCESSING_SYNC) {
        return testCryIfProcessJob(0u, &job);
    }
    return (testRunAsync(&job, &res) == E_OK) ? res : E_NOT_OK;
}

static int testKeyDeriveJobsBody(void)
{
    static const uint8 ikm[32] = {0x1c, 0x2d, 0x3e};
    uint8              want[32];
    uint8              got[32];
    uint32             len = sizeof(want);
    int                pt;

    if (Crypto_KeyElementSet(136u, 1u, ikm, sizeof(ikm)) != E_OK ||
        Crypto_KeySetValid(136u) != E_OK ||
        Crypto_KeyDerive(136u, 124u) != E_OK ||
        Crypto_KeyElementGet(124u, 1u, want, &len) != E_OK || len != 32u) {
        fprintf(stderr, "  derive job: direct KeyDerive\n");
        return 1;
    }
    for (pt = 0; pt < 2; ++pt) {
        testEraseKey(124u);
        len = sizeof(got);
        if (keyJob(CRYPTO_KEYDERIVE, 136u, 124u,
                   pt ? CRYPTO_PROCESSING_ASYNC : CRYPTO_PROCESSING_SYNC) !=
                E_OK ||
            Crypto_KeyElementGet(124u, 1u, got, &len) != E_OK || len != 32u ||
            memcmp(got, want, sizeof(want)) != 0) {
            fprintf(stderr, "  derive job: %s KEYDERIVE differs\n",
                    pt ? "async" : "sync");
            return 1;
        }
    }
    printf("  derive job: sync + async KEYDERIVE match Crypto_KeyDerive\n");
    return 0;
}

static int testKeyDeriveJobs(void)
{
    static const uint32 keys[] = {136u, 124u};
    return testWithKeys(testKeyDeriveJobsBody, keys, 2);
}

static int testKeyStateJobsBody(void)
{
    static const uint8   k[16] = {0x37};
    uint8                ct[16];
    Crypto_KeyStatusType st = CRYPTO_KEYSTATUS_VALID;

    if (Crypto_KeyElementSet(137u, 1u, k, sizeof(k)) != E_OK ||
        Crypto_KeySetValid(137u) != E_OK || aesCbcEncrypt(137u, ct) != E_OK) {
        fprintf(stderr, "  key jobs: setup\n");
        return 1;
    }
    if (keyJob(CRYPTO_KEYSETINVALID, 137u, 0u, CRYPTO_PROCESSING_SYNC) !=
            E_OK ||
        Crypto_KeyGetStatus(137u, &st) != E_OK ||
        st != CRYPTO_KEYSTATUS_INVALID ||
        aesCbcEncrypt(137u, ct) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  key jobs: sync KEYSETINVALID\n");
        return 1;
    }
    if (keyJob(CRYPTO_KEYSETVALID, 137u, 0u, CRYPTO_PROCESSING_ASYNC) != E_OK ||
        aesCbcEncrypt(137u, ct) != E_OK) {
        fprintf(stderr, "  key jobs: async KEYSETVALID\n");
        return 1;
    }
    if (keyJob(CRYPTO_KEYSETINVALID, 137u, 0u, CRYPTO_PROCESSING_ASYNC) !=
            E_OK ||
        aesCbcEncrypt(137u, ct) != CRYPTO_E_KEY_NOT_VALID) {
        fprintf(stderr, "  key jobs: async KEYSETINVALID\n");
        return 1;
    }
    if (keyJob(CRYPTO_RANDOMSEED, 0u, 0u, CRYPTO_PROCESSING_SYNC) != E_NOT_OK ||
        keyJob(CRYPTO_RANDOMSEED, 0u, 0u, CRYPTO_PROCESSING_ASYNC) !=
            E_NOT_OK) {
        fprintf(stderr, "  key jobs: RANDOMSEED accepted\n");
        return 1;
    }
    printf("  key jobs: KEYSETINVALID, async KEYSETVALID, RANDOMSEED "
           "rejected\n");
    return 0;
}

static int testKeyStateJobs(void)
{
    static const uint32 keys[] = {137u};
    return testWithKeys(testKeyStateJobsBody, keys, 1);
}

#ifdef HAVE_CURVE25519
/* Reads the RFC 7748 public value of a generated X25519 key. */
static int x25519Public(uint32 keyId, uint8* pub, uint32* pubLen)
{
    whClientContext* ctx = NULL;
    uint8            der[96];
    uint16           derLen = sizeof(der);
    uint8            label[WH_NVM_LABEL_LEN];
    word32           idx = 0u;
    word32           len = *pubLen;
    curve25519_key   key;
    int              rc = -1;

    if (wh_Autosar_KeystoreBegin(&ctx) == E_OK) {
        rc = wh_Client_KeyExportPublic(ctx, wh_Autosar_ComposeKeyId(keyId, 1u),
                                       WH_KEY_ALGO_CURVE25519, label,
                                       sizeof(label), der, &derLen);
        wh_Autosar_KeystoreEnd(ctx);
    }
    if (rc != 0 || wc_curve25519_init(&key) != 0) {
        return -1;
    }
    rc = wc_Curve25519PublicKeyDecode(der, &idx, &key, derLen);
    if (rc == 0) {
        rc = wc_curve25519_export_public_ex(&key, pub, &len,
                                            EC25519_LITTLE_ENDIAN);
    }
    wc_curve25519_free(&key);
    *pubLen = len;
    return rc;
}

static int testX25519KeyGenerateBody(void)
{
    uint8  pubA[32], pubB[32], secA[32], secB[32];
    uint32 lenA = sizeof(pubA), lenB = sizeof(pubB);
    uint32 sLenA = sizeof(secA), sLenB = sizeof(secB);

    if (Crypto_KeyGenerate(122u) != E_OK ||
        x25519Public(122u, pubA, &lenA) != 0 || lenA != 32u) {
        fprintf(stderr, "  x25519 keygen: KeyGenerate / public value\n");
        return 1;
    }
    if (Crypto_KeyExchangeCalcPubVal(123u, pubB, &lenB) != E_OK ||
        Crypto_KeyExchangeCalcSecret(122u, pubB, lenB) != E_OK ||
        Crypto_KeyExchangeCalcSecret(123u, pubA, lenA) != E_OK) {
        fprintf(stderr, "  x25519 keygen: exchange with a peer\n");
        return 1;
    }
    if (Crypto_KeyElementGet(122u, 1u, secA, &sLenA) != E_OK ||
        Crypto_KeyElementGet(123u, 1u, secB, &sLenB) != E_OK || sLenA != 32u ||
        sLenB != 32u || memcmp(secA, secB, 32) != 0) {
        fprintf(stderr, "  x25519 keygen: shared values differ\n");
        return 1;
    }
    printf("  x25519: KeyGenerate key agrees with a CalcPubVal peer\n");
    return 0;
}

static int testX25519KeyGenerate(void)
{
    static const uint32 keys[] = {122u, 123u};
    return testWithKeys(testX25519KeyGenerateBody, keys, 2);
}
#endif

static int testKeyElementBranchesBody(void)
{
    static const uint8 iv[16] = {0x1f, 0x2e, 0x3d, 0x4c};
    static const uint8 k[16]  = {0x45};
    uint8              src[32];
    uint8              fill[32];
    uint8              got[32];
    uint32             len;
    uint32             ids[4];
    uint32             nIds = 4u;
    int                i;

    for (i = 0; i < 32; ++i) {
        src[i]  = (uint8)(0xA0 + i);
        fill[i] = 0x55u;
    }
    len = sizeof(got);
    if (Crypto_KeyElementSet(131u, 5u, iv, sizeof(iv)) != E_OK ||
        Crypto_KeyElementIdsGet(131u, ids, &nIds) != E_OK || nIds != 2u ||
        ids[0] != 1u || ids[1] != 5u ||
        Crypto_KeyElementGet(131u, 5u, got, &len) != E_OK || len != 16u ||
        memcmp(got, iv, sizeof(iv)) != 0) {
        fprintf(stderr, "  keyelem: IV read-back\n");
        return 1;
    }
    len = 8u;
    if (Crypto_KeyElementGet(131u, 5u, got, &len) != E_NOT_OK) {
        fprintf(stderr, "  keyelem: IV into an 8-byte buffer\n");
        return 1;
    }
    len = sizeof(got);
    if (Crypto_KeyElementGet(132u, 5u, got, &len) !=
        CRYPTO_E_KEY_NOT_AVAILABLE) {
        fprintf(stderr, "  keyelem: absent IV\n");
        return 1;
    }
    /* Writing the material drops the IV. */
    nIds = 4u;
    if (Crypto_KeyElementSet(131u, 1u, src, sizeof(src)) != E_OK ||
        Crypto_KeyElementIdsGet(131u, ids, &nIds) != E_OK || nIds != 1u) {
        fprintf(stderr, "  keyelem: IV kept after material write\n");
        return 1;
    }
    len = sizeof(got);
    if (Crypto_KeyElementSet(132u, 1u, fill, sizeof(fill)) != E_OK ||
        Crypto_KeyElementCopyPartial(131u, 1u, 8u, 4u, 16u, 132u, 1u) != E_OK ||
        Crypto_KeyElementGet(132u, 1u, got, &len) != E_OK || len != 32u ||
        memcmp(got, fill, 4) != 0 || memcmp(got + 4, src + 8, 16) != 0 ||
        memcmp(got + 20, fill, 12) != 0) {
        fprintf(stderr, "  keyelem: partial copy into existing material\n");
        return 1;
    }
    memcpy(fill, got, sizeof(fill));
    if (Crypto_KeyElementCopyPartial(131u, 1u, 40u, 0u, 8u, 132u, 1u) !=
        E_NOT_OK) {
        fprintf(stderr, "  keyelem: source offset past the source\n");
        return 1;
    }
    if (Crypto_KeyElementSet(145u, 1u, k, sizeof(k)) != E_OK ||
        Crypto_KeySetValid(145u) != E_OK ||
        Crypto_KeyElementCopy(145u, 1u, 132u, 1u) != CRYPTO_E_KEY_READ_FAIL ||
        Crypto_KeyCopy(145u, 132u) != CRYPTO_E_KEY_READ_FAIL) {
        fprintf(stderr, "  keyelem: copy from a non-exportable key\n");
        return 1;
    }
    len = sizeof(got);
    if (Crypto_KeyElementGet(132u, 1u, got, &len) != E_OK || len != 32u ||
        memcmp(got, fill, sizeof(fill)) != 0) {
        fprintf(stderr, "  keyelem: failed copy changed the target\n");
        return 1;
    }
    printf("  keyelem: IV read-back, partial copy merge, copy read checks\n");
    return 0;
}

static int testKeyElementBranches(void)
{
    static const uint32 keys[] = {131u, 132u, 145u};
    return testWithKeys(testKeyElementBranchesBody, keys, 3);
}

int testKeyMgmtAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testKeyStatus);
    TEST_RUN(failures, testKeyElementIdsAndCopyPartial);
    TEST_RUN(failures, testBusyWhileInFlight);
    TEST_RUN(failures, testKeyExchangeJobsEcdh);
#ifdef HAVE_CURVE25519
    TEST_RUN(failures, testX25519Direct);
#endif
    TEST_RUN(failures, testKeyDerive);
    TEST_RUN(failures, testKeyGenerateAndSetValidJobs);
#ifdef HAVE_ED25519
    TEST_RUN(failures, testEd25519Async);
#endif
    TEST_RUN(failures, testKeyDeriveJobs);
    TEST_RUN(failures, testKeyStateJobs);
#ifdef HAVE_CURVE25519
    TEST_RUN(failures, testX25519KeyGenerate);
#endif
    TEST_RUN(failures, testKeyElementBranches);
    return failures;
}
