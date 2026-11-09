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
 * port/autosar/classic/examples/csm_smoke/test_sig.c
 *
 * Signature jobs checked against software wolfCrypt with the exported
 * public key, plus ML-DSA.
 */

#include "test_helpers.h"

#include "wolfhsm/wh_client.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/sha256.h"
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#endif

static const uint8 kMsg[] = "message signed through the AUTOSAR driver";

static int exportPub(uint32 keyId, uint16 algo, uint8* der, uint16* derLen)
{
    whClientContext* ctx = NULL;
    uint8            label[WH_NVM_LABEL_LEN];
    int              rc = -1;

    if (wh_Autosar_KeystoreBegin(&ctx) == E_OK) {
        rc = wh_Client_KeyExportPublic(ctx, wh_Autosar_ComposeKeyId(keyId, 1u),
                                       algo, label, sizeof(label), der, derLen);
        wh_Autosar_KeystoreEnd(ctx);
    }
    return rc;
}

static Std_ReturnType sigJob(Crypto_ServiceInfoType     svc,
                             Crypto_AlgorithmFamilyType fam,
                             Crypto_AlgorithmModeType mode, uint32 keyId,
                             Crypto_ProcessingType pt, uint8* sig,
                             uint32* sigLen, Crypto_VerifyResultType* ver)
{
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    Std_ReturnType              res = E_NOT_OK;
    Std_ReturnType              ret;

    testBuildJob(&job, &jpi, &pi, svc, fam, mode, keyId, pt, 7600u);
    pi.algorithm.secondaryFamily =
        (fam == CRYPTO_ALGOFAM_RSA || fam == CRYPTO_ALGOFAM_ECCNIST)
            ? CRYPTO_ALGOFAM_SHA2_256
            : CRYPTO_ALGOFAM_NOT_SET;
    job.jobPrimitiveInputOutput.inputPtr    = kMsg;
    job.jobPrimitiveInputOutput.inputLength = sizeof(kMsg);
    if (svc == CRYPTO_SIGNATUREGENERATE) {
        job.jobPrimitiveInputOutput.outputPtr       = sig;
        job.jobPrimitiveInputOutput.outputLengthPtr = sigLen;
    }
    else {
        job.jobPrimitiveInputOutput.secondaryInputPtr    = sig;
        job.jobPrimitiveInputOutput.secondaryInputLength = *sigLen;
        job.jobPrimitiveInputOutput.verifyPtr            = ver;
    }
    if (pt == CRYPTO_PROCESSING_SYNC) {
        return testCryIfProcessJob(0u, &job);
    }
    ret = testRunAsync(&job, &res);
    return (ret == E_OK) ? res : ret;
}

static int verifyBothWays(Crypto_AlgorithmFamilyType fam,
                          Crypto_AlgorithmModeType mode, uint32 keyId,
                          uint8* sig, uint32 sigLen, const char* tag)
{
    Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;

    if (sigJob(CRYPTO_SIGNATUREVERIFY, fam, mode, keyId, CRYPTO_PROCESSING_SYNC,
               sig, &sigLen, &ver) != E_OK ||
        ver != CRYPTO_E_VER_OK) {
        fprintf(stderr, "  %s: sync verify of good signature\n", tag);
        return 1;
    }
    sig[sigLen / 2u] ^= 0x01u;
    ver = CRYPTO_E_VER_OK;
    if (sigJob(CRYPTO_SIGNATUREVERIFY, fam, mode, keyId,
               CRYPTO_PROCESSING_ASYNC, sig, &sigLen, &ver) != E_OK ||
        ver != CRYPTO_E_VER_NOT_OK) {
        fprintf(stderr, "  %s: async verify of tampered signature\n", tag);
        return 1;
    }
    sig[sigLen / 2u] ^= 0x01u;
    return 0;
}

#ifndef NO_RSA
static int testRsaInteropBody(void)
{
    uint8  sig[256];
    uint32 sigLen = sizeof(sig);
    uint8  der[512];
    uint16 derLen = sizeof(der);
    uint8  digest[WC_SHA256_DIGEST_SIZE];
    uint8  enc[MAX_DER_DIGEST_SZ];
    uint8  plain[256];
    word32 encLen;
    word32 idx = 0u;
    RsaKey pub;
    int    rc;

    if (Crypto_KeyGenerate(141u) != E_OK || Crypto_KeySetValid(141u) != E_OK ||
        exportPub(141u, WH_KEY_ALGO_RSA, der, &derLen) != 0) {
        fprintf(stderr, "  rsa: keygen / export\n");
        return 1;
    }
    if (wc_Sha256Hash(kMsg, sizeof(kMsg), digest) != 0 ||
        wc_InitRsaKey_ex(&pub, NULL, INVALID_DEVID) != 0) {
        return 1;
    }
    rc     = wc_RsaPublicKeyDecode(der, &idx, &pub, derLen);
    encLen = wc_EncodeSignature(enc, digest, sizeof(digest), SHA256h);

    if (rc == 0 && sigJob(CRYPTO_SIGNATUREGENERATE, CRYPTO_ALGOFAM_RSA,
                          CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5, 141u,
                          CRYPTO_PROCESSING_SYNC, sig, &sigLen, NULL) != E_OK) {
        rc = -1;
    }
    if (rc == 0) {
        int n = wc_RsaSSL_Verify(sig, sigLen, plain, sizeof(plain), &pub);
        if (n != (int)encLen || memcmp(plain, enc, encLen) != 0) {
            fprintf(stderr, "  rsa: PKCS#1 v1.5 signature not DigestInfo\n");
            rc = -1;
        }
    }
    if (rc == 0 &&
        verifyBothWays(CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5,
                       141u, sig, sigLen, "rsa pkcs1") != 0) {
        rc = -1;
    }
#ifdef WC_RSA_PSS
    sigLen = sizeof(sig);
    if (rc == 0 &&
        sigJob(CRYPTO_SIGNATUREGENERATE, CRYPTO_ALGOFAM_RSA,
               CRYPTO_ALGOMODE_RSASSA_PSS, 141u, CRYPTO_PROCESSING_ASYNC, sig,
               &sigLen, NULL) != E_OK) {
        fprintf(stderr, "  rsa: PSS async sign\n");
        rc = -1;
    }
    if (rc == 0 &&
        wc_RsaPSS_VerifyCheck(sig, sigLen, plain, sizeof(plain), digest,
                              sizeof(digest), WC_HASH_TYPE_SHA256,
                              WC_MGF1SHA256, &pub) < 0) {
        fprintf(stderr, "  rsa: PSS signature rejected by software verify\n");
        rc = -1;
    }
    if (rc == 0 &&
        verifyBothWays(CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOMODE_RSASSA_PSS, 141u,
                       sig, sigLen, "rsa pss") != 0) {
        rc = -1;
    }
#endif
    wc_FreeRsaKey(&pub);
    if (rc != 0) {
        return 1;
    }
    printf("  rsa: PKCS#1 v1.5 + PSS over SHA-256(message) verify in "
           "software\n");
    return 0;
}

static int testRsaInterop(void)
{
    static const uint32 keys[] = {141u};
    return testWithKeys(testRsaInteropBody, keys, 1);
}
#endif

static int testEcdsaInteropBody(void)
{
    uint8   sig[80];
    uint32  sigLen = sizeof(sig);
    uint8   der[160];
    uint16  derLen = sizeof(der);
    uint8   digest[WC_SHA256_DIGEST_SIZE];
    word32  idx = 0u;
    int     res = 0;
    ecc_key pub;
    int     rc;

    if (Crypto_KeyGenerate(142u) != E_OK || Crypto_KeySetValid(142u) != E_OK ||
        exportPub(142u, WH_KEY_ALGO_ECC, der, &derLen) != 0) {
        fprintf(stderr, "  ecdsa: keygen / export\n");
        return 1;
    }
    if (wc_Sha256Hash(kMsg, sizeof(kMsg), digest) != 0 ||
        wc_ecc_init_ex(&pub, NULL, INVALID_DEVID) != 0) {
        return 1;
    }
    rc = wc_EccPublicKeyDecode(der, &idx, &pub, derLen);
    if (rc == 0 &&
        sigJob(CRYPTO_SIGNATUREGENERATE, CRYPTO_ALGOFAM_ECCNIST,
               CRYPTO_ALGOMODE_NOT_SET, 142u, CRYPTO_PROCESSING_ASYNC, sig,
               &sigLen, NULL) != E_OK) {
        fprintf(stderr, "  ecdsa: async sign\n");
        rc = -1;
    }
    if (rc == 0 && (wc_ecc_verify_hash(sig, sigLen, digest, sizeof(digest),
                                       &res, &pub) != 0 ||
                    res != 1)) {
        fprintf(stderr, "  ecdsa: signature rejected by software verify\n");
        rc = -1;
    }
    if (rc == 0 &&
        verifyBothWays(CRYPTO_ALGOFAM_ECCNIST, CRYPTO_ALGOMODE_NOT_SET, 142u,
                       sig, sigLen, "ecdsa") != 0) {
        rc = -1;
    }
    wc_ecc_free(&pub);
    if (rc != 0) {
        return 1;
    }
    printf("  ecdsa: SHA-256(message) signature verifies in software\n");
    return 0;
}

static int testEcdsaInterop(void)
{
    static const uint32 keys[] = {142u};
    return testWithKeys(testEcdsaInteropBody, keys, 1);
}

#ifdef WOLFSSL_HAVE_MLDSA
static int testMlDsaBody(void)
{
    static uint8 sig[DILITHIUM_MAX_SIG_SIZE];
    uint32       sigLen = sizeof(sig);

    if (Crypto_KeyGenerate(140u) != E_OK || Crypto_KeySetValid(140u) != E_OK) {
        fprintf(stderr, "  ml-dsa: keygen\n");
        return 1;
    }
    if (sigJob(CRYPTO_SIGNATUREGENERATE, WH_AUTOSAR_ALGOFAM_MLDSA,
               CRYPTO_ALGOMODE_NOT_SET, 140u, CRYPTO_PROCESSING_SYNC, sig,
               &sigLen, NULL) != E_OK ||
        sigLen != ML_DSA_LEVEL2_SIG_SIZE) {
        fprintf(stderr, "  ml-dsa: sign (sigLen=%u)\n", sigLen);
        return 1;
    }
    if (verifyBothWays(WH_AUTOSAR_ALGOFAM_MLDSA, CRYPTO_ALGOMODE_NOT_SET, 140u,
                       sig, sigLen, "ml-dsa") != 0) {
        return 1;
    }
    printf("  ml-dsa-44: sign + verify + tampered-sig OK\n");
    return 0;
}

static int testMlDsa(void)
{
    static const uint32 keys[] = {140u};
    return testWithKeys(testMlDsaBody, keys, 1);
}
#endif

int testSigAll(void)
{
    int failures = 0;
#ifndef NO_RSA
    TEST_RUN(failures, testRsaInterop);
#endif
    TEST_RUN(failures, testEcdsaInterop);
#ifdef WOLFSSL_HAVE_MLDSA
    TEST_RUN(failures, testMlDsa);
#endif
    return failures;
}
