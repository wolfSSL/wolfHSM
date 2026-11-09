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
 * port/autosar/classic/examples/csm_smoke/test_cipher.c
 *
 * AES modes against NIST SP 800-38A / software wolfCrypt, key copy, and
 * multi-call SHA-384/512.
 */

#include "test_helpers.h"

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha512.h"

/* SP 800-38A F.1.1 / F.2.1 / F.5.1, first block, AES-128. */
static const uint8 kKey[16]   = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8 kPt[16]    = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
static const uint8 kCbcIv[16] = {0, 1, 2,  3,  4,  5,  6,  7,
                                 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8 kCtrIv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                                 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
                                 0xfc, 0xfd, 0xfe, 0xff};
static const uint8 kEcbCt[16] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a,
                                 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3,
                                 0x24, 0x66, 0xef, 0x97};
static const uint8 kCbcCt[16] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19,
                                 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
                                 0x12, 0xe9, 0x19, 0x7d};
static const uint8 kCtrCt[16] = {0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20,
                                 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64,
                                 0x99, 0x0d, 0xb6, 0xce};

#define CIPHER_KEY 150u

static int installKey(const uint8* iv, uint32 ivLen)
{
    if (Crypto_KeyElementSet(CIPHER_KEY, 1u, kKey, sizeof(kKey)) != E_OK ||
        Crypto_KeySetValid(CIPHER_KEY) != E_OK) {
        return 1;
    }
    return (iv == NULL ||
            Crypto_KeyElementSet(CIPHER_KEY, 5u, iv, ivLen) == E_OK)
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

static int aesBlock(Crypto_ServiceInfoType svc, Crypto_AlgorithmModeType mode,
                    Crypto_ProcessingType pt, const uint8* in, uint8* out)
{
    uint32                      outLen = 16u;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, svc, CRYPTO_ALGOFAM_AES, mode, CIPHER_KEY, pt,
                 7700u);
    job.jobPrimitiveInputOutput.inputPtr        = in;
    job.jobPrimitiveInputOutput.inputLength     = 16u;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    return (runJob(&job) == E_OK && outLen == 16u) ? 0 : 1;
}

static int modeKat(Crypto_AlgorithmModeType mode, const uint8* iv,
                   const uint8* ct, const char* name)
{
    static const Crypto_ProcessingType pts[2] = {CRYPTO_PROCESSING_SYNC,
                                                 CRYPTO_PROCESSING_ASYNC};
    uint8                              out[16];
    uint8                              back[16];
    int                                i;

    if (installKey(iv, 16u) != 0) {
        fprintf(stderr, "  aes-%s: key install\n", name);
        return 1;
    }
    for (i = 0; i < 2; ++i) {
        if (aesBlock(CRYPTO_ENCRYPT, mode, pts[i], kPt, out) != 0 ||
            memcmp(out, ct, 16) != 0) {
            fprintf(stderr, "  aes-%s: %s encrypt\n", name,
                    i ? "async" : "sync");
            return 1;
        }
        if (aesBlock(CRYPTO_DECRYPT, mode, pts[i], ct, back) != 0 ||
            memcmp(back, kPt, 16) != 0) {
            fprintf(stderr, "  aes-%s: %s decrypt\n", name,
                    i ? "async" : "sync");
            return 1;
        }
    }
    return 0;
}

static int testAesModesBody(void)
{
    int failed = 0;
#ifdef HAVE_AES_ECB
    failed += modeKat(CRYPTO_ALGOMODE_ECB, NULL, kEcbCt, "ecb");
#endif
    failed += modeKat(CRYPTO_ALGOMODE_CBC, kCbcIv, kCbcCt, "cbc");
#ifdef WOLFSSL_AES_COUNTER
    failed += modeKat(CRYPTO_ALGOMODE_CTR, kCtrIv, kCtrCt, "ctr");
#endif
    if (failed == 0) {
        printf("  aes: ECB/CBC/CTR SP 800-38A, sync + async, IV from key "
               "element 5\n");
    }
    return failed;
}

static int testAesModes(void)
{
    static const uint32 keys[] = {CIPHER_KEY};
    return testWithKeys(testAesModesBody, keys, 1);
}

#ifdef HAVE_AESGCM
static int gcmJob(Crypto_ServiceInfoType svc, Crypto_ProcessingType pt,
                  const uint8* in, const uint8* aad, uint32 aadLen, uint8* tag,
                  uint32* tagLen, uint8* out, Crypto_VerifyResultType* ver,
                  Std_ReturnType* ret)
{
    uint32                      outLen = 32u;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    testBuildJob(&job, &jpi, &pi, svc, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOMODE_GCM,
                 CIPHER_KEY, pt, 7710u);
    job.jobPrimitiveInputOutput.inputPtr             = in;
    job.jobPrimitiveInputOutput.inputLength          = 32u;
    job.jobPrimitiveInputOutput.secondaryInputPtr    = aad;
    job.jobPrimitiveInputOutput.secondaryInputLength = aadLen;
    job.jobPrimitiveInputOutput.outputPtr            = out;
    job.jobPrimitiveInputOutput.outputLengthPtr      = &outLen;
    if (svc == CRYPTO_AEADENCRYPT) {
        job.jobPrimitiveInputOutput.secondaryOutputPtr       = tag;
        job.jobPrimitiveInputOutput.secondaryOutputLengthPtr = tagLen;
    }
    else {
        job.jobPrimitiveInputOutput.tertiaryInputPtr    = tag;
        job.jobPrimitiveInputOutput.tertiaryInputLength = *tagLen;
        job.jobPrimitiveInputOutput.verifyPtr           = ver;
    }
    *ret = runJob(&job);
    return (*ret == E_OK && outLen == 32u) ? 0 : 1;
}

static int testAesGcmBody(void)
{
    static const uint8 nonce[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                    0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
    static const uint8 aad[20]   = {0xfe, 0xed, 0xfa, 0xce, 0xde};
    uint8              pt[32];
    uint8              ct[32], swCt[32], back[32];
    uint8              tag[16], swTag[16];
    uint32             tagLen = sizeof(tag);
    Aes                sw;
    Std_ReturnType     ret;
    int                i;

    for (i = 0; i < 32; ++i)
        pt[i] = (uint8)(i * 3 + 1);
    if (installKey(nonce, sizeof(nonce)) != 0 ||
        wc_AesInit(&sw, NULL, INVALID_DEVID) != 0) {
        return 1;
    }
    if (wc_AesGcmSetKey(&sw, kKey, sizeof(kKey)) != 0 ||
        wc_AesGcmEncrypt(&sw, swCt, pt, sizeof(pt), nonce, sizeof(nonce), swTag,
                         sizeof(swTag), aad, sizeof(aad)) != 0) {
        wc_AesFree(&sw);
        return 1;
    }
    wc_AesFree(&sw);

    for (i = 0; i < 2; ++i) {
        Crypto_ProcessingType pt0 =
            i ? CRYPTO_PROCESSING_ASYNC : CRYPTO_PROCESSING_SYNC;
        Crypto_VerifyResultType ver = CRYPTO_E_VER_NOT_OK;

        tagLen = sizeof(tag);
        if (gcmJob(CRYPTO_AEADENCRYPT, pt0, pt, aad, sizeof(aad), tag, &tagLen,
                   ct, NULL, &ret) != 0 ||
            tagLen != 16u || memcmp(ct, swCt, 32) != 0 ||
            memcmp(tag, swTag, 16) != 0) {
            fprintf(stderr, "  gcm: %s encrypt differs from software\n",
                    i ? "async" : "sync");
            return 1;
        }
        if (gcmJob(CRYPTO_AEADDECRYPT, pt0, ct, aad, sizeof(aad), tag, &tagLen,
                   back, &ver, &ret) != 0 ||
            ver != CRYPTO_E_VER_OK || memcmp(back, pt, 32) != 0) {
            fprintf(stderr, "  gcm: %s decrypt\n", i ? "async" : "sync");
            return 1;
        }
        tag[0] ^= 0x01u;
        ver = CRYPTO_E_VER_OK;
        (void)gcmJob(CRYPTO_AEADDECRYPT, pt0, ct, aad, sizeof(aad), tag,
                     &tagLen, back, &ver, &ret);
        if (ret != E_OK || ver != CRYPTO_E_VER_NOT_OK) {
            fprintf(stderr, "  gcm: %s tampered tag not rejected\n",
                    i ? "async" : "sync");
            return 1;
        }
    }
    printf("  aes-gcm: matches software, tag check sync + async\n");
    return 0;
}

static int testAesGcm(void)
{
    static const uint32 keys[] = {CIPHER_KEY};
    return testWithKeys(testAesGcmBody, keys, 1);
}
#endif

static int testKeyCopyBody(void)
{
    uint8 out[16];

    if (installKey(kCbcIv, 16u) != 0 ||
        Crypto_KeyCopy(CIPHER_KEY, CIPHER_KEY + 1u) != E_OK ||
        Crypto_KeySetValid(CIPHER_KEY + 1u) != E_OK ||
        Crypto_KeyElementSet(CIPHER_KEY + 1u, 5u, kCbcIv, 16u) != E_OK) {
        fprintf(stderr, "  keycopy: KeyCopy\n");
        return 1;
    }
    {
        Crypto_PrimitiveInfoType    pi;
        Crypto_JobPrimitiveInfoType jpi;
        Crypto_JobType              job;
        uint32                      outLen = 16u;

        testBuildJob(&job, &jpi, &pi, CRYPTO_ENCRYPT, CRYPTO_ALGOFAM_AES,
                     CRYPTO_ALGOMODE_CBC, CIPHER_KEY + 1u,
                     CRYPTO_PROCESSING_SYNC, 7720u);
        job.jobPrimitiveInputOutput.inputPtr        = kPt;
        job.jobPrimitiveInputOutput.inputLength     = 16u;
        job.jobPrimitiveInputOutput.outputPtr       = out;
        job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
        if (testCryIfProcessJob(0u, &job) != E_OK ||
            memcmp(out, kCbcCt, 16) != 0) {
            fprintf(stderr, "  keycopy: copied key gives wrong ciphertext\n");
            return 1;
        }
    }
    printf("  keycopy: copied AES key encrypts like the source\n");
    return 0;
}

static int testKeyCopy(void)
{
    static const uint32 keys[] = {CIPHER_KEY, CIPHER_KEY + 1u};
    return testWithKeys(testKeyCopyBody, keys, 2);
}

#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_SHA512)
static int multiCallHash(Crypto_AlgorithmFamilyType fam, uint32 dLenWant,
                         const uint8* want)
{
    static const uint8          msg[] = "abc";
    uint8                       digest[64];
    uint32                      dLen = sizeof(digest);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    uint32                      i;

    testBuildJob(&job, &jpi, &pi, CRYPTO_HASH, fam, CRYPTO_ALGOMODE_NOT_SET, 0u,
                 CRYPTO_PROCESSING_SYNC, 7730u);
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode            = CRYPTO_OPERATIONMODE_START;
    if (testCryIfProcessJob(0u, &job) != E_OK)
        return 1;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_UPDATE;
    for (i = 0; i < 3u; ++i) {
        job.jobPrimitiveInputOutput.inputPtr    = msg + i;
        job.jobPrimitiveInputOutput.inputLength = 1u;
        if (testCryIfProcessJob(0u, &job) != E_OK)
            return 1;
    }
    job.jobPrimitiveInputOutput.mode        = CRYPTO_OPERATIONMODE_FINISH;
    job.jobPrimitiveInputOutput.inputLength = 0u;
    if (testCryIfProcessJob(0u, &job) != E_OK)
        return 1;
    return (dLen == dLenWant && memcmp(digest, want, dLenWant) == 0) ? 0 : 1;
}

static int testHashMultiCall384512(void)
{
    uint8 want384[48], want512[64];

    if (wc_Sha384Hash((const byte*)"abc", 3, want384) != 0 ||
        wc_Sha512Hash((const byte*)"abc", 3, want512) != 0) {
        return 1;
    }
    if (multiCallHash(CRYPTO_ALGOFAM_SHA2_384, 48u, want384) != 0 ||
        multiCallHash(CRYPTO_ALGOFAM_SHA2_512, 64u, want512) != 0) {
        fprintf(stderr, "  hash: multi-call SHA-384/512\n");
        return 1;
    }
    printf("  hash: SHA-384/512 START/UPDATE/FINISH OK\n");
    return 0;
}
#endif

int testCipherAll(void)
{
    int failures = 0;
    TEST_RUN(failures, testAesModes);
#ifdef HAVE_AESGCM
    TEST_RUN(failures, testAesGcm);
#endif
    TEST_RUN(failures, testKeyCopy);
#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_SHA512)
    TEST_RUN(failures, testHashMultiCall384512);
#endif
    return failures;
}
