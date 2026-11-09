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
 * port/autosar/classic/examples/csm_smoke/test_kat.c
 *
 * Published-vector KATs for hashes, AES-CBC, CMAC and HKDF, CMAC-KDF against
 * software, and ECDSA, Ed25519 and RSA PKCS#1 v1.5 sign/verify round trips.
 */

#include "test_helpers.h"

#include "wolfssl/wolfcrypt/kdf.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    Crypto_AlgorithmFamilyType family;
    uint32                     digestLen;
    const char*                msg;
    int                        msgLen; /* -1 means strlen */
    const char*                expectedHex;
} hashVector;

static const hashVector kHashVectors[] = {
    /* SHA-256 */
    {CRYPTO_ALGOFAM_SHA2_256, 32, "", 0,
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {CRYPTO_ALGOFAM_SHA2_256, 32, "abc", -1,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {CRYPTO_ALGOFAM_SHA2_256, 32,
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", -1,
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
#ifdef WOLFSSL_SHA384
    /* SHA-384 */
    {CRYPTO_ALGOFAM_SHA2_384, 48, "", 0,
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe"
     "76f65fbd51ad2f14898b95b"},
    {CRYPTO_ALGOFAM_SHA2_384, 48, "abc", -1,
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba"
     "1e7cc2358baeca134c825a7"},
#endif
#ifdef WOLFSSL_SHA512
    /* SHA-512 */
    {CRYPTO_ALGOFAM_SHA2_512, 64, "", 0,
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5"
     "d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    {CRYPTO_ALGOFAM_SHA2_512, 64, "abc", -1,
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a2"
     "74fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
#endif
};

static int runHashVector(const hashVector* v, int idx)
{
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;
    uint8                       digest[64];
    uint8                       expected[64];
    uint32                      dLen = v->digestLen;
    int                         expLen, msgLen;

    expLen = testHexDecode(v->expectedHex, expected, sizeof(expected));
    if (expLen != (int)v->digestLen) {
        fprintf(stderr, "  kat hash[%d]: bad expectedHex length\n", idx);
        return 1;
    }
    msgLen = (v->msgLen < 0) ? (int)strlen(v->msg) : v->msgLen;

    memset(&pi, 0, sizeof(pi));
    pi.service          = CRYPTO_HASH;
    pi.algorithm.family = v->family;
    memset(&jpi, 0, sizeof(jpi));
    jpi.processingType = CRYPTO_PROCESSING_SYNC;
    jpi.primitiveInfo  = &pi;
    memset(&job, 0, sizeof(job));
    job.jobId                                   = (uint32)(1000 + idx);
    job.jobPrimitiveInfo                        = &jpi;
    job.jobPrimitiveInputOutput.inputPtr        = (const uint8*)v->msg;
    job.jobPrimitiveInputOutput.inputLength     = (uint32)msgLen;
    job.jobPrimitiveInputOutput.outputPtr       = digest;
    job.jobPrimitiveInputOutput.outputLengthPtr = &dLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;

    if (testCryIfProcessJob(0u, &job) != E_OK) {
        fprintf(stderr, "  kat hash[%d] family=%u: ProcessJob failed\n", idx,
                v->family);
        return 1;
    }
    if (dLen != v->digestLen) {
        fprintf(stderr, "  kat hash[%d]: dLen=%u expected=%u\n", idx, dLen,
                v->digestLen);
        return 1;
    }
    if (memcmp(digest, expected, v->digestLen) != 0) {
        fprintf(stderr, "  kat hash[%d] family=%u: digest mismatch\n", idx,
                v->family);
        return 1;
    }
    return 0;
}

static int testHashKAT(void)
{
    int failed = 0;
    for (size_t i = 0; i < sizeof(kHashVectors) / sizeof(kHashVectors[0]);
         ++i) {
        failed += runHashVector(&kHashVectors[i], (int)i);
    }
    if (failed == 0) {
        printf("  KAT hash: %zu vector(s) OK\n",
               sizeof(kHashVectors) / sizeof(kHashVectors[0]));
    }
    return failed;
}

#ifdef HAVE_AES_CBC
typedef struct {
    int         keyBits;
    const char* keyHex;
    const char* ivHex;
    const char* ptHex;
    const char* ctHex;
} aesCbcVector;

/* NIST SP 800-38A Appendix F.2 (first block only). */
static const aesCbcVector kAesCbcVectors[] = {
    /* F.2.1 CBC-AES128.Encrypt */
    {128, "2b7e151628aed2a6abf7158809cf4f3c",
     "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a",
     "7649abac8119b246cee98e9b12e9197d"},
    /* F.2.5 CBC-AES256.Encrypt */
    {256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a",
     "f58c4c04d6e5f1ba779eabfb5f7bfbd6"}};

/* Distinct keystore ids so each vector keeps its own server-side key. */
static const uint32 kAesCbcKatKeyId[] = {0x80u, 0x81u};

static int runAesCbcVector(const aesCbcVector* v, int idx)
{
    uint8                       key[32], iv[16], pt[16], ct[16], out[16];
    int                         keyLen, ivLen, ptLen, ctLen;
    uint32                      outLen = sizeof(out);
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    keyLen = testHexDecode(v->keyHex, key, sizeof(key));
    ivLen  = testHexDecode(v->ivHex, iv, sizeof(iv));
    ptLen  = testHexDecode(v->ptHex, pt, sizeof(pt));
    ctLen  = testHexDecode(v->ctHex, ct, sizeof(ct));
    if (keyLen != v->keyBits / 8 || ivLen != 16 || ptLen != 16 || ctLen != 16) {
        fprintf(stderr, "  kat aes-cbc[%d]: bad hex\n", idx);
        return 1;
    }

    if (Crypto_KeyElementSet(kAesCbcKatKeyId[idx], 1u, key, (uint32)keyLen) !=
            E_OK ||
        Crypto_KeySetValid(kAesCbcKatKeyId[idx]) != E_OK ||
        Crypto_KeyElementSet(kAesCbcKatKeyId[idx], 5u, iv, (uint32)ivLen) !=
            E_OK) {
        fprintf(stderr, "  kat aes-cbc[%d]: KeyElementSet\n", idx);
        return 1;
    }

    memset(&pi, 0, sizeof(pi));
    pi.service             = CRYPTO_ENCRYPT;
    pi.algorithm.family    = CRYPTO_ALGOFAM_AES;
    pi.algorithm.mode      = CRYPTO_ALGOMODE_CBC;
    pi.algorithm.keyLength = (uint32)v->keyBits;
    memset(&jpi, 0, sizeof(jpi));
    jpi.processingType = CRYPTO_PROCESSING_SYNC;
    jpi.primitiveInfo  = &pi;
    jpi.cryIfKeyId     = kAesCbcKatKeyId[idx];
    memset(&job, 0, sizeof(job));
    job.jobId                                   = (uint32)(2000 + idx);
    job.jobPrimitiveInfo                        = &jpi;
    job.jobPrimitiveInputOutput.inputPtr        = pt;
    job.jobPrimitiveInputOutput.inputLength     = 16u;
    job.jobPrimitiveInputOutput.outputPtr       = out;
    job.jobPrimitiveInputOutput.outputLengthPtr = &outLen;
    job.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;

    if (testCryIfProcessJob(0u, &job) != E_OK) {
        fprintf(stderr, "  kat aes-cbc[%d]: ProcessJob (encrypt)\n", idx);
        return 1;
    }
    if (outLen != 16u || memcmp(out, ct, 16) != 0) {
        fprintf(stderr, "  kat aes-cbc[%d]: ciphertext mismatch\n", idx);
        return 1;
    }
    return 0;
}

static int testAesCbcKAT(void)
{
    int failed = 0;
    for (size_t i = 0; i < sizeof(kAesCbcVectors) / sizeof(kAesCbcVectors[0]);
         ++i) {
        failed += runAesCbcVector(&kAesCbcVectors[i], (int)i);
    }
    if (failed == 0) {
        printf("  KAT aes-cbc: %zu vector(s) OK\n",
               sizeof(kAesCbcVectors) / sizeof(kAesCbcVectors[0]));
    }
    return failed;
}
#else
static int testAesCbcKAT(void)
{
    return 0;
}
#endif /* HAVE_AES_CBC */

#if defined(HAVE_ECC) && !defined(WOLFHSM_CFG_NO_CRYPTO)
static int testEcdsaSelfConsistency(void)
{
    uint8                       pub[128];
    uint32                      pubLen = sizeof(pub);
    uint8                       digest[32];
    uint8                       sig[80];
    uint8                       verifyOut = 0xFFu;
    uint32                      sigLen    = sizeof(sig);
    Crypto_PrimitiveInfoType    piSign, piVer;
    Crypto_JobPrimitiveInfoType jpiSign, jpiVer;
    Crypto_JobType              jobSign = {0}, jobVer = {0};
    int                         i;

    for (i = 0; i < 32; ++i)
        digest[i] = (uint8)(i + 1);

    /* cryptoKeyId 101 = ECC P-256 in the smoke descriptor table. */
    if (Crypto_KeyExchangeCalcPubVal(101u, pub, &pubLen) != E_OK ||
        pubLen != 64u || Crypto_KeySetValid(101u) != E_OK) {
        fprintf(stderr, "  kat ecdsa: KeyExchangeCalcPubVal failed\n");
        return 1;
    }

    memset(&piSign, 0, sizeof(piSign));
    piSign.service             = CRYPTO_SIGNATUREGENERATE;
    piSign.algorithm.family    = CRYPTO_ALGOFAM_ECCNIST;
    piSign.algorithm.mode      = CRYPTO_ALGOMODE_NOT_SET;
    piSign.algorithm.keyLength = 256u;
    memset(&jpiSign, 0, sizeof(jpiSign));
    jpiSign.processingType                          = CRYPTO_PROCESSING_SYNC;
    jpiSign.primitiveInfo                           = &piSign;
    jpiSign.cryIfKeyId                              = 101u;
    jobSign.jobId                                   = 3201u;
    jobSign.jobPrimitiveInfo                        = &jpiSign;
    jobSign.jobPrimitiveInputOutput.inputPtr        = digest;
    jobSign.jobPrimitiveInputOutput.inputLength     = 32u;
    jobSign.jobPrimitiveInputOutput.outputPtr       = sig;
    jobSign.jobPrimitiveInputOutput.outputLengthPtr = &sigLen;
    jobSign.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &jobSign) != E_OK) {
        fprintf(stderr, "  kat ecdsa: sign failed\n");
        return 1;
    }

    memset(&piVer, 0, sizeof(piVer));
    piVer.service   = CRYPTO_SIGNATUREVERIFY;
    piVer.algorithm = piSign.algorithm;
    memset(&jpiVer, 0, sizeof(jpiVer));
    jpiVer.processingType                            = CRYPTO_PROCESSING_SYNC;
    jpiVer.primitiveInfo                             = &piVer;
    jpiVer.cryIfKeyId                                = 101u;
    jobVer.jobId                                     = 3202u;
    jobVer.jobPrimitiveInfo                          = &jpiVer;
    jobVer.jobPrimitiveInputOutput.inputPtr          = digest;
    jobVer.jobPrimitiveInputOutput.inputLength       = 32u;
    jobVer.jobPrimitiveInputOutput.secondaryInputPtr = sig;
    jobVer.jobPrimitiveInputOutput.secondaryInputLength = sigLen;
    jobVer.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
    jobVer.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr, "  kat ecdsa: verify call failed\n");
        return 1;
    }
    /* Per SWS Crypto_VerifyResultType: 0x00 == OK. */
    if (verifyOut != 0x00u) {
        fprintf(stderr, "  kat ecdsa: verifyPtr=%u (expected 0)\n", verifyOut);
        return 1;
    }

    /* Corrupt the signature value, not its DER header, so verify parses it
     * and the math rejects it. */
    if (sigLen < 24u) {
        fprintf(stderr, "  kat ecdsa: signature too short to tamper\n");
        return 1;
    }
    sig[20] ^= 0x01u;
    verifyOut = 0xFFu;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr, "  kat ecdsa: verify-bad call returned E_NOT_OK "
                        "(SWS expects E_OK with verifyPtr=NOT_OK)\n");
        return 1;
    }
    /* CRYPTO_E_VER_NOT_OK on Crypto_VerifyResultType is 0x01. */
    if (verifyOut != 0x01u) {
        fprintf(stderr,
                "  kat ecdsa: verify-bad verifyPtr=0x%02x (expected 0x01)\n",
                verifyOut);
        return 1;
    }
    /* Undo so the next stanza starts from a known-good signature. */
    sig[20] ^= 0x01u;

#ifdef WH_SMOKE_TEST_MALFORMED_SIG
    /* Malformed-DER tamper: flip the SEQUENCE tag. wolfCrypt rejects
     * the signature before completing math, returning a wolfCrypt-range
     * negative rc that the verify handler currently puts straight into
     * respHeader.rc (see port/autosar/docs/client_workarounds.md
     * Issue 1). With the upstream allowlist fix applied, the handler
     * folds the rejection into (rc=0, res=0); our isVerifyRejection
     * branch covers the same case from the client side and surfaces
     * verifyPtr=NOT_OK + E_OK either way. Enable via
     * -DWH_SMOKE_TEST_MALFORMED_SIG=1 once a patched wolfHSM is in
     * use. Pre-patch this triggers a connection-level break (the
     * client closes after seeing rc<0), surfacing as a server
     * disconnect rather than a server crash. */
    sig[0] ^= 0x01u;
    verifyOut = 0xFFu;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr,
                "  kat ecdsa: malformed-DER verify returned E_NOT_OK\n");
        return 1;
    }
    if (verifyOut != 0x01u) {
        fprintf(stderr,
                "  kat ecdsa: malformed-DER verifyPtr=0x%02x (expected 0x01)\n",
                verifyOut);
        return 1;
    }
    sig[0] ^= 0x01u;
    printf("  KAT ecdsa P-256: sign + good + math-fail + malformed-DER OK\n");
#else
    printf("  KAT ecdsa P-256: sign + good-sig verify + tampered-sig OK\n");
#endif
    return 0;
}
#else
static int testEcdsaSelfConsistency(void)
{
    return 0;
}
#endif

#if defined(HAVE_ED25519) && !defined(WOLFHSM_CFG_NO_CRYPTO)
static int testEd25519SelfConsistency(void)
{
    /* cryptoKeyId 102 = Ed25519 in the smoke descriptor table. */
    uint8                       msg[64];
    uint8                       sig[80];
    uint32                      sigLen    = sizeof(sig);
    uint8                       verifyOut = 0xFFu;
    Crypto_PrimitiveInfoType    piSign, piVer;
    Crypto_JobPrimitiveInfoType jpiSign, jpiVer;
    Crypto_JobType              jobSign = {0}, jobVer = {0};
    int                         i;

    for (i = 0; i < (int)sizeof(msg); ++i)
        msg[i] = (uint8)(i * 11 + 3);

    if (Crypto_KeyGenerate(102u) != E_OK || Crypto_KeySetValid(102u) != E_OK) {
        fprintf(stderr, "  kat ed25519: KeyGenerate failed\n");
        return 1;
    }

    memset(&piSign, 0, sizeof(piSign));
    piSign.service             = CRYPTO_SIGNATUREGENERATE;
    piSign.algorithm.family    = CRYPTO_ALGOFAM_ED25519;
    piSign.algorithm.mode      = CRYPTO_ALGOMODE_NOT_SET;
    piSign.algorithm.keyLength = 256u;
    memset(&jpiSign, 0, sizeof(jpiSign));
    jpiSign.processingType                          = CRYPTO_PROCESSING_SYNC;
    jpiSign.primitiveInfo                           = &piSign;
    jpiSign.cryIfKeyId                              = 102u;
    jobSign.jobId                                   = 3201u;
    jobSign.jobPrimitiveInfo                        = &jpiSign;
    jobSign.jobPrimitiveInputOutput.inputPtr        = msg;
    jobSign.jobPrimitiveInputOutput.inputLength     = sizeof(msg);
    jobSign.jobPrimitiveInputOutput.outputPtr       = sig;
    jobSign.jobPrimitiveInputOutput.outputLengthPtr = &sigLen;
    jobSign.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &jobSign) != E_OK) {
        fprintf(stderr, "  kat ed25519: sign failed\n");
        return 1;
    }
    if (sigLen != 64u) {
        fprintf(stderr, "  kat ed25519: sigLen=%u (expected 64)\n", sigLen);
        return 1;
    }

    memset(&piVer, 0, sizeof(piVer));
    piVer.service   = CRYPTO_SIGNATUREVERIFY;
    piVer.algorithm = piSign.algorithm;
    memset(&jpiVer, 0, sizeof(jpiVer));
    jpiVer.processingType                            = CRYPTO_PROCESSING_SYNC;
    jpiVer.primitiveInfo                             = &piVer;
    jpiVer.cryIfKeyId                                = 102u;
    jobVer.jobId                                     = 3202u;
    jobVer.jobPrimitiveInfo                          = &jpiVer;
    jobVer.jobPrimitiveInputOutput.inputPtr          = msg;
    jobVer.jobPrimitiveInputOutput.inputLength       = sizeof(msg);
    jobVer.jobPrimitiveInputOutput.secondaryInputPtr = sig;
    jobVer.jobPrimitiveInputOutput.secondaryInputLength = sigLen;
    jobVer.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
    jobVer.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr, "  kat ed25519: verify call failed\n");
        return 1;
    }
    if (verifyOut != 0x00u) {
        fprintf(stderr, "  kat ed25519: verifyPtr=0x%02x (expected 0)\n",
                verifyOut);
        return 1;
    }

    sig[20] ^= 0x01u;
    verifyOut = 0xFFu;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr, "  kat ed25519: bad-sig verify call failed\n");
        return 1;
    }
    if (verifyOut != 0x01u) {
        fprintf(stderr,
                "  kat ed25519: bad-sig verifyPtr=0x%02x (expected 1)\n",
                verifyOut);
        return 1;
    }
    printf("  KAT ed25519: keygen + sign + verify + tampered-sig OK\n");
    return 0;
}
#else
static int testEd25519SelfConsistency(void)
{
    return 0;
}
#endif

#if !defined(NO_RSA) && !defined(WOLFHSM_CFG_NO_CRYPTO)
static int testRsaPkcs1v15SelfConsistency(void)
{
    /* cryptoKeyId 103 = RSA-2048 in the smoke descriptor table. */
    uint8                       hash[32];
    uint8                       sig[256];
    uint32                      sigLen    = sizeof(sig);
    uint8                       verifyOut = 0xFFu;
    Crypto_PrimitiveInfoType    piSign, piVer;
    Crypto_JobPrimitiveInfoType jpiSign, jpiVer;
    Crypto_JobType              jobSign = {0}, jobVer = {0};
    int                         i;

    for (i = 0; i < (int)sizeof(hash); ++i)
        hash[i] = (uint8)(i * 13 + 7);

    /* RSA-2048 keygen is expensive; this can take a few seconds. */
    if (Crypto_KeyGenerate(103u) != E_OK || Crypto_KeySetValid(103u) != E_OK) {
        fprintf(stderr, "  kat rsa: KeyGenerate(RSA-2048) failed\n");
        return 1;
    }

    memset(&piSign, 0, sizeof(piSign));
    piSign.service             = CRYPTO_SIGNATUREGENERATE;
    piSign.algorithm.family    = CRYPTO_ALGOFAM_RSA;
    piSign.algorithm.mode      = CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5;
    piSign.algorithm.keyLength = 2048u;
    memset(&jpiSign, 0, sizeof(jpiSign));
    jpiSign.processingType                          = CRYPTO_PROCESSING_SYNC;
    jpiSign.primitiveInfo                           = &piSign;
    jpiSign.cryIfKeyId                              = 103u;
    jobSign.jobId                                   = 3201u;
    jobSign.jobPrimitiveInfo                        = &jpiSign;
    jobSign.jobPrimitiveInputOutput.inputPtr        = hash;
    jobSign.jobPrimitiveInputOutput.inputLength     = sizeof(hash);
    jobSign.jobPrimitiveInputOutput.outputPtr       = sig;
    jobSign.jobPrimitiveInputOutput.outputLengthPtr = &sigLen;
    jobSign.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &jobSign) != E_OK) {
        fprintf(stderr, "  kat rsa: sign failed\n");
        return 1;
    }
    if (sigLen != 256u) {
        fprintf(stderr, "  kat rsa: sigLen=%u (expected 256)\n", sigLen);
        return 1;
    }

    memset(&piVer, 0, sizeof(piVer));
    piVer.service   = CRYPTO_SIGNATUREVERIFY;
    piVer.algorithm = piSign.algorithm;
    memset(&jpiVer, 0, sizeof(jpiVer));
    jpiVer.processingType                            = CRYPTO_PROCESSING_SYNC;
    jpiVer.primitiveInfo                             = &piVer;
    jpiVer.cryIfKeyId                                = 103u;
    jobVer.jobId                                     = 3202u;
    jobVer.jobPrimitiveInfo                          = &jpiVer;
    jobVer.jobPrimitiveInputOutput.inputPtr          = hash;
    jobVer.jobPrimitiveInputOutput.inputLength       = sizeof(hash);
    jobVer.jobPrimitiveInputOutput.secondaryInputPtr = sig;
    jobVer.jobPrimitiveInputOutput.secondaryInputLength = sigLen;
    jobVer.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
    jobVer.jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr, "  kat rsa: verify call failed\n");
        return 1;
    }
    if (verifyOut != 0x00u) {
        fprintf(stderr, "  kat rsa: verifyPtr=0x%02x (expected 0)\n",
                verifyOut);
        return 1;
    }

    /* Tampered: flip a byte deep in the signature value. */
    sig[100] ^= 0x01u;
    verifyOut = 0xFFu;
    if (testCryIfProcessJob(0u, &jobVer) != E_OK) {
        fprintf(stderr, "  kat rsa: bad-sig verify call failed\n");
        return 1;
    }
    if (verifyOut != 0x01u) {
        fprintf(stderr, "  kat rsa: bad-sig verifyPtr=0x%02x (expected 1)\n",
                verifyOut);
        return 1;
    }
    printf("  KAT rsa-pkcs1-v1.5 2048: keygen + sign + verify + tampered-sig "
           "OK\n");
    return 0;
}
#else
static int testRsaPkcs1v15SelfConsistency(void)
{
    return 0;
}
#endif

#ifndef WOLFHSM_CFG_NO_CRYPTO
static int installCmacKey(uint32 cryptoKeyId)
{
    /* NIST CMAC AES-128 SP 800-38B example key K. */
    static const uint8 k[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    return (Crypto_KeyElementSet(cryptoKeyId, 1u, k, (uint32)sizeof(k)) ==
                E_OK &&
            Crypto_KeySetValid(cryptoKeyId) == E_OK)
               ? 0
               : 1;
}

static void buildCmacJob(Crypto_JobType* job, Crypto_JobPrimitiveInfoType* jpi,
                         Crypto_PrimitiveInfoType* pi,
                         Crypto_ServiceInfoType service, uint32 cryIfKeyId,
                         uint8 async, uint32 jobId)
{
    memset(pi, 0, sizeof(*pi));
    pi->service             = service;
    pi->algorithm.family    = CRYPTO_ALGOFAM_AES;
    pi->algorithm.mode      = CRYPTO_ALGOMODE_CMAC;
    pi->algorithm.keyLength = 128u;
    memset(jpi, 0, sizeof(*jpi));
    jpi->primitiveInfo = pi;
    jpi->cryIfKeyId    = cryIfKeyId;
    jpi->processingType =
        async ? CRYPTO_PROCESSING_ASYNC : CRYPTO_PROCESSING_SYNC;
    memset(job, 0, sizeof(*job));
    job->jobId                        = jobId;
    job->jobPrimitiveInfo             = jpi;
    job->jobPrimitiveInputOutput.mode = CRYPTO_OPERATIONMODE_SINGLECALL;
}

static int testCmacSyncAndAsync(void)
{
    /* cryptoKeyId 110 = AES-128 CMAC key (installed below). */
    const uint8 msg[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    /* SP 800-38B D.1 Example 2 tag. */
    const uint8    tag[16] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                              0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    uint8          mac[16];
    uint32         macLen = sizeof(mac);
    uint8          bad[16];
    uint8          macAsync[16];
    uint32         macAsyncLen = sizeof(macAsync);
    uint8          verifyOut;
    Std_ReturnType res = E_NOT_OK;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    if (installCmacKey(110u) != 0) {
        fprintf(stderr, "  kat cmac: KeyElementSet(110) failed\n");
        return 1;
    }

    buildCmacJob(&job, &jpi, &pi, CRYPTO_MACGENERATE, 110u, 0u, 1100u);
    job.jobPrimitiveInputOutput.inputPtr        = msg;
    job.jobPrimitiveInputOutput.inputLength     = (uint32)sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr       = mac;
    job.jobPrimitiveInputOutput.outputLengthPtr = &macLen;
    if (testCryIfProcessJob(0u, &job) != E_OK || macLen != 16u ||
        memcmp(mac, tag, sizeof(tag)) != 0) {
        fprintf(stderr, "  kat cmac: sync generate failed\n");
        return 1;
    }

    verifyOut = 0xFFu;
    buildCmacJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, 110u, 0u, 1101u);
    job.jobPrimitiveInputOutput.inputPtr             = msg;
    job.jobPrimitiveInputOutput.inputLength          = (uint32)sizeof(msg);
    job.jobPrimitiveInputOutput.secondaryInputPtr    = mac;
    job.jobPrimitiveInputOutput.secondaryInputLength = 128u;
    job.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
    if (testCryIfProcessJob(0u, &job) != E_OK || verifyOut != 0x00u) {
        fprintf(stderr,
                "  kat cmac: sync verify-good failed (verifyOut=0x%02x)\n",
                verifyOut);
        return 1;
    }

    memcpy(bad, mac, 16);
    bad[0] ^= 0x01u;
    verifyOut = 0xFFu;
    buildCmacJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, 110u, 0u, 1102u);
    job.jobPrimitiveInputOutput.inputPtr             = msg;
    job.jobPrimitiveInputOutput.inputLength          = (uint32)sizeof(msg);
    job.jobPrimitiveInputOutput.secondaryInputPtr    = bad;
    job.jobPrimitiveInputOutput.secondaryInputLength = 128u;
    job.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
    if (testCryIfProcessJob(0u, &job) != E_OK || verifyOut != 0x01u) {
        fprintf(stderr,
                "  kat cmac: sync verify-bad failed (verifyOut=0x%02x)\n",
                verifyOut);
        return 1;
    }

    /* Async MAC must match the sync output. */
    buildCmacJob(&job, &jpi, &pi, CRYPTO_MACGENERATE, 110u, 1u, 1103u);
    job.jobPrimitiveInputOutput.inputPtr        = msg;
    job.jobPrimitiveInputOutput.inputLength     = (uint32)sizeof(msg);
    job.jobPrimitiveInputOutput.outputPtr       = macAsync;
    job.jobPrimitiveInputOutput.outputLengthPtr = &macAsyncLen;
    if (testRunAsync(&job, &res) != E_OK || res != E_OK) {
        fprintf(stderr, "  kat cmac: async generate failed\n");
        return 1;
    }
    if (macAsyncLen != 16u || memcmp(macAsync, mac, 16) != 0) {
        fprintf(stderr, "  kat cmac: async mac mismatch sync\n");
        return 1;
    }

    verifyOut = 0xFFu;
    buildCmacJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, 110u, 1u, 1104u);
    job.jobPrimitiveInputOutput.inputPtr             = msg;
    job.jobPrimitiveInputOutput.inputLength          = (uint32)sizeof(msg);
    job.jobPrimitiveInputOutput.secondaryInputPtr    = mac;
    job.jobPrimitiveInputOutput.secondaryInputLength = 128u;
    job.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
    if (testRunAsync(&job, &res) != E_OK || res != E_OK || verifyOut != 0x00u) {
        fprintf(stderr,
                "  kat cmac: async verify-good failed (verifyOut=0x%02x)\n",
                verifyOut);
        return 1;
    }

    printf("  KAT cmac-aes-128: sync gen+verify-good+verify-bad, async gen "
           "(match) + verify-good OK\n");
    return 0;
}

/* RFC 4493 section 4: message prefixes of 0, 16, 40 and 64 bytes. */
static const char kCmacMsgHex[] =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

static const struct {
    uint32      len;
    const char* tagHex;
} kCmacVectors[] = {{0u, "bb1d6929e95937287fa37d129b756746"},
                    {16u, "070a16b46b4d4144f79bdd9dd04a287c"},
                    {40u, "dfa66747de9ae63030ca32611497c827"},
                    {64u, "51f0bebf7e3b9d92fc49741779363cfe"}};

static Std_ReturnType runCmacJob(Crypto_JobType* job, uint8 async)
{
    Std_ReturnType res = E_NOT_OK;

    if (!async) {
        return testCryIfProcessJob(0u, job);
    }
    return (testRunAsync(job, &res) == E_OK) ? res : E_NOT_OK;
}

static int testCmacRfc4493Body(void)
{
    uint8                       msg[64];
    uint8                       tag[16];
    uint8                       mac[16];
    uint32                      macLen;
    uint8                       verifyOut;
    uint8                       async;
    size_t                      i;
    Crypto_PrimitiveInfoType    pi;
    Crypto_JobPrimitiveInfoType jpi;
    Crypto_JobType              job;

    if (installCmacKey(111u) != 0 ||
        testHexDecode(kCmacMsgHex, msg, sizeof(msg)) != (int)sizeof(msg)) {
        return 1;
    }
    for (i = 0; i < sizeof(kCmacVectors) / sizeof(kCmacVectors[0]); ++i) {
        if (testHexDecode(kCmacVectors[i].tagHex, tag, sizeof(tag)) !=
            (int)sizeof(tag)) {
            return 1;
        }
        for (async = 0u; async < 2u; ++async) {
            macLen = sizeof(mac);
            buildCmacJob(&job, &jpi, &pi, CRYPTO_MACGENERATE, 111u, async,
                         1110u);
            job.jobPrimitiveInputOutput.inputPtr        = msg;
            job.jobPrimitiveInputOutput.inputLength     = kCmacVectors[i].len;
            job.jobPrimitiveInputOutput.outputPtr       = mac;
            job.jobPrimitiveInputOutput.outputLengthPtr = &macLen;
            if (runCmacJob(&job, async) != E_OK || macLen != 16u ||
                memcmp(mac, tag, sizeof(tag)) != 0) {
                fprintf(stderr, "  kat cmac: RFC 4493 ex %u generate (%s)\n",
                        (unsigned)(i + 1u), async ? "async" : "sync");
                return 1;
            }
            verifyOut = 0xFFu;
            buildCmacJob(&job, &jpi, &pi, CRYPTO_MACVERIFY, 111u, async, 1111u);
            job.jobPrimitiveInputOutput.inputPtr          = msg;
            job.jobPrimitiveInputOutput.inputLength       = kCmacVectors[i].len;
            job.jobPrimitiveInputOutput.secondaryInputPtr = tag;
            job.jobPrimitiveInputOutput.secondaryInputLength = 128u;
            job.jobPrimitiveInputOutput.verifyPtr            = &verifyOut;
            if (runCmacJob(&job, async) != E_OK ||
                verifyOut != CRYPTO_E_VER_OK) {
                fprintf(stderr, "  kat cmac: RFC 4493 ex %u verify (%s)\n",
                        (unsigned)(i + 1u), async ? "async" : "sync");
                return 1;
            }
        }
    }
    printf("  KAT cmac-aes-128: RFC 4493 examples 1-4, sync + async\n");
    return 0;
}

static int testCmacRfc4493(void)
{
    static const uint32 keys[] = {111u};
    return testWithKeys(testCmacRfc4493Body, keys, 1);
}

#if defined(HAVE_HKDF) || defined(HAVE_CMAC_KDF)
static int testKdfKatBody(void)
{
#ifdef HAVE_CMAC_KDF
    static const uint8 zeroSalt[AES_128_KEY_SIZE] = {0};
#endif
    uint8  ikm[22];
    uint8  want[32];
    uint8  got[32];
    uint32 gotLen = sizeof(got);

    memset(ikm, 0x0b, sizeof(ikm));
    if (Crypto_KeyElementSet(135u, 1u, ikm, sizeof(ikm)) != E_OK ||
        Crypto_KeySetValid(135u) != E_OK) {
        fprintf(stderr, "  kat kdf: source key\n");
        return 1;
    }
#ifdef HAVE_HKDF
    /* RFC 5869 A.3 (no salt, no info): first 32 bytes of the OKM. */
    if (testHexDecode("8da4e775a563c18f715f802a063c5a31"
                      "b8a11f5c5ee1879ec3454e5f3c738d2d",
                      want, sizeof(want)) != 32 ||
        Crypto_KeyDerive(135u, 124u) != E_OK ||
        Crypto_KeyElementGet(124u, 1u, got, &gotLen) != E_OK || gotLen != 32u ||
        memcmp(got, want, 32u) != 0) {
        fprintf(stderr, "  kat kdf: HKDF differs from RFC 5869 A.3\n");
        return 1;
    }
#endif
#ifdef HAVE_CMAC_KDF
    /* No salt element: the driver uses a zero block as the salt. */
    gotLen = sizeof(got);
    if (wc_KDA_KDF_twostep_cmac(zeroSalt, sizeof(zeroSalt), ikm, sizeof(ikm),
                                NULL, 0u, want, 16u, NULL,
                                INVALID_DEVID) != 0 ||
        Crypto_KeyDerive(135u, 125u) != E_OK ||
        Crypto_KeyElementGet(125u, 1u, got, &gotLen) != E_OK || gotLen != 16u ||
        memcmp(got, want, 16u) != 0) {
        fprintf(stderr, "  kat kdf: CMAC-KDF differs from software\n");
        return 1;
    }
#endif
    printf("  KAT kdf: HKDF against RFC 5869 A.3, CMAC-KDF against "
           "software\n");
    return 0;
}

static int testKdfKat(void)
{
    static const uint32 keys[] = {135u, 124u, 125u};
    return testWithKeys(testKdfKatBody, keys, 3);
}
#endif
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

int testKatAll(void)
{
    static const uint32 keys[]   = {0x80u, 0x81u, 101u, 102u, 103u, 110u};
    int                 failures = 0;
    size_t              i;

    TEST_RUN(failures, testHashKAT);
    TEST_RUN(failures, testAesCbcKAT);
    TEST_RUN(failures, testEcdsaSelfConsistency);
    TEST_RUN(failures, testEd25519SelfConsistency);
    TEST_RUN(failures, testRsaPkcs1v15SelfConsistency);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    TEST_RUN(failures, testCmacSyncAndAsync);
    TEST_RUN(failures, testCmacRfc4493);
#if defined(HAVE_HKDF) || defined(HAVE_CMAC_KDF)
    TEST_RUN(failures, testKdfKat);
#endif
#endif
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        testEraseKey(keys[i]);
    return failures;
}
