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
 * test-refactor/client-server/wh_test_crypto_cmac.c
 *
 * AES-CMAC tests against NIST SP 800-38B vectors. For each (key, msg, tag)
 * triple, exercises (a) one-shot generate with a cached server key,
 * (b) one-shot verify, and (c) incremental update/finalize. Also commits a
 * key to NVM and verifies through the cache->NVM->cache fetch path.
 * Streaming tests check input larger than one comm buffer message against
 * software CMAC.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
static int whTest_CryptoCmacImpl(whClientContext* ctx, int devId)
{
    int     ret   = 0;
    Cmac    cmac[1];
    uint8_t tag[AES_BLOCK_SIZE]       = {0};
    word32  tagSz;
    whKeyId keyId;
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "CMAC Key Label";
    word32  i;

    /* NIST SP 800-38B test vectors */
#ifdef WOLFSSL_AES_128
    const byte k128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
#endif
#ifdef WOLFSSL_AES_192
    const byte k192[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                         0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                         0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
#endif
#ifdef WOLFSSL_AES_256
    const byte k256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                         0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                         0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                         0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
#endif

    const byte m[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    enum {
        CMAC_MLEN_0   = 0,
        CMAC_MLEN_128 = 128 / 8,
        CMAC_MLEN_319 = 320 / 8 - 1,
        CMAC_MLEN_320 = 320 / 8,
        CMAC_MLEN_512 = 512 / 8,
    };

#ifdef WOLFSSL_AES_128
    const byte t128_0[]   = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                             0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
    const byte t128_128[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                             0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    const byte t128_319[] = {0x2c, 0x17, 0x84, 0x4c, 0x93, 0x1c, 0x07, 0x95,
                             0x15, 0x92, 0x73, 0x0a, 0x34, 0xd0, 0xd9, 0xd2};
    const byte t128_320[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                             0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
    const byte t128_512[] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                             0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};
#endif
#ifdef WOLFSSL_AES_192
    const byte t192_0[]   = {0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
                             0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67};
    const byte t192_128[] = {0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
                             0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84};
    const byte t192_320[] = {0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
                             0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e};
    const byte t192_512[] = {0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
                             0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11};
#endif
#ifdef WOLFSSL_AES_256
    const byte t256_0[]   = {0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
                             0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83};
    const byte t256_128[] = {0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
                             0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c};
    const byte t256_320[] = {0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
                             0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6};
    const byte t256_512[] = {0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
                             0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10};
#endif

    typedef struct {
        const byte* k;
        word32      kSz;
        const byte* m;
        word32      mSz;
        const byte* t;
        word32      tSz;
        word32      partial;
    } CmacTestCase;

    const CmacTestCase testCases[] = {
#ifdef WOLFSSL_AES_128
        {k128, sizeof(k128), m, CMAC_MLEN_0, t128_0, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_128, t128_128, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_319, t128_319, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_320, t128_320, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_512, t128_512, AES_BLOCK_SIZE, 0},
        {k128, sizeof(k128), m, CMAC_MLEN_512, t128_512, AES_BLOCK_SIZE, 5},
#endif
#ifdef WOLFSSL_AES_192
        {k192, sizeof(k192), m, CMAC_MLEN_0, t192_0, AES_BLOCK_SIZE, 0},
        {k192, sizeof(k192), m, CMAC_MLEN_128, t192_128, AES_BLOCK_SIZE, 0},
        {k192, sizeof(k192), m, CMAC_MLEN_320, t192_320, AES_BLOCK_SIZE, 0},
        {k192, sizeof(k192), m, CMAC_MLEN_512, t192_512, AES_BLOCK_SIZE, 0},
#endif
#ifdef WOLFSSL_AES_256
        {k256, sizeof(k256), m, CMAC_MLEN_0, t256_0, AES_BLOCK_SIZE, 0},
        {k256, sizeof(k256), m, CMAC_MLEN_128, t256_128, AES_BLOCK_SIZE, 0},
        {k256, sizeof(k256), m, CMAC_MLEN_320, t256_320, AES_BLOCK_SIZE, 0},
        {k256, sizeof(k256), m, CMAC_MLEN_512, t256_512, AES_BLOCK_SIZE, 0},
#endif
    };
    const word32 numCases = sizeof(testCases) / sizeof(testCases[0]);

    for (i = 0; i < numCases && ret == 0; i++) {
        const CmacTestCase* tc = &testCases[i];

        /* (a) One-shot generate with cached key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)tc->k, tc->kSz,
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (gen) tc=%d %d\n", i,
                           ret);
            break;
        }
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_InitCmac_ex (gen) tc=%d %d\n", i, ret);
            break;
        }
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to wh_Client_CmacSetKeyId (gen) tc=%d %d\n", i, ret);
            break;
        }
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret = wc_AesCmacGenerate_ex(cmac, tag, &tagSz, tc->m, tc->mSz, NULL, 0,
                                    NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_AesCmacGenerate_ex tc=%d %d\n", i, ret);
            break;
        }
        if (memcmp(tag, tc->t, AES_BLOCK_SIZE) != 0) {
            WH_ERROR_PRINT("CMAC generate mismatch tc=%d\n", i);
            ret = -1;
            break;
        }
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict (gen) tc=%d %d\n", i,
                           ret);
            break;
        }

        /* (b) One-shot verify with cached key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_VERIFY, labelIn,
                                   sizeof(labelIn), (uint8_t*)tc->k, tc->kSz,
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (ver) tc=%d %d\n", i,
                           ret);
            break;
        }
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to wh_Client_CmacSetKeyId (ver) tc=%d %d\n", i, ret);
            break;
        }
        ret = wc_AesCmacVerify_ex(cmac, tc->t, tc->tSz, tc->m, tc->mSz, NULL,
                                  0, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_AesCmacVerify_ex tc=%d %d\n", i, ret);
            break;
        }
        wc_CmacFree(cmac);
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict (ver) tc=%d %d\n", i,
                           ret);
            break;
        }

        /* (c) Incremental init/update/final with cached key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                   sizeof(labelIn), (uint8_t*)tc->k, tc->kSz,
                                   &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (inc) tc=%d %d\n", i,
                           ret);
            break;
        }
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_InitCmac_ex (inc) tc=%d %d\n", i, ret);
            break;
        }
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to wh_Client_CmacSetKeyId (inc) tc=%d %d\n", i, ret);
            break;
        }
        if (tc->partial > 0) {
            word32 firstSz  = tc->mSz / 2 - tc->partial;
            word32 secondSz = tc->mSz / 2 + tc->partial;
            ret             = wc_CmacUpdate(cmac, tc->m, firstSz);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed wc_CmacUpdate (inc1) tc=%d %d\n", i,
                               ret);
                break;
            }
            ret = wc_CmacUpdate(cmac, tc->m + firstSz, secondSz);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed wc_CmacUpdate (inc2) tc=%d %d\n", i,
                               ret);
                break;
            }
        }
        else {
            ret = wc_CmacUpdate(cmac, tc->m, tc->mSz);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed wc_CmacUpdate (inc) tc=%d %d\n", i,
                               ret);
                break;
            }
        }
        memset(tag, 0, sizeof(tag));
        tagSz = sizeof(tag);
        ret   = wc_CmacFinal(cmac, tag, &tagSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_CmacFinal (inc) tc=%d %d\n", i, ret);
            break;
        }
        if (memcmp(tag, tc->t, AES_BLOCK_SIZE) != 0) {
            WH_ERROR_PRINT("CMAC incremental mismatch tc=%d\n", i);
            ret = -1;
            break;
        }
        wc_CmacFree(cmac);
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict (inc) tc=%d %d\n", i,
                           ret);
            break;
        }
    }

    /* Round-trip a key through commit / evict / re-cache, then verify a tag
     * computed from the still-valid key material. */
    if (ret == 0) {
#ifdef WOLFSSL_AES_128
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_VERIFY, labelIn,
                                   sizeof(labelIn), (uint8_t*)k128,
                                   sizeof(k128), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache (commit) %d\n", ret);
        }
        else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            }
            else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                }
                else {
                    ret = wc_InitCmac_ex(cmac, k128, sizeof(k128), WC_CMAC_AES,
                                         NULL, NULL, devId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
                    }
                    else {
                        ret = wh_Client_CmacSetKeyId(cmac, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to wh_Client_CmacSetKeyId %d\n", ret);
                        }
                        else {
                            tagSz = sizeof(tag);
                            ret   = wc_AesCmacVerify_ex(
                                cmac, t128_512, sizeof(t128_512), m,
                                CMAC_MLEN_512, NULL, 0, NULL, devId);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed wc_AesCmacVerify_ex (commit) "
                                    "%d\n",
                                    ret);
                            }
                            else {
                                ret = wh_Client_KeyErase(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT(
                                        "Failed to wh_Client_KeyErase %d\n",
                                        ret);
                                }
                            }
                        }
                    }
                }
            }
        }
#endif /* WOLFSSL_AES_128 */
    }

    if (ret == 0) {
        WH_TEST_PRINT("CMAC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFSSL_AES_256
/* Spans several max size Update requests. Static to limit stack use. */
static uint8_t
    whTest_CmacBigBuf[3 * WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_UPDATE_SZ + 7u];

/* Compute a CMAC in software (no devId) to compare against. */
static int whTest_CmacReference(const uint8_t* key, uint32_t keyLen,
                                const uint8_t* in, uint32_t inLen,
                                uint8_t out[AES_BLOCK_SIZE])
{
    Cmac   sw[1];
    word32 outSz = AES_BLOCK_SIZE;
    int    ret;

    ret =
        wc_InitCmac_ex(sw, key, keyLen, WC_CMAC_AES, NULL, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_CmacUpdate(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_CmacFinal(sw, out, &outSz);
    }
    (void)wc_CmacFree(sw);
    return ret;
}

/* CMAC input larger than one message, checked against software CMAC */
static int _whTest_CryptoCmacStreaming(whClientContext* ctx, int devId)
{
    int            ret = 0;
    Cmac           cmac[1];
    uint8_t        tag[AES_BLOCK_SIZE];
    uint8_t        ref[AES_BLOCK_SIZE];
    word32         tagSz;
    whKeyId        keyId                     = WH_KEYID_ERASED;
    uint8_t        labelIn[WH_NVM_LABEL_LEN] = "CMAC Streaming";
    uint8_t*       buf                       = whTest_CmacBigBuf;
    const uint32_t bufSz = (uint32_t)sizeof(whTest_CmacBigBuf);
    const uint32_t maxSz = WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_UPDATE_SZ;
    /* Around the per-request limit, and spanning several requests */
    const uint32_t sizes[] = {WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_UPDATE_SZ,
                              WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_UPDATE_SZ + 1u,
                              sizeof(whTest_CmacBigBuf)};
    /* Crosses the partial block and the per-request limit */
    const uint32_t chunks[] = {
        5,  11,
        1,  WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_UPDATE_SZ + 3u,
        17, WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_UPDATE_SZ - 20u};
    const byte key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    uint32_t   i;
    bool       sent;

    for (i = 0; i < bufSz; i++) {
        buf[i] = (uint8_t)((i * 13u + 5u) & 0xff);
    }

    /* Case A: oneshot with an inline key on an uninitialized cmac */
    for (i = 0; ret == 0 && i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        memset(cmac, 0xA5, sizeof(cmac));
        tagSz = sizeof(tag);
        ret   = wc_AesCmacGenerate_ex(cmac, tag, &tagSz, buf, sizes[i], key,
                                      sizeof(key), NULL, devId);
        if (ret == 0) {
            ret = whTest_CmacReference(key, sizeof(key), buf, sizes[i], ref);
        }
        if (ret == 0 && memcmp(tag, ref, sizeof(ref)) != 0) {
            WH_ERROR_PRINT("CMAC streaming: generate mismatch sz=%u\n",
                           (unsigned)sizes[i]);
            ret = -1;
        }
        if (ret == 0) {
            memset(cmac, 0xA5, sizeof(cmac));
            ret = wc_AesCmacVerify_ex(cmac, ref, sizeof(ref), buf, sizes[i],
                                      key, sizeof(key), NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("CMAC streaming: verify failed sz=%u %d\n",
                               (unsigned)sizes[i], ret);
            }
        }
    }

    /* Case B: incremental updates with a cached HSM key */
    if (ret == 0) {
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, labelIn,
                                 sizeof(labelIn), (uint8_t*)key, sizeof(key),
                                 &keyId);
    }
    if (ret == 0) {
        uint32_t off = 0;
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
        }
        for (i = 0; ret == 0 && i < sizeof(chunks) / sizeof(chunks[0]); i++) {
            ret = wc_CmacUpdate(cmac, buf + off, chunks[i]);
            off += chunks[i];
        }
        if (ret == 0) {
            tagSz = sizeof(tag);
            ret   = wc_CmacFinal(cmac, tag, &tagSz);
        }
        (void)wc_CmacFree(cmac);
        if (ret == 0) {
            ret = whTest_CmacReference(key, sizeof(key), buf, off, ref);
        }
        if (ret == 0 && memcmp(tag, ref, sizeof(ref)) != 0) {
            WH_ERROR_PRINT("CMAC streaming: HSM key update mismatch\n");
            ret = -1;
        }
    }

    /* Case C: a failed Update leaves the streaming state unchanged */
    if (ret == 0) {
        whKeyId evictedId = keyId;

        ret   = wh_Client_KeyEvict(ctx, keyId);
        keyId = WH_KEYID_ERASED;
        if (ret == 0) {
            ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        }
        if (ret == 0) {
            ret = wh_Client_CmacSetKeyId(cmac, evictedId);
        }
        if (ret == 0) {
            /* Absorbed locally, so the evicted key is not seen yet */
            ret = wc_CmacUpdate(cmac, buf, 5);
        }
        if (ret == 0) {
            int rc = wh_Client_Cmac(ctx, cmac, WC_CMAC_AES, NULL, 0, buf + 5,
                                    2 * maxSz, NULL, NULL);
            if (rc == WH_ERROR_OK) {
                WH_ERROR_PRINT("CMAC streaming: expected evicted key error\n");
                ret = -1;
            }
            else if (cmac->bufferSz != 5 || cmac->totalSz != 0 ||
                     memcmp(cmac->buffer, buf, 5) != 0) {
                WH_ERROR_PRINT("CMAC streaming: state changed on error\n");
                ret = -1;
            }
        }
        (void)wc_CmacFree(cmac);
    }

    /* Case D: inline key set at init, then one large update */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, key, sizeof(key), WC_CMAC_AES, NULL, NULL,
                             devId);
        if (ret == 0) {
            ret = wc_CmacUpdate(cmac, buf, bufSz);
        }
        if (ret == 0) {
            tagSz = sizeof(tag);
            ret   = wc_CmacFinal(cmac, tag, &tagSz);
        }
        (void)wc_CmacFree(cmac);
        if (ret == 0) {
            ret = whTest_CmacReference(key, sizeof(key), buf, bufSz, ref);
        }
        if (ret == 0 && memcmp(tag, ref, sizeof(ref)) != 0) {
            WH_ERROR_PRINT("CMAC streaming: inline key update mismatch\n");
            ret = -1;
        }
    }

    /* Case E: async input that fits in the partial block needs no request */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
    }
    if (ret == 0) {
        sent = true;
        ret  = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, key,
                                           sizeof(key), buf, 5, &sent);
        if (ret == 0 && sent) {
            WH_ERROR_PRINT("CMAC streaming: 5 byte update was sent\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        sent = true;
        ret  = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                           buf + 5, 11, &sent);
        if (ret == 0 && (sent || cmac->bufferSz != AES_BLOCK_SIZE)) {
            WH_ERROR_PRINT("CMAC streaming: full block update was sent\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, NULL, 0,
                                           buf + 16, 1, &sent);
        if (ret == 0 && !sent) {
            WH_ERROR_PRINT("CMAC streaming: 17th byte was not sent\n");
            ret = -1;
        }
        if (ret == 0) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
    }
    if (ret == 0) {
        uint32_t outSz = sizeof(tag);
        do {
            ret = wh_Client_CmacFinalResponse(ctx, cmac, tag, &outSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_CmacReference(key, sizeof(key), buf, 17, ref);
    }
    if (ret == 0 && memcmp(tag, ref, sizeof(ref)) != 0) {
        WH_ERROR_PRINT("CMAC streaming: local absorb mismatch\n");
        ret = -1;
    }

    /* Case F: async updates of exactly the max size with a 32 byte key */
    if (ret == 0) {
        uint32_t off = 0;
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        while (ret == 0 && off < bufSz) {
            uint32_t chunk = bufSz - off;
            if (chunk > maxSz) {
                chunk = maxSz;
            }
            sent = false;
            ret  = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, key,
                                               sizeof(key), buf + off, chunk,
                                               &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_CmacUpdateResponse(ctx, cmac);
                } while (ret == WH_ERROR_NOTREADY);
            }
            off += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_CmacFinalRequest(ctx, cmac);
        }
        if (ret == 0) {
            uint32_t outSz = sizeof(tag);
            do {
                ret = wh_Client_CmacFinalResponse(ctx, cmac, tag, &outSz);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_CmacReference(key, sizeof(key), buf, bufSz, ref);
        }
        if (ret == 0 && memcmp(tag, ref, sizeof(ref)) != 0) {
            WH_ERROR_PRINT("CMAC streaming: async max chunk mismatch\n");
            ret = -1;
        }
    }

    /* Case G: rejected requests leave the state unchanged */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
    }
    if (ret == 0) {
        int rc;
        sent = true;
        rc   = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, key,
                                           sizeof(key), buf, maxSz + 1u, &sent);
        if (rc != WH_ERROR_BADARGS || sent || cmac->bufferSz != 0) {
            WH_ERROR_PRINT("CMAC streaming: oversize update not rejected\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc;
        sent = true;
        rc   = wh_Client_CmacUpdateRequest(ctx, cmac, WC_CMAC_AES, key, 20, buf,
                                           1, &sent);
        if (rc != WH_ERROR_BADARGS || sent || cmac->bufferSz != 0) {
            WH_ERROR_PRINT("CMAC streaming: bad key length not rejected\n");
            ret = -1;
        }
    }

    if (keyId != WH_KEYID_ERASED) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("CMAC STREAMING DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFSSL_AES_256 */

int whTest_Crypto_Cmac(whClientContext* ctx)
{
    int i;

    /* CMAC dispatches through the cryptocb, so run once per dispatch mode on
     * the per-client devId to cover both the normal and DMA server paths. */
    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        (void)wh_Client_SetDmaMode(ctx, i);
        WH_TEST_RETURN_ON_FAIL(
            whTest_CryptoCmacImpl(ctx, WH_CLIENT_DEVID(ctx)));
#ifdef WOLFSSL_AES_256
        WH_TEST_RETURN_ON_FAIL(
            _whTest_CryptoCmacStreaming(ctx, WH_CLIENT_DEVID(ctx)));
#endif
    }
    (void)wh_Client_SetDmaMode(ctx, 0);
    return 0;
}
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
