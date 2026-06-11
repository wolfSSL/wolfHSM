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
 * test-refactor/client-server/wh_test_crypto_aes.c
 *
 * AES round-trips routed through the server via WH_DEV_ID. Covers CBC, CTR,
 * ECB, and GCM in both client-side-key and HSM-cached-key forms, plus the
 * AES-CBC streaming request/response API. Under a WOLFHSM_CFG_DMA build the
 * wc_Aes* calls dispatch to the *Dma wrappers via the cryptocb.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if !defined(NO_AES) &&                                                        \
    (defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_COUNTER) ||                  \
     defined(HAVE_AES_ECB) || defined(HAVE_AESGCM))
static int whTest_CryptoAesImpl(whClientContext* ctx, int devId)
{
    int     ret   = 0;
    Aes     aes[1];
    whKeyId keyId                     = WH_KEYID_ERASED;
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "AES Key Label";

    /* NIST SP 800-38A / SP 800-38B test vectors (key + 64-byte message
     * spanning four AES blocks). Deterministic vectors keep the test
     * self-contained, no RNG needed. */
    const uint8_t key[]              = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                        0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                        0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t iv[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                        0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t plainIn[64]        = {
               0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
               0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
               0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
               0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
               0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
               0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t cipher[sizeof(plainIn)];
    uint8_t plainOut[sizeof(plainIn)];

#ifdef HAVE_AES_CBC
    /* CBC with client-side key */
    if (ret == 0) {
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed wc_AesInit %d\n", ret);
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, cipher, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(aes, plainOut, cipher, sizeof(cipher));
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CBC client key failed to match\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
    }

    /* CBC with HSM-cached key */
    if (ret == 0) {
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
        }
        if (ret == 0) {
            ret = wh_Client_AesSetKeyId(aes, keyId);
        }
        if (ret == 0) {
            ret = wc_AesSetIV(aes, iv);
        }
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, cipher, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            ret = wc_AesSetIV(aes, iv);
        }
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(aes, plainOut, cipher, sizeof(plainIn));
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CBC HSM key failed to match\n");
            ret = -1;
        }
        if (keyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, keyId);
            keyId = WH_KEYID_ERASED;
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    /* CTR with client-side key */
    if (ret == 0) {
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesCtrEncrypt(aes, cipher, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesCtrEncrypt(aes, plainOut, cipher, sizeof(cipher));
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CTR client key failed to match\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
    }

    /* CTR with HSM-cached key */
    if (ret == 0) {
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
        }
        if (ret == 0) {
            ret = wh_Client_AesSetKeyId(aes, keyId);
        }
        if (ret == 0) {
            ret = wc_AesSetIV(aes, iv);
        }
        if (ret == 0) {
            ret = wc_AesCtrEncrypt(aes, cipher, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            ret = wc_AesSetIV(aes, iv);
        }
        if (ret == 0) {
            ret = wc_AesCtrEncrypt(aes, plainOut, cipher, sizeof(plainIn));
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-CTR HSM key failed to match\n");
            ret = -1;
        }
        if (keyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, keyId);
            keyId = WH_KEYID_ERASED;
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CTR DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* ECB with client-side key */
    if (ret == 0) {
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            /* AES-ECB does not use an IV */
            ret = wc_AesSetKey(aes, key, sizeof(key), NULL, AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesEcbEncrypt(aes, cipher, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            ret = wc_AesSetKey(aes, key, sizeof(key), NULL, AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesEcbDecrypt(aes, plainOut, cipher, sizeof(cipher));
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-ECB client key failed to match\n");
            ret = -1;
        }
        (void)wc_AesFree(aes);
    }

    /* ECB with HSM-cached key */
    if (ret == 0) {
        memset(cipher, 0, sizeof(cipher));
        memset(plainOut, 0, sizeof(plainOut));
        ret = wc_AesInit(aes, NULL, devId);
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                  ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
                  labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
        }
        if (ret == 0) {
            ret = wh_Client_AesSetKeyId(aes, keyId);
        }
        if (ret == 0) {
            ret = wc_AesSetIV(aes, NULL);
        }
        if (ret == 0) {
            ret = wc_AesEcbEncrypt(aes, cipher, plainIn, sizeof(plainIn));
        }
        if (ret == 0) {
            ret = wc_AesSetIV(aes, NULL);
        }
        if (ret == 0) {
            ret = wc_AesEcbDecrypt(aes, plainOut, cipher, sizeof(plainIn));
        }
        if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
            WH_ERROR_PRINT("AES-ECB HSM key failed to match\n");
            ret = -1;
        }
        if (keyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, keyId);
            keyId = WH_KEYID_ERASED;
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES ECB DEVID=0x%X SUCCESS\n", devId);
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    {
        const uint8_t authIn[16] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                                    0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
                                    0xde, 0xad, 0xbe, 0xef};
        uint8_t       authTag[16];

        /* GCM with client-side key */
        if (ret == 0) {
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
            memset(authTag, 0, sizeof(authTag));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                ret = wc_AesGcmSetKey(aes, key, sizeof(key));
            }
            if (ret == 0) {
                ret = wc_AesGcmEncrypt(aes, cipher, plainIn, sizeof(plainIn),
                                       iv, sizeof(iv), authTag, sizeof(authTag),
                                       authIn, sizeof(authIn));
            }
            if (ret == 0) {
                ret = wc_AesGcmDecrypt(aes, plainOut, cipher, sizeof(plainIn),
                                       iv, sizeof(iv), authTag, sizeof(authTag),
                                       authIn, sizeof(authIn));
            }
            if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                WH_ERROR_PRINT("AES-GCM client key failed to match\n");
                ret = -1;
            }
            (void)wc_AesFree(aes);
        }

        /* GCM with HSM-cached key */
        if (ret == 0) {
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
            memset(authTag, 0, sizeof(authTag));
            ret = wc_AesInit(aes, NULL, devId);
            if (ret == 0) {
                keyId = WH_KEYID_ERASED;
                ret   = wh_Client_KeyCache(ctx,
                                           WH_NVM_FLAGS_USAGE_ENCRYPT |
                                             WH_NVM_FLAGS_USAGE_DECRYPT,
                                           labelIn, sizeof(labelIn), key,
                                           sizeof(key), &keyId);
            }
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
            }
            if (ret == 0) {
                ret = wc_AesGcmEncrypt(aes, cipher, plainIn, sizeof(plainIn),
                                       iv, sizeof(iv), authTag, sizeof(authTag),
                                       authIn, sizeof(authIn));
            }
            if (ret == 0) {
                ret = wc_AesGcmDecrypt(aes, plainOut, cipher, sizeof(plainIn),
                                       iv, sizeof(iv), authTag, sizeof(authTag),
                                       authIn, sizeof(authIn));
            }
            if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                WH_ERROR_PRINT("AES-GCM HSM key failed to match\n");
                ret = -1;
            }
            if (keyId != WH_KEYID_ERASED) {
                (void)wh_Client_KeyEvict(ctx, keyId);
                keyId = WH_KEYID_ERASED;
            }
            (void)wc_AesFree(aes);
        }
        if (ret == 0) {
            WH_TEST_PRINT("AES GCM DEVID=0x%X SUCCESS\n", devId);
        }
    }
#endif /* HAVE_AESGCM */

    return ret;
}

#ifdef HAVE_AES_CBC
/*
 * AES-CBC streaming via the explicit request/response API. Drives the server
 * directly with INVALID_DEVID so the cryptocb is not invoked, covering
 * wh_Client_AesCbcRequest / wh_Client_AesCbcResponse and IV chaining across two
 * halves. Not devId-routed, so this runs once rather than per devId.
 */
static int whTest_CryptoAesCbcStreaming(whClientContext* ctx)
{
    int            ret = 0;
    Aes            aes[1];
    const uint8_t  key[]             = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                        0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                        0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t  iv[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                         0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                         0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t  plainIn[64]       = {
               0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
               0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
               0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
               0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
               0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
               0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t        cipher[sizeof(plainIn)];
    uint8_t        plainOut[sizeof(plainIn)];
    const uint32_t halfSize = sizeof(plainIn) / 2;
    uint32_t       outSize  = 0;

    memset(cipher, 0, sizeof(cipher));
    memset(plainOut, 0, sizeof(plainOut));

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wh_Client_AesCbcRequest(ctx, aes, 1, plainIn, halfSize);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_AesCbcResponse(ctx, aes, cipher, &outSize);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_AesCbcRequest(ctx, aes, 1, plainIn + halfSize,
                                      halfSize);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_AesCbcResponse(ctx, aes, cipher + halfSize,
                                           &outSize);
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wh_Client_AesCbcRequest(ctx, aes, 0, cipher, halfSize);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_AesCbcResponse(ctx, aes, plainOut, &outSize);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_AesCbcRequest(ctx, aes, 0, cipher + halfSize,
                                      halfSize);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_AesCbcResponse(ctx, aes, plainOut + halfSize,
                                           &outSize);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0 && memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
        WH_ERROR_PRINT("AES-CBC streaming failed to match\n");
        ret = -1;
    }
    (void)wc_AesFree(aes);
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC ASYNC STREAMING SUCCESS\n");
    }
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
/* Verifies that wh_Client_AesCtr (and wh_Client_AesCtrDma when DMA is
 * enabled) reject aes->left > AES_BLOCK_SIZE with WH_ERROR_BADARGS.
 * wc_AesCtrEncrypt indexes aes->tmp via AES_BLOCK_SIZE - aes->left; an
 * oversized value would cause an out-of-bounds read disclosing server-side
 * memory across the HSM trust boundary. */
static int whTest_CryptoAesCtrLeftOob(whClientContext* ctx)
{
    int           devId = WH_DEV_ID;
    int           ret   = 0;
    int           tmp;
    Aes           aes[1];
    uint8_t       cipher[AES_BLOCK_SIZE]  = {0};
    const uint8_t key[]                   = {0x2b, 0x7e, 0x15, 0x16,
                                              0x28, 0xae, 0xd2, 0xa6,
                                              0xab, 0xf7, 0x15, 0x88,
                                              0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t iv[AES_BLOCK_SIZE]      = {0x00, 0x01, 0x02, 0x03,
                                             0x04, 0x05, 0x06, 0x07,
                                             0x08, 0x09, 0x0a, 0x0b,
                                             0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t plainIn[AES_BLOCK_SIZE] = {0x6b, 0xc1, 0xbe, 0xe2,
                                             0x2e, 0x40, 0x9f, 0x96,
                                             0xe9, 0x3d, 0x7e, 0x11,
                                             0x73, 0x93, 0x17, 0x2a};

    ret = wc_AesInit(aes, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
    }
    else {
        ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
        }
        else {
            aes->left = AES_BLOCK_SIZE + 1;
            tmp = wh_Client_AesCtr(ctx, aes, 1, plainIn, sizeof(plainIn),
                                   cipher);
            if (tmp != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT(
                    "AES-CTR: left > AES_BLOCK_SIZE should be BADARGS, "
                    "got %d\n",
                    tmp);
                ret = -1;
            }
        }
        (void)wc_AesFree(aes);
    }

#ifdef WOLFHSM_CFG_DMA
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
            else {
                aes->left = AES_BLOCK_SIZE + 1;
                tmp = wh_Client_AesCtrDma(ctx, aes, 1, plainIn,
                                          sizeof(plainIn), cipher);
                if (tmp != WH_ERROR_BADARGS) {
                    WH_ERROR_PRINT(
                        "AES-CTR DMA: left > AES_BLOCK_SIZE should be "
                        "BADARGS, got %d\n",
                        tmp);
                    ret = -1;
                }
            }
            (void)wc_AesFree(aes);
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    if (ret == 0) {
        WH_TEST_PRINT("AES CTR left OOB DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

int whTest_CryptoAesKeyUsagePolicies(whClientContext* ctx)
{
    int      ret        = 0;
    WC_RNG   rng[1];
    uint8_t  plaintext[AES_BLOCK_SIZE]  = {0};
    uint8_t  ciphertext[AES_BLOCK_SIZE] = {0};
    uint8_t  key[32]                    = {0};
    uint32_t keyLen                     = sizeof(key);
    whKeyId  keyId                      = WH_KEYID_ERASED;

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_RNG_GenerateBlock(rng, plaintext, sizeof(plaintext));
    if (ret == 0)
        ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate random data: %d\n", ret);
        goto done;
    }

#ifdef WOLFSSL_AES_COUNTER
    /* AES-CTR: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t ctrCipher[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"ctr-no-enc", strlen("ctr-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0)
                    ret = wc_AesSetIV(aes, iv);
                if (ret == 0) {
                    ret = wh_Client_AesCtr(ctx, aes, 1, plaintext,
                                           sizeof(plaintext), ctrCipher);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-CTR enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-CTR: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE]       = {0};
        uint8_t ctrOut[AES_BLOCK_SIZE]   = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"ctr-no-dec", strlen("ctr-no-dec"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0)
                    ret = wc_AesSetIV(aes, iv);
                if (ret == 0) {
                    ret = wh_Client_AesCtr(ctx, aes, 0, ciphertext,
                                           sizeof(ciphertext), ctrOut);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-CTR dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* AES-ECB: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t ecbCipher[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"ecb-no-enc", strlen("ecb-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesEcbEncrypt(aes, ecbCipher, plaintext,
                                           sizeof(plaintext));
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-ECB enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-ECB: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t ecbOut[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"ecb-no-dec", strlen("ecb-no-dec"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesEcbDecrypt(aes, ecbOut, ciphertext,
                                           sizeof(ciphertext));
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-ECB dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AESGCM
    /* AES-GCM: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t gcmIv[12]              = {0};
        uint8_t gcmCipher[AES_BLOCK_SIZE] = {0};
        uint8_t gcmTag[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"gcm-no-enc", strlen("gcm-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesGcmEncrypt(aes, gcmCipher, plaintext,
                                           sizeof(plaintext), gcmIv,
                                           sizeof(gcmIv), gcmTag, sizeof(gcmTag),
                                           NULL, 0);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-GCM enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-GCM: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t gcmIv[12]            = {0};
        uint8_t gcmOut[AES_BLOCK_SIZE] = {0};
        uint8_t gcmTag[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"gcm-no-dec", strlen("gcm-no-dec"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesGcmDecrypt(aes, gcmOut, ciphertext,
                                           sizeof(ciphertext), gcmIv,
                                           sizeof(gcmIv), gcmTag, sizeof(gcmTag),
                                           NULL, 0);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-GCM dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* HAVE_AESGCM */

#ifdef WOLFHSM_CFG_DMA
#ifdef WOLFSSL_AES_COUNTER
    /* AES-CTR DMA: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE]        = {0};
        uint8_t ctrCipher[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"dctr-no-enc",
                                   strlen("dctr-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0)
                    ret = wc_AesSetIV(aes, iv);
                if (ret == 0) {
                    ret = wh_Client_AesCtrDma(ctx, aes, 1, plaintext,
                                              sizeof(plaintext), ctrCipher);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-CTR DMA enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-CTR DMA: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE]      = {0};
        uint8_t ctrOut[AES_BLOCK_SIZE]  = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"dctr-no-dec",
                                   strlen("dctr-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0)
                    ret = wc_AesSetIV(aes, iv);
                if (ret == 0) {
                    ret = wh_Client_AesCtrDma(ctx, aes, 0, ciphertext,
                                              sizeof(ciphertext), ctrOut);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-CTR DMA dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
    /* AES-ECB DMA: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t ecbCipher[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"decb-no-enc",
                                   strlen("decb-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesEcbDma(ctx, aes, 1, plaintext,
                                              sizeof(plaintext), ecbCipher);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-ECB DMA enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-ECB DMA: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t ecbOut[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"decb-no-dec",
                                   strlen("decb-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesEcbDma(ctx, aes, 0, ciphertext,
                                              sizeof(ciphertext), ecbOut);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-ECB DMA dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
    /* AES-CBC DMA: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE]        = {0};
        uint8_t cbcCipher[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"dcbc-no-enc",
                                   strlen("dcbc-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0)
                    ret = wc_AesSetIV(aes, iv);
                if (ret == 0) {
                    ret = wh_Client_AesCbcDma(ctx, aes, 1, plaintext,
                                              sizeof(plaintext), cbcCipher);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-CBC DMA enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-CBC DMA: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE]     = {0};
        uint8_t cbcOut[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"dcbc-no-dec",
                                   strlen("dcbc-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0)
                    ret = wc_AesSetIV(aes, iv);
                if (ret == 0) {
                    ret = wh_Client_AesCbcDma(ctx, aes, 0, ciphertext,
                                              sizeof(ciphertext), cbcOut);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-CBC DMA dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
    /* AES-GCM DMA: encrypt without ENCRYPT flag */
    {
        Aes     aes[1];
        uint8_t gcmIv[12]                 = {0};
        uint8_t gcmCipher[AES_BLOCK_SIZE] = {0};
        uint8_t gcmTag[AES_BLOCK_SIZE]    = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"dgcm-no-enc",
                                   strlen("dgcm-no-enc"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesGcmDma(ctx, aes, 1, plaintext,
                                              sizeof(plaintext), gcmIv,
                                              sizeof(gcmIv), NULL, 0,
                                              NULL, gcmTag, sizeof(gcmTag),
                                              gcmCipher);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-GCM DMA enc without ENCRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }

    /* AES-GCM DMA: decrypt without DECRYPT flag */
    {
        Aes     aes[1];
        uint8_t gcmIv[12]              = {0};
        uint8_t gcmOut[AES_BLOCK_SIZE] = {0};
        uint8_t gcmTag[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"dgcm-no-dec",
                                   strlen("dgcm-no-dec"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wh_Client_AesGcmDma(ctx, aes, 0, ciphertext,
                                              sizeof(ciphertext), gcmIv,
                                              sizeof(gcmIv), NULL, 0,
                                              gcmTag, NULL, sizeof(gcmTag),
                                              gcmOut);
                    if (ret == WH_ERROR_USAGE)
                        ret = 0;
                    else {
                        WH_ERROR_PRINT(
                            "AES-GCM DMA dec without DECRYPT flag: expected "
                            "WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(ctx, keyId);
        }
    }
    if (ret != 0) {
        goto done;
    }
#endif /* HAVE_AESGCM */
#endif /* WOLFHSM_CFG_DMA */

done:
    wc_FreeRng(rng);
    if (ret == 0) {
        WH_TEST_PRINT("AES key usage policies DEVID=0x%X SUCCESS\n", WH_DEV_ID);
    }
    return ret;
}

int whTest_Crypto_Aes(whClientContext* ctx)
{
    /* AES round-trips dispatch through the cryptocb, so run on every devId to
     * cover both the normal and DMA server transports. */
    WH_TEST_FOREACH_DEVID(whTest_CryptoAesImpl(ctx, devId));
#ifdef HAVE_AES_CBC
    /* CBC streaming drives the request/response API directly (INVALID_DEVID),
     * so it is not devId-routed -- run it once. */
    WH_TEST_RETURN_ON_FAIL(whTest_CryptoAesCbcStreaming(ctx));
#endif
#ifdef WOLFSSL_AES_COUNTER
    WH_TEST_RETURN_ON_FAIL(whTest_CryptoAesCtrLeftOob(ctx));
#endif
    /* TODO: port legacy AES async + DMA-async coverage (comm-buffer & DMA, round-trip & KAT) -- the only remaining legacy crypto parity gap; deferred to follow-up PR. */
    return 0;
}
#endif /* !NO_AES && (HAVE_AES_CBC || WOLFSSL_AES_COUNTER || HAVE_AES_ECB || \
          HAVE_AESGCM) */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
