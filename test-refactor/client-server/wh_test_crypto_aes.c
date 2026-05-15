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
static int _whTest_CryptoAes(whClientContext* ctx)
{
    int     devId = WH_DEV_ID;
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

    /* CBC streaming via the explicit request/response API. Drives the server
     * directly with INVALID_DEVID so the cryptocb is not invoked; covers
     * wh_Client_AesCbcRequest / wh_Client_AesCbcResponse and IV chaining
     * across two halves. */
    if (ret == 0) {
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
            WH_TEST_PRINT("AES CBC ASYNC STREAMING DEVID=0x%X SUCCESS\n",
                          devId);
        }
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

int whTest_Crypto_Aes(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoAes(ctx));
    return 0;
}
#endif /* !NO_AES && (HAVE_AES_CBC || WOLFSSL_AES_COUNTER || HAVE_AES_ECB || \
          HAVE_AESGCM) */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
