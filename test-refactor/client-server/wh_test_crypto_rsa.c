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
 * test-refactor/client-server/wh_test_crypto_rsa.c
 *
 * RSA encrypt/decrypt round-trips routed through the server via WH_DEV_ID:
 * ephemeral key, server-exported key, and server-cached key paths.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifndef NO_RSA

#define RSA_KEY_BITS  2048
#define RSA_KEY_BYTES (RSA_KEY_BITS / 8)
#define RSA_EXPONENT  WC_RSA_EXPONENT
#define WH_TEST_RSA_PLAINTEXT "mytextisbigplain"

static int _whTest_CryptoRsa(whClientContext* ctx)
{
    int     devId = WH_DEV_ID;
    int     ret   = WH_ERROR_OK;
    WC_RNG  rng[1];
    RsaKey  rsa[1];
    char    plainText[sizeof(WH_TEST_RSA_PLAINTEXT)] = WH_TEST_RSA_PLAINTEXT;
    char    cipherText[RSA_KEY_BYTES];
    char    finalText[RSA_KEY_BYTES];
    whKeyId keyId = WH_KEYID_ERASED;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    /* Using ephemeral key */
    memset(cipherText, 0, sizeof(cipherText));
    memset(finalText, 0, sizeof(finalText));
    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
    }
    else {
        ret = wc_MakeRsaKey(rsa, RSA_KEY_BITS, RSA_EXPONENT, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_MakeRsaKey %d\n", ret);
        }
        else {
            ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                                      (byte*)cipherText, sizeof(cipherText),
                                      rsa, rng);
            if (ret < 0) {
                WH_ERROR_PRINT("Failed to wc_RsaPublicEncrypt %d\n", ret);
            }
            else {
                ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret,
                                           (byte*)finalText, sizeof(finalText),
                                           rsa);
                if (ret < 0) {
                    WH_ERROR_PRINT("Failed to wc_RsaPrivateDecrypt %d\n", ret);
                }
                else {
                    ret = 0;
                    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                        WH_ERROR_PRINT("Failed to match\n");
                        ret = -1;
                    }
                }
            }
        }
        (void)wc_FreeRsaKey(rsa);
    }

    if (ret == 0) {
        /* Using client export key */
        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
        }
        else {
            ret = wh_Client_RsaMakeExportKey(ctx, RSA_KEY_BITS, RSA_EXPONENT,
                                             rsa);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
            }
            else {
                ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                                          (byte*)cipherText, sizeof(cipherText),
                                          rsa, rng);
                if (ret < 0) {
                    WH_ERROR_PRINT("Failed to encrypt %d\n", ret);
                }
                else {
                    ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret,
                                               (byte*)finalText,
                                               sizeof(finalText), rsa);
                    if (ret < 0) {
                        WH_ERROR_PRINT("Failed to decrypt %d\n", ret);
                    }
                    else {
                        ret = 0;
                        if (memcmp(plainText, finalText, sizeof(plainText)) !=
                            0) {
                            WH_ERROR_PRINT("Failed to match\n");
                            ret = -1;
                        }
                    }
                }
            }
            (void)wc_FreeRsaKey(rsa);
        }
    }

    if (ret == 0) {
        /* Using keyCache key */
        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        ret = wh_Client_RsaMakeCacheKey(
            ctx, RSA_KEY_BITS, RSA_EXPONENT, &keyId,
            WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
        }
        else {
            ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
            }
            else {
                ret = wh_Client_RsaSetKeyId(rsa, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
                }
                else {
                    ret = wh_Client_RsaGetKeyId(rsa, &keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_GetKeyIdRsa %d\n", ret);
                    }
                    else {
                        ret = wc_RsaPublicEncrypt(
                            (byte*)plainText, sizeof(plainText),
                            (byte*)cipherText, sizeof(cipherText), rsa, rng);
                        if (ret < 0) {
                            WH_ERROR_PRINT("Failed to encrypt %d\n", ret);
                        }
                        else {
                            ret = wc_RsaPrivateDecrypt(
                                (byte*)cipherText, ret, (byte*)finalText,
                                sizeof(finalText), rsa);
                            if (ret < 0) {
                                WH_ERROR_PRINT("Failed to decrypt %d\n", ret);
                            }
                            else {
                                ret = 0;
                                if (memcmp(plainText, finalText,
                                           sizeof(plainText)) != 0) {
                                    WH_ERROR_PRINT("Failed to match\n");
                                    ret = -1;
                                }
                            }
                        }
                    }
                }
                (void)wc_FreeRsaKey(rsa);
            }
        }
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("RSA DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Cache a NONEXPORTABLE RSA keypair, export only the public half via
 * wh_Client_RsaExportPublicKey, then encrypt client-side with the exported
 * pub and decrypt server-side using the cached private. A successful round
 * trip proves the exported public key matches the cached private. */
static int _whTest_CryptoRsaExportPublicKey(whClientContext* ctx)
{
    int      devId = WH_DEV_ID;
    int      ret   = WH_ERROR_OK;
    WC_RNG   rng[1];
    RsaKey   rsaPub[1];
    RsaKey   rsaFull[1];
    char     plainText[sizeof(WH_TEST_RSA_PLAINTEXT)] = WH_TEST_RSA_PLAINTEXT;
    char     cipherText[RSA_KEY_BYTES];
    char     finalText[RSA_KEY_BYTES];
    whKeyId  keyId      = WH_KEYID_ERASED;
    uint8_t  denyBuf[2048];
    uint16_t denyLen    = sizeof(denyBuf);
    int      encLen;
    int      decLen;

    memset(cipherText, 0, sizeof(cipherText));
    memset(finalText, 0, sizeof(finalText));

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_RsaMakeCacheKey(
        ctx, RSA_KEY_BITS, RSA_EXPONENT, &keyId,
        WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT |
            WH_NVM_FLAGS_NONEXPORTABLE,
        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to make NONEXPORTABLE cached RSA key %d\n", ret);
    }

    /* Full export must be denied by the NONEXPORTABLE policy. */
    if (ret == 0) {
        int denyRet =
            wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf, &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE RSA full export was not denied: %d\n", denyRet);
            ret = -1;
        }
    }

    /* Public-only export must succeed and yield a usable public key. */
    if (ret == 0) {
        ret = wc_InitRsaKey_ex(rsaPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_RsaExportPublicKey(ctx, keyId, rsaPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_RsaExportPublicKey failed %d\n", ret);
            }
            else if (rsaPub->type != RSA_PUBLIC) {
                WH_ERROR_PRINT(
                    "Exported RSA key is not public-only (type=%d)\n",
                    rsaPub->type);
                ret = -1;
            }
            else {
                encLen = wc_RsaPublicEncrypt(
                    (byte*)plainText, sizeof(plainText), (byte*)cipherText,
                    sizeof(cipherText), rsaPub, rng);
                if (encLen < 0) {
                    WH_ERROR_PRINT("PublicEncrypt with exported pub failed %d\n",
                                   encLen);
                    ret = encLen;
                }
            }
            (void)wc_FreeRsaKey(rsaPub);
        }
    }

    /* Server-side decrypt with the cached private completes the round-trip. */
    if (ret == 0) {
        ret = wc_InitRsaKey_ex(rsaFull, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_RsaSetKeyId(rsaFull, keyId);
        }
        if (ret == 0) {
            decLen = wc_RsaPrivateDecrypt((byte*)cipherText, encLen,
                                          (byte*)finalText, sizeof(finalText),
                                          rsaFull);
            if (decLen < 0) {
                WH_ERROR_PRINT("HSM PrivateDecrypt failed %d\n", decLen);
                ret = decLen;
            }
            else if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                WH_ERROR_PRINT("RSA round-trip plaintext mismatch\n");
                ret = -1;
            }
        }
        (void)wc_FreeRsaKey(rsaFull);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("RSA EXPORT-PUBLIC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

int whTest_Crypto_Rsa(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsa(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsaExportPublicKey(ctx));
    return 0;
}

#endif /* !NO_RSA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
