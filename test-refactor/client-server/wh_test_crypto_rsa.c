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
 * RSA encrypt/decrypt round-trips routed through the server via the
 * per-client devId (WH_CLIENT_DEVID):
 * ephemeral key, server-exported key, and server-cached key paths.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"
#if !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048)
/* Fixed RSA key for the cached-key test */
#include "wolfssl/certs_test.h"
#endif

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

#ifdef WOLFSSL_KEY_GEN
static int _whTest_CryptoRsa(whClientContext* ctx)
{
    int     devId = WH_CLIENT_DEVID(ctx);
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
        ret = wc_InitRsaKey_ex(rsa, NULL, WH_CLIENT_DEVID(ctx));
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
            ret = wc_InitRsaKey_ex(rsa, NULL, WH_CLIENT_DEVID(ctx));
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
    int      devId = WH_CLIENT_DEVID(ctx);
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

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches a separate wh_Client_RsaExportPublicKey
 * and that it round-trips against the cached private key. */
static int _whTest_CryptoRsaCacheKeyAndExportPublic(whClientContext* ctx)
{
    int      devId = WH_CLIENT_DEVID(ctx);
    int      ret   = WH_ERROR_OK;
    WC_RNG   rng[1];
    RsaKey   genPub[1];
    RsaKey   refPub[1] = {0};
    char     plainText[sizeof(WH_TEST_RSA_PLAINTEXT)] = WH_TEST_RSA_PLAINTEXT;
    char     cipherText[RSA_KEY_BYTES];
    char     finalText[RSA_KEY_BYTES];
    whKeyId  keyId    = WH_KEYID_ERASED;
    byte     genDer[2048];
    byte     refDer[2048];
    int      genDerSz = 0;
    int      refDerSz = 0;
    int      encLen   = 0;
    int      decLen;

    memset(cipherText, 0, sizeof(cipherText));
    memset(finalText, 0, sizeof(finalText));

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_InitRsaKey_ex(genPub, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wh_Client_RsaMakeCacheKeyAndExportPublic(
        ctx, RSA_KEY_BITS, RSA_EXPONENT, &keyId,
        WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 0, NULL,
        genPub);
    if (ret != 0) {
        WH_ERROR_PRINT("RsaMakeCacheKeyAndExportPublic failed %d\n", ret);
    }

    /* Cross-check against a separate public export of the same keyId. */
    if (ret == 0) {
        ret = wc_InitRsaKey_ex(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_RsaExportPublicKey(ctx, keyId, refPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_RsaExportPublicKey failed %d\n", ret);
            }
            else {
                genDerSz =
                    wc_RsaKeyToPublicDer(genPub, genDer, sizeof(genDer));
                refDerSz =
                    wc_RsaKeyToPublicDer(refPub, refDer, sizeof(refDer));
                if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
                    (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
                    WH_ERROR_PRINT("keygen pubkey mismatch vs export\n");
                    ret = -1;
                }
            }
        }
    }

    /* Encrypt locally with the independently exported public key (refPub) the
     * client holds. */
    if (ret == 0) {
        encLen = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                                     (byte*)cipherText, sizeof(cipherText),
                                     refPub, rng);
        if (encLen < 0) {
            WH_ERROR_PRINT("PublicEncrypt with keygen pub failed %d\n", encLen);
            ret = encLen;
        }
    }

    /* Decrypt on the HSM using genPub directly as the HSM private-key handle
     * (no separate key object). */
    if (ret == 0) {
        decLen = wc_RsaPrivateDecrypt((byte*)cipherText, encLen,
                                      (byte*)finalText, sizeof(finalText),
                                      genPub);
        if (decLen < 0) {
            WH_ERROR_PRINT("HSM PrivateDecrypt failed %d\n", decLen);
            ret = decLen;
        }
        else if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
            WH_ERROR_PRINT("RSA keygen-pub round-trip mismatch\n");
            ret = -1;
        }
    }

    (void)wc_FreeRsaKey(refPub);
    (void)wc_FreeRsaKey(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("RSA CACHE-AND-EXPORT-PUBLIC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Exercises wh_Client_RsaFunction with an undersized output buffer. */
static int _whTest_CryptoRsaBufferTooSmall(whClientContext* ctx)
{
    const int  devId         = WH_CLIENT_DEVID(ctx);
    const int  rsa_key_bits  = 2048;
    const int  rsa_key_bytes = rsa_key_bits / 8;
    int        ret;
    RsaKey     rsa[1];
    const byte plain[]                              = "rsa buf size test";
    uint8_t    small_out[16]                        = {0};
    uint8_t    full_out[256 /* RSA-2048 modulus */] = {0};
    uint16_t   out_len;

    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_RsaMakeExportKey(ctx, rsa_key_bits, WC_RSA_EXPONENT, rsa);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_RsaMakeExportKey %d\n", ret);
        goto done;
    }

    out_len = (uint16_t)sizeof(small_out);
    ret     = wh_Client_RsaFunction(ctx, rsa, RSA_PUBLIC_ENCRYPT, plain,
                                    (uint16_t)sizeof(plain), small_out,
                                    &out_len);
    /* Server's wc_RsaFunction pre-checks the buffer and returns
       RSA_BUFFER_E. */
    if (ret != WH_ERROR_BUFFER_SIZE && ret != RSA_BUFFER_E) {
        WH_ERROR_PRINT(
            "RsaFunction small buf expected WH_ERROR_BUFFER_SIZE or "
            "RSA_BUFFER_E, got %d\n",
            ret);
        ret = WH_TEST_FAIL;
        goto done;
    }

    out_len = (uint16_t)sizeof(full_out);
    ret     = wh_Client_RsaFunction(ctx, rsa, RSA_PUBLIC_ENCRYPT, plain,
                                    (uint16_t)sizeof(plain), full_out,
                                    &out_len);
    if (ret != 0) {
        WH_ERROR_PRINT("RsaFunction full buf failed: %d\n", ret);
        goto done;
    }
    if (out_len != (uint16_t)rsa_key_bytes) {
        WH_ERROR_PRINT("RsaFunction full buf size %u, expected %d\n",
                       (unsigned)out_len, rsa_key_bytes);
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("RSA buffer-size DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    (void)wc_FreeRsaKey(rsa);
    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

#ifdef USE_CERT_BUFFERS_2048
/* RSA with a fixed key cached on the server. Needs no RSA keygen or DER export,
 * so it also runs without WOLFSSL_KEY_GEN */
static int _whTest_CryptoRsaCachedKey(whClientContext* ctx)
{
    int      devId = WH_CLIENT_DEVID(ctx);
    int      ret   = WH_ERROR_OK;
    WC_RNG   rng[1];
    RsaKey   rsa[1];
    int      rsaInit                            = 0;
    whKeyId  keyId                              = WH_KEYID_ERASED;
    uint8_t  label[]                            = "RsaCachedKey";
    char     msg[sizeof(WH_TEST_RSA_PLAINTEXT)] = WH_TEST_RSA_PLAINTEXT;
    byte     sig[RSA_KEY_BYTES];
    byte     out[RSA_KEY_BYTES];
    int      sigLen  = 0;
    int      outLen  = 0;
    int      sizeRet = 0;
    int      size    = 0;
    word32   idx     = 0;
    byte     pubDer[512];
    uint16_t pubDerLen = sizeof(pubDer);
    int      exportRet = 0;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyCache(
        ctx, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, label,
        sizeof(label), client_key_der_2048, sizeof_client_key_der_2048, &keyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to cache RSA key %d\n", ret);
    }

    /* Sign and verify by key ID */
    if (ret == WH_ERROR_OK) {
        ret = wc_InitRsaKey_ex(rsa, NULL, devId);
        if (ret == 0) {
            rsaInit = 1;
            ret     = wh_Client_RsaSetKeyId(rsa, keyId);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to set up RSA key %d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        sigLen =
            wc_RsaSSL_Sign((byte*)msg, sizeof(msg), sig, sizeof(sig), rsa, rng);
        if (sigLen != (int)sizeof(sig)) {
            WH_ERROR_PRINT("Failed to sign by key ID %d\n", sigLen);
            ret = -1;
        }
    }
    if (ret == WH_ERROR_OK) {
        outLen = wc_RsaSSL_Verify(sig, sigLen, out, sizeof(out), rsa);
        if ((outLen != (int)sizeof(msg)) ||
            (memcmp(msg, out, sizeof(msg)) != 0)) {
            WH_ERROR_PRINT("Failed to verify by key ID %d\n", outLen);
            ret = -1;
        }
    }
    if (rsaInit != 0) {
        (void)wc_FreeRsaKey(rsa);
        rsaInit = 0;
    }

    /* Export the public key, then evict the cached key so the local key
     * import below doesn't need a second cache slot */
    if (ret == WH_ERROR_OK) {
        exportRet = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_RSA, NULL,
                                              0, pubDer, &pubDerLen);
        ret       = wh_Client_KeyEvict(ctx, keyId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to evict RSA key %d\n", ret);
        }
        keyId = WH_KEYID_ERASED;
    }

    /* A local key with the HSM devId is sent to the server as DER, and public
     * key export builds DER on the server. Both need WOLFSSL_KEY_TO_DER and
     * return WH_ERROR_NOTIMPL without it. */
    if (ret == WH_ERROR_OK) {
        ret = wc_InitRsaKey_ex(rsa, NULL, devId);
        if (ret == 0) {
            rsaInit = 1;
            ret     = wc_RsaPublicKeyDecode(client_keypub_der_2048, &idx, rsa,
                                            sizeof_client_keypub_der_2048);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to load local RSA key %d\n", ret);
        }
    }
    if (ret == WH_ERROR_OK) {
        memset(out, 0, sizeof(out));
        outLen  = wc_RsaSSL_Verify(sig, sigLen, out, sizeof(out), rsa);
        sizeRet = wh_Client_RsaGetSize(ctx, rsa, &size);
#ifdef WOLFSSL_KEY_TO_DER
        if ((outLen != (int)sizeof(msg)) ||
            (memcmp(msg, out, sizeof(msg)) != 0) || (sizeRet != WH_ERROR_OK) ||
            (size != (int)sizeof(sig)) || (exportRet != WH_ERROR_OK)) {
            ret = -1;
        }
#else
        if ((outLen != WH_ERROR_NOTIMPL) || (sizeRet != WH_ERROR_NOTIMPL) ||
            (exportRet != WH_ERROR_NOTIMPL)) {
            ret = -1;
        }
#endif /* WOLFSSL_KEY_TO_DER */
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Verify %d, get size %d, export public key %d\n",
                           outLen, sizeRet, exportRet);
        }
    }
    if (rsaInit != 0) {
        (void)wc_FreeRsaKey(rsa);
    }
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("RSA CACHED-KEY DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* USE_CERT_BUFFERS_2048 */

int whTest_Crypto_Rsa(whClientContext* ctx)
{
#ifdef WOLFSSL_KEY_GEN
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsa(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsaExportPublicKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsaCacheKeyAndExportPublic(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsaBufferTooSmall(ctx));
#endif
#ifdef USE_CERT_BUFFERS_2048
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRsaCachedKey(ctx));
#endif
    (void)ctx;
    return 0;
}

#endif /* !NO_RSA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
