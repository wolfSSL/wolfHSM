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
 * test-refactor/client-server/wh_test_crypto_wcid.c
 *
 * Server-cached keys bound through wolfCrypt's init-by-id calls
 * (wc_AesInit_Id, wc_InitCmac_Id, wc_ecc_init_id, wc_InitRsaKey_Id,
 * wc_MlDsaKey_InitId) instead of wh_Client_*SetKeyId.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/rsa.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLF_PRIVATE_KEY_ID

#if !defined(NO_AES) && \
    (defined(HAVE_AES_CBC) || \
     (defined(WOLFSSL_CMAC) && defined(WOLFSSL_AES_DIRECT)))
static const uint8_t wcIdKeyA[AES_128_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t wcIdKeyB[AES_128_KEY_SIZE] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81};
#endif
static const uint8_t wcIdMsg[32] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
    0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
    0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
static int _whTest_WcIdAesCbc(Aes* aes, const uint8_t* key, uint8_t* out)
{
    const uint8_t iv[AES_BLOCK_SIZE] = {0};
    int           ret                = 0;

    if (key != NULL) {
        ret = wc_AesSetKey(aes, key, AES_128_KEY_SIZE, iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesSetIV(aes, iv);
    }
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(aes, out, wcIdMsg, sizeof(wcIdMsg));
    }
    return ret;
}

/* One AES-CBC case on a key bound through the id slot */
static int _whTest_WcIdAesCase(int devId, whKeyId slotId, int slotLen,
                               int doSetKeyId, whKeyId setId,
                               const uint8_t* key, const uint8_t* expect,
                               const char* what)
{
    Aes     aes[1];
    uint8_t out[sizeof(wcIdMsg)];
    int     ret;

    ret = wc_AesInit_Id(aes, (unsigned char*)&slotId, slotLen, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    if (doSetKeyId) {
        ret = wh_Client_AesSetKeyId(aes, setId);
    }
    if (ret == 0) {
        ret = _whTest_WcIdAesCbc(aes, key, out);
    }
    if (ret == 0 && memcmp(out, expect, sizeof(out)) != 0) {
        WH_ERROR_PRINT("AES id slot: %s\n", what);
        ret = -1;
    }
    wc_AesFree(aes);
    return ret;
}

static int _whTest_CryptoWcIdAes(whClientContext* ctx, int devId)
{
    int     ret                     = 0;
    Aes     aes[1];
    whKeyId idA                     = WH_KEYID_ERASED;
    whKeyId idB                     = WH_KEYID_ERASED;
    whKeyId idGlobal                = WH_KEYID_CLIENT_GLOBAL_FLAG;
    uint8_t label[WH_NVM_LABEL_LEN] = "WcId AES";
    uint8_t swA[sizeof(wcIdMsg)];
    uint8_t swB[sizeof(wcIdMsg)];

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = _whTest_WcIdAesCbc(aes, wcIdKeyA, swA);
    if (ret == 0) {
        ret = _whTest_WcIdAesCbc(aes, wcIdKeyB, swB);
    }
    wc_AesFree(aes);

    if (ret == 0) {
        ret = wh_Client_KeyCache(
            ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, label,
            sizeof(label), wcIdKeyA, sizeof(wcIdKeyA), &idA);
    }
    if (ret == 0) {
        ret = wh_Client_KeyCache(
            ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, label,
            sizeof(label), wcIdKeyB, sizeof(wcIdKeyB), &idB);
    }

    if (ret == 0) {
        ret = _whTest_WcIdAesCase(devId, idA, sizeof(idA), 0, 0, NULL, swA,
                                  "did not select the cached key");
    }
    if (ret == 0) {
        ret = _whTest_WcIdAesCase(devId, idA, sizeof(idA), 0, 0, wcIdKeyB, swA,
                                  "key bytes outranked the bound id");
    }
    if (ret == 0) {
        ret = _whTest_WcIdAesCase(devId, idA, sizeof(idA), 1, idB, NULL, swB,
                                  "SetKeyId did not override it");
    }
    if (ret == 0) {
        ret = _whTest_WcIdAesCase(devId, idA, sizeof(idA), 1, WH_KEYID_ERASED,
                                  wcIdKeyB, swB,
                                  "SetKeyId(ERASED) did not clear it");
    }
    if (ret == 0) {
        ret = _whTest_WcIdAesCase(devId, idA, 1, 0, 0, wcIdKeyB, swB,
                                  "short id was not ignored");
    }
    if (ret == 0) {
        ret = _whTest_WcIdAesCase(devId, idGlobal, sizeof(idGlobal), 0, 0,
                                  wcIdKeyB, swB, "erased id was not ignored");
    }

    if (!WH_KEYID_ISERASED(idA)) {
        (void)wh_Client_KeyEvict(ctx, idA);
    }
    if (!WH_KEYID_ISERASED(idB)) {
        (void)wh_Client_KeyEvict(ctx, idB);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES wolfCrypt id slot SUCCESS\n");
    }
    return ret;
}
#endif /* !NO_AES && HAVE_AES_CBC */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
/* One two-update CMAC case on a key bound through the id slot */
static int _whTest_WcIdCmacCase(int devId, whKeyId id, const uint8_t* key,
                                const uint8_t* expect, const char* what)
{
    Cmac    cmac[1];
    uint8_t tag[AES_BLOCK_SIZE];
    word32  tagSz = sizeof(tag);
    int     ret;

    ret = wc_InitCmac_Id(cmac, key, (key != NULL) ? AES_128_KEY_SIZE : 0,
                         WC_CMAC_AES, NULL, (unsigned char*)&id, sizeof(id),
                         NULL, devId);
    if (ret != 0) {
        return ret;
    }
    ret = wc_CmacUpdate(cmac, wcIdMsg, 7);
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, wcIdMsg + 7, sizeof(wcIdMsg) - 7);
    }
    if (ret == 0) {
        ret = wc_CmacFinal(cmac, tag, &tagSz);
    }
    if (ret == 0 && memcmp(tag, expect, sizeof(tag)) != 0) {
        WH_ERROR_PRINT("CMAC id slot: %s\n", what);
        ret = -1;
    }
    (void)wc_CmacFree(cmac);
    return ret;
}

static uint8_t wcIdBigMsg[WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_GENERATE_SZ + 1];

/* Keyed one-shot too large to inline, on a cmac bound to id or left unset */
static int _whTest_WcIdCmacBigOneshot(int devId, whKeyId id,
                                      const uint8_t* expect, const char* what)
{
    Cmac    cmac[1];
    uint8_t tag[AES_BLOCK_SIZE];
    word32  tagSz = sizeof(tag);
    int     ret   = 0;

    memset(cmac, 0xA5, sizeof(cmac));
    if (!WH_KEYID_ISERASED(id)) {
        ret = wc_InitCmac_Id(cmac, NULL, 0, WC_CMAC_AES, NULL,
                             (unsigned char*)&id, sizeof(id), NULL, devId);
    }
    if (ret == 0) {
        ret = wc_AesCmacGenerate_ex(cmac, tag, &tagSz, wcIdBigMsg,
                                    sizeof(wcIdBigMsg), wcIdKeyB,
                                    sizeof(wcIdKeyB), NULL, devId);
    }
    if (ret == 0 && memcmp(tag, expect, sizeof(tag)) != 0) {
        WH_ERROR_PRINT("CMAC id slot: %s\n", what);
        ret = -1;
    }
    if (!WH_KEYID_ISERASED(id)) {
        (void)wc_CmacFree(cmac);
    }
    return ret;
}

static int _whTest_CryptoWcIdCmac(whClientContext* ctx, int devId)
{
    int     ret                     = 0;
    Cmac    cmac[1];
    whKeyId idA                     = WH_KEYID_ERASED;
    uint8_t label[WH_NVM_LABEL_LEN] = "WcId CMAC";
    uint8_t swA[AES_BLOCK_SIZE];
    uint8_t swB[AES_BLOCK_SIZE];
    uint8_t swBigB[AES_BLOCK_SIZE];
    uint8_t tag[AES_BLOCK_SIZE];
    word32  tagSz                   = sizeof(swA);

    memset(wcIdBigMsg, 0x3C, sizeof(wcIdBigMsg));
    ret = wc_AesCmacGenerate_ex(cmac, swA, &tagSz, wcIdMsg, sizeof(wcIdMsg),
                                wcIdKeyA, sizeof(wcIdKeyA), NULL,
                                INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesCmacGenerate_ex(cmac, swB, &tagSz, wcIdMsg,
                                    sizeof(wcIdMsg), wcIdKeyB,
                                    sizeof(wcIdKeyB), NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_AesCmacGenerate_ex(cmac, swBigB, &tagSz, wcIdBigMsg,
                                    sizeof(wcIdBigMsg), wcIdKeyB,
                                    sizeof(wcIdKeyB), NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_SIGN, label,
                                 sizeof(label), wcIdKeyA, sizeof(wcIdKeyA),
                                 &idA);
    }
    if (ret == 0) {
        ret = _whTest_WcIdCmacCase(devId, idA, NULL, swA,
                                   "did not select the cached key");
    }
    if (ret == 0) {
        ret = _whTest_WcIdCmacCase(devId, idA, wcIdKeyB, swA,
                                   "key bytes outranked the bound id");
    }
    if (ret == 0) {
        ret = wc_InitCmac_Id(cmac, NULL, 0, WC_CMAC_AES, NULL,
                             (unsigned char*)&idA, sizeof(idA), NULL, devId);
        if (ret == 0) {
            tagSz = sizeof(tag);
            ret   = wc_AesCmacGenerate_ex(cmac, tag, &tagSz, wcIdMsg,
                                          sizeof(wcIdMsg), wcIdKeyB,
                                          sizeof(wcIdKeyB), NULL, devId);
            if (ret == 0 && memcmp(tag, swB, sizeof(tag)) != 0) {
                WH_ERROR_PRINT("CMAC id slot: one-shot key lost to the "
                               "bound id\n");
                ret = -1;
            }
            (void)wc_CmacFree(cmac);
        }
    }
    if (ret == 0) {
        memset(cmac, 0xA5, sizeof(cmac));
        tagSz = sizeof(tag);
        ret   = wc_AesCmacGenerate_ex(cmac, tag, &tagSz, wcIdMsg,
                                      sizeof(wcIdMsg), wcIdKeyB,
                                      sizeof(wcIdKeyB), NULL, devId);
        if (ret == 0 && memcmp(tag, swB, sizeof(tag)) != 0) {
            WH_ERROR_PRINT("CMAC id slot: one-shot read an uninitialized "
                           "cmac\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = _whTest_WcIdCmacBigOneshot(devId, idA, swBigB,
                                         "large one-shot key lost to the "
                                         "bound id");
    }
    if (ret == 0) {
        ret = _whTest_WcIdCmacBigOneshot(devId, WH_KEYID_ERASED, swBigB,
                                         "large one-shot read an "
                                         "uninitialized cmac");
    }

    if (!WH_KEYID_ISERASED(idA)) {
        (void)wh_Client_KeyEvict(ctx, idA);
    }
    if (ret == 0) {
        WH_TEST_PRINT("CMAC wolfCrypt id slot SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
static int _whTest_WcIdEccUse(WC_RNG* rng, int devId, ecc_key* key,
                              ecc_key* pub)
{
    uint8_t sig[ECC_MAX_SIG_SIZE];
    word32  sigLen = sizeof(sig);
    int     verify = 0;
    int     ret;

#ifndef HAVE_ECC_DHE
    (void)devId;
#endif
    ret = wc_ecc_set_curve(key, 32, ECC_SECP256R1);
    if (ret == 0) {
        ret = wc_ecc_sign_hash(wcIdMsg, sizeof(wcIdMsg), sig, &sigLen, rng,
                               key);
    }
    if (ret == 0) {
        ret = wc_ecc_verify_hash(sig, sigLen, wcIdMsg, sizeof(wcIdMsg),
                                 &verify, pub);
    }
    if (ret == 0 && verify != 1) {
        WH_ERROR_PRINT("ECC id slot signature did not verify\n");
        ret = -1;
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ecc_key peer[1];
        uint8_t secretA[32];
        uint8_t secretB[32];
        word32  lenA = sizeof(secretA);
        word32  lenB = sizeof(secretB);

        ret = wc_ecc_init_ex(peer, NULL, devId);
        if (ret == 0) {
            ret = wc_ecc_make_key(rng, 32, peer);
            if (ret == 0) {
                ret = wc_ecc_shared_secret(key, peer, secretA, &lenA);
            }
            if (ret == 0) {
                ret = wc_ecc_shared_secret(peer, pub, secretB, &lenB);
            }
            if (ret == 0 &&
                (lenA != lenB || memcmp(secretA, secretB, lenA) != 0)) {
                WH_ERROR_PRINT("ECC id slot ECDH secrets differ\n");
                ret = -1;
            }
            wc_ecc_free(peer);
        }
    }
#endif /* HAVE_ECC_DHE */
    return ret;
}

static int _whTest_CryptoWcIdEcc(whClientContext* ctx, int devId)
{
    int     ret = 0;
    WC_RNG  rng[1];
    ecc_key key[1];
    ecc_key pub[1];
    whKeyId keyId                   = WH_KEYID_ERASED;
    uint8_t label[WH_NVM_LABEL_LEN] = "WcId ECC";

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_init_ex(pub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Client_EccMakeCacheKeyAndExportPublic(
            ctx, 32, ECC_SECP256R1, &keyId,
            WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
                WH_NVM_FLAGS_USAGE_DERIVE,
            sizeof(label), label, pub);
        if (ret == 0) {
            ret = wc_ecc_init_id(key, (unsigned char*)&keyId, sizeof(keyId),
                                 NULL, devId);
            if (ret == 0) {
                ret = _whTest_WcIdEccUse(rng, devId, key, pub);
                wc_ecc_free(key);
            }
        }
        wc_ecc_free(pub);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);
    if (ret == 0) {
        WH_TEST_PRINT("ECC wolfCrypt id slot SUCCESS\n");
    }
    return ret;
}
#endif /* HAVE_ECC && HAVE_ECC_SIGN && HAVE_ECC_VERIFY */

#ifndef NO_RSA
#define WH_TEST_WCID_RSA_BITS 2048

static int _whTest_CryptoWcIdRsa(whClientContext* ctx, int devId)
{
    int     ret = 0;
    WC_RNG  rng[1];
    RsaKey  key[1];
    RsaKey  pub[1];
    whKeyId keyId = WH_KEYID_ERASED;
    uint8_t cipher[WH_TEST_WCID_RSA_BITS / 8];
    uint8_t plain[sizeof(wcIdMsg)];
    int     encLen = 0;
    int     decLen = 0;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    ret = wc_InitRsaKey_ex(pub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wh_Client_RsaMakeCacheKeyAndExportPublic(
            ctx, WH_TEST_WCID_RSA_BITS, WC_RSA_EXPONENT, &keyId,
            WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 0, NULL,
            pub);
        if (ret == 0) {
            encLen = wc_RsaPublicEncrypt(wcIdMsg, sizeof(wcIdMsg), cipher,
                                         sizeof(cipher), pub, rng);
            if (encLen < 0) {
                ret = encLen;
            }
        }
        if (ret == 0) {
            ret = wc_InitRsaKey_Id(key, (unsigned char*)&keyId, sizeof(keyId),
                                   NULL, devId);
            if (ret == 0) {
                decLen = wc_RsaPrivateDecrypt(cipher, (word32)encLen, plain,
                                              sizeof(plain), key);
                if (decLen < 0) {
                    ret = decLen;
                }
                else if (decLen != (int)sizeof(wcIdMsg) ||
                         memcmp(plain, wcIdMsg, sizeof(wcIdMsg)) != 0) {
                    WH_ERROR_PRINT("RSA id slot decrypt mismatch\n");
                    ret = -1;
                }
                (void)wc_FreeRsaKey(key);
            }
        }
        (void)wc_FreeRsaKey(pub);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);
    if (ret == 0) {
        WH_TEST_PRINT("RSA wolfCrypt id slot SUCCESS\n");
    }
    return ret;
}
#endif /* !NO_RSA */

#if defined(HAVE_DILITHIUM) && defined(WOLFSSL_MLDSA_PUBLIC_KEY) && \
    !defined(WOLFSSL_DILITHIUM_NO_SIGN) &&                         \
    !defined(WOLFSSL_DILITHIUM_NO_VERIFY) &&                       \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
#define WH_TEST_WCID_MLDSA

/* Sign and verify on the server with key, then verify locally with pub */
static int _whTest_WcIdMlDsaUse(WC_RNG* rng, MlDsaKey* key, MlDsaKey* pub)
{
    byte   sig[DILITHIUM_MAX_SIG_SIZE];
    word32 sigSz    = sizeof(sig);
    int    verified = 0;
    int    ret;

    ret = wc_MlDsaKey_SignCtx(key, NULL, 0, sig, &sigSz, wcIdMsg,
                              sizeof(wcIdMsg), rng);
    if (ret == 0) {
        ret = wc_MlDsaKey_VerifyCtx(key, sig, sigSz, NULL, 0, wcIdMsg,
                                    sizeof(wcIdMsg), &verified);
    }
    if (ret == 0 && verified == 1) {
        verified = 0;
        ret      = wc_MlDsaKey_VerifyCtx(pub, sig, sigSz, NULL, 0, wcIdMsg,
                                         sizeof(wcIdMsg), &verified);
    }
    if (ret == 0 && verified != 1) {
        WH_ERROR_PRINT("ML-DSA id slot signature did not verify\n");
        ret = -1;
    }
    return ret;
}

static int _whTest_CryptoWcIdMlDsa(whClientContext* ctx, int devId)
{
    int      ret   = 0;
    WC_RNG   rng[1];
    MlDsaKey key[1];
    MlDsaKey pub[1];
    whKeyId  keyId = WH_KEYID_ERASED;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    ret = wc_MlDsaKey_Init(pub, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_MlDsaKey_SetParams(pub, WC_ML_DSA_44);
        if (ret == 0) {
            ret = wh_Client_MlDsaMakeCacheKeyAndExportPublic(
                ctx, 0, WC_ML_DSA_44, &keyId,
                WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, 0, NULL,
                pub);
        }
        /* Keep the local check off the HSM */
        pub->devId = INVALID_DEVID;
        if (ret == 0) {
            ret = wc_MlDsaKey_InitId(key, (unsigned char*)&keyId,
                                     sizeof(keyId), NULL, devId);
            if (ret == 0) {
                ret = wc_MlDsaKey_SetParams(key, WC_ML_DSA_44);
                if (ret == 0) {
                    ret = _whTest_WcIdMlDsaUse(rng, key, pub);
                }
                if (ret == 0 &&
                    wh_Client_MlDsaSetKeyId(key, WH_KEYID_ERASED) == 0 &&
                    _whTest_WcIdMlDsaUse(rng, key, pub) == 0) {
                    WH_ERROR_PRINT("ML-DSA id slot: SetKeyId(ERASED) did "
                                   "not clear it\n");
                    ret = -1;
                }
                wc_MlDsaKey_Free(key);
            }
        }
        wc_MlDsaKey_Free(pub);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);
    if (ret == 0) {
        WH_TEST_PRINT("ML-DSA wolfCrypt id slot SUCCESS\n");
    }
    return ret;
}
#endif

int whTest_Crypto_WcId(whClientContext* ctx)
{
    int i;

    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        (void)wh_Client_SetDmaMode(ctx, i);
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
        WH_TEST_RETURN_ON_FAIL(
            _whTest_CryptoWcIdAes(ctx, WH_CLIENT_DEVID(ctx)));
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
        WH_TEST_RETURN_ON_FAIL(
            _whTest_CryptoWcIdCmac(ctx, WH_CLIENT_DEVID(ctx)));
#endif
#ifdef WH_TEST_WCID_MLDSA
        WH_TEST_RETURN_ON_FAIL(
            _whTest_CryptoWcIdMlDsa(ctx, WH_CLIENT_DEVID(ctx)));
#endif
    }
    (void)wh_Client_SetDmaMode(ctx, 0);
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoWcIdEcc(ctx, WH_CLIENT_DEVID(ctx)));
#endif
#ifndef NO_RSA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoWcIdRsa(ctx, WH_CLIENT_DEVID(ctx)));
#endif
    return 0;
}

#endif /* WOLF_PRIVATE_KEY_ID */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
