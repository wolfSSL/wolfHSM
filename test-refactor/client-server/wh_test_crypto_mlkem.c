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
 * test-refactor/client-server/wh_test_crypto_mlkem.c
 *
 * ML-KEM tests routed through the server:
 *   _whTest_CryptoMlKemMakeCacheKeyArgs - cache keygen argument checks,
 *                                         including WH_NVM_FLAGS_EPHEMERAL
 * Run for each enabled level, once with the comm buffer API and once with
 * the DMA API:
 *   _whTest_CryptoMlKemWolfCrypt        - wc_MlKemKey_* through the cryptocb
 *   _whTest_CryptoMlKemClient           - keygen, import / export, encaps /
 *                                         decaps, wrong key decaps
 *   _whTest_CryptoMlKemUsage            - cached key needs USAGE_DERIVE
 *   _whTest_CryptoMlKemExportPublic     - NONEXPORTABLE key allows only the
 *                                         public export
 *   _whTest_CryptoMlKemCacheKeyAndExportPublic - keygen public key matches
 *                                         a separate public export
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLFSSL_HAVE_MLKEM

#define WH_TEST_MLKEM_ARRAY_CNT(a) (sizeof(a) / sizeof((a)[0]))

static const int whTestMlKemLevels[] = {
#ifndef WOLFSSL_NO_ML_KEM_512
    WC_ML_KEM_512,
#endif
#ifndef WOLFSSL_NO_ML_KEM_768
    WC_ML_KEM_768,
#endif
#ifndef WOLFSSL_NO_ML_KEM_1024
    WC_ML_KEM_1024,
#endif
};

/* Comm buffer and DMA variants of the client API */
typedef struct {
    const char* name;
    int         dmaMode;
    /* Expected result of a public export into an undersized buffer */
    int tinyBufRet;
    int (*makeExportKey)(whClientContext* ctx, int level, MlKemKey* key);
    int (*makeCacheKeyAndExportPublic)(whClientContext* ctx, int level,
                                       whKeyId* inout_key_id, whNvmFlags flags,
                                       uint16_t label_len, const uint8_t* label,
                                       MlKemKey* pub);
    int (*importKey)(whClientContext* ctx, MlKemKey* key, whKeyId* inout_keyId,
                     whNvmFlags flags, uint16_t label_len, uint8_t* label);
    int (*exportKey)(whClientContext* ctx, whKeyId keyId, MlKemKey* key,
                     uint16_t label_len, uint8_t* label);
    int (*exportPublicKey)(whClientContext* ctx, whKeyId keyId, MlKemKey* key,
                           uint16_t label_len, uint8_t* label);
    int (*encapsulate)(whClientContext* ctx, MlKemKey* key, uint8_t* ct,
                       uint32_t* inout_ct_len, uint8_t* ss,
                       uint32_t* inout_ss_len);
    int (*decapsulate)(whClientContext* ctx, MlKemKey* key, const uint8_t* ct,
                       uint32_t ct_len, uint8_t* ss, uint32_t* inout_ss_len);
    int (*keyExport)(whClientContext* ctx, whKeyId keyId, uint8_t* out,
                     uint16_t* outSz);
    int (*keyExportPublic)(whClientContext* ctx, whKeyId keyId, uint8_t* out,
                           uint16_t* outSz);
} whTestMlKemApi;

static int _whTest_MlKemKeyExport(whClientContext* ctx, whKeyId keyId,
                                  uint8_t* out, uint16_t* outSz)
{
    return wh_Client_KeyExport(ctx, keyId, NULL, 0, out, outSz);
}

static int _whTest_MlKemKeyExportPublic(whClientContext* ctx, whKeyId keyId,
                                        uint8_t* out, uint16_t* outSz)
{
    return wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_MLKEM, NULL, 0,
                                     out, outSz);
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_MlKemKeyExportDma(whClientContext* ctx, whKeyId keyId,
                                     uint8_t* out, uint16_t* outSz)
{
    return wh_Client_KeyExportDma(ctx, keyId, out, *outSz, NULL, 0, outSz);
}

static int _whTest_MlKemKeyExportPublicDma(whClientContext* ctx, whKeyId keyId,
                                           uint8_t* out, uint16_t* outSz)
{
    return wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_MLKEM, out,
                                        *outSz, NULL, 0, outSz);
}
#endif /* WOLFHSM_CFG_DMA */

static const whTestMlKemApi whTestMlKemApis[] = {
    {
        "",
        0,
        WH_ERROR_ABORTED,
        wh_Client_MlKemMakeExportKey,
        wh_Client_MlKemMakeCacheKeyAndExportPublic,
        wh_Client_MlKemImportKey,
        wh_Client_MlKemExportKey,
        wh_Client_MlKemExportPublicKey,
        wh_Client_MlKemEncapsulate,
        wh_Client_MlKemDecapsulate,
        _whTest_MlKemKeyExport,
        _whTest_MlKemKeyExportPublic,
    },
#ifdef WOLFHSM_CFG_DMA
    {
        " DMA",
        1,
        WH_ERROR_NOSPACE,
        wh_Client_MlKemMakeExportKeyDma,
        wh_Client_MlKemMakeCacheKeyDma,
        wh_Client_MlKemImportKeyDma,
        wh_Client_MlKemExportKeyDma,
        wh_Client_MlKemExportPublicKeyDma,
        wh_Client_MlKemEncapsulateDma,
        wh_Client_MlKemDecapsulateDma,
        _whTest_MlKemKeyExportDma,
        _whTest_MlKemKeyExportPublicDma,
    },
#endif /* WOLFHSM_CFG_DMA */
};

static int _whTest_CryptoMlKemMakeCacheKeyArgs(whClientContext* ctx)
{
    /* Valid level so the server level check cannot mask the gate */
    const int level = whTestMlKemLevels[0];
    int       ret   = 0;
    whKeyId   keyId = WH_KEYID_ERASED;
    MlKemKey  pub[1];
    size_t    i;

    memset(pub, 0, sizeof(pub));
    if (wh_Client_MlKemMakeCacheKey(ctx, level, &keyId, WH_NVM_FLAGS_EPHEMERAL,
                                    0, NULL) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("ML-KEM cache keygen accepted EPHEMERAL\n");
        ret = WH_TEST_FAIL;
    }
    for (i = 0; i < WH_TEST_MLKEM_ARRAY_CNT(whTestMlKemApis); i++) {
        const whTestMlKemApi* api = &whTestMlKemApis[i];

        if ((api->makeCacheKeyAndExportPublic(ctx, level, &keyId,
                                              WH_NVM_FLAGS_EPHEMERAL, 0, NULL,
                                              pub) != WH_ERROR_BADARGS) ||
            (api->makeCacheKeyAndExportPublic(ctx, level, NULL,
                                              WH_NVM_FLAGS_NONE, 0, NULL,
                                              pub) != WH_ERROR_BADARGS) ||
            (api->makeCacheKeyAndExportPublic(ctx, level, &keyId,
                                              WH_NVM_FLAGS_NONE, 0, NULL,
                                              NULL) != WH_ERROR_BADARGS)) {
            WH_ERROR_PRINT("ML-KEM%s cache keygen argument check failed\n",
                           api->name);
            ret = WH_TEST_FAIL;
        }
    }
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("ML-KEM CACHE-KEY ARGS SUCCESS\n");
    }
    return ret;
}

#if !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) &&    \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)

static int _whTest_MlKemEncodePublic(MlKemKey* key, byte* out, word32* outLen)
{
    int ret = wc_MlKemKey_PublicKeySize(key, outLen);
    if (ret == 0) {
        ret = wc_MlKemKey_EncodePublicKey(key, out, *outLen);
    }
    return ret;
}

/* Encapsulate with pub, then decapsulate with the server key behind priv */
static int _whTest_MlKemRoundTrip(whClientContext*      ctx,
                                  const whTestMlKemApi* api, MlKemKey* pub,
                                  MlKemKey* priv, WC_RNG* rng)
{
    int      ret;
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ssEnc[WC_ML_KEM_SS_SZ];
    byte     ssDec[WC_ML_KEM_SS_SZ];
    word32   ctLen    = 0;
    uint32_t ssDecLen = sizeof(ssDec);

    ret = wc_MlKemKey_CipherTextSize(pub, &ctLen);
    if (ret == 0) {
        ret = wc_MlKemKey_Encapsulate(pub, ct, ssEnc, rng);
    }
    if (ret == 0) {
        ret = api->decapsulate(ctx, priv, ct, ctLen, ssDec, &ssDecLen);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s round trip failed %d\n", api->name, ret);
    }
    else if ((ssDecLen != sizeof(ssEnc)) ||
             (memcmp(ssEnc, ssDec, sizeof(ssEnc)) != 0)) {
        WH_ERROR_PRINT("ML-KEM%s round trip shared secret mismatch\n",
                       api->name);
        ret = WH_TEST_FAIL;
    }
    return ret;
}

static int _whTest_CryptoMlKemWolfCrypt(whClientContext* ctx, int level,
                                        WC_RNG* rng)
{
    int      ret;
    MlKemKey key[1];
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ssEnc[WC_ML_KEM_SS_SZ];
    byte     ssDec[WC_ML_KEM_SS_SZ];
    word32   ctLen = 0;

    ret = wc_MlKemKey_Init(key, level, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init ML-KEM key level=%d %d\n", level, ret);
        return ret;
    }

    ret = wc_MlKemKey_MakeKey(key, rng);
    if (ret == 0) {
        ret = wc_MlKemKey_CipherTextSize(key, &ctLen);
    }
    if (ret == 0) {
        ret = wc_MlKemKey_Encapsulate(key, ct, ssEnc, rng);
    }
    if (ret == 0) {
        ret = wc_MlKemKey_Decapsulate(key, ssDec, ct, ctLen);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM wolfCrypt level=%d failed %d\n", level, ret);
    }
    else if (memcmp(ssEnc, ssDec, sizeof(ssEnc)) != 0) {
        WH_ERROR_PRINT("ML-KEM wolfCrypt shared secret mismatch level=%d\n",
                       level);
        ret = WH_TEST_FAIL;
    }

    wc_MlKemKey_Free(key);
    return ret;
}

static int _whTest_CryptoMlKemClient(whClientContext*      ctx,
                                     const whTestMlKemApi* api, int level)
{
    const int devId       = WH_CLIENT_DEVID(ctx);
    int       ret         = 0;
    int       keyInited   = 0;
    int       wrongInited = 0;
    int       copyInited  = 0;
    MlKemKey  key[1];
    MlKemKey  wrongKey[1];
    MlKemKey  copyKey[1];
    whKeyId   keyId   = WH_KEYID_ERASED;
    uint8_t   label[] = "mlkem-client";
    uint8_t   labelOut[sizeof(label)];
    byte      ser[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    byte      copySer[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    uint16_t  serLen     = sizeof(ser);
    uint16_t  copySerLen = sizeof(copySer);
    byte      ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte      ssEnc[WC_ML_KEM_SS_SZ];
    byte      ssDec[WC_ML_KEM_SS_SZ];
    uint32_t  ctLen    = sizeof(ct);
    uint32_t  ssEncLen = sizeof(ssEnc);
    uint32_t  ssDecLen = sizeof(ssDec);

    memset(labelOut, 0, sizeof(labelOut));

    ret = wc_MlKemKey_Init(key, level, NULL, devId);
    if (ret == 0) {
        keyInited = 1;
        ret       = wc_MlKemKey_Init(wrongKey, level, NULL, devId);
    }
    if (ret == 0) {
        wrongInited = 1;
        ret         = wc_MlKemKey_Init(copyKey, level, NULL, devId);
    }
    if (ret == 0) {
        copyInited = 1;
        ret        = api->makeExportKey(ctx, level, key);
    }
    if (ret == 0) {
        ret = api->makeExportKey(ctx, level, wrongKey);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s keygen level=%d failed %d\n", api->name, level,
                       ret);
    }

    /* Import, export back, and compare the serialized keys and label */
    if (ret == 0) {
        ret = wh_Crypto_MlKemSerializeKey(key, serLen, ser, &serLen);
    }
    if (ret == 0) {
        ret = api->importKey(ctx, key, &keyId, WH_NVM_FLAGS_NONE, sizeof(label),
                             label);
    }
    if (ret == 0) {
        ret = api->exportKey(ctx, keyId, copyKey, sizeof(labelOut), labelOut);
    }
    if (ret == 0) {
        ret = wh_Crypto_MlKemSerializeKey(copyKey, copySerLen, copySer,
                                          &copySerLen);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s import/export level=%d failed %d\n", api->name,
                       level, ret);
    }
    else if ((serLen != copySerLen) || (memcmp(ser, copySer, serLen) != 0) ||
             (memcmp(label, labelOut, sizeof(label)) != 0)) {
        WH_ERROR_PRINT("ML-KEM%s exported key mismatch level=%d\n", api->name,
                       level);
        ret = WH_TEST_FAIL;
    }

    if (ret == 0) {
        ret = api->encapsulate(ctx, key, ct, &ctLen, ssEnc, &ssEncLen);
    }
    if (ret == 0) {
        ret = api->decapsulate(ctx, key, ct, ctLen, ssDec, &ssDecLen);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s encaps/decaps level=%d failed %d\n", api->name,
                       level, ret);
    }
    else if ((ssEncLen != ssDecLen) || (memcmp(ssEnc, ssDec, ssEncLen) != 0)) {
        WH_ERROR_PRINT("ML-KEM%s shared secret mismatch level=%d\n", api->name,
                       level);
        ret = WH_TEST_FAIL;
    }

    if (ret == 0) {
        ssDecLen = sizeof(ssDec);
        ret      = api->decapsulate(ctx, wrongKey, ct, ctLen, ssDec, &ssDecLen);
        if (ret != 0) {
            WH_ERROR_PRINT("ML-KEM%s wrong key decaps level=%d failed %d\n",
                           api->name, level, ret);
        }
        else if ((ssEncLen == ssDecLen) &&
                 (memcmp(ssEnc, ssDec, ssEncLen) == 0)) {
            WH_ERROR_PRINT("ML-KEM%s wrong key decaps matched level=%d\n",
                           api->name, level);
            ret = WH_TEST_FAIL;
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        int evictRet = wh_Client_KeyEvict(ctx, keyId);
        if ((ret == 0) && (evictRet != 0)) {
            WH_ERROR_PRINT("ML-KEM%s evict level=%d failed %d\n", api->name,
                           level, evictRet);
            ret = evictRet;
        }
    }
    if (copyInited) {
        wc_MlKemKey_Free(copyKey);
    }
    if (wrongInited) {
        wc_MlKemKey_Free(wrongKey);
    }
    if (keyInited) {
        wc_MlKemKey_Free(key);
    }
    return ret;
}

/* Encaps and decaps with a key referenced by its cache id */
static int _whTest_CryptoMlKemUsageOne(whClientContext*      ctx,
                                       const whTestMlKemApi* api, int level,
                                       whNvmFlags flags, int expRet)
{
    int      ret;
    int      encRet;
    int      decRet;
    MlKemKey key[1];
    whKeyId  keyId   = WH_KEYID_ERASED;
    uint8_t  label[] = "mlkem-usage";
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ssEnc[WC_ML_KEM_SS_SZ];
    byte     ssDec[WC_ML_KEM_SS_SZ];
    word32   ctSz     = 0;
    uint32_t ctLen    = sizeof(ct);
    uint32_t ssEncLen = sizeof(ssEnc);
    uint32_t ssDecLen = sizeof(ssDec);

    memset(ct, 0, sizeof(ct));
    ret = wc_MlKemKey_Init(key, level, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init ML-KEM key level=%d %d\n", level, ret);
        return ret;
    }

    ret = wh_Client_MlKemMakeCacheKey(ctx, level, &keyId, flags, sizeof(label),
                                      label);
    if (ret == 0) {
        ret = wh_Client_MlKemSetKeyId(key, keyId);
    }
    if (ret == 0) {
        ret = wc_MlKemKey_CipherTextSize(key, &ctSz);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s cache key level=%d failed %d\n", api->name,
                       level, ret);
    }

    if (ret == 0) {
        encRet = api->encapsulate(ctx, key, ct, &ctLen, ssEnc, &ssEncLen);
        decRet = api->decapsulate(ctx, key, ct, ctSz, ssDec, &ssDecLen);
        if ((encRet != expRet) || (decRet != expRet)) {
            WH_ERROR_PRINT("ML-KEM%s flags=0x%x level=%d: encaps %d, decaps "
                           "%d, expected %d\n",
                           api->name, (unsigned)flags, level, encRet, decRet,
                           expRet);
            ret = WH_TEST_FAIL;
        }
        else if ((expRet == 0) && ((ssEncLen != ssDecLen) ||
                                   (memcmp(ssEnc, ssDec, ssEncLen) != 0))) {
            WH_ERROR_PRINT("ML-KEM%s by-id shared secret mismatch level=%d\n",
                           api->name, level);
            ret = WH_TEST_FAIL;
        }
    }

    /* By-id operations must leave the key in the cache */
    if (!WH_KEYID_ISERASED(keyId)) {
        int evictRet = wh_Client_KeyEvict(ctx, keyId);
        if ((ret == 0) && (evictRet != 0)) {
            WH_ERROR_PRINT("ML-KEM%s by-id evict level=%d failed %d\n",
                           api->name, level, evictRet);
            ret = evictRet;
        }
    }
    wc_MlKemKey_Free(key);
    return ret;
}

static int _whTest_CryptoMlKemUsage(whClientContext*      ctx,
                                    const whTestMlKemApi* api, int level)
{
    static const struct {
        whNvmFlags flags;
        int        expRet;
    } cases[] = {
        {WH_NVM_FLAGS_NONE, WH_ERROR_USAGE},
        {WH_NVM_FLAGS_USAGE_DERIVE, WH_ERROR_OK},
    };
    size_t i;

    for (i = 0; i < WH_TEST_MLKEM_ARRAY_CNT(cases); i++) {
        WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemUsageOne(
            ctx, api, level, cases[i].flags, cases[i].expRet));
    }
    return 0;
}

static int _whTest_CryptoMlKemExportPublic(whClientContext*      ctx,
                                           const whTestMlKemApi* api, int level,
                                           WC_RNG* rng)
{
    const int devId      = WH_CLIENT_DEVID(ctx);
    int       ret        = 0;
    int       negRet     = 0;
    int       pubInited  = 0;
    int       privInited = 0;
    MlKemKey  pub[1];
    MlKemKey  priv[1];
    whKeyId   keyId = WH_KEYID_ERASED;
    byte      buf[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    uint16_t  bufLen = sizeof(buf);
    byte      enc[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
    word32    encLen = 0;

    ret = wh_Client_MlKemMakeCacheKey(
        ctx, level, &keyId,
        WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_NONEXPORTABLE, 0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s NONEXPORTABLE keygen level=%d failed %d\n",
                       api->name, level, ret);
        return ret;
    }

    negRet = api->keyExport(ctx, keyId, buf, &bufLen);
    if (negRet != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("ML-KEM%s NONEXPORTABLE full export level=%d "
                       "returned %d\n",
                       api->name, level, negRet);
        ret = WH_TEST_FAIL;
    }

    if (ret == 0) {
        ret = wc_MlKemKey_Init(pub, level, NULL, devId);
    }
    if (ret == 0) {
        pubInited = 1;
        ret       = api->exportPublicKey(ctx, keyId, pub, 0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT("ML-KEM%s public export level=%d failed %d\n",
                           api->name, level, ret);
        }
        else if (((pub->flags & MLKEM_FLAG_PUB_SET) == 0) ||
                 ((pub->flags & MLKEM_FLAG_PRIV_SET) != 0)) {
            WH_ERROR_PRINT("ML-KEM%s public export level=%d flags 0x%x\n",
                           api->name, level, (unsigned)pub->flags);
            ret = WH_TEST_FAIL;
        }
    }

    if (ret == 0) {
        ret = wc_MlKemKey_Init(priv, level, NULL, devId);
    }
    if (ret == 0) {
        privInited = 1;
        ret        = wh_Client_MlKemSetKeyId(priv, keyId);
    }
    if (ret == 0) {
        ret = _whTest_MlKemRoundTrip(ctx, api, pub, priv, rng);
    }

    /* Generic public export must match the typed public export */
    if (ret == 0) {
        ret = _whTest_MlKemEncodePublic(pub, enc, &encLen);
    }
    if (ret == 0) {
        bufLen = sizeof(buf);
        ret    = api->keyExportPublic(ctx, keyId, buf, &bufLen);
        if (ret != 0) {
            WH_ERROR_PRINT("ML-KEM%s generic public export level=%d "
                           "failed %d\n",
                           api->name, level, ret);
        }
        else if ((bufLen != encLen) || (memcmp(buf, enc, encLen) != 0)) {
            WH_ERROR_PRINT("ML-KEM%s generic public export mismatch "
                           "level=%d\n",
                           api->name, level);
            ret = WH_TEST_FAIL;
        }
    }

    /* 0xBADE is well clear of the ids the server assigns */
    if (ret == 0) {
        bufLen = sizeof(buf);
        negRet = api->keyExportPublic(ctx, (whKeyId)0xBADE, buf, &bufLen);
        if (negRet != WH_ERROR_NOTFOUND) {
            WH_ERROR_PRINT("ML-KEM%s public export of missing key "
                           "returned %d\n",
                           api->name, negRet);
            ret = WH_TEST_FAIL;
        }
    }
    if (ret == 0) {
        bufLen = 8;
        negRet = api->keyExportPublic(ctx, keyId, buf, &bufLen);
        if (negRet != api->tinyBufRet) {
            WH_ERROR_PRINT("ML-KEM%s public export to small buffer "
                           "returned %d, expected %d\n",
                           api->name, negRet, api->tinyBufRet);
            ret = WH_TEST_FAIL;
        }
    }

    if (privInited) {
        wc_MlKemKey_Free(priv);
    }
    if (pubInited) {
        wc_MlKemKey_Free(pub);
    }
    (void)wh_Client_KeyEvict(ctx, keyId);
    return ret;
}

static int _whTest_CryptoMlKemCacheKeyAndExportPublic(whClientContext*      ctx,
                                                      const whTestMlKemApi* api,
                                                      int level, WC_RNG* rng)
{
    int      ret       = 0;
    int      refInited = 0;
    MlKemKey genPub[1];
    MlKemKey refPub[1];
    whKeyId  keyId = WH_KEYID_ERASED;
    byte     genRaw[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
    byte     refRaw[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
    word32   genRawSz = 0;
    word32   refRawSz = 0;

    ret = wc_MlKemKey_Init(genPub, level, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init ML-KEM key level=%d %d\n", level, ret);
        return ret;
    }

    ret = api->makeCacheKeyAndExportPublic(
        ctx, level, &keyId, WH_NVM_FLAGS_USAGE_DERIVE, 0, NULL, genPub);
    if (ret == 0) {
        ret = wc_MlKemKey_Init(refPub, level, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        refInited = 1;
        ret       = api->exportPublicKey(ctx, keyId, refPub, 0, NULL);
    }
    if (ret == 0) {
        ret = _whTest_MlKemEncodePublic(genPub, genRaw, &genRawSz);
    }
    if (ret == 0) {
        ret = _whTest_MlKemEncodePublic(refPub, refRaw, &refRawSz);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("ML-KEM%s cache keygen and public export level=%d "
                       "failed %d\n",
                       api->name, level, ret);
    }
    else if ((genRawSz != refRawSz) ||
             (memcmp(genRaw, refRaw, genRawSz) != 0)) {
        WH_ERROR_PRINT("ML-KEM%s keygen public key mismatch level=%d\n",
                       api->name, level);
        ret = WH_TEST_FAIL;
    }

    /* genPub also refers to the cached private key */
    if (ret == 0) {
        ret = _whTest_MlKemRoundTrip(ctx, api, refPub, genPub, rng);
    }

    if (refInited) {
        wc_MlKemKey_Free(refPub);
    }
    wc_MlKemKey_Free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    return ret;
}

static int _whTest_CryptoMlKemLevel(whClientContext*      ctx,
                                    const whTestMlKemApi* api, int level,
                                    WC_RNG* rng)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemWolfCrypt(ctx, level, rng));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemClient(ctx, api, level));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemUsage(ctx, api, level));
    WH_TEST_RETURN_ON_FAIL(
        _whTest_CryptoMlKemExportPublic(ctx, api, level, rng));
    WH_TEST_RETURN_ON_FAIL(
        _whTest_CryptoMlKemCacheKeyAndExportPublic(ctx, api, level, rng));
    WH_TEST_PRINT("ML-KEM%s level=%d SUCCESS\n", api->name, level);
    return 0;
}

static int _whTest_CryptoMlKemLevels(whClientContext* ctx)
{
    int    ret = 0;
    size_t a;
    size_t l;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    for (a = 0; (ret == 0) && (a < WH_TEST_MLKEM_ARRAY_CNT(whTestMlKemApis));
         a++) {
        /* wolfCrypt calls take the matching cryptocb dispatch path */
        (void)wh_Client_SetDmaMode(ctx, whTestMlKemApis[a].dmaMode);
        for (l = 0;
             (ret == 0) && (l < WH_TEST_MLKEM_ARRAY_CNT(whTestMlKemLevels));
             l++) {
            ret = _whTest_CryptoMlKemLevel(ctx, &whTestMlKemApis[a],
                                           whTestMlKemLevels[l], rng);
        }
    }
    (void)wh_Client_SetDmaMode(ctx, 0);

    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* !WOLFSSL_MLKEM_NO_MAKE_KEY && !WOLFSSL_MLKEM_NO_ENCAPSULATE && \
          !WOLFSSL_MLKEM_NO_DECAPSULATE */

int whTest_Crypto_MlKem(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemMakeCacheKeyArgs(ctx));
#if !defined(WOLFSSL_MLKEM_NO_MAKE_KEY) &&    \
    !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE)
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoMlKemLevels(ctx));
#endif
    return 0;
}

#endif /* WOLFSSL_HAVE_MLKEM */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
