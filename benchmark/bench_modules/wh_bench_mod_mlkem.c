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
#include <string.h>

#include "wh_bench_mod.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#if defined(WOLFSSL_HAVE_MLKEM)

static int _benchMlKemKeyGen(whClientContext* client, whBenchOpContext* ctx,
                             int id, int securityLevel, int useDma)
{
    int ret = WH_ERROR_OK;
    int i;

    (void)wh_Client_SetDmaMode(client, useDma);

    for (i = 0; i < WOLFHSM_CFG_BENCH_KG_ITERS && ret == WH_ERROR_OK; i++) {
        MlKemKey key[1];
        int      benchStartRet;
        int      benchStopRet;

        ret =
            wc_MlKemKey_Init(key, securityLevel, NULL, WH_CLIENT_DEVID(client));
        if (ret != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wc_MlKemKey_Init %d\n", ret);
            break;
        }

        benchStartRet = wh_Bench_StartOp(ctx, id);
#ifdef WOLFHSM_CFG_DMA
        if (useDma) {
            ret = wh_Client_MlKemMakeExportKeyDma(client, securityLevel, key);
        }
        else
#endif /* WOLFHSM_CFG_DMA */
        {
            ret = wh_Client_MlKemMakeExportKey(client, securityLevel, key);
        }
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
        }
        else if (ret != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed ML-KEM keygen %d\n", ret);
        }
        else if (benchStopRet != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
        }

        wc_MlKemKey_Free(key);
    }

    return ret;
}

/*
 * Evict the cached benchmark key. Returns inRet, unless the eviction itself
 * failed while inRet was OK, in which case the eviction error is reported.
 */
static int _benchMlKemEvictKey(whClientContext* client, whKeyId keyId,
                               int inRet)
{
    int ret;

    if (WH_KEYID_ISERASED(keyId)) {
        return inRet;
    }

    ret = wh_Client_KeyEvict(client, keyId);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to evict ML-KEM key %d\n", ret);
        if (inRet == WH_ERROR_OK) {
            return ret;
        }
    }
    return inRet;
}

/*
 * Generate the benchmark key into the server key cache and bind its ID to the
 * client key struct, so the timed operations reference it by ID rather than
 * taking the implicit-import path on every iteration.
 *
 * The DMA rows use this same call: wh_Client_MlKemMakeCacheKeyDma is the DMA
 * form of MakeCacheKeyAndExportPublic, and the timed operations need only the
 * key ID and the parameter set wc_MlKemKey_Init already applied.
 */
static int _benchMlKemCacheKey(whClientContext* client, int securityLevel,
                               MlKemKey* key, whKeyId* outKeyId)
{
    int     ret;
    char    keyLabel[] = "bench-mlkem-key";
    whKeyId keyId      = WH_KEYID_ERASED;

    ret = wh_Client_MlKemMakeCacheKey(client, securityLevel, &keyId,
                                      WH_NVM_FLAGS_USAGE_ANY,
                                      (uint16_t)strlen(keyLabel),
                                      (uint8_t*)keyLabel);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed ML-KEM cache keygen %d\n", ret);
        return ret;
    }

    ret = wh_Client_MlKemSetKeyId(key, keyId);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to wh_Client_MlKemSetKeyId %d\n", ret);
        return _benchMlKemEvictKey(client, keyId, ret);
    }

    *outKeyId = keyId;
    return WH_ERROR_OK;
}

static int _benchMlKemEncaps(whClientContext* client, whBenchOpContext* ctx,
                             int id, int securityLevel, int useDma)
{
    int      ret = WH_ERROR_OK;
    int      i;
    MlKemKey key[1];
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ss[WC_ML_KEM_SS_SZ];
    whKeyId  keyId = WH_KEYID_ERASED;

    (void)wh_Client_SetDmaMode(client, useDma);

    ret = wc_MlKemKey_Init(key, securityLevel, NULL, WH_CLIENT_DEVID(client));
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to wc_MlKemKey_Init %d\n", ret);
        return ret;
    }

    ret = _benchMlKemCacheKey(client, securityLevel, key, &keyId);
    if (ret != WH_ERROR_OK) {
        wc_MlKemKey_Free(key);
        return ret;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == WH_ERROR_OK; i++) {
        word32 ctLen = sizeof(ct);
        word32 ssLen = sizeof(ss);
        int    benchStartRet;
        int    benchStopRet;

        memset(ct, 0, sizeof(ct));
        memset(ss, 0, sizeof(ss));

        benchStartRet = wh_Bench_StartOp(ctx, id);
#ifdef WOLFHSM_CFG_DMA
        if (useDma) {
            ret = wh_Client_MlKemEncapsulateDma(client, key, ct, &ctLen, ss,
                                                &ssLen);
        }
        else
#endif /* WOLFHSM_CFG_DMA */
        {
            ret = wh_Client_MlKemEncapsulate(client, key, ct, &ctLen, ss, &ssLen);
        }
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
        }
        else if (ret != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed ML-KEM encapsulate %d\n", ret);
        }
        else if (benchStopRet != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
        }
    }

    wc_MlKemKey_Free(key);

    return _benchMlKemEvictKey(client, keyId, ret);
}

static int _benchMlKemDecaps(whClientContext* client, whBenchOpContext* ctx,
                             int id, int securityLevel, int useDma)
{
    int      ret = WH_ERROR_OK;
    int      i;
    MlKemKey key[1];
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ssEnc[WC_ML_KEM_SS_SZ];
    byte     ssDec[WC_ML_KEM_SS_SZ];
    word32   ctLen = sizeof(ct);
    word32   ssEncLen = sizeof(ssEnc);
    whKeyId  keyId = WH_KEYID_ERASED;

    (void)wh_Client_SetDmaMode(client, useDma);

    ret = wc_MlKemKey_Init(key, securityLevel, NULL, WH_CLIENT_DEVID(client));
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to wc_MlKemKey_Init %d\n", ret);
        return ret;
    }

    ret = _benchMlKemCacheKey(client, securityLevel, key, &keyId);
    if (ret != WH_ERROR_OK) {
        wc_MlKemKey_Free(key);
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        ret = wh_Client_MlKemEncapsulateDma(client, key, ct, &ctLen, ssEnc,
                                            &ssEncLen);
    }
    else
#endif /* WOLFHSM_CFG_DMA */
    {
        ret = wh_Client_MlKemEncapsulate(client, key, ct, &ctLen, ssEnc,
                                         &ssEncLen);
    }
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed ML-KEM setup encapsulate %d\n", ret);
        wc_MlKemKey_Free(key);
        return _benchMlKemEvictKey(client, keyId, ret);
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == WH_ERROR_OK; i++) {
        word32 ssDecLen = sizeof(ssDec);
        int    benchStartRet;
        int    benchStopRet;

        memset(ssDec, 0, sizeof(ssDec));

        benchStartRet = wh_Bench_StartOp(ctx, id);
#ifdef WOLFHSM_CFG_DMA
        if (useDma) {
            ret = wh_Client_MlKemDecapsulateDma(client, key, ct, ctLen, ssDec,
                                                &ssDecLen);
        }
        else
#endif /* WOLFHSM_CFG_DMA */
        {
            ret = wh_Client_MlKemDecapsulate(client, key, ct, ctLen, ssDec,
                                             &ssDecLen);
        }
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
        }
        else if (ret != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed ML-KEM decapsulate %d\n", ret);
        }
        else if ((ssDecLen != ssEncLen) ||
                 (memcmp(ssDec, ssEnc, ssEncLen) != 0)) {
            WH_BENCH_PRINTF("ML-KEM decapsulate mismatch\n");
            ret = WH_ERROR_ABORTED;
        }
        else if (benchStopRet != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
        }
    }

    wc_MlKemKey_Free(key);

    return _benchMlKemEvictKey(client, keyId, ret);
}

#define WH_DEFINE_MLKEM_BENCH_NON_DMA_FNS(_Suffix, _Level)                    \
    int wh_Bench_Mod_MlKem##_Suffix##KeyGen(                                  \
        whClientContext* client, whBenchOpContext* ctx, int id, void* params) \
    {                                                                         \
        (void)params;                                                         \
        return _benchMlKemKeyGen(client, ctx, id, _Level, 0);                 \
    }                                                                         \
                                                                              \
    int wh_Bench_Mod_MlKem##_Suffix##Encaps(                                  \
        whClientContext* client, whBenchOpContext* ctx, int id, void* params) \
    {                                                                         \
        (void)params;                                                         \
        return _benchMlKemEncaps(client, ctx, id, _Level, 0);                 \
    }                                                                         \
                                                                              \
    int wh_Bench_Mod_MlKem##_Suffix##Decaps(                                  \
        whClientContext* client, whBenchOpContext* ctx, int id, void* params) \
    {                                                                         \
        (void)params;                                                         \
        return _benchMlKemDecaps(client, ctx, id, _Level, 0);                 \
    }

#ifdef WOLFHSM_CFG_DMA
#define WH_DEFINE_MLKEM_BENCH_DMA_FNS(_Suffix, _Level)                        \
    int wh_Bench_Mod_MlKem##_Suffix##KeyGenDma(                               \
        whClientContext* client, whBenchOpContext* ctx, int id, void* params) \
    {                                                                         \
        (void)params;                                                         \
        return _benchMlKemKeyGen(client, ctx, id, _Level, 1);                 \
    }                                                                         \
                                                                              \
    int wh_Bench_Mod_MlKem##_Suffix##EncapsDma(                               \
        whClientContext* client, whBenchOpContext* ctx, int id, void* params) \
    {                                                                         \
        (void)params;                                                         \
        return _benchMlKemEncaps(client, ctx, id, _Level, 1);                 \
    }                                                                         \
                                                                              \
    int wh_Bench_Mod_MlKem##_Suffix##DecapsDma(                               \
        whClientContext* client, whBenchOpContext* ctx, int id, void* params) \
    {                                                                         \
        (void)params;                                                         \
        return _benchMlKemDecaps(client, ctx, id, _Level, 1);                 \
    }
#else
#define WH_DEFINE_MLKEM_BENCH_DMA_FNS(_Suffix, _Level)                            \
int wh_Bench_Mod_MlKem##_Suffix##KeyGenDma(whClientContext* client,               \
                                           whBenchOpContext* ctx, int id,         \
                                           void* params)                           \
{                                                                                  \
    (void)client;                                                                  \
    (void)ctx;                                                                     \
    (void)id;                                                                      \
    (void)params;                                                                  \
    (void)_Level;                                                                  \
    return WH_ERROR_NOTIMPL;                                                       \
}                                                                                  \
                                                                                   \
int wh_Bench_Mod_MlKem##_Suffix##EncapsDma(whClientContext* client,               \
                                           whBenchOpContext* ctx, int id,         \
                                           void* params)                           \
{                                                                                  \
    (void)client;                                                                  \
    (void)ctx;                                                                     \
    (void)id;                                                                      \
    (void)params;                                                                  \
    (void)_Level;                                                                  \
    return WH_ERROR_NOTIMPL;                                                       \
}                                                                                  \
                                                                                   \
int wh_Bench_Mod_MlKem##_Suffix##DecapsDma(whClientContext* client,               \
                                           whBenchOpContext* ctx, int id,         \
                                           void* params)                           \
{                                                                                  \
    (void)client;                                                                  \
    (void)ctx;                                                                     \
    (void)id;                                                                      \
    (void)params;                                                                  \
    (void)_Level;                                                                  \
    return WH_ERROR_NOTIMPL;                                                       \
}
#endif /* WOLFHSM_CFG_DMA */

#ifndef WOLFSSL_NO_ML_KEM_512
WH_DEFINE_MLKEM_BENCH_NON_DMA_FNS(512, WC_ML_KEM_512)
WH_DEFINE_MLKEM_BENCH_DMA_FNS(512, WC_ML_KEM_512)
#endif
#ifndef WOLFSSL_NO_ML_KEM_768
WH_DEFINE_MLKEM_BENCH_NON_DMA_FNS(768, WC_ML_KEM_768)
WH_DEFINE_MLKEM_BENCH_DMA_FNS(768, WC_ML_KEM_768)
#endif
#ifndef WOLFSSL_NO_ML_KEM_1024
WH_DEFINE_MLKEM_BENCH_NON_DMA_FNS(1024, WC_ML_KEM_1024)
WH_DEFINE_MLKEM_BENCH_DMA_FNS(1024, WC_ML_KEM_1024)
#endif

#endif /* WOLFSSL_HAVE_MLKEM */
#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
