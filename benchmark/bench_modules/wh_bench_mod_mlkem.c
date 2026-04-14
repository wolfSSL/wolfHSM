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
                             int id, int securityLevel, int devId)
{
    int ret = WH_ERROR_OK;
    int i;

    for (i = 0; i < WOLFHSM_CFG_BENCH_KG_ITERS && ret == WH_ERROR_OK; i++) {
        MlKemKey key[1];
        int      benchStartRet;
        int      benchStopRet;

        ret = wc_MlKemKey_Init(key, securityLevel, NULL, devId);
        if (ret != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to wc_MlKemKey_Init %d\n", ret);
            break;
        }

        benchStartRet = wh_Bench_StartOp(ctx, id);
#ifdef WOLFHSM_CFG_DMA
        if (devId == WH_DEV_ID_DMA) {
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

static int _benchMlKemEncaps(whClientContext* client, whBenchOpContext* ctx,
                             int id, int securityLevel, int devId)
{
    int      ret = WH_ERROR_OK;
    int      i;
    MlKemKey key[1];
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ss[WC_ML_KEM_SS_SZ];

    ret = wc_MlKemKey_Init(key, securityLevel, NULL, devId);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to wc_MlKemKey_Init %d\n", ret);
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    if (devId == WH_DEV_ID_DMA) {
        ret = wh_Client_MlKemMakeExportKeyDma(client, securityLevel, key);
    }
    else
#endif /* WOLFHSM_CFG_DMA */
    {
        ret = wh_Client_MlKemMakeExportKey(client, securityLevel, key);
    }
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed ML-KEM key setup %d\n", ret);
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
        if (devId == WH_DEV_ID_DMA) {
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
    return ret;
}

static int _benchMlKemDecaps(whClientContext* client, whBenchOpContext* ctx,
                             int id, int securityLevel, int devId)
{
    int      ret = WH_ERROR_OK;
    int      i;
    MlKemKey key[1];
    byte     ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte     ssEnc[WC_ML_KEM_SS_SZ];
    byte     ssDec[WC_ML_KEM_SS_SZ];
    word32   ctLen = sizeof(ct);
    word32   ssEncLen = sizeof(ssEnc);

    ret = wc_MlKemKey_Init(key, securityLevel, NULL, devId);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to wc_MlKemKey_Init %d\n", ret);
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    if (devId == WH_DEV_ID_DMA) {
        ret = wh_Client_MlKemMakeExportKeyDma(client, securityLevel, key);
    }
    else
#endif /* WOLFHSM_CFG_DMA */
    {
        ret = wh_Client_MlKemMakeExportKey(client, securityLevel, key);
    }
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed ML-KEM key setup %d\n", ret);
        wc_MlKemKey_Free(key);
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    if (devId == WH_DEV_ID_DMA) {
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
        return ret;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == WH_ERROR_OK; i++) {
        word32 ssDecLen = sizeof(ssDec);
        int    benchStartRet;
        int    benchStopRet;

        memset(ssDec, 0, sizeof(ssDec));

        benchStartRet = wh_Bench_StartOp(ctx, id);
#ifdef WOLFHSM_CFG_DMA
        if (devId == WH_DEV_ID_DMA) {
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
    return ret;
}

#define WH_DEFINE_MLKEM_BENCH_NON_DMA_FNS(_Suffix, _Level)                        \
int wh_Bench_Mod_MlKem##_Suffix##KeyGen(whClientContext* client,                  \
                                        whBenchOpContext* ctx, int id,            \
                                        void* params)                              \
{                                                                                  \
    (void)params;                                                                  \
    return _benchMlKemKeyGen(client, ctx, id, _Level, WH_DEV_ID);                 \
}                                                                                  \
                                                                                   \
int wh_Bench_Mod_MlKem##_Suffix##Encaps(whClientContext* client,                  \
                                        whBenchOpContext* ctx, int id,            \
                                        void* params)                              \
{                                                                                  \
    (void)params;                                                                  \
    return _benchMlKemEncaps(client, ctx, id, _Level, WH_DEV_ID);                 \
}                                                                                  \
                                                                                   \
int wh_Bench_Mod_MlKem##_Suffix##Decaps(whClientContext* client,                  \
                                        whBenchOpContext* ctx, int id,            \
                                        void* params)                              \
{                                                                                  \
    (void)params;                                                                  \
    return _benchMlKemDecaps(client, ctx, id, _Level, WH_DEV_ID);                 \
}

#ifdef WOLFHSM_CFG_DMA
#define WH_DEFINE_MLKEM_BENCH_DMA_FNS(_Suffix, _Level)                            \
int wh_Bench_Mod_MlKem##_Suffix##KeyGenDma(whClientContext* client,               \
                                           whBenchOpContext* ctx, int id,         \
                                           void* params)                           \
{                                                                                  \
    (void)params;                                                                  \
    return _benchMlKemKeyGen(client, ctx, id, _Level, WH_DEV_ID_DMA);             \
}                                                                                  \
                                                                                   \
int wh_Bench_Mod_MlKem##_Suffix##EncapsDma(whClientContext* client,               \
                                           whBenchOpContext* ctx, int id,         \
                                           void* params)                           \
{                                                                                  \
    (void)params;                                                                  \
    return _benchMlKemEncaps(client, ctx, id, _Level, WH_DEV_ID_DMA);             \
}                                                                                  \
                                                                                   \
int wh_Bench_Mod_MlKem##_Suffix##DecapsDma(whClientContext* client,               \
                                           whBenchOpContext* ctx, int id,         \
                                           void* params)                           \
{                                                                                  \
    (void)params;                                                                  \
    return _benchMlKemDecaps(client, ctx, id, _Level, WH_DEV_ID_DMA);             \
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
