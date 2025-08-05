/*
 * Copyright (C) 2025 wolfSSL Inc.
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
#include "wh_bench_mod.h"

#include "wolfhsm/wh_error.h"

#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/sha256.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

#if !defined(NO_SHA256)

int _benchSha256(whClientContext* client, whBenchOpContext* ctx, int id,
                 int devId)
{
    (void)client;

    int            ret = 0;
    wc_Sha256      sha256[1];
    uint8_t        out[WC_SHA256_DIGEST_SIZE];
    int            i                 = 0;
    int            sha256Initialized = 0;
    const uint8_t* in;
    size_t         inLen;

#if defined(WOLFHSM_CFG_DMA)
    if (devId == WH_DEV_ID_DMA) {
        in    = WH_BENCH_DMA_BUFFER;
        inLen = WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE;
    }
    else
#endif
    {
        in    = WH_BENCH_DATA_IN_BUFFER;
        inLen = WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE;
#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
        memset(WH_BENCH_DATA_IN_BUFFER, 0xAA, inLen);
#endif
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        return ret;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;
        int initRet;
        int updateRet;
        int finalRet;

        /* Defer error checking until after all operations are complete */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        initRet       = wc_InitSha256_ex(sha256, NULL, devId);
        updateRet     = wc_Sha256Update(sha256, in, inLen);
        finalRet      = wc_Sha256Final(sha256, out);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (initRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_InitSha256_ex %d\n", initRet);
            ret = initRet;
            break;
        }

        sha256Initialized = 1;

        if (updateRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha256Update %d\n", updateRet);
            ret = updateRet;
            break;
        }
        if (finalRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha256Final %d\n", finalRet);
            ret = finalRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    /* Only free SHA256 if it was initialized */
    if (sha256Initialized) {
        (void)wc_Sha256Free(sha256);
    }

    return ret;
}

int wh_Bench_Mod_Sha256(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha256(client, ctx, id, WH_DEV_ID);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Sha256Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha256(client, ctx, id, WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* !defined(NO_SHA256) */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
