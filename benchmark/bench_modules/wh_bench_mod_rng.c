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
#include "wolfssl/wolfcrypt/random.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

#if !defined(WC_NO_RNG)

int _benchRng(whClientContext* client, whBenchOpContext* ctx, int id, int devId)
{
    (void)client;

    int      ret = 0;
    WC_RNG   rng;
    int      i              = 0;
    int      rngInitialized = 0;
    uint8_t* out            = WH_BENCH_DATA_OUT_BUFFER;
    word32   outLen         = WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE;

    ret = wc_InitRng_ex(&rng, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    rngInitialized = 1;

    ret = wh_Bench_SetDataSize(ctx, id, outLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        return ret;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;
        int genRet;

        /* Defer error checking until after all operations are complete */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        genRet        = wc_RNG_GenerateBlock(&rng, out, outLen);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (genRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_RNG_GenerateBlock %d\n", genRet);
            ret = genRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    if (rngInitialized) {
        wc_FreeRng(&rng);
    }

    return ret;
}

int wh_Bench_Mod_Rng(whClientContext* client, whBenchOpContext* ctx, int id,
                     void* params)
{
    (void)params;

    return _benchRng(client, ctx, id, WH_DEV_ID);
}

#endif /* !defined(WC_NO_RNG) */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
