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

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/sha256.h"

#if !defined(NO_HMAC)

#if !defined(NO_SHA256)

static const uint8_t key[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const size_t keyLen = sizeof(key) - 1; /* -1 for null terminator */

int _benchHmacSha256(whClientContext* client, whBenchOpContext* ctx, int id,
                     int devId)
{
    (void)client;

    int            ret = 0;
    Hmac           hmac[1];
    uint8_t        out[WC_SHA256_DIGEST_SIZE];
    int            i               = 0;
    int            hmacInitialized = 0;
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
        int setKeyRet;
        int updateRet;
        int finalRet;

        /* Defer error checking until after all operations are complete */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        initRet       = wc_HmacInit(hmac, NULL, devId);
        setKeyRet     = wc_HmacSetKey(hmac, WC_SHA256, key, (word32)keyLen);
        updateRet     = wc_HmacUpdate(hmac, in, inLen);
        finalRet      = wc_HmacFinal(hmac, out);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (initRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_HmacInit %d\n", initRet);
            ret = initRet;
            break;
        }

        hmacInitialized = 1;

        if (setKeyRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_HmacSetKey %d\n", setKeyRet);
            ret = setKeyRet;
            break;
        }
        if (updateRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_HmacUpdate %d\n", updateRet);
            ret = updateRet;
            break;
        }
        if (finalRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_HmacFinal %d\n", finalRet);
            ret = finalRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    /* Only free HMAC if it was initialized */
    if (hmacInitialized) {
        (void)wc_HmacFree(hmac);
    }

    return ret;
}

int wh_Bench_Mod_HmacSha256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
    (void)params;
    return _benchHmacSha256(client, ctx, id, WH_DEV_ID);
}

int wh_Bench_Mod_HmacSha256Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchHmacSha256(client, ctx, id, WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* !defined(NO_SHA256) */

#if defined(WOLFSSL_SHA3)

int wh_Bench_Mod_HmacSha3256(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
}

int wh_Bench_Mod_HmacSha3256Dma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params)
{
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
}

#endif /* WOLFSSL_SHA3 */

#endif /* !defined(NO_HMAC) */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
