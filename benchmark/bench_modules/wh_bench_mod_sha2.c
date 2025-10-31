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
#include "wolfhsm/wh_client_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/sha256.h"

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFHSM_CFG_TEST_POSIX)
#include "port/posix/posix_transport_shm.h"
#endif /* WOLFHSM_CFG_DMA && WOLFHSM_CFG_POSIX_TRANSPORT */

#if !defined(NO_SHA256)

int _benchSha256(whClientContext* client, whBenchOpContext* ctx, int id,
                 int devId)
{
    (void)client;

    int            ret = 0;
    wc_Sha256*     sha256 = NULL;
    wc_Sha256      sha256Stack;
    uint8_t        outStack[WC_SHA256_DIGEST_SIZE];
    uint8_t*       out;
    int            i                 = 0;
    int            sha256Initialized = 0;
    const uint8_t* in;
    size_t         inLen;

    sha256 = &sha256Stack;
    out    = outStack;

#if defined(WOLFHSM_CFG_DMA)
    if (devId == WH_DEV_ID_DMA) {
        inLen = WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE;
#if defined(WOLFHSM_CFG_TEST_POSIX)
        if (ctx->transportType == WH_BENCH_TRANSPORT_POSIX_DMA) {
            /* if static memory was used with DMA then use XMALLOC */
            void* heap =
                posixTransportShm_GetDmaHeap(client->comm->transport_context);
            in = XMALLOC(inLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (in == NULL) {
                WH_BENCH_PRINTF("Failed to allocate memory for DMA\n");
                return WH_ERROR_NOSPACE;
            }
            out = XMALLOC(WC_SHA256_DIGEST_SIZE, heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (out == NULL) {
                WH_BENCH_PRINTF("Failed to allocate memory for DMA\n");
                XFREE((uint8_t*)in, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return WH_ERROR_NOSPACE;
            }
        }
        else
#endif /* WOLFHSM_CFG_TEST_POSIX */
        {
            in = WH_BENCH_DMA_BUFFER;
        }
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

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFHSM_CFG_TEST_POSIX)
    if (devId == WH_DEV_ID_DMA &&
        ctx->transportType == WH_BENCH_TRANSPORT_POSIX_DMA) {
        /* if static memory was used with DMA then use XFREE */
        void* heap =
            posixTransportShm_GetDmaHeap(client->comm->transport_context);
        XFREE((uint8_t*)in, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(out, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif
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


#if defined(WOLFSSL_SHA224)

int _benchSha224(whClientContext* client, whBenchOpContext* ctx, int id,
                 int devId)
{
    (void)client;

    int            ret = 0;
    wc_Sha224      sha224[1];
    uint8_t        out[WC_SHA224_DIGEST_SIZE];
    int            i                 = 0;
    int            sha224Initialized = 0;
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
        initRet       = wc_InitSha224_ex(sha224, NULL, devId);
        updateRet     = wc_Sha224Update(sha224, in, inLen);
        finalRet      = wc_Sha224Final(sha224, out);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (initRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_InitSha224_ex %d\n", initRet);
            ret = initRet;
            break;
        }

        sha224Initialized = 1;

        if (updateRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha224Update %d\n", updateRet);
            ret = updateRet;
            break;
        }
        if (finalRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha224Final %d\n", finalRet);
            ret = finalRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    /* Only free SHA224 if it was initialized */
    if (sha224Initialized) {
        (void)wc_Sha224Free(sha224);
    }

    return ret;
}

int wh_Bench_Mod_Sha224(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha224(client, ctx, id, WH_DEV_ID);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Sha224Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha224(client, ctx, id, WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SHA224 */

#if defined(WOLFSSL_SHA384)

int _benchSha384(whClientContext* client, whBenchOpContext* ctx, int id,
                 int devId)
{
    (void)client;

    int            ret = 0;
    wc_Sha384      sha384[1];
    uint8_t        out[WC_SHA384_DIGEST_SIZE];
    int            i                 = 0;
    int            sha384Initialized = 0;
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
        initRet       = wc_InitSha384_ex(sha384, NULL, devId);
        updateRet     = wc_Sha384Update(sha384, in, inLen);
        finalRet      = wc_Sha384Final(sha384, out);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (initRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_InitSha384_ex %d\n", initRet);
            ret = initRet;
            break;
        }

        sha384Initialized = 1;

        if (updateRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha384Update %d\n", updateRet);
            ret = updateRet;
            break;
        }
        if (finalRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha384Final %d\n", finalRet);
            ret = finalRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    /* Only free SHA384 if it was initialized */
    if (sha384Initialized) {
        (void)wc_Sha384Free(sha384);
    }

    return ret;
}

int wh_Bench_Mod_Sha384(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha384(client, ctx, id, WH_DEV_ID);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Sha384Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha384(client, ctx, id, WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SHA384 */
#if defined(WOLFSSL_SHA512)

int _benchSha512(whClientContext* client, whBenchOpContext* ctx, int id,
                 int devId)
{
    (void)client;

    int            ret = 0;
    wc_Sha512      sha512[1];
    uint8_t        out[WC_SHA512_DIGEST_SIZE];
    int            i                 = 0;
    int            sha512Initialized = 0;
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
        initRet       = wc_InitSha512_ex(sha512, NULL, devId);
        updateRet     = wc_Sha512Update(sha512, in, inLen);
        finalRet      = wc_Sha512Final(sha512, out);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (initRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_InitSha512_ex %d\n", initRet);
            ret = initRet;
            break;
        }

        sha512Initialized = 1;

        if (updateRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha512Update %d\n", updateRet);
            ret = updateRet;
            break;
        }
        if (finalRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_Sha512Final %d\n", finalRet);
            ret = finalRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    /* Only free SHA512 if it was initialized */
    if (sha512Initialized) {
        (void)wc_Sha512Free(sha512);
    }

    return ret;
}

int wh_Bench_Mod_Sha512(whClientContext* client, whBenchOpContext* ctx, int id,
                        void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha512(client, ctx, id, WH_DEV_ID);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_Sha512Dma(whClientContext* client, whBenchOpContext* ctx,
                           int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha512(client, ctx, id, WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SHA512 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
