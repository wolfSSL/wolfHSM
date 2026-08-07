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
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/sha3.h"

#if defined(WOLFSSL_SHA3)

/* All four SHA3 variants share the wc_Sha3 struct and differ only in digest
 * size and the Init/Update/Final/Free entry points. They are dispatched
 * through this table, mirroring _Sha3VariantOps in wh_server_crypto.c. Note
 * that the variants also differ in Keccak rate (144/136/104/72 bytes), which
 * is what drives the throughput differences between them. */
typedef struct {
    const char* name;
    uint32_t    digestSize;
    int (*initFn)(wc_Sha3* sha, void* heap, int devId);
    int (*updateFn)(wc_Sha3* sha, const byte* data, word32 len);
    int (*finalFn)(wc_Sha3* sha, byte* hash);
    void (*freeFn)(wc_Sha3* sha);
} whBenchSha3Variant;

#ifndef WOLFSSL_NOSHA3_224
static const whBenchSha3Variant benchSha3_224 = {
    "SHA3-224",         WC_SHA3_224_DIGEST_SIZE, wc_InitSha3_224,
    wc_Sha3_224_Update, wc_Sha3_224_Final,       wc_Sha3_224_Free};
#endif
#ifndef WOLFSSL_NOSHA3_256
static const whBenchSha3Variant benchSha3_256 = {
    "SHA3-256",         WC_SHA3_256_DIGEST_SIZE, wc_InitSha3_256,
    wc_Sha3_256_Update, wc_Sha3_256_Final,       wc_Sha3_256_Free};
#endif
#ifndef WOLFSSL_NOSHA3_384
static const whBenchSha3Variant benchSha3_384 = {
    "SHA3-384",         WC_SHA3_384_DIGEST_SIZE, wc_InitSha3_384,
    wc_Sha3_384_Update, wc_Sha3_384_Final,       wc_Sha3_384_Free};
#endif
#ifndef WOLFSSL_NOSHA3_512
static const whBenchSha3Variant benchSha3_512 = {
    "SHA3-512",         WC_SHA3_512_DIGEST_SIZE, wc_InitSha3_512,
    wc_Sha3_512_Update, wc_Sha3_512_Final,       wc_Sha3_512_Free};
#endif

static int _benchSha3(whClientContext* client, whBenchOpContext* ctx, int id,
                      int useDma, const whBenchSha3Variant* v)
{
    int            ret = 0;
    wc_Sha3        sha3[1];
    uint8_t        out[WC_SHA3_512_DIGEST_SIZE]; /* largest digest */
    int            i               = 0;
    int            sha3Initialized = 0;
    const uint8_t* in;
    size_t         inLen;

    (void)wh_Client_SetDmaMode(client, useDma);

#if defined(WOLFHSM_CFG_DMA)
    if (useDma) {
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
        initRet       = v->initFn(sha3, NULL, WH_CLIENT_DEVID(client));
        updateRet     = v->updateFn(sha3, in, (word32)inLen);
        finalRet      = v->finalFn(sha3, out);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (initRet != 0) {
            WH_BENCH_PRINTF("Failed to init %s %d\n", v->name, initRet);
            ret = initRet;
            break;
        }

        sha3Initialized = 1;

        if (updateRet != 0) {
            WH_BENCH_PRINTF("Failed to update %s %d\n", v->name, updateRet);
            ret = updateRet;
            break;
        }
        if (finalRet != 0) {
            WH_BENCH_PRINTF("Failed to final %s %d\n", v->name, finalRet);
            ret = finalRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

    /* Only free SHA3 if it was initialized */
    if (sha3Initialized) {
        v->freeFn(sha3);
    }

    return ret;
}

#ifndef WOLFSSL_NOSHA3_224

int wh_Bench_Mod_Sha3224(whClientContext* client, whBenchOpContext* ctx, int id,
                         void* params)
{
    (void)params;
    return _benchSha3(client, ctx, id, 0, &benchSha3_224);
}

int wh_Bench_Mod_Sha3224Dma(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha3(client, ctx, id, 1, &benchSha3_224);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* !WOLFSSL_NOSHA3_224 */

#ifndef WOLFSSL_NOSHA3_256

int wh_Bench_Mod_Sha3256(whClientContext* client, whBenchOpContext* ctx, int id,
                         void* params)
{
    (void)params;
    return _benchSha3(client, ctx, id, 0, &benchSha3_256);
}

int wh_Bench_Mod_Sha3256Dma(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha3(client, ctx, id, 1, &benchSha3_256);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* !WOLFSSL_NOSHA3_256 */

#ifndef WOLFSSL_NOSHA3_384

int wh_Bench_Mod_Sha3384(whClientContext* client, whBenchOpContext* ctx, int id,
                         void* params)
{
    (void)params;
    return _benchSha3(client, ctx, id, 0, &benchSha3_384);
}

int wh_Bench_Mod_Sha3384Dma(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha3(client, ctx, id, 1, &benchSha3_384);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* !WOLFSSL_NOSHA3_384 */

#ifndef WOLFSSL_NOSHA3_512

int wh_Bench_Mod_Sha3512(whClientContext* client, whBenchOpContext* ctx, int id,
                         void* params)
{
    (void)params;
    return _benchSha3(client, ctx, id, 0, &benchSha3_512);
}

int wh_Bench_Mod_Sha3512Dma(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchSha3(client, ctx, id, 1, &benchSha3_512);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* !WOLFSSL_NOSHA3_512 */

#endif /* WOLFSSL_SHA3 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
