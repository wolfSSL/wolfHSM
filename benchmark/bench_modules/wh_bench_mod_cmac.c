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
#include "wolfssl/wolfcrypt/cmac.h"

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFHSM_CFG_TEST_POSIX)
#include "port/posix/posix_transport_shm.h"
#endif /* WOLFHSM_CFG_DMA && WOLFHSM_CFG_TEST_POSIX */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)

static const uint8_t key128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                 0x09, 0xcf, 0x4f, 0x3c};

static const uint8_t key256[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0x6d, 0x3b, 0x73, 0xfd, 0x40, 0x21,
    0x11, 0x20, 0x62, 0xf4, 0x8f, 0x40, 0xde, 0xf9, 0x04, 0x4b, 0x77,
    0x3c, 0x82, 0x09, 0x01, 0x02, 0x42, 0x03, 0x04, 0x05, 0x06};


int _benchCmacAes(whClientContext* client, whBenchOpContext* ctx, int id,
                  const uint8_t* key, size_t keyLen, int devId)
{
    int      ret = 0;
    word32   outLen;
    whKeyId  keyId = WH_KEYID_ERASED;
    Cmac     cmac[1];
    char     keyLabel[] = "baby's first key";
    byte     tag[WC_CMAC_TAG_MAX_SZ];
    int      i;
    uint8_t* in = NULL;
    size_t   inLen;
    uint8_t* out = NULL;

    /* cache the key on the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, sizeof(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        return ret;
    }

    out = tag; /* default to using tag buffer on the stack */
#if defined(WOLFHSM_CFG_DMA)
    if (devId == WH_DEV_ID_DMA) {
        inLen = WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE;
#if defined(WOLFHSM_CFG_TEST_POSIX)
        if (ctx->transportType == WH_BENCH_TRANSPORT_POSIX_DMA) {
            /* if static memory was used with DMA then use XMALLOC */
            void* heap =
                posixTransportShm_GetDmaHeap(client->comm->transport_context);
            in = (uint8_t*)XMALLOC(inLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (in == NULL) {
                WH_BENCH_PRINTF("Failed to allocate memory for DMA\n");
                return WH_ERROR_NOSPACE;
            }
            out = (uint8_t*)XMALLOC(WC_CMAC_TAG_MAX_SZ, heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);
            if (out == NULL) {
                WH_BENCH_PRINTF("Failed to allocate memory for DMA\n");
                XFREE(in, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return WH_ERROR_NOSPACE;
            }
        }
        else {
            in = WH_BENCH_DMA_BUFFER;
        }
#endif /* WOLFHSM_CFG_TEST_POSIX */
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
    outLen = sizeof(tag);

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;

        /* initialize the cmac struct */
        ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, NULL, devId);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_InitCmac_ex %d\n", ret);
            goto exit;
        }

        /* set the keyId on the struct */
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_SetKeyIdAes %d\n", ret);
            goto exit;
        }

        /* Perform the CMAC operation */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        /* Oneshot CMAC through wolfCrypt API will always be most performant
         * implementation */
        ret = wc_AesCmacGenerate_ex(cmac, out, &outLen, in, inLen, key, keyLen,
                                    NULL, devId);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            goto exit;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_AesCmacGenerate_ex: %d\n", ret);
            goto exit;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            goto exit;
        }
    }

exit:
    /* Evict the key from the cache if it's not DMA */
    if (keyId != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            /* Log the error but continue with cleanup */
            WH_BENCH_PRINTF("Failed to evict key from cache: %d\n", evictRet);
            ret = evictRet;
        }
    }
#if defined(WOLFHSM_CFG_DMA)
#if defined(WOLFHSM_CFG_TEST_POSIX)
    if (devId == WH_DEV_ID_DMA &&
        ctx->transportType == WH_BENCH_TRANSPORT_POSIX_DMA) {
        /* if static memory was used with DMA then use XFREE */
        void* heap =
            posixTransportShm_GetDmaHeap(client->comm->transport_context);
        XFREE(in, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(out, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* WOLFHSM_CFG_TEST_POSIX */
#endif
    (void)wc_CmacFree(cmac);
    return ret;
}

int wh_Bench_Mod_CmacAes128(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
    (void)params;
    return _benchCmacAes(client, ctx, id, key128, sizeof(key128), WH_DEV_ID);
}

int wh_Bench_Mod_CmacAes128Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchCmacAes(client, ctx, id, key128, sizeof(key128),
                         WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_CmacAes256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
    (void)params;
    return _benchCmacAes(client, ctx, id, key256, sizeof(key256), WH_DEV_ID);
}

int wh_Bench_Mod_CmacAes256Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params)
{
#if defined(WOLFHSM_CFG_DMA)
    (void)params;
    return _benchCmacAes(client, ctx, id, key256, sizeof(key256),
                         WH_DEV_ID_DMA);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_CMAC && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT) */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
