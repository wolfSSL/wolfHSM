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
#include "wolfhsm/wh_message_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha3.h"

#if !defined(NO_HMAC)

static const uint8_t key[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const size_t keyLen = sizeof(key) - 1; /* -1 for null terminator */

static int _benchHmac(whClientContext* client, whBenchOpContext* ctx, int id,
                      int useDma, int macType)
{
    int            ret   = 0;
    whKeyId        keyId = WH_KEYID_ERASED;
    Hmac           hmac[1];
    char           keyLabel[] = "hmac bench key";
    uint8_t        out[WC_MAX_DIGEST_SIZE];
    word32         outLen;
    int            i               = 0;
    int            hmacInitialized = 0;
    const uint8_t* in;
    size_t         inLen;

    (void)wh_Client_SetDmaMode(client, useDma);

#if defined(WH_BENCH_CRYPTOCB_DMA)
    if (useDma) {
        in    = WH_BENCH_DMA_BUFFER;
        inLen = WOLFHSM_CFG_BENCH_DMA_BUFFER_SIZE;
    }
    else
#endif
    {
        in    = WH_BENCH_DATA_IN_BUFFER;
        inLen = WOLFHSM_CFG_BENCH_DATA_BUFFER_SIZE;
        /* Without DMA the whole message must fit in one request */
        if (inLen > WH_MESSAGE_CRYPTO_HMAC_MAX_INLINE_GENERATE_SZ) {
            inLen = WH_MESSAGE_CRYPTO_HMAC_MAX_INLINE_GENERATE_SZ;
        }
#if defined(WOLFHSM_CFG_BENCH_INIT_DATA_BUFFERS)
        memset(WH_BENCH_DATA_IN_BUFFER, 0xAA, inLen);
#endif
    }

    ret = wh_Bench_SetDataSize(ctx, id, inLen);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Bench_SetDataSize %d\n", ret);
        return ret;
    }

    ret =
        wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_SIGN, (uint8_t*)keyLabel,
                           sizeof(keyLabel), key, (uint16_t)keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_KeyCache %d\n", ret);
        return ret;
    }

    ret = wc_HmacInit(hmac, NULL, WH_CLIENT_DEVID(client));
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_HmacInit %d\n", ret);
        goto exit;
    }
    hmacInitialized = 1;

    ret = wh_Client_HmacSetKeyId(hmac, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wh_Client_HmacSetKeyId %d\n", ret);
        goto exit;
    }

    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {
        int benchStartRet;
        int benchStopRet;
        int genRet;

        outLen = sizeof(out);

        /* Defer error checking until after all operations are complete */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        /* A NULL key selects the key ID in the struct */
        genRet =
            wc_HmacGenerate_ex(hmac, macType, out, &outLen, in, (word32)inLen,
                               NULL, 0, NULL, WH_CLIENT_DEVID(client));
        benchStopRet = wh_Bench_StopOp(ctx, id);

        /* Check for errors after all operations are complete */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp: %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (genRet != 0) {
            WH_BENCH_PRINTF("Failed to wc_HmacGenerate_ex %d\n", genRet);
            ret = genRet;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp: %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

exit:
    if (hmacInitialized) {
        (void)wc_HmacFree(hmac);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_KeyEvict %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }

    return ret;
}

#if !defined(NO_SHA256)

int wh_Bench_Mod_HmacSha256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
    (void)params;
    return _benchHmac(client, ctx, id, 0, WC_SHA256);
}

int wh_Bench_Mod_HmacSha256Dma(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA)
    (void)params;
    return _benchHmac(client, ctx, id, 1, WC_SHA256);
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

#ifndef WOLFSSL_NOSHA3_224

int wh_Bench_Mod_HmacSha3224(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)params;
    return _benchHmac(client, ctx, id, 0, WC_SHA3_224);
}

int wh_Bench_Mod_HmacSha3224Dma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA)
    (void)params;
    return _benchHmac(client, ctx, id, 1, WC_SHA3_224);
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

int wh_Bench_Mod_HmacSha3256(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)params;
    return _benchHmac(client, ctx, id, 0, WC_SHA3_256);
}

int wh_Bench_Mod_HmacSha3256Dma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA)
    (void)params;
    return _benchHmac(client, ctx, id, 1, WC_SHA3_256);
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

int wh_Bench_Mod_HmacSha3384(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)params;
    return _benchHmac(client, ctx, id, 0, WC_SHA3_384);
}

int wh_Bench_Mod_HmacSha3384Dma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA)
    (void)params;
    return _benchHmac(client, ctx, id, 1, WC_SHA3_384);
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

int wh_Bench_Mod_HmacSha3512(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)params;
    return _benchHmac(client, ctx, id, 0, WC_SHA3_512);
}

int wh_Bench_Mod_HmacSha3512Dma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA)
    (void)params;
    return _benchHmac(client, ctx, id, 1, WC_SHA3_512);
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

#endif /* !defined(NO_HMAC) */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
