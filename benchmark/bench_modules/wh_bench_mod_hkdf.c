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
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/sha256.h"

#if defined(HAVE_HKDF)


/* Output keying material size */
#define WH_BENCH_HKDF_OKM_SIZE 42

static int _benchHkdf(whClientContext* client, whBenchOpContext* ctx, int id,
                      int devId)
{
    /* Simple fixed inputs for HKDF to measure performance. The data mirrors
     * sizes from RFC 5869 test case 1 but we only care about timing here. */
    static const uint8_t hkdf_ikm[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    static const uint8_t hkdf_salt[] = {0x00, 0x01, 0x02, 0x03, 0x04,
                                        0x05, 0x06, 0x07, 0x08, 0x09,
                                        0x0a, 0x0b, 0x0c};
    static const uint8_t hkdf_info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                        0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    static const uint8_t label[]     = "hkdf-bench";

    int     ret = 0;
    whKeyId keyId;
    int     i;

    (void)devId;

    for (i = 0; i < WOLFHSM_CFG_BENCH_KG_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        keyId = WH_KEYID_ERASED;

        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret           = wh_Client_HkdfMakeCacheKey(
                      client, WC_SHA256, WH_KEYID_ERASED, hkdf_ikm,
                      (uint32_t)sizeof(hkdf_ikm), hkdf_salt, (uint32_t)sizeof(hkdf_salt),
                      hkdf_info, (uint32_t)sizeof(hkdf_info), &keyId, WH_NVM_FLAGS_NONE,
                      label, (uint32_t)sizeof(label), WH_BENCH_HKDF_OKM_SIZE);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_HkdfMakeCacheKey %d\n", ret);
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }

        /* Evict the cached key to free resources for next iteration */
        ret = wh_Client_KeyEvict(client, keyId);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_KeyEvict %d\n", ret);
            break;
        }
    }

    return ret;
}

int wh_Bench_Mod_HkdfSha256(whClientContext* client, whBenchOpContext* ctx,
                            int id, void* params)
{
    (void)params;
    return _benchHkdf(client, ctx, id, WH_DEV_ID);
}

#endif /* defined(HAVE_HKDF) */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
