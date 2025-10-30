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

#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/kdf.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

#if defined(HAVE_CMAC_KDF) && defined(WOLFSSL_CMAC)

#define WH_BENCH_CMAC_KDF_OUT_SIZE 40

static int _benchCmacKdf(whClientContext* client, whBenchOpContext* ctx, int id,
                         int devId)
{
    /* Derivation inputs mirror the unit test vectors to provide realistic
     * message sizes while keeping the benchmark deterministic. */
    static const uint8_t cmacKdfSalt[] = {
        0x20, 0x51, 0xaf, 0x34, 0x76, 0x2e, 0xbe, 0x55, 0x6f, 0x72, 0xa5, 0xc6,
        0xed, 0xc7, 0x77, 0x1e, 0xb9, 0x24, 0x5f, 0xad, 0x76, 0xf0, 0x34, 0xbe};
    static const uint8_t cmacKdfZ[] = {
        0xae, 0x8e, 0x93, 0xc9, 0xc9, 0x91, 0xcf, 0x89, 0x6a, 0x49, 0x1a,
        0x89, 0x07, 0xdf, 0x4e, 0x4b, 0xe5, 0x18, 0x6a, 0xe4, 0x96, 0xcd,
        0x34, 0x0d, 0xc1, 0x9b, 0x23, 0x78, 0x21, 0xdb, 0x7b, 0x60};
    static const uint8_t cmacKdfFixedInfo[] = {
        0xa2, 0x59, 0xca, 0xe2, 0xc4, 0xa3, 0x6b, 0x89, 0x56, 0x3c, 0xb1, 0x48,
        0xc7, 0x82, 0x51, 0x34, 0x3b, 0xbf, 0xab, 0xdc, 0x13, 0xca, 0x7a, 0xc2,
        0x17, 0x1c, 0x2e, 0xb6, 0x02, 0x1f, 0x44, 0x77, 0xfe, 0xa3, 0x3b, 0x28,
        0x72, 0x4d, 0xa7, 0x21, 0xee, 0x08, 0x7b, 0xff, 0xd7, 0x94, 0xa1, 0x56,
        0x37, 0x54, 0xb4, 0x25, 0xa8, 0xd0, 0x9b, 0x3e, 0x0d, 0xa5, 0xff, 0xed};
    static const uint8_t label[] = "cmac-kdf-bench";

    int     ret = 0;
    whKeyId keyId;
    int     i;

    (void)devId;

    for (i = 0; i < WOLFHSM_CFG_BENCH_KG_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        keyId = WH_KEYID_ERASED;

        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret           = wh_Client_CmacKdfMakeCacheKey(
                      client, WH_KEYID_ERASED, cmacKdfSalt, (uint32_t)sizeof(cmacKdfSalt),
                      WH_KEYID_ERASED, cmacKdfZ, (uint32_t)sizeof(cmacKdfZ),
                      cmacKdfFixedInfo, (uint32_t)sizeof(cmacKdfFixedInfo), &keyId,
                      WH_NVM_FLAGS_NONE, label, (uint32_t)sizeof(label),
                      WH_BENCH_CMAC_KDF_OUT_SIZE);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wh_Client_CmacKdfMakeCacheKey %d\n",
                            ret);
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

int wh_Bench_Mod_CmacKdf(whClientContext* client, whBenchOpContext* ctx, int id,
                         void* params)
{
    (void)params;
    return _benchCmacKdf(client, ctx, id, WH_DEV_ID);
}

#endif /* HAVE_CMAC_KDF && WOLFSSL_CMAC */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
