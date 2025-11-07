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
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/curve25519.h"

#if defined(HAVE_CURVE25519)

uint8_t key1_der[] = {
    0x30, 0x50, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22, 0x04, 0x20, 0x6b, 0x27, 0x7c, 0xb8, 0x16, 0x23, 0x41, 0x0e,
    0xf7, 0xb4, 0x45, 0x5f, 0xd2, 0x9f, 0x0e, 0xc3, 0x35, 0x2a, 0xc4, 0xf4,
    0xec, 0x2c, 0x76, 0x24, 0x83, 0x8a, 0x4d, 0x45, 0x05, 0x12, 0xb8, 0x78,
    0x81, 0x20, 0x17, 0x50, 0xb1, 0x65, 0x97, 0xe9, 0xcd, 0x64, 0x3b, 0x43,
    0xf0, 0xc9, 0x1c, 0x3c, 0x5f, 0x81, 0xdd, 0xe7, 0xb9, 0x87, 0x15, 0x2c,
    0x04, 0xaf, 0x1a, 0x0c, 0x6a, 0x12, 0x0f, 0xf2, 0xf6, 0x50};


uint8_t key2_der[] = {
    0x30, 0x50, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22, 0x04, 0x20, 0x79, 0x09, 0xf3, 0x0c, 0x34, 0x3b, 0xc6, 0x41,
    0xb2, 0x33, 0xcc, 0x70, 0xbb, 0xf0, 0xc5, 0xdb, 0xbe, 0xa7, 0xc1, 0x1b,
    0xcb, 0x17, 0x4a, 0x33, 0x3f, 0x6f, 0x02, 0xab, 0x70, 0x75, 0x82, 0x58,
    0x81, 0x20, 0x45, 0x50, 0xbb, 0x54, 0x91, 0xe4, 0x02, 0x5a, 0xd3, 0x41,
    0xa7, 0xad, 0x73, 0x60, 0x34, 0x47, 0x39, 0x63, 0xbd, 0x35, 0xfb, 0x63,
    0x07, 0xaa, 0xc5, 0xa0, 0x98, 0x61, 0x85, 0x31, 0x72, 0xd9};


int wh_Bench_Mod_Curve25519KeyGen(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)client;
    (void)params;

    int            ret    = 0;
    curve25519_key key[1] = {0};
    WC_RNG         rng[1] = {0};
    int            i;
    int            initialized_rng = 0;
    int            initialized_key = 0;

    /* Initialize the RNG for key generation */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    initialized_rng = 1;

    /* Benchmark the key generation */
    for (i = 0; i < WOLFHSM_CFG_BENCH_KG_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        /* Initialize the Curve25519 key before each iteration */
        ret = wc_curve25519_init_ex(key, NULL, WH_DEV_ID);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_curve25519_init_ex %d\n", ret);
            break;
        }

        initialized_key = 1;

        /* Start timing only the key generation */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret           = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, key);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after timing */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_curve25519_make_key %d\n", ret);
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }

        /* Free the key after each iteration */
        wc_curve25519_free(key);
        initialized_key = 0;
    }

    /* Free resources */
    if (initialized_key) {
        wc_curve25519_free(key);
    }

    if (initialized_rng) {
        wc_FreeRng(rng);
    }

    return ret;
}

int wh_Bench_Mod_Curve25519SharedSecret(whClientContext*  client,
                                        whBenchOpContext* ctx, int id,
                                        void* params)
{
    (void)params;

    int            ret = 0;
    word32         outLen;
    curve25519_key keyAlice[1] = {0};
    curve25519_key keyBob[1]   = {0};
    uint8_t        sharedSecret[CURVE25519_KEYSIZE];
    int            i;
    int            initialized_alice = 0;
    int            initialized_bob   = 0;
    whKeyId        keyIdAlice        = WH_KEYID_ERASED;
    whKeyId        keyIdBob          = WH_KEYID_ERASED;
    char           keyLabel[]        = "bench-key";

    /* Cache Alice's key in the HSM */
    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, (uint8_t*)keyLabel,
                             strlen(keyLabel), key1_der, sizeof(key1_der),
                             &keyIdAlice);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache Alice's key %d\n", ret);
        return ret;
    }

    /* Cache Bob's key in the HSM */
    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, (uint8_t*)keyLabel,
                             strlen(keyLabel), key2_der, sizeof(key2_der),
                             &keyIdBob);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache Bob's key %d\n", ret);
        wh_Client_KeyEvict(client, keyIdAlice);
        return ret;
    }

    /* Initialize Alice's key structure */
    ret = wc_curve25519_init_ex(keyAlice, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize Alice's key %d\n", ret);
        wh_Client_KeyEvict(client, keyIdAlice);
        wh_Client_KeyEvict(client, keyIdBob);
        return ret;
    }
    initialized_alice = 1;

    /* Set Alice's key ID */
    ret = wh_Client_Curve25519SetKeyId(keyAlice, keyIdAlice);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set Alice's key ID %d\n", ret);
        goto exit;
    }

    /* Initialize Bob's key structure */
    ret = wc_curve25519_init_ex(keyBob, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize Bob's key %d\n", ret);
        goto exit;
    }
    initialized_bob = 1;

    /* Set Bob's key ID */
    ret = wh_Client_Curve25519SetKeyId(keyBob, keyIdBob);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set Bob's key ID %d\n", ret);
        goto exit;
    }

    /* Benchmark the shared secret generation */
    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        outLen = CURVE25519_KEYSIZE;

        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret = wc_curve25519_shared_secret(keyAlice, keyBob, sharedSecret,
                                          &outLen);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_curve25519_shared_secret %d\n", ret);
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

exit:
    if (initialized_alice) {
        wc_curve25519_free(keyAlice);
    }

    if (initialized_bob) {
        wc_curve25519_free(keyBob);
    }

    /* Evict keys from HSM */
    if (keyIdAlice != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(client, keyIdAlice);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to evict Alice's key %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }

    if (keyIdBob != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(client, keyIdBob);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to evict Bob's key %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }

    return ret;
}

#endif /* HAVE_CURVE25519 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
