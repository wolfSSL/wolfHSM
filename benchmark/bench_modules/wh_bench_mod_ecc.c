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

#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"

#if defined(HAVE_ECC)

/* hardcoded DER-encoded ECC keys for benchmarking */
static const uint8_t aliceKeyDer[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xdc, 0x6e, 0x0d, 0x56,
    0xc3, 0xdf, 0x2c, 0xe9, 0xcf, 0xbe, 0xe5, 0x50, 0x9c, 0xe7, 0x9d,
    0x3d, 0x03, 0x49, 0x3c, 0x60, 0xa4, 0xbb, 0xfb, 0x6d, 0x85, 0xa3,
    0xe0, 0x82, 0x9a, 0xe3, 0xd7, 0x99, 0xa0, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x20, 0x0f, 0x05, 0xb9, 0x48, 0x5a, 0x7f, 0x2e, 0x70,
    0x27, 0xef, 0x6f, 0xa8, 0x3a, 0xa9, 0x4c, 0xbd, 0xde, 0x3b, 0xf0,
    0xba, 0x9e, 0xfb, 0x94, 0x34, 0x30, 0xfb, 0xd6, 0xa4, 0xac, 0x9e,
    0x85, 0x73, 0x00, 0x24, 0x64, 0x29, 0xb8, 0xed, 0xdd, 0xb9, 0x36,
    0xe0, 0x99, 0x8f, 0xf3, 0xf9, 0xdc, 0xe5, 0xb2, 0x70, 0x99, 0xa4,
    0x44, 0x19, 0xc7, 0x3d, 0xe7, 0x18, 0x59, 0xf7, 0xb8, 0xd6, 0x90};

static const uint8_t bobKeyDer[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x4a, 0x75, 0xa6, 0xd9,
    0x22, 0xd6, 0x65, 0xab, 0xde, 0x75, 0xbb, 0xe6, 0x63, 0x20, 0x06,
    0xd6, 0x85, 0x30, 0x14, 0x9b, 0x7f, 0xee, 0xf3, 0x7d, 0xb7, 0x39,
    0x95, 0x0c, 0x50, 0xb3, 0x1f, 0xba, 0xa0, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0x66, 0x16, 0xeb, 0x28, 0xbb, 0xba, 0xb4, 0x44, 0xcc,
    0xe2, 0x60, 0x1f, 0x85, 0x59, 0x8c, 0x3b, 0xed, 0x24, 0x8c, 0x05,
    0xbe, 0xbb, 0x22, 0x34, 0x3d, 0x0c, 0xc7, 0xb2, 0xda, 0x33, 0xf3,
    0xb7, 0x8b, 0x2b, 0xda, 0x20, 0xed, 0x75, 0xb0, 0xac, 0xeb, 0xbb,
    0xa4, 0xf8, 0xcd, 0xfe, 0x31, 0xce, 0x42, 0xa9, 0x86, 0xeb, 0xaf,
    0x40, 0x10, 0x1d, 0x99, 0x09, 0xae, 0xc4, 0xb6, 0x78, 0xf7, 0x6e};

/* Helper function for ECC sign benchmark */
int _benchEccSign(whClientContext* client, whBenchOpContext* ctx, int id,
                  const uint8_t* key, size_t keyLen, int curveSize, int devId)
{
    int     ret = 0;
    word32  sigLen;
    ecc_key eccKey[1] = {0};
    WC_RNG  rng[1]    = {0};
    byte    hash[32];
    byte    signature[128];
    int     i;
    int     initialized_rng = 0;
    int     initialized_key = 0;
    whKeyId keyId           = WH_KEYID_ERASED;
    char    keyLabel[]      = "bench-key";

    /* Initialize dummy hash data */
    for (i = 0; i < (int)sizeof(hash); i++) {
        hash[i] = (byte)i;
    }

    /* Initialize the RNG */
    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    initialized_rng = 1;

    /* Cache key in the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, strlen(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache key %d\n", ret);
        goto exit;
    }

    /* Initialize the ECC key */
    ret = wc_ecc_init_ex(eccKey, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    initialized_key = 1;

    /* Set key ID and curve */
    ret = wh_Client_EccSetKeyId(eccKey, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set key ID %d\n", ret);
        goto exit;
    }
    ret = wc_ecc_set_curve(eccKey, curveSize, -1);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set curve %d\n", ret);
        goto exit;
    }

    /* Benchmark the signing operation */
    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        sigLen = sizeof(signature);

        /* Time only the sign hash operation */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret = wc_ecc_sign_hash(hash, sizeof(hash), signature, &sigLen, rng,
                               eccKey);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_ecc_sign_hash %d\n", ret);
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

exit:
    /* Clean up resources */
    if (initialized_key) {
        wc_ecc_free(eccKey);
    }

    if (initialized_rng) {
        wc_FreeRng(rng);
    }

    /* Evict key from HSM */
    if (keyId != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to evict key %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }

    return ret;
}

/* Helper function for ECC verify benchmark */
int _benchEccVerify(whClientContext* client, whBenchOpContext* ctx, int id,
                    const uint8_t* key, size_t keyLen, int curveSize, int devId)
{
    int     ret = 0;
    word32  sigLen;
    ecc_key eccKey[1] = {0};
    WC_RNG  rng[1]    = {0};
    byte    hash[32];
    byte    signature[128];
    int     i;
    int     verify_status   = 0;
    int     initialized_rng = 0;
    int     initialized_key = 0;
    whKeyId keyId           = WH_KEYID_ERASED;
    char    keyLabel[]      = "bench-key";

    /* Initialize dummy hash data */
    for (i = 0; i < (int)sizeof(hash); i++) {
        hash[i] = (byte)i;
    }

    /* Initialize the RNG */
    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    initialized_rng = 1;

    /* Cache the key in the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, strlen(keyLabel),
                             (uint8_t*)key, keyLen, &keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache key %d\n", ret);
        goto exit;
    }

    /* Initialize the ECC key */
    ret = wc_ecc_init_ex(eccKey, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
        goto exit;
    }
    initialized_key = 1;

    /* Set key ID and curve */
    ret = wh_Client_EccSetKeyId(eccKey, keyId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set key ID %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_set_curve(eccKey, curveSize, -1);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set curve %d\n", ret);
        goto exit;
    }

    /* Generate a signature to verify before benchmarking */
    sigLen = sizeof(signature);
    ret = wc_ecc_sign_hash(hash, sizeof(hash), signature, &sigLen, rng, eccKey);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_ecc_sign_hash %d\n", ret);
        goto exit;
    }

    /* Benchmark the verification operation */
    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        /* Time only the verify hash operation */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret          = wc_ecc_verify_hash(signature, sigLen, hash, sizeof(hash),
                                          &verify_status, eccKey);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_ecc_verify_hash %d\n", ret);
            break;
        }
        if (verify_status != 1) {
            WH_BENCH_PRINTF("ECC verification failed\n");
            ret = -1;
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

exit:
    /* Clean up resources */
    if (initialized_key) {
        wc_ecc_free(eccKey);
    }

    if (initialized_rng) {
        wc_FreeRng(rng);
    }

    /* Evict key from HSM */
    if (keyId != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to evict key %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }

    return ret;
}

/* Helper function for ECC key generation benchmark */
int _benchEccKeyGen(whClientContext* client, whBenchOpContext* ctx, int id,
                    int curveSize, int devId)
{
    (void)client;

    int     ret    = 0;
    ecc_key key[1] = {0};
    WC_RNG  rng[1] = {0};
    int     i;
    int     initialized_rng = 0;
    int     initialized_key = 0;

    /* Initialize the RNG for key generation */
    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    initialized_rng = 1;

    /* Benchmark the key generation */
    for (i = 0; i < WOLFHSM_CFG_BENCH_KG_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        /* Initialize the ECC key before each iteration */
        ret = wc_ecc_init_ex(key, NULL, devId);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_ecc_init_ex %d\n", ret);
            break;
        }

        initialized_key = 1;

        /* Start timing only the key generation */
        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret           = wc_ecc_make_key(rng, curveSize, key);
        benchStopRet  = wh_Bench_StopOp(ctx, id);

        /* Check for errors after timing */
        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_ecc_make_key %d\n", ret);
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }

        /* Free the key after each iteration */
        wc_ecc_free(key);
        initialized_key = 0;
    }

exit:
    /* Free resources */
    if (initialized_key) {
        wc_ecc_free(key);
    }

    if (initialized_rng) {
        wc_FreeRng(rng);
    }

    return ret;
}

/* Helper function for ECC ECDH (shared secret) benchmark */
int _benchEccEcdh(whClientContext* client, whBenchOpContext* ctx, int id,
                  const uint8_t* aliceKeyData, size_t aliceKeyLen,
                  const uint8_t* bobKeyData, size_t bobKeyLen, int curveSize,
                  int devId)
{
    int     ret = 0;
    word32  outLen;
    ecc_key aliceKey[1] = {0};
    ecc_key bobKey[1]   = {0};
    WC_RNG  rng[1]      = {0};
    byte    sharedSecret[32];
    int     i;
    int     initialized_rng   = 0;
    int     initialized_alice = 0;
    int     initialized_bob   = 0;
    whKeyId keyIdAlice        = WH_KEYID_ERASED;
    whKeyId keyIdBob          = WH_KEYID_ERASED;
    char    keyLabel[]        = "bench-key";

    /* Initialize RNG for potential operations that require it */
    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto exit;
    }
    initialized_rng = 1;

    /* Cache Alice's key in the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, strlen(keyLabel),
                             (uint8_t*)aliceKeyData, aliceKeyLen, &keyIdAlice);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache Alice's key %d\n", ret);
        goto exit;
    }

    /* Cache Bob's key in the HSM */
    ret = wh_Client_KeyCache(client, 0, (uint8_t*)keyLabel, strlen(keyLabel),
                             (uint8_t*)bobKeyData, bobKeyLen, &keyIdBob);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache Bob's key %d\n", ret);
        goto exit;
    }

    /* Initialize Alice's key structure */
    ret = wc_ecc_init_ex(aliceKey, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize Alice's key %d\n", ret);
        goto exit;
    }
    initialized_alice = 1;

    /* Set Alice's key ID and curve */
    ret = wh_Client_EccSetKeyId(aliceKey, keyIdAlice);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set Alice's key ID %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_set_curve(aliceKey, curveSize, -1);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set Alice's curve %d\n", ret);
        goto exit;
    }

    /* Initialize Bob's key structure */
    ret = wc_ecc_init_ex(bobKey, NULL, devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize Bob's key %d\n", ret);
        goto exit;
    }
    initialized_bob = 1;

    /* Set Bob's key ID and curve */
    ret = wh_Client_EccSetKeyId(bobKey, keyIdBob);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set Bob's key ID %d\n", ret);
        goto exit;
    }

    ret = wc_ecc_set_curve(bobKey, curveSize, -1);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set Bob's curve %d\n", ret);
        goto exit;
    }

    /* Benchmark the shared secret generation */
    for (i = 0; i < WOLFHSM_CFG_BENCH_PK_ITERS && ret == 0; i++) {
        int benchStartRet;
        int benchStopRet;

        outLen = sizeof(sharedSecret);

        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret = wc_ecc_shared_secret(aliceKey, bobKey, sharedSecret, &outLen);
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_ecc_shared_secret %d\n", ret);
            break;
        }
        if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
            break;
        }
    }

exit:
    /* Clean up resources */
    if (initialized_alice) {
        wc_ecc_free(aliceKey);
    }

    if (initialized_bob) {
        wc_ecc_free(bobKey);
    }

    if (initialized_rng) {
        wc_FreeRng(rng);
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

int wh_Bench_Mod_EccP256Sign(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)params;
    return _benchEccSign(client, ctx, id, aliceKeyDer, sizeof(aliceKeyDer), 32,
                         WH_DEV_ID);
}

int wh_Bench_Mod_EccP256SignDma(whClientContext* client, whBenchOpContext* ctx,
                                int id, void* params)
{
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
}

int wh_Bench_Mod_EccP256Verify(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params)
{
    (void)params;
    return _benchEccVerify(client, ctx, id, aliceKeyDer, sizeof(aliceKeyDer),
                           32, WH_DEV_ID);
}

int wh_Bench_Mod_EccP256VerifyDma(whClientContext*  client,
                                  whBenchOpContext* ctx, int id, void* params)
{
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
}

int wh_Bench_Mod_EccP256KeyGen(whClientContext* client, whBenchOpContext* ctx,
                               int id, void* params)
{
    (void)params;
    return _benchEccKeyGen(client, ctx, id, 32, WH_DEV_ID);
}

int wh_Bench_Mod_EccP256Ecdh(whClientContext* client, whBenchOpContext* ctx,
                             int id, void* params)
{
    (void)params;
    return _benchEccEcdh(client, ctx, id, aliceKeyDer, sizeof(aliceKeyDer),
                         bobKeyDer, sizeof(bobKeyDer), 32, WH_DEV_ID);
}

#endif /* HAVE_ECC */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
