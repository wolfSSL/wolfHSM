/*
 * Copyright (C) 2026 wolfSSL Inc.
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
/*
 * test-refactor/client-server/wh_test_crypto_slhdsa.c
 *
 * SLH-DSA tests routed through the server.
 *
 * Parameter sets are chosen around the comm buffer: an SLH-DSA signature is
 * 7856 bytes at the smallest parameter set and 49856 at the largest, so the
 * comm-buffer path only works for 128s and everything else needs DMA. The
 * 'f' variant signs roughly twenty times faster, so the DMA tests use it.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/wc_slhdsa.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLFSSL_HAVE_SLHDSA

#if defined(WOLFSSL_SLHDSA_PARAM_128S) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
#define WH_TEST_SLHDSA_COMM_PARAM SLHDSA_SHAKE128S
#define WH_TEST_SLHDSA_COMM_SIG_LEN WC_SLHDSA_SHAKE128S_SIG_LEN
#endif

#if defined(WOLFSSL_SLHDSA_PARAM_128F) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
#define WH_TEST_SLHDSA_FAST_PARAM SLHDSA_SHAKE128F
#define WH_TEST_SLHDSA_FAST_SIG_LEN WC_SLHDSA_SHAKE128F_SIG_LEN
#endif

#ifdef WH_TEST_SLHDSA_COMM_PARAM

/* Drives the crypto callback through the plain wolfCrypt API, which is how an
 * application reaches the HSM. The key is ephemeral so the whole generate,
 * sign and verify chain crosses the wire. */
static int _whTest_SlhDsaWolfCryptImpl(whClientContext* ctx, int devId)
{
    int       ret      = 0;
    int       verified = 0;
    SlhDsaKey key[1];
    WC_RNG    rng[1];
    byte      msg[] = "Test message for SLH-DSA signing";
    byte      sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
    word32    sigSz = sizeof(sig);

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize SLH-DSA key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    if (ret == 0) {
        ret = wc_SlhDsaKey_MakeKey(key, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate SLH-DSA key: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_SlhDsaKey_Sign(key, NULL, 0, msg, sizeof(msg), sig, &sigSz,
                                rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with SLH-DSA: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_SlhDsaKey_Verify(key, NULL, 0, msg, sizeof(msg), sig, sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify SLH-DSA signature: %d\n", ret);
        }
        else {
            verified = 1;
        }
    }
    /* Tamper check: a corrupted signature must not verify. */
    if ((ret == 0) && verified) {
        sig[0] ^= 1;
        ret = wc_SlhDsaKey_Verify(key, NULL, 0, msg, sizeof(msg), sig, sigSz);
        if (ret == 0) {
            WH_ERROR_PRINT("SLH-DSA verified a tampered signature\n");
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SLH-DSA WOLFCRYPT DEVID=0x%X SUCCESS\n", devId);
    }

    wc_SlhDsaKey_Free(key);
    (void)wc_FreeRng(rng);
    return ret;
}

/* Ephemeral generate plus the pure, context and pre-hash signing shapes over
 * the comm buffer. */
static int _whTest_CryptoSlhDsaClient(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    SlhDsaKey key[1];

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize SLH-DSA key: %d\n", ret);
        return ret;
    }

    ret = wh_Client_SlhDsaMakeExportKey(ctx, WH_TEST_SLHDSA_COMM_PARAM, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate SLH-DSA key: %d\n", ret);
        goto done;
    }

    {
        byte   msg[] = "Test message for non-DMA SLH-DSA";
        byte   sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;

        ret = wh_Client_SlhDsaSign(ctx, msg, sizeof(msg), sig, &sigLen, key,
                                   NULL, 0, WC_HASH_TYPE_NONE, NULL, 0, 1, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign using SLH-DSA non-DMA: %d\n", ret);
            goto done;
        }
        if (sigLen != WH_TEST_SLHDSA_COMM_SIG_LEN) {
            WH_ERROR_PRINT("SLH-DSA signature length %u, expected %u\n",
                           (unsigned)sigLen,
                           (unsigned)WH_TEST_SLHDSA_COMM_SIG_LEN);
            ret = WH_TEST_FAIL;
            goto done;
        }

        ret = wh_Client_SlhDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                     &verified, key, NULL, 0,
                                     WC_HASH_TYPE_NONE, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify SLH-DSA non-DMA: %d\n", ret);
            goto done;
        }
        if (!verified) {
            WH_ERROR_PRINT("SLH-DSA non-DMA verification failed\n");
            ret = WH_TEST_FAIL;
            goto done;
        }

        /* A tampered signature must come back as a result, not an error */
        sig[0] ^= 0xFF;
        ret = wh_Client_SlhDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                     &verified, key, NULL, 0,
                                     WC_HASH_TYPE_NONE, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Verify with modified sig returned %d\n", ret);
            goto done;
        }
        if (verified) {
            WH_ERROR_PRINT("SLH-DSA non-DMA verified a bad signature\n");
            ret = WH_TEST_FAIL;
            goto done;
        }
    }

    /* FIPS 205 context string */
    {
        byte       msg[]    = "Context test message non-DMA";
        const byte context[] = {'w', 'o', 'l', 'f', 'H', 'S', 'M'};
        byte       sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
        word32     sigLen   = sizeof(sig);
        int        verified = 0;

        ret = wh_Client_SlhDsaSign(ctx, msg, sizeof(msg), sig, &sigLen, key,
                                   context, (byte)sizeof(context),
                                   WC_HASH_TYPE_NONE, NULL, 0, 1, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with context: %d\n", ret);
            goto done;
        }

        ret = wh_Client_SlhDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                     &verified, key, context,
                                     (byte)sizeof(context), WC_HASH_TYPE_NONE,
                                     0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify with context: %d\n", ret);
            goto done;
        }
        if (!verified) {
            WH_ERROR_PRINT("SLH-DSA context verification failed\n");
            ret = WH_TEST_FAIL;
            goto done;
        }

        /* The context is bound into the signature, so a different one fails */
        ret = wh_Client_SlhDsaVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                     &verified, key, NULL, 0,
                                     WC_HASH_TYPE_NONE, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Verify with dropped context returned %d\n", ret);
            goto done;
        }
        if (verified) {
            WH_ERROR_PRINT("SLH-DSA verified across differing contexts\n");
            ret = WH_TEST_FAIL;
            goto done;
        }
    }

#ifndef NO_SHA256
    /* HashSLH-DSA over a caller-supplied digest */
    {
        byte   digest[WC_SHA256_DIGEST_SIZE];
        byte   sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;

        memset(digest, 0x5A, sizeof(digest));

        ret = wh_Client_SlhDsaSign(ctx, digest, sizeof(digest), sig, &sigLen,
                                   key, NULL, 0, WC_HASH_TYPE_SHA256, NULL, 0,
                                   1, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to pre-hash sign: %d\n", ret);
            goto done;
        }

        ret = wh_Client_SlhDsaVerify(ctx, sig, sigLen, digest, sizeof(digest),
                                     &verified, key, NULL, 0,
                                     WC_HASH_TYPE_SHA256, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to pre-hash verify: %d\n", ret);
            goto done;
        }
        if (!verified) {
            WH_ERROR_PRINT("SLH-DSA pre-hash verification failed\n");
            ret = WH_TEST_FAIL;
            goto done;
        }
    }
#endif /* !NO_SHA256 */

    WH_TEST_PRINT("SLH-DSA NON-DMA DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}

/* Generate a key that stays on the server and use it purely by key ID. This is
 * the case that has no local key material at all, so the randomizer has to be
 * supplied by the caller: the deterministic entry points read PK.seed out of
 * the local key, which a key held entirely on the server does not have. */
static int _whTest_CryptoSlhDsaCachedKey(whClientContext* ctx)
{
    int       devId  = WH_CLIENT_DEVID(ctx);
    int       ret;
    whKeyId   keyId  = WH_KEYID_ERASED;
    SlhDsaKey pub[1];
    SlhDsaKey handle[1];
    int       pubInit    = 0;
    int       handleInit = 0;
    uint8_t   label[]    = "SlhDsaCached";
    byte      addRnd[WC_SLHDSA_MAX_SEED];

    memset(addRnd, 0x42, sizeof(addRnd));

    ret = wc_SlhDsaKey_Init(pub, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init SLH-DSA pub key: %d\n", ret);
        return ret;
    }
    pubInit = 1;

    ret = wh_Client_SlhDsaMakeCacheKeyAndExportPublic(
        ctx, WH_TEST_SLHDSA_COMM_PARAM, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, sizeof(label),
        label, pub);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache SLH-DSA key: %d\n", ret);
        goto done;
    }

    /* A bare handle: no key material, only the server key ID */
    ret = wc_SlhDsaKey_Init(handle, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init SLH-DSA handle: %d\n", ret);
        goto done;
    }
    handleInit = 1;

    ret = wh_Client_SlhDsaSetKeyId(handle, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set SLH-DSA key id: %d\n", ret);
        goto done;
    }

    {
        byte   msg[] = "Signed by a key that never left the HSM";
        byte   sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
        word32 sigLen = sizeof(sig);

        /* A caller-supplied randomizer: this dispatches to the server, which
         * holds the whole key. */
        ret = wc_SlhDsaKey_SignWithRandom(handle, NULL, 0, msg, sizeof(msg),
                                          sig, &sigLen, addRnd);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with a cached SLH-DSA key: %d\n",
                           ret);
            goto done;
        }

        /* The exported public key verifies it, through the server */
        ret = wc_SlhDsaKey_Verify(pub, NULL, 0, msg, sizeof(msg), sig, sigLen);
        if (ret != 0) {
            WH_ERROR_PRINT("Cached-key signature did not verify: %d\n", ret);
            goto done;
        }

        /* The same randomizer over the same message must repeat, which shows
         * the server signed with the cached key both times. */
        {
            byte   sig2[WH_TEST_SLHDSA_COMM_SIG_LEN];
            word32 sig2Len = sizeof(sig2);

            ret = wc_SlhDsaKey_SignWithRandom(handle, NULL, 0, msg,
                                              sizeof(msg), sig2, &sig2Len,
                                              addRnd);
            if (ret != 0) {
                WH_ERROR_PRINT("Second cached-key sign failed: %d\n", ret);
                goto done;
            }
            if ((sig2Len != sigLen) || (memcmp(sig, sig2, sigLen) != 0)) {
                WH_ERROR_PRINT("Cached-key SLH-DSA signatures differ\n");
                ret = WH_TEST_FAIL;
                goto done;
            }

            /* A different randomizer must change the signature: that is what
             * shows the caller's value reached the server rather than being
             * dropped on the way and replaced by a deterministic one. */
            memset(addRnd, 0x17, sizeof(addRnd));
            sig2Len = sizeof(sig2);
            ret     = wc_SlhDsaKey_SignWithRandom(handle, NULL, 0, msg,
                                                  sizeof(msg), sig2, &sig2Len,
                                                  addRnd);
            if (ret != 0) {
                WH_ERROR_PRINT("Third cached-key sign failed: %d\n", ret);
                goto done;
            }
            if ((sig2Len == sigLen) && (memcmp(sig, sig2, sigLen) == 0)) {
                WH_ERROR_PRINT("Cached-key randomizer was ignored\n");
                ret = WH_TEST_FAIL;
                goto done;
            }
            ret = wc_SlhDsaKey_Verify(pub, NULL, 0, msg, sizeof(msg), sig2,
                                      sig2Len);
            if (ret != 0) {
                WH_ERROR_PRINT("Re-randomized signature did not verify: %d\n",
                               ret);
                goto done;
            }
        }
    }

    WH_TEST_PRINT("SLH-DSA CACHED KEY DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (handleInit) {
        wc_SlhDsaKey_Free(handle);
    }
    if (pubInit) {
        wc_SlhDsaKey_Free(pub);
    }
    return ret;
}

/* FIPS 205 internal interface: the caller builds M' and the server signs it
 * directly. */
static int _whTest_CryptoSlhDsaMPrime(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    SlhDsaKey key[1];
    /* M' for a pure signature with an empty context: 0x00 || ctxSz || msg */
    byte      mprime[] = {0x00, 0x00, 'm', 'p', 'r', 'i', 'm', 'e'};
    byte      sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
    word32    sigLen = sizeof(sig);
    byte      addRnd[WC_SLHDSA_MAX_SEED];

    memset(addRnd, 0x42, sizeof(addRnd));

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize SLH-DSA key: %d\n", ret);
        return ret;
    }

    ret = wh_Client_SlhDsaMakeExportKey(ctx, WH_TEST_SLHDSA_COMM_PARAM, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate SLH-DSA key: %d\n", ret);
        goto done;
    }

    ret = wc_SlhDsaKey_SignMsgWithRandom(key, mprime, sizeof(mprime), sig,
                                         &sigLen, addRnd);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to sign M': %d\n", ret);
        goto done;
    }

    ret = wc_SlhDsaKey_VerifyMsg(key, mprime, sizeof(mprime), sig, sigLen);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to verify M' signature: %d\n", ret);
        goto done;
    }

    /* The same signature must not verify against a different M' */
    mprime[2] ^= 0xFF;
    ret = wc_SlhDsaKey_VerifyMsg(key, mprime, sizeof(mprime), sig, sigLen);
    if (ret == 0) {
        WH_ERROR_PRINT("M' verification accepted the wrong message\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SLH-DSA MPRIME DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}

/* wc_SlhDsaKey_CheckKey against a server-resident private key. */
static int _whTest_CryptoSlhDsaCheckPrivKey(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    whKeyId   keyId = WH_KEYID_ERASED;
    SlhDsaKey pub[1];
    SlhDsaKey handle[1];
    int       pubInit    = 0;
    int       handleInit = 0;
    uint8_t   label[]    = "SlhDsaCheck";

    ret = wc_SlhDsaKey_Init(pub, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    pubInit = 1;

    ret = wh_Client_SlhDsaMakeCacheKeyAndExportPublic(
        ctx, WH_TEST_SLHDSA_COMM_PARAM, &keyId, WH_NVM_FLAGS_USAGE_SIGN,
        sizeof(label), label, pub);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache SLH-DSA key: %d\n", ret);
        goto done;
    }

    ret = wc_SlhDsaKey_Init(handle, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        goto done;
    }
    handleInit = 1;
    (void)wh_Client_SlhDsaSetKeyId(handle, keyId);

    {
        byte   expected[WC_SLHDSA_MAX_PUB_LEN];
        int    pubSz;

        pubSz = wc_SlhDsaKey_PublicSize(pub);
        if ((pubSz <= 0) || ((word32)pubSz > sizeof(expected))) {
            WH_ERROR_PRINT("Bad SLH-DSA public size %d\n", pubSz);
            ret = WH_TEST_FAIL;
            goto done;
        }
        ret = wc_SlhDsaKey_ExportPublic(pub, expected, (word32*)&pubSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export SLH-DSA public key: %d\n", ret);
            goto done;
        }

        /* wc_SlhDsaKey_CheckKey takes the public key from the key struct, so
         * it exercises the callback with the handle's own (server-held)
         * material. */
        ret = wc_SlhDsaKey_CheckKey(handle);
        if (ret != 0) {
            WH_ERROR_PRINT("CheckKey rejected the cached key: %d\n", ret);
            goto done;
        }

        ret = wh_Client_SlhDsaCheckPrivKey(ctx, handle, expected,
                                           (word32)pubSz);
        if (ret != 0) {
            WH_ERROR_PRINT("CheckPrivKey rejected the matching key: %d\n", ret);
            goto done;
        }

        /* A public key that does not belong to the private key must be
         * rejected rather than silently accepted. */
        expected[0] ^= 0xFF;
        ret = wh_Client_SlhDsaCheckPrivKey(ctx, handle, expected,
                                           (word32)pubSz);
        if (ret != WC_KEY_MISMATCH_E) {
            WH_ERROR_PRINT("CheckPrivKey accepted a mismatched key: %d\n", ret);
            ret = WH_TEST_FAIL;
            goto done;
        }
    }

    WH_TEST_PRINT("SLH-DSA CHECKPRIVKEY DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (handleInit) {
        wc_SlhDsaKey_Free(handle);
    }
    if (pubInit) {
        wc_SlhDsaKey_Free(pub);
    }
    return ret;
}

#ifndef NO_SHA256
/* A digest whose length does not match the declared pre-hash algorithm is a
 * malformed request, not a signature that failed to verify. The two must stay
 * distinguishable: reporting res=0 would tell the caller the signature is bad
 * when the real problem is their own argument. */
static int _whTest_CryptoSlhDsaBadDigestLen(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    SlhDsaKey key[1];
    byte      digest[WC_SHA256_DIGEST_SIZE];
    byte      sig[WH_TEST_SLHDSA_COMM_SIG_LEN];
    word32    sigLen   = sizeof(sig);
    int       verified = 1;

    memset(digest, 0x3C, sizeof(digest));
    memset(sig, 0, sizeof(sig));

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wh_Client_SlhDsaMakeExportKey(ctx, WH_TEST_SLHDSA_COMM_PARAM, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate SLH-DSA key: %d\n", ret);
        goto done;
    }

    ret = wh_Client_SlhDsaSign(ctx, digest, sizeof(digest), sig, &sigLen, key,
                               NULL, 0, WC_HASH_TYPE_SHA256, NULL, 0, 1, 0);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to pre-hash sign: %d\n", ret);
        goto done;
    }

    /* Same signature, same hash type, digest one byte short */
    ret = wh_Client_SlhDsaVerify(ctx, sig, sigLen, digest,
                                 (word32)sizeof(digest) - 1, &verified, key,
                                 NULL, 0, WC_HASH_TYPE_SHA256, 0);
    if (ret == 0) {
        WH_ERROR_PRINT("Short digest reported as a verify result (res=%d) "
                       "instead of an error\n",
                       verified);
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SLH-DSA BAD DIGEST LEN DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}
#endif /* !NO_SHA256 */

/* A caller buffer smaller than the signature must report WH_ERROR_BUFFER_SIZE
 * and the length that would have been needed, without writing past the end. */
static int _whTest_CryptoSlhDsaBufferTooSmall(whClientContext* ctx)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    SlhDsaKey  key[1];
    const byte msg[]         = "slh-dsa buf size test";
    uint8_t    small_sig[16] = {0};
    word32     small_buf_sz  = (word32)sizeof(small_sig);
    word32     sig_len;

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_COMM_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wh_Client_SlhDsaMakeExportKey(ctx, WH_TEST_SLHDSA_COMM_PARAM, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate SLH-DSA key: %d\n", ret);
        goto done;
    }

    sig_len = small_buf_sz;
    ret = wh_Client_SlhDsaSign(ctx, msg, (word32)sizeof(msg), small_sig,
                               &sig_len, key, NULL, 0, WC_HASH_TYPE_NONE, NULL,
                               0, 1, 0);
    if (ret != WH_ERROR_BUFFER_SIZE) {
        WH_ERROR_PRINT("SlhDsaSign small buf expected WH_ERROR_BUFFER_SIZE, "
                       "got %d\n",
                       ret);
        ret = WH_TEST_FAIL;
        goto done;
    }
    if (sig_len <= small_buf_sz) {
        WH_ERROR_PRINT("SlhDsaSign small buf reported size %u not greater "
                       "than %u\n",
                       (unsigned)sig_len, (unsigned)small_buf_sz);
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SLH-DSA BUFFER SIZE DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}

#endif /* WH_TEST_SLHDSA_COMM_PARAM */

#ifdef WH_TEST_SLHDSA_FAST_PARAM
/* NIST CAVP SLH-DSA-SHAKE-128f keyGen vector (tgId=4, tcId=31). The seeded
 * generation path is what makes a known-answer test possible at all: a random
 * key generation has no expected output to compare against. */
static const byte whTestSlhDsaKatSeed[] = {
    /* SK.seed */
    0x39, 0x56, 0xAB, 0x39, 0x1B, 0x4D, 0x22, 0xFC,
    0x90, 0x7A, 0xF0, 0x74, 0x03, 0x26, 0xD0, 0x61,
    /* SK.prf */
    0xAB, 0x0E, 0xB2, 0x06, 0x43, 0x6F, 0x2B, 0x86,
    0xEB, 0xE0, 0x86, 0xD7, 0x77, 0x39, 0xB3, 0xE4,
    /* PK.seed */
    0x56, 0x50, 0x5C, 0x22, 0x9F, 0x4E, 0x7F, 0xA6,
    0xB2, 0x01, 0x71, 0x4C, 0x7D, 0xCC, 0x9D, 0xA3
};

static const byte whTestSlhDsaKatPub[] = {
    /* PK.seed */
    0x56, 0x50, 0x5C, 0x22, 0x9F, 0x4E, 0x7F, 0xA6,
    0xB2, 0x01, 0x71, 0x4C, 0x7D, 0xCC, 0x9D, 0xA3,
    /* PK.root */
    0x66, 0x57, 0x8F, 0x1F, 0x24, 0xC3, 0xFE, 0x37,
    0x1C, 0x97, 0xC1, 0x4C, 0xE0, 0xE7, 0x9C, 0xDC
};

/* Seeded generation over the comm buffer. Only the tiny key material crosses
 * the wire here, so the fast parameter set is usable even without DMA. */
static int _whTest_CryptoSlhDsaSeededKat(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    SlhDsaKey key[1];
    byte      pub[WC_SLHDSA_MAX_PUB_LEN];
    word32    pubSz = sizeof(pub);

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_FAST_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Through wc_SlhDsaKey_MakeKeyWithRandom so the seeded key generation
     * takes the callback path an application would. */
    {
        word32 n = (word32)(sizeof(whTestSlhDsaKatSeed) / 3);

        ret = wc_SlhDsaKey_MakeKeyWithRandom(
            key, whTestSlhDsaKatSeed, n, whTestSlhDsaKatSeed + n, n,
            whTestSlhDsaKatSeed + 2 * n, n);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Failed seeded SLH-DSA keygen: %d\n", ret);
        goto done;
    }

    ret = wc_SlhDsaKey_ExportPublic(key, pub, &pubSz);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export seeded public key: %d\n", ret);
        goto done;
    }

    if ((pubSz != sizeof(whTestSlhDsaKatPub)) ||
        (memcmp(pub, whTestSlhDsaKatPub, pubSz) != 0)) {
        WH_ERROR_PRINT("Seeded SLH-DSA public key does not match the KAT\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SLH-DSA SEEDED KAT DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* The fast parameter set signs a 17088-byte signature, which no reasonable
 * comm buffer holds, so this is the DMA path end to end. */
static int _whTest_CryptoSlhDsaDmaClient(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    SlhDsaKey key[1];
    byte      msg[] = "Test message for DMA SLH-DSA";
    byte      sig[WH_TEST_SLHDSA_FAST_SIG_LEN];
    word32    sigLen   = sizeof(sig);
    int       verified = 0;

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_FAST_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wh_Client_SlhDsaMakeExportKeyDma(ctx, WH_TEST_SLHDSA_FAST_PARAM, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate SLH-DSA key over DMA: %d\n", ret);
        goto done;
    }

    ret = wh_Client_SlhDsaSignDma(ctx, msg, sizeof(msg), sig, &sigLen, key,
                                  NULL, 0, WC_HASH_TYPE_NONE, NULL, 0, 1, 0);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to sign over DMA: %d\n", ret);
        goto done;
    }
    if (sigLen != WH_TEST_SLHDSA_FAST_SIG_LEN) {
        WH_ERROR_PRINT("DMA signature length %u, expected %u\n",
                       (unsigned)sigLen,
                       (unsigned)WH_TEST_SLHDSA_FAST_SIG_LEN);
        ret = WH_TEST_FAIL;
        goto done;
    }

    ret = wh_Client_SlhDsaVerifyDma(ctx, sig, sigLen, msg, sizeof(msg),
                                    &verified, key, NULL, 0, WC_HASH_TYPE_NONE,
                                    0);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to verify over DMA: %d\n", ret);
        goto done;
    }
    if (!verified) {
        WH_ERROR_PRINT("SLH-DSA DMA verification failed\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    sig[0] ^= 0xFF;
    ret = wh_Client_SlhDsaVerifyDma(ctx, sig, sigLen, msg, sizeof(msg),
                                    &verified, key, NULL, 0, WC_HASH_TYPE_NONE,
                                    0);
    if (ret != 0) {
        WH_ERROR_PRINT("DMA verify with modified sig returned %d\n", ret);
        goto done;
    }
    if (verified) {
        WH_ERROR_PRINT("SLH-DSA DMA verified a bad signature\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SLH-DSA DMA DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}

/* A cached key driven over DMA, plus a round trip of the key material through
 * the DMA import and export calls. */
static int _whTest_CryptoSlhDsaDmaCachedKey(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    whKeyId   keyId = WH_KEYID_ERASED;
    SlhDsaKey pub[1];
    SlhDsaKey handle[1];
    int       pubInit    = 0;
    int       handleInit = 0;
    uint8_t   label[]    = "SlhDsaDmaCached";

    ret = wc_SlhDsaKey_Init(pub, WH_TEST_SLHDSA_FAST_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    pubInit = 1;

    ret = wh_Client_SlhDsaMakeCacheKeyDma(
        ctx, WH_TEST_SLHDSA_FAST_PARAM, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, sizeof(label),
        label, pub);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache SLH-DSA key over DMA: %d\n", ret);
        goto done;
    }

    ret = wc_SlhDsaKey_Init(handle, WH_TEST_SLHDSA_FAST_PARAM, NULL, devId);
    if (ret != 0) {
        goto done;
    }
    handleInit = 1;
    (void)wh_Client_SlhDsaSetKeyId(handle, keyId);

    {
        byte   msg[] = "DMA signed by a key that never left the HSM";
        byte   sig[WH_TEST_SLHDSA_FAST_SIG_LEN];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;

        ret = wh_Client_SlhDsaSignDma(ctx, msg, sizeof(msg), sig, &sigLen,
                                      handle, NULL, 0, WC_HASH_TYPE_NONE, NULL,
                                      0, 1, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to DMA sign with a cached key: %d\n", ret);
            goto done;
        }

        ret = wh_Client_SlhDsaVerifyDma(ctx, sig, sigLen, msg, sizeof(msg),
                                        &verified, pub, NULL, 0,
                                        WC_HASH_TYPE_NONE, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to DMA verify a cached-key sig: %d\n", ret);
            goto done;
        }
        if (!verified) {
            WH_ERROR_PRINT("Cached-key DMA signature did not verify\n");
            ret = WH_TEST_FAIL;
            goto done;
        }
    }

    /* Export the public key on its own and check it matches what keygen
     * already handed back. */
    {
        SlhDsaKey exported[1];
        byte      a[WC_SLHDSA_MAX_PUB_LEN];
        byte      b[WC_SLHDSA_MAX_PUB_LEN];
        word32    aSz = sizeof(a);
        word32    bSz = sizeof(b);

        ret = wc_SlhDsaKey_Init(exported, WH_TEST_SLHDSA_FAST_PARAM, NULL,
                                devId);
        if (ret != 0) {
            goto done;
        }
        ret = wh_Client_SlhDsaExportPublicKeyDma(ctx, keyId, exported, 0, NULL);
        if (ret == 0) {
            ret = wc_SlhDsaKey_ExportPublic(pub, a, &aSz);
        }
        if (ret == 0) {
            ret = wc_SlhDsaKey_ExportPublic(exported, b, &bSz);
        }
        if ((ret == 0) && ((aSz != bSz) || (memcmp(a, b, aSz) != 0))) {
            WH_ERROR_PRINT("Exported SLH-DSA public key does not match\n");
            ret = WH_TEST_FAIL;
        }
        wc_SlhDsaKey_Free(exported);
        if (ret != 0) {
            WH_ERROR_PRINT("SLH-DSA DMA public key export failed: %d\n", ret);
            goto done;
        }
    }

    WH_TEST_PRINT("SLH-DSA DMA CACHED KEY DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (handleInit) {
        wc_SlhDsaKey_Free(handle);
    }
    if (pubInit) {
        wc_SlhDsaKey_Free(pub);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WH_TEST_SLHDSA_FAST_PARAM */

#ifdef WH_TEST_SLHDSA_COMM_PARAM
/* The comm buffer cannot carry the larger parameter sets, so the server must
 * say so rather than truncating the signature. */
#if defined(WOLFSSL_SLHDSA_PARAM_192S) || defined(WOLFSSL_SLHDSA_PARAM_256S)
#if defined(WOLFSSL_SLHDSA_PARAM_192S)
#define WH_TEST_SLHDSA_OVERSIZE_PARAM SLHDSA_SHAKE192S
#else
#define WH_TEST_SLHDSA_OVERSIZE_PARAM SLHDSA_SHAKE256S
#endif
static int _whTest_CryptoSlhDsaCommBufferLimit(whClientContext* ctx)
{
    int       devId = WH_CLIENT_DEVID(ctx);
    int       ret;
    SlhDsaKey key[1];
    byte      msg[] = "too big for the comm buffer";
    byte      sig[WC_SLHDSA_MAX_SIG_LEN];
    word32    sigLen = sizeof(sig);

    ret = wc_SlhDsaKey_Init(key, WH_TEST_SLHDSA_OVERSIZE_PARAM, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wh_Client_SlhDsaMakeExportKey(ctx, WH_TEST_SLHDSA_OVERSIZE_PARAM,
                                        key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate oversize SLH-DSA key: %d\n", ret);
        goto done;
    }

    ret = wh_Client_SlhDsaSign(ctx, msg, sizeof(msg), sig, &sigLen, key, NULL,
                               0, WC_HASH_TYPE_NONE, NULL, 0, 1, 0);
    if (ret != WH_ERROR_BUFFER_SIZE) {
        WH_ERROR_PRINT("Oversize sign expected WH_ERROR_BUFFER_SIZE, got %d\n",
                       ret);
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SLH-DSA COMM LIMIT DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_SlhDsaKey_Free(key);
    return ret;
}
#endif /* 192S || 256S */
#endif /* WH_TEST_SLHDSA_COMM_PARAM */

int whTest_Crypto_SlhDsa(whClientContext* ctx)
{
#ifdef WH_TEST_SLHDSA_COMM_PARAM
    /* The wolfCrypt-API driver is the path an application actually takes, so
     * run it in each dispatch mode the build offers. */
    int i;

    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        (void)wh_Client_SetDmaMode(ctx, i);
        WH_TEST_RETURN_ON_FAIL(
            _whTest_SlhDsaWolfCryptImpl(ctx, WH_CLIENT_DEVID(ctx)));
    }
    (void)wh_Client_SetDmaMode(ctx, 0);

    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaClient(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaCachedKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaMPrime(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaCheckPrivKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaBufferTooSmall(ctx));
#ifndef NO_SHA256
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaBadDigestLen(ctx));
#endif
#ifdef WH_TEST_SLHDSA_OVERSIZE_PARAM
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaCommBufferLimit(ctx));
#endif
#endif /* WH_TEST_SLHDSA_COMM_PARAM */

#ifdef WH_TEST_SLHDSA_FAST_PARAM
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaSeededKat(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaDmaClient(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSlhDsaDmaCachedKey(ctx));
#endif
#endif /* WH_TEST_SLHDSA_FAST_PARAM */

    (void)ctx;
#if !defined(WH_TEST_SLHDSA_COMM_PARAM) && !defined(WH_TEST_SLHDSA_FAST_PARAM)
    /* A verify-only build compiles out every signing parameter set, leaving
     * nothing above to run. Report that rather than a pass. */
    return WH_TEST_SKIPPED;
#else
    return 0;
#endif
}

#endif /* WOLFSSL_HAVE_SLHDSA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
