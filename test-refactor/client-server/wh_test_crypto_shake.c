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
 * test-refactor/client-server/wh_test_crypto_shake.c
 *
 * SHAKE128/256 routed through the server via the per-client devId.
 *
 * Every case runs the same input twice, once with INVALID_DEVID so wolfCrypt
 * computes it locally and once on the server, and requires the two to agree.
 * The software path is the oracle: what is under test is the offload, not
 * Keccak. The size tables are written out here rather than shared with the
 * client, so a wrong block size cannot agree with itself.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)

/* Long enough to span several comm-buffer messages at any supported size */
#define SHAKE_TEST_MAX_IN 20000u
/* Larger than any response can carry, so a SHAKE this long must fall back to
 * software rather than be truncated */
#define SHAKE_TEST_LONG_OUT (WOLFHSM_CFG_COMM_DATA_LEN + 1024u)

static uint8_t shakeTestIn[SHAKE_TEST_MAX_IN];
static uint8_t shakeTestOutDev[SHAKE_TEST_LONG_OUT];
static uint8_t shakeTestOutSw[SHAKE_TEST_LONG_OUT];

typedef struct {
    int         hashType;
    uint32_t    blockSize;
    const char* name;
    int (*initFn)(wc_Shake* sha, void* heap, int devId);
    int (*updateFn)(wc_Shake* sha, const byte* in, word32 inSz);
    int (*finalFn)(wc_Shake* sha, byte* out, word32 outSz);
    void (*freeFn)(wc_Shake* sha);
} shakeTestVariant;

static const shakeTestVariant shakeTestVariants[] = {
#ifdef WOLFSSL_SHAKE128
    {WC_HASH_TYPE_SHAKE128, 168u, "SHAKE128", wc_InitShake128,
     wc_Shake128_Update, wc_Shake128_Final, wc_Shake128_Free},
#endif
#ifdef WOLFSSL_SHAKE256
    {WC_HASH_TYPE_SHAKE256, 136u, "SHAKE256", wc_InitShake256,
     wc_Shake256_Update, wc_Shake256_Final, wc_Shake256_Free},
#endif
};

/* Hash inLen bytes, feeding the update in chunks of chunkSz (0 = all at once)
 * so the multi-update path and the partial-block buffering are exercised. */
static int _ShakeTestHash(int devId, const shakeTestVariant* v,
                          const uint8_t* in, uint32_t inLen, uint32_t chunkSz,
                          uint8_t* out, uint32_t outSz)
{
    wc_Shake sha[1];
    int      ret;
    uint32_t done = 0;

    ret = v->initFn(sha, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    while ((ret == 0) && (done < inLen)) {
        uint32_t remaining = inLen - done;
        uint32_t chunk     = (chunkSz == 0) ? remaining : chunkSz;

        if (chunk > remaining) {
            chunk = remaining;
        }
        ret = v->updateFn(sha, in + done, chunk);
        done += chunk;
    }

    if (ret == 0) {
        ret = v->finalFn(sha, out, outSz);
    }

    v->freeFn(sha);
    return ret;
}

/* Run one case on both paths and require them to agree. */
static int _ShakeTestCompare(int devId, const shakeTestVariant* v,
                             uint32_t inLen, uint32_t chunkSz, uint32_t outSz)
{
    int ret;

    memset(shakeTestOutDev, 0, outSz);
    memset(shakeTestOutSw, 0xA5, outSz);

    ret = _ShakeTestHash(INVALID_DEVID, v, shakeTestIn, inLen, chunkSz,
                         shakeTestOutSw, outSz);
    if (ret != 0) {
        WH_ERROR_PRINT("%s software hash failed: %d\n", v->name, ret);
        return ret;
    }

    ret = _ShakeTestHash(devId, v, shakeTestIn, inLen, chunkSz, shakeTestOutDev,
                         outSz);
    if (ret != 0) {
        WH_ERROR_PRINT("%s device hash failed (in %u chunk %u out %u): %d\n",
                       v->name, (unsigned)inLen, (unsigned)chunkSz,
                       (unsigned)outSz, ret);
        return ret;
    }

    if (memcmp(shakeTestOutDev, shakeTestOutSw, outSz) != 0) {
        WH_ERROR_PRINT("%s device and software differ (in %u chunk %u "
                       "out %u)\n",
                       v->name, (unsigned)inLen, (unsigned)chunkSz,
                       (unsigned)outSz);
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

static int _ShakeTestVariant(whClientContext* ctx, const shakeTestVariant* v)
{
    int      devId = WH_CLIENT_DEVID(ctx);
    uint32_t rate  = v->blockSize;
    uint32_t i;
    uint32_t j;
    int      ret = WH_ERROR_OK;
    /* Sizes around the block boundary, plus one long enough to need several
     * messages */
    const uint32_t inLens[]  = {0u,           1u,          rate - 1u,
                                rate,         rate + 1u,   2u * rate,
                                2u * rate + 7u, SHAKE_TEST_MAX_IN};
    /* All at once, then patterns that leave partial blocks buffered */
    const uint32_t chunks[]  = {0u, 1u, 7u, rate, rate + 1u};
    /* Output lengths a SHAKE caller might pick, including ones that are not
     * multiples of the block */
    const uint32_t outSzs[]  = {1u, 32u, 64u, rate, rate + 5u, 3u * rate};
    const uint32_t inLenCnt  = sizeof(inLens) / sizeof(inLens[0]);
    const uint32_t chunkCnt  = sizeof(chunks) / sizeof(chunks[0]);
    const uint32_t outSzCnt  = sizeof(outSzs) / sizeof(outSzs[0]);

    for (i = 0; (ret == WH_ERROR_OK) && (i < inLenCnt); i++) {
        for (j = 0; (ret == WH_ERROR_OK) && (j < chunkCnt); j++) {
            /* Chunking a 20000-byte input one byte at a time is a lot of
             * round trips for no extra coverage; the smaller inputs above
             * already exercise the same path */
            if ((inLens[i] > 4u * rate) && (chunks[j] != 0u) &&
                (chunks[j] < rate)) {
                continue;
            }
            ret = _ShakeTestCompare(devId, v, inLens[i], chunks[j], 32u);
        }
    }

    /* Output length is the part SHA3 has no equivalent of, so sweep it */
    for (i = 0; (ret == WH_ERROR_OK) && (i < outSzCnt); i++) {
        ret = _ShakeTestCompare(devId, v, 2u * rate + 7u, 0u, outSzs[i]);
    }

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("%s DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

/* A SHAKE asked for more output than a response can carry must still produce
 * the right answer, by declining the offload and letting software finish from
 * the state the client holds. */
static int _ShakeTestLongOutput(whClientContext* ctx, const shakeTestVariant* v)
{
    int devId = WH_CLIENT_DEVID(ctx);
    int ret;

    ret = _ShakeTestCompare(devId, v, 4096u, 0u, SHAKE_TEST_LONG_OUT);
    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("%s long output DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

/* Exercise the request/response primitives directly, the way the async SHA3
 * tests do, rather than only through the wolfCrypt API. */
static int _ShakeTestAsync(whClientContext* ctx, const shakeTestVariant* v)
{
    int      devId = WH_CLIENT_DEVID(ctx);
    int      ret;
    wc_Shake sha[1];
    uint8_t  out[64];
    uint32_t inLen = 3u * v->blockSize + 11u;
    uint32_t consumed = 0;

    ret = _ShakeTestHash(INVALID_DEVID, v, shakeTestIn, inLen, 0u,
                         shakeTestOutSw, sizeof(out));
    if (ret != 0) {
        return ret;
    }

    ret = v->initFn(sha, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    while ((ret == WH_ERROR_OK) && (consumed < inLen)) {
        uint32_t remaining = inLen - consumed;
        uint32_t chunk     = (remaining < v->blockSize) ? remaining
                                                        : v->blockSize;
        bool     sent      = false;

#ifdef WOLFSSL_SHAKE128
        if (v->hashType == WC_HASH_TYPE_SHAKE128) {
            ret = wh_Client_Shake128UpdateRequest(ctx, sha,
                                                  shakeTestIn + consumed,
                                                  chunk, &sent);
            if ((ret == WH_ERROR_OK) && sent) {
                do {
                    ret = wh_Client_Shake128UpdateResponse(ctx, sha);
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
#endif
#ifdef WOLFSSL_SHAKE256
        if (v->hashType == WC_HASH_TYPE_SHAKE256) {
            ret = wh_Client_Shake256UpdateRequest(ctx, sha,
                                                  shakeTestIn + consumed,
                                                  chunk, &sent);
            if ((ret == WH_ERROR_OK) && sent) {
                do {
                    ret = wh_Client_Shake256UpdateResponse(ctx, sha);
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
#endif
        consumed += chunk;
    }

    if (ret == WH_ERROR_OK) {
#ifdef WOLFSSL_SHAKE128
        if (v->hashType == WC_HASH_TYPE_SHAKE128) {
            ret = wh_Client_Shake128FinalRequest(ctx, sha, sizeof(out));
            if (ret == WH_ERROR_OK) {
                do {
                    ret = wh_Client_Shake128FinalResponse(ctx, sha, out,
                                                          sizeof(out));
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
#endif
#ifdef WOLFSSL_SHAKE256
        if (v->hashType == WC_HASH_TYPE_SHAKE256) {
            ret = wh_Client_Shake256FinalRequest(ctx, sha, sizeof(out));
            if (ret == WH_ERROR_OK) {
                do {
                    ret = wh_Client_Shake256FinalResponse(ctx, sha, out,
                                                          sizeof(out));
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
#endif
    }

    v->freeFn(sha);

    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("%s async failed: %d\n", v->name, ret);
        return ret;
    }
    if (memcmp(out, shakeTestOutSw, sizeof(out)) != 0) {
        WH_ERROR_PRINT("%s async result differs from software\n", v->name);
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("%s ASYNC DEVID=0x%X SUCCESS\n", v->name, devId);
    return WH_ERROR_OK;
}

/* wolfCrypt accepts a finalize asking for zero bytes: it writes nothing and
 * resets the context. Enabling the offload must not turn that into an error. */
static int _ShakeTestZeroLengthFinal(whClientContext* ctx,
                                     const shakeTestVariant* v)
{
    int      devId = WH_CLIENT_DEVID(ctx);
    int      ret;
    wc_Shake sha[1];
    uint8_t  out[1] = {0xA5};

    ret = v->initFn(sha, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = v->updateFn(sha, shakeTestIn, v->blockSize + 3u);
    if (ret == 0) {
        ret = v->finalFn(sha, out, 0u);
    }
    if (ret == 0 && out[0] != 0xA5) {
        WH_ERROR_PRINT("%s zero-length final wrote output\n", v->name);
        ret = WH_ERROR_ABORTED;
    }
    /* The context must be reusable afterwards, as a reset implies */
    if (ret == 0) {
        uint8_t again[32];
        ret = v->updateFn(sha, shakeTestIn, 4u);
        if (ret == 0) {
            ret = v->finalFn(sha, again, sizeof(again));
        }
    }

    v->freeFn(sha);

    if (ret != 0) {
        WH_ERROR_PRINT("%s zero-length final failed: %d\n", v->name, ret);
        return ret;
    }
    WH_TEST_PRINT("%s zero-length final SUCCESS\n", v->name);
    return WH_ERROR_OK;
}

#ifdef WOLFSSL_HASH_FLAGS
/* Keccak mode swaps SHAKE256's padding and the flag is not carried on the
 * wire, so the offload must decline and leave the result matching software. */
static int _ShakeTestKeccakFlag(whClientContext*        ctx,
                                const shakeTestVariant* v)
{
    wc_Shake sha[1];
    uint8_t  dev[32];
    uint8_t  sw[32];
    int      ret;
    int      i;

    for (i = 0; i < 2; i++) {
        int      devId = (i == 0) ? WH_CLIENT_DEVID(ctx) : INVALID_DEVID;
        uint8_t* out   = (i == 0) ? dev : sw;

        ret = v->initFn(sha, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha3_SetFlags(sha, WC_HASH_SHA3_KECCAK256);
        }
        if (ret == 0) {
            ret = v->updateFn(sha, shakeTestIn, v->blockSize + 3u);
        }
        if (ret == 0) {
            ret = v->finalFn(sha, out, sizeof(dev));
        }
        v->freeFn(sha);
        if (ret != 0) {
            WH_ERROR_PRINT("%s keccak-flag hash failed (devId %d): %d\n",
                           v->name, devId, ret);
            return ret;
        }
    }

    if (memcmp(dev, sw, sizeof(dev)) != 0) {
        WH_ERROR_PRINT("%s keccak-flag device and software differ\n", v->name);
        return WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("%s keccak flag SUCCESS\n", v->name);
    return WH_ERROR_OK;
}
#endif /* WOLFSSL_HASH_FLAGS */

/* The client entry points must reject bad arguments before going on the wire */
static int _ShakeTestBadArgs(whClientContext* ctx, const shakeTestVariant* v)
{
    wc_Shake sha[1];
    uint8_t  buf[8];
    int      bad = 0;

    if (v->initFn(sha, NULL, WH_CLIENT_DEVID(ctx)) != 0) {
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFSSL_SHAKE128
    if (v->hashType == WC_HASH_TYPE_SHAKE128) {
        bad = (wh_Client_Shake128(NULL, sha, buf, sizeof(buf), NULL, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake128(ctx, NULL, buf, sizeof(buf), NULL, 0) !=
               WH_ERROR_BADARGS) ||
              /* A length with no buffer behind it would digest the state */
              (wh_Client_Shake128(ctx, sha, NULL, sizeof(buf), NULL, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake128UpdateRequest(ctx, sha, buf, sizeof(buf),
                                               NULL) != WH_ERROR_BADARGS) ||
              (wh_Client_Shake128UpdateResponse(ctx, NULL) !=
               WH_ERROR_BADARGS) ||
              /* A SHAKE has no natural length, so finalizing needs one */
              (wh_Client_Shake128FinalRequest(ctx, sha, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake128FinalResponse(ctx, sha, NULL, 32u) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake128FinalResponse(ctx, sha, buf, 0) !=
               WH_ERROR_BADARGS);
    }
#endif
#ifdef WOLFSSL_SHAKE256
    if (v->hashType == WC_HASH_TYPE_SHAKE256) {
        bad = (wh_Client_Shake256(NULL, sha, buf, sizeof(buf), NULL, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake256(ctx, NULL, buf, sizeof(buf), NULL, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake256(ctx, sha, NULL, sizeof(buf), NULL, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake256UpdateRequest(ctx, sha, buf, sizeof(buf),
                                               NULL) != WH_ERROR_BADARGS) ||
              (wh_Client_Shake256UpdateResponse(ctx, NULL) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake256FinalRequest(ctx, sha, 0) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake256FinalResponse(ctx, sha, NULL, 32u) !=
               WH_ERROR_BADARGS) ||
              (wh_Client_Shake256FinalResponse(ctx, sha, buf, 0) !=
               WH_ERROR_BADARGS);
    }
#endif

#ifdef WOLFSSL_HASH_FLAGS
    /* Keccak mode is not carried on the wire, so the request helpers must
     * refuse it rather than return a digest with SHAKE padding. */
    if (!bad) {
        bool sent = false;
        (void)wc_Sha3_SetFlags(sha, WC_HASH_SHA3_KECCAK256);
#ifdef WOLFSSL_SHAKE128
        if (v->hashType == WC_HASH_TYPE_SHAKE128) {
            bad = (wh_Client_Shake128UpdateRequest(ctx, sha, buf, sizeof(buf),
                                                   &sent) !=
                   WH_ERROR_BADARGS) ||
                  (wh_Client_Shake128FinalRequest(ctx, sha, 32u) !=
                   WH_ERROR_BADARGS);
        }
#endif
#ifdef WOLFSSL_SHAKE256
        if (v->hashType == WC_HASH_TYPE_SHAKE256) {
            bad = (wh_Client_Shake256UpdateRequest(ctx, sha, buf, sizeof(buf),
                                                   &sent) !=
                   WH_ERROR_BADARGS) ||
                  (wh_Client_Shake256FinalRequest(ctx, sha, 32u) !=
                   WH_ERROR_BADARGS);
        }
#endif
        (void)wc_Sha3_SetFlags(sha, 0);
    }
#endif

    v->freeFn(sha);

    if (bad) {
        WH_ERROR_PRINT("%s accepted bad arguments\n", v->name);
        return WH_ERROR_ABORTED;
    }
    WH_TEST_PRINT("%s bad-args SUCCESS\n", v->name);
    return WH_ERROR_OK;
}
int whTest_Crypto_Shake(whClientContext* ctx)
{
    const uint32_t variantCnt =
        sizeof(shakeTestVariants) / sizeof(shakeTestVariants[0]);
    uint32_t i;

    for (i = 0; i < sizeof(shakeTestIn); i++) {
        shakeTestIn[i] = (uint8_t)(i * 31u + 7u);
    }

    for (i = 0; i < variantCnt; i++) {
        const shakeTestVariant* v = &shakeTestVariants[i];

        WH_TEST_RETURN_ON_FAIL(_ShakeTestBadArgs(ctx, v));
        WH_TEST_RETURN_ON_FAIL(_ShakeTestVariant(ctx, v));
        WH_TEST_RETURN_ON_FAIL(_ShakeTestAsync(ctx, v));
        WH_TEST_RETURN_ON_FAIL(_ShakeTestLongOutput(ctx, v));
        WH_TEST_RETURN_ON_FAIL(_ShakeTestZeroLengthFinal(ctx, v));
#ifdef WOLFSSL_HASH_FLAGS
        WH_TEST_RETURN_ON_FAIL(_ShakeTestKeccakFlag(ctx, v));
#endif
    }
    return 0;
}

#endif /* WOLFSSL_SHAKE128 || WOLFSSL_SHAKE256 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
