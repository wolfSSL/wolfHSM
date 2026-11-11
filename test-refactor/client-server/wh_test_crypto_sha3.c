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
 * test-refactor/client-server/wh_test_crypto_sha3.c
 *
 * SHA3-224/256/384/512 routed through the server via the per-client devId
 * (WH_CLIENT_DEVID). A single set of tests runs against all compiled
 * variants via a small dispatch table:
 *   sync      wolfCrypt API across length edge cases vs software reference,
 *             plus one-shot wrapper bad-arg rejection and Keccak-256 on
 *             the server
 *   async     direct exercise of the wh_Client_Sha3_* request/response
 *             primitives
 *   dma async same, via the DMA messaging path
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha3.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFSSL_SHA3)

typedef struct {
    const char* name;
    int         hashType;
    uint32_t    blockSize;
    uint32_t    digestSize;
    uint32_t    maxInlineSz;
    int (*initFn)(wc_Sha3* sha, void* heap, int devId);
    int (*updateFn)(wc_Sha3* sha, const byte* data, word32 len);
    int (*finalFn)(wc_Sha3* sha, byte* hash);
    /* native async client helpers */
    int (*asyncUpdateRequest)(whClientContext*, wc_Sha3*, const uint8_t*,
                              uint32_t, bool*);
    int (*asyncUpdateResponse)(whClientContext*, wc_Sha3*);
    int (*asyncFinalRequest)(whClientContext*, wc_Sha3*);
    int (*asyncFinalResponse)(whClientContext*, wc_Sha3*, uint8_t*);
    /* native one-shot helpers */
    int (*oneshotFn)(whClientContext*, wc_Sha3*, const uint8_t*, uint32_t,
                     uint8_t*);
#ifdef WOLFHSM_CFG_DMA
    int (*dmaUpdateRequest)(whClientContext*, wc_Sha3*, const uint8_t*,
                            uint32_t, bool*);
    int (*dmaUpdateResponse)(whClientContext*, wc_Sha3*);
    int (*dmaFinalRequest)(whClientContext*, wc_Sha3*);
    int (*dmaFinalResponse)(whClientContext*, wc_Sha3*, uint8_t*);
    int (*dmaOneshotFn)(whClientContext*, wc_Sha3*, const uint8_t*, uint32_t,
                        uint8_t*);
#endif
} whTestSha3Variant;

static const whTestSha3Variant whTestSha3Variants[] = {
#ifndef WOLFSSL_NOSHA3_224
    {
        "SHA3-224",
        WC_HASH_TYPE_SHA3_224,
        WC_SHA3_224_BLOCK_SIZE,
        WC_SHA3_224_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_MAX_INLINE_UPDATE_SZ(WC_SHA3_224_BLOCK_SIZE),
        wc_InitSha3_224,
        wc_Sha3_224_Update,
        wc_Sha3_224_Final,
        wh_Client_Sha3_224UpdateRequest,
        wh_Client_Sha3_224UpdateResponse,
        wh_Client_Sha3_224FinalRequest,
        wh_Client_Sha3_224FinalResponse,
        wh_Client_Sha3_224,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_224DmaUpdateRequest,
        wh_Client_Sha3_224DmaUpdateResponse,
        wh_Client_Sha3_224DmaFinalRequest,
        wh_Client_Sha3_224DmaFinalResponse,
        wh_Client_Sha3_224Dma,
#endif
    },
#endif
#ifndef WOLFSSL_NOSHA3_256
    {
        "SHA3-256",
        WC_HASH_TYPE_SHA3_256,
        WC_SHA3_256_BLOCK_SIZE,
        WC_SHA3_256_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_MAX_INLINE_UPDATE_SZ(WC_SHA3_256_BLOCK_SIZE),
        wc_InitSha3_256,
        wc_Sha3_256_Update,
        wc_Sha3_256_Final,
        wh_Client_Sha3_256UpdateRequest,
        wh_Client_Sha3_256UpdateResponse,
        wh_Client_Sha3_256FinalRequest,
        wh_Client_Sha3_256FinalResponse,
        wh_Client_Sha3_256,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_256DmaUpdateRequest,
        wh_Client_Sha3_256DmaUpdateResponse,
        wh_Client_Sha3_256DmaFinalRequest,
        wh_Client_Sha3_256DmaFinalResponse,
        wh_Client_Sha3_256Dma,
#endif
    },
#endif
#ifndef WOLFSSL_NOSHA3_384
    {
        "SHA3-384",
        WC_HASH_TYPE_SHA3_384,
        WC_SHA3_384_BLOCK_SIZE,
        WC_SHA3_384_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_MAX_INLINE_UPDATE_SZ(WC_SHA3_384_BLOCK_SIZE),
        wc_InitSha3_384,
        wc_Sha3_384_Update,
        wc_Sha3_384_Final,
        wh_Client_Sha3_384UpdateRequest,
        wh_Client_Sha3_384UpdateResponse,
        wh_Client_Sha3_384FinalRequest,
        wh_Client_Sha3_384FinalResponse,
        wh_Client_Sha3_384,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_384DmaUpdateRequest,
        wh_Client_Sha3_384DmaUpdateResponse,
        wh_Client_Sha3_384DmaFinalRequest,
        wh_Client_Sha3_384DmaFinalResponse,
        wh_Client_Sha3_384Dma,
#endif
    },
#endif
#ifndef WOLFSSL_NOSHA3_512
    {
        "SHA3-512",
        WC_HASH_TYPE_SHA3_512,
        WC_SHA3_512_BLOCK_SIZE,
        WC_SHA3_512_DIGEST_SIZE,
        WH_MESSAGE_CRYPTO_SHA3_MAX_INLINE_UPDATE_SZ(WC_SHA3_512_BLOCK_SIZE),
        wc_InitSha3_512,
        wc_Sha3_512_Update,
        wc_Sha3_512_Final,
        wh_Client_Sha3_512UpdateRequest,
        wh_Client_Sha3_512UpdateResponse,
        wh_Client_Sha3_512FinalRequest,
        wh_Client_Sha3_512FinalResponse,
        wh_Client_Sha3_512,
#ifdef WOLFHSM_CFG_DMA
        wh_Client_Sha3_512DmaUpdateRequest,
        wh_Client_Sha3_512DmaUpdateResponse,
        wh_Client_Sha3_512DmaFinalRequest,
        wh_Client_Sha3_512DmaFinalResponse,
        wh_Client_Sha3_512Dma,
#endif
    },
#endif
};

/* Reference hash via software (INVALID_DEVID) for cross-checks. */
static int whTest_Sha3Reference(const whTestSha3Variant* v, const uint8_t* in,
                                uint32_t inLen, uint8_t* out)
{
    wc_Sha3 sw[1];
    int     ret = v->initFn(sw, NULL, INVALID_DEVID);
    if (ret == 0 && inLen > 0) {
        ret = v->updateFn(sw, in, inLen);
    }
    if (ret == 0) {
        ret = v->finalFn(sw, out);
    }
    /* No Free variant function in our table — wc_Sha3 doesn't allocate by
     * default on POSIX so this is fine. */
    return ret;
}

/* Static buffer sized to cover all variants' max inline + tail slack.
 * SHA3-512 has the smallest block (72) so its floor((P)/block)*block lands
 * closest to the payload cap, making it the upper bound (possibly tied
 * with SHA3-224) across variants. 2x multiplier + 256 tail adds margin. */
#define WH_TEST_SHA3_BIGBUF_SZ                                              \
    (2u *                                                                   \
     (WH_MESSAGE_CRYPTO_SHA3_MAX_INLINE_UPDATE_SZ(WC_SHA3_512_BLOCK_SIZE) + \
      256u))
static uint8_t whTest_Sha3BigBuf[WH_TEST_SHA3_BIGBUF_SZ];

static void whTest_Sha3FillBuf(uint8_t* buf, uint32_t sz)
{
    uint32_t i;
    for (i = 0; i < sz; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xffu);
    }
}

/* Per-variant basic + large-input test using the wolfCrypt API. */
static int whTest_CryptoSha3OneVariant(whClientContext* ctx, int devId,
                                       const whTestSha3Variant* v)
{
    int      ret = WH_ERROR_OK;
    wc_Sha3  sha[1];
    uint8_t  out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t  ref[WC_SHA3_512_DIGEST_SIZE];
    uint32_t cases[] = {0u,
                        1u,
                        v->blockSize - 1u,
                        v->blockSize,
                        v->blockSize + 1u,
                        3u * v->blockSize,
                        v->maxInlineSz,
                        v->maxInlineSz + 1u,
                        WH_TEST_SHA3_BIGBUF_SZ - 1u};
    size_t   n;
    (void)ctx;

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    for (n = 0; n < sizeof(cases) / sizeof(cases[0]) && ret == 0; n++) {
        uint32_t len = cases[n];
        if (len > WH_TEST_SHA3_BIGBUF_SZ)
            continue;

        ret = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret != 0) {
            WH_ERROR_PRINT("%s reference failed: %d\n", v->name, ret);
            break;
        }

        ret = v->initFn(sha, NULL, devId);
        if (ret == 0 && len > 0) {
            ret = v->updateFn(sha, whTest_Sha3BigBuf, len);
        }
        if (ret == 0) {
            ret = v->finalFn(sha, out);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s mismatch at len=%u devId=0x%X\n", v->name,
                           (unsigned)len, devId);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("%s DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

/* One-shot wrapper bad-arg coverage: (in == NULL, inLen != 0) must be
 * rejected before any state mutation. Regression check: the oneshot
 * wrappers previously skipped the update branch on this input and silently
 * returned a digest of the (empty) state. */
static int whTest_CryptoSha3OneshotBadArgs(whClientContext*         ctx,
                                           const whTestSha3Variant* v)
{
    int     ret;
    wc_Sha3 sha[1];
    uint8_t out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t in[1] = {0};

    ret = v->initFn(sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = v->oneshotFn(ctx, sha, NULL, 1u, out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s oneshot(NULL,1): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }

    /* sha == NULL with valid input must be rejected, not dereferenced: the
     * oneshot reads sha->i to size each chunk before the lower-level helper's
     * NULL check runs. */
    ret = v->oneshotFn(ctx, NULL, in, sizeof(in), out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s oneshot(sha=NULL): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }

#ifdef WOLFHSM_CFG_DMA
    ret = v->initFn(sha, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
    ret = v->dmaOneshotFn(ctx, sha, NULL, 1u, out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s dma oneshot(NULL,1): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }
    ret = v->dmaOneshotFn(ctx, NULL, in, sizeof(in), out);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s dma oneshot(sha=NULL): expected BADARGS, got %d\n",
                       v->name, ret);
        return -1;
    }
#endif

    WH_TEST_PRINT("%s ONESHOT BADARGS SUCCESS\n", v->name);
    return 0;
}

/* Keccak-256 needs hash flags, and certifiable FIPS builds refuse it */
#if defined(WOLFSSL_HASH_FLAGS) && !defined(WOLFSSL_NO_KECCAK256)
#define WH_TEST_KECCAK256
#endif /* WOLFSSL_HASH_FLAGS && !WOLFSSL_NO_KECCAK256 */

#if defined(WH_TEST_KECCAK256) && !defined(WOLFSSL_NOSHA3_256)
/* A devId bound to the DMA-only callback, which has no non-DMA fallback */
#define WH_TEST_SHA3_DMA_DEVID 0x57534433 /* "WSD3" */

static const char whTest_Sha3KeccakIn[] = "wolfHSM SHA3 Keccak-mode vector";

/* SHA3-256 of the vector, via a direct API fn or wolfCrypt if fn is NULL */
static int whTest_Sha3KeccakHash(whClientContext* ctx, int devId, word32 flags,
                                 int (*fn)(whClientContext*, wc_Sha3*,
                                           const uint8_t*, uint32_t, uint8_t*),
                                 uint8_t* out)
{
    const uint32_t inLen = (uint32_t)(sizeof(whTest_Sha3KeccakIn) - 1u);
    wc_Sha3        sha[1];
    int            ret;

    ret = wc_InitSha3_256(sha, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha3_SetFlags(sha, flags);
    }
    if ((ret == 0) && (fn != NULL)) {
        ret = fn(ctx, sha, (const uint8_t*)whTest_Sha3KeccakIn, inLen, out);
    }
    else if (ret == 0) {
        ret = wc_Sha3_256_Update(sha, (const byte*)whTest_Sha3KeccakIn, inLen);
        if (ret == 0) {
            ret = wc_Sha3_256_Final(sha, out);
        }
    }
    wc_Sha3_256_Free(sha);
    return ret;
}

/* Keccak-256 must run on the server and match the software reference */
static int whTest_Sha3KeccakPath(whClientContext* ctx, const char* path,
                                 int devId,
                                 int (*fn)(whClientContext*, wc_Sha3*,
                                           const uint8_t*, uint32_t, uint8_t*),
                                 const uint8_t* ref)
{
    const uint16_t seq = ctx->comm->seq;
    uint8_t        out[WC_SHA3_256_DIGEST_SIZE];
    int            ret;

    ret = whTest_Sha3KeccakHash(ctx, devId, WC_HASH_SHA3_KECCAK256, fn, out);
    if (ret != 0) {
        WH_ERROR_PRINT("Keccak %s failed: %d\n", path, ret);
        return ret;
    }
    if ((seq == ctx->comm->seq) || (memcmp(out, ref, sizeof(out)) != 0)) {
        WH_ERROR_PRINT("Keccak %s not on the server or wrong\n", path);
        return -1;
    }
    return 0;
}

static int whTest_CryptoSha3Keccak(whClientContext* ctx, int devId)
{
    uint8_t keccakRef[WC_SHA3_256_DIGEST_SIZE];
    uint8_t sha3Ref[WC_SHA3_256_DIGEST_SIZE];
    int     ret;

    /* Software references, which must differ for the checks to mean much */
    ret = whTest_Sha3KeccakHash(ctx, INVALID_DEVID, WC_HASH_SHA3_KECCAK256,
                                NULL, keccakRef);
    if (ret == 0) {
        ret = whTest_Sha3KeccakHash(ctx, INVALID_DEVID, 0, NULL, sha3Ref);
    }
    if ((ret == 0) && (memcmp(keccakRef, sha3Ref, sizeof(keccakRef)) == 0)) {
        WH_ERROR_PRINT("Keccak and SHA3-256 digests unexpectedly equal\n");
        ret = -1;
    }

    if (ret == 0) {
        ret =
            whTest_Sha3KeccakPath(ctx, "wolfCrypt API", devId, NULL, keccakRef);
    }
    if (ret == 0) {
        ret = whTest_Sha3KeccakPath(ctx, "direct API", devId,
                                    wh_Client_Sha3_256, keccakRef);
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == 0) {
        ret = whTest_Sha3KeccakPath(ctx, "direct DMA API", devId,
                                    wh_Client_Sha3_256Dma, keccakRef);
    }
#ifndef WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
    if (ret == 0) {
        ret = wc_CryptoCb_RegisterDevice(WH_TEST_SHA3_DMA_DEVID,
                                         wh_Client_CryptoCbDma, ctx);
        if (ret == 0) {
            ret = whTest_Sha3KeccakPath(
                ctx, "DMA callback", WH_TEST_SHA3_DMA_DEVID, NULL, keccakRef);
            wc_CryptoCb_UnRegisterDevice(WH_TEST_SHA3_DMA_DEVID);
        }
    }
#endif /* !WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT */
#endif /* WOLFHSM_CFG_DMA */

    if (ret == 0) {
        WH_TEST_PRINT("SHA3-256 KECCAK DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WH_TEST_KECCAK256 && !WOLFSSL_NOSHA3_256 */

/* Per-variant native async test. Exercises: basic single round, pure-buffer
 * fill, multi-round, and oversized-input rejection. */
static int whTest_CryptoSha3AsyncOneVariant(whClientContext* ctx, int devId,
                                            const whTestSha3Variant* v)
{
    int     ret = WH_ERROR_OK;
    wc_Sha3 sha[1];
    uint8_t out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t ref[WC_SHA3_512_DIGEST_SIZE];

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    /* Case A: basic Update + Final via the async API */
    if (ret == 0) {
        uint32_t len  = 3u * v->blockSize + 17u;
        bool     sent = false;
        ret           = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        if (ret == 0)
            ret =
                v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf, len, &sent);
        if (ret == 0 && sent) {
            do {
                ret = v->asyncUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0)
            ret = v->asyncFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->asyncFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s async case A mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case B: pure-buffer-fill update (less than one block), Final */
    if (ret == 0) {
        uint32_t len  = v->blockSize - 1u;
        bool     sent = false;
        ret           = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        if (ret == 0)
            ret =
                v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf, len, &sent);
        if (ret == 0 && sent) {
            /* unexpected — should have been fully buffered */
            WH_ERROR_PRINT("%s case B: unexpected sent==true\n", v->name);
            ret = -1;
        }
        if (ret == 0)
            ret = v->asyncFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->asyncFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s async case B mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case C: multi-round, ~70% of per-call capacity per chunk */
    if (ret == 0) {
        uint32_t total    = WH_TEST_SHA3_BIGBUF_SZ;
        uint32_t consumed = 0;
        uint32_t cap;
        ret = whTest_Sha3Reference(v, whTest_Sha3BigBuf, total, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        while (ret == 0 && consumed < total) {
            cap = v->maxInlineSz + (uint32_t)(v->blockSize - 1u - sha->i);
            uint32_t chunk = (cap * 7u) / 10u;
            uint32_t rem   = total - consumed;
            bool     sent  = false;
            if (chunk == 0)
                chunk = 1;
            if (chunk > cap)
                chunk = cap;
            if (chunk > rem)
                chunk = rem;
            ret = v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf + consumed,
                                        chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = v->asyncUpdateResponse(ctx, sha);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0)
                consumed += chunk;
        }
        if (ret == 0)
            ret = v->asyncFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->asyncFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s async case C mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case D: oversize input must be rejected without state mutation. */
    if (ret == 0) {
        uint32_t cap, oversz;
        wc_Sha3  saved;
        bool     sent = false;
        ret           = v->initFn(sha, NULL, devId);
        cap           = v->maxInlineSz + (uint32_t)(v->blockSize - 1u - sha->i);
        oversz        = cap + 1u;
        if (oversz > WH_TEST_SHA3_BIGBUF_SZ)
            oversz = WH_TEST_SHA3_BIGBUF_SZ;
        if (ret == 0) {
            saved = *sha;
            ret   = v->asyncUpdateRequest(ctx, sha, whTest_Sha3BigBuf, oversz,
                                          &sent);
            if (ret != WH_ERROR_REQUEST_SIZE) {
                WH_ERROR_PRINT("%s case D: expected REQUEST_SIZE, got %d\n",
                               v->name, ret);
                ret = -1;
            }
            else if (sent) {
                WH_ERROR_PRINT("%s case D: sent should be false\n", v->name);
                ret = -1;
            }
            else if (memcmp(&saved, sha, sizeof(saved)) != 0) {
                WH_ERROR_PRINT("%s case D: sha state mutated\n", v->name);
                ret = -1;
            }
            else {
                ret = WH_ERROR_OK;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("%s ASYNC DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTest_CryptoSha3DmaAsyncOneVariant(whClientContext* ctx, int devId,
                                               const whTestSha3Variant* v)
{
    int     ret = WH_ERROR_OK;
    wc_Sha3 sha[1];
    uint8_t out[WC_SHA3_512_DIGEST_SIZE];
    uint8_t ref[WC_SHA3_512_DIGEST_SIZE];

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    /* Case A: single large DMA update + final */
    if (ret == 0) {
        uint32_t len  = WH_TEST_SHA3_BIGBUF_SZ;
        bool     sent = false;
        ret           = whTest_Sha3Reference(v, whTest_Sha3BigBuf, len, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        if (ret == 0)
            ret = v->dmaUpdateRequest(ctx, sha, whTest_Sha3BigBuf, len, &sent);
        if (ret == 0 && sent) {
            do {
                ret = v->dmaUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0)
            ret = v->dmaFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->dmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s DMA async case A mismatch\n", v->name);
            ret = -1;
        }
    }

    /* Case B: multi-round DMA with 1024-byte chunks */
    if (ret == 0) {
        uint32_t       total    = WH_TEST_SHA3_BIGBUF_SZ;
        uint32_t       consumed = 0;
        const uint32_t chunkSz  = 1024u;
        ret = whTest_Sha3Reference(v, whTest_Sha3BigBuf, total, ref);
        if (ret == 0)
            ret = v->initFn(sha, NULL, devId);
        while (ret == 0 && consumed < total) {
            uint32_t rem   = total - consumed;
            uint32_t chunk = (rem < chunkSz) ? rem : chunkSz;
            bool     sent  = false;
            ret = v->dmaUpdateRequest(ctx, sha, whTest_Sha3BigBuf + consumed,
                                      chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = v->dmaUpdateResponse(ctx, sha);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0)
                consumed += chunk;
        }
        if (ret == 0)
            ret = v->dmaFinalRequest(ctx, sha);
        if (ret == 0) {
            do {
                ret = v->dmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && memcmp(out, ref, v->digestSize) != 0) {
            WH_ERROR_PRINT("%s DMA async case B mismatch\n", v->name);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("%s DMA ASYNC DEVID=0x%X SUCCESS\n", v->name, devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

/* Run the cryptocb-routed suites (wolfCrypt API, one-shot bad-args, Keccak
 * contract) for every compiled variant against the given devId. */
static int _whTest_CryptoSha3Sync(whClientContext* ctx, int devId)
{
    int    ret = WH_ERROR_OK;
    size_t v;
    for (v = 0; v < sizeof(whTestSha3Variants) / sizeof(whTestSha3Variants[0]);
         v++) {
        ret = whTest_CryptoSha3OneVariant(ctx, devId, &whTestSha3Variants[v]);
        if (ret != 0)
            break;
        ret = whTest_CryptoSha3OneshotBadArgs(ctx, &whTestSha3Variants[v]);
        if (ret != 0)
            break;
    }
#if defined(WH_TEST_KECCAK256) && !defined(WOLFSSL_NOSHA3_256)
    if (ret == 0) {
        ret = whTest_CryptoSha3Keccak(ctx, devId);
    }
#endif
    return ret;
}

static int _whTest_CryptoSha3Async(whClientContext* ctx)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret   = WH_ERROR_OK;
    size_t v;
    for (v = 0; v < sizeof(whTestSha3Variants) / sizeof(whTestSha3Variants[0]);
         v++) {
        ret = whTest_CryptoSha3AsyncOneVariant(ctx, devId,
                                               &whTestSha3Variants[v]);
        if (ret != 0)
            break;
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_CryptoSha3DmaAsync(whClientContext* ctx)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret   = WH_ERROR_OK;
    size_t v;

    /* Prefer DMA dispatch so wolfCrypt-routed ops take the DMA path alongside
     * the wh_Client_*Dma request API driven by the test. */
    (void)wh_Client_SetDmaMode(ctx, 1);
    for (v = 0; v < sizeof(whTestSha3Variants) / sizeof(whTestSha3Variants[0]);
         v++) {
        ret = whTest_CryptoSha3DmaAsyncOneVariant(ctx, devId,
                                                  &whTestSha3Variants[v]);
        if (ret != 0)
            break;
    }
    /* Restore the standard (non-DMA) dispatch mode */
    (void)wh_Client_SetDmaMode(ctx, 0);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

/* A raw request; dropSz bytes are cut from the end to make it short */
typedef struct {
    uint32_t isLastBlock;
    uint32_t inSz;
    uint32_t outSz;
    uint32_t flags;
    uint32_t dropSz;
    uint32_t dmaInSz; /* DMA path only */
    uint32_t dmaOutAddr;
    uint32_t dmaOutSz;
} whTestSha3RawRequest;

/* Send each request as-is and require the server to return expected */
static int _whTest_Sha3RawRequests(whClientContext* ctx, int hashType, int dma,
                                   const whTestSha3RawRequest* reqs,
                                   uint32_t cnt, int expected)
{
    uint8_t*                              dataPtr;
    whMessageCrypto_GenericRequestHeader* hdr;
    whMessageCrypto_Sha3DmaRequest*       dmaReq;
    whMessageCrypto_Sha3Request*          req;
    uint8_t*                              in;
    uint32_t                              reqSz;
    uint16_t                              group;
    uint16_t                              action;
    uint16_t                              dataSz;
    uint32_t                              i;
    int                                   rc;
    int                                   ret = WH_ERROR_OK;

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }
    hdr    = (whMessageCrypto_GenericRequestHeader*)dataPtr;
    dmaReq = (whMessageCrypto_Sha3DmaRequest*)(hdr + 1);
    req    = dma ? &dmaReq->req : (whMessageCrypto_Sha3Request*)(hdr + 1);
    reqSz  = dma ? sizeof(*dmaReq) : sizeof(*req);
    in     = (uint8_t*)(hdr + 1) + reqSz;

    for (i = 0; (ret == WH_ERROR_OK) && (i < cnt); i++) {
        const whTestSha3RawRequest* r = &reqs[i];

        memset(dataPtr, 0, sizeof(*hdr) + reqSz);
        hdr->algoType    = (whMessageCrypto_AlgoType)hashType;
        hdr->affinity    = ctx->cryptoAffinity;
        req->isLastBlock = r->isLastBlock;
        req->inSz        = r->inSz;
        req->outSz       = r->outSz;
        req->flags       = r->flags;
        if (dma) {
            dmaReq->input.sz    = r->dmaInSz;
            dmaReq->output.addr = r->dmaOutAddr;
            dmaReq->output.sz   = r->dmaOutSz;
        }
        memcpy(in, whTest_Sha3BigBuf, r->inSz);

        ret = wh_Client_SendRequest(
            ctx, dma ? WH_MESSAGE_GROUP_CRYPTO_DMA : WH_MESSAGE_GROUP_CRYPTO,
            WC_ALGO_TYPE_HASH,
            (uint16_t)(sizeof(*hdr) + reqSz + r->inSz - r->dropSz), dataPtr);
        if (ret == WH_ERROR_OK) {
            do {
                ret =
                    wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                           WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == WH_ERROR_OK) {
            rc = ((whMessageCrypto_GenericResponseHeader*)dataPtr)->rc;
            if (rc != expected) {
                WH_ERROR_PRINT("type %d dma %d raw request %u returned %d, "
                               "expected %d\n",
                               hashType, dma, (unsigned)i, rc, expected);
                ret = WH_ERROR_ABORTED;
            }
        }
    }
    return ret;
}

#define WH_TEST_SHA3_RAW_CNT(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

#ifdef WH_TEST_KECCAK256
#define WH_TEST_SHA3_KECCAK_RC WH_ERROR_OK
#else
#define WH_TEST_SHA3_KECCAK_RC NOT_COMPILED_IN
#endif /* WH_TEST_KECCAK256 */

/* The server must check requests itself rather than trust the client */
static int _whTest_Sha3ServerRequests(whClientContext* ctx, const char* name,
                                      int hashType, uint32_t rate,
                                      uint32_t digestSize)
{
    const uint32_t maxOut = WH_MESSAGE_CRYPTO_SHA3_MAX_INLINE_OUTPUT_SZ;
    const uint32_t maxSqz = (maxOut / rate) * rate;
    const uint32_t finSz  = (digestSize != 0) ? digestSize : maxOut;
    /* Update and final, for every variant */
    const whTestSha3RawRequest accepted[] = {
        {0, rate, 0, 0, 0, 0, 0, 0},
        {1, rate - 1u, finSz, 0, 0, 0, 0, 0},
    };
    /* Update and final in Keccak mode, if the server offers it */
    const whTestSha3RawRequest keccak[] = {
        {0, rate, 0, WH_MESSAGE_CRYPTO_SHA3_FLAG_KECCAK256, 0, 0, 0, 0},
        {1, rate - 1u, finSz, WH_MESSAGE_CRYPTO_SHA3_FLAG_KECCAK256, 0, 0, 0,
         0},
    };
    /* Absorb and squeeze, SHAKE only */
    const whTestSha3RawRequest xofOps[] = {
        {1, rate - 1u, 0, 0, 0, 0, 0, 0},
        {0, 0, maxSqz, 0, 0, 0, 0, 0},
    };
    const whTestSha3RawRequest rejected[] = {
        /* Shorter than the request struct, then shorter than inSz */
        {1, 0, finSz, 0, 1u, 0, 0, 0},
        {1, 10u, finSz, 0, 1u, 0, 0, 0},
        /* Update not in whole blocks */
        {0, 1u, 0, 0, 0, 0, 0, 0},
        /* Final with a full-block tail, or too much output */
        {1, rate, finSz, 0, 0, 0, 0, 0},
        {1, 0, maxOut + 1u, 0, 0, 0, 0, 0},
        /* Unknown flags */
        {0, rate, 0, WH_MESSAGE_CRYPTO_SHA3_FLAG_KECCAK256 << 1, 0, 0, 0, 0},
    };
    /* SHAKE: absorb with a full tail, squeeze with input or bad sizes */
    const whTestSha3RawRequest xofRejected[] = {
        {1, rate, 0, 0, 0, 0, 0, 0},
        {0, 1u, rate, 0, 0, 0, 0, 0},
        {0, 0, rate + 1u, 0, 0, 0, 0, 0},
        {0, 0, maxSqz + rate, 0, 0, 0, 0, 0},
    };
    /* SHA3: wrong digest size, absorb and squeeze */
    const whTestSha3RawRequest fixedRejected[] = {
        {1, 0, digestSize - 1u, 0, 0, 0, 0, 0},
        {1, 0, digestSize + 1u, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, rate, 0, 0, 0, 0, 0},
    };
    const int isXof = (digestSize == 0);
    int       ret;

    whTest_Sha3FillBuf(whTest_Sha3BigBuf, WH_TEST_SHA3_BIGBUF_SZ);

    ret = _whTest_Sha3RawRequests(ctx, hashType, 0, accepted,
                                  WH_TEST_SHA3_RAW_CNT(accepted), WH_ERROR_OK);
    if (ret == WH_ERROR_OK) {
        ret = _whTest_Sha3RawRequests(ctx, hashType, 0, rejected,
                                      WH_TEST_SHA3_RAW_CNT(rejected),
                                      WH_ERROR_BADARGS);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_Sha3RawRequests(ctx, hashType, 0, keccak,
                                      WH_TEST_SHA3_RAW_CNT(keccak),
                                      WH_TEST_SHA3_KECCAK_RC);
    }
    if (ret == WH_ERROR_OK) {
        ret = _whTest_Sha3RawRequests(ctx, hashType, 0, xofOps,
                                      WH_TEST_SHA3_RAW_CNT(xofOps),
                                      isXof ? WH_ERROR_OK : WH_ERROR_BADARGS);
    }
    if (ret == WH_ERROR_OK) {
        ret = isXof
                  ? _whTest_Sha3RawRequests(ctx, hashType, 0, xofRejected,
                                            WH_TEST_SHA3_RAW_CNT(xofRejected),
                                            WH_ERROR_BADARGS)
                  : _whTest_Sha3RawRequests(ctx, hashType, 0, fixedRejected,
                                            WH_TEST_SHA3_RAW_CNT(fixedRejected),
                                            WH_ERROR_BADARGS);
    }
#ifdef WOLFHSM_CFG_DMA
    if (ret == WH_ERROR_OK) {
        /* DMA: output reserved, final with DMA input, partial DMA blocks */
        const whTestSha3RawRequest dmaRejected[] = {
            {0, rate, 0, 0, 0, 0, 0x1000u, 0},
            {0, rate, 0, 0, 0, 0, 0, 8u},
            {1, 0, finSz, 0, 0, rate, 0, 0},
            {0, 0, 0, 0, 0, 1u, 0, 0},
        };

        if (isXof) {
            /* SHAKE is not offered over DMA */
            ret = _whTest_Sha3RawRequests(ctx, hashType, 1, accepted,
                                          WH_TEST_SHA3_RAW_CNT(accepted),
                                          NOT_COMPILED_IN);
        }
        else {
            ret = _whTest_Sha3RawRequests(ctx, hashType, 1, accepted,
                                          WH_TEST_SHA3_RAW_CNT(accepted),
                                          WH_ERROR_OK);
            if (ret == WH_ERROR_OK) {
                ret = _whTest_Sha3RawRequests(ctx, hashType, 1, rejected,
                                              WH_TEST_SHA3_RAW_CNT(rejected),
                                              WH_ERROR_BADARGS);
            }
            if (ret == WH_ERROR_OK) {
                ret = _whTest_Sha3RawRequests(ctx, hashType, 1, keccak,
                                              WH_TEST_SHA3_RAW_CNT(keccak),
                                              WH_TEST_SHA3_KECCAK_RC);
            }
            if (ret == WH_ERROR_OK) {
                ret = _whTest_Sha3RawRequests(
                    ctx, hashType, 1, fixedRejected,
                    WH_TEST_SHA3_RAW_CNT(fixedRejected), WH_ERROR_BADARGS);
            }
            if (ret == WH_ERROR_OK) {
                ret = _whTest_Sha3RawRequests(ctx, hashType, 1, dmaRejected,
                                              WH_TEST_SHA3_RAW_CNT(dmaRejected),
                                              WH_ERROR_BADARGS);
            }
        }
    }
#endif /* WOLFHSM_CFG_DMA */
    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("%s server request checks SUCCESS\n", name);
    }
    return ret;
}

static int _whTest_CryptoSha3ServerRequests(whClientContext* ctx)
{
    int    ret = WH_ERROR_OK;
    size_t v;

    for (v = 0; (ret == WH_ERROR_OK) && (v < sizeof(whTestSha3Variants) /
                                                 sizeof(whTestSha3Variants[0]));
         v++) {
        const whTestSha3Variant* var = &whTestSha3Variants[v];

        ret = _whTest_Sha3ServerRequests(ctx, var->name, var->hashType,
                                         var->blockSize, var->digestSize);
    }
#ifdef WOLFSSL_SHAKE128
    if (ret == WH_ERROR_OK) {
        ret = _whTest_Sha3ServerRequests(ctx, "SHAKE128", WC_HASH_TYPE_SHAKE128,
                                         WC_SHA3_128_BLOCK_SIZE, 0);
    }
#endif /* WOLFSSL_SHAKE128 */
#ifdef WOLFSSL_SHAKE256
    if (ret == WH_ERROR_OK) {
        ret = _whTest_Sha3ServerRequests(ctx, "SHAKE256", WC_HASH_TYPE_SHAKE256,
                                         WC_SHA3_256_BLOCK_SIZE, 0);
    }
#endif /* WOLFSSL_SHAKE256 */
    return ret;
}

int whTest_Crypto_Sha3(whClientContext* ctx)
{
    int i;

    /* The wolfCrypt API path dispatches through the cryptocb, so run it once
     * per dispatch mode on the per-client devId to cover the normal and DMA
     * server paths. The explicit request/response suites are
     * transport-specific (comm-buffer Async vs DmaAsync), not devId-routed --
     * run each once. */
    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        (void)wh_Client_SetDmaMode(ctx, i);
        WH_TEST_RETURN_ON_FAIL(
            _whTest_CryptoSha3Sync(ctx, WH_CLIENT_DEVID(ctx)));
    }
    (void)wh_Client_SetDmaMode(ctx, 0);

    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha3Async(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha3DmaAsync(ctx));
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha3ServerRequests(ctx));
    return 0;
}

#endif /* WOLFSSL_SHA3 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
