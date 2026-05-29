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
 * test-refactor/client-server/wh_test_crypto_sha.c
 *
 * SHA-224 / 256 / 384 / 512 routed through the server via WH_DEV_ID.
 * Each hash size has four variants:
 *   whTest_CryptoSha<N>           sync wolfCrypt API single+multi block
 *   whTest_CryptoSha<N>LargeInput sync test with input larger than the
 *                                 server transport buffer (chunked send)
 *   whTest_CryptoSha<N>Async      direct exercise of wh_Client_Sha*Request
 *                                 / Response primitives
 *   whTest_CryptoSha<N>DmaAsync   same, via the DMA messaging path
 *
 * The legacy implementations are preserved verbatim as static *Impl
 * helpers; thin public wrappers above each family own the WC_RNG lifecycle
 * so the public API matches the rest of the test-refactor suite.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifndef NO_SHA256
static int whTest_CryptoSha256Impl(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx; (void)rng; /* Not currently used */
    int ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA256_DIGEST_SIZE] = {
        0xff, 0xe0, 0x54, 0xfe, 0x7a, 0xe0, 0xcb, 0x6d, 0xc6, 0x5c, 0x3a,
        0xf9, 0xb6, 0x1d, 0x52, 0x09, 0xf4, 0x39, 0x85, 0x1d, 0xb4, 0x3d,
        0x0b, 0xa5, 0x99, 0x73, 0x37, 0xdf, 0x15, 0x46, 0x68, 0xeb};
    /* Vector long enough to span a SHA256 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA256_DIGEST_SIZE] = {
        0x7b, 0x54, 0x45, 0x86, 0xb3, 0x51, 0x43, 0x4e, 0xf6, 0x83, 0xdb,
        0x78, 0x1d, 0x94, 0xd6, 0xb0, 0x36, 0x9b, 0x36, 0x56, 0x93, 0x0e,
        0xf4, 0x47, 0x9b, 0xae, 0xff, 0xfa, 0x1f, 0x36, 0x38, 0x64};

    /* Initialize SHA256 structure */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha256 on devId 0x%X: %d\n", devId,
                ret);
    } else {
        /* Test SHA256 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha256Update(sha256,
                (const byte*)inOne,
                WC_SHA256_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        } else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha256Final(sha256, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n", ret);
            } else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA256_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA256 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA256_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha256Free(sha256);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha256 for devId 0x%X: %d\n",
                    devId, ret);
        } else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha256Update(sha256,
                    (const byte*)inMulti,
                    1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha256Update (first) %d\n", ret);
            } else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha256Update(sha256,
                        (const byte*)inMulti + 1,
                        WC_SHA256_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha256Update (mid) %d\n", ret);
                } else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha256Update(sha256,
                            (const byte*)inMulti + 1 + WC_SHA256_BLOCK_SIZE,
                           strlen(inMulti) - 1 - WC_SHA256_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha256Update (last) %d\n",
                                ret);
                    } else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha256Final(sha256, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n",
                                    ret);
                        } else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA256_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA256 hash does not match the "
                                        "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha256Free(sha256);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA256 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA256 (no devId) so we can compare. */
static int whTest_Sha256Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA256_DIGEST_SIZE])
{
    wc_Sha256 sw[1];
    int       ret = wc_InitSha256_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha256Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(sw, out);
    }
    (void)wc_Sha256Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha256BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ + 64u)];

static int whTest_CryptoSha256LargeInputImpl(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    uint8_t   ref[WC_SHA256_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha256BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha256BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha256Update(sha256, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha256Final(sha256, out);
    }
    (void)wc_Sha256Free(sha256);
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA256 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, out);
        }
        (void)wc_Sha256Free(sha256);
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA256 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, out);
        }
        (void)wc_Sha256Free(sha256);
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA256 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha256_ex(sha256, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha256Update(sha256, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha256Final(sha256, out);
            }
            (void)wc_Sha256Free(sha256);
            if (ret == 0) {
                ret = whTest_Sha256Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA256 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA256 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA256 primitives. */
static int whTest_CryptoSha256AsyncImpl(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    uint8_t   ref[WC_SHA256_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha256BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha256BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha256UpdateRequest(ctx, sha256, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha256UpdateResponse(ctx, sha256);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha256FinalRequest(ctx, sha256);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA256 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha256Free(sha256);
        ret = wc_InitSha256_ex(sha256, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha256UpdateRequest(ctx, sha256, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA256: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha256FinalRequest(ctx, sha256);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA256 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha256Free(sha256);
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha256UpdateRequest(ctx, sha256, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha256UpdateResponse(ctx, sha256);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha256FinalRequest(ctx, sha256);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA256 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA256_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha256Free(sha256);
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha256->digest, WC_SHA256_DIGEST_SIZE);
            savedBuffLen = sha256->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA256_BLOCK_SIZE - 1u - sha256->buffLen);
            sent = true;
            rc   = wh_Client_Sha256UpdateRequest(ctx, sha256, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA256: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA256: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha256->buffLen != savedBuffLen ||
                     memcmp(sha256->digest, savedDigest,
                            WC_SHA256_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA256: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha256Free(sha256);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA256 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA256 primitives. */
static int whTest_CryptoSha256DmaAsyncImpl(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    uint8_t   ref[WC_SHA256_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha256BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha256BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha256DmaUpdateRequest(ctx, sha256, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha256DmaUpdateResponse(ctx, sha256);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha256DmaFinalRequest(ctx, sha256);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha256DmaFinalResponse(ctx, sha256, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha256Free(sha256);
    if (ret == 0) {
        ret = whTest_Sha256Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA256 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha256_ex(sha256, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            bool     sent  = false;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            ret = wh_Client_Sha256DmaUpdateRequest(ctx, sha256, buf + consumed,
                                                   chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha256DmaUpdateResponse(ctx, sha256);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha256DmaFinalRequest(ctx, sha256);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha256DmaFinalResponse(ctx, sha256, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha256Free(sha256);
        if (ret == 0) {
            ret = whTest_Sha256Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA256_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA256 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA256 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int _whTest_CryptoSha256(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha256Impl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha256LargeInput(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha256LargeInputImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha256Async(whClientContext* ctx)
{
    int    devId = WH_DEV_ID;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha256AsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_CryptoSha256DmaAsync(whClientContext* ctx)
{
    int    devId = WH_DEV_ID_DMA;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha256DmaAsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224
static int whTest_CryptoSha224Impl(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA224_DIGEST_SIZE] = {
        0xa8, 0x8c, 0xd5, 0xcd, 0xe6, 0xd6, 0xfe, 0x91, 0x36, 0xa4,
        0xe5, 0x8b, 0x49, 0x16, 0x74, 0x61, 0xea, 0x95, 0xd3, 0x88,
        0xca, 0x2b, 0xdb, 0x7a, 0xfd, 0xc3, 0xcb, 0xf4};
    /* Vector long enough to span a SHA224 block */
    const char inMulti[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
                           "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA224_DIGEST_SIZE] = {
        0xb4, 0x22, 0xdc, 0xe8, 0xf9, 0x48, 0x8c, 0x4b, 0xc3, 0xef,
        0x8e, 0x7d, 0xbe, 0x11, 0xc7, 0x21, 0xba, 0x38, 0xcb, 0x61,
        0xf5, 0x6b, 0x7d, 0xc5, 0x30, 0xa7, 0x9c, 0xfd};
    /* Initialize SHA224 structure */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha224 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA224 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha224Update(sha224, (const byte*)inOne, WC_SHA224_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha224Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha224Final(sha224, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha224Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA224_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA224 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA224_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha224Free(sha224);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha224 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha224Update(sha224, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha224Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha224Update(sha224, (const byte*)inMulti + 1,
                                      WC_SHA224_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha224Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha224Update(
                        sha224, (const byte*)inMulti + 1 + WC_SHA224_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA224_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha224Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha224Final(sha224, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha224Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA224_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA224 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha224Free(sha224);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA224 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA224 (no devId) so we can compare. */
static int whTest_Sha224Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA224_DIGEST_SIZE])
{
    wc_Sha224 sw[1];
    int       ret = wc_InitSha224_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha224Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha224Final(sw, out);
    }
    (void)wc_Sha224Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha224BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ + 64u)];

static int whTest_CryptoSha224LargeInputImpl(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    uint8_t   ref[WC_SHA224_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha224BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha224BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha224Update(sha224, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha224Final(sha224, out);
    }
    (void)wc_Sha224Free(sha224);
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA224 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha224Update(sha224, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha224Final(sha224, out);
        }
        (void)wc_Sha224Free(sha224);
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA224 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha224Update(sha224, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha224Final(sha224, out);
        }
        (void)wc_Sha224Free(sha224);
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA224 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha224_ex(sha224, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha224Update(sha224, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha224Final(sha224, out);
            }
            (void)wc_Sha224Free(sha224);
            if (ret == 0) {
                ret = whTest_Sha224Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA224 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA224 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA224 primitives. */
static int whTest_CryptoSha224AsyncImpl(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    uint8_t   ref[WC_SHA224_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha224BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha224BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha224UpdateRequest(ctx, sha224, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha224UpdateResponse(ctx, sha224);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha224FinalRequest(ctx, sha224);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA224 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha224Free(sha224);
        ret = wc_InitSha224_ex(sha224, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha224UpdateRequest(ctx, sha224, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA224: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha224FinalRequest(ctx, sha224);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA224 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha224Free(sha224);
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha224UpdateRequest(ctx, sha224, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha224UpdateResponse(ctx, sha224);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha224FinalRequest(ctx, sha224);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA224 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA256_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha224Free(sha224);
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha224->digest, WC_SHA256_DIGEST_SIZE);
            savedBuffLen = sha224->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA224_BLOCK_SIZE - 1u - sha224->buffLen);
            sent = true;
            rc   = wh_Client_Sha224UpdateRequest(ctx, sha224, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA224: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA224: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha224->buffLen != savedBuffLen ||
                     memcmp(sha224->digest, savedDigest,
                            WC_SHA256_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA224: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha224Free(sha224);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA224 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA224 primitives. */
static int whTest_CryptoSha224DmaAsyncImpl(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    uint8_t   ref[WC_SHA224_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha224BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha224BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha224DmaUpdateRequest(ctx, sha224, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha224DmaUpdateResponse(ctx, sha224);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha224DmaFinalRequest(ctx, sha224);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha224DmaFinalResponse(ctx, sha224, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha224Free(sha224);
    if (ret == 0) {
        ret = whTest_Sha224Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA224 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha224_ex(sha224, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            {
                bool sent = false;
                ret       = wh_Client_Sha224DmaUpdateRequest(
                    ctx, sha224, buf + consumed, chunk, &sent);
                if (ret == 0 && sent) {
                    do {
                        ret = wh_Client_Sha224DmaUpdateResponse(ctx, sha224);
                    } while (ret == WH_ERROR_NOTREADY);
                }
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha224DmaFinalRequest(ctx, sha224);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha224DmaFinalResponse(ctx, sha224, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha224Free(sha224);
        if (ret == 0) {
            ret = whTest_Sha224Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA224_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA224 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA224 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int _whTest_CryptoSha224(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha224Impl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha224LargeInput(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha224LargeInputImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha224Async(whClientContext* ctx)
{
    int    devId = WH_DEV_ID;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha224AsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_CryptoSha224DmaAsync(whClientContext* ctx)
{
    int    devId = WH_DEV_ID_DMA;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha224DmaAsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
static int whTest_CryptoSha384Impl(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA384_DIGEST_SIZE] = {
        0xed, 0xb1, 0x27, 0x30, 0xa3, 0x66, 0x09, 0x8b, 0x3b, 0x2b, 0xea, 0xc7,
        0x5a, 0x3b, 0xef, 0x1b, 0x09, 0x69, 0xb1, 0x5c, 0x48, 0xe2, 0x16, 0x3c,
        0x23, 0xd9, 0x69, 0x94, 0xf8, 0xd1, 0xbe, 0xf7, 0x60, 0xc7, 0xe2, 0x7f,
        0x3c, 0x46, 0x4d, 0x38, 0x29, 0xf5, 0x6c, 0x0d, 0x53, 0x80, 0x8b, 0x0b};
    /* Vector long enough to span a SHA384 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA384_DIGEST_SIZE] = {
        0xe2, 0x56, 0x2a, 0x4b, 0xe2, 0x0a, 0x40, 0x34, 0xc1, 0x23, 0x8b, 0x1d,
        0x68, 0x49, 0x17, 0xdb, 0x8d, 0x3a, 0x78, 0xab, 0x22, 0xf3, 0xa1, 0x51,
        0x70, 0xae, 0x26, 0x80, 0x06, 0x25, 0x99, 0xa5, 0x3d, 0x0f, 0xc3, 0x7a,
        0xbd, 0xe1, 0xe2, 0xc6, 0x07, 0xdf, 0xd9, 0x6a, 0x89, 0xa8, 0x2b, 0x99};
    /* Initialize SHA384 structure */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha384 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA384on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha384Update(sha384, (const byte*)inOne, WC_SHA384_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha384Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha384Final(sha384, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha384Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA384_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA384 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA384_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha384Free(sha384);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha384 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha384Update(sha384, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha384Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha384Update(sha384, (const byte*)inMulti + 1,
                                      WC_SHA384_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha384Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha384Update(
                        sha384, (const byte*)inMulti + 1 + WC_SHA384_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA384_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha384Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha384Final(sha384, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha384Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA384_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA384 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha384Free(sha384);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA384 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA384 (no devId) so we can compare. */
static int whTest_Sha384Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA384_DIGEST_SIZE])
{
    wc_Sha384 sw[1];
    int       ret = wc_InitSha384_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha384Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha384Final(sw, out);
    }
    (void)wc_Sha384Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha384BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ + 128u)];

static int whTest_CryptoSha384LargeInputImpl(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    uint8_t   ref[WC_SHA384_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha384BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha384BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha384Update(sha384, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha384Final(sha384, out);
    }
    (void)wc_Sha384Free(sha384);
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA384 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha384Update(sha384, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha384Final(sha384, out);
        }
        (void)wc_Sha384Free(sha384);
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA384 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha384Update(sha384, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha384Final(sha384, out);
        }
        (void)wc_Sha384Free(sha384);
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA384 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha384_ex(sha384, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha384Update(sha384, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha384Final(sha384, out);
            }
            (void)wc_Sha384Free(sha384);
            if (ret == 0) {
                ret = whTest_Sha384Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA384 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA384 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA384 primitives. */
static int whTest_CryptoSha384AsyncImpl(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    uint8_t   ref[WC_SHA384_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha384BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha384BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha384UpdateRequest(ctx, sha384, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha384UpdateResponse(ctx, sha384);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha384FinalRequest(ctx, sha384);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA384 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha384Free(sha384);
        ret = wc_InitSha384_ex(sha384, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha384UpdateRequest(ctx, sha384, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA384: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha384FinalRequest(ctx, sha384);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA384 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha384Free(sha384);
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha384UpdateRequest(ctx, sha384, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha384UpdateResponse(ctx, sha384);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha384FinalRequest(ctx, sha384);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA384 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA512_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha384Free(sha384);
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha384->digest, WC_SHA512_DIGEST_SIZE);
            savedBuffLen = sha384->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA384_BLOCK_SIZE - 1u - sha384->buffLen);
            sent = true;
            rc   = wh_Client_Sha384UpdateRequest(ctx, sha384, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA384: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA384: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha384->buffLen != savedBuffLen ||
                     memcmp(sha384->digest, savedDigest,
                            WC_SHA512_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA384: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha384Free(sha384);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA384 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA384 primitives. */
static int whTest_CryptoSha384DmaAsyncImpl(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    uint8_t   ref[WC_SHA384_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha384BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha384BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha384DmaUpdateRequest(ctx, sha384, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha384DmaUpdateResponse(ctx, sha384);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha384DmaFinalRequest(ctx, sha384);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha384DmaFinalResponse(ctx, sha384, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha384Free(sha384);
    if (ret == 0) {
        ret = whTest_Sha384Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA384 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha384_ex(sha384, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            {
                bool sent = false;
                ret       = wh_Client_Sha384DmaUpdateRequest(
                    ctx, sha384, buf + consumed, chunk, &sent);
                if (ret == 0 && sent) {
                    do {
                        ret = wh_Client_Sha384DmaUpdateResponse(ctx, sha384);
                    } while (ret == WH_ERROR_NOTREADY);
                }
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha384DmaFinalRequest(ctx, sha384);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha384DmaFinalResponse(ctx, sha384, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha384Free(sha384);
        if (ret == 0) {
            ret = whTest_Sha384Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA384_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA384 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA384 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int _whTest_CryptoSha384(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha384Impl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha384LargeInput(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha384LargeInputImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha384Async(whClientContext* ctx)
{
    int    devId = WH_DEV_ID;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha384AsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_CryptoSha384DmaAsync(whClientContext* ctx)
{
    int    devId = WH_DEV_ID_DMA;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha384DmaAsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static int whTest_CryptoSha512Impl(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA512_DIGEST_SIZE] = {
        0xb7, 0x3d, 0x19, 0x29, 0xaa, 0x61, 0x59, 0x34, 0xe6, 0x1a, 0x87,
        0x15, 0x96, 0xb3, 0xf3, 0xb3, 0x33, 0x59, 0xf4, 0x2b, 0x81, 0x75,
        0x60, 0x2e, 0x89, 0xf7, 0xe0, 0x6e, 0x5f, 0x65, 0x8a, 0x24, 0x36,
        0x67, 0x80, 0x7e, 0xd3, 0x00, 0x31, 0x4b, 0x95, 0xca, 0xcd, 0xd5,
        0x79, 0xf3, 0xe3, 0x3a, 0xbd, 0xfb, 0xe3, 0x51, 0x90, 0x95, 0x19,
        0xa8, 0x46, 0xd4, 0x65, 0xc5, 0x95, 0x82, 0xf3, 0x21};
    /* Vector long enough to span a SHA512 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA512_DIGEST_SIZE] = {
        0xf9, 0x09, 0xb7, 0xb7, 0x7d, 0xa2, 0x32, 0xc8, 0xcf, 0xa8, 0xcc,
        0xde, 0xc4, 0x36, 0x44, 0x74, 0x29, 0x4f, 0xc4, 0x9a, 0xcb, 0x60,
        0x13, 0x6b, 0xdb, 0x10, 0xd6, 0xa6, 0x9d, 0x1b, 0x45, 0xb2, 0x70,
        0xf5, 0x27, 0x9c, 0xe7, 0x80, 0x99, 0x19, 0x9b, 0x91, 0xb3, 0x83,
        0x7f, 0x70, 0xaf, 0x8e, 0x02, 0xd9, 0x6d, 0x20, 0xab, 0x1e, 0x72,
        0xde, 0x7a, 0x25, 0xa3, 0xe5, 0x60, 0x9e, 0xb0, 0x43};
    /* Initialize SHA512 structure */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha512 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA512 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha512Update(sha512, (const byte*)inOne, WC_SHA512_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha512Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha512Final(sha512, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha512Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA512_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA512 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA512_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha512Free(sha512);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha512 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha512Update(sha512, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha512Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha512Update(sha512, (const byte*)inMulti + 1,
                                      WC_SHA512_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha512Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha512Update(
                        sha512, (const byte*)inMulti + 1 + WC_SHA512_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA512_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha512Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha512Final(sha512, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha512Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA512_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA512 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha512Free(sha512);
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA512 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Hash a buffer with a pure-software SHA512 (no devId) so we can compare. */
static int whTest_Sha512Reference(const uint8_t* in, uint32_t inLen,
                                  uint8_t out[WC_SHA512_DIGEST_SIZE])
{
    wc_Sha512 sw[1];
    int       ret = wc_InitSha512_ex(sw, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Sha512Update(sw, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Sha512Final(sw, out);
    }
    (void)wc_Sha512Free(sw);
    return ret;
}

/* Drive the new multi-block wire format through the blocking wrapper. Tests:
 *  - large multi-request input,
 *  - exact per-call inline capacity boundary,
 *  - one-byte-over-capacity boundary (forces a tail in the client buffer),
 *  - non-aligned chunked update sequence.
 *
 * Buffer is sized to comfortably exceed the per-call inline capacity at any
 * reasonable comm-buffer size. We use a static buffer to keep stack pressure
 * low under ASAN. */
static uint8_t
    whTest_Sha512BigBuf[2 *
                        (WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ + 128u)];

static int whTest_CryptoSha512LargeInputImpl(whClientContext* ctx, int devId,
                                         WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    uint8_t   ref[WC_SHA512_DIGEST_SIZE];
    uint8_t*  buf   = whTest_Sha512BigBuf;
    uint32_t  BUFSZ = (uint32_t)sizeof(whTest_Sha512BigBuf);
    uint32_t  i;

    (void)ctx;
    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }

    /* Test 1: large single-update */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret == 0) {
        ret = wc_Sha512Update(sha512, buf, BUFSZ);
    }
    if (ret == 0) {
        ret = wc_Sha512Final(sha512, out);
    }
    (void)wc_Sha512Free(sha512);
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("SHA512 large input mismatch\n");
        ret = -1;
    }

    /* Test 2: exactly the per-call inline capacity in one shot */
    if (ret == 0) {
        const uint32_t cap = WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ;
        ret                = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha512Update(sha512, buf, cap);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(sha512, out);
        }
        (void)wc_Sha512Free(sha512);
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, cap, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA512 capacity-boundary mismatch\n");
            ret = -1;
        }
    }

    /* Test 3: capacity + 1 byte (one full request, then a tail buffered) */
    if (ret == 0) {
        const uint32_t cap1 =
            WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ + 1u;
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret == 0) {
            ret = wc_Sha512Update(sha512, buf, cap1);
        }
        if (ret == 0) {
            ret = wc_Sha512Final(sha512, out);
        }
        (void)wc_Sha512Free(sha512);
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, cap1, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("SHA512 capacity+1 mismatch\n");
            ret = -1;
        }
    }

    /* Test 4: non-aligned chunk stress test */
    if (ret == 0) {
        const uint32_t chunks[] = {13, 17, 1280, 41, 1};
        const size_t   nChunks  = sizeof(chunks) / sizeof(chunks[0]);
        uint32_t       total    = 0;
        size_t         k;
        for (k = 0; k < nChunks; k++) {
            total += chunks[k];
        }
        if (total > BUFSZ) {
            WH_ERROR_PRINT("test buffer too small for chunked stress test\n");
            ret = -1;
        }
        if (ret == 0) {
            uint32_t off = 0;
            ret          = wc_InitSha512_ex(sha512, NULL, devId);
            for (k = 0; ret == 0 && k < nChunks; k++) {
                ret = wc_Sha512Update(sha512, buf + off, chunks[k]);
                off += chunks[k];
            }
            if (ret == 0) {
                ret = wc_Sha512Final(sha512, out);
            }
            (void)wc_Sha512Free(sha512);
            if (ret == 0) {
                ret = whTest_Sha512Reference(buf, total, ref);
            }
            if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT("SHA512 chunked stress mismatch\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA512 LARGE-INPUT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the new async non-DMA SHA512 primitives. */
static int whTest_CryptoSha512AsyncImpl(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    uint8_t   ref[WC_SHA512_DIGEST_SIZE];
    /* Use the same large static buffer as the LargeInput test. */
    uint8_t* buf   = whTest_Sha512BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha512BigBuf);
    uint32_t i;
    bool     sent;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    }

    /* Case A: basic UpdateRequest -> UpdateResponse -> Final */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret == 0) {
        sent = false;
        ret  = wh_Client_Sha512UpdateRequest(ctx, sha512, buf, 256, &sent);
    }
    if (ret == 0 && sent) {
        do {
            ret = wh_Client_Sha512UpdateResponse(ctx, sha512);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = wh_Client_Sha512FinalRequest(ctx, sha512);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, 256, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA512 case A mismatch\n");
        ret = -1;
    }

    /* Case B: pure-buffer-fill update (sent must be false), then finalize */
    if (ret == 0) {
        (void)wc_Sha512Free(sha512);
        ret = wc_InitSha512_ex(sha512, NULL, devId);
    }
    if (ret == 0) {
        sent = true; /* expect to be cleared to false */
        ret  = wh_Client_Sha512UpdateRequest(ctx, sha512, buf, 10, &sent);
        if (ret == 0 && sent != false) {
            WH_ERROR_PRINT(
                "Async SHA512: expected sent==false on small update\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha512FinalRequest(ctx, sha512);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, 10, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async SHA512 case B mismatch\n");
        ret = -1;
    }

    /* Case C: multi-round async updates that span more than the per-call
     * inline capacity (forces multiple Request/Response pairs). */
    if (ret == 0) {
        uint32_t consumed = 0;
        (void)wc_Sha512Free(sha512);
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            /* arbitrary, 70% of max inline */
            uint32_t chunk =
                (WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ * 7 / 10);
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            sent = false;
            ret  = wh_Client_Sha512UpdateRequest(ctx, sha512, buf + consumed,
                                                 chunk, &sent);
            if (ret == 0 && sent) {
                do {
                    ret = wh_Client_Sha512UpdateResponse(ctx, sha512);
                } while (ret == WH_ERROR_NOTREADY);
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha512FinalRequest(ctx, sha512);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async SHA512 case C mismatch\n");
            ret = -1;
        }
    }

    /* Case D: oversized-input rejection. UpdateRequest with inLen > capacity
     * must return BADARGS without mutating sha. */
    if (ret == 0) {
        uint8_t  savedDigest[WC_SHA512_DIGEST_SIZE];
        word32   savedBuffLen;
        uint32_t cap;
        int      rc;
        (void)wc_Sha512Free(sha512);
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret == 0) {
            memcpy(savedDigest, sha512->digest, WC_SHA512_DIGEST_SIZE);
            savedBuffLen = sha512->buffLen;
            cap          = WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ +
                  (uint32_t)(WC_SHA512_BLOCK_SIZE - 1u - sha512->buffLen);
            sent = true;
            rc   = wh_Client_Sha512UpdateRequest(ctx, sha512, buf, cap + 1u,
                                                 &sent);
            if (rc != WH_ERROR_BADARGS) {
                WH_ERROR_PRINT("Async SHA512: expected BADARGS, got %d\n", rc);
                ret = -1;
            }
            else if (sent != false) {
                WH_ERROR_PRINT(
                    "Async SHA512: sent should remain false on err\n");
                ret = -1;
            }
            else if (sha512->buffLen != savedBuffLen ||
                     memcmp(sha512->digest, savedDigest,
                            WC_SHA512_DIGEST_SIZE) != 0) {
                WH_ERROR_PRINT(
                    "Async SHA512: state mutated on rejected call\n");
                ret = -1;
            }
        }
        (void)wc_Sha512Free(sha512);
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA512 ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the new async DMA SHA512 primitives. */
static int whTest_CryptoSha512DmaAsyncImpl(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    uint8_t   ref[WC_SHA512_DIGEST_SIZE];
    /* DMA bypasses the comm buffer, so any size goes; reuse the shared
     * static buffer to keep stack pressure low. */
    uint8_t* buf   = whTest_Sha512BigBuf;
    uint32_t BUFSZ = (uint32_t)sizeof(whTest_Sha512BigBuf);
    uint32_t i;

    (void)rng;

    for (i = 0; i < BUFSZ; i++) {
        buf[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    }

    /* Case A: single large DMA Update + Final */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret == 0) {
        bool sent = false;
        ret = wh_Client_Sha512DmaUpdateRequest(ctx, sha512, buf, BUFSZ, &sent);
        if (ret == 0 && sent) {
            do {
                ret = wh_Client_Sha512DmaUpdateResponse(ctx, sha512);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == 0) {
        ret = wh_Client_Sha512DmaFinalRequest(ctx, sha512);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_Sha512DmaFinalResponse(ctx, sha512, out);
        } while (ret == WH_ERROR_NOTREADY);
    }
    (void)wc_Sha512Free(sha512);
    if (ret == 0) {
        ret = whTest_Sha512Reference(buf, BUFSZ, ref);
    }
    if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
        WH_ERROR_PRINT("Async DMA SHA512 case A mismatch\n");
        ret = -1;
    }

    /* Case B: multiple DMA Update round-trips, then Final */
    if (ret == 0) {
        uint32_t consumed = 0;
        ret               = wc_InitSha512_ex(sha512, NULL, devId);
        while (ret == 0 && consumed < BUFSZ) {
            uint32_t chunk = 1024;
            if (consumed + chunk > BUFSZ) {
                chunk = BUFSZ - consumed;
            }
            {
                bool sent = false;
                ret       = wh_Client_Sha512DmaUpdateRequest(
                    ctx, sha512, buf + consumed, chunk, &sent);
                if (ret == 0 && sent) {
                    do {
                        ret = wh_Client_Sha512DmaUpdateResponse(ctx, sha512);
                    } while (ret == WH_ERROR_NOTREADY);
                }
            }
            consumed += chunk;
        }
        if (ret == 0) {
            ret = wh_Client_Sha512DmaFinalRequest(ctx, sha512);
        }
        if (ret == 0) {
            do {
                ret = wh_Client_Sha512DmaFinalResponse(ctx, sha512, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
        (void)wc_Sha512Free(sha512);
        if (ret == 0) {
            ret = whTest_Sha512Reference(buf, BUFSZ, ref);
        }
        if (ret == 0 && memcmp(out, ref, WC_SHA512_DIGEST_SIZE) != 0) {
            WH_ERROR_PRINT("Async DMA SHA512 case B mismatch\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("SHA512 DMA ASYNC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int _whTest_CryptoSha512(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha512Impl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha512LargeInput(whClientContext* ctx, int devId)
{
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha512LargeInputImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoSha512Async(whClientContext* ctx)
{
    int    devId = WH_DEV_ID;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha512AsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_CryptoSha512DmaAsync(whClientContext* ctx)
{
    int    devId = WH_DEV_ID_DMA;
    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }
    ret = whTest_CryptoSha512DmaAsyncImpl(ctx, devId, rng);
    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA512 */

int whTest_Crypto_Sha(whClientContext* ctx)
{
    /* Synchronous hashing (plain + large input) dispatches through the
     * cryptocb, so run it on every devId to cover the normal and DMA server
     * transports. The explicit request/response suites are transport-specific
     * (comm-buffer Async vs DmaAsync), not devId-routed -- run each once. */
#ifdef WOLFSSL_SHA224
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha224(ctx, devId));
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha224LargeInput(ctx, devId));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha224Async(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha224DmaAsync(ctx));
#endif
#endif
#ifndef NO_SHA256
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha256(ctx, devId));
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha256LargeInput(ctx, devId));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha256Async(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha256DmaAsync(ctx));
#endif
#endif
#ifdef WOLFSSL_SHA384
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha384(ctx, devId));
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha384LargeInput(ctx, devId));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha384Async(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha384DmaAsync(ctx));
#endif
#endif
#ifdef WOLFSSL_SHA512
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha512(ctx, devId));
    WH_TEST_FOREACH_DEVID(_whTest_CryptoSha512LargeInput(ctx, devId));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha512Async(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoSha512DmaAsync(ctx));
#endif
#endif
    (void)ctx;
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
