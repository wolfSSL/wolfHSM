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
 * test-refactor/client-server/wh_test_crypto_rng.c
 *
 * RNG round-trips: synchronous (wolfCrypt API), async non-DMA, and async DMA.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define WH_TEST_RNG_LIL 7
#define WH_TEST_RNG_MED 1024
#define WH_TEST_RNG_BIG (WOLFHSM_CFG_COMM_DATA_LEN * 2)

/* Returns 0 if buf appears to contain non-trivial data (not all zero), -1 on
 * the all-zero case which would suggest the response was never written. */
static int whTest_RngBufNonZero(const uint8_t* buf, uint32_t len)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return -1;
}

static int whTest_CryptoRngImpl(whClientContext* ctx, int devId)
{
    int     ret;
    WC_RNG  rng[1];
    uint8_t lil[WH_TEST_RNG_LIL];
    uint8_t med[WH_TEST_RNG_MED];
    uint8_t big[WH_TEST_RNG_BIG];

    (void)ctx;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
    }
    else {
        int freeRet;
        ret = wc_RNG_GenerateBlock(rng, lil, sizeof(lil));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        }
        else {
            ret = wc_RNG_GenerateBlock(rng, med, sizeof(med));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
            }
            else {
                ret = wc_RNG_GenerateBlock(rng, big, sizeof(big));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
                }
                else if (memcmp(lil, med, sizeof(lil)) == 0) {
                    /* The prefixes of two successive independent RNG calls
                     * must not match. A collision here indicates a stuck RNG */
                    WH_ERROR_PRINT("RNG: successive calls produced identical "
                                   "prefix\n");
                    ret = -1;
                }
            }
        }
        /* Always free the RNG if InitRng succeeded, regardless of which (if
         * any) GenerateBlock call failed. */
        freeRet = wc_FreeRng(rng);
        if (freeRet != 0) {
            WH_ERROR_PRINT("Failed to wc_FreeRng %d\n", freeRet);
            if (ret == 0) {
                ret = freeRet;
            }
        }
    }
    if (ret == 0) {
        WH_TEST_PRINT("RNG DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Direct exercise of the async non-DMA RNG primitives. */
static int _whTest_CryptoRngAsync(whClientContext* ctx)
{
    int      ret = WH_ERROR_OK;
    uint8_t  small[64];
    uint8_t  big[WOLFHSM_CFG_COMM_DATA_LEN * 2];
    uint32_t got;

    /* Case A: small Request -> poll Response */
    if (ret == 0) {
        memset(small, 0, sizeof(small));
        ret = wh_Client_RngGenerateRequest(ctx, sizeof(small));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG: Request(small) failed %d\n", ret);
        }
    }
    if (ret == 0) {
        got = sizeof(small);
        do {
            ret = wh_Client_RngGenerateResponse(ctx, small, &got);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG: Response(small) failed %d\n", ret);
        }
        else if (got != sizeof(small)) {
            WH_ERROR_PRINT("Async RNG: short read got=%u want=%u\n",
                           (unsigned)got, (unsigned)sizeof(small));
            ret = -1;
        }
        else if (whTest_RngBufNonZero(small, sizeof(small)) != 0) {
            WH_ERROR_PRINT("Async RNG: small buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case B: max-inline-size Request -> Response in a single round trip */
    if (ret == 0) {
        uint32_t cap = (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ;
        memset(big, 0, cap);
        ret = wh_Client_RngGenerateRequest(ctx, cap);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG: Request(max) failed %d\n", ret);
        }
        if (ret == 0) {
            got = cap;
            do {
                ret = wh_Client_RngGenerateResponse(ctx, big, &got);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret == 0 && got != cap) {
                WH_ERROR_PRINT("Async RNG: max read short got=%u want=%u\n",
                               (unsigned)got, (unsigned)cap);
                ret = -1;
            }
            else if (ret == 0 && whTest_RngBufNonZero(big, cap) != 0) {
                WH_ERROR_PRINT("Async RNG: max buffer all zeros\n");
                ret = -1;
            }
        }
    }

    /* Case C: caller-driven chunking to fill a buffer larger than the per-call
     * inline capacity. */
    if (ret == 0) {
        uint32_t cap      = (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ;
        uint32_t total    = (uint32_t)sizeof(big);
        uint32_t consumed = 0;

        memset(big, 0, total);
        while (ret == 0 && consumed < total) {
            uint32_t want = total - consumed;
            if (want > cap) {
                want = cap;
            }
            ret = wh_Client_RngGenerateRequest(ctx, want);
            if (ret == 0) {
                got = want;
                do {
                    ret = wh_Client_RngGenerateResponse(ctx, big + consumed,
                                                        &got);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (got == 0 || got > want) {
                    WH_ERROR_PRINT(
                        "Async RNG: bad chunk reply got=%u want=%u\n",
                        (unsigned)got, (unsigned)want);
                    ret = -1;
                }
                else {
                    consumed += got;
                }
            }
        }
        if (ret == 0 && whTest_RngBufNonZero(big, total) != 0) {
            WH_ERROR_PRINT("Async RNG: chunked buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case D: oversize request must be rejected without sending. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateRequest(
            ctx, (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ + 1u);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: oversize Request returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }

    /* Case E: zero-size request must be rejected. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateRequest(ctx, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: zero-size Request returned %d (want BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    /* Case F: NULL ctx rejection on both halves. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateRequest(NULL, 16);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: NULL ctx Request returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc;
        got = 16;
        rc  = wh_Client_RngGenerateResponse(NULL, small, &got);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG: NULL ctx Response returned %d (want BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    /* Case G: NULL inout_size rejection. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateResponse(ctx, small, NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Async RNG: NULL inout_size Response returned %d "
                           "(want BADARGS)\n",
                           rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("RNG ASYNC SUCCESS\n");
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Direct exercise of the async DMA RNG primitives. */
static int _whTest_CryptoRngDmaAsync(whClientContext* ctx)
{
    int ret = WH_ERROR_OK;
    /* DMA bypasses the comm buffer so we can request more than COMM_DATA_LEN
     * in a single round trip. */
    uint8_t big[WOLFHSM_CFG_COMM_DATA_LEN * 2];

    /* Case A: basic DMA Request -> Response */
    if (ret == 0) {
        memset(big, 0, sizeof(big));
        ret = wh_Client_RngGenerateDmaRequest(ctx, big, sizeof(big));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG DMA: Request failed %d\n", ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_RngGenerateDmaResponse(ctx);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Async RNG DMA: Response failed %d\n", ret);
        }
        else if (whTest_RngBufNonZero(big, sizeof(big)) != 0) {
            WH_ERROR_PRINT("Async RNG DMA: buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case B: small DMA request still works (no chunking semantics). */
    if (ret == 0) {
        uint8_t small[32];
        memset(small, 0, sizeof(small));
        ret = wh_Client_RngGenerateDmaRequest(ctx, small, sizeof(small));
        if (ret == 0) {
            do {
                ret = wh_Client_RngGenerateDmaResponse(ctx);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0 && whTest_RngBufNonZero(small, sizeof(small)) != 0) {
            WH_ERROR_PRINT("Async RNG DMA: small buffer all zeros\n");
            ret = -1;
        }
    }

    /* Case C: input validation. */
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaRequest(NULL, big, sizeof(big));
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: NULL ctx returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaRequest(ctx, NULL, sizeof(big));
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: NULL out returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaRequest(ctx, big, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: zero size returned %d (want BADARGS)\n", rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_RngGenerateDmaResponse(NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "Async RNG DMA: Response NULL ctx returned %d (want BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("RNG DMA ASYNC SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_Crypto_Rng(whClientContext* ctx)
{
    int i;

    /* Synchronous wolfCrypt RNG dispatches through the cryptocb, so run it
     * once per dispatch mode on the per-client devId to cover both the normal
     * and DMA server paths. */
    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        int dmaMode = -1;
        (void)wh_Client_SetDmaMode(ctx, i);
        /* Round-trip the dispatch mode through the getter (reports 0 in
         * non-DMA builds, where this loop only runs mode 0) */
        WH_TEST_RETURN_ON_FAIL(wh_Client_GetDmaMode(ctx, &dmaMode));
        WH_TEST_ASSERT_RETURN(dmaMode == i);
        WH_TEST_RETURN_ON_FAIL(
            whTest_CryptoRngImpl(ctx, WH_CLIENT_DEVID(ctx)));
    }
    (void)wh_Client_SetDmaMode(ctx, 0);

    /* The explicit request/response primitives are transport-specific
     * (comm-buffer vs DMA), not devId-routed -- run each once. */
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRngAsync(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoRngDmaAsync(ctx));
#endif
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
