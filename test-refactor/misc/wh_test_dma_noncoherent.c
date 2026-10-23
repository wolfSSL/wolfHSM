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
 * test-refactor/misc/wh_test_dma_noncoherent.c
 *
 * WOLFHSM_CFG_DMA_NONCOHERENT refusals: wolfCrypt cannot use DMA when client
 * caches are not coherent, so the client must refuse preferDma (at init and
 * through wh_Client_SetDmaMode) and every wolfCrypt operation on
 * WH_DEV_ID_DMA (AES-CBC and SHA-256 here) must fail with WC_HW_E instead of
 * falling back to software.
 * None of this reaches the server, so the test runs a client with no server.
 * Also checks the aligned, padded buffers from wh_Utils_DmaAlloc.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_DMA) && defined(WOLFHSM_CFG_DMA_NONCOHERENT) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_utils.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define BUFFER_SIZE 4096

/* wh_Utils_DmaAlloc must return a buffer aligned to WOLFHSM_CFG_DMA_ALIGN with
 * WH_DMA_PAD_SIZE(len) usable bytes, and wh_Utils_DmaFree must free it through
 * the raw pointer stored before it. Writing every padded byte and freeing lets
 * ASAN catch a short buffer or a wrong offset. */
static int _whTest_DmaNonCoherentAlloc(void)
{
    static const size_t lens[] = {
        0,
        1,
        WOLFHSM_CFG_DMA_ALIGN - 1,
        WOLFHSM_CFG_DMA_ALIGN,
        WOLFHSM_CFG_DMA_ALIGN + 1,
        3 * WOLFHSM_CFG_DMA_ALIGN,
        10 * WOLFHSM_CFG_DMA_ALIGN + 3,
    };
    /* Allocation sizes that would wrap without the overflow check:
     * WH_DMA_PAD_SIZE(SIZE_MAX) wraps to 0, and SIZE_MAX -
     * WOLFHSM_CFG_DMA_ALIGN + 1 pads without wrapping but the over-allocation
     * then does */
    static const size_t hugeLens[] = {
        SIZE_MAX,
        SIZE_MAX - WOLFHSM_CFG_DMA_ALIGN + 1,
    };
    uint8_t* buf;
    size_t   i;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        buf = (uint8_t*)wh_Utils_DmaAlloc(lens[i], NULL);
        WH_TEST_ASSERT_RETURN(buf != NULL);
        if (!WH_DMA_IS_ALIGNED(buf)) {
            WH_ERROR_PRINT("wh_Utils_DmaAlloc(%u) returned unaligned %p\n",
                           (unsigned)lens[i], (void*)buf);
            wh_Utils_DmaFree(buf, NULL);
            return WH_TEST_FAIL;
        }
        memset(buf, 0xA5, WH_DMA_PAD_SIZE(lens[i]));
        wh_Utils_DmaFree(buf, NULL);
    }

    for (i = 0; i < sizeof(hugeLens) / sizeof(hugeLens[0]); i++) {
        buf = (uint8_t*)wh_Utils_DmaAlloc(hugeLens[i], NULL);
        if (buf != NULL) {
            WH_ERROR_PRINT("wh_Utils_DmaAlloc(SIZE_MAX - %u) did not fail\n",
                           (unsigned)(SIZE_MAX - hugeLens[i]));
            wh_Utils_DmaFree(buf, NULL);
            return WH_TEST_FAIL;
        }
    }

    /* NULL is ignored */
    wh_Utils_DmaFree(NULL, NULL);

    WH_TEST_PRINT("DMA non-coherent wh_Utils_DmaAlloc SUCCESS\n");
    return WH_ERROR_OK;
}

static int _whTest_DmaNonCoherentRefusals(void)
{
    static uint8_t       req[BUFFER_SIZE];
    static uint8_t       resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientDmaConfig           dmaCfg[1]  = {{0}};
    whClientContext             client[1]  = {0};
    whClientConfig              c_conf[1]  = {{
                      .comm      = cc_conf,
                      .dmaConfig = dmaCfg,
    }};
    int                         useDma     = -1;
    int                         ret        = 0;

    /* preferDma in the config is refused before any initialization */
    dmaCfg[0].preferDma = 1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client, c_conf));

    dmaCfg[0].preferDma = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Turning DMA mode on is refused and leaves it off; turning it off is
     * still accepted */
    if (wh_Client_SetDmaMode(client, 1) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("wh_Client_SetDmaMode(1) was not refused\n");
        ret = -1;
    }
    if ((ret == 0) && ((wh_Client_GetDmaMode(client, &useDma) != WH_ERROR_OK) ||
                       (useDma != 0))) {
        WH_ERROR_PRINT("DMA mode is on after a refused SetDmaMode: %d\n",
                       useDma);
        ret = -1;
    }
    if ((ret == 0) && (wh_Client_SetDmaMode(client, 0) != WH_ERROR_OK)) {
        WH_ERROR_PRINT("wh_Client_SetDmaMode(0) failed\n");
        ret = -1;
    }

    /* wolfCrypt operations on WH_DEV_ID_DMA fail with WC_HW_E (no software
     * fallback), and freeing the object afterwards still works */
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    /* Needs a cipher operation that always reaches the cryptoCb: SetKey alone
     * only does so on builds that route it there, otherwise it returns 0 */
    if (ret == 0) {
        Aes           aes[1];
        const uint8_t key[AES_128_KEY_SIZE] = {0};
        const uint8_t iv[AES_BLOCK_SIZE]    = {0};
        uint8_t       in[AES_BLOCK_SIZE]    = {0};
        uint8_t       out[AES_BLOCK_SIZE]   = {0};
        int           rc;

        rc = wc_AesInit(aes, NULL, WH_DEV_ID_DMA);
        if (rc != 0) {
            WH_ERROR_PRINT("wc_AesInit on WH_DEV_ID_DMA failed %d\n", rc);
            ret = -1;
        }
        else {
            /* The key may be handed to the cryptoCb already (SETKEY) */
            rc = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (rc == 0) {
                rc = wc_AesCbcEncrypt(aes, out, in, sizeof(in));
            }
            if (rc != WC_HW_E) {
                WH_ERROR_PRINT("AES on WH_DEV_ID_DMA returned %d, expected "
                               "WC_HW_E\n",
                               rc);
                ret = -1;
            }
            wc_AesFree(aes);
        }
    }
#endif /* !NO_AES && HAVE_AES_CBC */

#ifndef NO_SHA256
    if (ret == 0) {
        wc_Sha256     sha[1];
        const uint8_t data[] = "noncoherent";
        int           rc;

        rc = wc_InitSha256_ex(sha, NULL, WH_DEV_ID_DMA);
        if (rc != 0) {
            WH_ERROR_PRINT("wc_InitSha256_ex on WH_DEV_ID_DMA failed %d\n", rc);
            ret = -1;
        }
        else {
            rc = wc_Sha256Update(sha, data, (word32)sizeof(data));
            if (rc != WC_HW_E) {
                WH_ERROR_PRINT("SHA256 on WH_DEV_ID_DMA returned %d, expected "
                               "WC_HW_E\n",
                               rc);
                ret = -1;
            }
            wc_Sha256Free(sha);
        }
    }
#endif /* !NO_SHA256 */

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    if (ret == 0) {
        WH_TEST_PRINT("DMA non-coherent refusals SUCCESS\n");
    }
    return ret;
}

int whTest_DmaNonCoherent(void* ctx)
{
    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(_whTest_DmaNonCoherentAlloc());
    WH_TEST_RETURN_ON_FAIL(_whTest_DmaNonCoherentRefusals());

    return WH_ERROR_OK;
}

#endif /* DMA && DMA_NONCOHERENT && ENABLE_CLIENT && !NO_CRYPTO */
