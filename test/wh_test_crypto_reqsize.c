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
/*
 * test/wh_test_crypto_reqsize.c
 *
 * Unit tests to verify _HandleAesGcmDma validates the declared inline-AAD
 * length against the received message, preventing reads past the packet.
 *
 * The client always builds a self-consistent frame, so these cases can only
 * be produced by driving wh_Server_HandleCryptoDmaRequest directly with a
 * hand-built packet.
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_server_crypto.h"
#endif

#include "wh_test_common.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_DMA) && defined(HAVE_AESGCM)

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

typedef struct {
    whServerContext       server[1];
    whNvmContext          nvm[1];
    whServerCryptoContext crypto[1];

    uint8_t                     reqBuf[BUFFER_SIZE];
    uint8_t                     respBuf[BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];

    whFlashRamsimCtx  fc[1];
    whFlashRamsimCfg  fc_conf[1];
    whFlashCb         fcb[1];
    whNvmFlashConfig  nf_conf[1];
    whNvmFlashContext nfc[1];
    whNvmCb           nfcb[1];
    whNvmConfig       n_conf[1];
    whServerConfig    s_conf[1];
} TestCtx;

/* Flash memory is static to avoid 1MB on the stack */
static uint8_t _flashMemory[FLASH_RAM_SIZE];

static int _SetupServer(TestCtx* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    memset(_flashMemory, 0, sizeof(_flashMemory));

    ctx->tmcf[0] = (whTransportMemConfig){
        .req       = (whTransportMemCsr*)ctx->reqBuf,
        .req_size  = sizeof(ctx->reqBuf),
        .resp      = (whTransportMemCsr*)ctx->respBuf,
        .resp_size = sizeof(ctx->respBuf),
    };
    ctx->tscb[0]    = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    ctx->cs_conf[0] = (whCommServerConfig){
        .transport_cb      = ctx->tscb,
        .transport_context = (void*)ctx->tmsc,
        .transport_config  = (void*)ctx->tmcf,
        .server_id         = 125,
    };

    ctx->fc_conf[0] = (whFlashRamsimCfg){
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = _flashMemory,
    };
    ctx->fcb[0]     = (whFlashCb)WH_FLASH_RAMSIM_CB;
    ctx->nf_conf[0] = (whNvmFlashConfig){
        .cb      = ctx->fcb,
        .context = ctx->fc,
        .config  = ctx->fc_conf,
    };
    ctx->nfcb[0]   = (whNvmCb)WH_NVM_FLASH_CB;
    ctx->n_conf[0] = (whNvmConfig){
        .cb      = ctx->nfcb,
        .context = ctx->nfc,
        .config  = ctx->nf_conf,
    };

    ctx->s_conf[0] = (whServerConfig){
        .comm_config = ctx->cs_conf,
        .nvm         = ctx->nvm,
        .crypto      = ctx->crypto,
    };

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(ctx->nvm, ctx->n_conf));
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(
        wc_InitRng_ex(ctx->crypto->rng, NULL, INVALID_DEVID));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(ctx->server, ctx->s_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_SetConnected(ctx->server, WH_COMM_CONNECTED));
    return 0;
}

static void _CleanupServer(TestCtx* ctx)
{
    (void)wh_Server_Cleanup(ctx->server);
    (void)wh_Nvm_Cleanup(ctx->nvm);
    (void)wc_FreeRng(ctx->crypto->rng);
    (void)wolfCrypt_Cleanup();
}

#define WH_TEST_GCM_KEY_SZ AES_128_KEY_SIZE
#define WH_TEST_GCM_IV_SZ 12
#define WH_TEST_GCM_TAG_SZ AES_BLOCK_SIZE
#define WH_TEST_GCM_AAD_SZ 16

/* Lay out a well-formed encrypt request carrying aadBytes of inline AAD after
 * the key, and return the size of the frame actually written. */
static uint16_t _BuildInlineAadRequest(uint8_t* req_packet, uint32_t aadBytes)
{
    whMessageCrypto_GenericRequestHeader* hdr =
        (whMessageCrypto_GenericRequestHeader*)req_packet;
    whMessageCrypto_AesGcmDmaRequest* req =
        (whMessageCrypto_AesGcmDmaRequest*)(req_packet + sizeof(*hdr));

    memset(req_packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    hdr->algoType    = WC_CIPHER_AES_GCM;
    hdr->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    hdr->affinity    = 0;

    req->enc         = 1;
    req->keySz       = WH_TEST_GCM_KEY_SZ;
    req->ivSz        = WH_TEST_GCM_IV_SZ;
    req->authTagSz   = WH_TEST_GCM_TAG_SZ;
    req->input.sz    = 0;
    req->input.addr  = 0;
    req->output.sz   = 0;
    req->output.addr = 0;
    /* addr 0 with a non-zero size is the inline-AAD encoding */
    req->aad.addr = 0;
    req->aad.sz   = aadBytes;

    return (uint16_t)(sizeof(*hdr) + sizeof(*req) + WH_TEST_GCM_KEY_SZ +
                      WH_TEST_GCM_IV_SZ + aadBytes);
}

/* Overwrite the declared sizes so the header disagrees with the frame. */
static void _DeclareSizes(uint8_t* req_packet, uint32_t ivSz, uint64_t aadSz)
{
    whMessageCrypto_AesGcmDmaRequest* req =
        (whMessageCrypto_AesGcmDmaRequest*)(req_packet +
                                            sizeof(whMessageCrypto_GenericRequestHeader));

    req->ivSz   = ivSz;
    req->aad.sz = aadSz;
}

static int _Dispatch(TestCtx* ctx, uint8_t* req_packet, uint16_t req_size,
                     uint8_t* resp_packet)
{
    uint16_t resp_size = 0;

    return wh_Server_HandleCryptoDmaRequest(
        ctx->server, WH_COMM_MAGIC_NATIVE, WC_ALGO_TYPE_CIPHER, 0, req_size,
        req_packet, &resp_size, resp_packet);
}

static int wh_Crypto_TestAesGcmDmaAadFraming(void)
{
    TestCtx  ctx[1];
    uint8_t  req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t  resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint16_t req_size;
    uint64_t craft;
    int      ret;

    WH_TEST_RETURN_ON_FAIL(_SetupServer(ctx));

    /* Test 1: the frame declares an inline AAD, but req_size stops short of
     * the AAD bytes it claims to carry. */
    req_size = _BuildInlineAadRequest(req_packet, WH_TEST_GCM_AAD_SZ);
    ret = _Dispatch(ctx, req_packet, (uint16_t)(req_size - WH_TEST_GCM_AAD_SZ),
                    resp_packet);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Short inline-AAD frame not rejected: %d\n", ret);
        _CleanupServer(ctx);
        return -1;
    }

    /* Test 2: a declared inline AAD larger than the message carrying it. */
    req_size = _BuildInlineAadRequest(req_packet, WH_TEST_GCM_AAD_SZ);
    _DeclareSizes(req_packet, WH_TEST_GCM_IV_SZ, (uint64_t)req_size + 1);
    ret = _Dispatch(ctx, req_packet, req_size, resp_packet);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Oversized inline-AAD length not rejected: %d\n", ret);
        _CleanupServer(ctx);
        return -1;
    }

    /* Test 3: a declared length whose low 32 bits match the frame exactly, so
     * only a check made before the truncation to uint32_t rejects it. */
    req_size = _BuildInlineAadRequest(req_packet, WH_TEST_GCM_AAD_SZ);
    _DeclareSizes(req_packet, WH_TEST_GCM_IV_SZ,
                  (uint64_t)0x100000000ull + WH_TEST_GCM_AAD_SZ);
    ret = _Dispatch(ctx, req_packet, req_size, resp_packet);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Truncating inline-AAD length not rejected: %d\n", ret);
        _CleanupServer(ctx);
        return -1;
    }

    /* Test 4: the length the unbounded 64-bit sum would have wrapped back onto
     * req_size, paired with an ivSz the equality check would then not bound. */
    req_size = _BuildInlineAadRequest(req_packet, WH_TEST_GCM_AAD_SZ);
    craft    = (uint64_t)(req_size -
                       sizeof(whMessageCrypto_GenericRequestHeader)) -
            ((uint64_t)sizeof(whMessageCrypto_AesGcmDmaRequest) +
             (uint64_t)WH_TEST_GCM_KEY_SZ + (uint64_t)0x40000000u);
    _DeclareSizes(req_packet, 0x40000000u, craft);
    ret = _Dispatch(ctx, req_packet, req_size, resp_packet);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Wrapped inline-AAD length not rejected: %d\n", ret);
        _CleanupServer(ctx);
        return -1;
    }

    /* Test 5: the correctly framed encoding must clear the framing check
     * rather than being rejected as malformed. */
    req_size = _BuildInlineAadRequest(req_packet, WH_TEST_GCM_AAD_SZ);
    ret      = _Dispatch(ctx, req_packet, req_size, resp_packet);
    if (ret == WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Well-formed inline-AAD frame rejected\n");
        _CleanupServer(ctx);
        return -1;
    }

    WH_TEST_PRINT("AES-GCM DMA inline-AAD framing tests: ALL PASSED\n");

    _CleanupServer(ctx);
    return 0;
}

int whTest_CryptoReqSize(void)
{
    WH_TEST_PRINT("Testing AES-GCM DMA request framing validation...\n");
    return wh_Crypto_TestAesGcmDmaAadFraming();
}

#else /* server && !no-crypto && DMA && AESGCM */

int whTest_CryptoReqSize(void)
{
    return 0;
}

#endif
