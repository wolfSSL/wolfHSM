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
 * test/wh_test_keystore_reqsize.c
 *
 * Unit tests to verify wh_Server_HandleKeyRequest validates req_size,
 * preventing unbounded reads from the request packet.
 *
 * Each test crafts a request packet with a valid fixed-size header but passes
 * a req_size that is too small to contain the variable-length data claimed by
 * the header.  A correct implementation must reject these with an error (e.g.
 * WH_ERROR_BUFFER_SIZE) rather than blindly reading past the end of the
 * packet.
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#endif

#include "wh_test_common.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE 8

/*
 * Helper: set up a minimal server context suitable for calling
 * wh_Server_HandleKeyRequest directly.  Mirrors the pattern used in
 * wh_test_she.c:wh_She_TestReqSizeChecking().
 */
typedef struct {
    whServerContext server[1];
    whNvmContext    nvm[1];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1];
#endif
    /* Transport (not exercised, but required for server init) */
    uint8_t                     reqBuf[BUFFER_SIZE];
    uint8_t                     respBuf[BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];
    /* Flash / NVM */
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

    /* Transport */
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
        .server_id         = 124,
    };

    /* Flash */
    ctx->fc_conf[0] = (whFlashRamsimCfg){
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = ~(uint8_t)0,
        .memory     = _flashMemory,
    };
    ctx->fcb[0]    = (whFlashCb)WH_FLASH_RAMSIM_CB;
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

    /* Server config */
    ctx->s_conf[0] = (whServerConfig){
        .comm_config = ctx->cs_conf,
        .nvm         = ctx->nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = ctx->crypto,
#endif
    };

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(ctx->nvm, ctx->n_conf));
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(
        wc_InitRng_ex(ctx->crypto->rng, NULL, INVALID_DEVID));
#endif
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(ctx->server, ctx->s_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_SetConnected(ctx->server, WH_COMM_CONNECTED));
    return 0;
}

static void _CleanupServer(TestCtx* ctx)
{
    (void)wh_Server_Cleanup(ctx->server);
    (void)wh_Nvm_Cleanup(ctx->nvm);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    (void)wc_FreeRng(ctx->crypto->rng);
    (void)wolfCrypt_Cleanup();
#endif
}

static int wh_Keystore_TestReqSizeChecking(void)
{
    TestCtx   ctx[1];
    uint8_t req_packet[WOLFHSM_CFG_COMM_DATA_LEN]  = {0};
    uint8_t resp_packet[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t req_size;
    uint16_t resp_size;
    int      ret;

    WH_TEST_RETURN_ON_FAIL(_SetupServer(ctx));

    /*
     * Test 1: WH_KEY_CACHE with req_size too small for the variable-length
     * key data.
     *
     * The request declares 32 bytes of key data following the fixed header,
     * but req_size only covers the header.
     */
    {
        whMessageKeystore_CacheRequest* req =
            (whMessageKeystore_CacheRequest*)req_packet;
        whMessageKeystore_CacheResponse* cacheResp =
            (whMessageKeystore_CacheResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(cacheResp, 0, sizeof(*cacheResp));
        resp_size = 0;
        req->sz      = 32;
        req->labelSz = 0;
        req->id      = 0;
        req->flags   = 0;
        req_size = sizeof(*req);
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_CACHE, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*cacheResp));
            WH_TEST_ASSERT_RETURN(cacheResp->rc != WH_ERROR_OK);
        }
    }

    /*
     * Test 2: WH_KEY_CACHE with req_size smaller than the fixed header.
     */
    {
        whMessageKeystore_CacheResponse* cacheResp =
            (whMessageKeystore_CacheResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(cacheResp, 0, sizeof(*cacheResp));
        resp_size = 0;
        req_size = sizeof(whMessageKeystore_CacheRequest) - 1;
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_CACHE, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*cacheResp));
            WH_TEST_ASSERT_RETURN(cacheResp->rc != WH_ERROR_OK);
        }
    }

    /*
     * Test 3: WH_KEY_CACHE with req.sz claiming more data than the entire
     * comm buffer.
     */
    {
        whMessageKeystore_CacheRequest* req =
            (whMessageKeystore_CacheRequest*)req_packet;
        whMessageKeystore_CacheResponse* cacheResp =
            (whMessageKeystore_CacheResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(cacheResp, 0, sizeof(*cacheResp));
        resp_size = 0;
        req->sz      = WOLFHSM_CFG_COMM_DATA_LEN;
        req->labelSz = 0;
        req->id      = 0;
        req->flags   = 0;
        req_size = sizeof(*req);
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_CACHE, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*cacheResp));
            WH_TEST_ASSERT_RETURN(cacheResp->rc != WH_ERROR_OK);
        }
    }

    /*
     * Test 4: WH_KEY_EVICT with req_size smaller than the fixed request
     * header.
     */
    {
        whMessageKeystore_EvictResponse* evictResp =
            (whMessageKeystore_EvictResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(evictResp, 0, sizeof(*evictResp));
        resp_size = 0;
        req_size = sizeof(whMessageKeystore_EvictRequest) - 1;
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_EVICT, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*evictResp));
            WH_TEST_ASSERT_RETURN(evictResp->rc != WH_ERROR_OK);
        }
    }

    /*
     * Test 5: WH_KEY_EXPORT with req_size smaller than the fixed request
     * header.
     */
    {
        whMessageKeystore_ExportResponse* exportResp =
            (whMessageKeystore_ExportResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(exportResp, 0, sizeof(*exportResp));
        resp_size = 0;
        req_size = sizeof(whMessageKeystore_ExportRequest) - 1;
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_EXPORT, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*exportResp));
            WH_TEST_ASSERT_RETURN(exportResp->rc != WH_ERROR_OK);
        }
    }

    /*
     * Test 6: WH_KEY_COMMIT with req_size smaller than the fixed request
     * header.
     */
    {
        whMessageKeystore_CommitResponse* commitResp =
            (whMessageKeystore_CommitResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(commitResp, 0, sizeof(*commitResp));
        resp_size = 0;
        req_size = sizeof(whMessageKeystore_CommitRequest) - 1;
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_COMMIT, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*commitResp));
            WH_TEST_ASSERT_RETURN(commitResp->rc != WH_ERROR_OK);
        }
    }

    /*
     * Test 7: WH_KEY_ERASE with req_size smaller than the fixed request
     * header.
     */
    {
        whMessageKeystore_EraseResponse* eraseResp =
            (whMessageKeystore_EraseResponse*)resp_packet;
        memset(req_packet, 0, sizeof(req_packet));
        memset(eraseResp, 0, sizeof(*eraseResp));
        resp_size = 0;
        req_size = sizeof(whMessageKeystore_EraseRequest) - 1;
        ret = wh_Server_HandleKeyRequest(ctx->server, WH_COMM_MAGIC_NATIVE,
                  WH_KEY_ERASE, req_size, req_packet,
                  &resp_size, resp_packet);
        if (ret == WH_ERROR_OK) {
            WH_TEST_ASSERT_RETURN(resp_size == sizeof(*eraseResp));
            WH_TEST_ASSERT_RETURN(eraseResp->rc != WH_ERROR_OK);
        }
    }

    WH_TEST_PRINT("Keystore req_size validation tests: ALL PASSED\n");

    _CleanupServer(ctx);
    return 0;
}

/*
 * Main entry point: run all keystore req_size validation tests.
 */
int whTest_KeystoreReqSize(void)
{
    WH_TEST_PRINT("Testing keystore HandleKeyRequest req_size validation...\n");
    return wh_Keystore_TestReqSizeChecking();
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO */
