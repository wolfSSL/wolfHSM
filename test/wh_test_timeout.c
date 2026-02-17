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
 * test/wh_test_timeout.c
 *
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT

#include "wolfhsm/wh_timeout.h"
#include "wolfhsm/wh_error.h"

#include "wh_test_common.h"
#include "wh_test_timeout.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#ifdef HAVE_AES_CBC
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#endif /* HAVE_AES_CBC */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

static int whTest_TimeoutCb(whTimeoutCtx* ctx, int* isExpired)
{
    (void)isExpired;
    int* counter = (int*)ctx->cbCtx;
    if (counter != NULL) {
        (*counter)++;
    }
    return WH_ERROR_OK;
}

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(HAVE_AES_CBC)

#define TIMEOUT_TEST_BUFFER_SIZE 4096
#define TIMEOUT_TEST_FLASH_RAM_SIZE (1024 * 1024)
#define TIMEOUT_TEST_FLASH_SECTOR_SIZE (128 * 1024)
#define TIMEOUT_TEST_FLASH_PAGE_SIZE 8

static whServerContext* timeoutTestServerCtx = NULL;

static int _timeoutTestConnectCb(void* context, whCommConnected connected)
{
    (void)context;

    if (timeoutTestServerCtx == NULL) {
        WH_ERROR_PRINT(
            "Timeout test connect callback server context is NULL\n");
        WH_TEST_ASSERT_RETURN(0);
    }

    return wh_Server_SetConnected(timeoutTestServerCtx, connected);
}

static int whTest_TimeoutAesCbc(void)
{
    WH_TEST_PRINT("Testing timeout AES CBC...\n");
    int rc = 0;

    /* Transport memory configuration */
    uint8_t              req[TIMEOUT_TEST_BUFFER_SIZE]  = {0};
    uint8_t              resp[TIMEOUT_TEST_BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]                        = {{
                               .req       = (whTransportMemCsr*)req,
                               .req_size  = sizeof(req),
                               .resp      = (whTransportMemCsr*)resp,
                               .resp_size = sizeof(resp),
    }};

    /* Client configuration with timeout */
    whTimeoutConfig timeoutCfg = {
        .timeoutUs = 1,
        .expiredCb = NULL,
        .cbCtx     = NULL,
    };

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
                 .connect_cb        = _timeoutTestConnectCb,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm              = cc_conf,
                      .respTimeoutConfig = &timeoutCfg,
    }};
    whClientContext             client[1]  = {0};

    /* Server configuration */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* Flash/NVM configuration */
    uint8_t          flash_memory[TIMEOUT_TEST_FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                                     = {0};
    whFlashRamsimCfg fc_conf[1]                                = {{
                                       .size       = TIMEOUT_TEST_FLASH_RAM_SIZE,
                                       .sectorSize = TIMEOUT_TEST_FLASH_SECTOR_SIZE,
                                       .pageSize   = TIMEOUT_TEST_FLASH_PAGE_SIZE,
                                       .erasedByte = ~(uint8_t)0,
                                       .memory     = flash_memory,
    }};
    const whFlashCb  fcb[1] = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext          nvm[1]    = {{0}};

    WH_TEST_RETURN_ON_FAIL(whTest_NvmCfgBackend(
        WH_NVM_TEST_BACKEND_FLASH, &nvm_setup, n_conf, fc_conf, fc, fcb));

    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
         .crypto      = crypto,
         .devId       = INVALID_DEVID,
    }};
    whServerContext server[1] = {0};

    timeoutTestServerCtx = server;

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));

    /* Server must be initialized before client (connect callback) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* CommInit handshake */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, NULL, NULL));

    /* Set up AES CBC encryption */
    {
        Aes     aes[1];
        uint8_t key[AES_BLOCK_SIZE]    = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                          0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                          0x0D, 0x0E, 0x0F, 0x10};
        uint8_t iv[AES_BLOCK_SIZE]     = {0};
        uint8_t plain[AES_BLOCK_SIZE]  = {0xAA};
        uint8_t cipher[AES_BLOCK_SIZE] = {0};

        WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, WH_DEV_ID));
        WH_TEST_RETURN_ON_FAIL(
            wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION));

        /* Call AES CBC encrypt WITHOUT having server handle the request.
         * The client should time out waiting for the response. */
        rc = wh_Client_AesCbc(client, aes, 1, plain, sizeof(plain), cipher);
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_TIMEOUT);

        wc_AesFree(aes);
    }

    /* Cleanup: server still has the unhandled request in the transport buffer.
     * Handle it before closing so the transport is in a clean state. */
    (void)wh_Server_HandleRequestMessage(server);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wc_FreeRng(crypto->rng);
    wh_Nvm_Cleanup(nvm);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}

/* Callback that overrides expiration on the first invocation by resetting and
 * restarting the timeout. On the second invocation it allows expiration. The
 * cbCtx points to an int counter tracking how many times the callback fired. */
static int _timeoutOverrideCb(whTimeoutCtx* ctx, int* isExpired)
{
    int* counter = (int*)ctx->cbCtx;
    if (counter == NULL) {
        return WH_ERROR_BADARGS;
    }

    (*counter)++;

    if (*counter <= 1) {
        /* First expiration: override and restart the timer */
        *isExpired = 0;
        wh_Timeout_Start(ctx);
    }
    /* Subsequent expirations: let it expire normally */
    return WH_ERROR_OK;
}

static int whTest_TimeoutAesCbcOverride(void)
{
    WH_TEST_PRINT("Testing timeout AES CBC with override callback...\n");
    int rc       = 0;
    int cb_count = 0;

    /* Transport memory configuration */
    uint8_t              req[TIMEOUT_TEST_BUFFER_SIZE]  = {0};
    uint8_t              resp[TIMEOUT_TEST_BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]                        = {{
                               .req       = (whTransportMemCsr*)req,
                               .req_size  = sizeof(req),
                               .resp      = (whTransportMemCsr*)resp,
                               .resp_size = sizeof(resp),
    }};

    /* Client configuration with timeout and override callback */
    whTimeoutConfig timeoutCfg = {
        .timeoutUs = 1,
        .expiredCb = _timeoutOverrideCb,
        .cbCtx     = &cb_count,
    };

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
                 .connect_cb        = _timeoutTestConnectCb,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm              = cc_conf,
                      .respTimeoutConfig = &timeoutCfg,
    }};
    whClientContext             client[1]  = {0};

    /* Server configuration */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* Flash/NVM configuration */
    uint8_t          flash_memory[TIMEOUT_TEST_FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                                     = {0};
    whFlashRamsimCfg fc_conf[1]                                = {{
                                       .size       = TIMEOUT_TEST_FLASH_RAM_SIZE,
                                       .sectorSize = TIMEOUT_TEST_FLASH_SECTOR_SIZE,
                                       .pageSize   = TIMEOUT_TEST_FLASH_PAGE_SIZE,
                                       .erasedByte = ~(uint8_t)0,
                                       .memory     = flash_memory,
    }};
    const whFlashCb  fcb[1] = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext          nvm[1]    = {{0}};

    WH_TEST_RETURN_ON_FAIL(whTest_NvmCfgBackend(
        WH_NVM_TEST_BACKEND_FLASH, &nvm_setup, n_conf, fc_conf, fc, fcb));

    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
         .crypto      = crypto,
         .devId       = INVALID_DEVID,
    }};
    whServerContext server[1] = {0};

    timeoutTestServerCtx = server;

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));

    /* Server must be initialized before client (connect callback) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* CommInit handshake */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, NULL, NULL));

    /* Set up AES CBC encryption */
    {
        Aes     aes[1];
        uint8_t key[AES_BLOCK_SIZE]    = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                          0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                          0x0D, 0x0E, 0x0F, 0x10};
        uint8_t iv[AES_BLOCK_SIZE]     = {0};
        uint8_t plain[AES_BLOCK_SIZE]  = {0xAA};
        uint8_t cipher[AES_BLOCK_SIZE] = {0};

        WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, WH_DEV_ID));
        WH_TEST_RETURN_ON_FAIL(
            wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION));

        /* Call AES CBC encrypt WITHOUT having server handle the request.
         * The override callback will suppress the first expiration, reset and
         * restart the timer. On the second expiration it lets it through. */
        rc = wh_Client_AesCbc(client, aes, 1, plain, sizeof(plain), cipher);
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_TIMEOUT);

        /* The callback should have fired twice: once overridden, once expired
         */
        WH_TEST_ASSERT_RETURN(cb_count == 2);

        wc_AesFree(aes);
    }

    /* Cleanup */
    (void)wh_Server_HandleRequestMessage(server);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wc_FreeRng(crypto->rng);
    wh_Nvm_Cleanup(nvm);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && HAVE_AES_CBC */

int whTest_Timeout(void)
{
    WH_TEST_PRINT("Testing timeout...\n");
    int             cb_count = 0;
    whTimeoutConfig cfg;
    whTimeoutCtx    timeout[1];

    cfg.timeoutUs = 1;
    cfg.expiredCb = whTest_TimeoutCb;
    cfg.cbCtx     = &cb_count;

    wh_Timeout_Init(timeout, &cfg);
    WH_TEST_ASSERT_RETURN(timeout->startUs == 0);
    WH_TEST_ASSERT_RETURN(timeout->timeoutUs == cfg.timeoutUs);
    WH_TEST_ASSERT_RETURN(timeout->expiredCb == cfg.expiredCb);
    WH_TEST_ASSERT_RETURN(timeout->cbCtx == cfg.cbCtx);

    wh_Timeout_Start(timeout);
    WH_TEST_ASSERT_RETURN(timeout->timeoutUs > 0);

    wh_Timeout_Stop(timeout);
    WH_TEST_ASSERT_RETURN(timeout->startUs == 0);
    WH_TEST_ASSERT_RETURN(timeout->timeoutUs == 0);

    /* No expiration when disabled */
    WH_TEST_ASSERT_RETURN(wh_Timeout_Expired(timeout) == 0);

    /* Test expired callback fires and increments counter */
    cb_count = 0;
    wh_Timeout_Init(timeout, &cfg);
    wh_Timeout_Start(timeout);
    /* timeoutUs is 1 us, so spin until expired */
    while (wh_Timeout_Expired(timeout) == 0)
        ;
    WH_TEST_ASSERT_RETURN(cb_count > 0);

    WH_TEST_ASSERT_RETURN(wh_Timeout_Init(0, 0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Set(0, 0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Start(0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Stop(0) == WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_Timeout_Expired(0) == 0);

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(HAVE_AES_CBC)
    WH_TEST_RETURN_ON_FAIL(whTest_TimeoutAesCbc());
    WH_TEST_RETURN_ON_FAIL(whTest_TimeoutAesCbcOverride());
#endif

    return 0;
}

#endif /* WOLFHSM_CFG_ENABLE_TIMEOUT */
