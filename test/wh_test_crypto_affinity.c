/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * test/wh_test_crypto_affinity.c
 *
 * Tests for the SetCryptoAffinity API, verifying that the server correctly
 * switches between hardware and software crypto implementations.
 */

#include "wolfhsm/wh_settings.h"

/* Only compile if we have crypto, client, server, and crypto callbacks */
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLF_CRYPTO_CB)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wh_test_common.h"
#include "wh_test_crypto_affinity.h"

#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (128 * 1024)
#define FLASH_PAGE_SIZE (8)
#define TEST_DEV_ID 0xCA

/* Counter to track how many times the crypto callback is invoked */
static int cryptoCbInvokeCount = 0;

static whServerContext* cryptoAffinityTestServerCtx = NULL;

/* Test crypto callback that just increments a counter and returns
 * CRYPTOCB_UNAVAILABLE to fall back to software */
static int _testCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)info;
    (void)ctx;

    cryptoCbInvokeCount++;

    /* Return CRYPTOCB_UNAVAILABLE to indicate we don't handle this operation
     * and wolfCrypt should fall back to software implementation */
    return CRYPTOCB_UNAVAILABLE;
}

static int _cryptoAffinityTestConnectCb(void*           context,
                                        whCommConnected connected)
{
    (void)context;

    if (cryptoAffinityTestServerCtx == NULL) {
        WH_ERROR_PRINT("Client connect callback server context is NULL\n");
        WH_TEST_ASSERT_RETURN(0);
    }

    /* Set server connect flag. In a "real" system, this should signal the
     * server via out-of-band mechanism. The server app is responsible for
     * receiving this signal and calling wh_Server_SetConnected() */
    return wh_Server_SetConnected(cryptoAffinityTestServerCtx, connected);
}


static int whTest_CryptoAffinityWithCb(void)
{
    int      rc        = 0;
    int32_t  server_rc = 0;
    uint32_t affinity  = 0;

    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE]  = {0};
    uint8_t              resp[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]           = {{
                  .req       = (whTransportMemCsr*)req,
                  .req_size  = sizeof(req),
                  .resp      = (whTransportMemCsr*)resp,
                  .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 1,
                 .connect_cb        = _cryptoAffinityTestConnectCb,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm = cc_conf,
    }};
    whClientContext             client[1]  = {0};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 123,
    }};

    /* Flash/NVM configuration */
    uint8_t          flash_memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                        = {0};
    whFlashRamsimCfg fc_conf[1]                   = {{
                          .size       = FLASH_RAM_SIZE,
                          .sectorSize = FLASH_SECTOR_SIZE,
                          .pageSize   = FLASH_PAGE_SIZE,
                          .erasedByte = ~(uint8_t)0,
                          .memory     = flash_memory,
    }};
    const whFlashCb  fcb[1]                       = {WH_FLASH_RAMSIM_CB};

    whNvmFlashContext nfc[1]     = {0};
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};


    whNvmCb      nfcb[1]   = {WH_NVM_FLASH_CB};
    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {0};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
         .crypto      = crypto,
         .devId       = TEST_DEV_ID,
    }};
    whServerContext server[1] = {0};

    cryptoAffinityTestServerCtx = server;

    WH_TEST_PRINT("  whTest_CryptoAffinityWithCb...");

    /* Initialize wolfCrypt and register our test crypto callback */
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(
        wc_CryptoCb_RegisterDevice(TEST_DEV_ID, _testCryptoCb, NULL));

    /* Initialize NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    /* Initialize RNG */
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));

    /* Initialize server and client */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Check that the server side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_Server_HandleRequestMessage(server));

    /* Send comm init */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, NULL, NULL));

    /* Verify initial state - should be HW since we configured with valid devId
     */
    WH_TEST_ASSERT_RETURN(server->devId == TEST_DEV_ID);
    WH_TEST_ASSERT_RETURN(server->defaultDevId == TEST_DEV_ID);

    /* Test 1a: Get initial affinity - should be HW */
    WH_TEST_RETURN_ON_FAIL(wh_Client_GetCryptoAffinityRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_GetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_HW);

    /* Test 1: Set SW affinity */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_SW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_SW);
    WH_TEST_ASSERT_RETURN(server->devId == INVALID_DEVID);

    /* Test 1b: Get affinity after setting SW - should be SW */
    WH_TEST_RETURN_ON_FAIL(wh_Client_GetCryptoAffinityRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_GetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_SW);

    /* Test 2: Set HW affinity - should succeed since we have valid defaultDevId
     */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_HW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_HW);
    WH_TEST_ASSERT_RETURN(server->devId == TEST_DEV_ID);

    /* Test 3: Invalid affinity value - should return BADARGS */
    WH_TEST_RETURN_ON_FAIL(wh_Client_SetCryptoAffinityRequest(client, 0xFF));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_BADARGS);

    /* Test 4: Verify crypto callback is invoked when HW affinity is set */
    cryptoCbInvokeCount = 0;

    /* Set HW affinity */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_HW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Do a crypto operation using the server's devId - this should hit our
     * callback */
    {
        WC_RNG  testRng[1];
        uint8_t randomBytes[16];
        rc = wc_InitRng_ex(testRng, NULL, server->devId);
        if (rc == 0) {
            (void)wc_RNG_GenerateBlock(testRng, randomBytes,
                                       sizeof(randomBytes));
            wc_FreeRng(testRng);
        }
    }

    /* Crypto callback should have been invoked at least once */
    WH_TEST_ASSERT_RETURN(cryptoCbInvokeCount > 0);

    /* Test 5: Verify crypto callback is NOT invoked when SW affinity is set */
    cryptoCbInvokeCount = 0;

    /* Set SW affinity */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_SW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Do a crypto operation using the server's devId (now INVALID_DEVID) */
    {
        WC_RNG  testRng[1];
        uint8_t randomBytes[16];
        rc = wc_InitRng_ex(testRng, NULL, server->devId);
        if (rc == 0) {
            (void)wc_RNG_GenerateBlock(testRng, randomBytes,
                                       sizeof(randomBytes));
            wc_FreeRng(testRng);
        }
    }

    /* Crypto callback should NOT have been invoked */
    WH_TEST_ASSERT_RETURN(cryptoCbInvokeCount == 0);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wc_FreeRng(crypto->rng);
    wh_Nvm_Cleanup(nvm);
    wc_CryptoCb_UnRegisterDevice(TEST_DEV_ID);
    wolfCrypt_Cleanup();

    WH_TEST_PRINT("PASS\n");
    return WH_ERROR_OK;
}


static int whTest_CryptoAffinityNoCb(void)
{
    int32_t  server_rc = 0;
    uint32_t affinity  = 0;

    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE]  = {0};
    uint8_t              resp[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]           = {{
                  .req       = (whTransportMemCsr*)req,
                  .req_size  = sizeof(req),
                  .resp      = (whTransportMemCsr*)resp,
                  .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 1,
                 .connect_cb        = _cryptoAffinityTestConnectCb,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm = cc_conf,
    }};
    whClientContext             client[1]  = {0};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 123,
    }};

    /* Flash/NVM configuration */
    uint8_t          flash_memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                        = {0};
    whFlashRamsimCfg fc_conf[1]                   = {{
                          .size       = FLASH_RAM_SIZE,
                          .sectorSize = FLASH_SECTOR_SIZE,
                          .pageSize   = FLASH_PAGE_SIZE,
                          .erasedByte = ~(uint8_t)0,
                          .memory     = flash_memory,
    }};
    const whFlashCb  fcb[1]                       = {WH_FLASH_RAMSIM_CB};

    whNvmFlashContext nfc[1]     = {0};
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};


    whNvmCb      nfcb[1]   = {WH_NVM_FLASH_CB};
    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {0};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {0};

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
         .crypto      = crypto,
         .devId       = INVALID_DEVID,
    }};
    whServerContext server[1] = {0};

    cryptoAffinityTestServerCtx = server;

    WH_TEST_PRINT("  whTest_CryptoAffinityNoCb...");

    /* Initialize wolfCrypt */
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());

    /* Initialize NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    /* Initialize RNG */
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));

    /* Initialize server and client */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Check that the server side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_Server_HandleRequestMessage(server));

    /* Send comm init */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, NULL, NULL));

    /* Verify initial state - should be SW since we configured with INVALID_DEVID
     */
    WH_TEST_ASSERT_RETURN(server->devId == INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(server->defaultDevId == INVALID_DEVID);

    /* Test 0: Get initial affinity - should be SW since configured with
     * INVALID_DEVID */
    WH_TEST_RETURN_ON_FAIL(wh_Client_GetCryptoAffinityRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_GetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_SW);

    /* Test 1: Set SW affinity - should succeed */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_SW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_SW);
    WH_TEST_ASSERT_RETURN(server->devId == INVALID_DEVID);

    /* Test 2: Set HW affinity - should fail with BADCONFIG since no HW
     * configured */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_HW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTIMPL);
    /* Affinity should remain SW after failed HW request */
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_SW);
    WH_TEST_ASSERT_RETURN(server->devId == INVALID_DEVID);

    /* Test 3: Verify SW affinity still works after failed HW request */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityRequest(client, WH_CRYPTO_AFFINITY_SW));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SetCryptoAffinityResponse(client, &server_rc, &affinity));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(affinity == WH_CRYPTO_AFFINITY_SW);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wc_FreeRng(crypto->rng);
    wh_Nvm_Cleanup(nvm);
    wolfCrypt_Cleanup();

    WH_TEST_PRINT("PASS\n");
    return WH_ERROR_OK;
}


int whTest_CryptoAffinity(void)
{
    WH_TEST_PRINT("Testing Crypto Affinity...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_CryptoAffinityWithCb());
    WH_TEST_RETURN_ON_FAIL(whTest_CryptoAffinityNoCb());

    return WH_ERROR_OK;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLF_CRYPTO_CB */
