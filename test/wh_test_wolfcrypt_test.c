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
 * test/wh_test_wolfcrypt_test.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/test/test.h"

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#endif

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_server.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#endif

#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <unistd.h>  /* For sleep */
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif


#define BUFFER_SIZE 4096
#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && !defined(NO_CRYPT_TEST)
int whTest_WolfCryptTestCfg(whClientConfig* config)
{
    int             ret       = 0;
    whClientContext client[1] = {0};

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_CommInit: %d\n", ret);
    }
    else {
        /* assumes wolfCrypt has been initialized before this function */
        ret = wolfcrypt_test(NULL);
    }

    /* Tell server to close */
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_SERVER)
static int whTest_ServerCfgLoop(whServerConfig* serverCfg)
{
    whServerContext server[1]    = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int             ret          = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));

    while (am_connected == WH_COMM_CONNECTED) {
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) && (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT(
                "[server] Failed to wh_Server_HandleRequestMessage ret=%d\n",
                ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);
    }

    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)) {
        ret = 0;
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    }
    else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT)
static void* _whClientTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_WolfCryptTestCfg(cf));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_SERVER)
static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_ServerCfgLoop(cf));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
static void _whClientServerThreadTest(whClientConfig* c_conf,
                                      whServerConfig* s_conf)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};

    void* retval;
    int   rc = 0;

    rc = pthread_create(&sthread, NULL, _whServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, c_conf);
        if (rc == 0) {
            /* All good. Block on joining */
            pthread_join(cthread, &retval);
            pthread_cancel(sthread);
        }
        else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
        }
    }
}

static int wh_ClientServer_MemThreadTest(void)
{
    int     ret               = 0;
    uint8_t req[BUFFER_SIZE]  = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};
    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
#if defined(WOLFHSM_CFG_TEST_CLIENT_CRYPTIMEOUT)
    whCryptoClientTimeOutCb tc_timeoutcb[1] = {WH_CLIENT_CRYPTO_TIMEOUT_CB};
#endif
    whCommClientConfig cc_conf[1] = {{
        .transport_cb      = tccb,
        .transport_context = (void*)tmcc,
        .transport_config  = (void*)tmcf,
#if defined(WOLFHSM_CFG_TEST_CLIENT_CRYPTIMEOUT)
        .crypt_timeout_cb = (void*)tc_timeoutcb,
#endif
        .client_id = 123,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm = cc_conf,
    }};
    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE / 2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    ret = wolfCrypt_Init();
    if (ret == 0) {
        ret = wc_InitRng_ex(crypto->rng, NULL, crypto->devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to initialize wolfCrypt rng: %d\n", ret);
        }
        else {
            _whClientServerThreadTest(c_conf, s_conf);
        }
    }
    else {
        WH_ERROR_PRINT("Failed to initialize wolfCrypt: %d\n", ret);
    }

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
int whTest_WolfCryptTest(void)
{
    printf("Testing wolfCrypt tests: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(wh_ClientServer_MemThreadTest());
    return 0;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#endif /* !WOLFHSM_CFG_NO_CRYPTO  && WOLFHSM_CFG_TEST_WOLFCRYPTTEST */
