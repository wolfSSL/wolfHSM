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

#include <stdio.h>
#include <string.h>

#include "wh_test_common.h"
#include "wh_test_server.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_keystore.h"

static int whTest_ServerInit(void)
{
    int ret;
    whServerContext server = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportServerCb transportCb = WH_TRANSPORT_MEM_SERVER_CB;
    static whTransportMemServerContext transportCtx = {0};
    whServerConfig cfg = {0};
    whCommServerConfig commCfg = {
        .transport_cb = &transportCb,
        .transport_context = &transportCtx,
        .transport_config = &transportCfg,
        .server_id = 1,
    };
    whServerCryptoContext cryptoCtx = {
        .devId = WH_DEV_ID_HSM,
    };
    cfg.comm_config = &commCfg;
    cfg.crypto = &cryptoCtx;

    printf("Testing server initialization...\n");

    /* Test invalid parameters */
    ret = wh_Server_Init(NULL, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    ret = wh_Server_Init(&server, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    ret = wh_Server_Init(NULL, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Test with invalid transport configuration */
    commCfg.transport_config = NULL;
    ret = wh_Server_Init(&server, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    commCfg.transport_config = &transportCfg;

    /* Test with invalid transport callback */
    commCfg.transport_cb = NULL;
    ret = wh_Server_Init(&server, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    commCfg.transport_cb = &transportCb;

    /* Test with invalid transport context */
    commCfg.transport_context = NULL;
    ret = wh_Server_Init(&server, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    commCfg.transport_context = &transportCtx;

    /* Test valid initialization */
    ret = wh_Server_Init(&server, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Cleanup */
    ret = wh_Server_Cleanup(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("Server initialization tests passed\n");
    return WH_ERROR_OK;
}

static int whTest_ServerCleanup(void)
{
    int ret;
    whServerContext server = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportServerCb transportCb = WH_TRANSPORT_MEM_SERVER_CB;
    static whTransportMemServerContext transportCtx = {0};
    whServerConfig cfg = {0};
    whCommServerConfig commCfg = {
        .transport_cb = &transportCb,
        .transport_context = &transportCtx,
        .transport_config = &transportCfg,
        .server_id = 1,
    };
    whServerCryptoContext cryptoCtx = {
        .devId = WH_DEV_ID_HSM,
    };
    cfg.comm_config = &commCfg;
    cfg.crypto = &cryptoCtx;

    printf("Testing server cleanup...\n");

    /* Test cleanup without initialization */
    ret = wh_Server_Cleanup(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test cleanup with NULL context */
    ret = wh_Server_Cleanup(NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Test cleanup after initialization */
    ret = wh_Server_Init(&server, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Server_Cleanup(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test double cleanup */
    ret = wh_Server_Cleanup(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("Server cleanup tests passed\n");
    return WH_ERROR_OK;
}

static int whTest_ServerKeystore(void)
{
    int ret;
    whServerContext server = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportServerCb transportCb = WH_TRANSPORT_MEM_SERVER_CB;
    static whTransportMemServerContext transportCtx = {0};
    whServerConfig cfg = {0};
    whCommServerConfig commCfg = {
        .transport_cb = &transportCb,
        .transport_context = &transportCtx,
        .transport_config = &transportCfg,
        .server_id = 1,
    };
    whServerCryptoContext cryptoCtx = {
        .devId = WH_DEV_ID_HSM,
    };
    cfg.comm_config = &commCfg;
    cfg.crypto = &cryptoCtx;

    printf("Testing server keystore...\n");

    /* Initialize server */
    ret = wh_Server_Init(&server, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test keystore operations */
    ret = wh_Server_KeystoreInit(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Server_KeystoreCleanup(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Cleanup */
    ret = wh_Server_Cleanup(&server);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("Server keystore tests passed\n");
    return WH_ERROR_OK;
}

int whTest_Server(void)
{
    int ret;

    printf("Testing server...\n");

    /* Test initialization */
    ret = whTest_ServerInit();
    if (ret != 0) {
        WH_ERROR_PRINT("Server initialization tests failed: %d\n", ret);
        return ret;
    }

    /* Test cleanup */
    ret = whTest_ServerCleanup();
    if (ret != 0) {
        WH_ERROR_PRINT("Server cleanup tests failed: %d\n", ret);
        return ret;
    }

    /* Test keystore */
    ret = whTest_ServerKeystore();
    if (ret != 0) {
        WH_ERROR_PRINT("Server keystore tests failed: %d\n", ret);
        return ret;
    }

    printf("All server tests passed\n");
    return WH_ERROR_OK;
}
