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
#include "wh_test_client_core.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

static int whTest_ClientCoreInit(void)
{
    int ret;
    whClientContext client = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportClientCb transportCb = WH_TRANSPORT_MEM_CLIENT_CB;
    static whTransportMemClientContext transportCtx = {0};
    whClientConfig cfg = {0};
    whCommClientConfig commCfg = {
        .transport_cb = &transportCb,
        .transport_context = &transportCtx,
        .transport_config = &transportCfg,
        .client_id = 1,
    };
    cfg.comm = &commCfg;

    printf("Testing client initialization...\n");

    /* Test invalid parameters */
    ret = wh_Client_Init(NULL, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    ret = wh_Client_Init(&client, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    ret = wh_Client_Init(NULL, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Test with invalid transport configuration */
    commCfg.transport_config = NULL;
    ret = wh_Client_Init(&client, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    commCfg.transport_config = &transportCfg;

    /* Test with invalid transport callback */
    commCfg.transport_cb = NULL;
    ret = wh_Client_Init(&client, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    commCfg.transport_cb = &transportCb;

    /* Test with invalid transport context */
    commCfg.transport_context = NULL;
    ret = wh_Client_Init(&client, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    commCfg.transport_context = &transportCtx;

    /* Test valid initialization */
    ret = wh_Client_Init(&client, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Cleanup */
    ret = wh_Client_Cleanup(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("Client initialization tests passed\n");
    return WH_ERROR_OK;
}

static int whTest_ClientCoreCleanup(void)
{
    int ret;
    whClientContext client = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportClientCb transportCb = WH_TRANSPORT_MEM_CLIENT_CB;
    static whTransportMemClientContext transportCtx = {0};
    whClientConfig cfg = {0};
    whCommClientConfig commCfg = {
        .transport_cb = &transportCb,
        .transport_context = &transportCtx,
        .transport_config = &transportCfg,
        .client_id = 1,
    };
    cfg.comm = &commCfg;

    printf("Testing client cleanup...\n");

    /* Test cleanup without initialization */
    ret = wh_Client_Cleanup(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test cleanup with NULL context */
    ret = wh_Client_Cleanup(NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Test cleanup after initialization */
    ret = wh_Client_Init(&client, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Client_Cleanup(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test double cleanup */
    ret = wh_Client_Cleanup(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("Client cleanup tests passed\n");
    return WH_ERROR_OK;
}

static int whTest_ClientCoreComm(void)
{
    int ret;
    whClientContext client = {0};
    static uint8_t req_buffer[4096];
    static uint8_t resp_buffer[4096];
    static whTransportMemConfig transportCfg = {
        .req = req_buffer,
        .req_size = sizeof(req_buffer),
        .resp = resp_buffer,
        .resp_size = sizeof(resp_buffer),
    };
    static const whTransportClientCb transportCb = WH_TRANSPORT_MEM_CLIENT_CB;
    static whTransportMemClientContext transportCtx = {0};
    whClientConfig cfg = {0};
    whCommClientConfig commCfg = {
        .transport_cb = &transportCb,
        .transport_context = &transportCtx,
        .transport_config = &transportCfg,
        .client_id = 1,
    };
    cfg.comm = &commCfg;

    printf("Testing client communication...\n");

    /* Initialize client */
    ret = wh_Client_Init(&client, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test communication setup */
    ret = wh_Client_CommSetup(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test communication teardown */
    ret = wh_Client_CommTeardown(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Cleanup */
    ret = wh_Client_Cleanup(&client);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("Client communication tests passed\n");
    return WH_ERROR_OK;
}

int whTest_ClientCore(void)
{
    int ret;

    printf("Testing client core...\n");

    /* Test initialization */
    ret = whTest_ClientCoreInit();
    if (ret != 0) {
        WH_ERROR_PRINT("Client initialization tests failed: %d\n", ret);
        return ret;
    }

    /* Test cleanup */
    ret = whTest_ClientCoreCleanup();
    if (ret != 0) {
        WH_ERROR_PRINT("Client cleanup tests failed: %d\n", ret);
        return ret;
    }

    /* Test communication */
    ret = whTest_ClientCoreComm();
    if (ret != 0) {
        WH_ERROR_PRINT("Client communication tests failed: %d\n", ret);
        return ret;
    }

    printf("All client core tests passed\n");
    return WH_ERROR_OK;
}
