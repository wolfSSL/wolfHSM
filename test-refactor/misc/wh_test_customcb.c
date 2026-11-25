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
 * test-refactor/misc/wh_test_customcb.c
 *
 * Server custom callbacks: registration, the registered check, and the
 * request and reply round trip.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

enum {
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};

/* Reply type and fill byte used by _ownTypeCb */
#define TEST_REPLY_TYPE (WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START + 1)
#define TEST_REPLY_BYTE ((uint8_t)0x5A)

/* Own client/server pair on the mem transport, since the test registers its
 * own server callbacks. Custom callbacks need no NVM or crypto. */
typedef struct {
    whServerContext server[1];
    whClientContext client[1];
    /* Transport */
    uint8_t                     reqBuf[BUFFER_SIZE];
    uint8_t                     respBuf[BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];
    whTransportClientCb         tccb[1];
    whTransportMemClientContext tmcc[1];
    whCommClientConfig          cc_conf[1];
    whClientConfig              c_conf[1];
    whServerConfig              s_conf[1];
} TestCtx;

/* Static to keep the misc group's stack footprint small */
static TestCtx _testCtx;

/* Copies the request's server buffer to its client buffer and reports the
 * copied size. Does not set the reply type. */
static int _loopbackCb(whServerContext*                 server,
                       const whMessageCustomCb_Request* req,
                       whMessageCustomCb_Response*      resp)
{
    uint8_t* serverPtr = NULL;
    uint8_t* clientPtr = NULL;
    size_t   copySz    = 0;

    (void)server;

    if (req->type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA64) {
        clientPtr = (uint8_t*)((uintptr_t)req->data.dma64.client_addr);
        serverPtr = (uint8_t*)((uintptr_t)req->data.dma64.server_addr);
        resp->data.dma64.client_sz = req->data.dma64.server_sz;
        copySz                     = (size_t)req->data.dma64.server_sz;
    }
    else if (req->type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA32) {
        clientPtr = (uint8_t*)((uintptr_t)req->data.dma32.client_addr);
        serverPtr = (uint8_t*)((uintptr_t)req->data.dma32.server_addr);
        resp->data.dma32.client_sz = req->data.dma32.server_sz;
        copySz                     = (size_t)req->data.dma32.server_sz;
    }
    if ((clientPtr != NULL) && (serverPtr != NULL) && (copySz > 0)) {
        memcpy(clientPtr, serverPtr, copySz);
    }

    return (int)req->id;
}

/* Replies with its own type and a full data buffer */
static int _ownTypeCb(whServerContext*                 server,
                      const whMessageCustomCb_Request* req,
                      whMessageCustomCb_Response*      resp)
{
    (void)server;
    (void)req;

    resp->type = TEST_REPLY_TYPE;
    memset(resp->data.buffer.data, TEST_REPLY_BYTE,
           sizeof(resp->data.buffer.data));

    return 0;
}

static int _SetupClientServer(TestCtx* t)
{
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    memset(t, 0, sizeof(*t));

    /* Transport */
    t->tmcf[0] = (whTransportMemConfig){
        .req       = (whTransportMemCsr*)t->reqBuf,
        .req_size  = sizeof(t->reqBuf),
        .resp      = (whTransportMemCsr*)t->respBuf,
        .resp_size = sizeof(t->respBuf),
    };
    t->tscb[0]    = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    t->cs_conf[0] = (whCommServerConfig){
        .transport_cb      = t->tscb,
        .transport_context = (void*)t->tmsc,
        .transport_config  = (void*)t->tmcf,
        .server_id         = 124,
    };
    t->tccb[0]    = (whTransportClientCb)WH_TRANSPORT_MEM_CLIENT_CB;
    t->cc_conf[0] = (whCommClientConfig){
        .transport_cb      = t->tccb,
        .transport_context = (void*)t->tmcc,
        .transport_config  = (void*)t->tmcf,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    };
    t->c_conf[0] = (whClientConfig){
        .comm = t->cc_conf,
    };
    t->s_conf[0] = (whServerConfig){
        .comm_config = t->cs_conf,
    };

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(t->server, t->s_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_SetConnected(t->server, WH_COMM_CONNECTED));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(t->client, t->c_conf));

    /* Comm init so the server learns the client id */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInitResponse(t->client, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(client_id == t->client->comm->client_id);

    return WH_ERROR_OK;
}

static void _CleanupClientServer(TestCtx* t)
{
    (void)wh_Client_Cleanup(t->client);
    (void)wh_Server_Cleanup(t->server);
}

/* Send one custom callback request and read the reply */
static int _Call(TestCtx* t, const whMessageCustomCb_Request* req,
                 whMessageCustomCb_Response* resp)
{
    memset(resp, 0, sizeof(*resp));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbRequest(t->client, req));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbResponse(t->client, resp));
    return WH_ERROR_OK;
}

/* Ask the server if a callback is registered and check the answer */
static int _CheckRegistered(TestCtx* t, uint32_t id, int expectErr)
{
    uint16_t outId   = 0;
    int      respErr = 0;

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CustomCheckRegisteredRequest(t->client, id));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(t->server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CustomCbCheckRegisteredResponse(t->client, &outId, &respErr));
    WH_TEST_ASSERT_RETURN(outId == id);
    WH_TEST_ASSERT_RETURN(respErr == expectErr);
    return WH_ERROR_OK;
}

/* Register a callback on every ID and call each one */
static int _whTest_CustomCbLoopback(TestCtx* t)
{
    whMessageCustomCb_Request  req;
    whMessageCustomCb_Response resp;
    uint32_t                   id;

    const char input[] = "The answer to the ultimate question of life, the "
                         "universe and everything is 42";
    char       output[sizeof(input)];

    for (id = 0; id < WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT; id++) {
        memset(output, 0, sizeof(output));
        memset(&req, 0, sizeof(req));
        req.id = id;

        /* The buffers are passed by address, in the host pointer size */
        if (sizeof(uintptr_t) == sizeof(uint64_t)) {
            req.type                   = WH_MESSAGE_CUSTOM_CB_TYPE_DMA64;
            req.data.dma64.server_addr = (uint64_t)((uintptr_t)input);
            req.data.dma64.server_sz   = sizeof(input);
            req.data.dma64.client_addr = (uint64_t)((uintptr_t)output);
        }
        else {
            req.type                   = WH_MESSAGE_CUSTOM_CB_TYPE_DMA32;
            req.data.dma32.server_addr = (uint32_t)((uintptr_t)input);
            req.data.dma32.server_sz   = sizeof(input);
            req.data.dma32.client_addr = (uint32_t)((uintptr_t)output);
        }

        /* Nothing is registered yet */
        WH_TEST_RETURN_ON_FAIL(_CheckRegistered(t, id, WH_ERROR_NOHANDLER));
        WH_TEST_RETURN_ON_FAIL(_Call(t, &req, &resp));
        WH_TEST_ASSERT_RETURN(resp.err == WH_ERROR_NOHANDLER);
        WH_TEST_ASSERT_RETURN(output[0] == 0);

        WH_TEST_RETURN_ON_FAIL(
            wh_Server_RegisterCustomCb(t->server, (uint16_t)id, _loopbackCb));
        WH_TEST_RETURN_ON_FAIL(_CheckRegistered(t, id, WH_ERROR_OK));

        WH_TEST_RETURN_ON_FAIL(_Call(t, &req, &resp));
        WH_TEST_ASSERT_RETURN(resp.err == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(resp.rc == (int32_t)id);
        WH_TEST_ASSERT_RETURN(0 == memcmp(output, input, sizeof(input)));

        /* The reply type and the size the callback wrote must come back */
        WH_TEST_ASSERT_RETURN(resp.type == req.type);
        if (req.type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA64) {
            WH_TEST_ASSERT_RETURN(resp.data.dma64.client_sz == sizeof(input));
        }
        else {
            WH_TEST_ASSERT_RETURN(resp.data.dma32.client_sz == sizeof(input));
        }
    }

    return WH_ERROR_OK;
}

/* A callback can reply with a type other than the request type */
static int _whTest_CustomCbOwnReplyType(TestCtx* t)
{
    whMessageCustomCb_Request  req;
    whMessageCustomCb_Response resp;
    size_t                     i;

    WH_TEST_RETURN_ON_FAIL(
        wh_Server_RegisterCustomCb(t->server, 0, _ownTypeCb));

    memset(&req, 0, sizeof(req));
    req.id   = 0;
    req.type = WH_MESSAGE_CUSTOM_CB_TYPE_DMA32;

    WH_TEST_RETURN_ON_FAIL(_Call(t, &req, &resp));
    WH_TEST_ASSERT_RETURN(resp.err == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(resp.type == TEST_REPLY_TYPE);
    for (i = 0; i < sizeof(resp.data.buffer.data); i++) {
        WH_TEST_ASSERT_RETURN(resp.data.buffer.data[i] == TEST_REPLY_BYTE);
    }

    return WH_ERROR_OK;
}

int whTest_CustomCb(void* ctx)
{
    int      ret;
    TestCtx* t = &_testCtx;

    (void)ctx;

    WH_TEST_PRINT("Testing server custom callbacks...\n");

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));

    ret = _whTest_CustomCbLoopback(t);
    if (ret == WH_ERROR_OK) {
        ret = _whTest_CustomCbOwnReplyType(t);
    }

    _CleanupClientServer(t);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
