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
 * test-refactor/misc/wh_test_client_id_binding.c
 *
 * Server-side client ID binding: a client ID assigned to the channel in the
 * server comm config, and the server COMM INIT callback.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

enum {
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};

/* COMM INIT callback state */
typedef struct {
    int     calls;
    int     refuseRc;      /* returned for any ID other than allowClientId */
    uint8_t allowClientId; /* only ID accepted, 0 accepts any */
    uint8_t lastClientId;
} whTestCommInitCbState;

static int _commInitCb(whServerContext* server, uint8_t clientId, void* arg)
{
    whTestCommInitCbState* state = (whTestCommInitCbState*)arg;

    if ((server == NULL) || (state == NULL)) {
        return WH_ERROR_BADARGS;
    }
    state->calls++;
    state->lastClientId = clientId;
    if ((state->allowClientId != 0) && (clientId != state->allowClientId)) {
        return state->refuseRc;
    }
    return WH_ERROR_OK;
}

/* Start a connected client and server on the memory transport */
static int _pairInit(whClientContext* client, whClientConfig* c_conf,
                     whServerContext* server, whServerConfig* s_conf)
{
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    return WH_ERROR_OK;
}

static int _pairCleanup(whClientContext* client, whServerContext* server)
{
    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));
    return WH_ERROR_OK;
}

/* Drive one COMM INIT with clientId. A refused request gets an empty
 * response, which the client reports as WH_ERROR_ABORTED, and must leave the
 * server's binding unchanged. */
static int _commInit(whClientContext* client, whServerContext* server,
                     uint8_t clientId, int expectOk)
{
    uint32_t respClientId = 0;
    uint32_t respServerId = 0;
    uint8_t  priorId      = server->comm->client_id;
    int      rc;

    client->comm->client_id = clientId;
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    rc = wh_Client_CommInitResponse(client, &respClientId, &respServerId);

    if (expectOk) {
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(respClientId == clientId);
        WH_TEST_ASSERT_RETURN(server->comm->client_id == clientId);
    }
    else {
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
        WH_TEST_ASSERT_RETURN(server->comm->client_id == priorId);
    }
    return WH_ERROR_OK;
}

/* End the session with COMM CLOSE, then start a new one on the same server
 * context */
static int _reconnect(whClientContext* client, whServerContext* server)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));
    WH_TEST_ASSERT_RETURN(server->comm->client_id == 0);
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    return WH_ERROR_OK;
}

static int _whTest_ClientIdBinding(void)
{
    const uint8_t assignedId = WH_TEST_DEFAULT_CLIENT_ID + 1;
    const uint8_t otherId    = WH_TEST_DEFAULT_CLIENT_ID + 2;

    /* Transport memory configuration */
    static uint8_t       req[BUFFER_SIZE];
    static uint8_t       resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
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
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm = cc_conf,
    }};
    static whClientContext      client[1];

    /* Server configuration/contexts. COMM INIT needs no NVM or crypto. */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};
    whServerConfig              s_conf[1]  = {{
                      .comm_config = cs_conf,
    }};
    static whServerContext      server[1];

    whTestCommInitCbState cbState;

    /* An assigned ID that no client can bind is a config error */
    cs_conf->client_id = WH_CLIENT_ID_MAX + 1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Server_Init(server, s_conf));

    /* The largest client ID is a valid assignment */
    cs_conf->client_id = WH_CLIENT_ID_MAX;
    WH_TEST_RETURN_ON_FAIL(_pairInit(client, c_conf, server, s_conf));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, WH_CLIENT_ID_MAX, 1));
    WH_TEST_RETURN_ON_FAIL(_pairCleanup(client, server));

    /* Assigned ID: only that ID can bind, including later in the session */
    cs_conf->client_id = assignedId;
    WH_TEST_RETURN_ON_FAIL(_pairInit(client, c_conf, server, s_conf));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    /* Still unbound */
    WH_TEST_ASSERT_RETURN(server->comm->client_id == 0);
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 1));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    WH_TEST_ASSERT_RETURN(server->comm->client_id == assignedId);
    /* The range check still applies */
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, 0, 0));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 1));
    /* The assigned ID still applies after a reconnect */
    WH_TEST_RETURN_ON_FAIL(_reconnect(client, server));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 1));
    WH_TEST_RETURN_ON_FAIL(_pairCleanup(client, server));

    /* Callback only: the callback decides which ID can bind */
    memset(&cbState, 0, sizeof(cbState));
    cbState.allowClientId = assignedId;
    cbState.refuseRc      = WH_ERROR_ACCESS;
    cs_conf->client_id    = 0;
    s_conf->commInitCb    = _commInitCb;
    s_conf->commInitCbArg = &cbState;
    WH_TEST_RETURN_ON_FAIL(_pairInit(client, c_conf, server, s_conf));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 1));
    WH_TEST_ASSERT_RETURN(cbState.calls == 1);
    WH_TEST_ASSERT_RETURN(cbState.lastClientId == assignedId);
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    WH_TEST_ASSERT_RETURN(cbState.calls == 2);
    WH_TEST_ASSERT_RETURN(cbState.lastClientId == otherId);
    WH_TEST_ASSERT_RETURN(server->comm->client_id == assignedId);
    /* Out of range IDs are refused before the callback runs */
    WH_TEST_RETURN_ON_FAIL(
        _commInit(client, server, (uint8_t)(WH_CLIENT_ID_MAX + 1), 0));
    WH_TEST_ASSERT_RETURN(cbState.calls == 2);
    /* The callback still runs after a reconnect */
    WH_TEST_RETURN_ON_FAIL(_reconnect(client, server));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    WH_TEST_ASSERT_RETURN(cbState.calls == 3);
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 1));
    WH_TEST_ASSERT_RETURN(cbState.calls == 4);
    /* Any value other than WH_ERROR_OK refuses, including a positive one */
    cbState.refuseRc = 1;
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    WH_TEST_ASSERT_RETURN(cbState.calls == 5);
    WH_TEST_RETURN_ON_FAIL(_pairCleanup(client, server));

    /* Assigned ID and callback: the assigned ID is checked first, and the
     * callback can still refuse the assigned ID */
    memset(&cbState, 0, sizeof(cbState));
    cbState.allowClientId = otherId;
    cbState.refuseRc      = WH_ERROR_ACCESS;
    cs_conf->client_id    = assignedId;
    WH_TEST_RETURN_ON_FAIL(_pairInit(client, c_conf, server, s_conf));
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, otherId, 0));
    WH_TEST_ASSERT_RETURN(cbState.calls == 0);
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 0));
    WH_TEST_ASSERT_RETURN(cbState.calls == 1);
    cbState.allowClientId = assignedId;
    WH_TEST_RETURN_ON_FAIL(_commInit(client, server, assignedId, 1));
    WH_TEST_ASSERT_RETURN(cbState.calls == 2);
    WH_TEST_RETURN_ON_FAIL(_pairCleanup(client, server));

    return WH_ERROR_OK;
}

int whTest_ClientIdBinding(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT(
        "Testing server-assigned client ID and COMM INIT callback...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientIdBinding());

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
