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
 * test-refactor/misc/wh_test_comm.c
 *
 * Sequential mem-transport coverage from legacy
 * test/wh_test_comm.c::whTest_CommMem. The pthread mem/tcp/shmem
 * variants live in the POSIX port (legacy harness retains them).
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define BUFFER_SIZE 4096
#define REQ_SIZE 32
#define RESP_SIZE 64
#define REPEAT_COUNT 10


static int _whTest_CommMem(void)
{
    int ret = 0;

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
    whTransportClientCb         tccb[1]   = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]   = {0};
    whCommClientConfig          c_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whCommClient                client[1] = {0};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          s_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};
    whCommServer                server[1] = {0};

    int counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len       = 0;
    uint16_t tx_req_flags     = WH_COMM_MAGIC_NATIVE;
    uint16_t tx_req_type      = 0;
    uint16_t tx_req_seq       = 0;

    uint8_t  rx_req[REQ_SIZE] = {0};
    uint16_t rx_req_len       = 0;
    uint16_t rx_req_flags     = 0;
    uint16_t rx_req_type      = 0;
    uint16_t rx_req_seq       = 0;

    uint8_t  tx_resp[RESP_SIZE] = {0};
    uint16_t tx_resp_len        = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len        = 0;
    uint16_t rx_resp_flags      = 0;
    uint16_t rx_resp_type       = 0;
    uint16_t rx_resp_seq        = 0;

    uint16_t seq_snapshot = 0;
    int      rc           = 0;

    /* BADARGS on uninitialized or NULL context */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_CommClient_IsRequestPending(NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_CommClient_IsRequestPending(client));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_CommClient_AbortPending(NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_CommClient_AbortPending(client));

    /* Init client and server */
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Init(server, s_conf, NULL, NULL));

    /* Fresh context: idle */
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

    /* Check that neither side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommServer_RecvRequest(server, &rx_req_flags,
                                                    &rx_req_type, &rx_req_seq,
                                                    &rx_req_len,
                                                    sizeof(rx_req), rx_req));

    /* RecvResponse with no outstanding request short-circuits to NOTREADY
     * without touching the transport. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommClient_RecvResponse(client, &rx_resp_flags,
                                                     &rx_resp_type,
                                                     &rx_resp_seq, &rx_resp_len,
                                                     sizeof(rx_resp), rx_resp));

    for (counter = 0; counter < REPEAT_COUNT; counter++) {
        (void)snprintf((char*)tx_req, sizeof(tx_req), "Request:%u", counter);
        tx_req_len  = strlen((char*)tx_req);
        tx_req_type = counter * 2;
        WH_TEST_RETURN_ON_FAIL(
            wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                &tx_req_seq, tx_req_len, tx_req));
        WH_TEST_DEBUG_PRINT("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
               ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len, tx_req);

        if (counter == 0) {
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                                  wh_CommClient_RecvResponse(
                                      client, &rx_resp_flags, &rx_resp_type,
                                      &rx_resp_seq, &rx_resp_len,
                                      sizeof(rx_resp), rx_resp));

            WH_TEST_ASSERT_RETURN(
                WH_ERROR_REQUEST_PENDING ==
                wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                          &tx_req_seq, tx_req_len, tx_req));
        }

        WH_TEST_RETURN_ON_FAIL(
            wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                      &rx_req_seq, &rx_req_len,
                                      sizeof(rx_req), rx_req));

        WH_TEST_DEBUG_PRINT("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
               ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len, rx_req);

        (void)snprintf((char*)tx_resp, sizeof(tx_resp), "Response:%s", rx_req);
        tx_resp_len = strlen((char*)tx_resp);
        ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                         rx_req_seq, tx_resp_len, tx_resp);
        if (ret != 0) {
            WH_ERROR_PRINT("Server SendResponse:%d\n", ret);
            return ret;
        }

        WH_TEST_DEBUG_PRINT(
            "Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
            ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp);

        WH_TEST_RETURN_ON_FAIL(wh_CommClient_RecvResponse(
            client, &rx_resp_flags, &rx_resp_type, &rx_resp_seq, &rx_resp_len,
            sizeof(rx_resp), rx_resp));

        WH_TEST_DEBUG_PRINT(
            "Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
            ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len,
            rx_resp);
    }

    /* Pending tracking: context is idle after the loop */
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

    /* Send a request: transitions to pending */
    (void)snprintf((char*)tx_req, sizeof(tx_req), "PendingTest");
    tx_req_len  = (uint16_t)strlen((char*)tx_req);
    tx_req_type = 0xABCD;
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_SendRequest(
        client, tx_req_flags, tx_req_type, &tx_req_seq, tx_req_len, tx_req));
    WH_TEST_ASSERT_RETURN(1 == wh_CommClient_IsRequestPending(client));

    /* Stacking guard: second send rejected without touching seq or transport */
    seq_snapshot = client->seq;
    rc           = wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                             &tx_req_seq, tx_req_len, tx_req);
    WH_TEST_ASSERT_RETURN(WH_ERROR_REQUEST_PENDING == rc);
    WH_TEST_ASSERT_RETURN(seq_snapshot == client->seq);
    WH_TEST_ASSERT_RETURN(1 == wh_CommClient_IsRequestPending(client));

    /* Server completes the exchange */
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_RecvRequest(
        server, &rx_req_flags, &rx_req_type, &rx_req_seq, &rx_req_len,
        sizeof(rx_req), rx_req));
    (void)snprintf((char*)tx_resp, sizeof(tx_resp), "Resp");
    tx_resp_len = (uint16_t)strlen((char*)tx_resp);
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendResponse(
        server, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp));

    /* Successful recv clears pending */
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_RecvResponse(
        client, &rx_resp_flags, &rx_resp_type, &rx_resp_seq, &rx_resp_len,
        sizeof(rx_resp), rx_resp));
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

    /* Second Recv with no outstanding request again yields NOTREADY */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommClient_RecvResponse(client, &rx_resp_flags,
                                                     &rx_resp_type,
                                                     &rx_resp_seq, &rx_resp_len,
                                                     sizeof(rx_resp), rx_resp));

    /* Send, then manually abort. Seq must not advance. */
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_SendRequest(
        client, tx_req_flags, tx_req_type, &tx_req_seq, tx_req_len, tx_req));
    WH_TEST_ASSERT_RETURN(1 == wh_CommClient_IsRequestPending(client));
    seq_snapshot = client->seq;
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_AbortPending(client));
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));
    WH_TEST_ASSERT_RETURN(seq_snapshot == client->seq);

    /* Drain the abandoned exchange on the server side so the transport state
     * doesn't linger across tests. */
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_RecvRequest(
        server, &rx_req_flags, &rx_req_type, &rx_req_seq, &rx_req_len,
        sizeof(rx_req), rx_req));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendResponse(
        server, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp));

    /* After abort the late response is ignored - pending is 0 so
     * RecvResponse short-circuits before consulting the transport. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommClient_RecvResponse(client, &rx_resp_flags,
                                                     &rx_resp_type,
                                                     &rx_resp_seq, &rx_resp_len,
                                                     sizeof(rx_resp), rx_resp));
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

    /* Out-of-range request length in the shared CSR (corruption, or a peer
     * built with a larger channel): far over the MTU, just over it, and
     * shorter than a header, down to empty. The server must reject it AND
     * complete the exchange, so the client gets an error instead of waiting
     * forever and the channel stays usable. */
    {
        uint16_t bad_lens[4];
        size_t   i;

        bad_lens[0] = 0xFFFF;
        bad_lens[1] = (uint16_t)(WH_COMM_MTU + 1);
        bad_lens[2] = (uint16_t)(sizeof(whCommHeader) - 1);
        bad_lens[3] = 0;

        for (i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++) {
            WH_TEST_RETURN_ON_FAIL(
                wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                          &tx_req_seq, tx_req_len, tx_req));
            ((whTransportMemCsr*)req)->s.len = bad_lens[i];

            /* Server rejects it without answering... */
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_REQUEST_SIZE ==
                wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                          &rx_req_seq, &rx_req_len,
                                          sizeof(rx_req), rx_req));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                                  wh_CommClient_RecvResponse(
                                      client, &rx_resp_flags, &rx_resp_type,
                                      &rx_resp_seq, &rx_resp_len,
                                      sizeof(rx_resp), rx_resp));
            WH_TEST_ASSERT_RETURN(1 == wh_CommClient_IsRequestPending(client));

            /* ...until the caller completes it with an empty packet */
            WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendEmptyResponse(server));
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_NOTREADY ==
                wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                          &rx_req_seq, &rx_req_len,
                                          sizeof(rx_req), rx_req));

            /* Client sees the empty packet as an error, not a hang */
            WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                                  wh_CommClient_RecvResponse(
                                      client, &rx_resp_flags, &rx_resp_type,
                                      &rx_resp_seq, &rx_resp_len,
                                      sizeof(rx_resp), rx_resp));
            WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

            /* The channel still works */
            WH_TEST_RETURN_ON_FAIL(
                wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                          &tx_req_seq, tx_req_len, tx_req));
            WH_TEST_RETURN_ON_FAIL(wh_CommServer_RecvRequest(
                server, &rx_req_flags, &rx_req_type, &rx_req_seq, &rx_req_len,
                sizeof(rx_req), rx_req));
            WH_TEST_RETURN_ON_FAIL(
                wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                           rx_req_seq, tx_resp_len, tx_resp));
            WH_TEST_RETURN_ON_FAIL(wh_CommClient_RecvResponse(
                client, &rx_resp_flags, &rx_resp_type, &rx_resp_seq,
                &rx_resp_len, sizeof(rx_resp), rx_resp));
            WH_TEST_ASSERT_RETURN(rx_resp_seq == tx_req_seq);
        }
    }

    /* The exact limits are still accepted: a bare header (empty payload) and
     * a full WH_COMM_MTU. The transport clamps its copy of an MTU-sized
     * request to the shared buffer; only the reported length matters here. */
    {
        uint16_t good_lens[2];
        uint16_t good_sizes[2];
        size_t   i;

        good_lens[0]  = (uint16_t)sizeof(whCommHeader);
        good_sizes[0] = 0;
        good_lens[1]  = (uint16_t)WH_COMM_MTU;
        good_sizes[1] = (uint16_t)WOLFHSM_CFG_COMM_DATA_LEN;

        for (i = 0; i < sizeof(good_lens) / sizeof(good_lens[0]); i++) {
            WH_TEST_RETURN_ON_FAIL(
                wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                          &tx_req_seq, tx_req_len, tx_req));
            ((whTransportMemCsr*)req)->s.len = good_lens[i];

            WH_TEST_RETURN_ON_FAIL(
                wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                          &rx_req_seq, &rx_req_len, 0, NULL));
            WH_TEST_ASSERT_RETURN(rx_req_len == good_sizes[i]);
            WH_TEST_ASSERT_RETURN(rx_req_seq == tx_req_seq);

            WH_TEST_RETURN_ON_FAIL(
                wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                           rx_req_seq, tx_resp_len, tx_resp));
            WH_TEST_RETURN_ON_FAIL(wh_CommClient_RecvResponse(
                client, &rx_resp_flags, &rx_resp_type, &rx_resp_seq,
                &rx_resp_len, sizeof(rx_resp), rx_resp));
            WH_TEST_ASSERT_RETURN(rx_resp_seq == tx_req_seq);
        }
    }

    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Cleanup(client));

    /* After Cleanup the context is no longer initialized; API reports BADARGS
     */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_CommClient_IsRequestPending(client));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_CommClient_AbortPending(client));

    return ret;
}


/* Server transport Send wrapping the mem transport: returns NOTREADY on the
 * first call, then, if _stubRefuseEmpty is set, refuses a zero-length packet as
 * the TCP transport does. */
static int _stubSendCalls   = 0;
static int _stubRefuseEmpty = 0;

static int _stubSendResponse(void* c, uint16_t len, const void* data)
{
    _stubSendCalls++;
    if (_stubSendCalls == 1) {
        return WH_ERROR_NOTREADY;
    }
    if ((len == 0) && _stubRefuseEmpty) {
        return WH_ERROR_BADARGS;
    }
    return wh_TransportMem_SendResponse(c, len, data);
}

/* wh_CommServer_SendEmptyResponse makes a single attempt (NOTREADY is left to
 * the caller) and reports WH_ERROR_ABORTED when the transport refuses an empty
 * packet. */
static int _whTest_CommDropFallback(void)
{
    uint8_t              req[BUFFER_SIZE]  = {0};
    uint8_t              resp[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]           = {
        {
         .req       = (whTransportMemCsr*)req,
         .req_size  = sizeof(req),
         .resp      = (whTransportMemCsr*)resp,
         .resp_size = sizeof(resp),
         }
    };

    whTransportClientCb         tccb[1]   = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]   = {0};
    whCommClientConfig          c_conf[1] = {
        {
         .transport_cb      = tccb,
         .transport_context = (void*)tmcc,
         .transport_config  = (void*)tmcf,
         .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
         }
    };
    whCommClient client[1] = {0};

    whTransportServerCb tscb[1] = {
        {
         .Init    = wh_TransportMem_Init,
         .Recv    = wh_TransportMem_RecvRequest,
         .Send    = _stubSendResponse,
         .Cleanup = wh_TransportMem_Cleanup,
         }
    };
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          s_conf[1] = {
        {
         .transport_cb      = tscb,
         .transport_context = (void*)tmsc,
         .transport_config  = (void*)tmcf,
         .server_id         = 124,
         }
    };
    whCommServer server[1] = {0};

    uint8_t  tx_req[REQ_SIZE] = "DropFallback";
    uint16_t tx_req_seq       = 0;
    uint16_t rx_len           = 0;

    _stubSendCalls   = 0;
    _stubRefuseEmpty = 1;

    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_CommServer_SendEmptyResponse(NULL));

    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Init(server, s_conf, NULL, NULL));

    WH_TEST_RETURN_ON_FAIL(
        wh_CommClient_SendRequest(client, WH_COMM_MAGIC_NATIVE, 0, &tx_req_seq,
                                  (uint16_t)strlen((char*)tx_req), tx_req));
    ((whTransportMemCsr*)req)->s.len = 0xFFFF;
    /* Rejecting doesn't touch the transport */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_REQUEST_SIZE ==
        wh_CommServer_RecvRequest(server, NULL, NULL, NULL, &rx_len, 0, NULL));
    WH_TEST_ASSERT_RETURN(_stubSendCalls == 0);

    /* One attempt per call: NOTREADY first, then the refusal */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommServer_SendEmptyResponse(server));
    WH_TEST_ASSERT_RETURN(_stubSendCalls == 1);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_CommServer_SendEmptyResponse(server));
    WH_TEST_ASSERT_RETURN(_stubSendCalls == 2);
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_AbortPending(client));

    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Cleanup(client));

    return WH_ERROR_OK;
}

/* A bad-length request through wh_Server_HandleRequestMessage. The server
 * Send returns NOTREADY once, so the server must retry the empty response.
 * If the transport accepts it, the server keeps running (returns WH_ERROR_OK),
 * the client gets WH_ERROR_ABORTED, and the next request on the same channel
 * succeeds. If the transport refuses it (refuseEmpty), the server returns
 * WH_ERROR_ABORTED. */
static int _whTest_CommServerDropRequest(int refuseEmpty)
{
    static uint8_t       req[BUFFER_SIZE];
    static uint8_t       resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {
        {
         .req       = (whTransportMemCsr*)req,
         .req_size  = sizeof(req),
         .resp      = (whTransportMemCsr*)resp,
         .resp_size = sizeof(resp),
         }
    };

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {
        {
         .transport_cb      = tccb,
         .transport_context = (void*)tmcc,
         .transport_config  = (void*)tmcf,
         .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
         }
    };
    whClientConfig c_conf[1] = {
        {
         .comm = cc_conf,
         }
    };
    static whClientContext client[1];

    whTransportServerCb tscb[1] = {
        {
         .Init    = wh_TransportMem_Init,
         .Recv    = wh_TransportMem_RecvRequest,
         .Send    = _stubSendResponse,
         .Cleanup = wh_TransportMem_Cleanup,
         }
    };
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {
        {
         .transport_cb      = tscb,
         .transport_context = (void*)tmsc,
         .transport_config  = (void*)tmcf,
         .server_id         = 124,
         }
    };
    whServerConfig s_conf[1] = {
        {
         .comm_config = cs_conf,
         }
    };
    static whServerContext server[1];

    const char echo[]      = "DropRequest";
    char       rx_echo[32] = {0};
    uint16_t   rx_echo_len = 0;

    memset(req, 0, sizeof(req));
    memset(resp, 0, sizeof(resp));
    memset(client, 0, sizeof(client));
    memset(server, 0, sizeof(server));
    _stubSendCalls   = 0;
    _stubRefuseEmpty = refuseEmpty;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_EchoRequest(client, (uint16_t)sizeof(echo), echo));
    ((whTransportMemCsr*)req)->s.len = (uint16_t)(WH_COMM_MTU + 1);
    if (refuseEmpty) {
        WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                              wh_Server_HandleRequestMessage(server));
        WH_TEST_ASSERT_RETURN(_stubSendCalls == 2);
        WH_TEST_RETURN_ON_FAIL(wh_CommClient_AbortPending(client->comm));
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));
        return WH_ERROR_OK;
    }
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_ASSERT_RETURN(_stubSendCalls == 2);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ABORTED ==
        wh_Client_EchoResponse(client, &rx_echo_len, rx_echo));

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_EchoRequest(client, (uint16_t)sizeof(echo), echo));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_EchoResponse(client, &rx_echo_len, rx_echo));
    WH_TEST_ASSERT_RETURN(rx_echo_len == sizeof(echo));
    WH_TEST_ASSERT_RETURN(0 == memcmp(rx_echo, echo, sizeof(echo)));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}


int whTest_Comm(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing comms: mem...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_CommMem());
    WH_TEST_RETURN_ON_FAIL(_whTest_CommDropFallback());
    WH_TEST_RETURN_ON_FAIL(_whTest_CommServerDropRequest(0));
    WH_TEST_RETURN_ON_FAIL(_whTest_CommServerDropRequest(1));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
