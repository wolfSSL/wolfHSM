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
                                                    &rx_req_len, rx_req));

    /* RecvResponse with no outstanding request short-circuits to NOTREADY
     * without touching the transport. */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTREADY ==
        wh_CommClient_RecvResponse(client, &rx_resp_flags, &rx_resp_type,
                                   &rx_resp_seq, &rx_resp_len, rx_resp));

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
                                      &rx_resp_seq, &rx_resp_len, rx_resp));

            WH_TEST_ASSERT_RETURN(
                WH_ERROR_REQUEST_PENDING ==
                wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                          &tx_req_seq, tx_req_len, tx_req));
        }

        WH_TEST_RETURN_ON_FAIL(
            wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                      &rx_req_seq, &rx_req_len, rx_req));

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

        WH_TEST_RETURN_ON_FAIL(
            wh_CommClient_RecvResponse(client, &rx_resp_flags, &rx_resp_type,
                                       &rx_resp_seq, &rx_resp_len, rx_resp));

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
        server, &rx_req_flags, &rx_req_type, &rx_req_seq, &rx_req_len, rx_req));
    (void)snprintf((char*)tx_resp, sizeof(tx_resp), "Resp");
    tx_resp_len = (uint16_t)strlen((char*)tx_resp);
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendResponse(
        server, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp));

    /* Successful recv clears pending */
    WH_TEST_RETURN_ON_FAIL(
        wh_CommClient_RecvResponse(client, &rx_resp_flags, &rx_resp_type,
                                   &rx_resp_seq, &rx_resp_len, rx_resp));
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

    /* Second Recv with no outstanding request again yields NOTREADY */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTREADY ==
        wh_CommClient_RecvResponse(client, &rx_resp_flags, &rx_resp_type,
                                   &rx_resp_seq, &rx_resp_len, rx_resp));

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
        server, &rx_req_flags, &rx_req_type, &rx_req_seq, &rx_req_len, rx_req));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendResponse(
        server, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp));

    /* After abort the late response is ignored - pending is 0 so
     * RecvResponse short-circuits before consulting the transport. */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTREADY ==
        wh_CommClient_RecvResponse(client, &rx_resp_flags, &rx_resp_type,
                                   &rx_resp_seq, &rx_resp_len, rx_resp));
    WH_TEST_ASSERT_RETURN(0 == wh_CommClient_IsRequestPending(client));

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


int whTest_Comm(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing comms: mem...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_CommMem());

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
