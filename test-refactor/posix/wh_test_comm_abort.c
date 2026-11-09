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
 * test-refactor/posix/wh_test_comm_abort.c
 *
 * Client recovery after abandoning a response, over the mem and TCP
 * transports.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
#define WH_CA_ENABLED
#endif

#include "wh_test_common.h"
#include "wh_test_list.h" /* WH_TEST_SKIPPED */
#include "wh_test_comm_abort.h"

#ifndef WH_CA_ENABLED

int whTest_CommAbort(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#else /* WH_CA_ENABLED */

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_timeout.h"
#include "wolfhsm/wh_transport_mem.h"
#include "port/posix/posix_transport_tcp.h"

#define CA_BUFFER_SIZE 4096
#define CA_TCP_PORT 23457
#define CA_MAX_POLLS 5000

#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT
static int _FakeExpired(void* context, int* expired)
{
    *expired = *(int*)context;
    return WH_ERROR_OK;
}
#endif

static int _Wait(int* polls)
{
    const struct timespec oneMs = {0, 1000000};

    (void)nanosleep(&oneMs, NULL);
    return ++(*polls) < CA_MAX_POLLS;
}

static int _ServerRecv(whCommServer* server, uint16_t* kind, uint16_t* seq,
                       uint16_t* len, uint8_t* rx)
{
    uint16_t magic = 0;
    int      polls = 0;
    int      rc;

    do {
        rc = wh_CommServer_RecvRequest(server, &magic, kind, seq, len,
                                       WOLFHSM_CFG_COMM_DATA_LEN, rx);
    } while ((rc == WH_ERROR_NOTREADY) && _Wait(&polls));
    if (rc == WH_ERROR_OK) {
        rc = wh_CommServer_SendResponse(server, magic, *kind, *seq, *len, rx);
    }
    return rc;
}

static int _AbandonAndResend(whCommClient* client, whCommServer* server,
                             int* expire)
{
    static uint8_t rx[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t*       req   = wh_CommClient_GetDataPtr(client);
    uint16_t       magic = 0;
    uint16_t       kind  = 0;
    uint16_t       seq   = 0;
    uint16_t       len   = 0;
    int            polls = 0;
    int            rc;

    memcpy(req, "Stale", 6);
    do {
        rc = wh_CommClient_SendRequest(client, WH_COMM_MAGIC_NATIVE, 1, &seq, 6,
                                       req);
    } while ((rc == WH_ERROR_NOTREADY) && _Wait(&polls));
    WH_TEST_RETURN_ON_FAIL(rc);

    if (expire == NULL) {
        WH_TEST_RETURN_ON_FAIL(wh_CommClient_AbortPending(client));
    }
    else {
        *expire = 1;
        rc      = wh_CommClient_RecvResponse(client, &magic, &kind, &seq, &len,
                                             sizeof(rx), rx);
        *expire = 0;
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_TIMEOUT);
    }

    memcpy(req, "Fresh", 6);
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommClient_SendRequest(
                              client, WH_COMM_MAGIC_NATIVE, 2, &seq, 6, req));

    WH_TEST_RETURN_ON_FAIL(_ServerRecv(server, &kind, &seq, &len, rx));
    WH_TEST_ASSERT_RETURN(kind == 1);

    polls = 0;
    do {
        rc = wh_CommClient_SendRequest(client, WH_COMM_MAGIC_NATIVE, 2, &seq, 6,
                                       req);
    } while ((rc == WH_ERROR_NOTREADY) && _Wait(&polls));
    WH_TEST_RETURN_ON_FAIL(rc);

    WH_TEST_RETURN_ON_FAIL(_ServerRecv(server, &kind, &seq, &len, rx));
    WH_TEST_ASSERT_RETURN(kind == 2);
    WH_TEST_ASSERT_RETURN(memcmp(rx, "Fresh", 6) == 0);

    polls = 0;
    do {
        rc = wh_CommClient_RecvResponse(client, &magic, &kind, &seq, &len,
                                        sizeof(rx), rx);
    } while ((rc == WH_ERROR_NOTREADY) && _Wait(&polls));
    WH_TEST_RETURN_ON_FAIL(rc);
    WH_TEST_ASSERT_RETURN(kind == 2);
    WH_TEST_ASSERT_RETURN(memcmp(rx, "Fresh", 6) == 0);
    return 0;
}

static int _RunAbandonCases(const whTransportClientCb* ccb, void* cctx,
                            const void* ccfg, const whTransportServerCb* scb,
                            void* sctx, const void* scfg)
{
    whCommClient       client[1];
    whCommServer       server[1];
    whCommClientConfig c_conf[1] = {{
        .transport_cb      = ccb,
        .transport_context = cctx,
        .transport_config  = ccfg,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whCommServerConfig s_conf[1] = {{
        .transport_cb      = scb,
        .transport_context = sctx,
        .transport_config  = scfg,
        .server_id         = 124,
    }};
#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT
    int             expire     = 0;
    whTimeoutCb     fakeCb[1]  = {{.expired = _FakeExpired}};
    whTimeoutConfig timeoutCfg = {.cb = fakeCb, .context = &expire};
    c_conf->respTimeoutConfig  = &timeoutCfg;
#endif

    memset(client, 0, sizeof(client));
    memset(server, 0, sizeof(server));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Init(server, s_conf, NULL, NULL));
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Init(client, c_conf));

    WH_TEST_RETURN_ON_FAIL(_AbandonAndResend(client, server, NULL));
#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT
    WH_TEST_RETURN_ON_FAIL(_AbandonAndResend(client, server, &expire));
#endif

    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Cleanup(client));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Cleanup(server));
    return 0;
}

int whTest_CommAbort(void* ctx)
{
    static uint8_t                 req[CA_BUFFER_SIZE];
    static uint8_t                 resp[CA_BUFFER_SIZE];
    whTransportMemConfig           tmcf[1]  = {{
                   .req       = (whTransportMemCsr*)req,
                   .req_size  = sizeof(req),
                   .resp      = (whTransportMemCsr*)resp,
                   .resp_size = sizeof(resp),
    }};
    whTransportClientCb            tmccb[1] = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportServerCb            tmscb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemClientContext    tmcc[1];
    whTransportMemServerContext    tmsc[1];
    posixTransportTcpConfig        tcpcf[1] = {{
               .server_ip_string = "127.0.0.1",
               .server_port      = CA_TCP_PORT,
    }};
    whTransportClientCb            tcccb[1] = {PTT_CLIENT_CB};
    whTransportServerCb            tcscb[1] = {PTT_SERVER_CB};
    posixTransportTcpClientContext tcc[1];
    posixTransportTcpServerContext tsc[1];

    (void)ctx;
    memset(req, 0, sizeof(req));
    memset(resp, 0, sizeof(resp));
    memset(tmcc, 0, sizeof(tmcc));
    memset(tmsc, 0, sizeof(tmsc));
    memset(tcc, 0, sizeof(tcc));
    memset(tsc, 0, sizeof(tsc));

    WH_TEST_PRINT("Testing abandoned response: mem...\n");
    WH_TEST_RETURN_ON_FAIL(
        _RunAbandonCases(tmccb, tmcc, tmcf, tmscb, tmsc, tmcf));
    WH_TEST_PRINT("Testing abandoned response: tcp...\n");
    WH_TEST_RETURN_ON_FAIL(
        _RunAbandonCases(tcccb, tcc, tcpcf, tcscb, tsc, tcpcf));
    return 0;
}

#endif /* WH_CA_ENABLED */
