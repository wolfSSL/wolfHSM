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
 * test/wh_test_comms.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */


#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include <unistd.h>  /* For usleep */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_transport_shm.h"
#endif

#include "wh_test_common.h"
#include "wh_test_comm.h"

#define BUFFER_SIZE 4096
#define REQ_SIZE 32
#define RESP_SIZE 64
#define REPEAT_COUNT 10
#define ONE_MS 1000

int whTest_CommMem(void)
{
    int ret = 0;

    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE] = {0};
    uint8_t              resp[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1] = {{
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
                 .client_id         = 123,
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

    /* Init client and server */
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Init(server, s_conf, NULL, NULL));

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

    /* Check that neither side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_CommServer_RecvRequest(server, &rx_req_flags,
                                                    &rx_req_type, &rx_req_seq,
                                                    &rx_req_len, rx_req));

    for (counter = 0; counter < REPEAT_COUNT; counter++) {
        snprintf((char*)tx_req, sizeof(tx_req), "Request:%u", counter);
        tx_req_len  = strlen((char*)tx_req);
        tx_req_type = counter * 2;
        WH_TEST_RETURN_ON_FAIL(
            wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                &tx_req_seq, tx_req_len, tx_req));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
               ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len, tx_req);
#endif

        if (counter == 0) {
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                                  wh_CommClient_RecvResponse(
                                      client, &rx_resp_flags, &rx_resp_type,
                                      &rx_resp_seq, &rx_resp_len, rx_resp));

            WH_TEST_ASSERT_RETURN(
                WH_ERROR_NOTREADY ==
                wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                          &tx_req_seq, tx_req_len, tx_req));
        }

        WH_TEST_RETURN_ON_FAIL(
            wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                      &rx_req_seq, &rx_req_len, rx_req));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
               ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len, rx_req);
#endif

        snprintf((char*)tx_resp, sizeof(tx_resp), "Response:%s", rx_req);
        tx_resp_len = strlen((char*)tx_resp);
        ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                         rx_req_seq, tx_resp_len, tx_resp);
        if (ret != 0) {
            WH_ERROR_PRINT("Server SendResponse:%d\n", ret);
            return ret;
        }

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf(
            "Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
            ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp);
#endif

        WH_TEST_RETURN_ON_FAIL(
            wh_CommClient_RecvResponse(client, &rx_resp_flags, &rx_resp_type,
                                       &rx_resp_seq, &rx_resp_len, rx_resp));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf(
            "Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
            ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len,
            rx_resp);
#endif
    }

    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_CommClient_Cleanup(client));

    return ret;
}


#if defined WOLFHSM_CFG_TEST_POSIX


static void* _whCommClientTask(void* cf)
{
    whCommClientConfig* config = (whCommClientConfig*)cf;
    int                 ret    = 0;
    whCommClient        client[1];
    int                 counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len       = 0;
    uint16_t tx_req_flags     = WH_COMM_MAGIC_NATIVE;
    uint16_t tx_req_type      = 0;
    uint16_t tx_req_seq       = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len        = 0;
    uint16_t rx_resp_flags      = 0;
    uint16_t rx_resp_type       = 0;
    uint16_t rx_resp_seq        = 0;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_CommClient_Init(client, config);
    WH_TEST_ASSERT_MSG(0 == ret, "Client Init: ret=%d", ret);

    for (counter = 0; counter < REPEAT_COUNT; counter++) {
        snprintf((char*)tx_req, sizeof(tx_req), "Request:%u", counter);
        tx_req_len  = strlen((char*)tx_req);
        tx_req_type = counter * 2;
        do {
            ret = wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                            &tx_req_seq, tx_req_len, tx_req);
            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Client SendRequest: ret=%d", ret);
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            if(ret != WH_ERROR_NOTREADY) {
	            printf("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len,
                   tx_req);
            }
#endif
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS) == 0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

        do {
            ret = wh_CommClient_RecvResponse(client, &rx_resp_flags,
                                             &rx_resp_type, &rx_resp_seq,
                                             &rx_resp_len, rx_resp);
            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Client RecvResponse: ret=%d", ret);
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            if(ret != WH_ERROR_NOTREADY) {
                printf("Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len,
                   rx_resp);
            }
#endif
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS) == 0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }
    }

    ret = wh_CommClient_Cleanup(client);
    WH_TEST_ASSERT_MSG(0 == ret, "Client Cleanup: ret=%d", ret);
    return NULL;
}

static void* _whCommServerTask(void* cf)
{
    whCommServerConfig* config = (whCommServerConfig*)cf;
    int                 ret    = 0;
    whCommServer        server[1];
    int                 counter = 1;

    ret = wh_CommServer_Init(server, config, NULL, NULL);
    WH_TEST_ASSERT_MSG(0 == ret, "Server Init: ret=%d", ret);

    uint8_t  rx_req[REQ_SIZE] = {0};
    uint16_t rx_req_len       = 0;
    uint16_t rx_req_flags     = 0;
    uint16_t rx_req_type      = 0;
    uint16_t rx_req_seq       = 0;

    uint8_t  tx_resp[RESP_SIZE] = {0};
    uint16_t tx_resp_len        = 0;

    for (counter = 0; counter < REPEAT_COUNT; counter++) {
        do {
            ret = wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                            &rx_req_seq, &rx_req_len,
                                            rx_req);

            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Server RecvRequest: ret=%d", ret);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
           if(ret != WH_ERROR_NOTREADY) {
               printf("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len,
                   rx_req);
           }
#endif
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS) == 0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        }

        do {
            snprintf((char*)tx_resp, sizeof(tx_resp), "Response:%s", rx_req);
            tx_resp_len = strlen((char*)tx_resp);
            ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                             rx_req_seq, tx_resp_len, tx_resp);

            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Server SendResponse: ret=%d", ret);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            if(ret != WH_ERROR_NOTREADY) {
                printf("Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len,
                   tx_resp);
            }
#endif
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS) == 0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        }
    }

    ret = wh_CommServer_Cleanup(server);
    WH_TEST_ASSERT_MSG(0 == ret, "Server Cleanup: ret=%d", ret);

    return NULL;
}

static void _whCommClientServerThreadTest(whCommClientConfig* c_conf,
                                          whCommServerConfig* s_conf)
{
    pthread_t cthread;
    pthread_t sthread;

    void* retval;
    int   rc = 0;

    rc = pthread_create(&sthread, NULL, _whCommServerTask, s_conf);
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Server thread create:%d\n", rc);
#endif

    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whCommClientTask, c_conf);
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client thread create:%d\n", rc);
#endif
        if (rc == 0) {
            /* All good. Block on joining */

            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        }
        else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);
        }
    }
}

void wh_CommClientServer_MemThreadTest(void)
{
    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE] = {0};
    uint8_t              resp[BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tmccb[1]  = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext csc[1]    = {};
    whCommClientConfig          c_conf[1] = {{
                 .transport_cb      = tmccb,
                 .transport_context = (void*)csc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 0x1,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tmscb[1]  = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext css[1]    = {};
    whCommServerConfig          s_conf[1] = {{
                 .transport_cb      = tmscb,
                 .transport_context = (void*)css,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 0xF,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}

void wh_CommClientServer_ShMemThreadTest(void)
{
    /* Transport memory configuration */
    posixTransportShmConfig tmcf[1] = {{
        .name = "/wh_test_comm_shm",
        .req_size   = BUFFER_SIZE,
        .resp_size  = BUFFER_SIZE,
        .dma_size = BUFFER_SIZE * 4,
    }};

    /* Make unique name for this test */
    char uniq_name[32] = {0};
    snprintf(uniq_name, sizeof(uniq_name),"/wh_test_comm_shm.%u",
            (unsigned) getpid());
    tmcf->name = uniq_name;

    /* Client configuration/contexts */
    whTransportClientCb            tmccb[1]  = {POSIX_TRANSPORT_SHM_CLIENT_CB};
    posixTransportShmClientContext csc[1]    = {};
    whCommClientConfig             c_conf[1] = {{
                    .transport_cb      = tmccb,
                    .transport_context = (void*)csc,
                    .transport_config  = (void*)tmcf,
                    .client_id         = 0x2,
    }};

    /* Server configuration/contexts */
    whTransportServerCb            tmscb[1]  = {POSIX_TRANSPORT_SHM_SERVER_CB};
    posixTransportShmServerContext css[1]    = {};
    whCommServerConfig             s_conf[1] = {{
                    .transport_cb      = tmscb,
                    .transport_context = (void*)css,
                    .transport_config  = (void*)tmcf,
                    .server_id         = 0xF,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}

void wh_CommClientServer_TcpThreadTest(void)
{
    posixTransportTcpConfig mytcpconfig[1] = {{
        .server_ip_string = "127.0.0.1",
        .server_port      = 23456,
    }};


    /* Client configuration/contexts */
    whTransportClientCb            pttccb[1] = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1]    = {};
    whCommClientConfig             c_conf[1] = {{
                    .transport_cb      = pttccb,
                    .transport_context = (void*)tcc,
                    .transport_config  = (void*)mytcpconfig,
                    .client_id         = 0x3,
    }};

    /* Server configuration/contexts */
    whTransportServerCb pttscb[1] = {PTT_SERVER_CB};

    posixTransportTcpServerContext tss[1]    = {};
    whCommServerConfig             s_conf[1] = {{
                    .transport_cb      = pttscb,
                    .transport_context = (void*)tss,
                    .transport_config  = (void*)mytcpconfig,
                    .server_id         = 0xF,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}

#endif /* defined(WOLFHSM_CFG_TEST_POSIX) */

int whTest_Comm(void)
{
    printf("Testing comms: mem...\n");
    WH_TEST_ASSERT(0 == whTest_CommMem());

#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing comms: (pthread) mem...\n");
    wh_CommClientServer_MemThreadTest();

    printf("Testing comms: (pthread) tcp...\n");
    wh_CommClientServer_TcpThreadTest();

    printf("Testing comms: (pthread) posix mem...\n");
    wh_CommClientServer_ShMemThreadTest();
#endif /* defined(WOLFHSM_CFG_TEST_POSIX) */

    return 0;
}
