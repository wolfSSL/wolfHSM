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

#include "wolfhsm/wh_settings.h"

#include "wh_test_common.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_server.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include <unistd.h>
#include <time.h>     /* For nanosleep */
#include <fcntl.h>    /* For O_* constants */
#include <sys/mman.h> /* For shm_open, mmap */
#include <sys/stat.h> /* For mode constants */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_transport_shm.h"

const struct timespec ONE_MS = {.tv_sec = 0, .tv_nsec = 1000000};
#endif

#include "wh_test_comm.h"

#define BUFFER_SIZE 4096
#define REQ_SIZE 32
#define RESP_SIZE 64
#define REPEAT_COUNT 10


#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)
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
#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
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
        (void)snprintf((char*)tx_req, sizeof(tx_req), "Request:%u", counter);
        tx_req_len  = strlen((char*)tx_req);
        tx_req_type = counter * 2;
        do {
            ret = wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                            &tx_req_seq, tx_req_len, tx_req);
            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Client SendRequest: ret=%d", ret);
            if(ret != WH_ERROR_NOTREADY) {
                WH_TEST_DEBUG_PRINT("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len,
                   tx_req);
            }
        } while ((ret == WH_ERROR_NOTREADY) && (nanosleep(&ONE_MS, NULL) == 0));

        if (ret != 0) {
            WH_TEST_DEBUG_PRINT("Client had failure. Exiting\n");
            break;
        }

        do {
            ret = wh_CommClient_RecvResponse(
                client, &rx_resp_flags, &rx_resp_type, &rx_resp_seq,
                &rx_resp_len, sizeof(rx_resp), rx_resp);
            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Client RecvResponse: ret=%d", ret);
            if(ret != WH_ERROR_NOTREADY) {
                WH_TEST_DEBUG_PRINT("Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len,
                   rx_resp);
            }
        } while ((ret == WH_ERROR_NOTREADY) && (nanosleep(&ONE_MS, NULL) == 0));

        if (ret != 0) {
            WH_TEST_DEBUG_PRINT("Client had failure. Exiting\n");
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
                                            sizeof(rx_req), rx_req);

            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Server RecvRequest: ret=%d", ret);

            if(ret != WH_ERROR_NOTREADY) {
                WH_TEST_DEBUG_PRINT("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len,
                   rx_req);
            }
        } while ((ret == WH_ERROR_NOTREADY) && (nanosleep(&ONE_MS, NULL) == 0));

        if (ret != 0) {
            WH_TEST_DEBUG_PRINT("Server had failure. Exiting\n");
            break;
        }

        do {
            (void)snprintf((char*)tx_resp, sizeof(tx_resp), "Response:%s", rx_req);
            tx_resp_len = strlen((char*)tx_resp);
            ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                             rx_req_seq, tx_resp_len, tx_resp);

            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Server SendResponse: ret=%d", ret);

            if(ret != WH_ERROR_NOTREADY) {
                WH_TEST_DEBUG_PRINT("Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len,
                   tx_resp);
            }
        } while ((ret == WH_ERROR_NOTREADY) && (nanosleep(&ONE_MS, NULL) == 0));

        if (ret != 0) {
            WH_TEST_DEBUG_PRINT("Server had failure. Exiting\n");
            break;
        }
    }

    ret = wh_CommServer_Cleanup(server);
    WH_TEST_ASSERT_MSG(0 == ret, "Server Cleanup: ret=%d", ret);

    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
static void _whCommClientServerThreadTest(whCommClientConfig* c_conf,
                                          whCommServerConfig* s_conf)
{
    pthread_t cthread;
    pthread_t sthread;

    void* retval;
    int   rc = 0;

    rc = pthread_create(&sthread, NULL, _whCommServerTask, s_conf);
    WH_TEST_DEBUG_PRINT("Server thread create:%d\n", rc);

    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whCommClientTask, c_conf);
        WH_TEST_DEBUG_PRINT("Client thread create:%d\n", rc);
        if (rc == 0) {
            /* All good. Block on joining */
            (void)pthread_join(cthread, &retval);
            (void)pthread_join(sthread, &retval);
        }
        else {
            /* Cancel the server thread */
            (void)pthread_cancel(sthread);
            (void)pthread_join(sthread, &retval);
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
    whTransportMemClientContext csc[1]    = {0};
    whCommClientConfig          c_conf[1] = {{
                 .transport_cb      = tmccb,
                 .transport_context = (void*)csc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tmscb[1]  = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext css[1]    = {0};
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
    posixTransportShmClientContext csc[1]    = {0};
    whCommClientConfig             c_conf[1] = {{
                    .transport_cb      = tmccb,
                    .transport_context = (void*)csc,
                    .transport_config  = (void*)tmcf,
                    .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};

    /* Server configuration/contexts */
    whTransportServerCb            tmscb[1]  = {POSIX_TRANSPORT_SHM_SERVER_CB};
    posixTransportShmServerContext css[1]    = {0};
    whCommServerConfig             s_conf[1] = {{
                    .transport_cb      = tmscb,
                    .transport_context = (void*)css,
                    .transport_config  = (void*)tmcf,
                    .server_id         = 0xF,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}

/* Mirror of the file-local ptshmHeader in port/posix/posix_transport_shm.c, so
 * the test can write layouts a well-behaved creator would never produce. Drift
 * shows up as the accept case below failing to connect. */
#define PTSHM_TEST_HEADER_SIZE 64
#define PTSHM_TEST_INITIALIZED_CREATOR 2
/* Larger than any object the test creates, and a valid buffer size, so the
 * layout is refused on the total-versus-object bound and nothing else */
#define PTSHM_TEST_OVERSIZE_BUFFER 65528

/* How the squat helper derives the dma_size it writes */
enum {
    PTSHM_TEST_DMA_GIVEN = 0, /* use the caller's dma_size verbatim */
    PTSHM_TEST_DMA_EXACT,     /* exactly fill the object: largest accepted */
    PTSHM_TEST_DMA_OVER       /* one byte more than the object can hold */
};

typedef union {
    struct {
        uint32_t initialized;
        uint16_t req_size;
        uint16_t resp_size;
        size_t   dma_size;
        pid_t    creator_pid;
        pid_t    user_pid;
    } f;
    uint8_t pad[PTSHM_TEST_HEADER_SIZE];
} ptshmTestHeader;

/* Squat the name with a caller-supplied header, then let the client open it.
 * Returns the client Init result, or WH_ERROR_ABORTED on setup failure. */
static int _whTest_CommShmSquat(char* name, off_t obj_size, uint16_t req_size,
                                uint16_t resp_size, size_t dma_size,
                                int dma_mode)
{
    int                            ret       = WH_ERROR_OK;
    int                            fd        = -1;
    ptshmTestHeader*               hdr       = NULL;
    struct stat                    st[1]     = {0};
    whCommConnected                connected = WH_COMM_DISCONNECTED;
    whTransportClientCb            cb[1]     = {POSIX_TRANSPORT_SHM_CLIENT_CB};
    posixTransportShmClientContext ctx[1]    = {0};
    posixTransportShmConfig        cfg[1]    = {0};

    cfg->name = name;

    (void)shm_unlink(name);
    fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        WH_ERROR_PRINT("shm_open(%s) failed\n", name);
        return WH_ERROR_ABORTED;
    }

    if (ftruncate(fd, obj_size) != 0) {
        WH_ERROR_PRINT("ftruncate(%s) failed\n", name);
        ret = WH_ERROR_ABORTED;
    }

    /* The OS may round the object up, so the sizes that sit on the accept and
     * reject sides of the bound come from the size it actually ended up with */
    if ((ret == WH_ERROR_OK) && (dma_mode != PTSHM_TEST_DMA_GIVEN)) {
        if (fstat(fd, st) != 0) {
            WH_ERROR_PRINT("fstat(%s) failed\n", name);
            ret = WH_ERROR_ABORTED;
        }
        else {
            dma_size = (size_t)st->st_size - sizeof(ptshmTestHeader) -
                       (size_t)req_size - (size_t)resp_size;
            if (dma_mode == PTSHM_TEST_DMA_OVER) {
                dma_size++;
            }
        }
    }

    if (ret == WH_ERROR_OK) {
        hdr = (ptshmTestHeader*)mmap(NULL, sizeof(*hdr),
                                     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (hdr == MAP_FAILED) {
            WH_ERROR_PRINT("mmap(%s) failed\n", name);
            ret = WH_ERROR_ABORTED;
        }
    }

    if (ret == WH_ERROR_OK) {
        hdr->f.req_size    = req_size;
        hdr->f.resp_size   = resp_size;
        hdr->f.dma_size    = dma_size;
        hdr->f.creator_pid = getpid();
        hdr->f.initialized = PTSHM_TEST_INITIALIZED_CREATOR;
        (void)munmap((void*)hdr, sizeof(*hdr));

        ret = cb->Init(ctx, cfg, NULL, NULL);

        /* Init folds NOTFOUND and NOTREADY into OK, so an OK return alone does
         * not mean the object was mapped. Report never-mapped as NOTREADY. */
        if (ret == WH_ERROR_OK) {
            if ((posixTransportShm_IsConnected(ctx, &connected) !=
                 WH_ERROR_OK) ||
                (connected != WH_COMM_CONNECTED)) {
                ret = WH_ERROR_NOTREADY;
            }
        }
        (void)cb->Cleanup(ctx);
    }

    (void)close(fd);
    (void)shm_unlink(name);
    return ret;
}

/* A creator that races to claim the name can describe a layout that does not
 * fit the object it created. Every such layout must be refused. */
static int _whTest_CommShmMalformedHeader(void)
{
    int   ret      = WH_ERROR_OK;
    char  name[48] = {0};
    off_t obj_size = 0;

    obj_size = sizeof(ptshmTestHeader) + REQ_SIZE + RESP_SIZE + BUFFER_SIZE;

    (void)snprintf(name, sizeof(name), "/wh_test_comm_shm_bad.%u",
                   (unsigned)getpid());

    /* Exactly fills the object: the largest dma_size that must be accepted */
    ret = _whTest_CommShmSquat(name, obj_size, REQ_SIZE, RESP_SIZE, 0,
                               PTSHM_TEST_DMA_EXACT);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Object far larger than the declared footprint is still accepted; the
     * transport maps only the footprint and ignores the padding */
    ret = _whTest_CommShmSquat(name, obj_size, REQ_SIZE, RESP_SIZE, 0,
                               PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* One byte more than the object holds: the smallest that must be refused */
    ret = _whTest_CommShmSquat(name, obj_size, REQ_SIZE, RESP_SIZE, 0,
                               PTSHM_TEST_DMA_OVER);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* dma_size larger than the bytes left after the header and buffers */
    ret = _whTest_CommShmSquat(name, obj_size, REQ_SIZE, RESP_SIZE, ~(size_t)0,
                               PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Valid buffer sizes whose total still overruns the object */
    ret = _whTest_CommShmSquat(name, obj_size, PTSHM_TEST_OVERSIZE_BUFFER,
                               PTSHM_TEST_OVERSIZE_BUFFER, 0,
                               PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Buffers too small for their control word */
    ret = _whTest_CommShmSquat(name, obj_size, sizeof(whTransportMemCsr) - 1,
                               RESP_SIZE, 0, PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    ret = _whTest_CommShmSquat(name, obj_size, REQ_SIZE,
                               sizeof(whTransportMemCsr) - 1, 0,
                               PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Buffers that are not a whole number of control words */
    ret = _whTest_CommShmSquat(name, obj_size, sizeof(whTransportMemCsr) + 1,
                               RESP_SIZE, 0, PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    ret = _whTest_CommShmSquat(name, obj_size, REQ_SIZE,
                               sizeof(whTransportMemCsr) + 1, 0,
                               PTSHM_TEST_DMA_GIVEN);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    return WH_TEST_SUCCESS;
}

/* The same rule applies to the server's own configuration, and a rejected
 * config must not leave an object behind for clients to trip over. */
static int _whTest_CommShmServerBadConfig(void)
{
    int                            ret       = WH_ERROR_OK;
    int                            fd        = -1;
    char                           name[48]  = {0};
    whTransportServerCb            cb[1]     = {POSIX_TRANSPORT_SHM_SERVER_CB};
    posixTransportShmServerContext ctx[1]    = {0};
    posixTransportShmConfig        cfg[1]    = {0};

    (void)snprintf(name, sizeof(name), "/wh_test_comm_shm_cfg.%u",
                   (unsigned)getpid());
    cfg->name      = name;
    cfg->req_size  = sizeof(whTransportMemCsr) + 1;
    cfg->resp_size = RESP_SIZE;
    cfg->dma_size  = 0;

    ret = cb->Init(ctx, cfg, NULL, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Nothing should be left linked under that name */
    fd = shm_open(name, O_RDONLY, 0);
    if (fd >= 0) {
        (void)close(fd);
        (void)shm_unlink(name);
        WH_ERROR_PRINT("server left %s linked after a rejected config\n", name);
        return WH_TEST_FAIL;
    }

    return WH_TEST_SUCCESS;
}

void wh_CommClientServer_TcpThreadTest(void)
{
    posixTransportTcpConfig mytcpconfig[1] = {{
        .server_ip_string = "127.0.0.1",
        .server_port      = 23456,
    }};


    /* Client configuration/contexts */
    whTransportClientCb            pttccb[1] = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1]    = {0};
    whCommClientConfig             c_conf[1] = {{
                    .transport_cb      = pttccb,
                    .transport_context = (void*)tcc,
                    .transport_config  = (void*)mytcpconfig,
                    .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};

    /* Server configuration/contexts */
    whTransportServerCb pttscb[1] = {PTT_SERVER_CB};

    posixTransportTcpServerContext tss[1]    = {0};
    whCommServerConfig             s_conf[1] = {{
                    .transport_cb      = pttscb,
                    .transport_context = (void*)tss,
                    .transport_config  = (void*)mytcpconfig,
                    .server_id         = 0xF,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)
int whTest_Comm(void)
{
    WH_TEST_PRINT("Testing comms: mem...\n");
    WH_TEST_ASSERT(0 == whTest_CommMem());

#if defined(WOLFHSM_CFG_TEST_POSIX)
    WH_TEST_PRINT("Testing comms: (pthread) mem...\n");
    wh_CommClientServer_MemThreadTest();

    WH_TEST_PRINT("Testing comms: (pthread) tcp...\n");
    wh_CommClientServer_TcpThreadTest();

    WH_TEST_PRINT("Testing comms: (pthread) posix mem...\n");
    wh_CommClientServer_ShMemThreadTest();

    WH_TEST_PRINT("Testing comms: posix shm malformed header...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_CommShmMalformedHeader());

    WH_TEST_PRINT("Testing comms: posix shm bad server config...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_CommShmServerBadConfig());
#endif /* defined(WOLFHSM_CFG_TEST_POSIX) */

    return 0;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
