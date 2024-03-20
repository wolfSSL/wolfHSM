#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#if defined(WH_CONFIG)
#include "wh_config.h"
#endif

#include "wh_test_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

#if defined(WH_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include <unistd.h>  /* For sleep */
#endif


#define BUFFER_SIZE 4096
#define REQ_SIZE 32
#define RESP_SIZE 64
#define REPEAT_COUNT 10
#define ONE_MS 1000

int whTest_ClientServerSequential(void)
{
    int ret = 0;

    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE];
    uint8_t              resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]   = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]   = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 1234,
    }};

    whClientContext client[1] = {0};

    whClientConfig c_conf[1] = {{
       .comm = cc_conf,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 5678,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1] = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = 1024 * 1024, /* 1MB  Flash */
        .sectorSize = 4096,        /* 4KB  Sector Size */
        .pageSize   = 8,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
    }};
    const whFlashCb  fcb[1]          = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig nf_conf[1] = {{
        .cb      = fcb,
        .context = fc,
        .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1] = {0};
    whNvmCb nfcb[1] = {WH_NVM_FLASH_CB};

    whNvmConfig n_conf[1] = {{
            .cb = nfcb,
            .context = nfc,
            .config = nf_conf,
    }};

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm_config = n_conf,
    }};
    whServerContext                server[1] = {0};

    /* Init client and server */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));

    int counter = 1;
    char recv_buffer[WH_COMM_MTU] = {0};
    char send_buffer[WH_COMM_MTU] = {0};
    uint16_t send_len = 0;
    uint16_t recv_len = 0;

    int32_t server_rc = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;
    uint32_t avail_size = 0;
    uint32_t reclaim_size = 0;
    whNvmId avail_objects = 0;
    whNvmId reclaim_objects = 0;

    /* Check that the server side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
            wh_Server_HandleRequestMessage(server));

    for (counter = 0; counter < REPEAT_COUNT; counter++) {

        /* Prepare echo test */
        sprintf(send_buffer, "Request:%u", counter);
        send_len = strlen(send_buffer);
        sprintf(recv_buffer, "NOTHING RECEIVED");
        recv_len = 0;

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_EchoRequest(client, send_len, send_buffer));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client EchoRequest:%d, len:%d, %.*s\n",
               ret, send_len, send_len, send_buffer);
#endif

        if (counter == 0) {
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                                  wh_Client_EchoResponse(
                                      client, &recv_len, recv_buffer));
        }

        WH_TEST_RETURN_ON_FAIL(
            wh_Server_HandleRequestMessage(server));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Server HandleRequestMessage:%d\n", ret);
#endif

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_EchoResponse(client, &recv_len, recv_buffer));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client EchoResponse:%d, len:%d, %.*s, expected:%.*s\n",
            ret, recv_len, recv_len, recv_buffer, send_len, send_buffer);
#endif
        WH_TEST_ASSERT_RETURN( recv_len == send_len);
        WH_TEST_ASSERT_RETURN( strncmp(recv_buffer, send_buffer, recv_len) == 0);
    }

    /* Perform NVM tests */
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(
            wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmInitResponse(client, &server_rc, &client_id, &server_id));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmInitResponse:%d, server_rc:%d, clientid:%d serverid:%d\n",
            ret, server_rc, client_id, server_id);
#endif

    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(
            wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmGetAvailableResponse(client, &server_rc,
                    &avail_size, &avail_objects,
                    &reclaim_size, &reclaim_objects));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailableResponse:%d, server_rc:%d avail_size:%d avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
            ret, server_rc, avail_size, avail_objects, reclaim_size, reclaim_objects);
#endif

    for (counter = 0; counter < 5; counter ++) {
        whNvmId id = counter + 20;
        whNvmAccess access = WOLFHSM_NVM_ACCESS_ANY;
        whNvmFlags flags = WOLFHSM_NVM_FLAGS_ANY;
        whNvmSize label_len = 0;
        char label[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize len = 0;

        whNvmId gid = 0;
        whNvmAccess gaccess = 0;
        whNvmFlags gflags = 0;
        char glabel[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize glen = 0;

        whNvmSize rlen = 0;

        label_len = sprintf(label, "Label:%d", id);
        len = sprintf(send_buffer, "Data:%d Counter:%d", id, counter);

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectRequest:%d, id:%u, access:0x%x, flags:0x%x, len:%u label:%s\nData:%s\n",
            ret, id, access, flags, len, label, send_buffer);
#endif

        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmAddObjectRequest(client,
                        id, access, flags,
                        label_len, (uint8_t*)label,
                        len, (uint8_t*)send_buffer));
        WH_TEST_RETURN_ON_FAIL(
                wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmAddObjectResponse(client, &server_rc));
        #if defined(WH_CFG_TEST_VERBOSE)
                printf("Client NvmAddObjectResponse:%d, server_rc:%d\n",
                    ret, server_rc);
        #endif

        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetAvailableRequest(client));
        WH_TEST_RETURN_ON_FAIL(
                wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetAvailableResponse(client, &server_rc,
                        &avail_size, &avail_objects,
                        &reclaim_size, &reclaim_objects));
        #if defined(WH_CFG_TEST_VERBOSE)
                printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
                    ret, server_rc, avail_size, avail_objects, reclaim_size, reclaim_objects);
        #endif

        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetMetadataRequest(client, id));
        WH_TEST_RETURN_ON_FAIL(
                wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetMetadataResponse(client, &server_rc,
                        &gid, &gaccess, &gflags,
                        &glen,
                        sizeof(glabel), (uint8_t*)glabel));
        #if defined(WH_CFG_TEST_VERBOSE)
                printf("Client NvmGetMetadataResponse:%d, id:%u, access:0x%x, flags:0x%x, len:%u label:%s\n",
            ret, gid, gaccess, gflags, glen, glabel);
        #endif

        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmReadRequest(client, id, 0, glen));
        WH_TEST_RETURN_ON_FAIL(
                wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmReadResponse(client, &server_rc,
                        &rlen, (uint8_t*)recv_buffer));
        #if defined(WH_CFG_TEST_VERBOSE)
                printf("Client NvmReadResponse:%d, server_rc:%d id:%u, len:%u data:%s\n",
            ret, server_rc, gid, rlen, recv_buffer);
        #endif
    }

    whNvmAccess list_access = WOLFHSM_NVM_ACCESS_ANY;
    whNvmFlags list_flags = WOLFHSM_NVM_FLAGS_ANY;
    whNvmId list_id = 0;
    whNvmId list_count = 0;
    do {
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmListRequest(client, list_access, list_flags, list_id));
    WH_TEST_RETURN_ON_FAIL(
            wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmListResponse(client, &server_rc,
                    &list_count, &list_id));
    #if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n",
        ret, server_rc, list_count, list_id);
    #endif

        if(list_count > 0) {
            WH_TEST_RETURN_ON_FAIL(
                    wh_Client_NvmDestroyObjectsRequest(client, 1, &list_id));
            WH_TEST_RETURN_ON_FAIL(
                    wh_Server_HandleRequestMessage(server));
            WH_TEST_RETURN_ON_FAIL(
                    wh_Client_NvmDestroyObjectsResponse(client, &server_rc));
            #if defined(WH_CFG_TEST_VERBOSE)
                    printf("Client NvmDestroyObjectsResponse:%d, server_rc:%d for id:%u with count:%u\n",
                ret, server_rc, list_id, list_count);
            #endif
            list_id = 0;
        }
    } while (list_count > 0);

    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmCleanupRequest(client));
    WH_TEST_RETURN_ON_FAIL(
            wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmCleanupResponse(client, &server_rc));
    #if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmCleanupResponse:%d, server_rc:%d\n",
                ret, server_rc);
    #endif

    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(
            wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmGetAvailableResponse(client, &server_rc,
                    &avail_size, &avail_objects,
                    &reclaim_size, &reclaim_objects));
    #if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
                ret, server_rc, avail_size, avail_objects, reclaim_size, reclaim_objects);
    #endif

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return ret;
}

#if 0
#if defined WH_CFG_TEST_POSIX


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
        sprintf((char*)tx_req, "Request:%u", counter);
        tx_req_len  = strlen((char*)tx_req);
        tx_req_type = counter * 2;
        do {
            ret = wh_CommClient_SendRequest(client, tx_req_flags, tx_req_type,
                                            &tx_req_seq, tx_req_len, tx_req);
            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Client SendRequest: ret=%d", ret);
#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len,
                   tx_req);
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
#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len,
                   rx_resp);
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

    ret = wh_CommServer_Init(server, config);
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
                                            &rx_req_seq, &rx_req_len, rx_req);

            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Server RecvRequest: ret=%d", ret);
#if defined(WH_CONFIG_TEST_VERBOSE)
            printf("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len,
                   rx_req);
#endif
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS) == 0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        }

        do {
            sprintf((char*)tx_resp, "Response:%s", rx_req);
            tx_resp_len = strlen((char*)tx_resp);
            ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                             rx_req_seq, tx_resp_len, tx_resp);

            WH_TEST_ASSERT_MSG((ret == WH_ERROR_NOTREADY) || (0 == ret),
                               "Server SendResponse: ret=%d", ret);
#if defined(WH_CONFIG_TEST_VERBOSE)
            printf("Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, "
                   "%s\n",
                   ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len,
                   tx_resp);
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
#if defined(WH_CFG_TEST_VERBOSE)
    printf("Server thread create:%d\n", rc);
#endif

    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whCommClientTask, c_conf);
#if defined(WH_CFG_TEST_VERBOSE)
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
    uint8_t              req[BUFFER_SIZE];
    uint8_t              resp[BUFFER_SIZE];
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
                 .client_id         = 1234,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tmscb[1]  = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext css[1]    = {};
    whCommServerConfig          s_conf[1] = {{
                 .transport_cb      = tmscb,
                 .transport_context = (void*)css,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 5678,
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
                    .client_id         = 1234,
    }};

    /* Server configuration/contexts */
    whTransportServerCb pttscb[1] = {PTT_SERVER_CB};

    posixTransportTcpServerContext tss[1]    = {};
    whCommServerConfig             s_conf[1] = {{
                    .transport_cb      = pttscb,
                    .transport_context = (void*)tss,
                    .transport_config  = (void*)mytcpconfig,
                    .server_id         = 5678,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}
#endif

#endif /* defined(WH_CFG_TEST_POSIX) */

int whTest_ClientServer(void)
{
    printf("Testing client/server sequential: mem...\n");
    WH_TEST_ASSERT(0 == whTest_ClientServerSequential());

#if 0
#if defined(WH_CFG_TEST_POSIX)
    printf("Testing comms: (pthread) mem...\n");
    wh_CommClientServer_MemThreadTest();

    printf("Testing comms: (pthread) tcp...\n");
    wh_CommClientServer_TcpThreadTest();
#endif /* defined(WH_CFG_TEST_POSIX) */
#endif
    return 0;
}
