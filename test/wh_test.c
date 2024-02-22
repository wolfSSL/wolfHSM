/*
 * test/wh_test.c
 *
 */

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* For sleep */

#include <pthread.h> /* For pthread_create/cancel/join/_t */

#if 0
#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"
#endif


#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"


#include "wolfhsm/wh_transport_mem.h"

#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"


/* HAL Flash state and configuration */
const whFlashCb myCb[1] = { POSIX_FLASH_FILE_CB };
posixFlashFileContext myHalFlashContext[1] = {0};
posixFlashFileConfig myHalFlashConfig[1] = {{
        .filename       = "myNvm.bin",
        .partition_size = 16384,
        .erased_byte    = (~(uint8_t)0),
}};

/* NVM Configuration using PosixSim HAL Flash */
whNvmFlashConfig myNvmConfig = {
        .cb = myCb,
        .context = myHalFlashContext,
        .config = myHalFlashConfig,
};

enum {
        REPEAT_COUNT = 10,
        REQ_SIZE = 32,
        RESP_SIZE = 64,
        BUFFER_SIZE = 4096,
        ONE_MS = 1000,
    };


static void _HexDump(const char* p, size_t data_len)
{
    const size_t bytesPerLine = 16;
    const unsigned char two_digits = 0x10;
    const unsigned char* u = (const unsigned char*)p;
    printf("    HD:%p for %lu bytes\n",p, data_len);
    if ( (p == NULL) || (data_len == 0))
        return;
    size_t off = 0;
    for (off = 0; off < data_len; off++)
    {
        if ((off % bytesPerLine) == 0)
            printf("    ");
        if(u[off] < two_digits) {
            printf("0%X ", u[off]);
        } else {
            printf("%X ", u[off]);
        }
        if ((off % bytesPerLine) == (bytesPerLine - 1))
            printf("\n");
    }
    if ( (off % bytesPerLine) != 0)
        printf("\n");
}


static void _ShowAvailable(const whNvmCb* cb, void* context)
{
    int rc = 0;
    whNvmSize free_space = 0;
    whNvmId free_objects = 0;
    whNvmSize reclaim_space = 0;
    whNvmId reclaim_objects = 0;
    rc = cb->GetAvailable(
            context,
            &free_space,
            &free_objects,
            &reclaim_space,
            &reclaim_objects);
    if (rc == 0) {
        printf( "NVM %p has %u bytes, and %u objects available \n"
                "           %u bytes, and %u objects reclaimable \n",
            context,
            (unsigned int)free_space, (unsigned int)free_objects,
            (unsigned int)reclaim_space, (unsigned int)reclaim_objects);
    } else {
        printf("NVM %p failed to get available info: %d.\n",
            context, rc);
    }
}

static void _ShowList(const whNvmCb* cb, void* context)
{
    int rc = 0;
    /* Dump NVM contents */
    uint16_t listCount = 0;
    uint16_t id = 0;
    do {
        listCount = 0;

        rc = cb->List(
                context,
                WOLFHSM_NVM_ACCESS_ANY,
                WOLFHSM_NVM_FLAGS_ANY,
                id,
                &listCount,
                &id);

        if ((rc == 0) && (listCount > 0)) {
            printf("Found object id 0x%X (%d) with %d more objects\n",
                    id, id, listCount - 1);
            whNvmMetadata myMetadata;
            memset(&myMetadata, 0, sizeof(myMetadata));
            rc = cb->GetMetadata(
                    context,
                    id,
                    &myMetadata);

            if (rc == 0) {

                uint8_t data[WOLFHSM_NVM_MAX_OBJECT_SIZE];
                memset(&data, 0, sizeof(data));

                printf("-Id:%04hX\n-Label:%.*s\n"
                        "-Access:%04hX\n-Flags:%04hX\n-Len:%d\n",
                        myMetadata.id,
                        (int)sizeof(myMetadata.label),
                        myMetadata.label,
                        myMetadata.access,
                        myMetadata.flags,
                        myMetadata.len);

                /* Read the data from this object */
                rc = cb->Read(
                        context,
                        id,
                        0,
                        myMetadata.len,
                        data);

                if (rc == 0) {
                    /* Show the data from this object */
                    _HexDump((const char*)data, (int)(myMetadata.len));
                }
            }
        } else break;
    } while (listCount > 0);
}

void wh_Nvm_UnitTest(void)
{
    int rc = 0;
    const whNvmCb cb[1] = {WH_NVM_FLASH_CB};
    whNvmFlashContext context[1]= {0};

    memset(context, 0, sizeof(*context));

    rc = cb->Init(
            context,
            &myNvmConfig);


    if (rc == 0) {
        printf("--Initial NVM contents\n");
        _ShowAvailable(cb, context);
        _ShowList(cb, context);

        /* Add 3 new Objects */
        unsigned char data1[]="Data1";
        unsigned char data2[]="Data2";
        unsigned char data3[]="Data3";
        unsigned char update1[]="Update1fdsafdasfdsafdsafdsafdsafdasfdasfd";
        unsigned char update2[]="Update2fdafdafdafdsafdsafdasfd";
        unsigned char update3[]="Update3fdsafdsafdafdafdafdafdafdafdafdsfadfdsfadsafdsafdasfdsa";
        whNvmId id1 = 100;
        whNvmId id2 = 400;
        whNvmId id3 = 300;

        whNvmId ids[] = {id1, id2, id3};

        whNvmMetadata meta1 = {.id = id1, .label = "Label1"};
        whNvmMetadata meta2 = {.id = id2, .label = "Label2"};
        whNvmMetadata meta3 = {.id = id3, .label = "Label3"};

        /* Add 3 objects */
        printf("--Adding 3 new objects\n");
        cb->AddObject(context, &meta1, sizeof(data1),data1);
        cb->AddObject(context, &meta2, sizeof(data2),data2);
        cb->AddObject(context, &meta3, sizeof(data3),data3);
        _ShowAvailable(cb, context);
        _ShowList(cb, context);

        /* Overwrite an existing Object */
        printf("--Overwrite an existing object\n");
        cb->AddObject(context, &meta1, sizeof(update1),update1);
        _ShowAvailable(cb, context);
        _ShowList(cb, context);

        /* Overwrite an existing Object twice */
        printf("--Overwrite an existing object again\n");
        cb->AddObject(context, &meta2, sizeof(update2),update2);
        cb->AddObject(context, &meta2, sizeof(update3),update3);
        _ShowAvailable(cb, context);
        _ShowList(cb, context);
        /* Regenerate */
        printf("--Reclaim space\n");
        cb->DestroyObjects(context, 0, NULL);
        _ShowAvailable(cb, context);
        _ShowList(cb, context);

        /* Destroy 3 objects */
        printf("--Destroy 3 objects\n");
        cb->DestroyObjects(context, sizeof(ids)/sizeof(ids[0]), ids);
        _ShowAvailable(cb, context);
        _ShowList(cb, context);

        printf("--Done\n");
        /* Clean up local data */
        rc = cb->Cleanup(context);

    } else {
        printf("Failed to initialize NVM\n");
    }
}

/* Transport memory configuration */
static uint8_t req[BUFFER_SIZE];
static uint8_t resp[BUFFER_SIZE];
whTransportMemConfig tmcf[1] = {{
        .req = (whTransportMemCsr*)req,
        .req_size = sizeof(req),
        .resp = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
}};

void wh_CommClientServer_Test(void)
{
    /* Client configuration/contexts */
    whTransportClientCb tccb[1] = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1] = {0};
    whCommClientConfig c_conf[1] = {{
            .transport_cb = tccb,
            .transport_context = (void*)tmcc,
            .transport_config = (void*)tmcf,
            .client_id = 1234,
    }};
    whCommClient client[1] = {0};

    /* Server configuration/contexts */
    whTransportServerCb tscb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1] = {0};
    whCommServerConfig s_conf[1] = {{
            .transport_cb = tscb,
            .transport_context = (void*)tmsc,
            .transport_config = (void*)tmcf,
            .server_id = 5678,
    }};
    whCommServer server[1] = {0};

    int ret = 0;
    ret = wh_CommClient_Init(client, c_conf);
    printf("CommClientInit:%d\n", ret);

    ret = wh_CommServer_Init(server, s_conf);
    printf("CommServerInit:%d\n", ret);

    int counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len = 0;
    uint16_t tx_req_flags = WH_COMM_MAGIC_NATIVE;
    uint16_t tx_req_type = 0;
    uint16_t tx_req_seq = 0;

    uint8_t  rx_req[REQ_SIZE] = {0};
    uint16_t rx_req_len = 0;
    uint16_t rx_req_flags = 0;
    uint16_t rx_req_type = 0;
    uint16_t rx_req_seq = 0;

    uint8_t  tx_resp[REQ_SIZE] = {0};
    uint16_t tx_resp_len = 0;

    uint8_t  rx_resp[REQ_SIZE] = {0};
    uint16_t rx_resp_len = 0;
    uint16_t rx_resp_flags = 0;
    uint16_t rx_resp_type = 0;
    uint16_t rx_resp_seq = 0;

    /* Check that neither side is ready to recv */
    ret = wh_CommServer_RecvRequest(server,
            &rx_req_flags, &rx_req_type, &rx_req_seq,
            &rx_req_len, rx_req);
    printf("Server initial RecvRequest:%d\n", ret);

    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        sprintf((char*)tx_req,"Request:%u",counter);
        tx_req_len = strlen((char*)tx_req);
        tx_req_type = counter*2;
        ret = wh_CommClient_SendRequest(client,
                tx_req_flags, tx_req_type, &tx_req_seq,
                tx_req_len, tx_req);
        printf("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len, tx_req);

        if (counter == 0) {
            ret = wh_CommClient_RecvResponse(client,
                    &rx_resp_flags, &rx_resp_type, &rx_resp_seq,
                    &rx_resp_len, rx_resp);
            printf("Client initial RecvResponse:%d\n", ret);
            ret = wh_CommClient_SendRequest(client,
                    tx_req_flags, tx_req_type, &tx_req_seq,
                    tx_req_len, tx_req);
            printf("Client duplicate SendRequest:%d\n",ret);
        }

        ret = wh_CommServer_RecvRequest(server,
                &rx_req_flags, &rx_req_type, &rx_req_seq,
                &rx_req_len, rx_req);
        printf("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                        ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len, rx_req);

        sprintf((char*)tx_resp,"Response:%s",rx_req);
        tx_resp_len = strlen((char*)tx_resp);
        ret = wh_CommServer_SendResponse(server,
                rx_req_flags, rx_req_type, rx_req_seq,
                tx_resp_len, tx_resp);
        printf("Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                        ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp);

        ret = wh_CommClient_RecvResponse(client,
                &rx_resp_flags, &rx_resp_type, &rx_resp_seq,
                &rx_resp_len, rx_resp);
        printf("Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                        ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len, rx_resp);

    }

    ret = wh_CommServer_Cleanup(server);
    printf("CommServerCleanup:%d\n", ret);

    ret = wh_CommClient_Cleanup(client);
    printf("CommClientCleanup:%d\n", ret);
}





static void* _whCommClientTask(void *cf)
{
    whCommClientConfig* config = (whCommClientConfig*)cf;
    int ret = 0;
    whCommClient client[1];
    int counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len = 0;
    uint16_t tx_req_flags = WH_COMM_MAGIC_NATIVE;
    uint16_t tx_req_type = 0;
    uint16_t tx_req_seq = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len = 0;
    uint16_t rx_resp_flags = 0;
    uint16_t rx_resp_type = 0;
    uint16_t rx_resp_seq = 0;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_CommClient_Init(client, config);
    printf("CommClientInit:%d\n", ret);

    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        sprintf((char*)tx_req,"Request:%u",counter);
        tx_req_len = strlen((char*)tx_req);
        tx_req_type = counter*2;
        do {
            ret = wh_CommClient_SendRequest(client,
                    tx_req_flags, tx_req_type, &tx_req_seq,
                    tx_req_len, tx_req);
            printf("Client SendRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                    ret, tx_req_flags, tx_req_type, tx_req_seq, tx_req_len, tx_req);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

        do {
        ret = wh_CommClient_RecvResponse(client,
                &rx_resp_flags, &rx_resp_type, &rx_resp_seq,
                &rx_resp_len, rx_resp);
        printf("Client RecvResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                        ret, rx_resp_flags, rx_resp_type, rx_resp_seq, rx_resp_len, rx_resp);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

    }

    ret = wh_CommClient_Cleanup(client);
    printf("CommClientCleanup:%d\n", ret);
    return NULL;
}

static void* _whCommServerTask(void* cf)
{
    whCommServerConfig* config = (whCommServerConfig*)cf;
    int ret = 0;
    whCommServer server[1];
    int counter = 1;

    ret = wh_CommServer_Init(server, config);
    printf("CommServerInit:%d\n", ret);

    uint8_t  rx_req[REQ_SIZE] = {0};
    uint16_t rx_req_len = 0;
    uint16_t rx_req_flags = 0;
    uint16_t rx_req_type = 0;
    uint16_t rx_req_seq = 0;

    uint8_t  tx_resp[RESP_SIZE] = {0};
    uint16_t tx_resp_len = 0;

    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        do {
            ret = wh_CommServer_RecvRequest(server,
                    &rx_req_flags, &rx_req_type, &rx_req_seq,
                    &rx_req_len, rx_req);
            printf("Server RecvRequest:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                            ret, rx_req_flags, rx_req_type, rx_req_seq, rx_req_len, rx_req);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        }

        do {
            sprintf((char*)tx_resp,"Response:%s",rx_req);
            tx_resp_len = strlen((char*)tx_resp);
            ret = wh_CommServer_SendResponse(server,
                    rx_req_flags, rx_req_type, rx_req_seq,
                    tx_resp_len, tx_resp);
            printf("Server SendResponse:%d, flags %x, type:%x, seq:%d, len:%d, %s\n",
                            ret, rx_req_flags, rx_req_type, rx_req_seq, tx_resp_len, tx_resp);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        }
    }

    ret = wh_CommServer_Cleanup(server);
    printf("CommServerCleanup:%d\n", ret);

    return NULL;
}

static void _whCommClientServerThreadTest( whCommClientConfig* c_conf,
                                    whCommServerConfig* s_conf)
{
    pthread_t cthread;
    pthread_t sthread;

    void* retval;
    int rc = 0;

    rc = pthread_create(&sthread, NULL, _whCommServerTask, s_conf);
    printf("Server thread create:%d\n", rc);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whCommClientTask, c_conf);
        printf("Client thread create:%d\n", rc);
        if (rc == 0) {
            /* All good. Block on joining */

            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        } else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);

        }
    }
}

void wh_CommClientServer_MemThreadTest(void)
{
    /* Client configuration/contexts */
    whTransportClientCb tmccb[1] = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext csc[1] = {};
    whCommClientConfig c_conf[1] = {{
            .transport_cb = tmccb,
            .transport_context = (void*)csc,
            .transport_config = (void*)tmcf,
            .client_id = 1234,
    }};

    /* Server configuration/contexts */
    whTransportServerCb tmscb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext css[1] = {};
    whCommServerConfig s_conf[1] = {{
            .transport_cb = tmscb,
            .transport_context = (void*)css,
            .transport_config = (void*)tmcf,
            .server_id = 5678,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}

posixTransportTcpConfig mytcpconfig[1] = {{
        .server_ip_string = "127.0.0.1",
        .server_port = 23456,
}};

void wh_CommClientServer_TcpThreadTest(void)
{
    /* Client configuration/contexts */
    whTransportClientCb pttccb[1] = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1] = {};
    whCommClientConfig c_conf[1] = {{
            .transport_cb = pttccb,
            .transport_context = (void*)tcc,
            .transport_config = (void*)mytcpconfig,
            .client_id = 1234,
    }};

    /* Server configuration/contexts */
    whTransportServerCb pttscb[1] = {PTT_SERVER_CB};

    posixTransportTcpServerContext tss[1] = {};
    whCommServerConfig s_conf[1] = {{
            .transport_cb = pttscb,
            .transport_context = (void*)tss,
            .transport_config = (void*)mytcpconfig,
            .server_id = 5678,
    }};

    _whCommClientServerThreadTest(c_conf, s_conf);
}

static void* _whClientTask(void *cf)
{
    whClientConfig* config = (whClientConfig*)cf;
    int ret = 0;
    whClient client[1];
    int counter = 1;

    uint8_t  tx_req[REQ_SIZE] = {0};
    uint16_t tx_req_len = 0;

    uint8_t  rx_resp[RESP_SIZE] = {0};
    uint16_t rx_resp_len = 0;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Client_Init(client, config);
    printf("wh_Client_Init:%d\n", ret);

    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        sprintf((char*)tx_req,"Request:%u",counter);
        tx_req_len = strlen((char*)tx_req);
        do {
            ret = wh_Client_EchoRequest(client,
                    tx_req_len, tx_req);
            printf("Client EchoRequest:%d, len:%d, %s\n",
                    ret, tx_req_len, tx_req);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }

        rx_resp_len = 0;
        memset(rx_resp, 0, sizeof(rx_resp));

        do {
            ret = wh_Client_EchoResponse(client,
                    &rx_resp_len, rx_resp);
            printf("Client EchoResponse:%d, len:%d, %s\n",
                    ret, rx_resp_len, rx_resp);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Client had failure. Exiting\n");
            break;
        }
    }

    ret = wh_Client_Cleanup(client);
    printf("wh_Client_Cleanup:%d\n", ret);
    return NULL;
}

static void* _whServerTask(void* cf)
{
    whServerConfig* config = (whServerConfig*)cf;
    int ret = 0;
    whServer server[1];
    int counter = 1;

    if (config == NULL) {
        return NULL;
    }

    ret = wh_Server_Init(server, config);
    printf("wh_Server_Init:%d\n", ret);

    for(counter = 0; counter < REPEAT_COUNT; counter++)
    {
        do {
            ret = wh_Server_HandleRequestMessage(server);
            printf("Server HandleRequestMessage:%d\n",ret);
        } while ((ret == WH_ERROR_NOTREADY) && (usleep(ONE_MS)==0));

        if (ret != 0) {
            printf("Server had failure. Exiting\n");
            break;
        } else {
            printf("Server processed message %d of %d\n", counter, REPEAT_COUNT);
        }
    }
    ret = wh_Server_Cleanup(server);
    printf("ServerCleanup:%d\n", ret);

    return NULL;
}

static void _whClientServerThreadTest(  whClientConfig* c_conf,
                                whServerConfig* s_conf)
{
    pthread_t cthread;
    pthread_t sthread;

    void* retval;
    int rc = 0;

    rc = pthread_create(&sthread, NULL, _whServerTask, s_conf);
    printf(" WH Server thread create:%d\n", rc);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, c_conf);
        printf("WH Client thread create:%d\n", rc);
        if (rc == 0) {
            /* All good. Block on joining */

            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        } else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);

        }
    }
}

void wh_ClientServer_TcpThreadTest(void)
{
    /* Client configuration/contexts */
    whTransportClientCb pttccb[1] = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1] = {};
    whCommClientConfig cc_conf[1] = {{
            .transport_cb = pttccb,
            .transport_context = (void*)tcc,
            .transport_config = (void*)mytcpconfig,
            .client_id = 1234,
    }};
    whClientConfig c_conf[1] = {{
            .comm = cc_conf,
            /*.nvm = NULL, */
    }};

    /* Server configuration/contexts */
    whTransportServerCb pttscb[1] = {PTT_SERVER_CB};
    posixTransportTcpServerContext tsc[1] = {};
    whCommServerConfig cs_conf[1] = {{
            .transport_cb = pttscb,
            .transport_context = (void*)tsc,
            .transport_config = (void*)mytcpconfig,
            .server_id = 5678,
    }};
    whServerConfig s_conf[1] = {{
            .comm = cs_conf,
            /*.nvm = NULL, */
    }};

    _whClientServerThreadTest(c_conf, s_conf);

}
int main(int argc, char** argv)
{
    (void)argc; (void)argv;

    wh_Nvm_UnitTest();
    wh_CommClientServer_Test();
    wh_CommClientServer_MemThreadTest();
    wh_CommClientServer_TcpThreadTest();
    wh_ClientServer_TcpThreadTest();
    return 0;
}



