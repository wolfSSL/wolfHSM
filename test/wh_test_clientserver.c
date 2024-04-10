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
#include "wolfhsm/wh_message.h"
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
#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */

/* Dummy callback that loopback-copies client data */
static int _customServerCb(whServerContext*                 server,
                           const whMessageCustomCb_Request* req,
                           whMessageCustomCb_Response*      resp)
{
    uint8_t* serverPtr = NULL;
    uint8_t* clientPtr = NULL;
    size_t   copySz    = 0;

    if (req->type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA64) {
        clientPtr = (uint8_t*)((uintptr_t)req->data.dma64.client_addr);
        serverPtr = (uint8_t*)((uintptr_t)req->data.dma64.server_addr);
        resp->data.dma64.client_sz = req->data.dma64.server_sz;
        copySz                     = req->data.dma64.server_sz;
    }
    else if (req->type == WH_MESSAGE_CUSTOM_CB_TYPE_DMA32) {
        clientPtr = (uint8_t*)((uintptr_t)req->data.dma32.client_addr);
        serverPtr = (uint8_t*)((uintptr_t)req->data.dma32.server_addr);
        resp->data.dma32.client_sz = req->data.dma32.server_sz;
        copySz                     = req->data.dma32.server_sz;
    }

    memcpy(clientPtr, serverPtr, copySz);

    return req->id;
}

/* Helper function to test client server callbacks. Client and server must be
 * already initialized */
static int _testCallbacks(whServerContext* server, whClientContext* client)
{
    size_t                     counter;
    whMessageCustomCb_Request  req     = {0};
    whMessageCustomCb_Response resp    = {0};
    uint16_t                   outId   = 0;
    int                        respErr = 0;

    const char input[] = "The answer to the ultimate question of life, the "
                         "universe and everything is 42";
    char       output[sizeof(input)] = {0};

    for (counter = 0; counter < WH_CUSTOM_CB_NUM_CALLBACKS; counter++) {
        req.id = counter;

        /* Check that the callback shows as unregistered */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CustomCheckRegisteredRequest(client, req.id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbCheckRegisteredResponse(
            client, &outId, &respErr));
        WH_TEST_ASSERT_RETURN(outId == req.id);
        WH_TEST_ASSERT_RETURN(respErr == WH_ERROR_NOHANDLER);

        /* Test that calling an unregistered callback returns error */
        WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbRequest(client, &req));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbResponse(client, &resp));
        WH_TEST_ASSERT_RETURN(resp.err == WH_ERROR_NOHANDLER);

        /* Register a custom callback */
        WH_TEST_RETURN_ON_FAIL(
            wh_Server_RegisterCustomCb(server, counter, _customServerCb));

        /* Check that the callback now shows as registered */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CustomCheckRegisteredRequest(client, req.id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbCheckRegisteredResponse(
            client, &outId, &respErr));
        WH_TEST_ASSERT_RETURN(outId == req.id);
        WH_TEST_ASSERT_RETURN(respErr == WH_ERROR_OK);

        /* prepare the rest of the request */
        if (sizeof(uintptr_t) == sizeof(uint64_t)) {
            /* 64-bit host system */
            req.type                   = WH_MESSAGE_CUSTOM_CB_TYPE_DMA64;
            req.data.dma64.server_addr = (uint64_t)((uintptr_t)input);
            req.data.dma64.server_sz   = sizeof(input);
            req.data.dma64.client_addr = (uint64_t)((uintptr_t)output);
            req.data.dma64.client_sz   = 0;
        }
        else if (sizeof(uintptr_t) == sizeof(uint32_t)) {
            /* 32-bit host system */
            req.type                   = WH_MESSAGE_CUSTOM_CB_TYPE_DMA32;
            req.data.dma32.server_addr = (uint32_t)((uintptr_t)&input);
            req.data.dma32.server_sz   = sizeof(input);
            req.data.dma32.client_addr = (uint32_t)((uintptr_t)output);
            req.data.dma32.client_sz   = 0;
        }

        WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbRequest(client, &req));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCbResponse(client, &resp));
        WH_TEST_ASSERT_RETURN(resp.err == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(resp.rc == counter);
        WH_TEST_ASSERT_RETURN(0 == memcmp(output, input, sizeof(input)));

        memset(output, 0, sizeof(output));
        memset(&req, 0, sizeof(req));
        memset(&resp, 0, sizeof(resp));
    }

    return WH_ERROR_OK;
}

static int _customServerDmaCb(struct whServerContext_t* server,
                              void* clientAddr, void** serverPtr,
                              uint32_t len, whDmaOper oper,
                              whDmaFlags flags)
{
    printf("**********CUSTOM DMA CALLBACK\n");

    return WH_ERROR_OK;
}


static int _customServerDma32Cb(struct whServerContext_t* server,
                                uint32_t clientAddr, void** serverPtr,
                                uint32_t len, whDmaOper oper, whDmaFlags flags)
{
    return _customServerDmaCb(server, (void*)((uintptr_t)clientAddr), serverPtr,
                              len, oper, flags);
}

static int _customServerDma64Cb(struct whServerContext_t* server,
                                uint64_t clientAddr, void** serverPtr,
                                uint64_t len, whDmaOper oper, whDmaFlags flags)
{
    return _customServerDmaCb(server, (void*)((uintptr_t)clientAddr), serverPtr,
                              len, oper, flags);
}

static int _testDma(whServerContext* server, whClientContext* client)
{
    typedef struct {
        uint32_t cliBuf[3];
        uint32_t srvBufAllow[3];
        uint32_t srvBufDeny[3];
        uint32_t srvBuf2Allow[3];
    } TestMemory;

    int rc = 0;

    TestMemory testMem = {0};

    /* Create a custom allow list */
    const whDmaAddrAllowList allowList = {
        .readList =
            {
                {&testMem.srvBufAllow, sizeof(testMem.srvBufAllow)},
                {&testMem.srvBuf2Allow, sizeof(testMem.srvBuf2Allow)},
            },
        .writeList =
            {
                {&testMem.srvBufAllow, sizeof(testMem.srvBufAllow)},
                {&testMem.srvBuf2Allow, sizeof(testMem.srvBuf2Allow)},
            },
    };

    /* Register a custom DMA callback */
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb(
        server, (whDmaCb){_customServerDma32Cb, _customServerDma64Cb}));

    /* Register our custom allow list */
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterAllowList(server, &allowList));

    /* Set known pattern in client Buffer */
    memset(testMem.cliBuf, 0xAA, sizeof(testMem.cliBuf));

    /* Perform a copy from "client mem" to allowed "server mem" */
    if (sizeof(void*) == sizeof(uint64_t)) {
        /* 64-bit host system */
        WH_TEST_RETURN_ON_FAIL(whServerDma_CopyFromClient64(
            server, testMem.srvBufAllow, (uint64_t)((uintptr_t)testMem.cliBuf),
            sizeof(testMem.cliBuf), (whDmaFlags){0}));
    }
    else if (sizeof(void*) == sizeof(uint32_t)) {
        /* 32-bit host system */
        WH_TEST_RETURN_ON_FAIL(whServerDma_CopyFromClient32(
            server, testMem.srvBufAllow, (uint32_t)((uintptr_t)testMem.cliBuf),
            sizeof(testMem.cliBuf), (whDmaFlags){0}));
    }

    /* Ensure data was copied */
    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.cliBuf, testMem.srvBufAllow,
                                      sizeof(testMem.cliBuf)));

    /* Clear client data */
    memset(testMem.cliBuf, 0, sizeof(testMem.cliBuf));

    /* Perform a copy from "server mem" to "client mem" */
    if (sizeof(void*) == sizeof(uint64_t)) {
        /* 64-bit host system */
        WH_TEST_RETURN_ON_FAIL(whServerDma_CopyToClient64(
            server, (uint64_t)((uintptr_t)testMem.cliBuf), testMem.srvBufAllow,
            sizeof(testMem.srvBufAllow), (whDmaFlags){0}));
    }
    else if (sizeof(void*) == sizeof(uint32_t)) {
        /* 32-bit host system */
        WH_TEST_RETURN_ON_FAIL(whServerDma_CopyToClient32(
            server, (uint32_t)((uintptr_t)testMem.cliBuf), testMem.srvBufAllow,
            sizeof(testMem.srvBufAllow), (whDmaFlags){0}));
    }

    /* Ensure data was copied */
    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.srvBufAllow, testMem.cliBuf,
                                      sizeof(testMem.srvBufAllow)));

    /* Now try and copy from the denylisted addresses */
    if (sizeof(void*) == sizeof(uint64_t)) {
        /* 64-bit host system */
        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              whServerDma_CopyFromClient64(
                                  server, testMem.srvBufDeny,
                                  (uint64_t)((uintptr_t)testMem.cliBuf),
                                  sizeof(testMem.cliBuf), (whDmaFlags){0}));
        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              whServerDma_CopyToClient64(
                                  server, (uint64_t)((uintptr_t)testMem.cliBuf),
                                  testMem.srvBufDeny,
                                  sizeof(testMem.srvBufDeny), (whDmaFlags){0}));
    }
    else if (sizeof(void*) == sizeof(uint32_t)) {
        /* 32-bit host system */
        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              whServerDma_CopyFromClient32(
                                  server, testMem.srvBufDeny,
                                  (uint32_t)((uintptr_t)testMem.cliBuf),
                                  sizeof(testMem.cliBuf), (whDmaFlags){0}));
        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              whServerDma_CopyToClient32(
                                  server, (uint32_t)((uintptr_t)testMem.cliBuf),
                                  testMem.srvBufDeny,
                                  sizeof(testMem.srvBufDeny), (whDmaFlags){0}));
    }

    return rc;
}

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
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
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
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 5678,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = 1024 * 1024, /* 1MB  Flash */
        .sectorSize = 128 * 1024,  /* 128KB  Sector Size */
        .pageSize   = 8,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};

    crypto_context crypto[1] = {{
        .devId = INVALID_DEVID,
    }};

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
         .crypto      = crypto,
    }};
    whServerContext server[1] = {0};

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    /* Init client and server */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));

    int      counter                  = 1;
    char     recv_buffer[WH_COMM_DATA_LEN] = {0};
    char     send_buffer[WH_COMM_DATA_LEN] = {0};
    uint16_t send_len                 = 0;
    uint16_t recv_len                 = 0;

    int32_t  server_rc       = 0;
    uint32_t client_id       = 0;
    uint32_t server_id       = 0;
    uint32_t avail_size      = 0;
    uint32_t reclaim_size    = 0;
    whNvmId  avail_objects   = 0;
    whNvmId  reclaim_objects = 0;

    /* Check that the server side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_Server_HandleRequestMessage(server));

    for (counter = 0; counter < REPEAT_COUNT; counter++) {

        /* Prepare echo test */
        send_len =
            snprintf(send_buffer, sizeof(send_buffer), "Request:%u", counter);
        snprintf(recv_buffer, sizeof(recv_buffer), "NOTHING RECEIVED");
        recv_len = 0;

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_EchoRequest(client, send_len, send_buffer));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client EchoRequest:%d, len:%d, %.*s\n", ret, send_len, send_len,
               send_buffer);
#endif

        if (counter == 0) {
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_NOTREADY ==
                wh_Client_EchoResponse(client, &recv_len, recv_buffer));
        }

        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Server HandleRequestMessage:%d\n", ret);
#endif

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_EchoResponse(client, &recv_len, recv_buffer));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client EchoResponse:%d, len:%d, %.*s, expected:%.*s\n", ret,
               recv_len, recv_len, recv_buffer, send_len, send_buffer);
#endif
        WH_TEST_ASSERT_RETURN(recv_len == send_len);
        WH_TEST_ASSERT_RETURN(strncmp(recv_buffer, send_buffer, recv_len) == 0);
    }

    /* Perform NVM tests */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmInitResponse(client, &server_rc, &client_id, &server_id));

#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmInitResponse:%d, server_rc:%d, clientid:%d serverid:%d\n",
           ret, server_rc, client_id, server_id);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailableResponse:%d, server_rc:%d avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, server_rc, avail_size, avail_objects, reclaim_size,
           reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == NF_OBJECT_COUNT);


    for (counter = 0; counter < 5; counter++) {
        whNvmId     id                           = counter + 20;
        whNvmAccess access                       = WOLFHSM_NVM_ACCESS_ANY;
        whNvmFlags  flags                        = WOLFHSM_NVM_FLAGS_ANY;
        whNvmSize   label_len                    = 0;
        char        label[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize   len                          = 0;

        whNvmId     gid                           = 0;
        whNvmAccess gaccess                       = 0;
        whNvmFlags  gflags                        = 0;
        char        glabel[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize   glen                          = 0;
        whNvmSize   rlen                          = 0;

        whNvmId lastAvailObjects = 0;

        label_len = snprintf(label, sizeof(label), "Label:%d", id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       id, counter);

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectRequest:%d, id:%u, access:0x%x, flags:0x%x, "
               "len:%u label:%s\nData:%s\n",
               ret, id, access, flags, len, label, send_buffer);
#endif

        lastAvailObjects = avail_objects;

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectRequest(
            client, id, access, flags, label_len, (uint8_t*)label, len,
            (uint8_t*)send_buffer));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmAddObjectResponse(client, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectResponse:%d, server_rc:%d\n", ret,
               server_rc);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
            client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
            &reclaim_objects));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, server_rc, avail_size, avail_objects, reclaim_size,
               reclaim_objects);
#endif

        /* Check that available objects decreased by one */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataRequest(client, id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
            client, &server_rc, &gid, &gaccess, &gflags, &glen, sizeof(glabel),
            (uint8_t*)glabel));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetMetadataResponse:%d, id:%u, access:0x%x, "
               "flags:0x%x, len:%u label:%s\n",
               ret, gid, gaccess, gflags, glen, glabel);
#endif

        /* Ensure metadata matches that of the object we just wrote */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(gid == id);

        memset(recv_buffer, 0, sizeof(recv_buffer));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadRequest(client, id, 0, glen));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadResponse(
            client, &server_rc, &rlen, (uint8_t*)recv_buffer));
#if defined(WH_CFG_TEST_VERBOSE)
        printf(
            "Client NvmReadResponse:%d, server_rc:%d id:%u, len:%u data:%s\n",
            ret, server_rc, gid, rlen, recv_buffer);
#endif

        /* Ensure data and size of response object matches that of the written
         * object */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(rlen == len);
        WH_TEST_ASSERT_RETURN(0 == memcmp(send_buffer, recv_buffer, len));
    }

    whNvmAccess list_access = WOLFHSM_NVM_ACCESS_ANY;
    whNvmFlags  list_flags  = WOLFHSM_NVM_FLAGS_ANY;
    whNvmId     list_id     = 0;
    whNvmId     list_count  = 0;
    do {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmListRequest(client, list_access, list_flags, list_id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmListResponse(
            client, &server_rc, &list_count, &list_id));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n", ret,
               server_rc, list_count, list_id);
#endif

        if (list_count > 0) {
            /* ensure list_id contains ID of object written, and list_count
             * shows remaining items in list */
            WH_TEST_ASSERT_RETURN(list_id == 20 + (5 - list_count));

            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmDestroyObjectsRequest(client, 1, &list_id));
            WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmDestroyObjectsResponse(client, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjectsResponse:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, server_rc, list_id, list_count);
#endif
            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetMetadataRequest(client, list_id));
            WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
            WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
                client, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n",
                   ret, server_rc, list_count, list_id);
#endif

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
    WH_TEST_ASSERT_RETURN(avail_objects == NF_OBJECT_COUNT);

    for (counter = 0; counter < 5; counter++) {
        whNvmMetadata meta = {
            .id     = counter + 40,
            .access = WOLFHSM_NVM_ACCESS_ANY,
            .flags  = WOLFHSM_NVM_FLAGS_ANY,
            .len    = 0,
            .label  = {0},
        };
        whNvmSize len = 0;

        whNvmId     gid                           = 0;
        whNvmAccess gaccess                       = 0;
        whNvmFlags  gflags                        = 0;
        char        glabel[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize   glen                          = 0;

        whNvmId lastAvailObjects = 0;

        snprintf((char*)(meta.label), sizeof(meta.label), "Label:%d", meta.id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       meta.id, counter);

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectDmaRequest:%d, id:%u, access:0x%x, "
               "flags:0x%x, len:%u label:%s\nData:%s\n",
               ret, meta.id, meta.access, meta.flags, len, meta.label,
               send_buffer);
#endif

        lastAvailObjects = avail_objects;

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectDmaRequest(
            client, &meta, len, (uint8_t*)send_buffer));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmAddObjectDmaResponse(client, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectDmaResponse:%d, server_rc:%d, meta.len:%u\n",
               ret, server_rc, meta.len);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
            client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
            &reclaim_objects));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, server_rc, avail_size, avail_objects, reclaim_size,
               reclaim_objects);
#endif
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmGetMetadataRequest(client, meta.id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
            client, &server_rc, &gid, &gaccess, &gflags, &glen, sizeof(glabel),
            (uint8_t*)glabel));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetMetadataResponse:%d, id:%u, access:0x%x, "
               "flags:0x%x, len:%u label:%s\n",
               ret, gid, gaccess, gflags, glen, glabel);
#endif

        /* Ensure metadata matches that of the object we just wrote */
        WH_TEST_ASSERT_RETURN(gid == meta.id);


        memset(recv_buffer, 0, sizeof(recv_buffer));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadDmaRequest(
            client, meta.id, 0, glen, (uint8_t*)recv_buffer));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmReadDmaResponse(client, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmReadDmaResponse:%d, server_rc:%d id:%u, len:%u "
               "data:%s\n",
               ret, server_rc, gid, glen, recv_buffer);
#endif

        /* Ensure data and size of response object matches that of the written
         * object */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(glen == len);
        WH_TEST_ASSERT_RETURN(0 == memcmp(send_buffer, recv_buffer, len));
    }

    do {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmListRequest(client, list_access, list_flags, list_id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmListResponse(
            client, &server_rc, &list_count, &list_id));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n", ret,
               server_rc, list_count, list_id);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        if (list_count > 0) {
            /* ensure list_id contains ID of object written, and list_count
             * shows remaining items in list */
            WH_TEST_ASSERT_RETURN(list_id == 40 + (5 - list_count));

            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmDestroyObjectsRequest(client, 1, &list_id));
            WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmDestroyObjectsResponse(client, &server_rc));
            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjectsResponse:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, server_rc, list_id, list_count);
#endif

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetMetadataRequest(client, list_id));
            WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
            WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
                client, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmCleanupRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmCleanupResponse(client, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmCleanupResponse:%d, server_rc:%d\n", ret, server_rc);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, server_rc, avail_size, avail_objects, reclaim_size,
           reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == NF_OBJECT_COUNT);

    /* Test custom registered callbacks */
    WH_TEST_RETURN_ON_FAIL(_testCallbacks(server, client));

    /* Test DMA callbacks and address allowlisting */
    WH_TEST_RETURN_ON_FAIL(_testDma(server, client));

    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return ret;
}

int whTest_ClientCfg(whClientConfig* clientCfg)
{
    int ret = 0;
    whClientContext client[1] = {0};

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, clientCfg));

    int counter = 1;
    char recv_buffer[WH_COMM_DATA_LEN] = {0};
    char send_buffer[WH_COMM_DATA_LEN] = {0};
    uint16_t send_len = 0;
    uint16_t recv_len = 0;

    int32_t server_rc = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;
    uint32_t avail_size = 0;
    uint32_t reclaim_size = 0;
    whNvmId avail_objects = 0;
    whNvmId reclaim_objects = 0;

    for (counter = 0; counter < REPEAT_COUNT; counter++) {

        /* Prepare echo test */
        send_len =
            snprintf(send_buffer, sizeof(send_buffer), "Request:%u", counter);
        snprintf(recv_buffer, sizeof(recv_buffer), "NOTHING RECEIVED");
        recv_len = 0;

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_Echo(client, send_len, send_buffer, &recv_len, recv_buffer));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client Echo:%d, len:%d, %.*s, expected:%.*s\n",
            ret, recv_len, recv_len, recv_buffer, send_len, send_buffer);
#endif
        WH_TEST_ASSERT_RETURN( recv_len == send_len);
        WH_TEST_ASSERT_RETURN( strncmp(recv_buffer, send_buffer, recv_len) == 0);
    }

    /* Perform NVM tests */

    WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmInit(client, &server_rc, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));

#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailable:%d, server_rc:%d avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, server_rc, avail_size, avail_objects, reclaim_size,
           reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == NF_OBJECT_COUNT);


    for (counter = 0; counter < 5; counter++) {
        whNvmId     id                           = counter + 20;
        whNvmAccess access                       = WOLFHSM_NVM_ACCESS_ANY;
        whNvmFlags  flags                        = WOLFHSM_NVM_FLAGS_ANY;
        whNvmSize   label_len                    = 0;
        char        label[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize   len                          = 0;

        whNvmId     gid                           = 0;
        whNvmAccess gaccess                       = 0;
        whNvmFlags  gflags                        = 0;
        char        glabel[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize   glen                          = 0;
        whNvmSize   rlen                          = 0;

        whNvmId lastAvailObjects = 0;

        label_len = snprintf(label, sizeof(label), "Label:%d", id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       id, counter);

        lastAvailObjects = avail_objects;

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmAddObject(
            client, id, access, flags, label_len, (uint8_t*)label, len,
            (uint8_t*)send_buffer, &server_rc));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObject:%d, server_rc:%d\n", ret,
               server_rc);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(
            client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
            &reclaim_objects));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, server_rc, avail_size, avail_objects, reclaim_size,
               reclaim_objects);
#endif

        /* Check that available objects decreased by one */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmGetMetadata(client, id, &server_rc, &gid,
                                           &gaccess, &gflags, &glen,
                                           sizeof(glabel), (uint8_t*)glabel));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetMetadata:%d, id:%u, access:0x%x, "
               "flags:0x%x, len:%u label:%s\n",
               ret, gid, gaccess, gflags, glen, glabel);
#endif

        /* Ensure metadata matches that of the object we just wrote */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(gid == id);

        memset(recv_buffer, 0, sizeof(recv_buffer));
        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmRead(client, id, 0, glen,
                                                       &server_rc, &rlen,
                                                       (uint8_t*)recv_buffer));

#if defined(WH_CFG_TEST_VERBOSE)
        printf(
            "Client NvmRead:%d, server_rc:%d id:%u, len:%u data:%s\n",
            ret, server_rc, gid, rlen, recv_buffer);
#endif

        /* Ensure data and size of response object matches that of the written
         * object */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(rlen == len);
        WH_TEST_ASSERT_RETURN(0 == memcmp(send_buffer, recv_buffer, len));
    }

    whNvmAccess list_access = WOLFHSM_NVM_ACCESS_ANY;
    whNvmFlags  list_flags  = WOLFHSM_NVM_FLAGS_ANY;
    whNvmId     list_id     = 0;
    whNvmId     list_count  = 0;
    do {
        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmList(client, list_access, list_flags, list_id,
                              &server_rc, &list_count, &list_id));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmList:%d, server_rc:%d count:%u id:%u\n", ret,
               server_rc, list_count, list_id);
#endif

        if (list_count > 0) {
            /* ensure list_id contains ID of object written, and list_count
             * shows remaining items in list */
            WH_TEST_ASSERT_RETURN(list_id == 20 + (5 - list_count));

            WH_TEST_RETURN_ON_FAIL(
                ret = wh_Client_NvmDestroyObjects(client, 1, &list_id, 0, NULL,
                                                  &server_rc));

#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjects:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, server_rc, list_id, list_count);
#endif
            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetMetadata(client, list_id, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmGetMetadata:%d, server_rc:%d count:%u id:%u\n",
                   ret, server_rc, list_count, list_id);
#endif

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_NUM_NVMOBJECTS);

    for (counter = 0; counter < 5; counter++) {
        whNvmMetadata meta = {
            .id     = counter + 40,
            .access = WOLFHSM_NVM_ACCESS_ANY,
            .flags  = WOLFHSM_NVM_FLAGS_ANY,
            .len    = 0,
            .label  = {0},
        };
        whNvmSize len = 0;

        whNvmId     gid                           = 0;
        whNvmAccess gaccess                       = 0;
        whNvmFlags  gflags                        = 0;
        char        glabel[WOLFHSM_NVM_LABEL_LEN] = {0};
        whNvmSize   glen                          = 0;

        whNvmId lastAvailObjects = 0;

        snprintf((char*)(meta.label), sizeof(meta.label), "Label:%d", meta.id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       meta.id, counter);

        lastAvailObjects = avail_objects;

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmAddObjectDma(client, &meta, len, (uint8_t*)send_buffer, &server_rc));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectDma:%d, server_rc:%d, meta.len:%u\n",
               ret, server_rc, meta.len);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(client, &server_rc, &avail_size, &avail_objects, &reclaim_size, &reclaim_objects));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, server_rc, avail_size, avail_objects, reclaim_size,
               reclaim_objects);
#endif
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetMetadata(client, meta.id, &server_rc, &gid, &gaccess, &gflags, &glen, sizeof(glabel), (uint8_t*)glabel));

#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmGetMetadata:%d, id:%u, access:0x%x, "
               "flags:0x%x, len:%u label:%s\n",
               ret, gid, gaccess, gflags, glen, glabel);
#endif

        /* Ensure metadata matches that of the object we just wrote */
        WH_TEST_ASSERT_RETURN(gid == meta.id);


        memset(recv_buffer, 0, sizeof(recv_buffer));
        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmReadDma(client, meta.id, 0, glen,
                                       (uint8_t*)recv_buffer, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmReadDma:%d, server_rc:%d id:%u, len:%u "
               "data:%s\n",
               ret, server_rc, gid, glen, recv_buffer);
#endif

        /* Ensure data and size of response object matches that of the written
         * object */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(glen == len);
        WH_TEST_ASSERT_RETURN(0 == memcmp(send_buffer, recv_buffer, len));
    }

    do {
        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmList(client, list_access, list_flags, list_id,
                                    &server_rc, &list_count, &list_id));
#if defined(WH_CFG_TEST_VERBOSE)
        printf("Client NvmList:%d, server_rc:%d count:%u id:%u\n", ret,
               server_rc, list_count, list_id);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        if (list_count > 0) {
            /* ensure list_id contains ID of object written, and list_count
             * shows remaining items in list */
            WH_TEST_ASSERT_RETURN(list_id == 40 + (5 - list_count));

            WH_TEST_RETURN_ON_FAIL(
                ret = wh_Client_NvmDestroyObjects(client, 1, &list_id, 0, NULL,
                                                  &server_rc));

            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

#if defined(WH_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjects:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, server_rc, list_id, list_count);
#endif

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetMetadata(client, list_id, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmCleanup(client, &server_rc));
#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmCleanup:%d, server_rc:%d\n", ret, server_rc);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
#if defined(WH_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, server_rc, avail_size, avail_objects, reclaim_size,
           reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == NF_OBJECT_COUNT);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return ret;
}


int whTest_ServerCfgLoop(whServerConfig* serverCfg)
{
    int ret = 0;

    whServerContext server[1] = {0};

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));

    /* Spin and process client requests, exiting on error */
    while (1) {
        ret = wh_Server_HandleRequestMessage(server);
        if (ret != 0 && ret != WH_ERROR_NOTREADY) {
            printf("[server] whServer_HandleRequestMessage ret=%d\n", ret);
            return ret;
        }
    }


    return 0;
}


#if defined(WH_CFG_TEST_POSIX)
static void* _whClientTask(void *cf)
{
    (void)whTest_ClientCfg(cf);
    return NULL;
}

static void* _whServerTask(void* cf)
{
    (void)whTest_ServerCfgLoop(cf);
    return NULL;
}


static void _whClientServerThreadTest(whClientConfig* c_conf,
                                whServerConfig* s_conf)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};

    void* retval;
    int rc = 0;

    rc = pthread_create(&sthread, NULL, _whServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, c_conf);
        if (rc == 0) {
            /* All good. Block on joining */

            pthread_join(cthread, &retval);
            pthread_cancel(sthread);
        } else {
            /* Cancel the server thread */
            pthread_cancel(sthread);

        }
    }
}

static int wh_ClientServer_MemThreadTest(void)
{
    uint8_t req[BUFFER_SIZE] = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

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
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE/2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
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
    whNvmContext nvm[1] = {{0}};

    /* Crypto context */
    crypto_context crypto[1] = {{
            .devId = INVALID_DEVID,
    }};

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
       .crypto = crypto,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));

    _whClientServerThreadTest(c_conf, s_conf);

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WH_CFG_TEST_POSIX */



int whTest_ClientServer(void)
{
    printf("Testing client/server sequential: mem...\n");
    WH_TEST_ASSERT(0 == whTest_ClientServerSequential());

#if defined(WH_CFG_TEST_POSIX)
    printf("Testing client/server: (pthread) mem...\n");
    WH_TEST_ASSERT(0 == wh_ClientServer_MemThreadTest());


#endif /* defined(WH_CFG_TEST_POSIX) */

    return 0;
}
