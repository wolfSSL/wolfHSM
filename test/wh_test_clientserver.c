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
#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wh_test_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_client.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include <unistd.h>  /* For sleep */

#include "port/posix/posix_transport_shm.h"
#endif


#define BUFFER_SIZE 4096
#define REQ_SIZE 32
#define RESP_SIZE 64
#define REPEAT_COUNT 10
#define ONE_MS 1000
#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */

#ifdef WOLFHSM_CFG_DMA
#define DMA_TEST_MEM_NWORDS 3

typedef struct {
    /* Simulated client memory region */
    uint32_t cliBuf[DMA_TEST_MEM_NWORDS];
    /* Simulated server address in the allow list */
    uint32_t srvBufAllow[DMA_TEST_MEM_NWORDS];
    /* Simulated server mem region not in the allow list */
    uint32_t srvBufDeny[DMA_TEST_MEM_NWORDS];
    /* Simulated "remapped" client address */
    uint32_t srvRemapBufAllow[DMA_TEST_MEM_NWORDS];
} TestMemory;

#define TEST_MEM_CLI_BYTE ((uint8_t)0xAA)
#define TEST_MEM_UNMAPPED_BYTE ((uint8_t)0xBB)
#endif /* WOLFHSM_CFG_DMA */

/* Pointer to a local server context so a connect callback can access it. Should
 * be set before calling wh_ClientInit() */
static whServerContext* clientServerSequentialTestServerCtx = NULL;

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

    for (counter = 0; counter < WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT; counter++) {
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

#ifdef WOLFHSM_CFG_DMA
static int _customServerDmaCb(struct whServerContext_t* server,
                              void* clientAddr, void** serverPtr, uint32_t len,
                              whServerDmaOper oper, whServerDmaFlags flags)
{
    /* remapped "client" address, a.k.a. arbitary "server" buffer */
    void* srvTmpBuf = (void*)((uintptr_t)clientAddr +
                              (offsetof(TestMemory, srvRemapBufAllow) -
                               offsetof(TestMemory, cliBuf)));

    /* This DMA callback simulates the remapping of client addresses by simply
     * copying the data between the client address and the "remapped" server
     * address, which is just an arbitrary server buffer */
    switch (oper) {
        case WH_DMA_OPER_CLIENT_READ_PRE:
            /* temp buffer to be used as copy source, so copy in data from
             * client */
            memcpy(srvTmpBuf, (void*)((uintptr_t)clientAddr), len);
            /* ensure subsequent copies use server temp buf as copy source */
            *serverPtr = srvTmpBuf;
            break;

        case WH_DMA_OPER_CLIENT_WRITE_PRE:
            /* subsequent writes use server temp buf as copy dest */
            *serverPtr = srvTmpBuf;
            break;

        case WH_DMA_OPER_CLIENT_READ_POST:
            /* simulate unmapping of the address by clearing the server temp
             * buffer */
            memset(srvTmpBuf, TEST_MEM_UNMAPPED_BYTE, len);
            break;

        case WH_DMA_OPER_CLIENT_WRITE_POST:
            /* temp buffer was just used as copy dest, so copy data out to
             * client address */
            memcpy(clientAddr, srvTmpBuf, len);
            break;
    }

    return WH_ERROR_OK;
}

#if WH_DMA_IS_32BIT
static int _customServerDma32Cb(struct whServerContext_t* server,
                                uint32_t clientAddr, void** serverPtr,
                                uint32_t len, whServerDmaOper oper,
                                whServerDmaFlags flags)
{
    return _customServerDmaCb(server, (void*)((uintptr_t)clientAddr), serverPtr,
                              len, oper, flags);
}
#endif /* WH_DMA_IS_32BIT */
#if WH_DMA_IS_64BIT
static int _customServerDma64Cb(struct whServerContext_t* server,
                                uint64_t clientAddr, void** serverPtr,
                                uint64_t len, whServerDmaOper oper,
                                whServerDmaFlags flags)
{
    return _customServerDmaCb(server, (void*)((uintptr_t)clientAddr), serverPtr,
                              len, oper, flags);
}
#endif /* WH_DMA_IS_64BIT */

static int _testDma(whServerContext* server, whClientContext* client)
{
    int        rc      = 0;
    TestMemory testMem = {0};

    const whServerDmaAddrAllowList allowList = {
        .readList =
            {
                {&testMem.srvBufAllow, sizeof(testMem.srvBufAllow)},
                {&testMem.srvRemapBufAllow, sizeof(testMem.srvRemapBufAllow)},
            },
        .writeList =
            {
                {&testMem.srvBufAllow, sizeof(testMem.srvBufAllow)},
                {&testMem.srvRemapBufAllow, sizeof(testMem.srvRemapBufAllow)},
            },
    };

    /* Register a custom DMA callback */
#if WH_DMA_IS_32BIT
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_DmaRegisterCb32(server, _customServerDma32Cb));
#else
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_DmaRegisterCb64(server, _customServerDma64Cb));
#endif

    /* Register our custom allow list */
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterAllowList(server, &allowList));

    /* Check allowed operations for addresses in the allowlist */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK == wh_Server_DmaCheckMemOperAllowed(
                           server, WH_DMA_OPER_CLIENT_READ_PRE,
                           testMem.srvBufAllow, sizeof(testMem.srvBufAllow)));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_DmaCheckMemOperAllowed(server, WH_DMA_OPER_CLIENT_READ_PRE,
                                         testMem.srvRemapBufAllow,
                                         sizeof(testMem.srvRemapBufAllow)));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK == wh_Server_DmaCheckMemOperAllowed(
                           server, WH_DMA_OPER_CLIENT_WRITE_PRE,
                           testMem.srvBufAllow, sizeof(testMem.srvBufAllow)));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_DmaCheckMemOperAllowed(server, WH_DMA_OPER_CLIENT_WRITE_PRE,
                                         testMem.srvRemapBufAllow,
                                         sizeof(testMem.srvRemapBufAllow)));

    /* Ensure an address not in the allowlist is denied for all operations */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_DmaCheckMemOperAllowed(
                              server, WH_DMA_OPER_CLIENT_READ_PRE,
                              testMem.srvBufDeny, sizeof(testMem.srvBufDeny)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_DmaCheckMemOperAllowed(
                              server, WH_DMA_OPER_CLIENT_WRITE_PRE,
                              testMem.srvBufDeny, sizeof(testMem.srvBufDeny)));

    /* Zero-sized operations should be denied */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_Server_DmaCheckMemOperAllowed(server, WH_DMA_OPER_CLIENT_READ_PRE,
                                         testMem.srvBufAllow, 0));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_Server_DmaCheckMemOperAllowed(server, WH_DMA_OPER_CLIENT_WRITE_PRE,
                                         testMem.srvBufAllow, 0));

    /* Set known pattern in client Buffer */
    memset(testMem.cliBuf, TEST_MEM_CLI_BYTE, sizeof(testMem.cliBuf));

    /* Perform a copy from "client mem" to allowed "server mem" */
    WH_TEST_RETURN_ON_FAIL(whServerDma_CopyFromClient(
        server, testMem.srvBufAllow, (uintptr_t)testMem.cliBuf,
        sizeof(testMem.cliBuf), (whServerDmaFlags){0}));

    /* Ensure data was copied */
    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.cliBuf, testMem.srvBufAllow,
                                      sizeof(testMem.cliBuf)));

    /* custom DMA callback uses the tmp server buffer for input data and
     * should set it to a known pattern on exit */
    uint8_t tmp[sizeof(testMem.srvRemapBufAllow)];
    memset(tmp, TEST_MEM_UNMAPPED_BYTE, sizeof(tmp));
    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.srvRemapBufAllow, tmp,
                                      sizeof(testMem.srvRemapBufAllow)));

    /* Clear client data */
    memset(testMem.cliBuf, 0, sizeof(testMem.cliBuf));
    memset(testMem.srvRemapBufAllow, 0, sizeof(testMem.srvRemapBufAllow));

    /* Perform a copy from "server mem" to "client mem" */
    WH_TEST_RETURN_ON_FAIL(whServerDma_CopyToClient(
        server, (uintptr_t)testMem.cliBuf, testMem.srvBufAllow,
        sizeof(testMem.srvBufAllow), (whServerDmaFlags){0}));

    /* Ensure data was copied */
    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.srvBufAllow, testMem.cliBuf,
                                      sizeof(testMem.srvBufAllow)));

    /* Now try and copy from the denylisted addresses */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          whServerDma_CopyFromClient(server, testMem.srvBufDeny,
                                                     (uintptr_t)testMem.cliBuf,
                                                     sizeof(testMem.cliBuf),
                                                     (whServerDmaFlags){0}));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        whServerDma_CopyToClient(server, (uintptr_t)testMem.cliBuf,
                                 testMem.srvBufDeny, sizeof(testMem.srvBufDeny),
                                 (whServerDmaFlags){0}));

    /* Check that zero-sized copies fail, even from allowed addresses */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == whServerDma_CopyFromClient(
                                                  server, testMem.srvBufAllow,
                                                  (uintptr_t)testMem.cliBuf, 0,
                                                  (whServerDmaFlags){0}));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          whServerDma_CopyToClient(
                              server, (uintptr_t)testMem.cliBuf,
                              testMem.srvBufAllow, 0, (whServerDmaFlags){0}));

    /* Finally, check that registering a NULL callbacks clears the DMA callback
     * table, and that the copies otherwise work as normal */
#if WH_DMA_IS_32BIT
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb32(server, NULL));
#else
    WH_TEST_RETURN_ON_FAIL(wh_Server_DmaRegisterCb64(server, NULL));
#endif

    /* Use remap buffer as copy src, since client address isn't in allowlist */
    memcpy(testMem.srvRemapBufAllow, testMem.cliBuf, sizeof(testMem.cliBuf));

    WH_TEST_RETURN_ON_FAIL(whServerDma_CopyFromClient(
        server, testMem.srvBufAllow, (uintptr_t)testMem.srvRemapBufAllow,
        sizeof(testMem.cliBuf), (whServerDmaFlags){0}));

    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.srvRemapBufAllow,
                                      testMem.srvBufAllow,
                                      sizeof(testMem.srvBufAllow)));
    memset(testMem.srvRemapBufAllow, 0, sizeof(testMem.srvRemapBufAllow));

    WH_TEST_RETURN_ON_FAIL(whServerDma_CopyToClient(
        server, (uintptr_t)testMem.srvRemapBufAllow, testMem.srvBufAllow,
        sizeof(testMem.srvRemapBufAllow), (whServerDmaFlags){0}));

    WH_TEST_ASSERT_RETURN(0 == memcmp(testMem.srvBufAllow,
                                      testMem.srvRemapBufAllow,
                                      sizeof(testMem.srvBufAllow)));

    return rc;
}
#endif /* WOLFHSM_CFG_DMA */

int _testClientCounter(whClientContext* client)
{
    const whNvmId  counterId              = 1;
    const uint32_t MAX_COUNTER_VAL        = 0xFFFFFFFF;
    const size_t   NUM_COUNTER_INCREMENTS = 2 * WOLFHSM_CFG_NVM_OBJECT_COUNT;
    size_t         i                      = 0;
    int            rc                     = 0;
    uint32_t       counter;
    int32_t        server_rc;
    uint32_t       avail_size;
    uint32_t       reclaim_size;
    whNvmId        avail_objects;
    whNvmId        reclaim_objects;

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Testing NVM counters...\n");
#endif

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterReset(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    /* Verify incrementation logic, ensuring we increment past the number of
     * available NVM objects ensuring we aren't leaking objects  */
    for (i = 0; i < NUM_COUNTER_INCREMENTS; i++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterIncrement(client, counterId, &counter));
        WH_TEST_ASSERT_RETURN(counter == i + 1);

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterRead(client, counterId, &counter));
        WH_TEST_ASSERT_RETURN(counter == i + 1);
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterReset(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);

    /* test saturation */
    counter = MAX_COUNTER_VAL;
    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterInit(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER_VAL);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterIncrement(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER_VAL);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CounterIncrement(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER_VAL);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterRead(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == MAX_COUNTER_VAL);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterReset(client, counterId, &counter));
    WH_TEST_ASSERT_RETURN(counter == 0);


    WH_TEST_RETURN_ON_FAIL(wh_Client_CounterDestroy(client, counterId));

    /* verify reset and destroy work and don't leak slots */
    for (i = 1; i < NUM_COUNTER_INCREMENTS; i++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CounterReset(client, (whNvmId)i, &counter));
        WH_TEST_ASSERT_RETURN(counter == 0);

        WH_TEST_RETURN_ON_FAIL(wh_Client_CounterDestroy(client, (whNvmId)i));

        /* ensure we fail to read destroyed counter*/
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_NOTFOUND ==
            wh_Client_CounterRead(client, (whNvmId)i, &counter));
    }

    /* Ensure NVM is empty */
    WH_TEST_RETURN_ON_FAIL(rc = wh_Client_NvmGetAvailable(
                               client, &server_rc, &avail_size, &avail_objects,
                               &reclaim_size, &reclaim_objects));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           rc, (int)server_rc, (int)avail_size, (int)avail_objects,
           (int)reclaim_size, (int)reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);

    return WH_ERROR_OK;
}

int _clientServerSequentialTestConnectCb(void* context, whCommConnected connected)
{
    if (clientServerSequentialTestServerCtx == NULL) {
        WH_ERROR_PRINT("Client connect callback server context is NULL\n");
        WH_TEST_ASSERT_RETURN(0);
    }

    /* Set server connect flag. In a "real" system, this should signal the
     * server via out-of-band mechanism. The server app is responsible for
     * receiving this signal and calling wh_Server_SetConnected() */
    return wh_Server_SetConnected(clientServerSequentialTestServerCtx,
                                  connected);
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
                 .client_id         = 123,
                 .connect_cb        = _clientServerSequentialTestConnectCb,
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
                 .server_id         = 124,
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
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};
#endif

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
         .crypto      = crypto,
#endif
    }};
    whServerContext server[1] = {0};

    whCommConnected server_connected = WH_COMM_DISCONNECTED;

    /* Expose the server context to our client connect callback */
    clientServerSequentialTestServerCtx = server;

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));
#endif
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    /* Server API should return NOTREADY until the server is connected */
    WH_TEST_RETURN_ON_FAIL(wh_Server_GetConnected(server, &server_connected));
    WH_TEST_ASSERT_RETURN(WH_COMM_DISCONNECTED == server_connected);
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_Server_HandleRequestMessage(server));


    /* Init client and server contexts. NOTE: in this test the server MUST be
    initialized before the client, as the client init function triggers the
    server "connect" via the connect callback, and this will be overwritten (set
    to zero) on server init */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Ensure server is now "connected" */
    WH_TEST_RETURN_ON_FAIL(wh_Server_GetConnected(server, &server_connected));
    WH_TEST_ASSERT_RETURN(WH_COMM_CONNECTED == server_connected);

    int      counter                  = 1;
    char     recv_buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    char     send_buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t send_len                 = 0;
    uint16_t recv_len                 = 0;

    int32_t  server_rc       = 0;
    uint32_t client_id       = 0;
    uint32_t server_id       = 0;
    uint32_t avail_size      = 0;
    uint32_t reclaim_size    = 0;
    whNvmId  avail_objects   = 0;
    whNvmId  reclaim_objects = 0;

    /* Ensure null terminated */
    uint8_t version[WH_INFO_VERSION_LEN + 1] = {0};
    uint8_t build[WH_INFO_VERSION_LEN + 1] = {0};
    uint32_t cfg_comm_data_len = 0;
    uint32_t cfg_nvm_object_count = 0;
    uint32_t cfg_server_keycache_count = 0;
    uint32_t cfg_server_keycache_bufsize = 0;
    uint32_t cfg_server_customcb_count = 0;
    uint32_t cfg_server_dmaaddr_count = 0;
    uint32_t debug_state = 0;
    uint32_t boot_state = 0;
    uint32_t lifecycle_state = 0;
    uint32_t nvm_state = 0;

    /* Check that the server side is ready to recv */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY ==
                          wh_Server_HandleRequestMessage(server));

    /* Send the comm init message so server can obtain client ID */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(client_id == client->comm->client_id);


    /* Send the comm info message */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInfoRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInfoResponse(client,
            version,
            build,
            &cfg_comm_data_len,
            &cfg_nvm_object_count,
            &cfg_server_keycache_count,
            &cfg_server_keycache_bufsize,
            &cfg_server_customcb_count,
            &cfg_server_dmaaddr_count,
            &debug_state,
            &boot_state,
            &lifecycle_state,
            &nvm_state));
    printf("Server Info: \n - Version:%s\n - Build:%s\n", version, build);
    printf(" - cfg_comm_data_len:%u\n", (unsigned int)cfg_comm_data_len);
    printf(" - cfg_nvm_object_count:%u\n", (unsigned int)cfg_nvm_object_count);
    printf(" - cfg_server_keycache_count:%u\n",
           (unsigned int)cfg_server_keycache_count);
    printf(" - cfg_server_keycache_bufsize:%u\n",
           (unsigned int)cfg_server_keycache_bufsize);
    printf(" - cfg_server_customcb_count:%u\n",
           (unsigned int)cfg_server_customcb_count);
    printf(" - cfg_server_dmaaddr_count:%u\n",
           (unsigned int)cfg_server_dmaaddr_count);
    printf(" - debug_state:%u\n", (unsigned int)debug_state);
    printf(" - boot_state:%u\n", (unsigned int)boot_state);
    printf(" - lifecycle_state:%u\n", (unsigned int)lifecycle_state);
    printf(" - nvm_state:%u\n", (unsigned int)nvm_state);

    for (counter = 0; counter < REPEAT_COUNT; counter++) {

        /* Prepare echo test */
        send_len =
            snprintf(send_buffer, sizeof(send_buffer), "Request:%u", counter);
        snprintf(recv_buffer, sizeof(recv_buffer), "NOTHING RECEIVED");
        recv_len = 0;

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_EchoRequest(client, send_len, send_buffer));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client EchoRequest:%d, len:%d, %.*s\n", ret, send_len, send_len,
               send_buffer);
#endif

        if (counter == 0) {
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_NOTREADY ==
                wh_Client_EchoResponse(client, &recv_len, recv_buffer));
        }

        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Server HandleRequestMessage:%d\n", ret);
#endif

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_EchoResponse(client, &recv_len, recv_buffer));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmInitResponse:%d, server_rc:%d, clientid:%d serverid:%d\n",
           ret, (int)server_rc, (int)client_id, (int)server_id);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailableResponse:%d, server_rc:%d avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
           (int)reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);


    for (counter = 0; counter < 5; counter++) {
        whNvmId     id                          = counter + 20;
        whNvmAccess access                      = WH_NVM_ACCESS_ANY;
        whNvmFlags  flags                       = WH_NVM_FLAGS_ANY;
        whNvmSize   label_len                   = 0;
        char        label[WH_NVM_LABEL_LEN]     = {0};
        whNvmSize   len                         = 0;

        whNvmId     gid                         = 0;
        whNvmAccess gaccess                     = 0;
        whNvmFlags  gflags                      = 0;
        char        glabel[WH_NVM_LABEL_LEN]    = {0};
        whNvmSize   glen                        = 0;
        whNvmSize   rlen                        = 0;

        whNvmId lastAvailObjects = 0;

        label_len = snprintf(label, sizeof(label), "Label:%d", id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       id, counter);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectResponse:%d, server_rc:%d\n", ret,
                (int)server_rc);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
            client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
            &reclaim_objects));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
               (int)reclaim_objects);
#endif

        /* Check that available objects decreased by one */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataRequest(client, id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
            client, &server_rc, &gid, &gaccess, &gflags, &glen, sizeof(glabel),
            (uint8_t*)glabel));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf(
            "Client NvmReadResponse:%d, server_rc:%d id:%u, len:%u data:%s\n",
            ret, (int)server_rc, (unsigned int)gid, (unsigned int)rlen, recv_buffer);
#endif

        /* Ensure data and size of response object matches that of the written
         * object */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(rlen == len);
        WH_TEST_ASSERT_RETURN(0 == memcmp(send_buffer, recv_buffer, len));
    }

    whNvmAccess list_access = WH_NVM_ACCESS_ANY;
    whNvmFlags  list_flags  = WH_NVM_FLAGS_ANY;
    whNvmId     list_id     = 0;
    whNvmId     list_count  = 0;
    do {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmListRequest(client, list_access, list_flags, list_id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmListResponse(
            client, &server_rc, &list_count, &list_id));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n", ret,
                (int)server_rc, (unsigned int)list_count, (unsigned int)list_id);
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjectsResponse:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, (int)server_rc, (unsigned int)list_id, (unsigned int)list_count);
#endif
            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(
                wh_Client_NvmGetMetadataRequest(client, list_id));
            WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
            WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
                client, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n",
                   ret, (int)server_rc, (unsigned int)list_count, (unsigned int)list_id);
#endif

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);

#ifdef WOLFHSM_CFG_DMA
    /* Same writeback test, but with DMA */
    for (counter = 0; counter < 5; counter++) {
        whNvmMetadata meta = {
            .id     = counter + 40,
            .access = WH_NVM_ACCESS_ANY,
            .flags  = WH_NVM_FLAGS_ANY,
            .len    = 0,
            .label  = {0},
        };
        whNvmSize len = 0;

        whNvmId     gid                         = 0;
        whNvmAccess gaccess                     = 0;
        whNvmFlags  gflags                      = 0;
        char        glabel[WH_NVM_LABEL_LEN]    = {0};
        whNvmSize   glen                        = 0;

        whNvmId lastAvailObjects = 0;

        snprintf((char*)(meta.label), sizeof(meta.label), "Label:%d", meta.id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       meta.id, counter);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectDmaResponse:%d, server_rc:%d, meta.len:%u\n",
               ret, (int)server_rc, (unsigned int)meta.len);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
            client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
            &reclaim_objects));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
               (int)reclaim_objects);
#endif
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmGetMetadataRequest(client, meta.id));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
            client, &server_rc, &gid, &gaccess, &gflags, &glen, sizeof(glabel),
            (uint8_t*)glabel));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmReadDmaResponse:%d, server_rc:%d id:%u, len:%u "
               "data:%s\n",
               ret, (int)server_rc, (unsigned int)gid, (unsigned int)glen, recv_buffer);
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmListResponse:%d, server_rc:%d count:%u id:%u\n", ret,
                (int)server_rc, (unsigned int)list_count, (unsigned int)list_id);
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

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjectsResponse:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, (int)server_rc, (unsigned int)list_id, (unsigned int)list_count);
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmCleanupResponse:%d, server_rc:%d\n", ret, (int)server_rc);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailableResponse(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailableResponse:%d, server_rc:%d, avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
           (int)reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);

#endif /* WOLFHSM_CFG_DMA */

    /* Test custom registered callbacks */
    WH_TEST_RETURN_ON_FAIL(_testCallbacks(server, client));

#ifdef WOLFHSM_CFG_DMA
    /* Test DMA callbacks and address allowlisting */
    WH_TEST_RETURN_ON_FAIL(_testDma(server, client));
#endif /* WOLFHSM_CFG_DMA */

    /* Check that we are still connected */
    WH_TEST_RETURN_ON_FAIL(wh_Server_GetConnected(server, &server_connected));
    WH_TEST_ASSERT_RETURN(server_connected == WH_COMM_CONNECTED);

    /* Disconnect the server */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseRequest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommCloseResponse(client));

    /* Ensure we show as disconnected */
    WH_TEST_RETURN_ON_FAIL(wh_Server_GetConnected(server, &server_connected));
    WH_TEST_ASSERT_RETURN(server_connected == WH_COMM_DISCONNECTED);

    /* Clean up the contexts */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    wh_Nvm_Cleanup(nvm);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return ret;
}

int whTest_ClientCfg(whClientConfig* clientCfg)
{
    int ret = 0;
    whClientContext client[1] = {0};

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, clientCfg));

    int counter = 1;
    char recv_buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    char send_buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t send_len = 0;
    uint16_t recv_len = 0;

    int32_t server_rc = 0;
    uint32_t client_id = 0;
    uint32_t server_id = 0;
    uint32_t avail_size = 0;
    uint32_t reclaim_size = 0;
    whNvmId avail_objects = 0;
    whNvmId reclaim_objects = 0;

    /* Init client/server comms */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(client_id == client->comm->client_id);


    for (counter = 0; counter < REPEAT_COUNT; counter++) {

        /* Prepare echo test */
        send_len =
            snprintf(send_buffer, sizeof(send_buffer), "Request:%u", counter);
        snprintf(recv_buffer, sizeof(recv_buffer), "NOTHING RECEIVED");
        recv_len = 0;

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_Echo(client, send_len, send_buffer, &recv_len, recv_buffer));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailable:%d, server_rc:%d avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
           (int)reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);


    for (counter = 0; counter < 5; counter++) {
        whNvmId     id                          = counter + 20;
        whNvmAccess access                      = WH_NVM_ACCESS_ANY;
        whNvmFlags  flags                       = WH_NVM_FLAGS_ANY;
        whNvmSize   label_len                   = 0;
        char        label[WH_NVM_LABEL_LEN]     = {0};
        whNvmSize   len                         = 0;

        whNvmId     gid                         = 0;
        whNvmAccess gaccess                     = 0;
        whNvmFlags  gflags                      = 0;
        char        glabel[WH_NVM_LABEL_LEN]    = {0};
        whNvmSize   glen                        = 0;
        whNvmSize   rlen                        = 0;

        whNvmId lastAvailObjects = 0;

        label_len = snprintf(label, sizeof(label), "Label:%d", id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       id, counter);

        lastAvailObjects = avail_objects;

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmAddObject(
            client, id, access, flags, label_len, (uint8_t*)label, len,
            (uint8_t*)send_buffer, &server_rc));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmAddObject:%d, server_rc:%d\n", ret,
               (int)server_rc);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(
            client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
            &reclaim_objects));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
               (int)reclaim_objects);
#endif

        /* Check that available objects decreased by one */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmGetMetadata(client, id, &server_rc, &gid,
                                           &gaccess, &gflags, &glen,
                                           sizeof(glabel), (uint8_t*)glabel));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
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

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf(
            "Client NvmRead:%d, server_rc:%d id:%u, len:%u data:%s\n",
            ret, (int)server_rc, (unsigned int)gid, (unsigned int)rlen, recv_buffer);
#endif

        /* Ensure data and size of response object matches that of the written
         * object */
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(rlen == len);
        WH_TEST_ASSERT_RETURN(0 == memcmp(send_buffer, recv_buffer, len));
    }

    whNvmAccess list_access = WH_NVM_ACCESS_ANY;
    whNvmFlags  list_flags  = WH_NVM_FLAGS_ANY;
    whNvmId     list_id     = 0;
    whNvmId     list_count  = 0;
    do {
        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmList(client, list_access, list_flags, list_id,
                              &server_rc, &list_count, &list_id));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmList:%d, server_rc:%d count:%u id:%u\n", ret,
                (int)server_rc, (unsigned int)list_count, (unsigned int)list_id);
#endif

        if (list_count > 0) {
            /* ensure list_id contains ID of object written, and list_count
             * shows remaining items in list */
            WH_TEST_ASSERT_RETURN(list_id == 20 + (5 - list_count));

            WH_TEST_RETURN_ON_FAIL(
                ret = wh_Client_NvmDestroyObjects(client, 1, &list_id, &server_rc));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjects:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, (int)server_rc, (unsigned int)list_id, (unsigned int)list_count);
#endif
            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetMetadata(client, list_id, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            printf("Client NvmGetMetadata:%d, server_rc:%d count:%u id:%u\n",
                   ret, (int)server_rc, (unsigned int)list_count, (unsigned int)list_id);
#endif

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);

#ifdef WOLFHSM_CFG_DMA
    /* Same writeback test, but with DMA */
    for (counter = 0; counter < 5; counter++) {
        whNvmMetadata meta = {
            .id     = counter + 40,
            .access = WH_NVM_ACCESS_ANY,
            .flags  = WH_NVM_FLAGS_ANY,
            .len    = 0,
            .label  = {0},
        };
        whNvmSize len = 0;

        whNvmId     gid                         = 0;
        whNvmAccess gaccess                     = 0;
        whNvmFlags  gflags                      = 0;
        char        glabel[WH_NVM_LABEL_LEN]    = {0};
        whNvmSize   glen                        = 0;

        whNvmId lastAvailObjects = 0;

        snprintf((char*)(meta.label), sizeof(meta.label), "Label:%d", meta.id);
        len = snprintf(send_buffer, sizeof(send_buffer), "Data:%d Counter:%d",
                       meta.id, counter);

        lastAvailObjects = avail_objects;

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmAddObjectDma(client, &meta, len, (uint8_t*)send_buffer, &server_rc));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmAddObjectDma:%d, server_rc:%d, meta.len:%u\n",
               ret, (int)server_rc, meta.len);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(client, &server_rc, &avail_size, &avail_objects, &reclaim_size, &reclaim_objects));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
               "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
               (int)reclaim_objects);
#endif
        WH_TEST_ASSERT_RETURN(lastAvailObjects - 1 == avail_objects);

        WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetMetadata(client, meta.id, &server_rc, &gid, &gaccess, &gflags, &glen, sizeof(glabel), (uint8_t*)glabel));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmGetMetadata:%d, id:%u, access:0x%x, "
               "flags:0x%x, len:%u label:%s\n",
               ret, (unsigned int)gid, (unsigned int)gaccess, (unsigned int)gflags, (unsigned int)glen, glabel);
#endif

        /* Ensure metadata matches that of the object we just wrote */
        WH_TEST_ASSERT_RETURN(gid == meta.id);


        memset(recv_buffer, 0, sizeof(recv_buffer));
        WH_TEST_RETURN_ON_FAIL(
            ret = wh_Client_NvmReadDma(client, meta.id, 0, glen,
                                       (uint8_t*)recv_buffer, &server_rc));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmReadDma:%d, server_rc:%d id:%u, len:%u "
               "data:%s\n",
               ret, (int)server_rc, (unsigned int)gid, (unsigned int)glen, recv_buffer);
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
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
        printf("Client NvmList:%d, server_rc:%d count:%u id:%u\n", ret,
               (int)server_rc, (unsigned int)list_count, (unsigned int)list_id);
#endif
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        if (list_count > 0) {
            /* ensure list_id contains ID of object written, and list_count
             * shows remaining items in list */
            WH_TEST_ASSERT_RETURN(list_id == 40 + (5 - list_count));

            WH_TEST_RETURN_ON_FAIL(
                ret = wh_Client_NvmDestroyObjects(client, 1, &list_id, &server_rc));

            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
            printf("Client NvmDestroyObjects:%d, server_rc:%d for "
                   "id:%u with count:%u\n",
                   ret, (int)server_rc, (unsigned int)list_id, (unsigned int)list_count);
#endif

            /* Ensure object was destroyed and no longer exists */
            WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetMetadata(client, list_id, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
            WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == server_rc);

            list_id = 0;
        }
    } while (list_count > 0);


    WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmCleanup(client, &server_rc));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmCleanup:%d, server_rc:%d\n", ret, (int)server_rc);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Ensure NVM tests didn't leak objects */
    WH_TEST_RETURN_ON_FAIL(ret = wh_Client_NvmGetAvailable(
        client, &server_rc, &avail_size, &avail_objects, &reclaim_size,
        &reclaim_objects));
#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("Client NvmGetAvailable:%d, server_rc:%d, avail_size:%d "
           "avail_objects:%d, reclaim_size:%d reclaim_objects:%d\n",
           ret, (int)server_rc, (int)avail_size, (int)avail_objects, (int)reclaim_size,
           (int)reclaim_objects);
#endif
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(avail_objects == WOLFHSM_CFG_NVM_OBJECT_COUNT);

#endif /* WOLFHSM_CFG_DMA */

    /* Test client counter API */
    WH_TEST_RETURN_ON_FAIL(_testClientCounter(client));

    WH_TEST_RETURN_ON_FAIL(wh_Client_CommClose(client));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return ret;
}


int whTest_ServerCfgLoop(whServerConfig* serverCfg)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));

    while(am_connected == WH_COMM_CONNECTED) {
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) &&
                (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("[server] Failed to wh_Server_HandleRequestMessage ret=%d\n", ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);
    }

    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)){
        ret = 0;
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    } else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}


#if defined(WOLFHSM_CFG_TEST_POSIX)
static void* _whClientTask(void *cf)
{
    WH_TEST_ASSERT(0 == whTest_ClientCfg(cf));
    return NULL;
}

static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_ServerCfgLoop(cf));
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
                 .client_id         = 123,
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
                 .server_id         = 124,
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

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
            .devId = INVALID_DEVID,
    }};
#endif

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
       .crypto = crypto,
#endif
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));
#endif
    _whClientServerThreadTest(c_conf, s_conf);

    wh_Nvm_Cleanup(nvm);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return WH_ERROR_OK;
}


static int wh_ClientServer_PosixMemMapThreadTest(void)
{
    posixTransportShmConfig tmcf[1] = {{
        .shmObjName = "/wh_test_clientserver_shm",
        .req_size   = BUFFER_SIZE,
        .resp_size  = BUFFER_SIZE,
    }};

    /* Client configuration/contexts */
    whTransportClientCb            tccb[1]    = {POSIX_TRANSPORT_SHM_CLIENT_CB};
    posixTransportShmClientContext tmcc[1]    = {0};
    whCommClientConfig             cc_conf[1] = {{
                    .transport_cb      = tccb,
                    .transport_context = (void*)tmcc,
                    .transport_config  = (void*)tmcf,
                    .client_id         = 123,
    }};
    whClientConfig                 c_conf[1]  = {{
                         .comm = cc_conf,
    }};
    /* Server configuration/contexts */
    whTransportServerCb            tscb[1]    = {POSIX_TRANSPORT_SHM_SERVER_CB};
    posixTransportShmServerContext tmsc[1]    = {0};
    whCommServerConfig             cs_conf[1] = {{
                    .transport_cb      = tscb,
                    .transport_context = (void*)tmsc,
                    .transport_config  = (void*)tmcf,
                    .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE / 2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
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

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
            .devId = INVALID_DEVID,
    }};
#endif

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
       .crypto = crypto,
#endif
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));
#endif
    _whClientServerThreadTest(c_conf, s_conf);

    wh_Nvm_Cleanup(nvm);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */



int whTest_ClientServer(void)
{
    printf("Testing client/server sequential: mem...\n");
    WH_TEST_ASSERT(0 == whTest_ClientServerSequential());

#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing client/server: (pthread) mem...\n");
    WH_TEST_ASSERT(0 == wh_ClientServer_MemThreadTest());

    printf("Testing client/server: (pthread) POSIX shared memory ...\n");
    WH_TEST_ASSERT(0 == wh_ClientServer_PosixMemMapThreadTest());
#endif /* defined(WOLFHSM_CFG_TEST_POSIX) */

    return 0;
}
