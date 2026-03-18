/*
 * Copyright (C) 2025 wolfSSL Inc.
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

#include <stdlib.h>
#include <string.h>

#include <wolfhsm/wh_nvm.h>
#include <wolfhsm/wh_nvm_flash.h>
#include <wolfhsm/wh_nvm_flash_log.h>
#include <wolfhsm/wh_flash_ramsim.h>
#include <wolfhsm/wh_transport_mem.h>
#include <wolfhsm/wh_error.h>

#include "wh_test_common.h"


/* Opaque struct for client+server memory transport setup */
struct whTest_ClientServerMemSetup {
    uint8_t*                    req;
    uint8_t*                    resp;
    int                         bufferSize;
    whTransportMemConfig        transportMemCfg;
    whTransportClientCb         transportClientCb;
    whTransportMemClientContext transportMemClientCtx;
    whCommClientConfig          commClientCfg;
    whTransportServerCb         transportServerCb;
    whTransportMemServerContext transportMemServerCtx;
    whCommServerConfig          commServerCfg;
};

/* Opaque struct for NVM setup */
struct whTest_NvmSetup {
    uint8_t*              memory;
    int                   flashRamSize;
    whFlashRamsimCtx      flashRamsimCtx;
    whFlashRamsimCfg      flashRamsimCfg;
    whFlashCb             flashCb;
    whTestNvmBackendUnion nvmBackendUnion;
    whNvmConfig           nvmConfig;
    whNvmContext          nvmContext;
};


/**
 * Helper function to configure and select an NVM backend for testing.
 *
 * @param type      The type of NVM backend to configure (see
 * NvmTestBackendType).
 * @param nvmSetup  Pointer to a union of NVM backend setup structures (output).
 * @param nvmCfg    Pointer to the NVM configuration structure to populate
 * (output).
 * @param fCfg      Pointer to the RamSim flash configuration structure.
 * @param fCtx      Pointer to the RamSim flash context structure.
 * @param fCb       Pointer to the RamSim flash callback structure.
 *
 * @return WH_ERROR_OK on success, or WH_ERROR_BADARGS on failure.
 */
int whTest_NvmCfgBackend(whTestNvmBackendType   type,
                         whTestNvmBackendUnion* nvmSetup, whNvmConfig* nvmCfg,
                         whFlashRamsimCfg* fCfg, whFlashRamsimCtx* fCtx,
                         const whFlashCb* fCb)
{

    WH_TEST_ASSERT(nvmSetup != NULL);
    WH_TEST_ASSERT(nvmCfg != NULL);
    WH_TEST_ASSERT(fCfg != NULL);

    switch (type) {
#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
        case WH_NVM_TEST_BACKEND_FLASH_LOG:
            nvmSetup->nvmFlashLogCfg.flash_cb = fCb;
            /* restrict simulated flash partition to nvm_flash_log_partition */
            WH_TEST_ASSERT(fCfg->size >= WH_NVM_FLASH_LOG_PARTITION_SIZE * 2);
            fCfg->sectorSize = WH_NVM_FLASH_LOG_PARTITION_SIZE;
            nvmSetup->nvmFlashLogCfg.flash_cfg = fCfg;
            nvmSetup->nvmFlashLogCfg.flash_ctx = fCtx;
            memset(&nvmSetup->nvmFlashLogCtx, 0,
                   sizeof(nvmSetup->nvmFlashLogCtx));
            static whNvmCb nflcb[1] = {WH_NVM_FLASH_LOG_CB};

            nvmCfg->cb      = nflcb;
            nvmCfg->context = &nvmSetup->nvmFlashLogCtx;
            nvmCfg->config  = &nvmSetup->nvmFlashLogCfg;
            break;
#endif
        case WH_NVM_TEST_BACKEND_FLASH:
            /* NVM Flash Configuration using RamSim HAL Flash */
            nvmSetup->nvmFlashCfg.cb      = fCb;
            nvmSetup->nvmFlashCfg.context = fCtx;
            nvmSetup->nvmFlashCfg.config  = fCfg;

            memset(&nvmSetup->nvmFlashCtx, 0, sizeof(nvmSetup->nvmFlashCtx));
            static whNvmCb nfcb[1] = {WH_NVM_FLASH_CB};

            nvmCfg->cb      = nfcb;
            nvmCfg->context = &nvmSetup->nvmFlashCtx;
            nvmCfg->config  = &nvmSetup->nvmFlashCfg;
            break;

        default:
            return WH_ERROR_BADARGS;
    }

    return 0;
}


/*
 * Helper to wire (or re-wire) the transport mem config from the current
 * buffer pointers and size stored in the setup struct.
 */
static void _csMemSetup_WireTransportCfg(whTest_ClientServerMemSetup* setup)
{
    memset(&setup->transportMemCfg, 0, sizeof(setup->transportMemCfg));
    setup->transportMemCfg.req       = (whTransportMemCsr*)setup->req;
    setup->transportMemCfg.req_size  = setup->bufferSize;
    setup->transportMemCfg.resp      = (whTransportMemCsr*)setup->resp;
    setup->transportMemCfg.resp_size = setup->bufferSize;
}

int whTest_ClientServerMemSetup_Init(
    whTest_ClientServerMemSetup** outSetup,
    int                           clientId,
    int                           serverId,
    whCommSetConnectedCb          connectCb,
    whCommClientConfig**          outCommClientCfg,
    whCommServerConfig**          outCommServerCfg)
{
    whTest_ClientServerMemSetup* setup;

    if (outSetup == NULL || outCommClientCfg == NULL ||
        outCommServerCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    setup = malloc(sizeof(*setup));
    if (setup == NULL) {
        return WH_ERROR_ABORTED;
    }
    memset(setup, 0, sizeof(*setup));

    /* Allocate default-sized buffers */
    setup->bufferSize = WH_TEST_BUFFER_SIZE;
    setup->req = malloc(setup->bufferSize);
    setup->resp = malloc(setup->bufferSize);
    if (setup->req == NULL || setup->resp == NULL) {
        free(setup->req);
        free(setup->resp);
        free(setup);
        return WH_ERROR_ABORTED;
    }
    memset(setup->req, 0, setup->bufferSize);
    memset(setup->resp, 0, setup->bufferSize);

    /* Wire transport memory config */
    _csMemSetup_WireTransportCfg(setup);

    /* Client transport */
    whTransportClientCb clientCb = WH_TRANSPORT_MEM_CLIENT_CB;
    setup->transportClientCb = clientCb;
    memset(&setup->transportMemClientCtx, 0,
           sizeof(setup->transportMemClientCtx));

    /* Client comm config */
    memset(&setup->commClientCfg, 0, sizeof(setup->commClientCfg));
    setup->commClientCfg.transport_cb      = &setup->transportClientCb;
    setup->commClientCfg.transport_context = (void*)&setup->transportMemClientCtx;
    setup->commClientCfg.transport_config  = (void*)&setup->transportMemCfg;
    setup->commClientCfg.client_id         = clientId;
    setup->commClientCfg.connect_cb        = connectCb;

    /* Server transport */
    whTransportServerCb serverCb = WH_TRANSPORT_MEM_SERVER_CB;
    setup->transportServerCb = serverCb;
    memset(&setup->transportMemServerCtx, 0,
           sizeof(setup->transportMemServerCtx));

    /* Server comm config */
    memset(&setup->commServerCfg, 0, sizeof(setup->commServerCfg));
    setup->commServerCfg.transport_cb      = &setup->transportServerCb;
    setup->commServerCfg.transport_context = (void*)&setup->transportMemServerCtx;
    setup->commServerCfg.transport_config  = (void*)&setup->transportMemCfg;
    setup->commServerCfg.server_id         = serverId;

    *outSetup         = setup;
    *outCommClientCfg = &setup->commClientCfg;
    *outCommServerCfg = &setup->commServerCfg;

    return WH_ERROR_OK;
}

int whTest_ClientServerMemSetup_ResizeBuffers(
    whTest_ClientServerMemSetup* setup,
    int                          newBufferSize)
{
    uint8_t* newReq;
    uint8_t* newResp;

    if (setup == NULL || newBufferSize <= 0) {
        return WH_ERROR_BADARGS;
    }

    newReq = malloc(newBufferSize);
    newResp = malloc(newBufferSize);
    if (newReq == NULL || newResp == NULL) {
        free(newReq);
        free(newResp);
        return WH_ERROR_ABORTED;
    }
    memset(newReq, 0, newBufferSize);
    memset(newResp, 0, newBufferSize);

    /* Free old buffers and install new ones */
    free(setup->req);
    free(setup->resp);
    setup->req        = newReq;
    setup->resp       = newResp;
    setup->bufferSize = newBufferSize;

    /* Re-wire the transport config to point at the new buffers */
    _csMemSetup_WireTransportCfg(setup);

    return WH_ERROR_OK;
}

int whTest_ClientServerMemSetup_Cleanup(
    whTest_ClientServerMemSetup* setup)
{
    if (setup == NULL) {
        return WH_ERROR_BADARGS;
    }

    free(setup->req);
    free(setup->resp);
    free(setup);

    return WH_ERROR_OK;
}


int whTest_NvmSetup_Init(
    whTest_NvmSetup**    outSetup,
    whTestNvmBackendType nvmType,
    whNvmContext**       outNvmContext)
{
    whTest_NvmSetup* setup;
    int              rc;

    if (outSetup == NULL || outNvmContext == NULL) {
        return WH_ERROR_BADARGS;
    }

    setup = malloc(sizeof(*setup));
    if (setup == NULL) {
        return WH_ERROR_ABORTED;
    }
    memset(setup, 0, sizeof(*setup));

    /* Allocate default flash memory */
    setup->flashRamSize = WH_TEST_FLASH_RAM_SIZE;
    setup->memory = malloc(setup->flashRamSize);
    if (setup->memory == NULL) {
        free(setup);
        return WH_ERROR_ABORTED;
    }
    memset(setup->memory, 0, setup->flashRamSize);

    /* Configure flash ramsim */
    setup->flashRamsimCfg.size       = setup->flashRamSize;
    setup->flashRamsimCfg.sectorSize = WH_TEST_FLASH_SECTOR_SIZE;
    setup->flashRamsimCfg.pageSize   = WH_TEST_FLASH_PAGE_SIZE;
    setup->flashRamsimCfg.erasedByte = ~(uint8_t)0;
    setup->flashRamsimCfg.memory     = setup->memory;

    {
        whFlashCb cb = WH_FLASH_RAMSIM_CB;
        setup->flashCb = cb;
    }

    /* Configure NVM backend */
    memset(&setup->nvmConfig, 0, sizeof(setup->nvmConfig));
    rc = whTest_NvmCfgBackend(nvmType, &setup->nvmBackendUnion,
                              &setup->nvmConfig, &setup->flashRamsimCfg,
                              &setup->flashRamsimCtx, &setup->flashCb);
    if (rc != 0) {
        free(setup->memory);
        free(setup);
        return rc;
    }

    /* Init NVM */
    rc = wh_Nvm_Init(&setup->nvmContext, &setup->nvmConfig);
    if (rc != 0) {
        free(setup->memory);
        free(setup);
        return rc;
    }

    *outSetup      = setup;
    *outNvmContext  = &setup->nvmContext;

    return WH_ERROR_OK;
}

int whTest_NvmSetup_ResizeFlash(
    whTest_NvmSetup* setup,
    int              flashRamSize,
    int              flashSectorSize,
    int              flashPageSize)
{
    uint8_t* newMemory;
    int      rc;

    if (setup == NULL || flashRamSize <= 0 || flashSectorSize <= 0 ||
        flashPageSize <= 0) {
        return WH_ERROR_BADARGS;
    }

    /* Cleanup existing NVM state */
    wh_Nvm_Cleanup(&setup->nvmContext);

    /* Reallocate flash memory */
    newMemory = malloc(flashRamSize);
    if (newMemory == NULL) {
        return WH_ERROR_ABORTED;
    }
    memset(newMemory, 0, flashRamSize);

    free(setup->memory);
    setup->memory       = newMemory;
    setup->flashRamSize = flashRamSize;

    /* Reconfigure flash ramsim */
    setup->flashRamsimCfg.size       = flashRamSize;
    setup->flashRamsimCfg.sectorSize = flashSectorSize;
    setup->flashRamsimCfg.pageSize   = flashPageSize;
    setup->flashRamsimCfg.memory     = setup->memory;

    /* Re-init NVM */
    rc = wh_Nvm_Init(&setup->nvmContext, &setup->nvmConfig);
    if (rc != 0) {
        return rc;
    }

    return WH_ERROR_OK;
}

int whTest_NvmSetup_Cleanup(
    whTest_NvmSetup* setup)
{
    if (setup == NULL) {
        return WH_ERROR_BADARGS;
    }

    wh_Nvm_Cleanup(&setup->nvmContext);
    free(setup->memory);
    free(setup);

    return WH_ERROR_OK;
}
