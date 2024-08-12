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
 * src/wh_server_nvm.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_nvm.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_nvm.h"

int wh_Server_HandleNvmRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;

    if (    (server == NULL) ||
            (req_packet == NULL) ||
            (resp_packet == NULL) ||
            (out_resp_size == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* III: Translate function returns do not need to be checked since args
     * are not NULL */

    switch (action) {

    case WH_MESSAGE_NVM_ACTION_INIT:
    {
        whMessageNvm_InitRequest req = {0};
        whMessageNvm_InitResponse resp = {0};

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Convert request struct */
            wh_MessageNvm_TranslateInitRequest(magic,
                    (whMessageNvm_InitRequest*)req_packet, &req);
            /* Process the init action */
            resp.clientnvm_id = req.clientnvm_id;
            resp.servernvm_id = server->comm->server_id;
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateInitResponse(magic,
                &resp, (whMessageNvm_InitResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_CLEANUP:
    {
        /* No request message */
        whMessageNvm_SimpleResponse resp = {0};

        if (req_size != 0) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Process the cleanup action */
            resp.rc = 0;
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_LIST:
    {
        whMessageNvm_ListRequest req = {0};
        whMessageNvm_ListResponse resp = {0};

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Convert request struct */
            wh_MessageNvm_TranslateListRequest(magic,
                    (whMessageNvm_ListRequest*)req_packet, &req);

            /* Process the list action */
            resp.rc = wh_Nvm_List(server->nvm,
                    req.access, req.flags, req.startId,
                    &resp.count, &resp.id);
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateListResponse(magic,
                &resp, (whMessageNvm_ListResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_GETAVAILABLE:
    {
        /* No Request packet */
        whMessageNvm_GetAvailableResponse resp = {0};

        if (req_size != 0) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Process the available action */
            resp.rc = wh_Nvm_GetAvailable(server->nvm,
                    &resp.avail_size, &resp.avail_objects,
                    &resp.reclaim_size, &resp.reclaim_objects);
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateGetAvailableResponse(magic,
                &resp, (whMessageNvm_GetAvailableResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_GETMETADATA:
    {
        whMessageNvm_GetMetadataRequest req = {0};
        whMessageNvm_GetMetadataResponse resp = {0};
        whNvmMetadata meta = {0};

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Convert request struct */
            wh_MessageNvm_TranslateGetMetadataRequest(magic,
                    (whMessageNvm_GetMetadataRequest*)req_packet, &req);

            /* Process the getmetadata action */
            resp.rc = wh_Nvm_GetMetadata(server->nvm, req.id, &meta);

            if (resp.rc == 0) {
                resp.id = meta.id;
                resp.access = meta.access;
                resp.flags = meta.flags;
                resp.len = meta.len;
                memcpy(resp.label, meta.label, sizeof(resp.label));
            }
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateGetMetadataResponse(magic,
                &resp, (whMessageNvm_GetMetadataResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_ADDOBJECT:
    {
        whMessageNvm_AddObjectRequest req = {0};
        uint16_t hdr_len = sizeof(req);
        whNvmMetadata meta = {0};
        const uint8_t* data = (const uint8_t*)req_packet + hdr_len;
        whMessageNvm_SimpleResponse resp = {0};

        if (req_size < sizeof(req)) {
            /* Problem in the request or transport. */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Convert request struct */
            wh_MessageNvm_TranslateAddObjectRequest(magic,
                    (whMessageNvm_AddObjectRequest*)req_packet, &req);
            if(req_size == (hdr_len + req.len)) {
                /* Process the AddObject action */
                meta.id = req.id;
                meta.access = req.access;
                meta.flags = req.flags;
                meta.len = req.len;
                memcpy(meta.label, req.label, sizeof(meta.label));
                resp.rc = wh_Nvm_AddObject(server->nvm, &meta, req.len, data);
            }
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
   }; break;

    case WH_MESSAGE_NVM_ACTION_DESTROYOBJECTS:
    {
        whMessageNvm_DestroyObjectsRequest req = {0};
        whMessageNvm_SimpleResponse resp = {0};

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Convert request struct */
            wh_MessageNvm_TranslateDestroyObjectsRequest(magic,
                    (whMessageNvm_DestroyObjectsRequest*)req_packet, &req);

            if (req.list_count <= WH_MESSAGE_NVM_MAX_DESTROY_OBJECTS_COUNT) {
                /* Process the DestroyObjects action */
                resp.rc = wh_Nvm_DestroyObjects(server->nvm,
                        req.list_count, req.list);
            } else {
                /* Problem in transport or request */
                resp.rc = WH_ERROR_ABORTED;
            }
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_READ:
    {
        whMessageNvm_ReadRequest req = {0};
        whMessageNvm_ReadResponse resp = {0};
        uint16_t hdr_len = sizeof(resp);
        uint8_t* data = (uint8_t*)resp_packet + hdr_len;
        uint16_t data_len = 0;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        } else {
            /* Convert request struct */
            wh_MessageNvm_TranslateReadRequest(magic,
                    (whMessageNvm_ReadRequest*)req_packet, &req);

            if (req.data_len > WH_MESSAGE_NVM_MAX_READ_LEN) {
                resp.rc = WH_ERROR_ABORTED;
            } else {
                /* Process the Read action */
                resp.rc = wh_Nvm_Read(server->nvm,
                    req.id, req.offset, req.data_len, data);
                if (resp.rc == 0) {
                    data_len = req.data_len;
                }
            }
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateReadResponse(magic,
                &resp, (whMessageNvm_ReadResponse*)resp_packet);
        *out_resp_size = sizeof(resp) + data_len;
    }; break;

    case WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA32:
    {
        whMessageNvm_AddObjectDma32Request req = {0};
        whMessageNvm_SimpleResponse resp = {0};
        void* metadata = NULL;
        void* data = NULL;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }

        if (resp.rc == 0) {
            /* Convert request struct */
            wh_MessageNvm_TranslateAddObjectDma32Request(magic,
                    (whMessageNvm_AddObjectDma32Request*)req_packet, &req);

            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress32(
                server, req.metadata_hostaddr, &metadata, sizeof(whNvmMetadata),
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            resp.rc = wh_Server_DmaProcessClientAddress32(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            /* Process the AddObject action */
            resp.rc = wh_Nvm_AddObject(server->nvm,
                    (whNvmMetadata*)metadata,
                    req.data_len,
                    (const uint8_t*)data);
        }
        if (resp.rc == 0) {
            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress32(
                server, req.metadata_hostaddr, &metadata, sizeof(whNvmMetadata),
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            resp.rc = wh_Server_DmaProcessClientAddress32(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_READDMA32:
    {
        whMessageNvm_ReadDma32Request req = {0};
        whMessageNvm_SimpleResponse resp = {0};
        void* data = NULL;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }
        if (resp.rc == 0) {
            /* Convert request struct */
            wh_MessageNvm_TranslateReadDma32Request(magic,
                    (whMessageNvm_ReadDma32Request*)req_packet, &req);

            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress32(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            /* Process the Read action */
            resp.rc = wh_Nvm_Read(server->nvm, req.id, req.offset, req.data_len,
                    (uint8_t*)data);
        }
        if (resp.rc == 0) {
            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress32(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA64:
    {
        whMessageNvm_AddObjectDma64Request req = {0};
        whMessageNvm_SimpleResponse resp = {0};
        void* metadata = NULL;
        void* data = NULL;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }
        if (resp.rc == 0) {
            /* Convert request struct */
            wh_MessageNvm_TranslateAddObjectDma64Request(magic,
                    (whMessageNvm_AddObjectDma64Request*)req_packet, &req);

            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress64(
                server, req.metadata_hostaddr, &metadata, sizeof(whNvmMetadata),
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            resp.rc = wh_Server_DmaProcessClientAddress64(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            /* Process the AddObject action */
            resp.rc = wh_Nvm_AddObject(server->nvm,
                    (whNvmMetadata*)metadata,
                    req.data_len,
                    (const uint8_t*)data);
        }
        if (resp.rc == 0) {
            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress64(
                server, req.metadata_hostaddr, &metadata, sizeof(whNvmMetadata),
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            resp.rc = wh_Server_DmaProcessClientAddress64(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_READDMA64:
    {
        whMessageNvm_ReadDma64Request req = {0};
        whMessageNvm_SimpleResponse resp = {0};
        void* data = NULL;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }
        if (resp.rc == 0) {
            /* Convert request struct */
            wh_MessageNvm_TranslateReadDma64Request(magic,
                    (whMessageNvm_ReadDma64Request*)req_packet, &req);

            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress64(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        }
        if (resp.rc == 0) {
            /* Process the Read action */
            resp.rc = wh_Nvm_Read(server->nvm, req.id, req.offset, req.data_len,
                    (uint8_t*)data);
        }
        if (resp.rc == 0) {
            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress64(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    default:
        /* Unknown request. Respond with empty packet */
        /* TODO: Use ErrorResponse packet instead */
        *out_resp_size = 0;
    }
    return rc;
}

