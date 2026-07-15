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
 * src/wh_client_nvm.c
 */

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"

#include "wolfhsm/wh_client.h"

/** NVM Init */
int wh_Client_NvmInitRequest(whClientContext* c)
{
    whMessageNvm_InitRequest msg = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    msg.clientnvm_id = c->comm->client_id;

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_INIT,
            sizeof(msg), &msg);
}

int wh_Client_NvmInitResponse(whClientContext* c, int32_t *out_rc,
        uint32_t *out_clientnvm_id, uint32_t *out_servernvm_id)
{
    whMessageNvm_InitResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_INIT) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
            if (out_clientnvm_id != NULL) {
                *out_clientnvm_id = msg.clientnvm_id;
            }
            if (out_servernvm_id != NULL) {
                *out_servernvm_id = msg.servernvm_id;
            }
        }
    }
    return rc;
}

int wh_Client_NvmInit(whClientContext* c, int32_t *out_rc,
        uint32_t *out_clientnvm_id, uint32_t *out_servernvm_id)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmInitRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_NvmInitResponse(c, out_rc,
                    out_clientnvm_id, out_servernvm_id);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM Cleanup */
int wh_Client_NvmCleanupRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_CLEANUP,
            0, NULL);
}

int wh_Client_NvmCleanupResponse(whClientContext* c, int32_t *out_rc)
{
    whMessageNvm_SimpleResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_CLEANUP) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
        }
    }
    return rc;
}

int wh_Client_NvmCleanup(whClientContext* c, int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmCleanupRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_NvmCleanupResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM GetAvailable */
int wh_Client_NvmGetAvailableRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_GETAVAILABLE,
            0, NULL);
}

int wh_Client_NvmGetAvailableResponse(whClientContext* c, int32_t *out_rc,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects)
{
    whMessageNvm_GetAvailableResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_GETAVAILABLE) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
            if (out_avail_size != NULL) {
                *out_avail_size = msg.avail_size;
            }
            if (out_reclaim_size != NULL) {
                *out_reclaim_size = msg.reclaim_size;
            }
            if (out_avail_objects != NULL) {
                *out_avail_objects = msg.avail_objects;
            }
            if (out_reclaim_objects != NULL) {
                *out_reclaim_objects = msg.reclaim_objects;
            }
        }
    }
    return rc;
}

int wh_Client_NvmGetAvailable(whClientContext* c, int32_t *out_rc,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmGetAvailableRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_NvmGetAvailableResponse(c, out_rc,
                    out_avail_size, out_avail_objects,
                    out_reclaim_size, out_reclaim_objects);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM AddObject */
int wh_Client_NvmAddObjectRequest(whClientContext* c,
        whNvmId id, whNvmAccess access, whNvmFlags flags,
        whNvmSize label_len, uint8_t* label,
        whNvmSize len, const uint8_t* data)
{
    /*TODO: Add scatter/gather into CommClient to avoid construction here */
    uint8_t buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageNvm_AddObjectRequest* msg = (whMessageNvm_AddObjectRequest*)buffer;
    uint16_t hdr_len = sizeof(*msg);
    uint8_t* payload = (uint8_t*)buffer + hdr_len;

    if (    (c == NULL) ||
            ((label == NULL) && (label_len > 0)) ||
            (label_len > WH_NVM_LABEL_LEN) ||
            ((data == NULL) && (len > 0)) ||
            (len > WH_MESSAGE_NVM_MAX_ADDOBJECT_LEN) ){
        return WH_ERROR_BADARGS;
    }

    msg->id = id;
    msg->access = access;
    msg->flags = flags;
    msg->len = len;
    if(label_len > 0) {
        memcpy(msg->label, label, label_len);
    }
    if(len > 0) {
        memcpy(payload, data, len);
    }

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_ADDOBJECT,
            hdr_len + len, buffer);
}

int wh_Client_NvmAddObjectResponse(whClientContext* c, int32_t *out_rc)
{
    whMessageNvm_SimpleResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_ADDOBJECT) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
        }
    }
    return rc;
}

int wh_Client_NvmAddObject(whClientContext* c,
        whNvmId id, whNvmAccess access, whNvmFlags flags,
        whNvmSize label_len, uint8_t* label,
        whNvmSize len, const uint8_t* data, int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmAddObjectRequest(c,
                id, access, flags,
                label_len, label,
                len, data);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmAddObjectResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM List */
int wh_Client_NvmListRequest(whClientContext* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id)
{
    whMessageNvm_ListRequest msg = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    msg.access = access;
    msg.flags = flags;
    msg.startId = start_id;

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_LIST,
            sizeof(msg), &msg);
}

int wh_Client_NvmListResponse(whClientContext* c, int32_t *out_rc,
        whNvmId *out_count, whNvmId *out_id)
{
    whMessageNvm_ListResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_LIST) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
            if (out_count != NULL) {
                *out_count = msg.count;
            }
            if (out_id != NULL) {
                *out_id = msg.id;
            }
        }
    }
    return rc;
}

int wh_Client_NvmList(whClientContext* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        int32_t *out_rc, whNvmId *out_count, whNvmId *out_id)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmListRequest(c, access, flags, start_id);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_NvmListResponse(c, out_rc,
                    out_count, out_id);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM GetMetadata */
int wh_Client_NvmGetMetadataRequest(whClientContext* c, whNvmId id)
{
    whMessageNvm_GetMetadataRequest msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    msg.id = id;
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_GETMETADATA,
            sizeof(msg), &msg);
}

int wh_Client_NvmGetMetadataResponse(whClientContext* c, int32_t *out_rc,
        whNvmId *out_id, whNvmAccess *out_access, whNvmFlags *out_flags,
        whNvmSize *out_len,
        whNvmSize label_len, uint8_t* label)
{
    whMessageNvm_GetMetadataResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_GETMETADATA) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
            if (out_id != NULL) {
                *out_id = msg.id;
            }
            if (out_access != NULL) {
                *out_access = msg.access;
            }
            if (out_flags != NULL) {
                *out_flags = msg.flags;
            }
            if (out_len != NULL) {
                *out_len = msg.len;
            }
            if (label != NULL) {
                if (label_len > sizeof(msg.label)) {
                    label_len = sizeof(msg.label);
                }
                memcpy(label, msg.label, label_len);
            }
        }
    }
    return rc;
}

int wh_Client_NvmGetMetadata(whClientContext* c, whNvmId id,
        int32_t *out_rc, whNvmId *out_id, whNvmAccess *out_access,
        whNvmFlags *out_flags, whNvmSize *out_len,
        whNvmSize label_len, uint8_t* label)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_NvmGetMetadataRequest(c, id);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmGetMetadataResponse(c, out_rc,
                    out_id, out_access, out_flags, out_len,
                    label_len, label);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM DestroyObjects */
int wh_Client_NvmDestroyObjectsRequest(whClientContext* c,
        whNvmId list_count, const whNvmId* id_list)
{
    whMessageNvm_DestroyObjectsRequest msg = {0};
    int counter = 0;

    if (    (c == NULL) ||
            ((id_list == NULL) && (list_count > 0)) ||
            (list_count > WH_MESSAGE_NVM_MAX_DESTROY_OBJECTS_COUNT) ){
        return WH_ERROR_BADARGS;
    }

    msg.list_count = list_count;
    for (counter = 0; counter < list_count; counter++) {
        msg.list[counter] = id_list[counter];
    }

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_DESTROYOBJECTS,
            sizeof(msg), &msg);
}

int wh_Client_NvmDestroyObjectsResponse(whClientContext* c, int32_t *out_rc)
{
    whMessageNvm_SimpleResponse msg = {0};
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(msg), &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_DESTROYOBJECTS) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
        }
    }
    return rc;
}

int wh_Client_NvmDestroyObjects(whClientContext* c,
        whNvmId list_count, const whNvmId* id_list,
        int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmDestroyObjectsRequest(c,
                list_count, id_list);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmDestroyObjectsResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM Read */
int wh_Client_NvmReadRequest(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len)
{
    whMessageNvm_ReadRequest msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    msg.id = id;
    msg.offset = offset;
    msg.data_len = data_len;
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_READ,
            sizeof(msg), &msg);
}

int wh_Client_NvmReadResponse(whClientContext* c, int32_t *out_rc,
        whNvmSize *out_len, uint8_t* data)
{
    uint8_t                    buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageNvm_ReadResponse* msg = (whMessageNvm_ReadResponse*)buffer;
    uint16_t hdr_len = sizeof(*msg);
    uint8_t* payload = buffer + hdr_len;

    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, sizeof(buffer), buffer);
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_NVM) ||
            (resp_action != WH_MESSAGE_NVM_ACTION_READ) ||
            (resp_size < hdr_len) || (resp_size > sizeof(buffer)) ||
            (resp_size - hdr_len > WH_MESSAGE_NVM_MAX_READ_LEN)) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg->rc;
            }
            if (out_len != NULL) {
                *out_len = resp_size - hdr_len;
            }
            if (data != NULL) {
                memcpy(data, payload, resp_size - hdr_len);
            }
        }
    }
    return rc;
}

int wh_Client_NvmRead(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        int32_t *out_rc, whNvmSize *out_len, uint8_t* data)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_NvmReadRequest(c, id, offset, data_len);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmReadResponse(c, out_rc,
                    out_len, data);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

#ifdef WOLFHSM_CFG_DMA

int wh_Client_NvmAddObjectDmaRequest(whClientContext* c,
                                     whNvmMetadata*   metadata,
                                     whNvmSize data_len, const uint8_t* data)
{
    whMessageNvm_AddObjectDmaRequest msg         = {0};
    uintptr_t                        metaAddrPtr = 0;
    uintptr_t                        dataAddrPtr = 0;
    int                              ret         = WH_ERROR_OK;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Fail fast if busy: don't acquire a mapping a rejected send would leak. */
    if (wh_CommClient_IsRequestPending(c->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    /* One op in flight: clear both slots up front so a metadata-only object -
     * or a failed metadata PRE that skips the data PRE - leaves the data slot's
     * POST a no-op and never acts on a stale (shared-union) size. */
    memset(&c->dma.asyncCtx.nvmAdd, 0, sizeof(c->dma.asyncCtx.nvmAdd));

    /* PRE-translate the metadata struct (fixed size) and the optional data
     * buffer; the matching Response POST releases them. */
    ret = wh_Client_DmaAsyncPre(c, &c->dma.asyncCtx.nvmAdd.meta,
                                (uintptr_t)metadata, sizeof(whNvmMetadata),
                                WH_DMA_OPER_CLIENT_READ_PRE, &metaAddrPtr);
    if (ret == WH_ERROR_OK) {
        /* len 0 (no data buffer) is a no-op in the helper, leaving dataAddrPtr
         * at 0 so no raw, untranslated pointer reaches the message. */
        ret = wh_Client_DmaAsyncPre(c, &c->dma.asyncCtx.nvmAdd.data,
                                    (uintptr_t)data,
                                    (data != NULL) ? data_len : 0,
                                    WH_DMA_OPER_CLIENT_READ_PRE, &dataAddrPtr);
    }

    msg.metadata_hostaddr = (uint64_t)metaAddrPtr;
    /* 0 when there is no data buffer to DMA (dataAddrPtr is set only by the
     * data PRE); never forward a raw, untranslated client pointer. */
    msg.data_hostaddr = (uint64_t)dataAddrPtr;
    msg.data_len      = data_len;

    if (ret == WH_ERROR_OK) {
        ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_NVM,
                                    WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA,
                                    sizeof(msg), &msg);
    }

    if (ret != WH_ERROR_OK) {
        /* Send/PRE failed: release whatever was acquired (helper no-ops on the
         * unset slot), in reverse order. */
        (void)wh_Client_DmaAsyncPost(c, &c->dma.asyncCtx.nvmAdd.data);
        (void)wh_Client_DmaAsyncPost(c, &c->dma.asyncCtx.nvmAdd.meta);
    }
    return ret;
}

int wh_Client_NvmAddObjectDmaResponse(whClientContext* c, int32_t* out_rc)
{
    whMessageNvm_SimpleResponse msg         = {0};
    int                         rc          = 0;
    uint16_t                    resp_group  = 0;
    uint16_t                    resp_action = 0;
    uint16_t                    resp_size   = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &resp_group, &resp_action, &resp_size,
                                sizeof(msg), &msg);
    /* NOTREADY: response not in yet - return without POST so the pending
     * request keeps its mappings; POST runs once the response arrives. */
    if (rc == WH_ERROR_NOTREADY) {
        return rc;
    }
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_NVM) ||
            (resp_action != WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA) ||
            (resp_size != sizeof(msg))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
        }
    }

    /* POST cleanup for both slots, reverse acquisition order. These are
     * READ inputs the server has already consumed and the object is stored
     * server-side, so releasing the client-side mappings is cleanup; a release
     * failure must not override an otherwise-successful result. */
    (void)wh_Client_DmaAsyncPost(c, &c->dma.asyncCtx.nvmAdd.data);
    (void)wh_Client_DmaAsyncPost(c, &c->dma.asyncCtx.nvmAdd.meta);
    return rc;
}

int wh_Client_NvmAddObjectDma(whClientContext* c, whNvmMetadata* metadata,
                              whNvmSize data_len, const uint8_t* data,
                              int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmAddObjectDmaRequest(c, metadata, data_len, data);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmAddObjectDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

int wh_Client_NvmReadDmaRequest(whClientContext* c, whNvmId id,
                                whNvmSize offset, whNvmSize data_len,
                                uint8_t* data)
{
    whMessageNvm_ReadDmaRequest msg         = {0};
    uintptr_t                   dataAddrPtr = 0;
    int                         ret         = WH_ERROR_OK;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Fail fast if busy: don't acquire a mapping a rejected send would leak. */
    if (wh_CommClient_IsRequestPending(c->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    /* PRE-translate the output data buffer (only when there is one); the server
     * writes the NVM contents and the Response POST copies them back. len 0 (no
     * buffer) is a no-op in the helper, keeping a raw, untranslated pointer out
     * of the message. */
    ret = wh_Client_DmaAsyncPre(c, &c->dma.asyncCtx.buf, (uintptr_t)data,
                                (data != NULL) ? data_len : 0,
                                WH_DMA_OPER_CLIENT_WRITE_PRE, &dataAddrPtr);

    if (ret == WH_ERROR_OK) {
        msg.id            = id;
        msg.offset        = offset;
        msg.data_len      = data_len;
        msg.data_hostaddr = (uint64_t)dataAddrPtr;

        ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_NVM,
                                    WH_MESSAGE_NVM_ACTION_READDMA, sizeof(msg),
                                    &msg);
    }

    /* On any failure release the mapping; POST no-ops on the unset slot. */
    if (ret != WH_ERROR_OK) {
        (void)wh_Client_DmaAsyncPost(c, &c->dma.asyncCtx.buf);
    }
    return ret;
}

int wh_Client_NvmReadDmaResponse(whClientContext* c, int32_t* out_rc)
{
    whMessageNvm_SimpleResponse msg         = {0};
    int                         rc          = 0;
    uint16_t                    resp_group  = 0;
    uint16_t                    resp_action = 0;
    uint16_t                    resp_size   = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &resp_group, &resp_action, &resp_size,
                                sizeof(msg), &msg);
    /* NOTREADY: response not in yet - return without POST so the pending
     * request keeps its mapping; POST runs once the response arrives. */
    if (rc == WH_ERROR_NOTREADY) {
        return rc;
    }
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_NVM) ||
            (resp_action != WH_MESSAGE_NVM_ACTION_READDMA) ||
            (resp_size != sizeof(msg))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg.rc;
            }
        }
    }

    /* POST cleanup: copy the server's writes back into the caller's buffer and
     * release the mapping. This is a WRITE-back: if it fails the caller has no
     * valid data, so surface the POST failure over an otherwise-successful
     * result. */
    {
        int postRc = wh_Client_DmaAsyncPost(c, &c->dma.asyncCtx.buf);
        if (rc == WH_ERROR_OK) {
            rc = postRc;
        }
    }
    return rc;
}

int wh_Client_NvmReadDma(whClientContext* c, whNvmId id, whNvmSize offset,
                         whNvmSize data_len, uint8_t* data, int32_t* out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_NvmReadDmaRequest(c, id, offset, data_len, data);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmReadDmaResponse(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */