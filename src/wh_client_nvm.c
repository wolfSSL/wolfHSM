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
            &resp_size, &msg);
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
            &resp_size, &msg);
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
            &resp_size, &msg);
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
            &resp_size, &msg);
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
            &resp_size, &msg);
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
            &resp_size, &msg);
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
            &resp_size, &msg);
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
    uint8_t buffer[WH_MESSAGE_NVM_MAX_READ_LEN] = {0};
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
            &resp_size, buffer);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_READ) ||
                (resp_size < hdr_len) ||
                (resp_size - hdr_len > WH_MESSAGE_NVM_MAX_READ_LEN) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
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

/** NVM AddObjectDma32 */
int wh_Client_NvmAddObjectDma32Request(whClientContext* c,
        uint32_t metadata_hostaddr,
        whNvmSize data_len, uint32_t data_hostaddr)
{
    whMessageNvm_AddObjectDma32Request msg = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    msg.metadata_hostaddr = metadata_hostaddr;
    msg.data_hostaddr = data_hostaddr;
    msg.data_len = data_len;

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA32,
            sizeof(msg), &msg);
}

int wh_Client_NvmAddObjectDma32Response(whClientContext* c, int32_t *out_rc)
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
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA32) ||
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

int wh_Client_NvmAddObjectDma32(whClientContext* c,
        uint32_t metadata_hostaddr, whNvmSize data_len, uint32_t data_hostaddr,
        int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmAddObjectDma32Request(c,
                metadata_hostaddr, data_len, data_hostaddr);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmAddObjectDma32Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM AddObjectDma64 */
int wh_Client_NvmAddObjectDma64Request(whClientContext* c,
        uint64_t metadata_hostaddr,
        whNvmSize data_len, uint64_t data_hostaddr)
{
    whMessageNvm_AddObjectDma64Request msg = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    msg.metadata_hostaddr = metadata_hostaddr;
    msg.data_hostaddr = data_hostaddr;
    msg.data_len = data_len;

    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA64,
            sizeof(msg), &msg);
}

int wh_Client_NvmAddObjectDma64Response(whClientContext* c, int32_t *out_rc)
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
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA64) ||
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

int wh_Client_NvmAddObjectDma64(whClientContext* c,
        uint64_t metadata_hostaddr, whNvmSize data_len, uint64_t data_hostaddr,
        int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_NvmAddObjectDma64Request(c,
                metadata_hostaddr, data_len, data_hostaddr);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmAddObjectDma64Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM AddObjectDMA Helper functions */
int wh_Client_NvmAddObjectDmaRequest(whClientContext* c,
        whNvmMetadata* metadata,
        whNvmSize data_len, const uint8_t* data)
{
    if (sizeof(intptr_t) == sizeof(uint32_t)) {
        return wh_Client_NvmAddObjectDma32Request(c,
                (intptr_t)metadata, data_len, (intptr_t)data);
    }
    if (sizeof(intptr_t) == sizeof(uint64_t)) {
        return wh_Client_NvmAddObjectDma64Request(c,
                (intptr_t)metadata, data_len, (intptr_t)data);
    }
    return WH_ERROR_BADARGS;
}

int wh_Client_NvmAddObjectDmaResponse(whClientContext* c, int32_t *out_rc)
{
    if (sizeof(intptr_t) == sizeof(uint32_t)) {
        return wh_Client_NvmAddObjectDma32Response(c, out_rc);
    }
    if (sizeof(intptr_t) == sizeof(uint64_t)) {
        return wh_Client_NvmAddObjectDma64Response(c, out_rc);
    }
    return WH_ERROR_BADARGS;
}

int wh_Client_NvmAddObjectDma(whClientContext* c,
        whNvmMetadata* metadata, whNvmSize data_len, const uint8_t* data,
        int32_t *out_rc)
{
    if (sizeof(intptr_t) == sizeof(uint32_t)) {
        return wh_Client_NvmAddObjectDma32(c,
                (intptr_t)metadata, data_len, (intptr_t)data,
                out_rc);
    }
    if (sizeof(intptr_t) == sizeof(uint64_t)) {
        return wh_Client_NvmAddObjectDma64(c,
                (intptr_t)metadata, data_len, (intptr_t)data,
                out_rc);
    }
    return WH_ERROR_BADARGS;
}

/** NVM ReadDma32 */
int wh_Client_NvmReadDma32Request(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint32_t data_hostaddr)
{
    whMessageNvm_ReadDma32Request msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    msg.id = id;
    msg.offset = offset;
    msg.data_len = data_len;
    msg.data_hostaddr = data_hostaddr;
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_READDMA32,
            sizeof(msg), &msg);
}

int wh_Client_NvmReadDma32Response(whClientContext* c, int32_t *out_rc)
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
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_READDMA32) ||
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

int wh_Client_NvmReadDma32(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint32_t data_hostaddr, int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_NvmReadDma32Request(c,
                id, offset, data_len, data_hostaddr);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmReadDma32Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM ReadDma64 */
int wh_Client_NvmReadDma64Request(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint64_t data_hostaddr)
{
    whMessageNvm_ReadDma64Request msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    msg.id = id;
    msg.offset = offset;
    msg.data_len = data_len;
    msg.data_hostaddr = data_hostaddr;
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_NVM, WH_MESSAGE_NVM_ACTION_READDMA64,
            sizeof(msg), &msg);
}

int wh_Client_NvmReadDma64Response(whClientContext* c, int32_t *out_rc)
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
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_NVM) ||
                (resp_action != WH_MESSAGE_NVM_ACTION_READDMA64) ||
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

int wh_Client_NvmReadDma64(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint64_t data_hostaddr, int32_t *out_rc)
{
    int rc = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_NvmReadDma64Request(c,
                id, offset, data_len, data_hostaddr);
    } while (rc == WH_ERROR_NOTREADY);
    if (rc == 0) {
        do {
            rc = wh_Client_NvmReadDma64Response(c, out_rc);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

/** NVM ReadDma Helper functions */
int wh_Client_NvmReadDmaRequest(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint8_t* data)
{
    if (sizeof(intptr_t) == sizeof(uint32_t)) {
        return wh_Client_NvmReadDma32Request(c,
                id, offset, data_len, (intptr_t)data);
    }
    if (sizeof(intptr_t) == sizeof(uint64_t)) {
        return wh_Client_NvmReadDma64Request(c,
                id, offset, data_len, (intptr_t)data);
    }
    return WH_ERROR_BADARGS;
}

int wh_Client_NvmReadDmaResponse(whClientContext* c, int32_t *out_rc)
{
    if (sizeof(intptr_t) == sizeof(uint32_t)) {
        return wh_Client_NvmReadDma32Response(c, out_rc);
    }
    if (sizeof(intptr_t) == sizeof(uint64_t)) {
        return wh_Client_NvmReadDma64Response(c, out_rc);
    }
    return WH_ERROR_BADARGS;
}

int wh_Client_NvmReadDma(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len, uint8_t* data,
        int32_t *out_rc)
{
    if (sizeof(intptr_t) == sizeof(uint32_t)) {
        return wh_Client_NvmReadDma32(c,
                id, offset, data_len, (intptr_t)data,
                out_rc);
    }
    if (sizeof(intptr_t) == sizeof(uint64_t)) {
        return wh_Client_NvmReadDma64(c,
                id, offset, data_len, (intptr_t)data,
                out_rc);
    }
    return WH_ERROR_BADARGS;
}

