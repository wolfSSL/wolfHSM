/*
 * src/wh_client_nvm.c
 */

/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
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
    int rc = 0;
    whMessageNvm_InitResponse msg = {0};
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
    int rc = 0;
    whMessageNvm_SimpleResponse msg = {0};
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
    int rc = 0;
    whMessageNvm_GetAvailableResponse msg = {0};
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
    uint8_t buffer[WH_COMM_DATA_LEN] = {0};
    whMessageNvm_AddObjectRequest* msg = (whMessageNvm_AddObjectRequest*)buffer;
    uint16_t hdr_len = sizeof(*msg);
    uint8_t* payload = (uint8_t*)buffer + hdr_len;

    if (    (c == NULL) ||
            ((label == NULL) && (label_len > 0)) ||
            (label_len > WOLFHSM_NVM_LABEL_LEN) ||
            ((data == NULL) && (len > 0)) ||
            (len > WH_MESSAGE_NVM_MAX_ADD_OBJECT_LEN) ){
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
    int rc = 0;
    whMessageNvm_SimpleResponse msg = {0};
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


