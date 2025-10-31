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
 * src/wh_client.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

/* Components */
#include "wolfhsm/wh_comm.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"

#include "wolfhsm/wh_client_cryptocb.h"
#endif /* WOLFHSM_CFG_NO_CRYPTO */

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_message_counter.h"
#include "wolfhsm/wh_client.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
const int WH_DEV_IDS_ARRAY[WH_NUM_DEVIDS] = {
        WH_DEV_ID,
#ifdef WOLFHSM_CFG_DMA
        WH_DEV_ID_DMA,
#endif /* WOLFHSM_CFG_DMA */
};
#endif /* WOLFHSM_CFG_NO_CRYPTO */

int wh_Client_Init(whClientContext* c, const whClientConfig* config)
{
    int rc = 0;
    if((c == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(c, 0, sizeof(*c));
#ifdef WOLFHSM_CFG_CANCEL_API
    /* register the cancel callback */
    c->cancelCb = config->cancelCb;
#endif

    rc = wh_CommClient_Init(c->comm, config->comm);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    if( rc == 0) {
        rc = wolfCrypt_Init();
        if (rc != 0) {
            rc = WH_ERROR_ABORTED;
        }

        if (rc == 0) {
            rc = wc_CryptoCb_RegisterDevice(WH_DEV_ID,
                    wh_Client_CryptoCb, c);
            if (rc != 0) {
                rc = WH_ERROR_ABORTED;
            }

#ifdef WOLFHSM_CFG_DMA
            if (rc == 0) {
                /* Initialize DMA configuration and callbacks, if provided */
                if (NULL != config->dmaConfig) {
                    c->dma.dmaAddrAllowList =
                        config->dmaConfig->dmaAddrAllowList;
                    c->dma.cb = config->dmaConfig->cb;
                }

                rc = wc_CryptoCb_RegisterDevice(WH_DEV_ID_DMA,
                                                wh_Client_CryptoCbDma, c);
                if (rc != 0) {
                    rc = WH_ERROR_ABORTED;
                }
            }
#endif /* WOLFHSM_CFG_DMA */
        }
    }
#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

    if (rc != 0) {
        wh_Client_Cleanup(c);
    }
    return rc;
}

int wh_Client_Cleanup(whClientContext* c)
{
    if (c ==NULL) {
        return WH_ERROR_BADARGS;
    }

#ifndef WOLFHSM_CFG_NO_CRYPTO
    (void)wolfCrypt_Cleanup();
#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

    (void)wh_CommClient_Cleanup(c->comm);

    memset(c, 0, sizeof(*c));
    return 0;
}

int wh_Client_SendRequest(whClientContext* c,
        uint16_t group, uint16_t action,
        uint16_t data_size, const void* data)
{
    int rc = 0;
    uint16_t req_id = 0;
    uint16_t kind = WH_MESSAGE_KIND(group, action);

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    rc = wh_CommClient_SendRequest(c->comm, WH_COMM_MAGIC_NATIVE, kind, &req_id,
        data_size, data);
    if (rc == 0) {
        c->last_req_kind = kind;
        c->last_req_id = req_id;
    }
    return rc;
}

int wh_Client_RecvResponse(whClientContext *c,
        uint16_t *out_group, uint16_t *out_action,
        uint16_t *out_size, void* data)
{
    int rc = 0;
    uint16_t resp_magic = 0;
    uint16_t resp_kind = 0;
    uint16_t resp_id = 0;
    uint16_t resp_size = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_CommClient_RecvResponse(c->comm,
                &resp_magic, &resp_kind, &resp_id,
                &resp_size, data);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_magic != WH_COMM_MAGIC_NATIVE) ||
                (resp_kind != c->last_req_kind) ||
                (resp_id != c->last_req_id) ){
            /* Invalid or unexpected message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid and expected message. Set outputs */
            if (out_group != NULL) {
                *out_group = WH_MESSAGE_GROUP(resp_kind);
            }
            if (out_action != NULL) {
                *out_action = WH_MESSAGE_ACTION(resp_kind);
            }
            if (out_size != NULL) {
                *out_size = resp_size;
            }
        }
    }
    return rc;
}

int wh_Client_CommInitRequest(whClientContext* c)
{
    whMessageCommInitRequest msg = {0};

    if (c == NULL) {
       return WH_ERROR_BADARGS;
   }

   /* Populate the message.*/
   msg.client_id = c->comm->client_id;

   return wh_Client_SendRequest(c,
           WH_MESSAGE_GROUP_COMM, WH_MESSAGE_COMM_ACTION_INIT,
           sizeof(msg), &msg);
}

int wh_Client_CommInitResponse(whClientContext* c,
                                uint32_t *out_clientid,
                                uint32_t *out_serverid)
{
    int rc = 0;
    whMessageCommInitResponse msg = {0};
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_COMM) ||
                (resp_action != WH_MESSAGE_COMM_ACTION_INIT) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_clientid != NULL) {
                *out_clientid = msg.client_id;
            }
            if (out_serverid != NULL) {
                *out_serverid = msg.server_id;
            }
        }
    }
    return rc;
}

int wh_Client_CommInit(whClientContext* c,
                        uint32_t *out_clientid,
                        uint32_t *out_serverid)
{
    int rc = 0;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_CommInitRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CommInitResponse(c, out_clientid, out_serverid);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

int wh_Client_CommInfoRequest(whClientContext* c)
{
    if (c == NULL) {
       return WH_ERROR_BADARGS;
   }

   return wh_Client_SendRequest(c,
           WH_MESSAGE_GROUP_COMM, WH_MESSAGE_COMM_ACTION_INFO,
           0, NULL);
}

int wh_Client_CommInfoResponse(whClientContext* c,
        uint8_t* out_version,
        uint8_t* out_build,
        uint32_t *out_cfg_comm_data_len,
        uint32_t *out_cfg_nvm_object_count,
        uint32_t *out_cfg_keycache_count,
        uint32_t *out_cfg_keycache_bufsize,
        uint32_t *out_cfg_keycache_bigcount,
        uint32_t *out_cfg_keycache_bigbufsize,
        uint32_t *out_cfg_customcb_count,
        uint32_t *out_cfg_dmaaddr_count,
        uint32_t *out_debug_state,
        uint32_t *out_boot_state,
        uint32_t *out_lifecycle_state,
        uint32_t *out_nvm_state)
{
    int rc = 0;
    whMessageCommInfoResponse msg = {0};
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, &msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_COMM) ||
                (resp_action != WH_MESSAGE_COMM_ACTION_INFO) ||
                (resp_size != sizeof(msg)) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message */
            if (out_version != NULL) {
                memcpy(out_version, msg.version, sizeof(msg.version));
            }
            if (out_build != NULL) {
                memcpy(out_build, msg.build, sizeof(msg.build));
            }
            if (out_cfg_comm_data_len != NULL) {
                *out_cfg_comm_data_len = msg.cfg_comm_data_len;
            }
            if (out_cfg_nvm_object_count != NULL) {
                *out_cfg_nvm_object_count = msg.cfg_nvm_object_count;
            }
            if (out_cfg_keycache_count != NULL) {
                *out_cfg_keycache_count = msg.cfg_server_keycache_count;
            }
            if (out_cfg_keycache_bufsize != NULL) {
                *out_cfg_keycache_bufsize = msg.cfg_server_keycache_bufsize;
            }
            if (out_cfg_keycache_count != NULL) {
                *out_cfg_keycache_bigcount = msg.cfg_server_keycache_bigcount;
            }
            if (out_cfg_keycache_bufsize != NULL) {
                *out_cfg_keycache_bigbufsize = msg.cfg_server_keycache_bigbufsize;
            }
            if (out_cfg_customcb_count != NULL) {
                *out_cfg_customcb_count = msg.cfg_server_customcb_count;
            }
            if (out_cfg_dmaaddr_count != NULL) {
                *out_cfg_dmaaddr_count = msg.cfg_server_dmaaddr_count;
            }
            if (out_debug_state != NULL) {
                *out_debug_state = msg.debug_state;
            }
            if (out_boot_state != NULL) {
                *out_boot_state = msg.boot_state;
            }
            if (out_lifecycle_state != NULL) {
                *out_lifecycle_state = msg.lifecycle_state;
            }
            if (out_nvm_state != NULL) {
                *out_nvm_state = msg.nvm_state;
            }
        }
    }
    return rc;
}

int wh_Client_CommInfo(whClientContext* c,
        uint8_t* out_version,
        uint8_t* out_build,
        uint32_t *out_cfg_comm_data_len,
        uint32_t *out_cfg_nvm_object_count,
        uint32_t *out_cfg_keycache_count,
        uint32_t *out_cfg_keycache_bufsize,
        uint32_t *out_cfg_keycache_bigcount,
        uint32_t *out_cfg_keycache_bigbufsize,
        uint32_t *out_cfg_customcb_count,
        uint32_t *out_cfg_dmaaddr_count,
        uint32_t *out_debug_state,
        uint32_t *out_boot_state,
        uint32_t *out_lifecycle_state,
        uint32_t *out_nvm_state)
{
    int rc = 0;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_CommInfoRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CommInfoResponse(c,
                    out_version,
                    out_build,
                    out_cfg_comm_data_len,
                    out_cfg_nvm_object_count,
                    out_cfg_keycache_count,
                    out_cfg_keycache_bufsize,
                    out_cfg_keycache_bigcount,
                    out_cfg_keycache_bigbufsize,
                    out_cfg_customcb_count,
                    out_cfg_dmaaddr_count,
                    out_debug_state,
                    out_boot_state,
                    out_lifecycle_state,
                    out_nvm_state);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}


int wh_Client_CommCloseRequest(whClientContext* c)
{
    if (c == NULL) {
       return WH_ERROR_BADARGS;
   }

   return wh_Client_SendRequest(c,
           WH_MESSAGE_GROUP_COMM, WH_MESSAGE_COMM_ACTION_CLOSE,
           0, NULL);
}

int wh_Client_CommCloseResponse(whClientContext* c)
{
    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, NULL);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_COMM) ||
                (resp_action != WH_MESSAGE_COMM_ACTION_CLOSE) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            /* Valid message. Server is now disconnected */
            /* TODO: Cleanup the client */
        }
    }
    return rc;
}

int wh_Client_CommClose(whClientContext* c)
{
    int rc = 0;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_CommCloseRequest(c);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_CommCloseResponse(c);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

#ifdef WOLFHSM_CFG_CANCEL_API
int wh_Client_EnableCancel(whClientContext* c)
{
    if (c == NULL)
        return WH_ERROR_BADARGS;
    c->cancelable = 1;
    return 0;
}

int wh_Client_DisableCancel(whClientContext* c)
{
    if (c == NULL)
        return WH_ERROR_BADARGS;
    c->cancelable = 0;
    return 0;
}

int wh_Client_CancelRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (c->cancelCb == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Since we aren't sending this request through the standard transport, we
     * need to update the client context's last sent "kind" to prevent the Comm
     * Client receive function from discarding the next response as an
     * out-of-order/corrupted message. No need to update the sequence number/ID
     * as it will not have been incremented by the cancel operation, as it is
     * out-of-band */
    c->last_req_kind = WH_MESSAGE_KIND(WH_MESSAGE_GROUP_CANCEL, 0);

    return c->cancelCb(c->comm->seq);
}

int wh_Client_CancelResponse(whClientContext* c)
{
    int ret = 0;
    uint16_t group;
    uint16_t action;
    uint16_t size;
    uint8_t* buf;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    /* check if the request was canceled */
    buf = wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &size, buf);
    if (ret == 0 && group != WH_MESSAGE_GROUP_CANCEL)
        return WH_ERROR_CANCEL_LATE;
    return ret;
}

int wh_Client_Cancel(whClientContext* c)
{
    int ret;
    ret = wh_Client_CancelRequest(c);
    if (ret == 0) {
        do {
            ret = wh_Client_CancelResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_CANCEL_API */

int wh_Client_EchoRequest(whClientContext* c, uint16_t size, const void* data)
{
    uint8_t* msg = NULL;

    if (    (c == NULL) ||
            ((size > 0) && (data == NULL)) ||
            ((size > WOLFHSM_CFG_COMM_DATA_LEN) && (data != NULL)) ){
        return WH_ERROR_BADARGS;
    }

    msg = wh_CommClient_GetDataPtr(c->comm);
    if (msg == NULL) {
        return WH_ERROR_BADARGS;
    }
    memcpy(msg, data, size);
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_COMM, WH_MESSAGE_COMM_ACTION_ECHO,
            size, msg);
}

int wh_Client_EchoResponse(whClientContext* c, uint16_t *out_size, void* data)
{
    int rc = 0;
    uint8_t*  msg = {0};
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL) {
     return WH_ERROR_BADARGS;
    }

    msg = wh_CommClient_GetDataPtr(c->comm);
    if (msg == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
         &resp_group, &resp_action,
         &resp_size, msg);
    if (rc == 0) {
        /* Validate response */
        if (    (resp_group != WH_MESSAGE_GROUP_COMM) ||
                (resp_action != WH_MESSAGE_COMM_ACTION_ECHO) ){
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        } else {
            if (out_size != NULL) {
                *out_size = resp_size;
            }
            if (data != NULL) {
                memcpy(data, msg, resp_size);
            }
        }
    }
    return rc;
}

int wh_Client_Echo(whClientContext* c, uint16_t snd_len, const void* snd_data,
        uint16_t *out_rcv_len, void* rcv_data)
{
    int rc = 0;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    do {
        rc = wh_Client_EchoRequest(c, snd_len, snd_data);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == 0) {
        do {
            rc = wh_Client_EchoResponse(c, out_rcv_len, rcv_data);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

int wh_Client_CustomCbRequest(whClientContext* c, const whMessageCustomCb_Request* req)
{
    if (NULL == c || req == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CUSTOM, req->id,
                                 sizeof(*req), req);
}

int wh_Client_CustomCbResponse(whClientContext*          c,
                             whMessageCustomCb_Response* outResp)
{
    whMessageCustomCb_Response resp;
    uint16_t                 resp_group  = 0;
    uint16_t                 resp_action = 0;
    uint16_t                 resp_size   = 0;
    int32_t                  rc          = 0;

    if (NULL == c || outResp == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc =
        wh_Client_RecvResponse(c, &resp_group, &resp_action, &resp_size, &resp);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (resp_size != sizeof(resp) || resp_group != WH_MESSAGE_GROUP_CUSTOM) {
        /* message invalid */
        return WH_ERROR_ABORTED;
    }

    memcpy(outResp, &resp, sizeof(resp));

    return WH_ERROR_OK;
}

int wh_Client_CustomCheckRegisteredRequest(whClientContext* c, uint32_t id)
{
    whMessageCustomCb_Request req = {0};

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    req.id = id;
    req.type = WH_MESSAGE_CUSTOM_CB_TYPE_QUERY;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_CUSTOM, req.id,
                                 sizeof(req), &req);
}


int wh_Client_CustomCbCheckRegisteredResponse(whClientContext* c, uint16_t* outId, int* responseError)
{
    int rc = 0;
    whMessageCustomCb_Response resp = {0};

    if (c == NULL || outId == NULL || responseError == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_CustomCbResponse(c, &resp);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (resp.type != WH_MESSAGE_CUSTOM_CB_TYPE_QUERY) {
        /* message invalid */
        return WH_ERROR_ABORTED;
    }

    if (resp.err != WH_ERROR_OK && resp.err != WH_ERROR_NOHANDLER) {
        /* error codes that aren't related to the query should be fatal */
        return WH_ERROR_ABORTED;
    }

    *outId = resp.id;
    *responseError = resp.err;

    return WH_ERROR_OK;
}


int wh_Client_CustomCbCheckRegistered(whClientContext* c, uint16_t id, int* responseError)
{
    int rc = 0;

    if (NULL == c || NULL == responseError) {
        return WH_ERROR_BADARGS;
    }

    do {
        rc = wh_Client_CustomCheckRegisteredRequest(c, id);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc == WH_ERROR_OK) {
        do {
            rc = wh_Client_CustomCbCheckRegisteredResponse(c, &id, responseError);
        } while (rc == WH_ERROR_NOTREADY);
    }

    return rc;
}


int wh_Client_KeyCacheRequest_ex(whClientContext* c, uint32_t flags,
                                 uint8_t* label, uint16_t labelSz, const uint8_t* in,
                                 uint16_t inSz, uint16_t keyId)
{
    whMessageKeystore_CacheRequest* req = NULL;
    uint8_t*                        packIn;

    if (c == NULL || in == NULL || inSz == 0 ||
        sizeof(*req) + inSz > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageKeystore_CacheRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    packIn = (uint8_t*)(req + 1);
    req->id    = keyId;
    req->flags = flags;
    req->sz    = inSz;

    if (label == NULL) {
        req->labelSz = 0;
    }
    else {
        req->labelSz = labelSz;
        /* write label */
        if (labelSz > WH_NVM_LABEL_LEN) {
            memcpy(req->label, label, WH_NVM_LABEL_LEN);
        }
        else {
            memcpy(req->label, label, labelSz);
        }
    }

    /* write in */
    memcpy(packIn, in, inSz);

    /* write request */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_CACHE,
                                 sizeof(*req) + inSz, (uint8_t*)req);
}

int wh_Client_KeyCacheRequest(whClientContext* c, uint32_t flags,
                              uint8_t* label, uint16_t labelSz, const uint8_t* in,
                              uint16_t inSz)
{
    return wh_Client_KeyCacheRequest_ex(c, flags, label, labelSz, in, inSz,
                                        WH_KEYID_ERASED);
}

int wh_Client_KeyCacheResponse(whClientContext* c, uint16_t* keyId)
{
    uint16_t                        group;
    uint16_t                        action;
    uint16_t                        size;
    int                             ret;
    whMessageKeystore_CacheResponse *resp = NULL;

    if (c == NULL || keyId == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageKeystore_CacheResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else {
            *keyId = resp->id;
        }
    }

    return ret;
}

int wh_Client_KeyCache(whClientContext* c, uint32_t flags, uint8_t* label,
                       uint16_t labelSz, const uint8_t* in, uint16_t inSz,
                       uint16_t* keyId)
{
    int ret = WH_ERROR_OK;

    ret = wh_Client_KeyCacheRequest_ex(c, flags, label, labelSz, in, inSz,
                                       *keyId);

    if (ret == 0) {
        do {
            ret = wh_Client_KeyCacheResponse(c, keyId);
        } while (ret == WH_ERROR_NOTREADY);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s label:%.*s key_id:%x ret:%d \n", __func__, labelSz,
           label, *keyId, ret);
#endif
    return ret;
}

int wh_Client_KeyEvictRequest(whClientContext* c, uint16_t keyId)
{
    whMessageKeystore_EvictRequest* req = NULL;

    if (c == NULL || keyId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageKeystore_EvictRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->id = keyId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_EVICT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_KeyEvictResponse(whClientContext* c)
{
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         size;
    int                              ret;
    whMessageKeystore_EvictResponse resp;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)&resp);

    if (ret == 0) {
        if (resp.rc != 0) {
            ret = resp.rc;
        }
    }

    return ret;
}

int wh_Client_KeyEvict(whClientContext* c, uint16_t keyId)
{
    int ret;
    ret = wh_Client_KeyEvictRequest(c, keyId);
    if (ret == 0) {
        do {
            ret = wh_Client_KeyEvictResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("client %s key_id:%x ret:%d \n", __func__, keyId, ret);
#endif
    return ret;
}

int wh_Client_KeyExportRequest(whClientContext* c, whKeyId keyId)
{
    whMessageKeystore_ExportRequest* req = NULL;

    if (c == NULL || keyId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageKeystore_ExportRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->id = keyId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_EXPORT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_KeyExportResponse(whClientContext* c, uint8_t* label,
                                uint16_t labelSz, uint8_t* out, uint16_t* outSz)
{
    uint16_t                          group;
    uint16_t                          action;
    uint16_t                          size;
    int                               ret;
    whMessageKeystore_ExportResponse *resp = NULL;
    uint8_t*                          packOut;

    if (c == NULL || outSz == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageKeystore_ExportResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else {
            if (out == NULL) {
                *outSz = resp->len;
            }
            else if (*outSz < resp->len) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(out, packOut, resp->len);
                *outSz = resp->len;
            }
            if (label != NULL) {
                if (labelSz > sizeof(resp->label)) {
                    memcpy(label, resp->label, WH_NVM_LABEL_LEN);
                }
                else
                    memcpy(label, resp->label, labelSz);
            }
        }
    }
    return ret;
}

int wh_Client_KeyExport(whClientContext* c, whKeyId keyId, uint8_t* label,
                        uint16_t labelSz, uint8_t* out, uint16_t* outSz)
{
    int ret;
    ret = wh_Client_KeyExportRequest(c, keyId);
    if (ret == 0) {
        do {
            ret = wh_Client_KeyExportResponse(c, label, labelSz, out, outSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_KeyCommitRequest(whClientContext* c, whNvmId keyId)
{
    whMessageKeystore_CommitRequest* req = NULL;

    if (c == NULL || keyId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageKeystore_CommitRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->id = keyId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_COMMIT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_KeyCommitResponse(whClientContext* c)
{
    uint16_t                          group;
    uint16_t                          action;
    uint16_t                          size;
    int                               ret;
    whMessageKeystore_CommitResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageKeystore_CommitResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret  = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
    }
    return ret;
}

int wh_Client_KeyCommit(whClientContext* c, whNvmId keyId)
{
    int ret;
    ret = wh_Client_KeyCommitRequest(c, keyId);
    if (ret == 0) {
        do {
            ret = wh_Client_KeyCommitResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_KeyEraseRequest(whClientContext* c, whNvmId keyId)
{
    whMessageKeystore_EraseRequest* req = NULL;

    if (c == NULL || keyId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageKeystore_EraseRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->id = keyId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_ERASE,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_KeyEraseResponse(whClientContext* c)
{
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         size;
    int                              ret;
    whMessageKeystore_EraseResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageKeystore_EraseResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret  = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
    }
    return ret;
}

int wh_Client_KeyErase(whClientContext* c, whNvmId keyId)
{
    int ret;
    ret = wh_Client_KeyEraseRequest(c, keyId);
    if (ret == 0) {
        do {
            ret = wh_Client_KeyEraseResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_CounterInitRequest(whClientContext* c, whNvmId counterId,
    uint32_t counter)
{
    whMessageCounter_InitRequest* req = NULL;

    if (c == NULL || counterId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCounter_InitRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->counterId = counterId;
    req->counter = counter;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_COUNTER, WH_COUNTER_INIT,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_CounterInitResponse(whClientContext* c, uint32_t* counter)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageCounter_InitResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageCounter_InitResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else if (counter != NULL) {
            *counter = resp->counter;
        }
    }
    return ret;
}

int wh_Client_CounterInit(whClientContext* c, whNvmId counterId,
    uint32_t* counter)
{
    int ret;
    ret = wh_Client_CounterInitRequest(c, counterId, *counter);
    if (ret == 0) {
        do {
            ret = wh_Client_CounterInitResponse(c, counter);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_CounterResetRequest(whClientContext* c, whNvmId counterId)
{
    return wh_Client_CounterInitRequest(c, counterId, 0);
}

int wh_Client_CounterResetResponse(whClientContext* c, uint32_t* counter)
{
    return wh_Client_CounterInitResponse(c, counter);
}

int wh_Client_CounterReset(whClientContext* c, whNvmId counterId,
    uint32_t* counter)
{
    *counter = 0;
    return wh_Client_CounterInit(c, counterId, counter);
}

int wh_Client_CounterIncrementRequest(whClientContext* c, whNvmId counterId)
{
    whMessageCounter_IncrementRequest* req = NULL;

    if (c == NULL || counterId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCounter_IncrementRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->counterId = counterId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_COUNTER,
                                 WH_COUNTER_INCREMENT, sizeof(*req),
                                 (uint8_t*)req);
}

int wh_Client_CounterIncrementResponse(whClientContext* c, uint32_t* counter)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageCounter_IncrementResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageCounter_IncrementResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else if (counter != NULL) {
            *counter = resp->counter;
        }
    }
    return ret;
}

int wh_Client_CounterIncrement(whClientContext* c, whNvmId counterId,
    uint32_t* counter)
{
    int ret;
    ret = wh_Client_CounterIncrementRequest(c, counterId);
    if (ret == 0) {
        do {
            ret = wh_Client_CounterIncrementResponse(c, counter);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_CounterReadRequest(whClientContext* c, whNvmId counterId)
{
    whMessageCounter_ReadRequest* req = NULL;

    if (c == NULL || counterId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCounter_ReadRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->counterId = counterId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_COUNTER, WH_COUNTER_READ,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_CounterReadResponse(whClientContext* c, uint32_t* counter)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageCounter_ReadResponse* resp = NULL;

    if (c == NULL || counter == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageCounter_ReadResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
        else {
            *counter = resp->counter;
        }
    }
    return ret;
}

int wh_Client_CounterRead(whClientContext* c, whNvmId counterId,
    uint32_t* counter)
{
    int ret;
    ret = wh_Client_CounterReadRequest(c, counterId);
    if (ret == 0) {
        do {
            ret = wh_Client_CounterReadResponse(c, counter);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_CounterDestroyRequest(whClientContext* c, whNvmId counterId)
{
    whMessageCounter_DestroyRequest* req = NULL;

    if (c == NULL || counterId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCounter_DestroyRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->counterId = counterId;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_COUNTER, WH_COUNTER_DESTROY,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_CounterDestroyResponse(whClientContext* c)
{
    uint16_t group;
    uint16_t action;
    uint16_t size;
    int ret;
    whMessageCounter_DestroyResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageCounter_DestroyResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        if (resp->rc != 0) {
            ret = resp->rc;
        }
    }
    return ret;
}

int wh_Client_CounterDestroy(whClientContext* c, whNvmId counterId)
{
    int ret;
    ret = wh_Client_CounterDestroyRequest(c, counterId);
    if (ret == 0) {
        do {
            ret = wh_Client_CounterDestroyResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA

int wh_Client_KeyCacheDmaRequest(whClientContext* c, uint32_t flags,
                                 uint8_t* label, uint16_t labelSz,
                                 const void* keyAddr, uint16_t keySz,
                                 uint16_t keyId)
{
    int                                ret;
    whMessageKeystore_CacheDmaRequest* req = NULL;
    uintptr_t                          keyAddrPtr = 0;

    if (c == NULL || (labelSz > 0 && label == NULL)) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageKeystore_CacheDmaRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(req, 0, sizeof(*req));
    req->id      = keyId;
    req->flags   = flags;
    req->labelSz = labelSz;

    /* Set up DMA buffer info */
    req->key.sz   = keySz;
    ret           = wh_Client_DmaProcessClientAddress(
        c, (uintptr_t)keyAddr, (void**)&keyAddrPtr, keySz,
        WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
    req->key.addr = keyAddrPtr;

    /* Copy label if provided, truncate if necessary */
    if (labelSz > 0) {
        if (labelSz > WH_NVM_LABEL_LEN) {
            labelSz = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, labelSz);
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_CACHE_DMA,
                                    sizeof(*req), (uint8_t*)req);
    }

    (void)wh_Client_DmaProcessClientAddress(
        c, (uintptr_t)keyAddr, (void**)&keyAddrPtr, keySz,
        WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    return ret;
}

int wh_Client_KeyCacheDmaResponse(whClientContext* c, uint16_t* keyId)
{
    uint16_t                            group;
    uint16_t                            action;
    uint16_t                            size;
    int                                 ret;
    whMessageKeystore_CacheDmaResponse* resp = NULL;

    if (c == NULL || keyId == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp =
        (whMessageKeystore_CacheDmaResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(c, &group, &action, &size, (uint8_t*)resp);

    if (ret == 0) {
        /* Validate response */
        if ((group != WH_MESSAGE_GROUP_KEY) || (action != WH_KEY_CACHE_DMA) ||
            (size != sizeof(*resp))) {
            /* Invalid message */
            ret = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (resp->rc != 0) {
                ret = resp->rc;
            }
            else {
                *keyId = resp->id;
            }
        }
    }
    return ret;
}

int wh_Client_KeyCacheDma(whClientContext* c, uint32_t flags, uint8_t* label,
                          uint16_t labelSz, const void* keyAddr, uint16_t keySz,
                          uint16_t* keyId)
{
    int ret;
    ret = wh_Client_KeyCacheDmaRequest(c, flags, label, labelSz, keyAddr, keySz,
                                       *keyId);
    if (ret == 0) {
        do {
            ret = wh_Client_KeyCacheDmaResponse(c, keyId);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_KeyExportDmaRequest(whClientContext* c, uint16_t keyId,
                                  const void* keyAddr, uint16_t keySz)
{
    whMessageKeystore_ExportDmaRequest* req = NULL;

    if (c == NULL || keyId == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }

    req =
        (whMessageKeystore_ExportDmaRequest*)wh_CommClient_GetDataPtr(c->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }
    req->id       = keyId;
    req->key.addr = (uint64_t)((uintptr_t)keyAddr);
    req->key.sz   = keySz;

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_KEY, WH_KEY_EXPORT_DMA,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_KeyExportDmaResponse(whClientContext* c, uint8_t* label,
                                   uint16_t labelSz, uint16_t* outSz)
{
    uint16_t                             resp_group;
    uint16_t                             resp_action;
    uint16_t                             resp_size;
    int                                  rc;
    whMessageKeystore_ExportDmaResponse* resp = NULL;

    if (c == NULL || outSz == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp =
        (whMessageKeystore_ExportDmaResponse*)wh_CommClient_GetDataPtr(c->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c, &resp_group, &resp_action, &resp_size,
                                (uint8_t*)resp);
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_KEY) ||
            (resp_action != WH_KEY_EXPORT_DMA) ||
            (resp_size != sizeof(*resp))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (resp->rc != 0) {
                rc = resp->rc;
            }
            else {
                *outSz = resp->len;
                if (label != NULL) {
                    if (labelSz > WH_NVM_LABEL_LEN) {
                        labelSz = WH_NVM_LABEL_LEN;
                    }
                    memcpy(label, resp->label, labelSz);
                }
            }
        }
    }
    return rc;
}

int wh_Client_KeyExportDma(whClientContext* c, uint16_t keyId,
                           const void* keyAddr, uint16_t keySz, uint8_t* label,
                           uint16_t labelSz, uint16_t* outSz)
{
    int ret;
    ret = wh_Client_KeyExportDmaRequest(c, keyId, keyAddr, keySz);
    if (ret == 0) {
        do {
            ret = wh_Client_KeyExportDmaResponse(c, label, labelSz, outSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
