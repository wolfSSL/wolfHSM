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

#ifdef WOLFHSM_CFG_ENABLE_SERVER

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_keyid.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_nvm.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_nvm.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    (defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS))
#include "wolfhsm/wh_crypto.h"
#endif

/* Translate a client-supplied NVM id to the server-internal TYPE/USER/ID
 * encoding. When WOLFHSM_CFG_LEGACY_CLIENT_NVM is defined, the id is passed
 * through verbatim (legacy global-flat behavior). */
static whNvmId _NvmTranslateFromClient(whServerContext* server,
                                       whNvmId          clientId)
{
#ifdef WOLFHSM_CFG_LEGACY_CLIENT_NVM
    (void)server;
    return clientId;
#else
    return wh_KeyId_TranslateFromClient(WH_KEYTYPE_NVM, server->comm->client_id,
                                        clientId);
#endif
}

static whNvmId _NvmTranslateToClient(whNvmId serverId)
{
#ifdef WOLFHSM_CFG_LEGACY_CLIENT_NVM
    return serverId;
#else
    return wh_KeyId_TranslateToClient(serverId);
#endif
}

#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
/* Reject ids that are invalid in the translated scheme: the bare id portion
 * must be non-zero (id=0 is the erased sentinel; auto-generation is not
 * supported here) and the WRAPPED and HW flags are not valid for NVM
 * objects. */
static int _NvmValidateClientId(whNvmId clientId)
{
    if ((clientId & WH_KEYID_MASK) == WH_KEYID_ERASED) {
        return WH_ERROR_BADARGS;
    }
    if ((clientId &
         (WH_KEYID_CLIENT_WRAPPED_FLAG | WH_KEYID_CLIENT_HW_FLAG)) != 0) {
        return WH_ERROR_BADARGS;
    }
    return WH_ERROR_OK;
}
#endif

/* Handle NVM read, do access checking and clamping */
static int _HandleNvmRead(whServerContext* server, uint8_t* out_data,
                          whNvmSize offset, whNvmSize len, whNvmSize* out_len,
                          whNvmId id)
{
    whNvmMetadata meta;
    int32_t       rc;

    if ((server == NULL) || (out_data == NULL) || (out_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (len > WH_MESSAGE_NVM_MAX_READ_LEN) {
        return WH_ERROR_ABORTED;
    }

    rc = wh_Nvm_GetMetadata(server->nvm, id, &meta);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    if (offset >= meta.len)
        return WH_ERROR_BADARGS;

    /* Clamp length to object size, use overflow-safe comparison */
    if (len > meta.len - offset) {
        len = meta.len - offset;
    }

    rc = wh_Nvm_ReadChecked(server->nvm, id, offset, len, out_data);
    if (rc != WH_ERROR_OK)
        return rc;
    *out_len = len;
    return WH_ERROR_OK;
}

int wh_Server_HandleNvmRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    (void)seq;

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

            rc = WH_SERVER_NVM_LOCK(server);
            if (rc == WH_ERROR_OK) {
#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
                /* The GLOBAL flag on startId selects which namespace to
                 * iterate: set => global (USER=0), clear => this client's own
                 * objects (USER=client_id). The flag rides through both
                 * translation helpers, so iterating with the previously
                 * returned id stays in the same namespace. */
                const uint16_t target_user =
                    ((req.startId & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0)
                        ? WH_KEYUSER_GLOBAL
                        : server->comm->client_id;
                /* startId id-portion of 0 is the start-from-beginning
                 * sentinel; pass it through unchanged. Otherwise translate to
                 * the server-internal id so wh_Nvm_List resumes after it. */
                whNvmId cur =
                    ((req.startId & WH_KEYID_MASK) == 0)
                        ? 0
                        : _NvmTranslateFromClient(server, req.startId);
                whNvmId hit_id = 0;
                whNvmId total  = 0;

                rc = WH_ERROR_OK;
                for (;;) {
                    whNvmId next_id   = 0;
                    whNvmId remaining = 0;
                    rc = wh_Nvm_List(server->nvm, req.access, req.flags, cur,
                                     &remaining, &next_id);
                    if (rc != WH_ERROR_OK || remaining == 0) {
                        break;
                    }

                    if (WH_KEYID_TYPE(next_id) == WH_KEYTYPE_NVM &&
                        WH_KEYID_USER(next_id) == target_user) {
                        if (hit_id == 0) {
                            hit_id = next_id;
                        }
                        total++;
                    }
                    cur = next_id;
                    if (remaining == 1) {
                        break;
                    }
                }

                if (rc == WH_ERROR_OK) {
                    resp.id = (hit_id != 0) ? _NvmTranslateToClient(hit_id) : 0;
                    resp.count = total;
                }
#else
                /* Process the list action */
                rc = wh_Nvm_List(server->nvm, req.access, req.flags,
                                 req.startId, &resp.count, &resp.id);
#endif

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = rc;
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
            rc = WH_SERVER_NVM_LOCK(server);
            if (rc == WH_ERROR_OK) {
                /* Process the available action */
                rc = wh_Nvm_GetAvailable(
                    server->nvm, &resp.avail_size, &resp.avail_objects,
                    &resp.reclaim_size, &resp.reclaim_objects);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = rc;
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

            rc = WH_SERVER_NVM_LOCK(server);
            if (rc == WH_ERROR_OK) {
                /* Process the getmetadata action */
                rc = wh_Nvm_GetMetadata(server->nvm,
                                        _NvmTranslateFromClient(server, req.id),
                                        &meta);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */

            if (rc == WH_ERROR_OK) {
                resp.id     = _NvmTranslateToClient(meta.id);
                resp.access = meta.access;
                resp.flags  = meta.flags;
                resp.len    = meta.len;
                memcpy(resp.label, meta.label, sizeof(resp.label));
            }
            resp.rc = rc;
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
#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
                int validate_rc = _NvmValidateClientId(req.id);
                if (validate_rc != WH_ERROR_OK) {
                    resp.rc = validate_rc;
                }
                else
#endif
                {
                    /* Process the AddObject action */
                    meta.id     = _NvmTranslateFromClient(server, req.id);
                    meta.access = req.access;
                    meta.flags  = req.flags;
                    meta.len    = req.len;
                    memcpy(meta.label, req.label, sizeof(meta.label));

                    rc = WH_ERROR_OK;
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    (defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS))
                    /* Block direct NVM import of stateful (LMS/XMSS) private
                     * key state; only on-HSM keygen may create such objects. */
                    if (wh_Crypto_IsStatefulSigPrivBlob(data,
                                                        (uint16_t)req.len)) {
                        rc = WH_ERROR_ACCESS;
                    }
#endif
                    if (rc == WH_ERROR_OK) {
                        rc = WH_SERVER_NVM_LOCK(server);
                        if (rc == WH_ERROR_OK) {
                            rc = wh_Nvm_AddObjectChecked(server->nvm, &meta,
                                                         req.len, data);

                            (void)WH_SERVER_NVM_UNLOCK(server);
                        } /* WH_SERVER_NVM_LOCK() */
                    }
                    resp.rc = rc;
                }
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
                whNvmId
                    translated_ids[WH_MESSAGE_NVM_MAX_DESTROY_OBJECTS_COUNT];
                whNvmId i;
                for (i = 0; i < req.list_count; i++) {
                    translated_ids[i] =
                        _NvmTranslateFromClient(server, req.list[i]);
                }

                rc = WH_SERVER_NVM_LOCK(server);
                if (rc == WH_ERROR_OK) {
                    /* Process the DestroyObjects action */
                    rc = wh_Nvm_DestroyObjectsChecked(
                        server->nvm, req.list_count, translated_ids);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
                resp.rc = rc;
            }
            else {
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
        whMessageNvm_ReadRequest  req      = {0};
        whMessageNvm_ReadResponse resp     = {0};
        uint16_t                  hdr_len  = sizeof(resp);
        uint8_t*                  data     = (uint8_t*)resp_packet + hdr_len;
        whNvmSize                 data_len = 0;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }
        else {
            /* Convert request struct */
            wh_MessageNvm_TranslateReadRequest(
                magic, (whMessageNvm_ReadRequest*)req_packet, &req);

            rc = WH_SERVER_NVM_LOCK(server);
            if (rc == WH_ERROR_OK) {
                rc = _HandleNvmRead(server, data, req.offset, req.data_len,
                                    &req.data_len,
                                    _NvmTranslateFromClient(server, req.id));
                if (rc == WH_ERROR_OK) {
                    data_len = req.data_len;
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = rc;
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateReadResponse(
            magic, &resp, (whMessageNvm_ReadResponse*)resp_packet);
        *out_resp_size = sizeof(resp) + data_len;
    }; break;

#ifdef WOLFHSM_CFG_DMA

    case WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA:
    {
        whMessageNvm_AddObjectDmaRequest req = {0};
        whMessageNvm_SimpleResponse resp = {0};
        void* metadata = NULL;
        void* data = NULL;
        int metadata_dma_pre_ok = 0;
        int data_dma_pre_ok = 0;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }
        if (resp.rc == 0) {
            /* Convert request struct */
            wh_MessageNvm_TranslateAddObjectDmaRequest(magic,
                    (whMessageNvm_AddObjectDmaRequest*)req_packet, &req);

            /* perform platform-specific host address processing */
            resp.rc = wh_Server_DmaProcessClientAddress(
                server, req.metadata_hostaddr, &metadata, sizeof(whNvmMetadata),
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            if (resp.rc == 0) {
                metadata_dma_pre_ok = 1;
            }
        }
        if (resp.rc == 0) {
            resp.rc = wh_Server_DmaProcessClientAddress(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            if (resp.rc == 0) {
                data_dma_pre_ok = 1;
            }
        }
        if (resp.rc == 0) {
            /* Take a local copy of the metadata so we can rewrite the id
             * field without touching host memory. */
            whNvmMetadata local_meta = *(const whNvmMetadata*)metadata;
#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
            resp.rc = _NvmValidateClientId(local_meta.id);
#endif
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    (defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS))
            /* Block direct NVM import of stateful (LMS/XMSS) private key state;
             * only on-HSM keygen may create such objects. */
            if ((resp.rc == WH_ERROR_OK) &&
                wh_Crypto_IsStatefulSigPrivBlob((const uint8_t*)data,
                                                (uint16_t)req.data_len)) {
                resp.rc = WH_ERROR_ACCESS;
            }
#endif
            if (resp.rc == WH_ERROR_OK) {
                local_meta.id = _NvmTranslateFromClient(server, local_meta.id);

                rc = WH_SERVER_NVM_LOCK(server);
                if (rc == WH_ERROR_OK) {
                    /* Process the AddObject action */
                    rc = wh_Nvm_AddObjectChecked(server->nvm, &local_meta,
                                                 req.data_len,
                                                 (const uint8_t*)data);

                    (void)WH_SERVER_NVM_UNLOCK(server);
                } /* WH_SERVER_NVM_LOCK() */
                resp.rc = rc;
            }
        }
        /* Always call POST for successful PREs, regardless of operation
         * result */
        if (metadata_dma_pre_ok) {
            (void)wh_Server_DmaProcessClientAddress(
                server, req.metadata_hostaddr, &metadata, sizeof(whNvmMetadata),
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }
        if (data_dma_pre_ok) {
            (void)wh_Server_DmaProcessClientAddress(
                server, req.data_hostaddr, &data, req.data_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_NVM_ACTION_READDMA:
    {
        whMessageNvm_ReadDmaRequest req  = {0};
        whMessageNvm_SimpleResponse resp = {0};
        whNvmMetadata               meta = {0};
        whNvmSize                   read_len = 0;
        void*                       data = NULL;
        int                         data_dma_pre_ok = 0;

        if (req_size != sizeof(req)) {
            /* Request is malformed */
            resp.rc = WH_ERROR_ABORTED;
        }
        if (resp.rc == 0) {
            /* Convert request struct */
            wh_MessageNvm_TranslateReadDmaRequest(magic,
                    (whMessageNvm_ReadDmaRequest*)req_packet, &req);

            rc = WH_SERVER_NVM_LOCK(server);
            if (rc == WH_ERROR_OK) {
                whNvmId server_id = _NvmTranslateFromClient(server, req.id);
                rc = wh_Nvm_GetMetadata(server->nvm, server_id, &meta);

                if (rc == 0) {
                    if (req.offset >= meta.len) {
                        rc = WH_ERROR_BADARGS;
                    }
                }

                if (rc == 0) {
                    read_len = req.data_len;
                    /* Clamp length to object size, use overflow-safe
                     * comparison */
                    if (read_len > meta.len - req.offset) {
                        read_len = meta.len - req.offset;
                    }
                }

                /* use unclamped length for DMA address processing in case DMA
                 * callbacks are sensible to alignment and/or size */
                if (rc == 0) {
                    /* perform platform-specific host address processing */
                    rc = wh_Server_DmaProcessClientAddress(
                        server, req.data_hostaddr, &data, req.data_len,
                        WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
                    if (rc == 0) {
                        data_dma_pre_ok = 1;
                    }
                }
                if (rc == 0) {
                    /* Process the Read action */
                    rc = wh_Nvm_ReadChecked(server->nvm, server_id, req.offset,
                                            read_len, (uint8_t*)data);
                }
                /* Always call POST for successful PRE, regardless of read
                 * result */
                if (data_dma_pre_ok) {
                    (void)wh_Server_DmaProcessClientAddress(
                        server, req.data_hostaddr, &data, req.data_len,
                        WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() */
            resp.rc = rc;
        }
        /* Convert the response struct */
        wh_MessageNvm_TranslateSimpleResponse(magic,
                &resp, (whMessageNvm_SimpleResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;
#endif /* WOLFHSM_CFG_DMA */

    default:
        /* Unknown request. Respond with empty packet */
        /* TODO: Use ErrorResponse packet instead */
        *out_resp_size = 0;
    }
    return rc;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
