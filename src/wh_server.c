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
 * src/wh_server.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines*/
#include "wolfhsm/wh_error.h"

/* Server Components */
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_nvm.h"
#include "wolfhsm/wh_message_auth.h"

/* Server API's */
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_nvm.h"
#include "wolfhsm/wh_server_auth.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_counter.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfhsm/wh_server_cert.h"
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
#include "wolfhsm/wh_server_she.h"
#endif

/** Forward declarations. */
/* TODO: Move these out to separate C files */
static int _wh_Server_HandlePkcs11Request(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);

int wh_Server_Init(whServerContext* server, whServerConfig* config)
{
    int rc = 0;

    if ((server == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(server, 0, sizeof(*server));
    server->nvm = config->nvm;
    server->auth = config->auth;

#ifndef WOLFHSM_CFG_NO_CRYPTO
    server->crypto = config->crypto;
    if (server->crypto != NULL) {
#if defined(WOLF_CRYPTO_CB)
        server->crypto->devId = config->devId;
#else
        server->crypto->devId = INVALID_DEVID;
#endif
    }
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    server->she = config->she;
#endif
#endif

#ifdef WOLFHSM_CFG_LOGGING
    if (config->logConfig != NULL) {
        rc = wh_Log_Init(&server->log, config->logConfig);
        if (rc != WH_ERROR_OK) {
            (void)wh_Server_Cleanup(server);
            return WH_ERROR_ABORTED;
        }
    }
#endif /* WOLFHSM_CFG_LOGGING */

    rc = wh_CommServer_Init(server->comm, config->comm_config,
            wh_Server_SetConnectedCb, (void*)server);
    if (rc != 0) {
        (void)wh_Server_Cleanup(server);
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_DMA
    /* Initialize DMA configuration and callbacks, if provided */
    if (NULL != config->dmaConfig) {
        server->dma.dmaAddrAllowList = config->dmaConfig->dmaAddrAllowList;
        server->dma.cb               = config->dmaConfig->cb;
    }
#endif /* WOLFHSM_CFG_DMA */

    /* Log the server startup */
    WH_LOG(&server->log, WH_LOG_LEVEL_INFO, "Server Initialized");

    return rc;
}

int wh_Server_Cleanup(whServerContext* server)
{
    if (server ==NULL) {
        return WH_ERROR_BADARGS;
    }

    (void)wh_CommServer_Cleanup(server->comm);

    /* Log the server cleanup */
    WH_LOG(&server->log, WH_LOG_LEVEL_INFO, "Server Cleanup");

#ifdef WOLFHSM_CFG_LOGGING
    (void)wh_Log_Cleanup(&server->log);
#endif /* WOLFHSM_CFG_LOGGING */

    memset(server, 0, sizeof(*server));

    return WH_ERROR_OK;
}


int wh_Server_SetConnected(whServerContext *server, whCommConnected connected)
{
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    server->connected = connected;
    return WH_ERROR_OK;
}

int wh_Server_SetConnectedCb(void* s, whCommConnected connected)
{
    return wh_Server_SetConnected((whServerContext*)s, connected);
}

int wh_Server_GetConnected(whServerContext *server,
                            whCommConnected *out_connected)
{
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (out_connected != NULL) {
        *out_connected = server->connected;
    }
    return WH_ERROR_OK;
}


static int _wh_Server_HandleCommRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t* out_resp_size, void* resp_packet)
{
    (void)seq;

    int rc = 0;
    switch (action) {
    case WH_MESSAGE_COMM_ACTION_INIT:
    {
        whMessageCommInitRequest req = {0};
        whMessageCommInitResponse resp = {0};

        /* Convert request struct */
        wh_MessageComm_TranslateInitRequest(magic,
                (whMessageCommInitRequest*)req_packet, &req);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
        /* USER=0 is reserved for global keys, client_id must be non-zero */
        if (req.client_id == WH_KEYUSER_GLOBAL) {
            *out_resp_size = 0;
            return WH_ERROR_BADARGS;
        }
#endif

        /* Process the init action */
        server->comm->client_id = req.client_id;

        resp.client_id = server->comm->client_id;
        resp.server_id = server->comm->server_id;

        WH_LOG_F(&server->log, WH_LOG_LEVEL_INFO,
                 "CommInit: client_id=0x%08X, server_id=0x%08X", req.client_id,
                 resp.server_id);

        /* Convert the response struct */
        wh_MessageComm_TranslateInitResponse(magic,
                &resp, (whMessageCommInitResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    case WH_MESSAGE_COMM_ACTION_INFO:
    {
        const uint8_t version[WH_INFO_VERSION_LEN] =
                WOLFHSM_CFG_INFOVERSION;
        const uint8_t build[WH_INFO_VERSION_LEN] =
                WOLFHSM_CFG_INFOBUILD;

        /* No request message */
        whMessageCommInfoResponse resp = {0};

        /* Process the info action */
        memcpy(resp.version, version, sizeof(resp.version));
        memcpy(resp.build, build, sizeof(resp.build));
        resp.cfg_comm_data_len = WOLFHSM_CFG_COMM_DATA_LEN;
        resp.cfg_nvm_object_count = WOLFHSM_CFG_NVM_OBJECT_COUNT;
        resp.cfg_server_customcb_count = WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT;
        resp.cfg_server_dmaaddr_count    = WOLFHSM_CFG_DMAADDR_COUNT;
        resp.cfg_server_keycache_bufsize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE;
        resp.cfg_server_keycache_count = WOLFHSM_CFG_SERVER_KEYCACHE_COUNT;
        resp.cfg_server_keycache_bigbufsize = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
        resp.cfg_server_keycache_bigcount = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT;

        /* III Growth */
        resp.debug_state = 1;
        resp.boot_state = 2;
        resp.lifecycle_state = 3;
        resp.nvm_state = 4;

        /* Convert the response struct */
        wh_MessageComm_TranslateInfoResponse(magic,
                &resp, (whMessageCommInfoResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;


    case WH_MESSAGE_COMM_ACTION_CLOSE:
    {
        /* No message */
        /* Process the close action */
        wh_Server_SetConnected(server, WH_COMM_DISCONNECTED);
        *out_resp_size = 0;

        WH_LOG_F(&server->log, WH_LOG_LEVEL_INFO, "CommClose: client_id=0x%08X",
                 server->comm->client_id);
    }; break;

    case WH_MESSAGE_COMM_ACTION_ECHO:
    {
        /* Process the echo action */
        if (req_packet != resp_packet) {
            memcpy(resp_packet, req_packet, req_size);
        }
        *out_resp_size = req_size;
    }; break;

    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

static int _wh_Server_HandlePkcs11Request(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    (void)server;
    (void)magic;
    (void)seq;
    (void)req_size;
    (void)req_packet;
    (void)resp_packet;

    int rc = 0;
    switch (action) {
    /* TODO: Add PKCS11 message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

int wh_Server_HandleRequestMessage(whServerContext* server)
{
    uint16_t magic = 0;
    uint16_t kind = 0;
    uint16_t group = 0;
    uint16_t action = 0;
    uint16_t seq = 0;
    uint16_t size = 0;
    uint8_t* data = NULL;
    int      handlerRc = 0;

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Use the CommServer internal buffer to avoid copies */
    data = wh_CommServer_GetDataPtr(server->comm);

    /* Are we connected with a valid data pointer? */
    if (    (server->connected == WH_COMM_DISCONNECTED) ||
            (data == NULL) ) {
        return WH_ERROR_NOTREADY;
    }

    int rc = wh_CommServer_RecvRequest(server->comm, &magic, &kind, &seq,
            &size, data);
    /* Got a packet? */
    if (rc == WH_ERROR_OK) {
        group = WH_MESSAGE_GROUP(kind);
        action = WH_MESSAGE_ACTION(kind);

#ifndef WOLFHSM_CFG_NO_AUTHENTICATION
        /* General authentication check for if user has permissions for the
         * group and action requested. When dealing with key ID's there should
         * be an additional authorization check after parsing the request and
         * translating the key ID and before it is used. */
        /* Check authorization if auth context is configured */
        if (server->auth != NULL) {
            rc = wh_Auth_CheckRequestAuthorization(server->auth, group, action);
            if (rc != WH_ERROR_OK) {
                /* Authorization failed - send error response to client but keep server running */
                int32_t error_response = (int32_t)WH_AUTH_PERMISSION_ERROR;
                uint16_t resp_size = sizeof(error_response);

            /* Translate the error response for endian conversion */
            error_response = (int32_t)wh_Translate32(magic, (uint32_t)error_response);

            /* Send error response to client */
            do {
                rc = wh_CommServer_SendResponse(server->comm, magic, kind, seq,
                                                resp_size, &error_response);
            } while (rc == WH_ERROR_NOTREADY);

            /* Log the authorization failure */
            WH_LOG_ON_ERROR_F(&server->log, WH_LOG_LEVEL_ERROR, WH_AUTH_PERMISSION_ERROR,
                              "Authorization failed for (group=%d, action=%d, seq=%d)",
                              group, action, seq);

                return rc;
            }
        }
#endif /* WOLFHSM_CFG_NO_AUTHENTICATION */

        switch (group) {

        case WH_MESSAGE_GROUP_COMM:
            rc = _wh_Server_HandleCommRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        case WH_MESSAGE_GROUP_NVM:
            rc = wh_Server_HandleNvmRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        case WH_MESSAGE_GROUP_AUTH:
            rc = wh_Server_HandleAuthRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        case WH_MESSAGE_GROUP_COUNTER:
            rc = wh_Server_HandleCounter(server, magic, action, size, data,
                                         &size, data);
            break;

#ifndef WOLFHSM_CFG_NO_CRYPTO
        case WH_MESSAGE_GROUP_KEY:
            rc = wh_Server_HandleKeyRequest(server, magic, action, size, data,
                                            &size, data);
            break;

        case WH_MESSAGE_GROUP_CRYPTO:
            rc = wh_Server_HandleCryptoRequest(server, magic, action, seq, size,
                                               data, &size, data);
            break;

#ifdef WOLFHSM_CFG_DMA
        case WH_MESSAGE_GROUP_CRYPTO_DMA:
            rc = wh_Server_HandleCryptoDmaRequest(server, magic, action, seq,
                                                  size, data, &size, data);
            break;
#endif /* WOLFHSM_CFG_DMA */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

        case WH_MESSAGE_GROUP_PKCS11:
            rc = _wh_Server_HandlePkcs11Request(server, magic, action, seq,
                    size, data, &size, data);
        break;

#ifdef WOLFHSM_CFG_SHE_EXTENSION
        case WH_MESSAGE_GROUP_SHE:
            rc = wh_Server_HandleSheRequest(server, magic, action, size, data,
                                            &size, data);
            break;
#endif

        case WH_MESSAGE_GROUP_CUSTOM:
            rc = wh_Server_HandleCustomCbRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
        case WH_MESSAGE_GROUP_CERT:
            rc = wh_Server_HandleCertRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */

        default:
            /* Unknown group. Return empty packet */
            rc   = WH_ERROR_NOTIMPL;
            data = NULL;
            size = 0;
        }

        /* Capture handler result for logging. The response packet already
         * contains the error code for the client in the resp.rc field. */
        handlerRc = rc;

        /* Always send the response to the client, regardless of handler error.
         * The response packet contains the operational error code for the
         * client in the resp.rc field. */
        do {
            rc = wh_CommServer_SendResponse(server->comm, magic, kind, seq,
                                            size, data);
        } while (rc == WH_ERROR_NOTREADY);

        /* Log error code from request handler, if present */
        WH_LOG_ON_ERROR_F(&server->log, WH_LOG_LEVEL_ERROR, handlerRc,
                          "Handler (group=%d, action=%d, seq=%d) returned %d",
                          group, action, seq, handlerRc);
        (void)handlerRc; /* suppress unused var warning */

        /* Log error code from sending response, if present */
        WH_LOG_ON_ERROR_F(
            &server->log, WH_LOG_LEVEL_ERROR, rc,
            "SendResponse failed for (group=%d, action=%d, seq=%d): %d", group,
            action, seq, rc);

        /* Handler errors are logged above via handlerRc but don't affect
         * return code. Errors from SendResponse are propagated back to the
         * caller in rc */
    }
    else if (rc != WH_ERROR_NOTREADY) {
        /* Log error code from processing request, if present */
        WH_LOG_ON_ERROR_F(
            &server->log, WH_LOG_LEVEL_ERROR, rc,
            "RecvRequest failed for (group=%d, action=%d, seq=%d): %d", group,
            action, seq, rc);
    }

    return rc;
}

#ifdef WOLFHSM_CFG_THREADSAFE
int wh_Server_NvmLock(whServerContext* server)
{
    if (server == NULL || server->nvm == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Lock_Acquire(&server->nvm->lock);
}

int wh_Server_NvmUnlock(whServerContext* server)
{
    if (server == NULL || server->nvm == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Lock_Release(&server->nvm->lock);
}
#endif /* WOLFHSM_CFG_THREADSAFE */

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
