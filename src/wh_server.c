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
#include "wolfhsm/wh_packet.h"

/* Server API's */
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_nvm.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_counter.h"
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
        server->dma.cb32             = config->dmaConfig->cb32;
        server->dma.cb64             = config->dmaConfig->cb64;
    }
#endif /* WOLFHSM_CFG_DMA */

    return rc;
}

int wh_Server_Cleanup(whServerContext* server)
{
    if (server ==NULL) {
        return WH_ERROR_BADARGS;
    }

    (void)wh_CommServer_Cleanup(server->comm);

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

int wh_Server_GetCanceledSequence(whServerContext* server, uint16_t* outSeq)
{
    if (server == NULL || outSeq == NULL)
        return WH_ERROR_BADARGS;
    *outSeq = server->cancelSeq;
    server->cancelSeq = 0;
    return 0;
}

int wh_Server_SetCanceledSequence(whServerContext* server, uint16_t cancelSeq)
{
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }
    server->cancelSeq = cancelSeq;
    return WH_ERROR_OK;
}

static int _wh_Server_HandleCommRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t* out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    case WH_MESSAGE_COMM_ACTION_INIT:
    {
        whMessageCommInitRequest req = {0};
        whMessageCommInitResponse resp = {0};

        /* Convert request struct */
        wh_MessageComm_TranslateInitRequest(magic,
                (whMessageCommInitRequest*)req_packet, &req);

        /* Process the init action */
        server->comm->client_id = req.client_id;
        resp.client_id = server->comm->client_id;
        resp.server_id = server->comm->server_id;

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
        resp.cfg_server_dmaaddr_count = WOLFHSM_CFG_SERVER_DMAADDR_COUNT;
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
    if (rc == 0) {
        group = WH_MESSAGE_GROUP(kind);
        action = WH_MESSAGE_ACTION(kind);
        switch (group) {

        case WH_MESSAGE_GROUP_COMM:
            rc = _wh_Server_HandleCommRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        case WH_MESSAGE_GROUP_NVM:
            rc = wh_Server_HandleNvmRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        case WH_MESSAGE_GROUP_COUNTER:
            rc = wh_Server_HandleCounter(server, action, data, &size);
        break;

#ifndef WOLFHSM_CFG_NO_CRYPTO
        case WH_MESSAGE_GROUP_KEY:
            rc = wh_Server_HandleKeyRequest(server, magic, action, seq,
                    data, &size);
        break;

        case WH_MESSAGE_GROUP_CRYPTO:
            rc = wh_Server_HandleCryptoRequest(server, action, data,
                &size, seq);
        break;

#ifdef WOLFHSM_CFG_DMA
        case WH_MESSAGE_GROUP_CRYPTO_DMA:
            rc = wh_Server_HandleCryptoDmaRequest(server, action, data,
                &size, seq);
            break;
#endif /* WOLFHSM_CFG_DMA */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

        case WH_MESSAGE_GROUP_PKCS11:
            rc = _wh_Server_HandlePkcs11Request(server, magic, action, seq,
                    size, data, &size, data);
        break;

#ifdef WOLFHSM_CFG_SHE_EXTENSION
        case WH_MESSAGE_GROUP_SHE:
            rc = wh_Server_HandleSheRequest(server, action, data,
                &size);
        break;
#endif

        case WH_MESSAGE_GROUP_CUSTOM:
            rc = wh_Server_HandleCustomCbRequest(server, magic, action, seq,
                    size, data, &size, data);
        break;

        default:
            /* Unknown group. Return empty packet*/
            /* TODO: Respond with aux error flag */
            size = 0;
        }

        /* Send a response */
        /* TODO: Respond with ErrorResponse if handler returns an error */
        if (rc == 0 || rc == WH_ERROR_CANCEL) {
            /* notify the client that their request was canceled */
            if (rc == WH_ERROR_CANCEL) {
                kind = WH_MESSAGE_KIND(WH_MESSAGE_GROUP_CANCEL, 0);
                size = 0;
                data = NULL;
            }
            do {
                rc = wh_CommServer_SendResponse(server->comm, magic, kind, seq,
                    size, data);
            } while (rc == WH_ERROR_NOTREADY);
        }
    }
    return rc;
}
