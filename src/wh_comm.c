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
 * src/wh_comm.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>  /* For sized ints */
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "wolfhsm/wh_comm.h"


/** Conditional byteswap functions */

uint8_t wh_Translate8(uint16_t magic, uint8_t val)
{
    (void) magic;
    return val;
}

uint16_t wh_Translate16(uint16_t magic, uint16_t val)
{
    return WH_COMM_FLAGS_SWAPTEST(magic) ? val : wh_Utils_Swap16(val);
}

uint32_t wh_Translate32(uint16_t magic, uint32_t val)
{
    return WH_COMM_FLAGS_SWAPTEST(magic) ? val : wh_Utils_Swap32(val);
}

uint64_t wh_Translate64(uint16_t magic, uint64_t val)
{
    return WH_COMM_FLAGS_SWAPTEST(magic) ? val : wh_Utils_Swap64(val);
}


/** Client functions */

int wh_CommClient_Init(whCommClient* context, const whCommClientConfig* config)
{
    int rc = 0;

    if (    (context == NULL) ||
            (config == NULL)     ) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->transport_cb       = config->transport_cb;
    context->transport_context  = config->transport_context;
    context->client_id          = config->client_id;
    context->connect_cb         = config->connect_cb;

    if (context->transport_cb->Init != NULL) {
        rc = context->transport_cb->Init(context->transport_context,
                config->transport_config, NULL, NULL);
    }
    if (rc == 0) {
        uintptr_t packet_addr = (uintptr_t)context->packet;
        context->hdr = (whCommHeader*)(packet_addr);
        context->data = (void*)(packet_addr + sizeof(*(context->hdr)));
        context->initialized = 1;

        /* Underlying transport is ready, so invoke connect callback */
        if (context->connect_cb != NULL) {
            rc = context->connect_cb(context, WH_COMM_CONNECTED);
        }
    }
    return rc;
}

/* If a request buffer is available, send a new request to the server.  The
 * sequence number will be incremented on transport success.
 */
int wh_CommClient_SendRequest(whCommClient* context, uint16_t magic,
    uint16_t kind, uint16_t *out_seq, uint16_t data_size, const void* data)
{
    int rc = 0;

    if (    (context == NULL) ||
            (context->initialized == 0) ||
            (context->transport_cb == NULL) ||
            (context->transport_cb->Send == NULL)) {
        return WH_ERROR_BADARGS;
    }

    context->hdr->magic = magic;
    context->hdr->kind = wh_Translate16(magic, kind);
    context->hdr->seq = wh_Translate16(magic, context->seq + 1);
    if (    (data != NULL) &&
            (data_size != 0) &&
            (data != context->data)) {
        memcpy(context->data, data, data_size);
    }
    rc = context->transport_cb->Send(context->transport_context,
            sizeof(*(context->hdr)) + data_size,
            context->packet);
    if (rc == 0) {
        context->seq++;
        if (out_seq != NULL) *out_seq = context->seq;
    }
    return rc;
}

/* If a response packet has been buffered, get the header and copy the data out
 * of the buffer.
 */
int wh_CommClient_RecvResponse(whCommClient* context,
        uint16_t* out_magic, uint16_t* out_kind, uint16_t* out_seq,
        uint16_t* out_size, void* data)
{
    int rc = 0;
    uint16_t magic = 0;
    uint16_t kind = 0;
    uint16_t seq = 0;
    uint16_t size = sizeof(context->packet);
    uint16_t data_size = 0;

    if (    (context == NULL) ||
            (context->initialized == 0) ||
            (context->transport_cb == NULL) ||
            (context->transport_cb->Recv == NULL)){
        return WH_ERROR_BADARGS;
    }

    rc = context->transport_cb->Recv(context->transport_context,
            &size,
            context->packet);
    if (rc == 0) {
        if (size < sizeof(*context->hdr)) {
            /* Size is too small */
            rc = WH_ERROR_ABORTED;
        }
        if (rc == 0) {
            data_size = size - sizeof(*context->hdr);
            magic = context->hdr->magic;
            kind = wh_Translate16(magic, context->hdr->kind);
            seq = wh_Translate16(magic, context->hdr->seq);
            if (    (data != NULL) &&
                    (data_size != 0) &&
                    (data != context->data)) {
                memcpy(data, context->data, data_size);
            }
            if (out_magic != NULL) *out_magic = magic;
            if (out_kind != NULL) *out_kind = kind;
            if (out_seq != NULL) *out_seq = seq;
            if (out_size != NULL) *out_size = data_size;
        }
    }
    return rc;
}

uint8_t* wh_CommClient_GetDataPtr(whCommClient* context)
{
    if (context == NULL) {
        return NULL;
    }
    return context->data;
}

/* Inform the server that no further communications are necessary and any
 * unfinished requests can be ignored.
 */
int wh_CommClient_Cleanup(whCommClient* context)
{
    int rc = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Signal a non-blocking disconnect to the server if registered */
    if (context->connect_cb != NULL) {
        (void)context->connect_cb(context, WH_COMM_DISCONNECTED);
    }

    if (    (context->transport_cb != NULL) &&
            (context->transport_cb->Cleanup != NULL)) {
        rc = context->transport_cb->Cleanup(context->transport_context);
    }

    /* Mark as not initialized regardless of cleanup return */
    context->initialized = 0;
    return rc;
}


/** Server Functions */

int wh_CommServer_Init(whCommServer* context, const whCommServerConfig* config,
                        whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    int rc = 0;

    if (    (context == NULL) ||
            (config == NULL)     ) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->transport_context  = config->transport_context;
    context->transport_cb       = config->transport_cb;
    context->server_id          = config->server_id;

    if (context->transport_cb->Init != NULL) {
        rc = context->transport_cb->Init(context->transport_context,
                config->transport_config, connectcb, connectcb_arg);
    }
    if (rc == 0) {
        uintptr_t packet_addr = (uintptr_t)context->packet;
        context->hdr = (whCommHeader*)packet_addr;
        context->data = (void*)(packet_addr + sizeof(*(context->hdr)));
        context->initialized = 1;
    }
    return rc;
}

int wh_CommServer_RecvRequest(whCommServer* context,
        uint16_t* out_magic, uint16_t* out_kind, uint16_t* out_seq,
        uint16_t* out_size, void* data)
{
    int rc = 0;
    uint16_t magic = 0;
    uint16_t kind = 0;
    uint16_t seq = 0;
    uint16_t size = sizeof(context->packet);
    uint16_t data_size = 0;

    if (    (context == NULL) ||
            (context->initialized == 0) ||
            (context->transport_cb == NULL) ||
            (context->transport_cb->Recv == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = context->transport_cb->Recv(context->transport_context,
            &size,
            context->packet);
    if (rc == 0) {
        if (size < sizeof(*context->hdr)) {
            rc = WH_ERROR_ABORTED;
        }
        if (rc == 0) {
            data_size = size - sizeof(*context->hdr);
            magic = context->hdr->magic;
            kind = wh_Translate16(magic, context->hdr->kind);
            seq = wh_Translate16(magic, context->hdr->seq);

            /* Copy the data from the internal buffer if necessary */
            if (    (data != NULL) &&
                    (data_size != 0) &&
                    (data != context->data) ) {
                memcpy(data, context->data, data_size);
            }
            if (out_magic != NULL) *out_magic = magic;
            if (out_kind != NULL) *out_kind = kind;
            if (out_seq != NULL) *out_seq = seq;
            if (out_size != NULL) *out_size = data_size;
        }
    }
    return rc;
}

int wh_CommServer_SendResponse(whCommServer* context,
        uint16_t magic, uint16_t kind, uint16_t seq,
        uint16_t data_size, const void* data)
{
    int rc = 0;

    if (    (context == NULL) ||
            (context->initialized == 0) ||
            (context->transport_cb == NULL) ||
            (context->transport_cb->Send == NULL)){
        return WH_ERROR_BADARGS;
    }

    context->hdr->magic = magic;
    context->hdr->kind = wh_Translate16(magic, kind);
    context->hdr->seq = wh_Translate16(magic, seq);

    /* Copy the data into the internal buffer if necessary */
    if (    (data != NULL) &&
            (data_size != 0) &&
            (data != context->data) ) {
        memcpy(context->data, data, data_size);
    }
    rc = context->transport_cb->Send(context->transport_context,
            sizeof(*(context->hdr)) + data_size,
            context->packet);
    return rc;
}

uint8_t* wh_CommServer_GetDataPtr(whCommServer* context)
{
    if (context == NULL) {
        return NULL;
    }
    return context->data;
}

int wh_CommServer_Cleanup(whCommServer* context)
{
    int rc = 0;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (    (context->transport_cb != NULL) &&
            (context->transport_cb->Cleanup != NULL)) {
        rc = context->transport_cb->Cleanup(context->transport_context);
    }

    /* Mark as not initialized regardless of cleanup return */
    context->initialized = 0;
    return rc;
}
