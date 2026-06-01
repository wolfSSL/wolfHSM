/*
 * port/armv8m-tz/wh_transport_nsc.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_PORT_ARMV8M_TZ_NSC

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wh_transport_nsc.h"

/*
 * Resolved on the non-secure side via the wolfBoot --cmse-implib import
 * library; on the secure side the same symbol is provided by the host's
 * NSC veneer (wolfBoot's src/wolfhsm_callable.c). The server callbacks
 * below never call this; --gc-sections strips client-side code from the
 * secure image.
 */
extern int wcs_wolfhsm_transmit(const uint8_t* cmd, uint32_t cmdSz,
                                uint8_t* rsp, uint32_t* rspSz);


/* ============================================================
 * Non-secure (client) callbacks
 * ============================================================ */

static int _NscClientInit(void* context, const void* config,
                          whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    whTransportNscClientContext* ctx = (whTransportNscClientContext*)context;

    (void)config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->initialized = 1;

    /* Synchronous bridge: the secure side is always reachable once linked. */
    if (connectcb != NULL) {
        connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
}

static int _NscClientSend(void* context, uint16_t size, const void* data)
{
    whTransportNscClientContext* ctx = (whTransportNscClientContext*)context;
    uint32_t rspSz;
    int      rc;

    if (ctx == NULL || data == NULL || ctx->initialized == 0U) {
        return WH_ERROR_BADARGS;
    }
    if (size == 0U || size > WH_TRANSPORT_NSC_BUFFER_SIZE) {
        return WH_ERROR_BADARGS;
    }
    /* prior response must be consumed before next Send */
    if (ctx->last_rsp_size != 0U) {
        return WH_ERROR_NOTREADY;
    }

    rspSz = (uint32_t)WH_TRANSPORT_NSC_BUFFER_SIZE;
    rc    = wcs_wolfhsm_transmit((const uint8_t*)data, (uint32_t)size,
                                 ctx->rsp_buf, &rspSz);
    if (rc != 0) {
        ctx->last_rsp_size = 0;
        /* propagate known wolfHSM error codes, collapse unknowns */
        if (rc == WH_ERROR_BADARGS || rc == WH_ERROR_NOTREADY ||
            rc == WH_ERROR_ABORTED) {
            return rc;
        }
        return WH_ERROR_ABORTED;
    }
    if (rspSz == 0U || rspSz > (uint32_t)WH_TRANSPORT_NSC_BUFFER_SIZE) {
        ctx->last_rsp_size = 0;
        return WH_ERROR_ABORTED;
    }

    ctx->last_rsp_size = (uint16_t)rspSz;
    return WH_ERROR_OK;
}

static int _NscClientRecv(void* context, uint16_t* out_size, void* data)
{
    whTransportNscClientContext* ctx = (whTransportNscClientContext*)context;

    if (ctx == NULL || out_size == NULL || data == NULL ||
        ctx->initialized == 0U) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->last_rsp_size == 0U) {
        return WH_ERROR_NOTREADY;
    }
    /* out_size is in/out capacity; reject truncation, keep cached response */
    if (*out_size < ctx->last_rsp_size) {
        return WH_ERROR_BADARGS;
    }

    memcpy(data, ctx->rsp_buf, ctx->last_rsp_size);
    *out_size          = ctx->last_rsp_size;
    ctx->last_rsp_size = 0;
    return WH_ERROR_OK;
}

static int _NscClientCleanup(void* context)
{
    whTransportNscClientContext* ctx = (whTransportNscClientContext*)context;
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    ctx->initialized = 0;
    return WH_ERROR_OK;
}

const whTransportClientCb whTransportNscClient_Cb = {
    .Init    = _NscClientInit,
    .Send    = _NscClientSend,
    .Recv    = _NscClientRecv,
    .Cleanup = _NscClientCleanup,
};


/* ============================================================
 * Secure-side (server) callbacks
 *
 * The host's NSC veneer populates req_buf/req_size/rsp_buf/rsp_capacity
 * and sets request_pending = 1 before calling wh_Server_HandleRequestMessage.
 * Recv hands the request to the dispatcher; Send writes the response back
 * into rsp_buf and stores its size for the veneer to read.
 * ============================================================ */

static int _NscServerInit(void* context, const void* config,
                          whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    whTransportNscServerContext* ctx = (whTransportNscServerContext*)context;

    (void)config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));

    if (connectcb != NULL) {
        connectcb(connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
}

static int _NscServerRecv(void* context, uint16_t* inout_size, void* data)
{
    whTransportNscServerContext* ctx = (whTransportNscServerContext*)context;

    if (ctx == NULL || inout_size == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (!ctx->request_pending || ctx->req_buf == NULL || ctx->req_size == 0U) {
        return WH_ERROR_NOTREADY;
    }
    /* clear stale rsp_size up-front so every exit path leaves a clean state */
    ctx->rsp_size = 0;

    if (ctx->req_size > *inout_size) {
        ctx->request_pending = 0;
        return WH_ERROR_ABORTED;
    }

    memcpy(data, ctx->req_buf, ctx->req_size);
    *inout_size          = ctx->req_size;
    ctx->request_pending = 0;
    return WH_ERROR_OK;
}

static int _NscServerSend(void* context, uint16_t size, const void* data)
{
    /* veneer is responsible for Recv/Send pairing; Send does not enforce it */
    whTransportNscServerContext* ctx = (whTransportNscServerContext*)context;

    if (ctx == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (size == 0U || size > ctx->rsp_capacity) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->rsp_buf == NULL) {
        return WH_ERROR_ABORTED;
    }

    memcpy(ctx->rsp_buf, data, size);
    ctx->rsp_size = size;
    return WH_ERROR_OK;
}

static int _NscServerCleanup(void* context)
{
    whTransportNscServerContext* ctx = (whTransportNscServerContext*)context;
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* clear stale NS pointers so they cannot survive reinit */
    memset(ctx, 0, sizeof(*ctx));
    return WH_ERROR_OK;
}

const whTransportServerCb whTransportNscServer_Cb = {
    .Init    = _NscServerInit,
    .Recv    = _NscServerRecv,
    .Send    = _NscServerSend,
    .Cleanup = _NscServerCleanup,
};

#endif /* WOLFHSM_CFG_PORT_ARMV8M_TZ_NSC */
