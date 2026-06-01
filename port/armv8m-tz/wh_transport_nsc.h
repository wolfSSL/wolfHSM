/*
 * port/armv8m-tz/wh_transport_nsc.h
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

/*
 * Synchronous TrustZone NSC bridge transport for wolfHSM.
 *
 * The non-secure (client) side calls a single ARMv8-M Cortex-M
 * cmse_nonsecure_entry veneer (`wcs_wolfhsm_transmit`) provided by the
 * secure-side host. The veneer hands the request to the secure-side
 * server context, runs `wh_Server_HandleRequestMessage` once inline,
 * and returns the response in the same call. There is no polling,
 * notify counter, or async producer/consumer — Send delivers the
 * response, Recv just hands it back.
 *
 * The transport is target-agnostic across ARMv8-M TrustZone parts;
 * the target-specific NSC veneer is provided by the host.
 */

#ifndef WH_TRANSPORT_NSC_H_
#define WH_TRANSPORT_NSC_H_

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_PORT_ARMV8M_TZ_NSC

#include <stdint.h>
#include "wolfhsm/wh_comm.h"

#define WH_TRANSPORT_NSC_BUFFER_SIZE WH_COMM_MTU

/*
 * Non-secure (client) context. Owns the response buffer in NS .bss.
 * Not internally thread-safe.
 */
typedef struct {
    uint8_t  rsp_buf[WH_TRANSPORT_NSC_BUFFER_SIZE];
    uint16_t last_rsp_size;
    uint8_t  initialized;
    uint8_t  WH_PAD[5]; /* trailing slack */
} whTransportNscClientContext;

/* Empty config; Init accepts NULL since there is nothing to read. */
typedef struct {
    uint8_t WH_PAD[1];
} whTransportNscClientConfig;

/*
 * Secure-side server context. Populated by the NSC veneer per call:
 * before invoking `wh_Server_HandleRequestMessage` the host sets
 * req_buf/req_size/rsp_buf/rsp_capacity; after the dispatcher returns,
 * the host reads rsp_size to pass back to the non-secure caller.
 */
typedef struct {
    const uint8_t* req_buf;
    uint8_t*       rsp_buf;
    uint16_t       req_size;
    uint16_t       rsp_capacity;
    uint16_t       rsp_size;        /* set by Send, read by veneer */
    uint8_t        request_pending; /* set by veneer, cleared by Recv */
    uint8_t        WH_PAD[1];
} whTransportNscServerContext;

typedef struct {
    uint8_t WH_PAD[1];
} whTransportNscServerConfig;

/* Pre-populated tables; callbacks are file-local in wh_transport_nsc.c */
extern const whTransportClientCb whTransportNscClient_Cb;
extern const whTransportServerCb whTransportNscServer_Cb;

#endif /* WOLFHSM_CFG_PORT_ARMV8M_TZ_NSC */

#endif /* WH_TRANSPORT_NSC_H_ */
