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
 * wolfhsm/wh_transport_mem.h
 *
 * wolfHSM Transport binding using 2 memory blocks
 */

/* Memory block comms
 * Client and server each have access to a shared memory, which is split into
 * request and response buffers.  The top 64-bits of each buffer provide control
 * and status registers that are used to convey flow control.
 *
 * The client generally writes to the request buffer and reads from the response
 * buffer.  The server generally reads from the request buffer and writes to
 * the response buffer.
 *
 * The client sends a request by:
 *  1. Receive the previous response to ensure completion.
 *  2. Writes request data: req->data[] = data[]
 *  3. Increments requestid: req_id = req->notify++
 *  4. Optionally sends notify interrupt to server.
 *
 * The client receives a response to req_id by:
 *  1. Check if the request is complete: resp->notify == req_id
 *  2. Read response data: data[] = resp->data[]
 *
 * The server handles a request by:
 *  1. Check for new request: req->notify != resp->notify
 *  2. Read request data: data[] = req->data[]
 *  3. Save requestid: req_id = req->notify
 *
 * The server sends a response by:
 *  1. Write response data: resp->data[] = data[]
 *  2. Set response id to requestid: resp->notify = req_id
 *  3. Optionally send notify interrupt to client
 *
 *
 * Example usage:
 *
 * uint8_t req_buffer[4096];
 * uint8_t resp_buffer[4096];
 *
 * whTransportMemConfig tmcfg[1] = {{
 *      .req = req_buffer,
 *      .req_size = sizeof(req_buffer),
 *      .resp = resp_buffer
 *      .resp_size = sizeof(resp_buffer),
 * }};
 *
 * whTransportClientCb tmccb[1] = {WH_TRANSPORT_MEM_CLIENT_CB};
 * whTransportMemClientContext tmcc[1] = {0};
 * whCommClientConfig ccc[1] = {{
 *      .transport_cb = tmccb,
 *      .transport_context = tmcc,
 *      .transport_config = tmcfg,
 *      .client_id = 1234,
 * }};
 * whCommClient cc[1] = {0};
 * wh_CommClient_Init(cc, ccc);
 *
 * whTransportServerCb tmscb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
 * whTransportMemServerContext tmsc[1] = {0};
 * whCommServerConfig csc[1] = {{
 *      .transport_cb = tmscb,
 *      .transport_context = tmsc,
 *      .transport_config = tmcfg,
 *      .server_id = 5678,
 * }};
 * whCommServer cs[1] = {0};
 * wh_CommServer_Init(cs, csc);
 *
 */

#ifndef WOLFHSM_WH_TRANSPORT_MEM_H_
#define WOLFHSM_WH_TRANSPORT_MEM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_comm.h"

/** Common configuration structure */
typedef struct {
    void* req;
    void* resp;
    uint16_t req_size;
    uint16_t resp_size;
    uint8_t WH_PAD[4];
} whTransportMemConfig;


/** Common context */

/* Memory buffer control/status layout.  Data buffer follows immediately */
typedef union whTransportMemCsr_t {
    uint64_t u64;
    struct {
        uint16_t notify;   /* Incremented to notify */
        uint16_t len;      /* Length of data */
        uint16_t ack;      /* Opt: Acknowledge the reverse notify */
        uint16_t wait;     /* Opt: Incremented while waiting*/
    } s;
} whTransportMemCsr;

typedef struct {
    volatile whTransportMemCsr* req;
    volatile whTransportMemCsr* resp;
    void* req_data;
    void* resp_data;
    int initialized;
    uint16_t req_size;
    uint16_t resp_size;
} whTransportMemContext;

/* Naming conveniences. Reuses the same types. */
typedef whTransportMemContext whTransportMemClientContext;
typedef whTransportMemContext whTransportMemServerContext;

/** Callback function declarations */
int wh_TransportMem_Init(void* c, const void* cf,
        whCommSetConnectedCb connectcb, void* connectcb_arg);
int wh_TransportMem_InitClear(void* c, const void* cf,
        whCommSetConnectedCb connectcb, void* connectcb_arg);
int wh_TransportMem_Cleanup(void* c);
int wh_TransportMem_SendRequest(void* c, uint16_t len, const void* data);
int wh_TransportMem_RecvRequest(void* c, uint16_t *out_len, void* data);
int wh_TransportMem_SendResponse(void* c, uint16_t len, const void* data);
int wh_TransportMem_RecvResponse(void* c, uint16_t *out_len, void* data);

#define WH_TRANSPORT_MEM_CLIENT_CB              \
{                                               \
    .Init =     wh_TransportMem_InitClear,      \
    .Send =     wh_TransportMem_SendRequest,    \
    .Recv =     wh_TransportMem_RecvResponse,   \
    .Cleanup =  wh_TransportMem_Cleanup,        \
}

#define WH_TRANSPORT_MEM_SERVER_CB              \
{                                               \
    .Init =     wh_TransportMem_Init,           \
    .Recv =     wh_TransportMem_RecvRequest,    \
    .Send =     wh_TransportMem_SendResponse,   \
    .Cleanup =  wh_TransportMem_Cleanup,        \
}


#endif /* !WOLFHSM_WH_TRANSPORT_MEM_H_ */
