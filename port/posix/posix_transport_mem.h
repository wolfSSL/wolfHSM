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
 * port/posix_transport_mem.h
 *
 * wolfHSM Transport Mem binding using POSIX shared memory
 */

/* Memory block comms
 * Example usage:
 *
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

#ifndef PORT_POSIX_POSIX_TRANSPORT_MEM_H_
#define PORT_POSIX_POSIX_TRANSPORT_MEM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_comm.h"

/** Common configuration structure */
typedef struct {
    char*    shmFileName; /* Null terminated, up to NAME_MAX */
    uint16_t req_size;
    uint16_t resp_size;
    uint8_t  WH_PAD[4];
} posixTransportMemConfig;


/** Common context */

typedef struct {
    char*                  shmFileName;
    void*                  shmBuf;
    whTransportMemContext* transport_ctx;
} posixTransportMemContext;

/* Naming conveniences. Reuses the same types. */
typedef posixTransportMemContext posixTransportMemClientContext;
typedef posixTransportMemContext posixTransportMemServerContext;

/** Callback function declarations */
int posixTransportMem_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);
int posixTransportMem_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);

int posixTransportMem_Cleanup(void* c);
int posixTransportMem_SendRequest(void* c, uint16_t len, const void* data);
int posixTransportMem_RecvRequest(void* c, uint16_t* out_len, void* data);
int posixTransportMem_SendResponse(void* c, uint16_t len, const void* data);
int posixTransportMem_RecvResponse(void* c, uint16_t* out_len, void* data);

#define POSIX_TRANSPORT_MEM_CLIENT_CB              \
    {                                              \
        .Init    = posixTransportMem_ClientInit,   \
        .Send    = posixTransportMem_SendRequest,  \
        .Recv    = posixTransportMem_RecvResponse, \
        .Cleanup = posixTransportMem_Cleanup,      \
    }

#define POSIX_TRANSPORT_MEM_SERVER_CB              \
    {                                              \
        .Init    = posixTransportMem_ServerInit,   \
        .Recv    = posixTransportMem_RecvRequest,  \
        .Send    = posixTransportMem_SendResponse, \
        .Cleanup = posixTransportMem_Cleanup,      \
    }


#endif /* !PORT_POSIX_POSIX_TRANSPORT_MEM_H_ */
