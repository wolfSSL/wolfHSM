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
 * port/posix_transport_shm.h
 *
 * wolfHSM Transport Mem binding using POSIX shared memory functionality
 *
 * For this implementation, the server creates a POSIX shared memory object
 * named config->name of a size to hold a common header block, the request and
 * response buffers, and an optional DMA section.  Note POSIX specifies the
 * name should start with "/", include no other "/" characters, and be less than
 * NAME_MAX (limits.h) long.
 *
 * Once the server creates the named shared memory object, it sets the full
 * size, maps it, and updates the header block with the configured sizes. After
 * completing updates to the header block, it then builds a TransportMem
 * server context using the request and response buffers.  Note the server will
 * attempt to unlink the named shared memory object prior to creation.
 *
 * The client is configured with only the name of the shared object and it busy-
 * retries to open the named shared object, once in the client_init() and
 * subsequently in send_request(), if the mapping was unsuccessful due to a late
 * server.  It then maps the header block, reads the configuration sizes, and
 * configures a TransportMem client context. The client also unlinks the shared
 * object on successful mapping.
 *
 * Both the server and the client also provide their process ids within the
 * header block to support asynchronous signalling using POSIX RT signals.
 *
 * The optional DMA block is intended to allow the client to use the DMA
 * versions of requests by configuring the base address of the DMA request to be
 * the mapped address of the DMA block.
 *
 */

#ifndef PORT_POSIX_POSIX_TRANSPORT_SHM_H_
#define PORT_POSIX_POSIX_TRANSPORT_SHM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <limits.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

/** POSIX SHM configuration structure */
typedef struct {
    char*       name; /* Null terminated, up to NAME_MAX */
    size_t      dma_size;
    uint16_t    req_size;
    uint16_t    resp_size;
} posixTransportShmConfig;


/** POSIX SHM context */
typedef enum {
    PTSHM_STATE_NONE = 0,       /* Not opened, not mapped */
    PTSHM_STATE_MAPPED,         /* Opened and mapped, no client */
    PTSHM_STATE_INITIALIZED,    /* Fully initialized */
    PTSHM_STATE_DONE,           /* Closed and complete */
} posixTransportShmState;

typedef struct {
    char                    name[NAME_MAX];
    posixTransportShmState  state;
    void*                   ptr;
    size_t                  size;
    uint8_t*                dma;
    size_t                  dma_size;
    whTransportMemContext   transportMemCtx[1];
    whCommSetConnectedCb    connectcb;
    void*                   connectcb_arg;
} posixTransportShmContext;

/* Naming conveniences. Reuses the same types. */
typedef posixTransportShmContext posixTransportShmClientContext;
typedef posixTransportShmContext posixTransportShmServerContext;

/** Custom functions */
int posixTransportShm_IsConnected(posixTransportShmContext* ctx,
        whCommConnected *out_connected);

int posixTransportShm_GetCreatorPid(posixTransportShmContext* ctx,
        pid_t *out_pid);
int posixTransportShm_GetUserPid(posixTransportShmContext* ctx,
        pid_t *out_pid);

int posixTransportShm_GetDma(posixTransportShmContext* ctx,
        void* *out_dma, size_t *out_size);


/** Callback function declarations */
int posixTransportShm_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);
int posixTransportShm_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);

int posixTransportShm_Cleanup(void* c);
int posixTransportShm_SendRequest(void* c, uint16_t len, const void* data);
int posixTransportShm_RecvRequest(void* c, uint16_t* out_len, void* data);
int posixTransportShm_SendResponse(void* c, uint16_t len, const void* data);
int posixTransportShm_RecvResponse(void* c, uint16_t* out_len, void* data);

#define POSIX_TRANSPORT_SHM_CLIENT_CB              \
    {                                              \
        .Init    = posixTransportShm_ClientInit,   \
        .Send    = posixTransportShm_SendRequest,  \
        .Recv    = posixTransportShm_RecvResponse, \
        .Cleanup = posixTransportShm_Cleanup,      \
    }

#define POSIX_TRANSPORT_SHM_SERVER_CB              \
    {                                              \
        .Init    = posixTransportShm_ServerInit,   \
        .Recv    = posixTransportShm_RecvRequest,  \
        .Send    = posixTransportShm_SendResponse, \
        .Cleanup = posixTransportShm_Cleanup,      \
    }


#endif /* !PORT_POSIX_POSIX_TRANSPORT_SHM_H_ */
