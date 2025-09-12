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
 * port/posix_transport_dma.h
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

#ifndef PORT_POSIX_POSIX_TRANSPORT_SHM_REFERENCE_H_
#define PORT_POSIX_POSIX_TRANSPORT_SHM_REFERENCE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <limits.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "port/posix/posix_transport_shm.h"

/* Naming conveniences. Reuses the same types. */
typedef posixTransportShmContext posixTransportRefClientContext;
typedef posixTransportShmContext posixTransportRefServerContext;
typedef posixTransportShmConfig posixTransportRefConfig;

/** Custom functions */
int posixTransportShm_GetHeapHint(posixTransportShmContext* ctx,
    void** out_hint);

#include "wolfhsm/wh_server.h"
int wh_Server_PosixStaticMemoryDMA(whServerContext* server, uintptr_t clientAddr,
        void** xformedCliAddr, size_t len, whServerDmaOper oper,
        whServerDmaFlags flags);

#include "wolfhsm/wh_client.h"
int wh_Client_PosixStaticMemoryDMA(whClientContext* client, uintptr_t clientAddr,
    void** xformedCliAddr, size_t len, whClientDmaOper oper,
    whClientDmaFlags flags);

/** Callback function declarations */
int posixTransportShm_ClientInitReference(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);
int posixTransportShm_ServerInitReference(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);

int posixTransportShm_CleanupReference(void* c);

#ifdef WOLFSSL_STATIC_MEMORY
#define POSIX_TRANSPORT_DMA_CLIENT_CB       \
    {                                              \
        .Init    = posixTransportShm_ClientInitReference,   \
        .Send    = posixTransportShm_SendRequest,  \
        .Recv    = posixTransportShm_RecvResponse, \
        .Cleanup = posixTransportShm_CleanupReference,      \
    }

#define POSIX_TRANSPORT_DMA_SERVER_CB      \
    {                                              \
        .Init    = posixTransportShm_ServerInitReference, \
        .Recv    = posixTransportShm_RecvRequest,  \
        .Send    = posixTransportShm_SendResponse, \
        .Cleanup = posixTransportShm_Cleanup,      \
    }
#endif

#endif /* !PORT_POSIX_POSIX_TRANSPORT_SHM_REFERENCE_H_ */
