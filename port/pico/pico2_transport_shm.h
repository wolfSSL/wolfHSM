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
 * port/pico-2/pico2_transport_shm.h
 *
 * wolfHSM Transport Mem binding using Raspberry Pi Pico-2 shared memory
 *
 * For this implementation, shared memory is accessed between two cores on the
 * Pico-2 microcontroller. Each core has access to the same RAM regions. The
 * server (typically Core 0) creates the shared memory buffers and the client
 * (typically Core 1) connects to them.
 *
 * The implementation uses a header structure to store configuration and
 * synchronization information, followed by request and response buffers.
 * Optionally, a DMA section can be allocated for DMA operations.
 *
 * Core-to-core synchronization is handled through simple spinlock mechanisms
 * and memory barriers to ensure coherence between cores.
 */

#ifndef PORT_PICO2_PICO2_TRANSPORT_SHM_H_
#define PORT_PICO2_PICO2_TRANSPORT_SHM_H_

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Pico-2 SHM configuration structure */
typedef struct {
    uint16_t    req_size;      /* Request buffer size */
    uint16_t    resp_size;     /* Response buffer size */
    size_t      dma_size;      /* DMA buffer size (optional) */
    void*       shared_mem;    /* Base address of shared memory region (must be 4-byte aligned) */
    size_t      shared_mem_size; /* Total size of shared memory region */
} pico2TransportShmConfig;

/** Pico-2 SHM context state */
typedef enum {
    PICO2_SHM_STATE_NONE = 0,        /* Not initialized */
    PICO2_SHM_STATE_INITIALIZED,     /* Initialized and ready */
    PICO2_SHM_STATE_DONE,            /* Cleanup complete */
} pico2TransportShmState;

/** Pico-2 SHM context */
typedef struct {
    pico2TransportShmState  state;
    void*                   shared_mem;
    size_t                  shared_mem_size;
    uint8_t*                req;
    uint8_t*                resp;           
    uint8_t*                dma;
    size_t                  dma_size;
    uint16_t                req_size;
    uint16_t                resp_size;
    whTransportMemContext   transportMemCtx[1];
    whCommSetConnectedCb    connectcb;
    void*                   connectcb_arg;
    void*                   heap;      /* heap hint used in pass by reference */
} pico2TransportShmContext;

/** Type aliases for client and server contexts */
typedef pico2TransportShmContext pico2TransportShmClientContext;
typedef pico2TransportShmContext pico2TransportShmServerContext;

/** Custom getter functions */

/**
 * @brief Get DMA buffer information from context
 *
 * @param[in] ctx Pointer to the transport context.
 * @param[out] out_dma Pointer to store DMA buffer address
 * @param[out] out_size Pointer to store DMA buffer size
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_GetDma(pico2TransportShmContext* ctx,
        void** out_dma, size_t *out_size);

/**
 * @brief Set heap hint for DMA operations
 *
 * @param[in] ctx Pointer to the transport context.
 * @param[in] heap Pointer to the heap hint
 * @return WH_ERROR_OK on success, or WH_ERROR_BADARGS on error
 */
int pico2TransportShm_SetDmaHeap(pico2TransportShmContext* ctx, void* heap);

/**
 * @brief Get heap hint for DMA operations
 *
 * @param[in] ctx Pointer to the transport context.
 * @return Pointer to the heap hint or NULL
 */
void* pico2TransportShm_GetDmaHeap(pico2TransportShmContext* ctx);

/** Transport callback function declarations */

/**
 * @brief Client initialization callback
 *
 * @param[in] c Pointer to the transport context.
 * @param[in] cf Pointer to the transport configuration.
 * @param[in] connectcb Connection callback function (optional).
 * @param[in] connectcb_arg Argument for connection callback.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);

/**
 * @brief Server initialization callback
 *
 * @param[in] c Pointer to the transport context.
 * @param[in] cf Pointer to the transport configuration.
 * @param[in] connectcb Connection callback function (optional).
 * @param[in] connectcb_arg Argument for connection callback.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);

/**
 * @brief Cleanup callback
 *
 * @param[in] c Pointer to the transport context.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_Cleanup(void* c);

/**
 * @brief Send request callback
 *
 * @param[in] c Pointer to the transport context.
 * @param[in] len Length of the request data.
 * @param[in] data Pointer to the request data.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_SendRequest(void* c, uint16_t len, const void* data);

/**
 * @brief Receive request callback
 *
 * @param[in] c Pointer to the transport context.
 * @param[out] out_len Pointer to store the received data length.
 * @param[out] data Pointer to store the received data.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_RecvRequest(void* c, uint16_t* out_len, void* data);

/**
 * @brief Send response callback
 *
 * @param[in] c Pointer to the transport context.
 * @param[in] len Length of the response data.
 * @param[in] data Pointer to the response data.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_SendResponse(void* c, uint16_t len, const void* data);

/**
 * @brief Receive response callback
 *
 * @param[in] c Pointer to the transport context.
 * @param[out] out_len Pointer to store the received data length.
 * @param[out] data Pointer to store the received data.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_RecvResponse(void* c, uint16_t* out_len, void* data);

/** Callback macros for client and server configurations */

#define PICO2_TRANSPORT_SHM_CLIENT_CB              \
    {                                              \
        .Init    = pico2TransportShm_ClientInit,   \
        .Send    = pico2TransportShm_SendRequest,  \
        .Recv    = pico2TransportShm_RecvResponse, \
        .Cleanup = pico2TransportShm_Cleanup,      \
    }

#define PICO2_TRANSPORT_SHM_SERVER_CB              \
    {                                              \
        .Init    = pico2TransportShm_ServerInit,   \
        .Recv    = pico2TransportShm_RecvRequest,  \
        .Send    = pico2TransportShm_SendResponse, \
        .Cleanup = pico2TransportShm_Cleanup,      \
    }

/** DMA callback support */
#ifdef WOLFHSM_CFG_DMA

#include "wolfhsm/wh_dma.h"
#include "wolfhsm/wh_server.h"

/**
 * @brief Server DMA callback using static shared memory
 *
 * @param[in] server Pointer to server context.
 * @param[in] clientAddr Client address for DMA operation.
 * @param[out] xformedCliAddr Transformed client address.
 * @param[in] len Length of data for DMA operation.
 * @param[in] oper DMA operation type.
 * @param[in] flags DMA operation flags.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ServerStaticMemDmaCallback(
    whServerContext* server, uintptr_t clientAddr, void** xformedCliAddr,
    size_t len, whServerDmaOper oper, whServerDmaFlags flags);

#include "wolfhsm/wh_client.h"

/**
 * @brief Client DMA callback using static shared memory
 *
 * @param[in] client Pointer to client context.
 * @param[in] clientAddr Client address for DMA operation.
 * @param[out] xformedCliAddr Transformed client address.
 * @param[in] len Length of data for DMA operation.
 * @param[in] oper DMA operation type.
 * @param[in] flags DMA operation flags.
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ClientStaticMemDmaCallback(whClientContext* client,
                                                 uintptr_t        clientAddr,
                                                 void** xformedCliAddr,
                                                 size_t len, whDmaOper oper,
                                                 whDmaFlags flags);

#endif /* WOLFHSM_CFG_DMA */

#ifdef __cplusplus
}
#endif

#endif /* !PORT_PICO2_PICO2_TRANSPORT_SHM_H_ */
