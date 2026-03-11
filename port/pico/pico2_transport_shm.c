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
 * port/pico-2/pico2_transport_shm.c
 *
 * Implementation of transport callbacks for Raspberry Pi Pico-2 using
 * shared memory between two cores.
 */

#include <string.h>
#include <stdint.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_comm.h"

#include "pico2_transport_shm.h"

/** Header structure for shared memory layout */
#define PICO2_SHM_HEADER_SIZE 32
typedef union {
    struct {
        uint32_t initialized; /* Set non-zero when setup complete */
        uint16_t req_size;    /* Size of request buffer */
        uint16_t resp_size;   /* Size of response buffer */
        size_t   dma_size;    /* Size of shared DMA space */
    };
    uint8_t WH_PAD[PICO2_SHM_HEADER_SIZE];
} pico2ShmHeader;

typedef struct {
    void*            ptr;
    size_t           size;
    pico2ShmHeader*  header;
    uint8_t*         req;
    uint8_t*         resp;
    uint8_t*         dma;
    size_t           dma_size;
    uint16_t         req_size;
    uint16_t         resp_size;
} pico2ShmMapping;

enum {
    PICO2_INITIALIZED_NONE      = 0,
    PICO2_INITIALIZED_CREATOR   = 1,
    PICO2_INITIALIZED_USER      = 2,
};

/**
 * @brief Initialize the header and buffers in shared memory
 *
 * This function calculates the layout of the shared memory region and
 * initializes the header structure.
 *
 * @param[in] cfg Pointer to configuration structure
 * @param[out] map Pointer to mapping structure to fill
 * @return WH_ERROR_OK on success, or error code on failure
 */
static int pico2TransportShm_MapMemory(const pico2TransportShmConfig* cfg,
                                       pico2ShmMapping* map)
{
    if ((cfg == NULL) || (map == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if ((cfg->shared_mem == NULL) || (cfg->shared_mem_size == 0) ||
        (cfg->req_size == 0) || (cfg->resp_size == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Calculate required size with overflow check */
    if ((SIZE_MAX - PICO2_SHM_HEADER_SIZE < cfg->req_size) ||
        (SIZE_MAX - PICO2_SHM_HEADER_SIZE - cfg->req_size < cfg->resp_size) ||
        (SIZE_MAX - PICO2_SHM_HEADER_SIZE - cfg->req_size - cfg->resp_size < cfg->dma_size)) {
        return WH_ERROR_BADARGS;
    }
    size_t required_size = PICO2_SHM_HEADER_SIZE + cfg->req_size +
                           cfg->resp_size + cfg->dma_size;

    if (cfg->shared_mem_size < required_size) {
        return WH_ERROR_BADARGS;
    }

    memset(map, 0, sizeof(*map));

    /* Set up the mapping */
    map->ptr       = (void*)cfg->shared_mem;
    map->size      = cfg->shared_mem_size;
    map->header    = (pico2ShmHeader*)map->ptr;
    map->req       = (uint8_t*)(map->header + 1);
    map->resp      = map->req + cfg->req_size;
    map->dma       = map->resp + cfg->resp_size;
    map->dma_size  = cfg->dma_size;
    map->req_size  = cfg->req_size;
    map->resp_size = cfg->resp_size;

    return WH_ERROR_OK;
}

/** Core synchronization primitives for Pico-2 */

/**
 * @brief Memory barrier to ensure memory operations are visible across cores
 *
 * This is a simple implementation using volatile access and inline assembly.
 * For Pico-2, we use a compiler barrier and optional hardware fence.
 */
static inline void pico2TransportShm_MemoryBarrier(void)
{
    /* Compiler barrier */
    asm volatile("" : : : "memory");

    #ifdef WOLFHSM_CFG_PICO2_DMB
    /* Optional data memory barrier for strict ordering */
    asm volatile("dmb" : : : "memory");
    #endif
}

/**
 * @brief Flush a region from cache (if applicable)
 *
 * On Pico-2, this is a no-op for non-cached memory, but included for
 * compatibility with other ports.
 */
static inline void pico2TransportShm_CacheFlush(void* ptr, size_t len)
{
    (void)ptr;
    (void)len;
    /* Pico-2 cores typically don't have separate caches for shared SRAM */
}

/**
 * @brief Invalidate cache for a region (if applicable)
 *
 * On Pico-2, this is a no-op for non-cached memory, but included for
 * compatibility with other ports.
 */
static inline void pico2TransportShm_CacheInvalidate(void* ptr, size_t len)
{
    (void)ptr;
    (void)len;
    /* Pico-2 cores typically don't have separate caches for shared SRAM */
}

#if defined(WOLFHSM_CFG_ENABLE_SERVER)

/**
 * @brief Server initialization - creates the shared memory layout
 *
 * @param[in] c Pointer to the transport context
 * @param[in] cf Pointer to the configuration structure
 * @param[in] connectcb Connection callback (optional)
 * @param[in] connectcb_arg Argument for connection callback
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    int ret = WH_ERROR_OK;
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;
    const pico2TransportShmConfig* cfg = (const pico2TransportShmConfig*)cf;
    pico2ShmMapping map[1] = {0};
    whTransportMemConfig tmcfg[1] = {0};

    if ((ctx == NULL) || (cfg == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Map the shared memory */
    ret = pico2TransportShm_MapMemory(cfg, map);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Initialize and clear the buffers */
    memset(map->header, 0, PICO2_SHM_HEADER_SIZE);
    memset(map->req, 0, cfg->req_size);
    memset(map->resp, 0, cfg->resp_size);
    if (cfg->dma_size > 0) {
        memset(map->dma, 0, cfg->dma_size);
    }

    /* Set up the header */
    map->header->req_size  = cfg->req_size;
    map->header->resp_size = cfg->resp_size;
    map->header->dma_size  = cfg->dma_size;
    pico2TransportShm_MemoryBarrier();
    map->header->initialized = PICO2_INITIALIZED_CREATOR;

    /* Configure the underlying transport context */
    tmcfg->req       = map->req;
    tmcfg->req_size  = cfg->req_size;
    tmcfg->resp      = map->resp;
    tmcfg->resp_size = cfg->resp_size;

    /* Initialize the shared memory transport */
    ret = wh_TransportMem_Init(ctx->transportMemCtx, tmcfg, NULL, NULL);
    if (ret == WH_ERROR_OK) {
        ctx->state             = PICO2_SHM_STATE_INITIALIZED;
        ctx->shared_mem        = cfg->shared_mem;
        ctx->shared_mem_size   = cfg->shared_mem_size;
        ctx->req               = map->req;
        ctx->resp              = map->resp;
        ctx->dma               = map->dma;
        ctx->dma_size          = cfg->dma_size;
        ctx->req_size          = cfg->req_size;
        ctx->resp_size         = cfg->resp_size;
        ctx->connectcb         = connectcb;
        ctx->connectcb_arg     = connectcb_arg;

        /* Signal connection if callback is provided */
        if (connectcb != NULL) {
            connectcb(connectcb_arg, WH_COMM_CONNECTED);
        }
    }

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)

/**
 * @brief Client initialization - connects to existing shared memory
 *
 * The client waits for the server to initialize the shared memory layout.
 *
 * @param[in] c Pointer to the transport context
 * @param[in] cf Pointer to the configuration structure
 * @param[in] connectcb Connection callback (optional)
 * @param[in] connectcb_arg Argument for connection callback
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    int ret = WH_ERROR_OK;
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;
    const pico2TransportShmConfig* cfg = (const pico2TransportShmConfig*)cf;
    pico2ShmMapping map[1] = {0};
    whTransportMemConfig tmcfg[1] = {0};
    uint32_t max_retries = 10000;  /* Allow time for server to initialize */
    uint32_t retry_count = 0;

    if ((ctx == NULL) || (cfg == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Map the shared memory */
    ret = pico2TransportShm_MapMemory(cfg, map);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Wait for server to initialize */
    while ((map->header->initialized != PICO2_INITIALIZED_CREATOR) &&
           (retry_count < max_retries)) {
        retry_count++;
        pico2TransportShm_MemoryBarrier();
    }

    if (map->header->initialized != PICO2_INITIALIZED_CREATOR) {
        return WH_ERROR_NOTREADY;
    }

    /* Validate server configuration matches client configuration */
    if ((map->header->req_size != cfg->req_size) ||
        (map->header->resp_size != cfg->resp_size) ||
        (map->header->dma_size != cfg->dma_size)) {
        return WH_ERROR_BADARGS;
    }

    /* Configure the underlying transport context */
    tmcfg->req       = map->req;
    tmcfg->req_size  = map->header->req_size;
    tmcfg->resp      = map->resp;
    tmcfg->resp_size = map->header->resp_size;

    /* Initialize the shared memory transport with clear */
    ret = wh_TransportMem_InitClear(ctx->transportMemCtx, tmcfg, NULL, NULL);
    if (ret == WH_ERROR_OK) {
        ctx->state             = PICO2_SHM_STATE_INITIALIZED;
        ctx->shared_mem        = cfg->shared_mem;
        ctx->shared_mem_size   = cfg->shared_mem_size;
        ctx->req               = map->req;
        ctx->resp              = map->resp;
        ctx->dma               = map->dma;
        ctx->dma_size          = map->header->dma_size;
        ctx->req_size          = map->header->req_size;
        ctx->resp_size         = map->header->resp_size;
        ctx->connectcb         = connectcb;
        ctx->connectcb_arg     = connectcb_arg;

        /* Mark as user initialized */
        pico2TransportShm_MemoryBarrier();
        map->header->initialized = PICO2_INITIALIZED_USER;

        /* Signal connection if callback is provided */
        if (connectcb != NULL) {
            connectcb(connectcb_arg, WH_COMM_CONNECTED);
        }
    }

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

/**
 * @brief Cleanup the transport context
 *
 * @param[in] c Pointer to the transport context
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_Cleanup(void* c)
{
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Clean up the underlying transport context */
    (void)wh_TransportMem_Cleanup(ctx->transportMemCtx);

    ctx->state = PICO2_SHM_STATE_DONE;

    return WH_ERROR_OK;
}

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)

/**
 * @brief Send a request from client to server
 *
 * @param[in] c Pointer to the transport context
 * @param[in] len Length of the request data
 * @param[in] data Pointer to the request data
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_SendRequest(void* c, uint16_t len, const void* data)
{
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;

    if ((ctx == NULL) || (ctx->state != PICO2_SHM_STATE_INITIALIZED)) {
        return WH_ERROR_BADARGS;
    }

    /* Ensure memory operations are visible to the server */
    pico2TransportShm_MemoryBarrier();

    return wh_TransportMem_SendRequest(ctx->transportMemCtx, len, data);
}

/**
 * @brief Receive a response from server to client
 *
 * @param[in] c Pointer to the transport context
 * @param[out] out_len Pointer to store the response length
 * @param[out] data Pointer to store the response data
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;

    if ((ctx == NULL) || (ctx->state != PICO2_SHM_STATE_INITIALIZED)) {
        return WH_ERROR_BADARGS;
    }

    /* Ensure we see updates from the server */
    pico2TransportShm_CacheInvalidate(ctx->resp, ctx->resp_size);
    pico2TransportShm_MemoryBarrier();

    return wh_TransportMem_RecvResponse(ctx->transportMemCtx, out_len, data);
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#if defined(WOLFHSM_CFG_ENABLE_SERVER)

/**
 * @brief Receive a request from client on server
 *
 * @param[in] c Pointer to the transport context
 * @param[out] out_len Pointer to store the request length
 * @param[out] data Pointer to store the request data
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;

    if ((ctx == NULL) || (ctx->state != PICO2_SHM_STATE_INITIALIZED)) {
        return WH_ERROR_BADARGS;
    }

    /* Ensure we see updates from the client */
    pico2TransportShm_CacheInvalidate(ctx->req, ctx->req_size);
    pico2TransportShm_MemoryBarrier();

    return wh_TransportMem_RecvRequest(ctx->transportMemCtx, out_len, data);
}

/**
 * @brief Send a response from server to client
 *
 * @param[in] c Pointer to the transport context
 * @param[in] len Length of the response data
 * @param[in] data Pointer to the response data
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_SendResponse(void* c, uint16_t len, const void* data)
{
    pico2TransportShmContext* ctx = (pico2TransportShmContext*)c;

    if ((ctx == NULL) || (ctx->state != PICO2_SHM_STATE_INITIALIZED)) {
        return WH_ERROR_BADARGS;
    }

    /* Ensure memory operations are visible to the client */
    pico2TransportShm_CacheFlush(ctx->resp, ctx->resp_size);
    pico2TransportShm_MemoryBarrier();

    return wh_TransportMem_SendResponse(ctx->transportMemCtx, len, data);
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */

/**
 * @brief Get DMA buffer information
 *
 * @param[in] ctx Pointer to the transport context
 * @param[out] out_dma Pointer to store DMA buffer address
 * @param[out] out_size Pointer to store DMA buffer size
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_GetDma(pico2TransportShmContext* ctx,
                            void* *out_dma, size_t *out_size)
{
    if ((ctx == NULL) || (out_dma == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    *out_dma = ctx->dma;
    *out_size = ctx->dma_size;

    return WH_ERROR_OK;
}

/**
 * @brief Set heap hint for DMA operations
 *
 * @param[in] ctx Pointer to the transport context
 * @param[in] heap Pointer to the heap hint
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_SetDmaHeap(pico2TransportShmContext* ctx, void* heap)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->heap = heap;
    return WH_ERROR_OK;
}

/**
 * @brief Get heap hint for DMA operations
 *
 * @param[in] ctx Pointer to the transport context
 * @return Pointer to the heap hint or NULL
 */
void* pico2TransportShm_GetDmaHeap(pico2TransportShmContext* ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->heap;
}

/** DMA callback implementations */
#ifdef WOLFHSM_CFG_DMA

#include "wolfhsm/wh_dma.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

/**
 * @brief Server DMA callback for static shared memory
 *
 * @param[in] server Pointer to server context
 * @param[in] clientAddr Client address for DMA operation
 * @param[out] xformedCliAddr Transformed client address
 * @param[in] len Length of data for DMA operation
 * @param[in] oper DMA operation type
 * @param[in] flags DMA operation flags
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ServerStaticMemDmaCallback(
    whServerContext* server, uintptr_t clientAddr, void** xformedCliAddr,
    size_t len, whServerDmaOper oper, whServerDmaFlags flags)
{
    pico2TransportShmContext* ctx = NULL;

    (void)oper;
    (void)flags;

    if ((server == NULL) || (xformedCliAddr == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Get transport context from server */
    ctx = (pico2TransportShmContext*)server->transport_context;

    if ((ctx == NULL) || (ctx->dma == NULL) || (ctx->dma_size == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Verify the address is within DMA buffer */
    if ((clientAddr < (uintptr_t)ctx->dma) || (len > ctx->dma_size) ||
        ((clientAddr - (uintptr_t)ctx->dma) > (ctx->dma_size - len))) {
        return WH_ERROR_BADARGS;
    }

    /* Address is already in shared memory, no transformation needed */
    *xformedCliAddr = (void*)clientAddr;

    return WH_ERROR_OK;
}

/**
 * @brief Client DMA callback for static shared memory
 *
 * @param[in] client Pointer to client context
 * @param[in] clientAddr Client address for DMA operation
 * @param[out] xformedCliAddr Transformed client address
 * @param[in] len Length of data for DMA operation
 * @param[in] oper DMA operation type
 * @param[in] flags DMA operation flags
 * @return WH_ERROR_OK on success, or error code on failure
 */
int pico2TransportShm_ClientStaticMemDmaCallback(whClientContext* client,
                                                 uintptr_t        clientAddr,
                                                 void** xformedCliAddr,
                                                 size_t len, whDmaOper oper,
                                                 whDmaFlags flags)
{
    pico2TransportShmContext* ctx = NULL;

    (void)oper;
    (void)flags;

    if ((client == NULL) || (xformedCliAddr == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Get transport context from client */
    ctx = (pico2TransportShmContext*)client->transport_context;

    if ((ctx == NULL) || (ctx->dma == NULL) || (ctx->dma_size == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Verify the address is within DMA buffer */
    if ((clientAddr < (uintptr_t)ctx->dma) || (len > ctx->dma_size) ||
        ((clientAddr - (uintptr_t)ctx->dma) > (ctx->dma_size - len))) {
        return WH_ERROR_BADARGS;
    }

    /* Address is already in shared memory, no transformation needed */
    *xformedCliAddr = (void*)clientAddr;

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_DMA */
