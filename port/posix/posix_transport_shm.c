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
 * port/posix/posix_transport_shm.c
 */

#include <fcntl.h>     /* For O_* constants */
#include <sys/mman.h>  /* For shm_open, mmap */
#include <sys/stat.h>  /* For mode constants */
#include <unistd.h>    /* For ftruncate, getpid, sleep */
#include <errno.h>     /* For errno */
#include <stdlib.h>    /* For exit */
#include <string.h>    /* For memset */
#include <stdint.h>
#include <stdio.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "port/posix/posix_transport_shm.h"

/* Shared memory creation flags */
#define PTSHM_CREATEMODE 0666

/* Pad header to reasonable alignment */
#define PTSHM_HEADER_SIZE 64
typedef union {
    struct {
        uint32_t initialized;   /* Set non-zero when setup */
        uint16_t req_size;      /* Size of request buffer */
        uint16_t resp_size;     /* Size of response buffer */
        size_t dma_size;        /* Size of shared DMA space */
        pid_t creator_pid;      /* Process ID of the creator */
        pid_t user_pid;         /* Process ID of user */
    };
    uint8_t WH_PAD[PTSHM_HEADER_SIZE];
} ptshmHeader;

typedef struct {
    void* ptr;
    size_t size;
    ptshmHeader* header;
    uint8_t* req;
    uint8_t* resp;
    uint8_t* dma;
    size_t dma_size;
    uint16_t req_size;
    uint16_t resp_size;
} ptshmMapping;

enum {
    PTSHM_INITIALIZED_NONE      = 0,
    PTSHM_INITIALIZED_CLEANUP   = 1,
    PTSHM_INITIALIZED_CREATOR   = 2,
    PTSHM_INITIALIZED_USER      = 3,
};
/** Local declarations */

/* Memory map and interpret the header block */
static int posixTransportShm_Map(int fd, size_t size, ptshmMapping* map);

#if defined(WOLFHSM_CFG_ENABLE_SERVER)
/* Create and map a shared object for transport */
static int posixTransportShm_CreateMap(char* name, uint16_t req_size,
        uint16_t resp_size, size_t dma_size, ptshmMapping* map);
#endif

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
/* Use and map a shared object for transport */
static int posixTransportShm_UseMap(char* name, ptshmMapping* map);

/* Map the shared object if not already mapped */
static int posixTransportShm_HandleMap(posixTransportShmContext *ctx);
#endif

/** Local Definitions */
static int posixTransportShm_Map(int fd, size_t size, ptshmMapping* map)
{
    int ret = WH_ERROR_OK;
    void* ptr = NULL;

    if (    (fd < 0) ||
            (map == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* Map the shared memory object */
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr != MAP_FAILED) {
        memset(map, 0, sizeof(*map));
        map->ptr = ptr;
        map->size = size;
        map->header = (ptshmHeader*)ptr;
        map->req = (uint8_t*)(map->header + 1);
        map->resp = map->req + map->header->req_size;
        map->dma = map->resp + map->header->resp_size;
        map->dma_size = map->header->dma_size;
    } else {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
static int posixTransportShm_UseMap(char* name, ptshmMapping* map)
{
    int ret = WH_ERROR_OK;
    int fd = -1;

    if( (name == NULL) || (map == NULL)) {
        return WH_ERROR_BADARGS;
    }

    fd = shm_open(name, O_RDWR, 0);
    if (fd >= 0) {
        /* Check the size */
        struct stat st[1] = { 0 };
        ret = fstat(fd, st);
        if (ret == 0) {
            if (st->st_size != 0) {
                /* Map the header and get configuration */
                ptshmHeader* header = (ptshmHeader*)mmap(NULL, sizeof(*header),
                        PROT_READ, MAP_SHARED, fd, 0);
                if (header != MAP_FAILED) {
                    size_t size = 0;
                    if (header->initialized == PTSHM_INITIALIZED_CREATOR) {
                        /* Read provided sizes */
                        size = sizeof(*header) +
                                    header->req_size +
                                    header->resp_size +
                                    header->dma_size;
                    } else {
                        /* Header not configured */
                        ret = WH_ERROR_NOTREADY;
                    }
                    /* Unmap the header and remap the whole area if necessary */
                    (void)munmap((void*)header, sizeof(*header));

                    if (ret == WH_ERROR_OK) {
                        ret = posixTransportShm_Map(fd, size, map);
                        if (ret == WH_ERROR_OK) {
                            /* Unlnk the object */
                            (void)shm_unlink(name);

                            map->header->user_pid = getpid();
                            XMEMFENCE();
                            map->header->initialized = PTSHM_INITIALIZED_USER;
                        }
                    }
                } else {
                    /* Mapping the header failed */
                    ret = WH_ERROR_ABORTED;
                }
            } else {
                /* ftruncate has not completed */
                ret = WH_ERROR_NOTREADY;
            }
            (void)close(fd);
        } else {
            /* Problem getting file stat */
            ret = WH_ERROR_ABORTED;
        }
    } else {
        if (errno == ENOENT) {
            /* File does not exist */
            ret = WH_ERROR_NOTFOUND;
        } else {
            /* Some other error */
            ret = WH_ERROR_ABORTED;
        }
    }
    return ret;
}
#endif

#if defined(WOLFHSM_CFG_ENABLE_SERVER)
static int posixTransportShm_CreateMap(char* name, uint16_t req_size,
        uint16_t resp_size, size_t dma_size, ptshmMapping* map)
{
    int ret = WH_ERROR_OK;
    int fd = -1;

    if (    (name == NULL) ||
            (map == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* Attempt to remove any existing object. */
    (void)shm_unlink(name);
    /* Create shared memory object and set the size */
    fd = shm_open(name, O_CREAT | O_RDWR, PTSHM_CREATEMODE);
    if (fd >= 0) {
        /* Set the size of the shared memory object.
         * Note this is the minimum size, as the OS may make it larger. */
        size_t size = sizeof(*(map->header)) + req_size + resp_size + dma_size;
        if (ftruncate(fd, size) == 0) {
            /* Map the header and set the configuration */
            ptshmHeader* header = (ptshmHeader*)mmap(NULL, sizeof(*header),
                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (header != MAP_FAILED) {
                header->req_size = req_size;
                header->resp_size = resp_size;
                header->dma_size = dma_size;
                header->creator_pid = getpid();
                XMEMFENCE();
                header->initialized = PTSHM_INITIALIZED_CREATOR;

                /* Unmap the header and remap the full area */
                (void)munmap((void*)header, sizeof(*header));
                ret = posixTransportShm_Map(fd, size, map);
            } else {
                /* Problem mapping the header */
                ret = WH_ERROR_ABORTED;
            }
        } else {
            /* Problem setting the size. */
            ret = WH_ERROR_ABORTED;
        }
        close(fd);
    } else {
        /* Problem creating the shared memory */
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}
#endif


#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
/* Map the shared object if not already mapped */
static int posixTransportShm_HandleMap(posixTransportShmContext *ctx)
{
    int ret = WH_ERROR_OK;
    ptshmMapping                map[1]      = { 0 };
    whTransportMemConfig        tMemCfg[1]  = { 0 };

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (    (ret == WH_ERROR_OK) &&
            (ctx->state == PTSHM_STATE_NONE) ) {
        /* Attempt to map */
        ret = posixTransportShm_UseMap(ctx->name, map);
        if (ret == WH_ERROR_OK) {
            /* Configure the underlying transport context */
            tMemCfg->req_size  = map->header->req_size;
            tMemCfg->resp_size = map->header->resp_size;
            tMemCfg->req       = map->req;
            tMemCfg->resp      = map->resp;

            /* Initialize the shared memory transport */
            ret = wh_TransportMem_InitClear(ctx->transportMemCtx, tMemCfg, NULL,
                    NULL);

            if (ret == WH_ERROR_OK) {
                ctx->ptr = map->ptr;
                ctx->size = map->size;
                ctx->dma = map->dma;
                ctx->dma_size = map->dma_size;
                ctx->state = PTSHM_STATE_INITIALIZED;

                if (ctx->connectcb != NULL) {
                    ctx->connectcb(ctx->connectcb_arg, WH_COMM_CONNECTED);
                }
            } else {
                /* Problem initializing the transport */
                (void)munmap(map->ptr, map->size);
            }
        }
    }
    if (    (ret == WH_ERROR_OK) &&
            ((ctx->state == PTSHM_STATE_MAPPED) ||
             (ctx->state == PTSHM_STATE_DONE) ) ) {
        /* Mapped is invalid for a client */
        ret = WH_ERROR_ABORTED;
    };

    return ret;
}
#endif


/** Custom functions */
int posixTransportShm_IsConnected(posixTransportShmContext* ctx,
        whCommConnected *out_connected)
{
    ptshmHeader* header = NULL;
    whCommConnected connected = WH_COMM_DISCONNECTED;
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    header = (ptshmHeader*)ctx->ptr;
    if (header == NULL) {
        return WH_ERROR_NOTREADY;
    }
    if (header->initialized == PTSHM_INITIALIZED_USER) {
        connected = WH_COMM_CONNECTED;
    }
    if (out_connected != NULL) {
        *out_connected = connected;
    }
    return WH_ERROR_OK;
}


int posixTransportShm_GetCreatorPid(posixTransportShmContext* ctx,
        pid_t *out_pid)
{
    ptshmHeader* header = NULL;
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    header = (ptshmHeader*)ctx->ptr;
    if (    (header == NULL) ||
            (header->initialized < PTSHM_INITIALIZED_CREATOR) ) {
        return WH_ERROR_NOTREADY;
    }
    if (out_pid != NULL) {
        *out_pid = header->creator_pid;
    }
    return WH_ERROR_OK;
}


int posixTransportShm_GetUserPid(posixTransportShmContext* ctx,
        pid_t *out_pid)
{
    ptshmHeader* header = NULL;
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    header = (ptshmHeader*)ctx->ptr;
    if (    (header == NULL) ||
            (header->initialized < PTSHM_INITIALIZED_USER) ) {
        return WH_ERROR_NOTREADY;
    }
    if (out_pid != NULL) {
        *out_pid = header->user_pid;
    }
    return WH_ERROR_OK;

}


int posixTransportShm_GetDma(posixTransportShmContext* ctx,
        void* *out_dma, size_t *out_size)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (out_dma != NULL) {
        *out_dma = ctx->dma;
    }
    if (out_size != NULL) {
        *out_size = ctx->dma_size;
    }
    return WH_ERROR_OK;
}


#if defined(WOLFHSM_CFG_ENABLE_SERVER)
/** Callback function definitions */
int posixTransportShm_ServerInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    posixTransportShmContext*   ctx         = (posixTransportShmContext*)c;
    posixTransportShmConfig*    config      = (posixTransportShmConfig*)cf;
    int                         ret         = WH_ERROR_OK;
    ptshmMapping                map[1]      = { 0 };
    whTransportMemConfig        tMemCfg[1]  = { 0 };

    if (    (ctx == NULL) ||
            (config == NULL) ||
            (config->name == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    ret = posixTransportShm_CreateMap( config->name,
                            config->req_size,
                            config->resp_size,
                            config->dma_size,
                            map);

    if (ret == WH_ERROR_OK) {
        memset(ctx, 0, sizeof(*ctx));
        snprintf(ctx->name, sizeof(ctx->name), "%s", config->name);
        ctx->connectcb = connectcb;
        ctx->connectcb_arg = connectcb_arg;

        /* Configure the underlying transport context */
        tMemCfg->req_size  = map->header->req_size;
        tMemCfg->resp_size = map->header->resp_size;
        tMemCfg->req       = map->req;
        tMemCfg->resp      = map->resp;

        /* Initialize the shared memory transport */
        ret = wh_TransportMem_Init(ctx->transportMemCtx, tMemCfg, NULL, NULL);

        if (ret == WH_ERROR_OK) {
            ctx->ptr = map->ptr;
            ctx->size = map->size;
            ctx->dma = map->dma;
            ctx->dma_size = map->dma_size;

            ctx->state = PTSHM_STATE_MAPPED;

        } else {
            /* Problem initializing the transport */
            (void)munmap(map->ptr, map->size);
            (void)shm_unlink(config->name);
        }
    }
    return ret;
}
#endif


#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
int posixTransportShm_ClientInit(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    posixTransportShmContext*   ctx         = (posixTransportShmContext*)c;
    posixTransportShmConfig*    config      = (posixTransportShmConfig*)cf;
    int                         ret         = WH_ERROR_OK;

    if (    (ctx == NULL) ||
            (config == NULL) ||
            (config->name == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(ctx, 0, sizeof(*ctx));
    snprintf(ctx->name, sizeof(ctx->name), "%s", config->name);
    ctx->connectcb = connectcb;
    ctx->connectcb_arg = connectcb_arg;

    ret = posixTransportShm_HandleMap(ctx);
    if (    (ret == WH_ERROR_NOTFOUND) ||
            (ret == WH_ERROR_NOTREADY) ) {
        /* Good enough for now.  Set to ok. */
        ret = WH_ERROR_OK;
    }

    return ret;
}
#endif


int posixTransportShm_Cleanup(void* c)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->ptr != NULL) {
        ptshmHeader* header = (ptshmHeader*)ctx->ptr;
        header->initialized = PTSHM_INITIALIZED_CLEANUP;

        (void)wh_TransportMem_Cleanup(ctx->transportMemCtx);
        (void)munmap(ctx->ptr, ctx->size);
        ctx->ptr = NULL;
    }
    ctx->state = PTSHM_STATE_DONE;
    return 0;
}

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
int posixTransportShm_SendRequest(void* c, uint16_t len, const void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;
    int ret = WH_ERROR_OK;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check connected status */
    switch(ctx->state) {
    case PTSHM_STATE_NONE:
        ret = posixTransportShm_HandleMap(ctx);
        if (ret == WH_ERROR_OK) {
            if(ctx->connectcb != NULL) {
                ctx->connectcb(ctx->connectcb_arg, WH_COMM_CONNECTED);
            }
        } else {
            if (ret == WH_ERROR_NOTFOUND) {
                /* Server hasn't created the object yet */
                ret = WH_ERROR_NOTREADY;
            }
        }
        break;

    case PTSHM_STATE_MAPPED:
        /* Invalid state for a client */
        ret = WH_ERROR_BADARGS;
        break;

    case PTSHM_STATE_INITIALIZED:
        ret = WH_ERROR_OK;
        break;

    case PTSHM_STATE_DONE:
    default:
        ret = WH_ERROR_ABORTED;
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_TransportMem_SendRequest(ctx->transportMemCtx, len, data);
    }
    return ret;
}

int posixTransportShm_RecvResponse(void* c, uint16_t* out_len, void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_RecvResponse(ctx->transportMemCtx, out_len, data);
}

#ifdef WOLFHSM_CFG_DMA
/** DMA function callbacks that can make use of WOLFSSL_STATIC_MEMORY using
 * the POSIX shared memory transport.
*/

int wh_Client_PosixStaticMemoryDMA(struct whClientContext_t* client,
                                   uintptr_t clientAddr, void** xformedCliAddr,
                                   size_t len, whDmaOper oper,
                                   whDmaFlags flags)
{
    int       ret     = WH_ERROR_OK;
    int       isInDma = 0;
    void*     dmaPtr;
    size_t    dmaSize;
    uintptr_t dmaBuffer; /* buffer in DMA space */
    uintptr_t dmaOffset;
    void*     heap = NULL;

    /* NULL pointer maps to NULL, short circuit here */
    if (clientAddr == 0 || len == 0) {
        *xformedCliAddr = NULL;
        return WH_ERROR_OK;
    }

    /* First check if the address is in the expected DMA area */
    ret = posixTransportShm_GetDma(client->comm->transport_context, &dmaPtr,
                                   &dmaSize);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if ((dmaPtr != NULL) && (dmaSize > 0) && (len < dmaSize) &&
        (clientAddr >= (uintptr_t)dmaPtr) &&
        (clientAddr < (uintptr_t)(dmaPtr + dmaSize - len))) {
        dmaBuffer = clientAddr;
        isInDma   = 1;
    }
    else {
        heap = client->dma.heap;
        if (heap == NULL) {
            return WH_ERROR_NOTREADY;
        }
    }

    if (oper == WH_DMA_OPER_CLIENT_READ_PRE ||
        oper == WH_DMA_OPER_CLIENT_WRITE_PRE) {
        if (isInDma == 0) {
            dmaBuffer = (uintptr_t)XMALLOC(len, heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (dmaBuffer == 0) {
                return WH_ERROR_NOSPACE;
            }
            dmaOffset = dmaBuffer - (uintptr_t)dmaPtr;
            memcpy((void*)dmaBuffer, (void*)clientAddr, len);
        }
        else {
            dmaOffset = clientAddr - (uintptr_t)dmaPtr;
        }
        /* return an offset into the DMA area */
        *xformedCliAddr = (void*)dmaOffset;
    }
    else if (oper == WH_DMA_OPER_CLIENT_READ_POST) {
        if (isInDma == 0) {
            uint8_t* ptr = (uint8_t*)dmaPtr + (uintptr_t)*xformedCliAddr;
            XFREE(ptr, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    else if (oper == WH_DMA_OPER_CLIENT_WRITE_POST) {
        if (isInDma == 0) {
            uint8_t* ptr = (uint8_t*)dmaPtr + (uintptr_t)*xformedCliAddr;
            memcpy((void*)clientAddr, ptr,
                   len); /* copy results of what server wrote */
            XFREE(ptr, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    (void)flags;
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#if defined(WOLFHSM_CFG_ENABLE_SERVER)
int posixTransportShm_SendResponse(void* c, uint16_t len, const void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_TransportMem_SendResponse(ctx->transportMemCtx, len, data);
}

int posixTransportShm_RecvRequest(void* c, uint16_t* out_len, void* data)
{
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;
    int ret = WH_ERROR_OK;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check connected status */
    switch(ctx->state) {
    case PTSHM_STATE_NONE:
        /* Server should not get this state */
        ret = WH_ERROR_BADARGS;
        break;

    case PTSHM_STATE_MAPPED:
    {
        /* Check to see if client connected */
        whCommConnected connected = WH_COMM_DISCONNECTED;
        posixTransportShm_IsConnected(ctx, &connected);
        if (connected == WH_COMM_CONNECTED) {
            ctx->state = PTSHM_STATE_INITIALIZED;
            if (ctx->connectcb != NULL) {
                ctx->connectcb(ctx->connectcb_arg, connected);
            }
            ret = WH_ERROR_OK;
        }
    } break;

    case PTSHM_STATE_INITIALIZED:
        ret = WH_ERROR_OK;
        break;

    case PTSHM_STATE_DONE:
    default:
        ret = WH_ERROR_ABORTED;
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_TransportMem_RecvRequest(ctx->transportMemCtx, out_len, data);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* Generic offset into the DMA area. This function can operate with no knowledge
 * of what structures the DMA area is. It takes in an offset, validates it, and
 * returns the pointer into the DMA area based off of the offset.  */
int wh_Server_PosixStaticMemoryDMA(whServerContext* server,
                                   uintptr_t clientAddr, void** xformedCliAddr,
                                   size_t len, whServerDmaOper oper,
                                   whServerDmaFlags flags)
{
    posixTransportShmContext* ctx;
    void*                     dma_ptr;
    size_t                    dma_size;
    int                       ret;

    (void)oper;
    (void)flags;

    if (server == NULL || xformedCliAddr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the transport context from the server's communication context */
    ctx = (posixTransportShmContext*)server->comm->transport_context;
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the DMA section pointer and size */
    ret = posixTransportShm_GetDma(ctx, &dma_ptr, &dma_size);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (dma_ptr == NULL || dma_size == 0) {
        return WH_ERROR_NOTREADY;
    }

    if (len > dma_size || clientAddr > dma_size - len) {
        return WH_ERROR_BADARGS;
    }

    /* Return the transformed address (DMA pointer + offset) */
    *xformedCliAddr = (void*)((uintptr_t)dma_ptr + clientAddr);
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFHSM_CFG_ENABLE_SERVER */
