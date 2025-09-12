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
 * port/posix/posix_transport_dma.c
 */

/* This builds on top of posix_transport_shm.c adding in staticmemory feature
 * use and passing shared memory locations from the client <-> server by
 * reference. Avoiding memcpy calls where possible for increased performance. */

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
#include "wolfhsm/wh_server.h"

#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_dma.h"

/* included for static memory structs and api */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/memory.h"


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

/** Custom functions */
int posixTransportShm_GetHeapHint(posixTransportShmContext* ctx,
        void* *out_hint)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (out_hint != NULL) {
        *out_hint = ctx->heap;
    }
    return WH_ERROR_OK;
}

int wh_Client_PosixStaticMemoryDMA(whClientContext* client, uintptr_t clientAddr,
    void** xformedCliAddr, size_t len, whClientDmaOper oper,
    whClientDmaFlags flags)
{
    int ret = WH_ERROR_OK;
    int isInDma = 0;
    void* dmaPtr;
    size_t dmaSize;
    uintptr_t dmaBuffer; /* buffer in DMA space */
    uintptr_t dmaOffset;
    void* heap;

    /* NULL pointer maps to NULL, short circuit here */
    if (clientAddr == 0 || len == 0) {
        *xformedCliAddr = NULL;
        return WH_ERROR_OK;
    }

    /* First check if the address is in the expected DMA area */
    ret = posixTransportShm_GetDma(client->comm->transport_context,
        &dmaPtr, &dmaSize);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    
    if (dmaPtr != NULL && dmaSize > 0 && 
            clientAddr >= (uintptr_t)dmaPtr &&
            (clientAddr + len) < (uintptr_t)(dmaPtr + dmaSize)) {
        dmaBuffer = clientAddr;
        isInDma = 1;
    }
    else {
        posixTransportShm_GetHeapHint(client->comm->transport_context, &heap);
    }
    
    if (oper == WH_DMA_OPER_SERVER_READ_PRE
        || oper == WH_DMA_OPER_SERVER_WRITE_PRE) {
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
    else if (oper == WH_DMA_OPER_SERVER_READ_POST) {
        if (isInDma == 0) {
            uint8_t* ptr = (uint8_t*)dmaPtr + (uintptr_t)*xformedCliAddr;
            XFREE(ptr, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    else if (oper == WH_DMA_OPER_SERVER_WRITE_POST) {
        if (isInDma == 0) {
            uint8_t* ptr = (uint8_t*)dmaPtr + (uintptr_t)*xformedCliAddr;
            memcpy((void*)clientAddr, ptr, len); /* copy results of what server wrote */
            XFREE(ptr, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    (void)flags;
    return ret;
}


int wh_Server_PosixStaticMemoryDMA(whServerContext* server, uintptr_t clientAddr,
    void** xformedCliAddr, size_t len, whServerDmaOper oper,
    whServerDmaFlags flags)
{
    posixTransportShmContext* ctx;
    void* dma_ptr;
    size_t dma_size;
    int ret;

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

    if (len + clientAddr > dma_size) {
        return WH_ERROR_BADARGS;
    }

    /* Convert client address to offset within DMA section */
    if (clientAddr < (uintptr_t)0 || clientAddr > (uintptr_t)(dma_size)) {
        return WH_ERROR_OK;
    }

    /* Return the transformed address (DMA pointer + offset) */
    *xformedCliAddr = (void*)((uintptr_t)dma_ptr + clientAddr);
    return WH_ERROR_OK;
}

/* Set the static memory for the shared memory transport
 * Devides up the shared memory into buffers to be used and passed by reference
 */
int posixTransportShm_SetStaticMemory(posixTransportShmContext* ctx,
    posixTransportShmConfig* cfg)
{
#ifdef WOLFSSL_STATIC_MEMORY
    WOLFSSL_HEAP_HINT* hint = NULL;
    int ret = WH_ERROR_OK;

    ret = wc_LoadStaticMemory_ex(&hint, cfg->dmaStaticMemListSz,
        cfg->dmaStaticMemList,  cfg->dmaStaticMemDist, ctx->dma, ctx->dma_size,
        0, 0);
    if (ret == 0) {
        ctx->heap = (void*)hint;
        ret = WH_ERROR_OK;
    } else {
        ret = WH_ERROR_ABORTED;
    }
    return ret;
#else
    (void)ctx;
    (void)cfg;
    return WH_ERROR_NOTIMPL;
 #endif
}

/** Callback function definitions */

/* Does the same as ServerInit, but also sets up the static memory */
int posixTransportShm_ServerInitReference(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    int ret;
    
    ret = posixTransportShm_ServerInit(c, cf, connectcb, connectcb_arg);

#ifdef WOLFSSL_STATIC_MEMORY
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;
    ctx->heap = (void*)ctx->dma + sizeof(WOLFSSL_HEAP);
#else
    ret = WH_ERROR_NOTIMPL;
#endif
    return ret;
}


int posixTransportShm_ClientInitReference(void* c, const void* cf,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
    int ret = WH_ERROR_OK;
    int max_attempts = 10;
    int attempt = 0;

    /* Retry connecting to the shared memory object until server is ready.
     * This fixes a race condition where the client tries to connect before
     * the server has finished creating and initializing the shared memory object. */
    for (attempt = 0; attempt < max_attempts; attempt++) {
        ret = posixTransportShm_ClientInit(c, cf, connectcb, connectcb_arg);
        if (ret == WH_ERROR_OK) {
            /* Successfully connected, now set up static memory */
            ret = posixTransportShm_SetStaticMemory(c,
                (posixTransportShmConfig*)cf);
            if (ret == WH_ERROR_OK) {
                /* Everything successful */
                break;
            } else if (ret == WH_ERROR_NOTIMPL) {
                /* Static memory not implemented, but connection is OK */
                ret = WH_ERROR_OK;
                break;
            } else {
                /* Static memory setup failed, retry connection */
                ret = WH_ERROR_NOTREADY;
            }
        }
        
        if (ret == WH_ERROR_NOTREADY || ret == WH_ERROR_NOTFOUND) {
            /* Server not ready yet, wait a bit and retry with exponential backoff */
            usleep(10000 * (1 << attempt)); /* 10ms, 20ms, 40ms, 80ms, etc. */
            ret = WH_ERROR_OK; /* Will retry on next iteration */
        } else {
            /* Other error, don't retry */
            break;
        }
    }

    return ret;
}


/* Only the server should call this to clean up the static memory pool
 * The client can call the posixTransportShm_Cleanup function instead. */
int posixTransportShm_CleanupReference(void* c)
{
    int ret;

#ifdef WOLFSSL_STATIC_MEMORY
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;
    /* Unload of static memory is used to free up mutexes */
    wc_UnloadStaticMemory(ctx->heap);
#endif

    ret = posixTransportShm_Cleanup(c);
    if (ret == WH_ERROR_OK) {
    }
    return 0;
}


int posixTransportShm_SendRequestReference(void* c, uint16_t len, const void* data)
{
    int ret = WH_ERROR_OK;

    /* TODO: translate data into an offset and length to be sent in request */
    ret = posixTransportShm_SendRequest(c, len, data);

    return ret;
}


int TranslateRequestReference(void* c, uint16_t* outSz, void** outPtr,
    void* data, int dataSz)
{
    int ret = WH_ERROR_OK;
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    if (dataSz != (sizeof(uintptr_t) * 2)) {
        return WH_ERROR_BADARGS;
    }

    *outPtr = (void*)(((uintptr_t*)data)[0] + ctx->dma);
    *outSz  = (uint16_t)((uintptr_t*)data)[1];

    return ret;
}


int posixTransportShm_RecvRequestReference(void* c, uint16_t* out_len, void* data)
{
    int ret = WH_ERROR_OK;

    ret = posixTransportShm_RecvRequest(c, out_len, data);
    if (ret == WH_ERROR_OK) {
         /* TODO: translate data into an offset and length to be sent in request */
    }
    return ret;
}

int posixTransportShm_SendResponseReference(void* c, uint16_t len, const void* data)
{
    int ret;
    posixTransportShmContext* ctx = (posixTransportShmContext*)c;

    /* Only need to check NULL, mem transport checks other state info */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* trasnlate and sanity checks on pointer to send in response */
    
    /* TODO: check that address is in the correct range, after heap hint and before
       end */


    ret = posixTransportShm_SendResponse(c, len, data);
    return ret;
}


int posixTransportShm_RecvResponseReference(void* c, uint16_t* out_len, void* data)
{
    int ret;

    ret = posixTransportShm_RecvResponse(c, out_len, data);
    if (ret == WH_ERROR_OK) {
        /* TODO: translate data into an offset and length to be sent in response */
    }
    return ret;
}