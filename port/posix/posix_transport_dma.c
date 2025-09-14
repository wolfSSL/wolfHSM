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

#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_dma.h"

/* included for static memory structs and api */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/memory.h"

/** Local declarations */

/** Custom functions */

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
    void* heap = NULL;

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

    if ((dmaPtr != NULL) && (dmaSize > 0) && (len < dmaSize) &&
            (clientAddr >= (uintptr_t)dmaPtr) &&
            (clientAddr < (uintptr_t)(dmaPtr + dmaSize - len))) {
        dmaBuffer = clientAddr;
        isInDma = 1;
    }
    else {
        heap = client->dma.heap;
        if (heap == NULL) {
            return WH_ERROR_NOTREADY;
        }
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

    if (len > dma_size || clientAddr > dma_size - len) {
        return WH_ERROR_BADARGS;
    }

    /* Return the transformed address (DMA pointer + offset) */
    *xformedCliAddr = (void*)((uintptr_t)dma_ptr + clientAddr);
    return WH_ERROR_OK;
}