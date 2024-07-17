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
 * src/wh_server_dma.c
 */

/* Pick up server config */
#include "wolfhsm/wh_server.h"

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "wolfhsm/wh_error.h"


/* TODO: if the Address allowlist ever gets large, we should consider a more
 * efficient representation (requiring sorted array and binary search, or
 * building a binary tree, etc.) */

static int _checkOperValid(whServerDmaOper oper)
{
    if (oper < WH_DMA_OPER_CLIENT_READ_PRE ||
        oper > WH_DMA_OPER_CLIENT_WRITE_POST) {
        return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _checkAddrAgainstAllowList(const whServerDmaAddrList allowList, void* addr,
                                      size_t size)
{
    uintptr_t startAddr = (uintptr_t)addr;
    uintptr_t endAddr   = startAddr + size;
    int i = 0;

    if (0 == size) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the address range is fully within a allowlist entry */
    for (i = 0; i < WOLFHSM_CFG_SERVER_DMAADDR_COUNT; i++) {
        uintptr_t allowListStartAddr = (uintptr_t)allowList[i].addr;
        uintptr_t allowListEndAddr   = allowListStartAddr + allowList[i].size;

        if (0 == allowList[i].size) {
            continue;
        }

        if (startAddr >= allowListStartAddr && endAddr <= allowListEndAddr) {
            return WH_ERROR_OK;
        }
    }

    return WH_ERROR_ACCESS;
}

static int _checkMemOperAgainstAllowList(const whServerContext* server,
                                         whServerDmaOper oper, void* addr,
                                         size_t size)
{
    int rc = WH_ERROR_OK;

    rc = _checkOperValid(oper);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* If no allowlist is registered, anything goes */
    if (server->dma.dmaAddrAllowList == NULL) {
        return WH_ERROR_OK;
    }

    /* If a read/write operation is requested, check the transformed address
     * against the appropriate allowlist
     *
     * TODO: do we need to allowlist check on POST in case there are subsequent
     * memory operations for some reason?
     */
    if (oper == WH_DMA_OPER_CLIENT_READ_PRE) {
        rc = _checkAddrAgainstAllowList(server->dma.dmaAddrAllowList->readList, addr, size);
    }
    else if (oper == WH_DMA_OPER_CLIENT_WRITE_PRE) {
        rc = _checkAddrAgainstAllowList(server->dma.dmaAddrAllowList->writeList, addr, size);
    }

    return rc;
}

int wh_Server_DmaCheckMemOperAllowed(const whServerContext* server,
                                  whServerDmaOper oper, void* addr, size_t size)
{
    /* NULL addr is allowed here, since 0 is a valid address */
    if (NULL == server || 0 == size) {
        return WH_ERROR_BADARGS;
    }

    return _checkMemOperAgainstAllowList(server, oper, addr, size);
}

int wh_Server_DmaRegisterCb32(whServerContext* server, whServerDmaClientMem32Cb cb)
{
    /* No NULL check for cb, since it is optional and always NULL checked before
     * it is called */
    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    server->dma.cb32 = cb;

    return WH_ERROR_OK;
}

int wh_Server_DmaRegisterCb64(whServerContext* server, whServerDmaClientMem64Cb cb)
{
    /* No NULL check for cb, since it is optional and always NULL checked before
     * it is called */
    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    server->dma.cb64 = cb;

    return WH_ERROR_OK;
}

int wh_Server_DmaRegisterAllowList(whServerContext*                server,
                                   const whServerDmaAddrAllowList* allowlist)
{
    if (NULL == server || NULL == allowlist) {
        return WH_ERROR_BADARGS;
    }

    server->dma.dmaAddrAllowList = allowlist;

    return WH_ERROR_OK;
}


int wh_Server_DmaProcessClientAddress32(whServerContext* server,
                                        uint32_t         clientAddr,
                                        void** xformedCliAddr, uint32_t len,
                                        whServerDmaOper  oper,
                                        whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == server || NULL == xformedCliAddr) {
        return WH_ERROR_BADARGS;
    }

    /* Transformed address defaults to raw client address */
    *xformedCliAddr = (void*)((uintptr_t)clientAddr);

    /* Perform user-supplied address transformation, cache manipulation, etc */
    if (NULL != server->dma.cb32) {
        rc = server->dma.cb32(server, clientAddr, xformedCliAddr, len, oper,
                                flags);
        if (rc != WH_ERROR_OK) {
            return rc;
        }
    }

    /* if the server has a allowlist registered, check transformed address
     * against it */
    return _checkMemOperAgainstAllowList(server, oper, *xformedCliAddr, len);
}

int wh_Server_DmaProcessClientAddress64(whServerContext* server,
                                        uint64_t         clientAddr,
                                        void** xformedCliAddr, uint64_t len,
                                        whServerDmaOper oper, whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == server || NULL == xformedCliAddr) {
        return WH_ERROR_BADARGS;
    }

    /* Transformed address defaults to raw client address */
    *xformedCliAddr = (void*)((uintptr_t)clientAddr);

    /* Perform user-supplied address transformation, cache manipulation, etc */
    if (NULL != server->dma.cb64) {
        rc = server->dma.cb64(server, clientAddr, xformedCliAddr, len, oper,
                              flags);
        if (rc != WH_ERROR_OK) {
            return rc;
        }
    }

    /* if the server has a allowlist registered, check address against it */
    return _checkMemOperAgainstAllowList(server, oper, *xformedCliAddr, len);
}


int whServerDma_CopyFromClient32(struct whServerContext_t* server,
                                 void* serverPtr, uint32_t clientAddr,
                                 size_t len, whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be checked against UINT32Max? Should it be uint32_t? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(server, WH_DMA_OPER_CLIENT_READ_PRE,
                                       serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-read */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(serverPtr, transformedAddr, len);

    /* Process the client address post-read */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_POST,
        flags);

    return rc;
}


int whServerDma_CopyFromClient64(struct whServerContext_t* server,
                                 void* serverPtr, uint64_t clientAddr,
                                 size_t len, whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be be uint64_t? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(server, WH_DMA_OPER_CLIENT_READ_PRE,
                                       serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-read */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(serverPtr, transformedAddr, len);

    /* process the client address post-read */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_POST,
        flags);

    return rc;
}

int whServerDma_CopyToClient32(struct whServerContext_t* server,
                               uint32_t clientAddr, void* serverPtr, size_t len,
                               whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be checked against UINT32Max? Should it be uint32_t ? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(server, WH_DMA_OPER_CLIENT_WRITE_PRE,
                                       serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-write */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_WRITE_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(transformedAddr, serverPtr, len);

    /* Process the client address post-write */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len,
        WH_DMA_OPER_CLIENT_WRITE_POST, flags);

    return rc;
}


int whServerDma_CopyToClient64(struct whServerContext_t* server,
                               uint64_t clientAddr, void* serverPtr, size_t len,
                               whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be uint64_t? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(server, WH_DMA_OPER_CLIENT_WRITE_PRE,
                                       serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-write */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_WRITE_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(transformedAddr, serverPtr, len);

    /* Process the client address post-write */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len,
        WH_DMA_OPER_CLIENT_WRITE_POST, flags);

    return rc;
}
