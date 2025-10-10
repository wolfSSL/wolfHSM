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

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_DMA

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"


int wh_Server_DmaCheckMemOperAllowed(const whServerContext* server,
                                  whServerDmaOper oper, void* addr, size_t size)
{
    /* NULL addr is allowed here, since 0 is a valid address */
    if (NULL == server || 0 == size) {
        return WH_ERROR_BADARGS;
    }

    return wh_Dma_CheckMemOperAgainstAllowList(server->dma.dmaAddrAllowList,
                                               oper, addr, size);
}

int wh_Server_DmaRegisterCb(whServerContext* server, whServerDmaClientMemCb cb)
{
    /* No NULL check for cb, since it is optional and always NULL checked before
     * it is called */
    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    server->dma.cb = cb;

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
int wh_Server_DmaRegisterMemCopyCb(whServerContext* server,
                                   whServerDmaMemCopyCb cb)
{
    /* No NULL check for cb, since it is optional and always NULL checked before
     * it is called */
    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    server->dma.memCopyCb = cb;

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */

int wh_Server_DmaRegisterAllowList(whServerContext*                server,
                                   const whServerDmaAddrAllowList* allowlist)
{
    if (NULL == server || NULL == allowlist) {
        return WH_ERROR_BADARGS;
    }

    server->dma.dmaAddrAllowList = allowlist;

    return WH_ERROR_OK;
}

int wh_Server_DmaProcessClientAddress(whServerContext* server,
                                      uintptr_t        clientAddr,
                                      void** xformedCliAddr, size_t len,
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
    if (NULL != server->dma.cb) {
        rc = server->dma.cb(server, clientAddr, xformedCliAddr, len, oper,
                            flags);
        if (rc != WH_ERROR_OK) {
            return rc;
        }
    }

    /* if the server has a allowlist registered, check address against it */
    if (rc == WH_ERROR_OK && len > 0) {
        rc = wh_Dma_CheckMemOperAgainstAllowList(server->dma.dmaAddrAllowList,
                                                 oper, *xformedCliAddr, len);
    }

    return rc;
}

int whServerDma_CopyFromClient(struct whServerContext_t* server,
                               void* serverPtr, uintptr_t clientAddr,
                               size_t len, whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = wh_Dma_CheckMemOperAgainstAllowList(server->dma.dmaAddrAllowList,
                                             WH_DMA_OPER_CLIENT_READ_PRE,
                                             serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-read */
    rc = wh_Server_DmaProcessClientAddress(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
    if (server->dma.memCopyCb != NULL) {
        rc = server->dma.memCopyCb(server, (uintptr_t)transformedAddr,
                                   (uintptr_t)serverPtr, len,
                                   WH_DMA_COPY_OPER_CLIENT_READ, flags);
        if (rc != WH_ERROR_OK) {
            return rc;
        }
    }
    else 
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */
    {

        /* TODO: should we add a flag to force client word-sized reads? */
        memcpy(serverPtr, transformedAddr, len);
    }

    /* process the client address post-read */
    rc = wh_Server_DmaProcessClientAddress(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_POST,
        flags);

    return rc;
}

int whServerDma_CopyToClient(struct whServerContext_t* server,
                             uintptr_t clientAddr, void* serverPtr, size_t len,
                             whServerDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = wh_Dma_CheckMemOperAgainstAllowList(server->dma.dmaAddrAllowList,
                                             WH_DMA_OPER_CLIENT_WRITE_PRE,
                                             serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-write */
    rc = wh_Server_DmaProcessClientAddress(server, clientAddr, &transformedAddr,
                                           len, WH_DMA_OPER_CLIENT_WRITE_PRE,
                                           flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
    if (server->dma.memCopyCb != NULL) {
        rc = server->dma.memCopyCb(server, clientAddr, (uintptr_t)serverPtr,
                                   len, WH_DMA_COPY_OPER_CLIENT_WRITE, flags);
        if (rc != WH_ERROR_OK) {
            return rc;
        }
    }
    else
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */
    {

        /* TODO: should we add a flag to force client word-sized reads? */
        memcpy(transformedAddr, serverPtr, len);
    }

    /* Process the client address post-write */
    rc = wh_Server_DmaProcessClientAddress(server, clientAddr, &transformedAddr,
                                           len, WH_DMA_OPER_CLIENT_WRITE_POST,
                                           flags);

    return rc;
}

#endif /* WOLFHSM_CFG_DMA */