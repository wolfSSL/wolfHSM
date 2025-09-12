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
 * src/wh_client_dma.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_DMA

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

static int _checkOperValid(whClientDmaOper oper)
{
    if (oper < WH_DMA_OPER_SERVER_READ_PRE ||
        oper > WH_DMA_OPER_SERVER_WRITE_POST) {
        return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _checkAddrAgainstAllowList(const whClientDmaAddrList allowList,
    void* addr, size_t size)
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


static int _checkMemOperAgainstAllowList(const whClientContext* client,
                                         whClientDmaOper oper, void* addr,
                                         size_t size)
{
    int rc = WH_ERROR_OK;

    rc = _checkOperValid(oper);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* If no allowlist is registered, anything goes */
    if (client->dma.dmaAddrAllowList == NULL) {
        return WH_ERROR_OK;
    }

    /* If a read/write operation is requested, check the transformed address
     * against the appropriate allowlist
     *
     * TODO: do we need to allowlist check on POST in case there are subsequent
     * memory operations for some reason?
     */
    if (oper == WH_DMA_OPER_SERVER_READ_PRE) {
        rc = _checkAddrAgainstAllowList(client->dma.dmaAddrAllowList->readList,
            addr, size);
    }
    else if (oper == WH_DMA_OPER_SERVER_WRITE_PRE) {
        rc = _checkAddrAgainstAllowList(client->dma.dmaAddrAllowList->writeList,
            addr, size);
    }

    return rc;
}

int wh_Client_DmaRegisterCb(whClientContext* client, whClientDmaClientMemCb cb)
{
    /* No NULL check for cb, since it is optional and always NULL checked before
     * it is called */
    if (NULL == client) {
        return WH_ERROR_BADARGS;
    }

    client->dma.cb = cb;

    return WH_ERROR_OK;
}


/* Processes the given client address and translates it into a value that the
 * server will understand. This can be used to map the address into a known
 * location of shared memory. */
int wh_Client_DmaProcessClientAddress(whClientContext* client,
                                      uintptr_t        clientAddr,
                                      void** xformedCliAddr, size_t len,
                                      whClientDmaOper  oper,
                                      whClientDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == client || NULL == xformedCliAddr) {
        return WH_ERROR_BADARGS;
    }

    /* Perform user-supplied address transformation, cache manipulation, etc */
    if (NULL != client->dma.cb) {
        rc = client->dma.cb(client, clientAddr, xformedCliAddr, len, oper,
                            flags);
        if (rc != WH_ERROR_OK) {
            return rc;
        }
    }
    else {
        /* Transformed address defaults to raw client address */
        *xformedCliAddr = (void*)((uintptr_t)clientAddr);
    }

    /* if the server has a allowlist registered, check address against it */
    return _checkMemOperAgainstAllowList(client, oper, *xformedCliAddr, len);
}

#endif /* WOLFHSM_CFG_DMA */
