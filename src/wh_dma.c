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
 * src/wh_dma.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_DMA

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_dma.h"

/* internal DMA function declarations */
static int _checkOperValid(whDmaOper oper);
static int _checkAddrAgainstAllowList(const whDmaAddrList allowList, void* addr,
                                      size_t size);

static int _checkOperValid(whDmaOper oper)
{
    if (oper < WH_DMA_OPER_CLIENT_READ_PRE ||
        oper > WH_DMA_OPER_CLIENT_WRITE_POST) {
        return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _checkAddrAgainstAllowList(const whDmaAddrList allowList, void* addr,
                                      size_t size)
{
    uintptr_t startAddr = (uintptr_t)addr;
    uintptr_t endAddr   = startAddr + size;
    int       i         = 0;

    if (0 == size) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the address range is fully within a allowlist entry */
    for (i = 0; i < WOLFHSM_CFG_DMAADDR_COUNT; i++) {
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


static int _checkMemOperAgainstAllowList(const whDmaAddrAllowList* allowlist,
                                         whDmaOper oper, void* addr,
                                         size_t size)
{
    int rc = WH_ERROR_OK;

    rc = _checkOperValid(oper);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* If no allowlist is registered, anything goes */
    if (allowlist == NULL) {
        return WH_ERROR_OK;
    }

    /* If a read/write operation is requested, check the transformed address
     * against the appropriate allowlist
     *
     * TODO: do we need to allowlist check on POST in case there are subsequent
     * memory operations for some reason?
     */
    if (oper == WH_DMA_OPER_CLIENT_READ_PRE) {
        rc = _checkAddrAgainstAllowList(allowlist->readList, addr, size);
    }
    else if (oper == WH_DMA_OPER_CLIENT_WRITE_PRE) {
        rc = _checkAddrAgainstAllowList(allowlist->writeList, addr, size);
    }

    return rc;
}


int wh_Dma_CheckMemOperAgainstAllowList(const whDmaAddrAllowList* allowlist,
                                        whDmaOper oper, void* addr, size_t size)
{
    if (0 == size) {
        return WH_ERROR_BADARGS;
    }

    return _checkMemOperAgainstAllowList(allowlist, oper, addr, size);
}

#endif /* WOLFHSM_CFG_DMA */
