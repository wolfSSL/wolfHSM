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
 * wolfhsm/wh_dma.h
 *
 * Common DMA API for client and server
 */

#include <stdint.h>
#include <stddef.h>

#ifndef WOLFHSM_WH_COMMON_DMA_H_
#define WOLFHSM_WH_COMMON_DMA_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

/* This is the same for both client and server, the client cares about when the
 * server is about to access its memory and the server cares about when it is
 * about to access the clients memory. */
typedef enum {
    /* Indicates server is about to read from client memory */
    WH_DMA_OPER_CLIENT_READ_PRE = 0,
    /* Indicates server has just read from client memory */
    WH_DMA_OPER_CLIENT_READ_POST = 1,
    /* Indicates server is about to write to client memory */
    WH_DMA_OPER_CLIENT_WRITE_PRE = 2,
    /* Indicates server has just written to client memory */
    WH_DMA_OPER_CLIENT_WRITE_POST = 3,
} whDmaOper;

#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
typedef enum {
    WH_DMA_COPY_OPER_CLIENT_READ  = 0,
    WH_DMA_COPY_OPER_CLIENT_WRITE = 1,
} whDmaCopyOper;
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */

/* Flags embedded in request/response structs provided by client */
typedef struct {
    uint8_t cacheForceInvalidate : 1;
    uint8_t : 7;
} whDmaFlags;

/* Common DMA address entry within the allowed tables */
typedef struct {
    void*  addr;
    size_t size;
} whDmaAddr;
typedef whDmaAddr whDmaAddrList[WOLFHSM_CFG_DMAADDR_COUNT];

/* Holds allowable client read/write addresses */
typedef struct {
    whDmaAddrList readList;  /* Allowed client read addresses */
    whDmaAddrList writeList; /* Allowed client write addresses */
} whDmaAddrAllowList;

int wh_Dma_CheckMemOperAgainstAllowList(const whDmaAddrAllowList* allowlist,
                                    whDmaOper oper, void* addr, size_t len);

#endif /* WOLFHSM_WH_COMMON_DMA_H_ */
