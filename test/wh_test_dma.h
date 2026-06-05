/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test/wh_test_dma.h
 *
 * DMA allow list boundary check tests
 */
#ifndef TEST_WH_TEST_DMA_H_
#define TEST_WH_TEST_DMA_H_

#include "wolfhsm/wh_settings.h"

int whTest_Dma(void);

#ifdef WOLFHSM_CFG_DMA
#include <stdint.h>
#include <stddef.h>
#include "wolfhsm/wh_dma.h"

struct whClientContext_t;
struct whServerContext_t;

/* Shared "bounce-pool" translating DMA callback harness (see wh_test_dma.c).
 * Register whTestDma_BounceClientCb / whTestDma_BounceServerCb as the client /
 * server DMA callbacks; the server callback rejects any address a *Dma path
 * failed to translate. Single-client only (see wh_test_dma.c). */

/* Reset the pool between independent test sequences. */
void whTestDma_BounceReset(void);

/* Translating client DMA callback (matches whClientDmaClientMemCb). */
int whTestDma_BounceClientCb(struct whClientContext_t* client,
                             uintptr_t clientAddr, void** xformedAddr,
                             size_t len, whDmaOper oper, whDmaFlags flags);

/* Validating server DMA callback (matches whServerDmaClientMemCb): identity
 * maps in-pool addresses, rejects out-of-pool ones with WH_ERROR_ACCESS. */
int whTestDma_BounceServerCb(struct whServerContext_t* server,
                             uintptr_t clientAddr, void** serverPtr, size_t len,
                             whDmaOper oper, whDmaFlags flags);

/* Slots currently allocated (0 between operations); for leak assertions. */
int whTestDma_BounceOutstanding(void);

/* Count of len>0 POSTs that found no matching live slot (a stray/double POST).
 * Should stay 0. */
int whTestDma_BounceStrayPosts(void);

/* Fault injection: allow this many further slot allocations, then fail (the
 * client callback returns an error). Negative = unlimited (the default). Used
 * to drive the *Dma Request leak-recovery paths. */
void whTestDma_BounceSetAllocBudget(int allocs);
#endif /* WOLFHSM_CFG_DMA */

#endif /* TEST_WH_TEST_DMA_H_ */
