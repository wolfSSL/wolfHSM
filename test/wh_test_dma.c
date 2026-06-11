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
 * test/wh_test_dma.c
 *
 * Tests for DMA allow list boundary checking, including integer overflow
 * detection on the end-address computation.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_DMA

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_dma.h"

#include "wh_test_common.h"
#include "wh_test_dma.h"

/*
 * Shared "bounce-pool" translating DMA callback harness.
 *
 * Models a split-address-space port: the server can only reach a dedicated pool,
 * not arbitrary client RAM. The client callback bounces each buffer through a
 * pool slot and hands the server the pool address; the server callback rejects
 * (WH_ERROR_ACCESS) any address outside the pool, so a *Dma API that forgot to
 * translate is caught. Freed slots are poisoned, so a premature POST
 * (use-after-free) corrupts the data, and a POST matching no live slot is
 * counted as a stray/double POST.
 *
 * Missing translation is caught in both harnesses; the use-after-free class is
 * deterministic only in the single-thread pump harness, where the client POST
 * is ordered before the server read.
 *
 * Single-client only: the allocator is mutated only by the (serialized) client
 * side; the server just reads/writes pool bytes, with happens-before provided
 * by the request/response round-trip through the transport.
 */
struct whClientContext_t; /* opaque: callbacks only use the pointer */
struct whServerContext_t; /* opaque: callbacks only use the pointer */

/* Generous headroom for the few buffers one op maps concurrently (the largest
 * being an ML-DSA-sized key); the pool recycles between ops. */
#define BOUNCE_POOL_SIZE \
    ((64 * 1024) + (8 * WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))
#define BOUNCE_POOL_SLOTS 64
#define BOUNCE_POISON_BYTE ((uint8_t)0xEF)

typedef struct {
    int       inUse;
    uintptr_t base; /* address within g_bouncePool */
    size_t    len;
} bounceSlot;

static uint8_t    g_bouncePool[BOUNCE_POOL_SIZE];
static bounceSlot g_bounceSlots[BOUNCE_POOL_SLOTS];
static size_t     g_bounceUsed;        /* bump offset into the pool */
static int        g_bounceOutstanding; /* slots currently allocated */
static int        g_bounceStrayPost;   /* len>0 POSTs with no matching slot */
static int        g_bounceAllocBudget; /* allocs still allowed; <0 = unlimited */

void whTestDma_BounceReset(void)
{
    memset(g_bouncePool, BOUNCE_POISON_BYTE, sizeof(g_bouncePool));
    memset(g_bounceSlots, 0, sizeof(g_bounceSlots));
    g_bounceUsed        = 0;
    g_bounceOutstanding = 0;
    g_bounceStrayPost   = 0;
    g_bounceAllocBudget = -1;
}

int whTestDma_BounceOutstanding(void)
{
    return g_bounceOutstanding;
}

int whTestDma_BounceStrayPosts(void)
{
    return g_bounceStrayPost;
}

void whTestDma_BounceSetAllocBudget(int allocs)
{
    g_bounceAllocBudget = allocs;
}

static bounceSlot* _bounceAlloc(size_t len)
{
    int    i;
    size_t aligned = (len + 7u) & ~(size_t)7u; /* 8-byte align slices */

    /* Injected failure for exercising leak-recovery paths; no diagnostic. */
    if (g_bounceAllocBudget == 0) {
        return NULL;
    }

    if (g_bounceUsed + aligned > sizeof(g_bouncePool)) {
        /* With recycle-on-empty this usually means a leaked mapping (PRE
         * without POST) rather than a too-small pool. */
        WH_ERROR_PRINT("wh_test bounce: pool exhausted (used %u + %u > %u, "
                       "%d outstanding); likely a leaked DMA mapping\n",
                       (unsigned)g_bounceUsed, (unsigned)aligned,
                       (unsigned)sizeof(g_bouncePool), g_bounceOutstanding);
        return NULL;
    }
    for (i = 0; i < BOUNCE_POOL_SLOTS; i++) {
        if (!g_bounceSlots[i].inUse) {
            g_bounceSlots[i].inUse = 1;
            g_bounceSlots[i].base  = (uintptr_t)&g_bouncePool[g_bounceUsed];
            g_bounceSlots[i].len   = len;
            g_bounceUsed += aligned;
            g_bounceOutstanding++;
            if (g_bounceAllocBudget > 0) {
                g_bounceAllocBudget--;
            }
            return &g_bounceSlots[i];
        }
    }
    WH_ERROR_PRINT("wh_test bounce: out of slots (%d); raise BOUNCE_POOL_SLOTS "
                   "or check for a leaked mapping\n",
                   BOUNCE_POOL_SLOTS);
    return NULL;
}

static bounceSlot* _bounceFind(uintptr_t base)
{
    int i;
    for (i = 0; i < BOUNCE_POOL_SLOTS; i++) {
        if (g_bounceSlots[i].inUse && g_bounceSlots[i].base == base) {
            return &g_bounceSlots[i];
        }
    }
    return NULL;
}

static void _bounceFree(bounceSlot* s)
{
    /* Poison on free so any read of a stale (post-POST) slot is detectable. */
    memset((void*)s->base, BOUNCE_POISON_BYTE, s->len);
    s->inUse = 0;
    s->base  = 0;
    s->len   = 0;
    g_bounceOutstanding--;
    /* Recycle the whole pool once every slot has been released, so a long run
     * of operations cannot exhaust the bump offset. */
    if (g_bounceOutstanding == 0) {
        g_bounceUsed = 0;
    }
}

int whTestDma_BounceClientCb(struct whClientContext_t* client,
                             uintptr_t clientAddr, void** xformedAddr,
                             size_t len, whDmaOper oper, whDmaFlags flags)
{
    bounceSlot* s;
    (void)client;
    (void)flags;

    /* Zero-length operations carry no data and are never dereferenced by the
     * server; pass the address through untouched (no slot needed). */
    if (len == 0) {
        *xformedAddr = (void*)clientAddr;
        return WH_ERROR_OK;
    }

    switch (oper) {
        case WH_DMA_OPER_CLIENT_READ_PRE:
            /* Server is about to read client memory: copy it into a pool slot
             * and hand the server the pool address. */
            s = _bounceAlloc(len);
            if (s == NULL) {
                return WH_ERROR_ABORTED;
            }
            memcpy((void*)s->base, (void*)clientAddr, len);
            *xformedAddr = (void*)s->base;
            break;

        case WH_DMA_OPER_CLIENT_WRITE_PRE:
            /* Server is about to write client memory: give it a pool slot to
             * write into. */
            s = _bounceAlloc(len);
            if (s == NULL) {
                return WH_ERROR_ABORTED;
            }
            *xformedAddr = (void*)s->base;
            break;

        case WH_DMA_OPER_CLIENT_READ_POST:
            /* Release (and poison) the slot. A len>0 POST matching no live slot
             * is a stray/double POST (a real port would free a bogus pointer);
             * record it. */
            s = _bounceFind((uintptr_t)*xformedAddr);
            if (s != NULL) {
                _bounceFree(s);
            }
            else {
                g_bounceStrayPost++;
            }
            break;

        case WH_DMA_OPER_CLIENT_WRITE_POST:
            /* Server done writing: copy the result back to the client buffer,
             * then release (and poison) the slot. See READ_POST on stray. */
            s = _bounceFind((uintptr_t)*xformedAddr);
            if (s != NULL) {
                memcpy((void*)clientAddr, (void*)s->base, len);
                _bounceFree(s);
            }
            else {
                g_bounceStrayPost++;
            }
            break;
    }
    return WH_ERROR_OK;
}

int whTestDma_BounceServerCb(struct whServerContext_t* server,
                             uintptr_t clientAddr, void** serverPtr, size_t len,
                             whDmaOper oper, whDmaFlags flags)
{
    uintptr_t base = (uintptr_t)g_bouncePool;
    (void)server;
    (void)oper;
    (void)flags;

    /* An address outside the pool means a *Dma path skipped translation and
     * sent a raw client pointer; reject it. Overflow-safe: clientAddr - base is
     * only formed once clientAddr >= base. */
    if (len > 0) {
        if (clientAddr < base || clientAddr - base > sizeof(g_bouncePool) ||
            len > sizeof(g_bouncePool) - (clientAddr - base)) {
            WH_ERROR_PRINT("wh_test bounce: server got untranslated address %p "
                           "(len %u) outside the DMA pool\n",
                           (void*)clientAddr, (unsigned)len);
            return WH_ERROR_ACCESS;
        }
    }

    /* Pool address is directly usable by the server in this same process. */
    *serverPtr = (void*)clientAddr;
    return WH_ERROR_OK;
}

static int whTest_DmaAllowListBasic(void)
{
    int                rc;
    whDmaAddrAllowList allowList;

    memset(&allowList, 0, sizeof(allowList));

    allowList.readList[0].addr = (void*)((uintptr_t)0x10000);
    allowList.readList[0].size = 0x10000;

    WH_TEST_PRINT("  Testing basic allow list acceptance...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)((uintptr_t)0x10000), 0x1000);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    WH_TEST_PRINT("  Testing basic allow list rejection...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)((uintptr_t)0x30000), 0x1000);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Testing zero-size rejection...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)((uintptr_t)0x10000), 0);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    WH_TEST_PRINT("  Testing NULL allowlist passthrough...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        NULL, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)((uintptr_t)0x10000), 0x1000);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    return WH_ERROR_OK;
}

static int whTest_DmaAllowListOverflow(void)
{
    int                rc;
    whDmaAddrAllowList allowList;
    uintptr_t          maliciousAddr;
    size_t             maliciousSize;

    memset(&allowList, 0, sizeof(allowList));

    /*
     * Allow list region: [0x10000, 0x20000)
     *   allowListEndAddr = 0x10000 + 0x10000 = 0x20000 (no overflow)
     */
    allowList.readList[0].addr = (void*)((uintptr_t)0x10000);
    allowList.readList[0].size = 0x10000;

    /*
     * Craft a request whose endAddr wraps around to land inside the allow list:
     *   startAddr  = UINTPTR_MAX - 0xFF   (near top of address space)
     *   size       = 0x20100
     *   endAddr    = (UINTPTR_MAX - 0xFF) + 0x20100
     *             = UINTPTR_MAX + 0x20001
     *             = 0x20000  (truncated on any width)
     *
     * Without overflow protection the check sees:
     *   startAddr(huge) >= allowListStartAddr(0x10000)  -> TRUE
     *   endAddr(0x20000) <= allowListEndAddr(0x20000)   -> TRUE
     * and incorrectly allows access to memory at the top of the address space.
     */
    maliciousAddr = UINTPTR_MAX - 0xFF;
    maliciousSize = 0x20100;

    WH_TEST_PRINT("  Testing request end-address overflow "
                  "(sizeof(uintptr_t)=%u)...\n",
                  (unsigned)sizeof(uintptr_t));
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)maliciousAddr, maliciousSize);
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK);

    /*
     * Second vector: addr = UINTPTR_MAX, size = 1
     *   endAddr = UINTPTR_MAX + 1 = 0  (wraps to zero)
     */
    WH_TEST_PRINT("  Testing boundary wrap addr=UINTPTR_MAX size=1...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)UINTPTR_MAX, 1);
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK);

    /*
     * Third vector: size = UINTPTR_MAX with a non-zero start address.
     *   addr = 1, size = UINTPTR_MAX
     *   endAddr = 1 + UINTPTR_MAX = 0  (wraps to zero)
     */
    WH_TEST_PRINT("  Testing maximum size overflow addr=1 "
                  "size=UINTPTR_MAX...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_READ_PRE,
        (void*)((uintptr_t)1), (size_t)UINTPTR_MAX);
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK);

    /* Also test the write list path */
    memset(&allowList, 0, sizeof(allowList));
    allowList.writeList[0].addr = (void*)((uintptr_t)0x10000);
    allowList.writeList[0].size = 0x10000;

    WH_TEST_PRINT("  Testing write-path overflow...\n");
    rc = wh_Dma_CheckMemOperAgainstAllowList(
        &allowList, WH_DMA_OPER_CLIENT_WRITE_PRE,
        (void*)maliciousAddr, maliciousSize);
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK);

    return WH_ERROR_OK;
}

int whTest_Dma(void)
{
    WH_TEST_PRINT("Testing DMA allow list checks...\n");

    WH_TEST_RETURN_ON_FAIL(whTest_DmaAllowListBasic());
    WH_TEST_RETURN_ON_FAIL(whTest_DmaAllowListOverflow());

    WH_TEST_PRINT("DMA allow list tests PASSED\n");
    return WH_ERROR_OK;
}

#else /* !WOLFHSM_CFG_DMA */

int whTest_Dma(void)
{
    return 0;
}

#endif /* WOLFHSM_CFG_DMA */
