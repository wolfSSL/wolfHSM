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

#ifdef WOLFHSM_CFG_TEST_DMA_ALIGN_CHECK
#include <stdio.h>
#include <stdlib.h>

#if defined(__SANITIZE_ADDRESS__)
#define WH_DMA_ALIGN_CHECK_ASAN
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define WH_DMA_ALIGN_CHECK_ASAN
#endif
#endif

#ifdef WH_DMA_ALIGN_CHECK_ASAN
#include <sanitizer/asan_interface.h>
#include <sanitizer/common_interface_defs.h>
#endif

/* Abort when a buffer the server writes shares a cache line with other data.
 * The start is checked directly. The padding is only checked under ASAN, which
 * keeps the bytes around each stack, heap and global object unaddressable. A
 * buffer inside a larger object, such as a struct member, only gets the start
 * check. */
static void _CheckDmaWriteBuffer(uintptr_t addr, size_t len)
{
    const void* bad = NULL;

    if (len == 0) {
        return;
    }
    if (!WH_DMA_IS_ALIGNED(addr)) {
        bad = (const void*)addr;
    }
#ifdef WH_DMA_ALIGN_CHECK_ASAN
    else {
        bad = __asan_region_is_poisoned((void*)addr, WH_DMA_PAD_SIZE(len));
    }
#endif
    if (bad == NULL) {
        return;
    }

    WOLFHSM_CFG_PRINTF("DMA output buffer %p (len %u) is not aligned and "
                       "padded to WOLFHSM_CFG_DMA_ALIGN (%u), first bad byte "
                       "%p\n",
                       (void*)addr, (unsigned)len,
                       (unsigned)WOLFHSM_CFG_DMA_ALIGN, bad);
    /* abort() does not flush stdio, and a piped stdout is buffered */
    (void)fflush(NULL);
#ifdef WH_DMA_ALIGN_CHECK_ASAN
    /* Names the offending variable and the call that passed it */
    __asan_describe_address((void*)bad);
    __sanitizer_print_stack_trace();
#endif
    abort();
}
#endif /* WOLFHSM_CFG_TEST_DMA_ALIGN_CHECK */


int wh_Client_DmaRegisterAllowList(whClientContext*          client,
                                   const whDmaAddrAllowList* allowlist)
{
    if (NULL == client) {
        return WH_ERROR_BADARGS;
    }

    /* A NULL allowlist clears any previously registered list (no enforcement),
     * symmetric with wh_Client_DmaRegisterCb(NULL). */
    client->dma.dmaAddrAllowList = allowlist;

    return WH_ERROR_OK;
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
 * location of shared memory. This also handles post translate operations
 * given the whDmaOper passed in. */
int wh_Client_DmaProcessClientAddress(whClientContext* client,
                                      uintptr_t        clientAddr,
                                      void** xformedCliAddr, size_t len,
                                      whDmaOper oper, whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == xformedCliAddr) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_TEST_DMA_ALIGN_CHECK
    /* Every buffer the server writes passes through here, whatever the port
     * callback does with it */
    if (oper == WH_DMA_OPER_CLIENT_WRITE_PRE) {
        _CheckDmaWriteBuffer(clientAddr, len);
    }
#endif

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

    /* if the client has a allowlist registered, check address against it */
    if (rc == WH_ERROR_OK && len > 0) {
        rc = wh_Dma_CheckMemOperAgainstAllowList(client->dma.dmaAddrAllowList,
                                                 oper, *xformedCliAddr, len);
    }
    return rc;
}

int wh_Client_DmaAsyncPre(whClientContext* client, whClientDmaAsyncBuf* buf,
                          uintptr_t clientAddr, uint64_t len, whDmaOper preOper,
                          uintptr_t* outXformedAddr)
{
    int       rc       = WH_ERROR_OK;
    uintptr_t addr     = 0;
    whDmaOper postOper = WH_DMA_OPER_CLIENT_READ_POST;

    if (client == NULL || buf == NULL || outXformedAddr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* The POST always matches the PRE's direction, so derive it here rather
     * than have every caller pass (and risk mismatching) both halves. */
    switch (preOper) {
        case WH_DMA_OPER_CLIENT_READ_PRE:
            postOper = WH_DMA_OPER_CLIENT_READ_POST;
            break;
        case WH_DMA_OPER_CLIENT_WRITE_PRE:
            postOper = WH_DMA_OPER_CLIENT_WRITE_POST;
            break;
        default:
            /* Caller passed a POST or otherwise invalid operation, not a PRE. */
            return WH_ERROR_BADARGS;
    }

    /* Clear the whole slot up front so a skipped or failed PRE leaves nothing
     * for the matching POST (run in the Response) to act on. */
    memset(buf, 0, sizeof(*buf));
    *outXformedAddr = 0;

    /* Nothing to map (e.g. an optional buffer that is absent): leave the slot
     * cleared and report success with a 0 transformed address. */
    if (len == 0) {
        return WH_ERROR_OK;
    }

    rc = wh_Client_DmaProcessClientAddress(client, clientAddr, (void**)&addr,
                                           (size_t)len, preOper,
                                           (whDmaFlags){0});
    if (rc == WH_ERROR_OK) {
        buf->xformedAddr = addr;
        buf->clientAddr  = clientAddr;
        buf->sz          = len;
        buf->postOper    = postOper;
        *outXformedAddr  = addr;
    }
    return rc;
}

int wh_Client_DmaAsyncPost(whClientContext* client, whClientDmaAsyncBuf* buf)
{
    int       rc;
    uintptr_t addr;

    if (client == NULL || buf == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Nothing stashed (PRE was skipped or the slot was already cleaned up):
     * a legitimate no-op, distinct from the NULL-arg misuse above. */
    if (buf->sz == 0) {
        return WH_ERROR_OK;
    }

    addr = buf->xformedAddr;
    rc   = wh_Client_DmaProcessClientAddress(client, buf->clientAddr,
                                             (void**)&addr, (size_t)buf->sz,
                                             buf->postOper, (whDmaFlags){0});
    /* Clear the whole slot even on failure so a later Response cannot re-run
     * the POST; the failure is returned to the caller. */
    memset(buf, 0, sizeof(*buf));
    return rc;
}
#endif /* WOLFHSM_CFG_DMA */
