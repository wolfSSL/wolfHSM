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
 * test-refactor/posix/wh_test_posix_shm_dma.c
 *
 * In-place buffers in the POSIX shared memory client DMA callback. A client
 * buffer already inside the DMA area is passed to the server as its offset,
 * without a bounce copy; with WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT a
 * buffer the server writes must also be aligned. The object is mapped twice, as
 * server and as client, so the two mappings sit at different addresses as in
 * two processes.
 */

#include "wolfhsm/wh_settings.h"

#include "wh_test_common.h"
#include "wh_test_list.h" /* WH_TEST_SKIPPED */

#if !defined(WOLFHSM_CFG_DMA) || defined(WOLFHSM_CFG_NO_CRYPTO) || \
    !defined(WOLFHSM_CFG_ENABLE_CLIENT) || !defined(WOLFHSM_CFG_ENABLE_SERVER)

int whTest_PosixShmDmaInPlace(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#else

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "port/posix/posix_transport_shm.h"

/* Without the rule any alignment is accepted; 64 just exercises the path */
#ifdef WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
#define SHMDMA_ALIGN WOLFHSM_CFG_DMA_ALIGN
#else
#define SHMDMA_ALIGN 64
#endif
#define SHMDMA_LEN 64

static int _ShmDmaInPlace(whClientContext* client, uint8_t* cliDma,
                          uint8_t* srvDma)
{
    whDmaFlags flags;
    void*      off = NULL;
    uint8_t*   buf;
    int        ret;

    memset(&flags, 0, sizeof(flags));
    buf = (uint8_t*)(((uintptr_t)cliDma + SHMDMA_ALIGN - 1) &
                     ~((uintptr_t)SHMDMA_ALIGN - 1));
    WH_TEST_ASSERT_RETURN(srvDma != cliDma);

    /* Aligned output: used in place, the server reaches it by offset */
    ret = posixTransportShm_ClientStaticMemDmaCallback(
        client, (uintptr_t)buf, &off, SHMDMA_LEN, WH_DMA_OPER_CLIENT_WRITE_PRE,
        flags);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN((uintptr_t)off == (uintptr_t)(buf - cliDma));
    memset(srvDma + (uintptr_t)off, 0xA5, SHMDMA_LEN);
    WH_TEST_ASSERT_RETURN(buf[0] == 0xA5 && buf[SHMDMA_LEN - 1] == 0xA5);
    ret = posixTransportShm_ClientStaticMemDmaCallback(
        client, (uintptr_t)buf, &off, SHMDMA_LEN, WH_DMA_OPER_CLIENT_WRITE_POST,
        flags);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Unaligned output: shares a cache line, refused when non-coherent */
    ret = posixTransportShm_ClientStaticMemDmaCallback(
        client, (uintptr_t)(buf + 1), &off, SHMDMA_LEN,
        WH_DMA_OPER_CLIENT_WRITE_PRE, flags);
#ifdef WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
#else
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
#endif

    /* Unaligned input: the server only reads it, so always accepted */
    ret = posixTransportShm_ClientStaticMemDmaCallback(
        client, (uintptr_t)(buf + 1), &off, SHMDMA_LEN,
        WH_DMA_OPER_CLIENT_READ_PRE, flags);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN((uintptr_t)off == (uintptr_t)(buf + 1 - cliDma));
    ret = posixTransportShm_ClientStaticMemDmaCallback(
        client, (uintptr_t)(buf + 1), &off, SHMDMA_LEN,
        WH_DMA_OPER_CLIENT_READ_POST, flags);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    return 0;
}

int whTest_PosixShmDmaInPlace(void* ctx)
{
    char                           name[32];
    posixTransportShmConfig        cfg;
    posixTransportShmServerContext srvShm[1];
    posixTransportShmClientContext cliShm[1];
    whClientContext                client[1];
    void*                          cliDma = NULL;
    void*                          srvDma = NULL;
    int                            ret;

    (void)ctx;
    /* Per-process name, so concurrent test runs do not share the object */
    (void)snprintf(name, sizeof(name), "/wh_test_shmdma_%d", (int)getpid());
    memset(&cfg, 0, sizeof(cfg));
    cfg.name      = name;
    cfg.req_size  = 256;
    cfg.resp_size = 256;
    cfg.dma_size  = 4 * SHMDMA_ALIGN;

    memset(client, 0, sizeof(client));
    client->comm->transport_context = cliShm;

    ret = posixTransportShm_ServerInit(srvShm, &cfg, NULL, NULL);
    if (ret == 0) {
        ret = posixTransportShm_ClientInit(cliShm, &cfg, NULL, NULL);
        if (ret == 0) {
            (void)posixTransportShm_GetDma(cliShm, &cliDma, NULL);
            (void)posixTransportShm_GetDma(srvShm, &srvDma, NULL);
            ret = (cliDma == NULL || srvDma == NULL)
                      ? WH_ERROR_NOTREADY
                      : _ShmDmaInPlace(client, cliDma, srvDma);
            (void)posixTransportShm_Cleanup(cliShm);
        }
        (void)posixTransportShm_Cleanup(srvShm);
        (void)shm_unlink(name); /* normally already unlinked by the client */
    }
    return ret;
}

#endif
