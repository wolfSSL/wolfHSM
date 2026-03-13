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
