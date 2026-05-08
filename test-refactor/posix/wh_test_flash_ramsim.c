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
 * test-refactor/wh_test_flash_ramsim.c
 *
 * Flash RamSim test suite. Exercises the RAM-based flash simulator
 * through init, write-lock, erase, program, verify, and blank-check
 * operations. No setup/cleanup needed -- the test manages its own
 * flash context internally.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define TEST_FLASH_SIZE   (1024 * 1024)
#define TEST_SECTOR_SIZE  (4096)
#define TEST_PAGE_SIZE    (256)


static void _fillTestData(uint8_t* buf, uint32_t size,
    uint32_t base)
{
    uint32_t i;
    for (i = 0; i < size; i++) {
        buf[i] = (uint8_t)(base + i);
    }
}


/*
 * Verify that write-lock prevents erase and program, and that
 * unlock restores access.
 */
int whTest_FlashWriteLock(void* ctx)
{
    int              ret;
    whFlashRamsimCtx fctx;
    static uint8_t   memory[TEST_FLASH_SIZE];
    uint8_t          page[TEST_PAGE_SIZE] = {0};
    whFlashRamsimCfg cfg = {
        .size       = TEST_FLASH_SIZE,
        .sectorSize = TEST_SECTOR_SIZE,
        .pageSize   = TEST_PAGE_SIZE,
        .erasedByte = 0xFF,
        .memory     = memory,
    };

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(whFlashRamsim_Init(&fctx, &cfg));

    if (fctx.writeLocked == 1) {
        WH_ERROR_PRINT("RamSim locked on init\n");
        whFlashRamsim_Cleanup(&fctx);
        return WH_TEST_FAIL;
    }

    /* Lock sector 0 */
    ret = whFlashRamsim_WriteLock(&fctx, 0, cfg.sectorSize);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("WriteLock failed: ret=%d\n", ret);
        whFlashRamsim_Cleanup(&fctx);
        return ret;
    }

    /* Erase and program must fail while locked */
    ret = whFlashRamsim_Erase(&fctx, 0, cfg.sectorSize);
    if (ret != WH_ERROR_LOCKED) {
        WH_ERROR_PRINT("Erase not blocked by lock: ret=%d\n",
            ret);
        whFlashRamsim_Cleanup(&fctx);
        return WH_TEST_FAIL;
    }

    ret = whFlashRamsim_Program(&fctx, 0, TEST_PAGE_SIZE, page);
    if (ret != WH_ERROR_LOCKED) {
        WH_ERROR_PRINT("Program not blocked by lock: ret=%d\n",
            ret);
        whFlashRamsim_Cleanup(&fctx);
        return WH_TEST_FAIL;
    }

    /* Unlock and verify access is restored */
    ret = whFlashRamsim_WriteUnlock(&fctx, 0, cfg.sectorSize);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("WriteUnlock failed: ret=%d\n", ret);
        whFlashRamsim_Cleanup(&fctx);
        return ret;
    }

    whFlashRamsim_Cleanup(&fctx);
    return 0;
}


/*
 * Erase every sector, program every page with known data,
 * verify, then erase again and blank-check.
 */
int whTest_FlashEraseProgramVerify(void* ctx)
{
    int              ret;
    whFlashRamsimCtx fctx;
    static uint8_t   memory[TEST_FLASH_SIZE];
    uint8_t          testData[TEST_PAGE_SIZE];
    uint32_t         sector;
    whFlashRamsimCfg cfg = {
        .size       = TEST_FLASH_SIZE,
        .sectorSize = TEST_SECTOR_SIZE,
        .pageSize   = TEST_PAGE_SIZE,
        .erasedByte = 0xFF,
        .memory     = memory,
    };

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(whFlashRamsim_Init(&fctx, &cfg));

    for (sector = 0; sector < cfg.size / cfg.sectorSize;
         sector++) {
        uint32_t sOff = sector * cfg.sectorSize;
        uint32_t page;

        /* Erase sector */
        ret = whFlashRamsim_Erase(&fctx, sOff,
            cfg.sectorSize);
        if (ret != 0) {
            WH_ERROR_PRINT("Erase sector %u failed: %d\n",
                (unsigned)sector, ret);
            whFlashRamsim_Cleanup(&fctx);
            return ret;
        }

        /* Blank check after erase */
        ret = whFlashRamsim_BlankCheck(&fctx, sOff,
            cfg.sectorSize);
        if (ret != 0) {
            WH_ERROR_PRINT("BlankCheck sector %u failed: %d\n",
                (unsigned)sector, ret);
            whFlashRamsim_Cleanup(&fctx);
            return ret;
        }

        /* Program and verify each page */
        for (page = 0;
             page < cfg.sectorSize / cfg.pageSize;
             page++) {
            uint32_t pOff = sOff + page * cfg.pageSize;

            _fillTestData(testData, cfg.pageSize, page);

            ret = whFlashRamsim_Program(&fctx, pOff,
                cfg.pageSize, testData);
            if (ret != 0) {
                WH_ERROR_PRINT("Program page %u sector %u"
                    " failed: %d\n",
                    (unsigned)page, (unsigned)sector, ret);
                whFlashRamsim_Cleanup(&fctx);
                return ret;
            }

            ret = whFlashRamsim_Verify(&fctx, pOff,
                cfg.pageSize, testData);
            if (ret != 0) {
                WH_ERROR_PRINT("Verify page %u sector %u"
                    " failed: %d\n",
                    (unsigned)page, (unsigned)sector, ret);
                whFlashRamsim_Cleanup(&fctx);
                return ret;
            }
        }

        /* Sector should no longer be blank */
        ret = whFlashRamsim_BlankCheck(&fctx, sOff,
            cfg.sectorSize);
        if (ret != WH_ERROR_NOTBLANK) {
            WH_ERROR_PRINT("Sector %u blank after program:"
                " %d\n", (unsigned)sector, ret);
            whFlashRamsim_Cleanup(&fctx);
            return WH_TEST_FAIL;
        }

        /* Erase and confirm blank */
        ret = whFlashRamsim_Erase(&fctx, sOff,
            cfg.sectorSize);
        if (ret != 0) {
            WH_ERROR_PRINT("Re-erase sector %u failed: %d\n",
                (unsigned)sector, ret);
            whFlashRamsim_Cleanup(&fctx);
            return ret;
        }

        ret = whFlashRamsim_BlankCheck(&fctx, sOff,
            cfg.sectorSize);
        if (ret != 0) {
            WH_ERROR_PRINT("Sector %u not blank after"
                " re-erase: %d\n", (unsigned)sector, ret);
            whFlashRamsim_Cleanup(&fctx);
            return ret;
        }
    }

    whFlashRamsim_Cleanup(&fctx);
    return 0;
}
