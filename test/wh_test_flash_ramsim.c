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
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER)

#include "wh_test_common.h"
#include "wh_test_flash_ramsim.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_error.h"

#define TEST_FLASH_SIZE (1024 * 1024)
#define TEST_SECTOR_SIZE (4096)
#define TEST_PAGE_SIZE (256)

static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue);
#if defined(WH_TEST_FLASH_RAMSIM_DEBUG)
static void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset);
#endif


static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue)
{
    size_t i = 0;
    for (i = 0; i < size; i++) {
        buffer[i] = (uint8_t)(baseValue + i);
    }
}

#if defined(WH_TEST_FLASH_RAMSIM_DEBUG)
static void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset)
{
    printf("Memory at offset %u: ", offset);
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */


int whTest_Flash_RamSim(void)
{
    int              ret;
    whFlashRamsimCtx ctx;
    uint8_t memory[TEST_FLASH_SIZE] = {0};
    whFlashRamsimCfg cfg = {.size       = TEST_FLASH_SIZE,
                            .sectorSize = TEST_SECTOR_SIZE,
                            .pageSize   = TEST_PAGE_SIZE,
                            .erasedByte = 0xFF,
                            .memory     = memory,
    };

    uint8_t testData[TEST_PAGE_SIZE] = {0};
    uint8_t readData[TEST_PAGE_SIZE] = {0};

    printf("Testing RAM-based flash simulator...\n");

    WH_TEST_RETURN_ON_FAIL(whFlashRamsim_Init(&ctx, &cfg));

    /* First, check write lock functionality, assuming we start unlocked */
    if (ctx.writeLocked == 1) {
        WH_ERROR_PRINT("RamSim locked on init\n");
        whFlashRamsim_Cleanup(&ctx);
        return WH_TEST_FAIL;
    }
    if ((ret = whFlashRamsim_WriteLock(&ctx, 0, cfg.sectorSize)) !=
        WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to set write lock, ret=%d\n", ret);
        whFlashRamsim_Cleanup(&ctx);
        return ret;
    }
    if ((ret = whFlashRamsim_Erase(&ctx, 0, cfg.sectorSize)) !=
        WH_ERROR_LOCKED) {
        WH_ERROR_PRINT("RamSim lock protection fail on erase, ret=%d\n", ret);
        whFlashRamsim_Cleanup(&ctx);
        return ret;
    }
    if ((ret = whFlashRamsim_Program(&ctx, 0, TEST_PAGE_SIZE, testData)) !=
        WH_ERROR_LOCKED) {
        WH_ERROR_PRINT("RamSim lock protection fail on program, ret=%d\n", ret);
        whFlashRamsim_Cleanup(&ctx);
        return ret;
    }
    if ((ret = whFlashRamsim_WriteUnlock(&ctx, 0, cfg.sectorSize)) !=
        WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to unlock, ret=%d\n", ret);
        whFlashRamsim_Cleanup(&ctx);
        return ret;
    }

    uint32_t sector = 0;
    for (sector = 0; sector < cfg.size / cfg.sectorSize; sector++) {

        uint32_t sectorOffset = sector * cfg.sectorSize;

        if ((ret = whFlashRamsim_Erase(&ctx, sectorOffset, cfg.sectorSize)) !=
            0) {
            WH_ERROR_PRINT("whFlashRamsim_Erase failed to erase sector %u "
                           "(offset=%u, size=%u): ret=%d\n",
                           (unsigned int)sector, (unsigned int)sectorOffset, (unsigned int)cfg.sectorSize, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }

        if ((ret = whFlashRamsim_BlankCheck(&ctx, sectorOffset,
                                            cfg.sectorSize)) != 0) {
            WH_ERROR_PRINT(
                "Sector %u is not blank (offset=%u, size=%u): ret=%d\n", (unsigned int)sector,
                (unsigned int)sectorOffset, (unsigned int)cfg.sectorSize, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }

        uint32_t page = 0;
        for (page = 0; page < cfg.sectorSize / cfg.pageSize; page++) {

            uint32_t pageOffset = sectorOffset + page * cfg.pageSize;

            fillTestData(testData, cfg.pageSize, page);

            if ((ret = whFlashRamsim_Read(&ctx, pageOffset, cfg.pageSize,
                                          readData)) != 0) {
                WH_ERROR_PRINT("whFlashRamsim_Read failed: ret=%d\n", ret);
                whFlashRamsim_Cleanup(&ctx);
                return ret;
            };

#if WH_TEST_FLASH_RAMSIM_DEBUG
            printf("Page %u in sector %u before programming:\n", (unsigned int)page, (unsigned int)sector);
            printMemory(readData, cfg.pageSize, pageOffset);
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */

            if ((ret = whFlashRamsim_Program(&ctx, pageOffset, cfg.pageSize,
                                             testData)) != 0) {
                WH_ERROR_PRINT("whFlashRamsim_Program failed to program page "
                               "%u in sector %u: ret=%d\n",
                               (unsigned int)page, (unsigned int)sector, ret);
                whFlashRamsim_Cleanup(&ctx);
                return ret;
            }

#if WH_TEST_FLASH_RAMSIM_DEBUG
            printf("Page %u in sector %u after programming:\n", (unsigned int)page, (unsigned int)sector);
            whFlashRamsim_Read(&ctx, pageOffset, cfg.pageSize, readData);
            printMemory(readData, cfg.pageSize, pageOffset);
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */

            if ((ret = whFlashRamsim_Verify(&ctx, pageOffset, cfg.pageSize,
                                            testData)) != 0) {
                WH_ERROR_PRINT("whFlashRamsim_Verify failed for page %u in "
                               "sector %u: ret=%d\n",
                               (unsigned int)page, (unsigned int)sector, ret);
                whFlashRamsim_Cleanup(&ctx);
                return ret;
            }
        }

        if ((ret = whFlashRamsim_BlankCheck(
                 &ctx, sectorOffset, cfg.sectorSize)) != WH_ERROR_NOTBLANK) {
            WH_ERROR_PRINT("Sector %u is not blank, ret=%d\n", (unsigned int)sector, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }

        if ((ret = whFlashRamsim_Erase(&ctx, sectorOffset, cfg.sectorSize)) !=
            0) {
            WH_ERROR_PRINT(
                "whFlashRamsim_Erase failed to erase sector %u: ret=%d\n",
                (unsigned int)sector, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }

        if ((ret = whFlashRamsim_BlankCheck(&ctx, sectorOffset,
                                            cfg.sectorSize)) != 0) {
            WH_ERROR_PRINT("Sector %u is not blank, ret=%d\n", (unsigned int)sector, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }
    }

    whFlashRamsim_Cleanup(&ctx);

    return 0;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
