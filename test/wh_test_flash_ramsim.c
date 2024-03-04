#include <stdio.h>
#include <string.h>

#include "wh_test_common.h"
#include "wh_test_flash_ramsim.h"
#include "wolfhsm/wh_flash_ramsim.h"

#define TEST_FLASH_SIZE (1024 * 1024)
#define TEST_SECTOR_SIZE (256)
#define TEST_PAGE_SIZE (256)

static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue);
#if defined(WH_TEST_FLASH_RAMSIM_DEBUG)
static void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset);
#endif


static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue)
{
    for (size_t i = 0; i < size; i++) {
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
    whFlashRamsimCfg cfg = {.size       = TEST_FLASH_SIZE,
                            .sectorSize = TEST_SECTOR_SIZE,
                            .pageSize   = TEST_PAGE_SIZE,
                            .erasedByte = 0xFF};

    uint8_t testData[TEST_PAGE_SIZE] = {0};
    uint8_t readData[TEST_PAGE_SIZE] = {0};

    printf("Testing RAM-based flash simulator...\n");

    WH_TEST_RETURN_ON_FAIL(whFlashRamsim_Init(&ctx, &cfg));

    for (uint32_t sector = 0; sector < cfg.size / cfg.sectorSize; sector++) {

        uint32_t sectorOffset = sector * cfg.sectorSize;

        if (whFlashRamsim_Erase(&ctx, sectorOffset, cfg.sectorSize) != 0) {
            WH_ERROR_PRINT(
                "whFlashRamsim_Erase failed to erase sector %u: ret=%d\n",
                sector, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }

        if (whFlashRamsim_BlankCheck(&ctx, sectorOffset, cfg.sectorSize) != 0) {
            WH_ERROR_PRINT("Sector %u is not blank, ret=%d\n", sector, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }


        for (uint32_t page = 0; page < cfg.sectorSize / cfg.pageSize; page++) {

            uint32_t pageOffset = sectorOffset + page * cfg.pageSize;

            fillTestData(testData, cfg.pageSize, page);

            if ((ret = whFlashRamsim_Read(&ctx, pageOffset, cfg.pageSize,
                                          readData)) != 0) {
                WH_ERROR_PRINT("whFlashRamsim_Read failed: ret=%d\n", ret);
                whFlashRamsim_Cleanup(&ctx);
                return ret;
            };

#if WH_TEST_FLASH_RAMSIM_DEBUG
            printf("Page %u in sector %u before programming:\n", page, sector);
            printMemory(readData, cfg.pageSize, pageOffset);
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */

            if ((ret = whFlashRamsim_Program(&ctx, pageOffset, cfg.pageSize,
                                             testData)) != 0) {
                WH_ERROR_PRINT("whFlashRamsim_Program failed to program page "
                               "%u in sector %u: ret=%d\n",
                               page, sector, ret);
                whFlashRamsim_Cleanup(&ctx);
                return ret;
            }

#if WH_TEST_FLASH_RAMSIM_DEBUG
            printf("Page %u in sector %u after programming:\n", page, sector);
            whFlashRamsim_Read(&ctx, pageOffset, cfg.pageSize, readData);
            printMemory(readData, cfg.pageSize, pageOffset);
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */

            if ((ret = whFlashRamsim_Verify(&ctx, pageOffset, cfg.pageSize,
                                            testData)) != 0) {
                WH_ERROR_PRINT("whFlashRamsim_Verify failed for page %u in "
                               "sector %u: ret=%d\n",
                               page, sector, ret);
                whFlashRamsim_Cleanup(&ctx);
                return ret;
            }
        }

        if (whFlashRamsim_Erase(&ctx, sectorOffset, cfg.sectorSize) != 0) {
            WH_ERROR_PRINT(
                "whFlashRamsim_Erase failed to erase sector %u: ret=%d\n",
                sector, ret);
            whFlashRamsim_Cleanup(&ctx);
            return ret;
        }

        if (whFlashRamsim_BlankCheck(&ctx, sectorOffset, cfg.sectorSize) != 0) {
            WH_ERROR_PRINT("Sector %u is not blank, ret=%d\n", sector, ret);
        }
    }

    whFlashRamsim_Cleanup(&ctx);

    return 0;
}
