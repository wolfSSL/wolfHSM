#include <stdio.h>
#include <string.h>

#include "wh_test_common.h"
#include "wh_test_flash_ramsim.h"
#include "wolfhsm/wh_nvm_flash_ramsim.h"

#define TEST_FLASH_SIZE (1024 * 1024)
#define TEST_SECTOR_SIZE (256)
#define TEST_PAGE_SIZE (256)

static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue);
#if defined(WH_TEST_FLASH_RAMSIM_DEBUG)
static void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset);
#endif


static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue)
{
    for (uint32_t i = 0; i < size; ++i) {
        buffer[i] = (uint8_t)(baseValue + i);
    }
}

#if defined(WH_TEST_FLASH_RAMSIM_DEBUG)
static void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset)
{
    printf("Memory at offset %u: ", offset);
    for (uint32_t i = 0; i < size; ++i) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */


int whTest_Flash_RamSim(void)
{
    WhNvmFlashRamSimCtx ctx;
    WhNvmFlashRamSimCfg cfg = {.size       = TEST_FLASH_SIZE,
                               .sectorSize = TEST_SECTOR_SIZE,
                               .pageSize   = TEST_PAGE_SIZE,
                               .erasedByte = 0xFF
    }; 

    uint8_t testData[TEST_PAGE_SIZE];
    uint8_t readData[TEST_PAGE_SIZE];

    printf("Testing RAM-based flash simulator...\n");

    if (WhNvmFlashRamSim_Init(&ctx, &cfg) != WH_NVM_FLASH_RAMSIM_OK) {
        printf("Flash initialization failed.\n");
        return -1;
    }

    for (uint32_t sector = 0; sector < cfg.size / cfg.sectorSize; ++sector) {
        uint32_t sectorOffset = sector * cfg.sectorSize;
        for (uint32_t page = 0; page < cfg.sectorSize / cfg.pageSize; ++page) {
            uint32_t pageOffset = sectorOffset + page * cfg.pageSize;
            fillTestData(testData, cfg.pageSize, page);

            if(WhNvmFlashRamSim_Read(&ctx, pageOffset, cfg.pageSize, readData) != WH_NVM_FLASH_RAMSIM_OK) {
                printf("Unable to read unprogrammed page\n");
                WhNvmFlashRamSim_Cleanup(&ctx);
                return -1;
            };

#if WH_TEST_FLASH_RAMSIM_DEBUG
            printf("Page %u in sector %u before programming:\n", page, sector);
            printMemory(readData, cfg.pageSize, pageOffset);
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */

            if (WhNvmFlashRamSim_Program(&ctx, pageOffset, cfg.pageSize,
                                         testData) != WH_NVM_FLASH_RAMSIM_OK) {
                printf("Error programming page %u in sector %u\n", page,
                       sector);
                WhNvmFlashRamSim_Cleanup(&ctx);
                return -1;
            }

#if WH_TEST_FLASH_RAMSIM_DEBUG
            printf("Page %u in sector %u after programming:\n", page, sector);
            WhNvmFlashRamSim_Read(&ctx, pageOffset, cfg.pageSize, readData);
            printMemory(readData, cfg.pageSize, pageOffset);
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */

            if (WhNvmFlashRamSim_Verify(&ctx, pageOffset, cfg.pageSize,
                                        testData) != WH_NVM_FLASH_RAMSIM_OK) {
                printf("Verification failed for page %u in sector %u\n", page,
                       sector);
                WhNvmFlashRamSim_Cleanup(&ctx);
                return -1;
            }
        }

        if (WhNvmFlashRamSim_Erase(&ctx, sectorOffset, cfg.sectorSize) !=
            WH_NVM_FLASH_RAMSIM_OK) {
            printf("Error erasing sector %u\n", sector);
            WhNvmFlashRamSim_Cleanup(&ctx);
            return -1;
        }

#if WH_TEST_FLASH_RAMSIM_DEBUG
        printf("Sector %u after erasing:\n", sector);
        if (WhNvmFlashRamSim_BlankCheck(&ctx, sectorOffset, cfg.sectorSize) ==
            WH_NVM_FLASH_RAMSIM_OK) {
            printf("Sector %u is blank.\n", sector);
        }
        else {
            printf("Sector %u is not blank.\n", sector);
        }
#endif /* WH_TEST_FLASH_RAMSIM_DEBUG */
    }

    printf("All operations completed successfully.\n");
    WhNvmFlashRamSim_Cleanup(&ctx);

    return 0;
}
