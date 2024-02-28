#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm_flash_ramsim.h"


static bool isMemoryErased(const uint8_t* memory, uint32_t offset, uint32_t size);

#if WH_NVM_FLASH_RAMSIM_DEBUG
/* debug functions */
static void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue);
static void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset);
#endif


static bool isMemoryErased(const uint8_t* memory, uint32_t offset, uint32_t size)
{
    for (uint32_t i = 0; i < size; ++i) {
        if (memory[offset + i] != 0xFF) {
            return false;
        }
    }
    return true;
}



/* Simulator functions */
int WhNvmFlashRamSim_Init(void* context, const void* config)
{
    WhNvmFlashRamSimCtx*       ctx = (WhNvmFlashRamSimCtx*)context;
    const WhNvmFlashRamSimCfg* cfg = (const WhNvmFlashRamSimCfg*)config;

    ctx->size       = cfg->size;
    ctx->sectorSize = cfg->sectorSize;
    ctx->pageSize   = cfg->pageSize;
    ctx->memory     = (uint8_t*)malloc(ctx->size);
    if (!ctx->memory) {
        return WH_NVM_FLASH_RAMSIM_ERR_INVALID_PARAM;
    }

    memset(ctx->memory, 0xFF, ctx->size); // Simulate erased flash
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Cleanup(void* context)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    free(ctx->memory);
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Program(void* context, uint32_t offset, uint32_t size,
                             const uint8_t* data)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    // Ensure offset and size are within bounds and size is a multiple of page size
    if (offset + size > ctx->size || size % ctx->pageSize != 0) {
        return WH_NVM_FLASH_RAMSIM_ERR_INVALID_PARAM;
    }

    // Check if the target area is already erased
    if (!isMemoryErased(ctx->memory, offset, size)) {
        return WH_ERROR_NOTBLANK;
    }

    // Perform the programming operation
    memcpy(ctx->memory + offset, data, size);
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Read(void* context, uint32_t offset, uint32_t size,
                          uint8_t* data)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    memcpy(data, ctx->memory + offset, size);
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Erase(void* context, uint32_t offset, uint32_t size)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    if (offset % ctx->sectorSize != 0 || size % ctx->sectorSize != 0) {
        return WH_NVM_FLASH_RAMSIM_ERR_INVALID_PARAM;
    }

    memset(ctx->memory + offset, 0xFF, size); // Simulate erase
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Verify(void* context, uint32_t offset, uint32_t size,
                            const uint8_t* data)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    for (uint32_t i = 0; i < size; ++i) {
        if (ctx->memory[offset + i] != data[i]) {
            return WH_ERROR_NOTVERIFIED;
        }
    }
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_BlankCheck(void* context, uint32_t offset, uint32_t size)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    for (uint32_t i = 0; i < size; ++i) {
        if (ctx->memory[offset + i] != 0xFF) {
            return WH_ERROR_NOTBLANK;
        }
    }
    return WH_NVM_FLASH_RAMSIM_OK;
}

uint32_t WhNvmFlashRamSim_PartitionSize(void* context)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    return ctx->sectorSize;
}

int WhNvmFlashRamSim_WriteLock(void* context, uint32_t offset, uint32_t size)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    ctx->writeLocked         = 1;
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_WriteUnlock(void* context, uint32_t offset, uint32_t size)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;
    ctx->writeLocked         = 0;
    return WH_NVM_FLASH_RAMSIM_OK;
}


#if 0

#if WH_NVM_FLASH_RAMSIM_DEBUG
void fillTestData(uint8_t* buffer, uint32_t size, uint32_t baseValue)
{
    for (uint32_t i = 0; i < size; ++i) {
        buffer[i] = (uint8_t)(baseValue + i);
    }
}

void printMemory(uint8_t* buffer, uint32_t size, uint32_t offset)
{
    printf("Memory at offset %u: ", offset);
    for (uint32_t i = 0; i < size; ++i) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}
#endif


/* Main program */
int main() {
	WhNvmFlashRamSimCtx ctx;
	WhNvmFlashRamSimCfg cfg = {1024 * 1024, 4096, 256}; // 1MB flash, 4KB sector, 256B page
	uint8_t testData[256];
	uint8_t readData[256];

	if (WhNvmFlashRamSim_Init(&ctx, &cfg) != WH_NVM_FLASH_RAMSIM_OK) {
		printf("Flash initialization failed.\n");
		return 1;
	}

	for (uint32_t sector = 0; sector < cfg.size / cfg.sectorSize; ++sector) {
		uint32_t sectorOffset = sector * cfg.sectorSize;
		for (uint32_t page = 0; page < cfg.sectorSize / cfg.pageSize; ++page) {
			uint32_t pageOffset = sectorOffset + page * cfg.pageSize;
			fillTestData(testData, cfg.pageSize, page);

#if WH_NVM_FLASH_RAMSIM_DEBUG
			WhNvmFlashRamSim_Read(&ctx, pageOffset, cfg.pageSize, readData);
			printf("Page %u in sector %u before programming:\n", page, sector);
			printMemory(readData, cfg.pageSize, pageOffset);
#endif

			if (WhNvmFlashRamSim_Program(&ctx, pageOffset, cfg.pageSize, testData) != WH_NVM_FLASH_RAMSIM_OK) {
				printf("Error programming page %u in sector %u\n", page, sector);
				WhNvmFlashRamSim_Cleanup(&ctx);
				return 1;
			}

#if WH_NVM_FLASH_RAMSIM_DEBUG
			printf("Page %u in sector %u after programming:\n", page, sector);
			WhNvmFlashRamSim_Read(&ctx, pageOffset, cfg.pageSize, readData);
			printMemory(readData, cfg.pageSize, pageOffset);
#endif

			if (WhNvmFlashRamSim_Verify(&ctx, pageOffset, cfg.pageSize, testData) != WH_NVM_FLASH_RAMSIM_OK) {
				printf("Verification failed for page %u in sector %u\n", page, sector);
				WhNvmFlashRamSim_Cleanup(&ctx);
				return 1;
			}
		}

		if (WhNvmFlashRamSim_Erase(&ctx, sectorOffset, cfg.sectorSize) != WH_NVM_FLASH_RAMSIM_OK) {
			printf("Error erasing sector %u\n", sector);
			WhNvmFlashRamSim_Cleanup(&ctx);
			return 1;
		}

#if WH_NVM_FLASH_RAMSIM_DEBUG
		printf("Sector %u after erasing:\n", sector);
		if (WhNvmFlashRamSim_BlankCheck(&ctx, sectorOffset, cfg.sectorSize) == WH_NVM_FLASH_RAMSIM_OK) {
			printf("Sector %u is blank.\n", sector);
		} else {
			printf("Sector %u is not blank.\n", sector);
		}
#endif
	}

	printf("All operations completed successfully.\n");
	WhNvmFlashRamSim_Cleanup(&ctx);
	return 0;
}
#endif
