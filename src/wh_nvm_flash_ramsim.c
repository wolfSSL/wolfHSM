#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm_flash_ramsim.h"


static bool isMemoryErased(WhNvmFlashRamSimCtx* context, uint32_t offset,
                           uint32_t size);


static bool isMemoryErased(WhNvmFlashRamSimCtx* context, uint32_t offset,
                           uint32_t size)
{
    for (uint32_t i = 0; i < size; ++i) {
        if (context->memory[offset + i] != context->erasedByte) {
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

    if (context == NULL || config == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->size       = cfg->size;
    ctx->sectorSize = cfg->sectorSize;
    ctx->pageSize   = cfg->pageSize;
    ctx->memory     = (uint8_t*)malloc(ctx->size);
    ctx->erasedByte = cfg->erasedByte;

    if (!ctx->memory) {
        return WH_ERROR_BADARGS;
    }

    /* Simulate starting from erased flash */
    memset(ctx->memory, ctx->erasedByte, ctx->size);

    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Cleanup(void* context)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    free(ctx->memory);

    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Program(void* context, uint32_t offset, uint32_t size,
                             const uint8_t* data)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;


    if (context == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Ensure offset and size are within bounds and size is a multiple of page
     * size */
    if (offset + size > ctx->size || size % ctx->pageSize != 0) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the target area is already erased */
    if (!isMemoryErased(ctx, offset, size)) {
        return WH_ERROR_NOTBLANK;
    }

    /* Perform the programming operation */
    memcpy(ctx->memory + offset, data, size);

    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Read(void* context, uint32_t offset, uint32_t size,
                          uint8_t* data)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }

    memcpy(data, ctx->memory + offset, size);
    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Erase(void* context, uint32_t offset, uint32_t size)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (offset % ctx->sectorSize != 0 || size % ctx->sectorSize != 0) {
        return WH_ERROR_BADARGS;
    }

    /* Perform the erase */
    memset(ctx->memory + offset, ctx->erasedByte, size);

    return WH_NVM_FLASH_RAMSIM_OK;
}

int WhNvmFlashRamSim_Verify(void* context, uint32_t offset, uint32_t size,
                            const uint8_t* data)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check stored data equals input data */
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

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!isMemoryErased(ctx, offset, size)) {
        return WH_ERROR_NOTBLANK;
    }

    return WH_NVM_FLASH_RAMSIM_OK;
}


uint32_t WhNvmFlashRamSim_PartitionSize(void* context)
{
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return ctx->sectorSize;
}


int WhNvmFlashRamSim_WriteLock(void* context, uint32_t offset, uint32_t size)
{
    (void)offset;
    (void)size;

    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->writeLocked = 1;

    return WH_NVM_FLASH_RAMSIM_OK;
}


int WhNvmFlashRamSim_WriteUnlock(void* context, uint32_t offset, uint32_t size)
{
    (void)offset;
    (void)size;
    WhNvmFlashRamSimCtx* ctx = (WhNvmFlashRamSimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->writeLocked = 0;

    return WH_NVM_FLASH_RAMSIM_OK;
}


