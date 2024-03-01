#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash_ramsim.h"


static bool isMemoryErased(whFlashRamsimCtx* context, uint32_t offset,
                           uint32_t size);


static bool isMemoryErased(whFlashRamsimCtx* context, uint32_t offset,
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
int whFlashRamsim_Init(void* context, const void* config)
{
    whFlashRamsimCtx*       ctx = (whFlashRamsimCtx*)context;
    const whFlashRamsimCfg* cfg = (const whFlashRamsimCfg*)config;

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

    return WH_FLASH_RAMSIM_OK;
}

int whFlashRamsim_Cleanup(void* context)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    free(ctx->memory);

    return WH_FLASH_RAMSIM_OK;
}

int whFlashRamsim_Program(void* context, uint32_t offset, uint32_t size,
                             const uint8_t* data)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;


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

    return WH_FLASH_RAMSIM_OK;
}

int whFlashRamsim_Read(void* context, uint32_t offset, uint32_t size,
                          uint8_t* data)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }

    memcpy(data, ctx->memory + offset, size);
    return WH_FLASH_RAMSIM_OK;
}

int whFlashRamsim_Erase(void* context, uint32_t offset, uint32_t size)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (offset % ctx->sectorSize != 0 || size % ctx->sectorSize != 0) {
        return WH_ERROR_BADARGS;
    }

    /* Perform the erase */
    memset(ctx->memory + offset, ctx->erasedByte, size);

    return WH_FLASH_RAMSIM_OK;
}

int whFlashRamsim_Verify(void* context, uint32_t offset, uint32_t size,
                            const uint8_t* data)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL || data == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check stored data equals input data */
    for (uint32_t i = 0; i < size; ++i) {
        if (ctx->memory[offset + i] != data[i]) {
            return WH_ERROR_NOTVERIFIED;
        }
    }

    return WH_FLASH_RAMSIM_OK;
}


int whFlashRamsim_BlankCheck(void* context, uint32_t offset, uint32_t size)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!isMemoryErased(ctx, offset, size)) {
        return WH_ERROR_NOTBLANK;
    }

    return WH_FLASH_RAMSIM_OK;
}


uint32_t whFlashRamsim_PartitionSize(void* context)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return ctx->sectorSize;
}


int whFlashRamsim_WriteLock(void* context, uint32_t offset, uint32_t size)
{
    (void)offset;
    (void)size;

    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->writeLocked = 1;

    return WH_FLASH_RAMSIM_OK;
}


int whFlashRamsim_WriteUnlock(void* context, uint32_t offset, uint32_t size)
{
    (void)offset;
    (void)size;
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->writeLocked = 0;

    return WH_FLASH_RAMSIM_OK;
}


