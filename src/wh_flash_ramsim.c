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
 * src/wh_flash_ramsim.c
 *
 */

#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <stdlib.h>  /* For malloc/free */
#include <string.h>
#include <stdbool.h>

#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_flash_ramsim.h"

/** Forward declarations */
static bool isMemoryErased(whFlashRamsimCtx* context, uint32_t offset,
                           uint32_t size);


static bool isMemoryErased(whFlashRamsimCtx* context, uint32_t offset,
                           uint32_t size)
{
    size_t i = 0;
    for (i = 0; i < size; ++i) {
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

    if (ctx == NULL || cfg == NULL || (cfg->sectorSize == 0) ||
        (cfg->pageSize == 0) || (cfg->sectorSize % cfg->pageSize != 0)) {
        return WH_ERROR_BADARGS;
    }

    ctx->size        = cfg->size;
    ctx->sectorSize  = cfg->sectorSize;
    ctx->pageSize    = cfg->pageSize;
    ctx->memory      = (uint8_t*)malloc(ctx->size);
    ctx->erasedByte  = cfg->erasedByte;
    ctx->writeLocked = 0;

    if (!ctx->memory) {
        return WH_ERROR_BADARGS;
    }

    /* Simulate starting from erased flash */
    memset(ctx->memory, ctx->erasedByte, ctx->size);

    return WH_ERROR_OK;
}

int whFlashRamsim_Cleanup(void* context)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->memory != NULL) {
        free(ctx->memory);
        ctx->memory = NULL;
    }

    return WH_ERROR_OK;
}

int whFlashRamsim_Program(void* context, uint32_t offset, uint32_t size,
                          const uint8_t* data)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (    (ctx == NULL) ||
            (ctx->memory == NULL) ||
            (ctx->pageSize == 0) ||
            ((data == NULL) && (size != 0))) {
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

    /* Check that partition isn't locked */
    if (size > 0 && ctx->writeLocked) {
        return WH_ERROR_LOCKED;
    }

    /* Perform the programming operation */
    if (size != 0) {
        memcpy(ctx->memory + offset, data, size);
    }
    return WH_ERROR_OK;
}

int whFlashRamsim_Read(void* context, uint32_t offset, uint32_t size,
                       uint8_t* data)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (    (ctx == NULL) ||
            (ctx->memory == NULL) ||
            ((offset + size) > ctx->size) ||
            ((data == NULL) && (size !=0))) {
        return WH_ERROR_BADARGS;
    }

    if (size != 0) {
        memcpy(data, ctx->memory + offset, size);
    }
    return WH_ERROR_OK;
}

int whFlashRamsim_Erase(void* context, uint32_t offset, uint32_t size)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (    (ctx == NULL) ||
            (ctx->memory == NULL) ||
            ((offset + size) > ctx->size)) {
        return WH_ERROR_BADARGS;
    }

    if (offset % ctx->sectorSize != 0 || size % ctx->sectorSize != 0) {
        return WH_ERROR_BADARGS;
    }

    /* Check that partition isn't locked */
    if ((size != 0) && (ctx->writeLocked)) {
        return WH_ERROR_LOCKED;
    }

    /* Perform the erase */
    if (size != 0) {
        memset(ctx->memory + offset, ctx->erasedByte, size);
    }
    return WH_ERROR_OK;
}

int whFlashRamsim_Verify(void* context, uint32_t offset, uint32_t size,
                         const uint8_t* data)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;
    if (    (ctx == NULL) ||
            (ctx->memory == NULL) ||
            ((offset + size) > ctx->size) ||
            ((data == NULL) && (size != 0))) {
        return WH_ERROR_BADARGS;
    }

    /* Check stored data equals input data */
    if (size != 0) {
        if(memcmp(ctx->memory + offset, data, size) != 0) {
            return WH_ERROR_NOTVERIFIED;
        }
    }
    return WH_ERROR_OK;
}


int whFlashRamsim_BlankCheck(void* context, uint32_t offset, uint32_t size)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (    (ctx == NULL) ||
            (ctx->memory == NULL) ||
            ((offset + size) > ctx->size)) {
        return WH_ERROR_BADARGS;
    }

    if (!isMemoryErased(ctx, offset, size)) {
        return WH_ERROR_NOTBLANK;
    }

    return WH_ERROR_OK;
}


uint32_t whFlashRamsim_PartitionSize(void* context)
{
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (ctx == NULL) {
        /* Invalid context.  Must return positive size, so 0 */
        return 0;
    }

    return ctx->sectorSize;
}


int whFlashRamsim_WriteLock(void* context, uint32_t offset, uint32_t size)
{
    (void)offset;
    (void)size;

    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->writeLocked = 1;

    return WH_ERROR_OK;
}


int whFlashRamsim_WriteUnlock(void* context, uint32_t offset, uint32_t size)
{
    (void)offset;
    (void)size;
    whFlashRamsimCtx* ctx = (whFlashRamsimCtx*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->writeLocked = 0;

    return WH_ERROR_OK;
}
