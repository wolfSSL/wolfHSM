/*
 * Copyright (C) 2025 wolfSSL Inc.
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
#ifndef WH_FLASH_FAULTINJECT_H_
#define WH_FLASH_FAULTINJECT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_flash.h"

typedef struct {
    const whFlashCb* realCb;
    void*            realCtx;
    int              failAfterPrograms;
} whFlashFaultInjectCtx;

typedef struct {
    const whFlashCb* realCb;
    void*            realCtx;
    void*            realCfg;
} whFlashFaultInjectCfg;

int whFlashFaultInject_Init(void* context, const void* config);
int whFlashFaultInject_Cleanup(void* context);
int whFlashFaultInject_Program(void* context, uint32_t offset, uint32_t size,
                               const uint8_t* data);
int whFlashFaultInject_Read(void* context, uint32_t offset, uint32_t size,
                            uint8_t* data);
int whFlashFaultInject_Erase(void* context, uint32_t offset, uint32_t size);
int whFlashFaultInject_Verify(void* context, uint32_t offset, uint32_t size,
                              const uint8_t* data);
int whFlashFaultInject_BlankCheck(void* context, uint32_t offset,
                                  uint32_t size);
uint32_t whFlashFaultInject_PartitionSize(void* context);
int whFlashFaultInject_WriteLock(void* context, uint32_t offset, uint32_t size);
int whFlashFaultInject_WriteUnlock(void* context, uint32_t offset,
                                   uint32_t size);

/* clang-format off */
#define WH_FLASH_FAULTINJECT_CB                              \
    {                                                        \
        .Init          = whFlashFaultInject_Init,            \
        .Cleanup       = whFlashFaultInject_Cleanup,         \
        .PartitionSize = whFlashFaultInject_PartitionSize,   \
        .WriteLock     = whFlashFaultInject_WriteLock,       \
        .WriteUnlock   = whFlashFaultInject_WriteUnlock,     \
        .Read          = whFlashFaultInject_Read,            \
        .Program       = whFlashFaultInject_Program,         \
        .Erase         = whFlashFaultInject_Erase,           \
        .Verify        = whFlashFaultInject_Verify,          \
        .BlankCheck    = whFlashFaultInject_BlankCheck,      \
    }
/* clang-format on */

#endif /* !WH_FLASH_FAULTINJECT_H_  */
