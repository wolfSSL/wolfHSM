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
#ifndef WH_FLASH_RAMSIM_H_
#define WH_FLASH_RAMSIM_H_

#include <stdint.h>

/* Configuration and context structures */
typedef struct {
    uint32_t size;
    uint32_t sectorSize;
    uint32_t pageSize;
    uint8_t  erasedByte;
    uint8_t WH_PAD[3];
} whFlashRamsimCfg;

typedef struct {
    uint8_t* memory;
    uint32_t size;
    uint32_t sectorSize;
    uint32_t pageSize;
    int      writeLocked;
    uint8_t  erasedByte;
    uint8_t WH_PAD[7];
} whFlashRamsimCtx;


/* Simulator function prototypes */
int whFlashRamsim_Init(void* context, const void* config);
int whFlashRamsim_Cleanup(void* context);
int whFlashRamsim_Program(void* context, uint32_t offset, uint32_t size,
                             const uint8_t* data);
int whFlashRamsim_Read(void* context, uint32_t offset, uint32_t size,
                          uint8_t* data);
int whFlashRamsim_Erase(void* context, uint32_t offset, uint32_t size);
int whFlashRamsim_Verify(void* context, uint32_t offset, uint32_t size,
                            const uint8_t* data);
int whFlashRamsim_BlankCheck(void* context, uint32_t offset, uint32_t size);
uint32_t whFlashRamsim_PartitionSize(void* context);
int whFlashRamsim_WriteLock(void* context, uint32_t offset, uint32_t size);
int whFlashRamsim_WriteUnlock(void* context, uint32_t offset, uint32_t size);

/* clang-format off */
#define WH_FLASH_RAMSIM_CB                           \
    {                                                    \
        .Init          = whFlashRamsim_Init,          \
        .Cleanup       = whFlashRamsim_Cleanup,       \
        .PartitionSize = whFlashRamsim_PartitionSize, \
        .WriteLock     = whFlashRamsim_WriteLock,     \
        .WriteUnlock   = whFlashRamsim_WriteUnlock,   \
        .Read          = whFlashRamsim_Read,          \
        .Program       = whFlashRamsim_Program,       \
        .Erase         = whFlashRamsim_Erase,         \
        .Verify        = whFlashRamsim_Verify,        \
        .BlankCheck    = whFlashRamsim_BlankCheck,    \
    }
/* clang-format on */

#endif /* WH_FLASH_RAMSIM_H_ */
