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
 * wolfhsm/wh_flash.h
 *
 * Abstract library to implement a flash-like back end.
 *
 */

#ifndef WOLFHSM_WH_FLASH_H_
#define WOLFHSM_WH_FLASH_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

typedef struct {
    int (*Init)(void* context,const void* config);
    int (*Cleanup)(void* context);

    uint32_t (*PartitionSize)(void* context);

    int (*WriteLock)(void* context,
            uint32_t offset, uint32_t size);
    int (*WriteUnlock)(void* context,
            uint32_t offset, uint32_t size);

    int (*Read)(void* context,
            uint32_t offset, uint32_t size, uint8_t* data);
    int (*Program)(void* context,
            uint32_t offset, uint32_t size, const uint8_t* data);
    int (*Erase)(void* context,
            uint32_t offset, uint32_t size);

    int (*Verify)(void* context,
            uint32_t offset, uint32_t size, const uint8_t* data);
    int (*BlankCheck)(void* context,
            uint32_t offset, uint32_t size);
} whFlashCb;

#endif /* !WOLFHSM_WH_FLASH_H_ */
