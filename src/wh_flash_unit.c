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
 * src/wh_flash_unit.c
 *
 * Wrapper on flash device using programmable units rather than bytes for
 * offsets and counts.
 *
 */

#include <stdint.h>
#include <stddef.h>     /* For NULL */
#include <string.h>     /* For memset, memcpy */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"

#include "wolfhsm/wh_flash_unit.h"

/** Helper functions based on units rather than bytes */

int wh_FlashUnit_WriteUnlock(const whFlashCb* cb, void* context,
        uint32_t offset, uint32_t count)
{
    uint32_t byte_offset = offset * WHFU_BYTES_PER_UNIT;
    uint32_t byte_count = count * WHFU_BYTES_PER_UNIT;
    if ((cb == NULL) || (cb->WriteUnlock == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return cb->WriteUnlock(context, byte_offset, byte_count);
}

int wh_FlashUnit_WriteLock(const whFlashCb* cb, void* context,
        uint32_t offset, uint32_t count)
{
    uint32_t byte_offset = offset * WHFU_BYTES_PER_UNIT;
    uint32_t byte_count = count * WHFU_BYTES_PER_UNIT;
    if ((cb == NULL) || (cb->WriteLock == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return cb->WriteLock(context, byte_offset, byte_count);
}

/* Read count units starting at offset into data */
int wh_FlashUnit_Read(const whFlashCb* cb, void* context,
        uint32_t offset, uint32_t count, whFlashUnit* data)
{
    uint32_t byte_offset = offset * WHFU_BYTES_PER_UNIT;
    uint32_t byte_count = count * WHFU_BYTES_PER_UNIT;
    if ((cb == NULL) || (cb->Read == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return cb->Read(context, byte_offset, byte_count,(uint8_t*) data);
}

/* Program from data count units starting at offset */
int wh_FlashUnit_Program(const whFlashCb* cb, void* context,
        uint32_t offset, uint32_t count, const whFlashUnit* data)
{
    uint32_t byte_offset = offset * WHFU_BYTES_PER_UNIT;
    uint32_t byte_count = count * WHFU_BYTES_PER_UNIT;
    int ret = 0;
    if (    (cb == NULL) ||
            (cb->BlankCheck == NULL) ||
            (cb->Program == NULL) ||
            (cb->Verify == NULL)) {
            return WH_ERROR_BADARGS;
    }
    /* Blank check first */
    ret = cb->BlankCheck(context,
            byte_offset,
            byte_count);
    if (ret == 0) {
        /* Program the output data */
        ret = cb->Program(
                context,
                byte_offset,
                byte_count,
                (uint8_t*) data);
        if (ret == 0) {
            /* Verify the programming was successful */
            ret = cb->Verify(
                    context,
                    byte_offset,
                    byte_count,
                    (uint8_t*) data);
        }
    }
    return ret;
}

int wh_FlashUnit_BlankCheck(const whFlashCb* cb, void* context,
        uint32_t offset, uint32_t count)
{
    uint32_t byte_offset = offset * WHFU_BYTES_PER_UNIT;
    uint32_t byte_count = count * WHFU_BYTES_PER_UNIT;
    if ((cb == NULL) || (cb->BlankCheck == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return cb->BlankCheck(context, byte_offset, byte_count);
}

int wh_FlashUnit_Erase(const whFlashCb* cb, void* context,
        uint32_t offset, uint32_t count)
{
    uint32_t byte_offset = offset * WHFU_BYTES_PER_UNIT;
    uint32_t byte_count = count * WHFU_BYTES_PER_UNIT;

    if (    (cb == NULL) ||
            (cb->Erase == NULL) ||
            (cb->BlankCheck == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (count == 0) return 0;

    int ret = cb->Erase(context, byte_offset, byte_count);

    if (ret == 0) {
        ret = cb->BlankCheck(context, byte_offset, byte_count);
    }

    return ret;
}

/** Helper functions to use buffered reads and writes for bytes */

uint32_t wh_FlashUnit_Bytes2Units(uint32_t bytes)
{
    return WHFU_BYTES2UNITS(bytes);
}


int wh_FlashUnit_ReadBytes(const whFlashCb* cb, void* context,
        uint32_t byte_offset, uint32_t data_len, uint8_t* data)
{
    whFlashUnitBuffer buffer;
    int data_units;
    int data_rem;

    int ret = 0;
    uint32_t offset_units = byte_offset / WHFU_BYTES_PER_UNIT;
    uint32_t offset_rem = byte_offset % WHFU_BYTES_PER_UNIT;

    if ((cb == NULL) || (cb->Read == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Get to aligned unit reads */
    if (offset_rem != 0) {
        ret = wh_FlashUnit_Read(cb, context, offset_units, 1, &buffer.unit);
        if (ret == 0) {
            uint32_t this_size = offset_rem;
            if (data_len < this_size) this_size = data_len;
            memcpy(data, &buffer.bytes[WHFU_BYTES_PER_UNIT - offset_rem], this_size);
            data += this_size;
            data_len -= this_size;
            offset_units++;
        }
    }

    data_units = data_len / WHFU_BYTES_PER_UNIT;
    data_rem = data_len % WHFU_BYTES_PER_UNIT;

    /* Read aligned data */
    if ((ret == 0) && (data_units != 0)) {
        ret = wh_FlashUnit_Read(cb, context, offset_units, data_units,
                (whFlashUnit*)data);
        offset_units += data_units;
        data += data_units * WHFU_BYTES_PER_UNIT;
    }

    /* Read remaining */
    if ((ret == 0) && (data_rem != 0)) {
        ret = wh_FlashUnit_Read(cb, context, offset_units, 1, &buffer.unit);
        if (ret == 0) {
            memcpy(data, buffer.bytes, data_rem);
        }
    }
    return ret;
}

int wh_FlashUnit_ProgramBytes(const whFlashCb* cb, void* context,
        uint32_t byte_offset, uint32_t byte_count, const uint8_t* data)
{
    int ret = 0;
    whFlashUnitBuffer buffer = {0};

    uint32_t offset = byte_offset / WHFU_BYTES_PER_UNIT;
    /* Unaligned writes are skipped */
    data += byte_offset % WHFU_BYTES_PER_UNIT;

    uint32_t count = byte_count / WHFU_BYTES_PER_UNIT;
    uint32_t rem = byte_count % WHFU_BYTES_PER_UNIT;

    if ((cb == NULL) || (cb->Program == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Aligned programming */
    ret = wh_FlashUnit_Program(cb, context,
            offset, count, (whFlashUnit*)data);

    /* Final partial unit */
    if ((ret == 0) && (rem != 0)) {
        /* Short writes are filled with erased value */
        data = data + count * WHFU_BYTES_PER_UNIT;
        memcpy(buffer.bytes, data, rem);
        ret = wh_FlashUnit_Program(cb, context,
                offset + count, 1, &buffer.unit);
    }
    return ret;
}
