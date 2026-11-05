/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test/wh_test_flash.c
 *
 * Low-level flash HAL test. Kept apart from the NVM flash tests so embedded
 * ports can link it without the RAM-simulated flash those tests need.
 */
#include <string.h>

#include "wolfhsm/wh_settings.h"

/* core test includes */
#include "wh_test_common.h"

/* APIs to test */
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_unit.h"

#include "wh_test_flash.h"

int whTest_Flash(const whFlashCb* fcb, void* fctx, const void* cfg)
{
    uint8_t write_bytes[8] = {0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87};
    uint8_t read_bytes[8]  = {0};
    uint8_t pattern[WHFU_BYTES_PER_UNIT * 4];
    uint8_t readback[WHFU_BYTES_PER_UNIT * 4];
    whFlashUnit write_buffer[4] = {0};
    whFlashUnit read_buffer[4]  = {0};

    uint32_t partition_units = 0;
    uint32_t base_unit       = 20;
    uint32_t i;

    WH_TEST_ASSERT_RETURN(WHFU_BYTES_PER_UNIT == WOLFHSM_CFG_FLASH_UNIT_SIZE);
    WH_TEST_RETURN_ON_FAIL(fcb->Init(fctx, cfg));

    partition_units = wh_FlashUnit_Bytes2Units(fcb->PartitionSize(fctx));

    /* Unlock the first partition */
    WH_TEST_RETURN_ON_FAIL(
        wh_FlashUnit_WriteUnlock(fcb, fctx, 0, partition_units));

    /* Erase the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Erase(fcb, fctx, 0, partition_units));

    /* Blank check the first partition */
    WH_TEST_RETURN_ON_FAIL(
        wh_FlashUnit_BlankCheck(fcb, fctx, 0, partition_units));

    /* Program a few different unit sizes */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx, 0, 1, write_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx, 1, 2, write_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx, 3, 3, write_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx, 6, 4, write_buffer));

    /* Read back and check */
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx, 0, 1, read_buffer));
    WH_TEST_RETURN_ON_FAIL(
        memcmp(write_buffer, read_buffer, 1 * WHFU_BYTES_PER_UNIT));
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx, 1, 2, read_buffer));
    WH_TEST_RETURN_ON_FAIL(
        memcmp(write_buffer, read_buffer, 2 * WHFU_BYTES_PER_UNIT));
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx, 3, 3, read_buffer));
    WH_TEST_RETURN_ON_FAIL(
        memcmp(write_buffer, read_buffer, 3 * WHFU_BYTES_PER_UNIT));
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx, 6, 4, read_buffer));
    WH_TEST_RETURN_ON_FAIL(
        memcmp(write_buffer, read_buffer, 4 * WHFU_BYTES_PER_UNIT));

    /* Program a few different byte sizes */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 10 * WHFU_BYTES_PER_UNIT, 1, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 11 * WHFU_BYTES_PER_UNIT, 2, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 12 * WHFU_BYTES_PER_UNIT, 3, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 13 * WHFU_BYTES_PER_UNIT, 4, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 14 * WHFU_BYTES_PER_UNIT, 5, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 15 * WHFU_BYTES_PER_UNIT, 6, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 16 * WHFU_BYTES_PER_UNIT, 7, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, 17 * WHFU_BYTES_PER_UNIT, 8, write_bytes));

    /* Read back and compare */
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 10 * WHFU_BYTES_PER_UNIT, 1, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 1));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 11 * WHFU_BYTES_PER_UNIT, 2, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 2));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 12 * WHFU_BYTES_PER_UNIT, 3, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 3));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 13 * WHFU_BYTES_PER_UNIT, 4, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 4));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 14 * WHFU_BYTES_PER_UNIT, 5, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 5));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 15 * WHFU_BYTES_PER_UNIT, 6, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 6));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 16 * WHFU_BYTES_PER_UNIT, 7, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 7));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, 17 * WHFU_BYTES_PER_UNIT, 8, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 8));

    /* Test unaligned ReadBytes (exercises the offset_rem != 0 path) */
    for (i = 0; i < sizeof(pattern); i++) {
        pattern[i] = (uint8_t)(0x10 + i);
    }

    /* Program 4 full units at base_unit */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        fcb, fctx, base_unit * WHFU_BYTES_PER_UNIT, sizeof(pattern), pattern));

    /* offset_rem = 3: should read pattern[3..7] */
    memset(readback, 0, sizeof(readback));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, base_unit * WHFU_BYTES_PER_UNIT + 3, 5, readback));
    WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[3], 5));

    /* offset_rem = 1: should read pattern[1..10] */
    memset(readback, 0, sizeof(readback));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, base_unit * WHFU_BYTES_PER_UNIT + 1, 10, readback));
    WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[1], 10));

    /* offset_rem = 5: should read pattern[5..7] */
    memset(readback, 0, sizeof(readback));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        fcb, fctx, base_unit * WHFU_BYTES_PER_UNIT + 5, 3, readback));
    WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[5], 3));

    /* Full 3-phase read: leading partial + aligned middle + trailing */
    memset(readback, 0, sizeof(readback));
    WH_TEST_RETURN_ON_FAIL(
        wh_FlashUnit_ReadBytes(fcb, fctx, base_unit * WHFU_BYTES_PER_UNIT + 2,
                               2 * WHFU_BYTES_PER_UNIT + 5, readback));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(readback, &pattern[2], 2 * WHFU_BYTES_PER_UNIT + 5));

    /* Erase the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Erase(fcb, fctx, 0, partition_units));

    /* Blank check the first partition */
    WH_TEST_RETURN_ON_FAIL(
        wh_FlashUnit_BlankCheck(fcb, fctx, 0, partition_units));

    /* Lock the first partition */
    WH_TEST_RETURN_ON_FAIL(
        wh_FlashUnit_WriteLock(fcb, fctx, 0, partition_units));

    WH_TEST_RETURN_ON_FAIL(fcb->Cleanup(fctx));

    return 0;
}
