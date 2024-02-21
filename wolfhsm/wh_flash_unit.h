/*
 * wolfhsm/wh_flash_unit.h
 *
 * Helper library to use units instead of bytes for a HAL Flash backend.
 *
 * This library assumes the HAL Flash provides a contiguous area that contains
 * 2 consecutive partitions, each of whHalFlash_PartitionSize() bytes:
 * Partition 0: Byte offset 0 to  (partition_size - 1)
 * Partition 1: Byte offset partition_size to (partition_size*2 - 1)
 *
 * Note that all offsets and count parameters are in Units, not bytes unless
 * specifically named byte_offet or byte_count.
 */

#ifndef WOLFHSM_WH_FLASH_UNIT_H_
#define WOLFHSM_WH_FLASH_UNIT_H_

#include <stdint.h>
#include <wolfhsm/wh_flash.h>

/* Smallest programmable unit/size.  Alignment as well */
typedef uint64_t whFlashUnit;

#define WHFU_BYTES_PER_UNIT sizeof(whFlashUnit)

/* Helper to round up at compile time */
#define WHFU_DIV_ROUND_UP(_n, _d) (((_n)/(_d)) + !!((_n)%(_d)))

#define WHFU_BYTES2UNITS(_b) (((_b)/WHFU_BYTES_PER_UNIT) + \
                              !!((_b)%WHFU_BYTES_PER_UNIT))
typedef union {
    whFlashUnit unit;
    uint8_t bytes[WHFU_BYTES_PER_UNIT];
} whFlashUnitBuffer;

/* Compute the number of units necessary to hold bytes, rounding up */
uint32_t wh_FlashUnit_Bytes2Units(uint32_t bytes);

int wh_FlashUnit_WriteUnlock(const whFlashCb* cb, void* context, uint32_t offset,
        uint32_t count);

int wh_FlashUnit_WriteLock(const whFlashCb* cb, void* context, uint32_t offset,
        uint32_t count);

/* Read count units starting at offset into data */
int wh_FlashUnit_Read(const whFlashCb* cb, void* context, uint32_t offset,
        uint32_t count, whFlashUnit* data);

/* Program from data count units starting at offset */
int wh_FlashUnit_Program(const whFlashCb* cb, void* context, uint32_t offset,
        uint32_t count, const whFlashUnit* data);

int wh_FlashUnit_BlankCheck(const whFlashCb* cb, void* context, uint32_t offset,
        uint32_t count);

int wh_FlashUnit_Erase(const whFlashCb* cb, void* context, uint32_t offset,
        uint32_t count);

/** Helper functions to use buffered reads and writes for bytes */

int wh_FlashUnit_ReadBytes(const whFlashCb* cb, void* context, uint32_t byte_offset,
        uint32_t data_len, uint8_t* data);

int wh_FlashUnit_ProgramBytes(const whFlashCb* cb, void* context, uint32_t byte_offset,
        uint32_t byte_count, const uint8_t* data);

#endif /* WOLFHSM_WH_FLASH_UNIT_H_ */
