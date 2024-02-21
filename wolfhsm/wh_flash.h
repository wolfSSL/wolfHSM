/*
 * wolfhsm/wh_flash.h
 *
 * Abstract library to implement a flash-like back end.
 *
 */

#ifndef WOLFHSM_WH_FLASH_H_
#define WOLFHSM_WH_FLASH_H_

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

#endif /* WOLFHSM_WH_FLASH_H_ */
