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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef WOLFHSM_WH_NVM_FLASH_LOG_H_
#define WOLFHSM_WH_NVM_FLASH_LOG_H_

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)

#include "wolfhsm/wh_settings.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_flash.h"

#ifndef WH_NVM_FLASH_LOG_WRITE_GRANULARITY
#define WH_NVM_FLASH_LOG_WRITE_GRANULARITY 64
#endif

#ifndef WOLFHSM_CFG_NVM_OBJECT_COUNT
#define WOLFHSM_CFG_NVM_OBJECT_COUNT 32
#endif

#ifndef WH_NVM_FLASH_LOG_PARTITION_SIZE
#define WH_NVM_FLASH_LOG_PARTITION_SIZE (4 * 1024)
#endif

typedef struct {
    uint32_t partition_epoch;
    uint32_t size;
    uint8_t  _pad[WH_NVM_FLASH_LOG_WRITE_GRANULARITY - sizeof(uint32_t) * 2];
} whNvmFlashLogPartitionHeader;

/* In-memory representation of a partition */
typedef struct {
    whNvmFlashLogPartitionHeader header;
    uint8_t                      data[WH_NVM_FLASH_LOG_PARTITION_SIZE];
} whNvmFlashLogMemPartition;

/* Flash log backend context structure */
typedef struct {
    const whFlashCb*          flash_cb;  /* Flash callback interface */
    void*                     flash_ctx; /* Flash context */
    uint32_t                  partition_size;
    uint32_t                  active_partition; /* 0 or 1 */
    int                       is_initialized;
    whNvmFlashLogMemPartition directory;
} whNvmFlashLogContext;

/* Flash log backend config structure */
typedef struct {
    const whFlashCb* flash_cb;  /* Flash callback interface */
    void*            flash_ctx; /* Flash context */
    const void*      flash_cfg; /* Config to be passed to cb->Init */
} whNvmFlashLogConfig;

int wh_NvmFlashLog_Init(void* c, const void* cf);
int wh_NvmFlashLog_Cleanup(void* c);
int wh_NvmFlashLog_List(void* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        whNvmId *out_avail_objects, whNvmId *out_id);
int wh_NvmFlashLog_GetAvailable(void* c,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);
int wh_NvmFlashLog_GetMetadata(void* c, whNvmId id, whNvmMetadata* meta);
int wh_NvmFlashLog_AddObject(void* c, whNvmMetadata* meta,
        whNvmSize data_len, const uint8_t* data);
int wh_NvmFlashLog_DestroyObjects(void* c, whNvmId list_count,
        const whNvmId* id_list);
int wh_NvmFlashLog_Read(void* c, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* data);

#define WH_NVM_FLASH_LOG_CB                          \
{                                                    \
    .Init = wh_NvmFlashLog_Init,                     \
    .Cleanup = wh_NvmFlashLog_Cleanup,               \
    .List = wh_NvmFlashLog_List,                     \
    .GetAvailable = wh_NvmFlashLog_GetAvailable,     \
    .GetMetadata = wh_NvmFlashLog_GetMetadata,       \
    .AddObject = wh_NvmFlashLog_AddObject,           \
    .DestroyObjects = wh_NvmFlashLog_DestroyObjects, \
    .Read = wh_NvmFlashLog_Read,                     \
}

#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */

#endif /* WOLFHSM_WH_NVM_FLASH_LOG_H_ */
