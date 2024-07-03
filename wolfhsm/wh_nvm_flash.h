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
 * wolfhsm/nvm_flash.h
 *
 * Concrete library to implement an NVM data store using a whFlash bottom end.
 *
 */

#ifndef WOLFHSM_WH_NVMFLASH_H_
#define WOLFHSM_WH_NVMFLASH_H_

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_unit.h"

/* Number of objects in a directory */
#ifndef NF_OBJECT_COUNT
#include "wolfhsm/wh_server.h"
#define NF_OBJECT_COUNT (WOLFHSM_NUM_NVMOBJECTS)
#endif

/* In-memory computed status of an Object or Directory */
typedef enum {
    NF_STATUS_UNKNOWN    = 0,    /* State is unknown/not read yet */
    NF_STATUS_FREE       = 1,    /* State is known to be free/erased */
    NF_STATUS_USED       = 2,    /* State is known to be used/intact */
    NF_STATUS_DATA_BAD   = 3,    /* State is known damaged or duplicate data */
    NF_STATUS_META_BAD   = 4,    /* State is known damaged meta */
} nfStatus;

/* In-memory version of an Object or Directory State */
typedef struct {
    nfStatus status;
    uint32_t epoch;
    uint32_t start;
    uint32_t count;
} nfMemState;

/* In-memory version of an Object */
typedef struct {
    nfMemState state;
    whNvmMetadata metadata;
} nfMemObject;

/* In-memory version of a Directory */
typedef struct {
    nfMemObject objects[NF_OBJECT_COUNT];
    int next_free_object;
    uint32_t next_free_data;
    int reclaimable_entries;
    uint32_t reclaimable_data;
} nfMemDirectory;

/** whNvm config and context structure definitions */
/* In memory configuration structure associated with an NVM instance */
typedef struct whNvmFlashConfig_t {
    const whFlashCb* cb;    /* whFlash callback */
    void* context;          /* whFlash context to be passed to cb */
    const void* config;     /* Config to be passed to cb->Init */
} whNvmFlashConfig;

typedef struct whNvmFlashContext_t {
    const whFlashCb* cb;            /* Flash callbacks */
    void* flash;                    /* Flash context to use */
    nfMemState state;               /* State of active partition */
    nfMemDirectory directory;       /* Cache of active objects */
    uint32_t partition_units;       /* Size of partition in units */
    int active;                     /* Which partition (0 or 1) is active */
    int initialized;
    uint8_t WH_PAD[4];
} whNvmFlashContext;

/** whNvm Interface */
int wh_NvmFlash_Init(void* c, const void* cf);
int wh_NvmFlash_Cleanup(void* c);
int wh_NvmFlash_List(void* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        whNvmId *out_avail_objects, whNvmId *out_id);
int wh_NvmFlash_GetAvailable(void* c,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);
int wh_NvmFlash_GetMetadata(void* c, whNvmId id, whNvmMetadata* meta);
int wh_NvmFlash_AddObject(void* c, whNvmMetadata* meta,
        whNvmSize data_len, const uint8_t* data);
int wh_NvmFlash_DestroyObjects(void* c, whNvmId list_count,
        const whNvmId* id_list);
int wh_NvmFlash_Read(void* c, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* data);

#define WH_NVM_FLASH_CB                             \
{                                                   \
    .Init = wh_NvmFlash_Init,                       \
    .Cleanup = wh_NvmFlash_Cleanup,                 \
    .List = wh_NvmFlash_List,                       \
    .GetAvailable = wh_NvmFlash_GetAvailable,       \
    .GetMetadata = wh_NvmFlash_GetMetadata,         \
    .AddObject = wh_NvmFlash_AddObject,             \
    .DestroyObjects = wh_NvmFlash_DestroyObjects,   \
    .Read = wh_NvmFlash_Read,                       \
}

#endif /* WOLFHSM_WH_NVMFLASH_H_ */
