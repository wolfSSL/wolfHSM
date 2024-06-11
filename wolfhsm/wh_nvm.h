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
 * wolfhsm/wh_nvm.h
 *
 * Abstract library to provide management of NVM objects providing basic
 * metadata association with blocks of data.  The backend storage is expected
 * to have flash-style semantics with Read, Erase, and Program hooks.
 *
 * This library is expected to provide reliable, atomic operations (recoverable)
 * to ensure transactions are fully committed prior to returning success.
 * Initial indexing and handling of incomplete transactions are allowed to take
 * longer than ordinary runtime function calls.
 *
 * NVM objects are added with a fixed length and data.  Removal of objects
 * causes the backend to replicate the entire partition without the
 * listed objects present, which also maximizes the contiguous free space.
 *
 */

#ifndef WOLFHSM_WH_NVM_H_
#define WOLFHSM_WH_NVM_H_

#include <stdint.h>

#include "wolfhsm/wh_common.h"  /* For whNvm types */


enum WH_NVM_IDS {
    WH_NVM_INVALID_ID = 0,
};


typedef struct {
    int (*Init)(void* context, const void *config);
    int (*Cleanup)(void* context);

    /* Retrieve the current free space, or the maximum data object length that can
     * be successfully created and the number of free entries in the directory.
     * Also get the sizes that could be reclaimed if the partition was regenerated:
     *  wh_Nvm_DestroyObjects(c, 0, NULL);
     * Any out_ parameters may be NULL without error. */
    int (*GetAvailable)(void* context,
            uint32_t *out_avail_size, whNvmId *out_avail_objects,
            uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);

    /* Add a new object. Duplicate ids are allowed, but only the most recent
     * version will be accessible. */
    int (*AddObject)(void* context, whNvmMetadata *meta,
            whNvmSize data_len, const uint8_t* data);

    /* Retrieve the next matching id starting at start_id. Sets out_count to the
     * total number of id's that match access and flags. */
    int (*List)(void* context, whNvmAccess access, whNvmFlags flags,
        whNvmId start_id, whNvmId *out_count, whNvmId *out_id);

    /* Retrieve object metadata using the id */
    int (*GetMetadata)(void* context, whNvmId id,
            whNvmMetadata* meta);

    /* Destroy a list of objects by replicating the current state without the id's
     * in the provided list.  Id's in the list that are not present do not cause an
     * error.  Atomically: erase the inactive partition, add all remaining objects,
     * switch the active partition, and erase the old active (now inactive)
     * partition.  Interruption prior completing the write of the new partition will
     * recover as before the replication.  Interruption after the new partition is
     * fully populated will recover as after, including restarting erasure. */
    int (*DestroyObjects)(void* context, whNvmId list_count,
            const whNvmId* id_list);

    /* Read the data of the object starting at the byte offset */
    int (*Read)(void* context, whNvmId id, whNvmSize offset,
            whNvmSize data_len, uint8_t* data);
} whNvmCb;


/** NVM Context helper structs and functions */
/* Simple helper context structure associated with an NVM instance */
typedef struct whNvmContext_t {
    whNvmCb *cb;
    void* context;
} whNvmContext;

/* Simple helper configuration structure associated with an NVM instance */
typedef struct whNvmConfig_t {
    whNvmCb *cb;
    void* context;
    void* config;
} whNvmConfig;


int wh_Nvm_Init(whNvmContext* context, const whNvmConfig *config);
int wh_Nvm_Cleanup(whNvmContext* context);

int wh_Nvm_GetAvailable(whNvmContext* context,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);

int wh_Nvm_AddObjectWithReclaim(whNvmContext* context, whNvmMetadata *meta,
    whNvmSize dataLen, const uint8_t* data);

int wh_Nvm_AddObject(whNvmContext* context, whNvmMetadata *meta,
        whNvmSize data_len, const uint8_t* data);

int wh_Nvm_List(whNvmContext* context,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        whNvmId *out_count, whNvmId *out_id);

int wh_Nvm_GetMetadata(whNvmContext* context, whNvmId id,
        whNvmMetadata* meta);

int wh_Nvm_DestroyObjects(whNvmContext* context, whNvmId list_count,
        const whNvmId* id_list);

int wh_Nvm_Read(whNvmContext* context, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* data);

#endif /* WOLFHSM_WH_NVM_H_ */
