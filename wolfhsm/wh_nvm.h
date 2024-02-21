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

#if 0
/* Opaque context structure associated with an NVM instance */
typedef struct whNvmContext_t whNvmContext;

/* Opaque configuration structure associated with an NVM instance */
typedef struct whNvmConfig_t whNvmConfig;
#endif

enum {
    WH_NVM_INVALID_ID = 0,
    WH_NVM_MAX_DESTROY_OBJECTS_COUNT = 10,
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
            whNvmSize *out_size, whNvmId *out_count,
            whNvmSize *out_reclaim_size, whNvmId *out_reclaim_count);

    /* Add a new object. Duplicate ids are allowed, but only the most recent
     * version will be accessible. */
    int (*AddObject)(void* context, whNvmMetadata *meta,
            whNvmSize data_len, const uint8_t* data);

    /* Retrieve the next matching id starting at start_id. Sets out_count to the
     * total number of id's that match access and flags. */
    int (*List)(void* context, whNvmAccess access, whNvmFlags flags,
        whNvmId start_id, whNvmId* out_count, whNvmId* out_id);

    /* Retrieve object metadata using the id */
    int (*GetMetadata)(void* context, whNvmId id,
            whNvmMetadata* out_meta);

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
            whNvmSize data_len, uint8_t* out_data);
} whNvmCb;

#if 0
int wh_Nvm_Init(whNvmContext* context, const whNvmConfig *config);
int wh_Nvm_Cleanup(whNvmContext* context);

/* Retrieve the current free space, or the maximum data object length that can
 * be successfully created and the number of free entries in the directory.
 * Also get the sizes that could be reclaimed if the partition was regenerated:
 *  wh_Nvm_DestroyObjects(c, 0, NULL);
 * Any out_ parameters may be NULL without error. */
int wh_Nvm_GetAvailable(whNvmContext* context,
        whNvmSize *out_size, whNvmId *out_count,
        whNvmSize *out_reclaim_size, whNvmId *out_reclaim_count);

/* Add a new object. Duplicate ids are allowed, but only the most recent
 * version will be accessible. */
int wh_Nvm_AddObject(whNvmContext* context, whNvmMetadata *meta,
        whNvmSize data_len, const uint8_t* data);

/* Retrieve the next matching id starting at start_id. Sets out_count to the
 * total number of id's that match access and flags. */
int wh_Nvm_List(whNvmContext* context, whNvmAccess access, whNvmFlags flags,
    whNvmId start_id, whNvmId* out_count, whNvmId* out_id);

/* Retrieve object metadata using the id */
int wh_Nvm_GetMetadata(whNvmContext* context, whNvmId id,
        whNvmMetadata* out_meta);

/* Destroy a list of objects by replicating the current state without the id's
 * in the provided list.  Id's in the list that are not present do not cause an
 * error.  Atomically: erase the inactive partition, add all remaining objects,
 * switch the active partition, and erase the old active (now inactive)
 * partition.  Interruption prior completing the write of the new partition will
 * recover as before the replication.  Interruption after the new partition is
 * fully populated will recover as after, including restarting erasure. */
int wh_Nvm_DestroyObjects(whNvmContext* context, whNvmId list_count,
        const whNvmId* id_list);

/* Read the data of the object starting at the byte offset */
int wh_Nvm_Read(whNvmContext* context, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* out_data);
#endif

#if 0
enum {
    WH_NVM_API_INIT             = 1,
    WH_NVM_API_CLEANUP          = 2,
    WH_NVM_API_GETAVAILABLE     = 3,
    WH_NVM_API_ADDOBJECT        = 4,
    WH_NVM_API_LIST             = 5,
    WH_NVM_API_GETMETADATA      = 6,
    WH_NVM_API_READ             = 7,
    WH_NVM_API_DESTROYOBJECTS   = 8,
};

struct whNvmApi_Init_t {
    const whNvmConfig* config;
};

struct whNvmApi_Cleanup_t {
    /* No args/state */
};

struct whNvmApi_GetAvailable_t {
    whNvmSize *out_avail_size;
    whNvmId *out_avail_count;
    whNvmSize *out_reclaim_size;
    whNvmId *out_reclaim_count;
};

struct whNvmApi_AddObject_t {
    const whNvmMetadata* meta;
    const whNvmSize data_len;
    const uint8_t* data;
};

struct whNvmApi_List_t {
    const whNvmAccess access;
    const whNvmFlags flags;
    const whNvmId start_id;
    whNvmId *out_count;
    whNvmId *out_id;
};

struct whNvmApi_GetMetadata_t {
    const whNvmId id;
    whNvmMetadata* meta;
};

struct whNvmApi_Read_t {
    const whNvmId id;
    const whNvmSize offset;
    const whNvmSize data_len;
    uint8_t* data;
};

struct whNvmApi_DestroyObjects_t {
    const whNvmId ids[WH_NVM_MAX_DESTROY_OBJECTS_COUNT];
};

typedef struct {
    int api;
    union {
        struct whNvmApi_Init_t Init;
        struct whNvmApi_Cleanup_t Cleanup;
        struct whNvmApi_GetAvailable_t GetAvailable;
        struct whNvmApi_AddObject_t AddObject;
        struct whNvmApi_List_t List;
        struct whNvmApi_GetMetadata_t GetMetadata;
        struct whNvmApi_Read_t Read;
        struct whNvmApi_DestroyObjects_t DestroyObjects;
    } arg;
} whNvmApiArg;

typedef int (*whNvm_Callback)(whNvmContext* context, whNvmApiArg* apiarg);
#endif

#endif /* WOLFHSM_WH_NVM_H_ */
