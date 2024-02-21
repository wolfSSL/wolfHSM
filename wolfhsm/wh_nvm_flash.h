/*
 * wolfhsm/nvm_flash.h
 *
 * Concrete library to implement an NVM data store using a flash-like back end.
 *
 */

#ifndef WOLFHSM_WH_NVMFLASH_H_
#define WOLFHSM_WH_NVMFLASH_H_

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_unit.h"

/* Number of objects in a directory */
#define NF_OBJECT_COUNT 32

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

/** whNvm required structure definitions */
typedef struct whNvmFlashContext_t {
    int initialized;

    const whFlashCb* cb;
    void* flash;                    /* Flash context to use */
    uint32_t partition_units;       /* Size of partition in units */

    int active;                     /* Which partition (0 or 1) is active */
    nfMemState state;               /* State of active partition */
    nfMemDirectory directory;       /* Cache of active objects */
} whNvmFlashContext;

/* In memory configuration structure associated with an NVM instance */
typedef struct whNvmFlashConfig_t {
    const whFlashCb* cb;
    void* context;         /* NvmFlash context */
    const void* config;     /* Config to pass to NvmFlash_Init*/
} whNvmFlashConfig;


/* NVM Interface */
int wh_NvmFlash_Init(void* c, const void* cf);
int wh_NvmFlash_Cleanup(void* c);
int wh_NvmFlash_List(void* c, whNvmAccess access, whNvmFlags flags,
    whNvmId start_id, whNvmId* out_count, whNvmId* out_id);
int wh_NvmFlash_GetAvailable(void* c,
        whNvmSize *out_size, whNvmId *out_count,
        whNvmSize *out_reclaim_size, whNvmId *out_reclaim_count);
int wh_NvmFlash_GetMetadata(void* c, whNvmId id, whNvmMetadata* out_meta);
int wh_NvmFlash_AddObject(void* c, whNvmMetadata *meta,
        whNvmSize data_len,const uint8_t* data);
int wh_NvmFlash_DestroyObjects(void* c, whNvmId list_count,
        const whNvmId* id_list);
int wh_NvmFlash_Read(void* c, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* out_data);

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
