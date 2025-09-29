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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * wh NVM Flash Layer
 *
 * This NVM layer provides secure, atomic storage of data on flash devices
 * with large write granularity (e.g., 64 bytes). The layer manages two
 * equal-sized partitions in flash, with only one partition active at any time.
 * All objects metadata are cached in memory for fast access.
 *
 * Atomicity Guarantee:
 * On every modification, the inactive partition is erased, all objects are
 * written to it, and only then is the partition header (containing an
 * incremented epoch counter) programmed. At initialization, the layer selects
 * the partition with the highest epoch as active, ensuring that after any
 * interruption, either the state before or after the write is valid.
 *
 * Object Storage Format:
 * Objects are stored back-to-back in the partition, each consisting of a
 * whNvmMetadata structure immediately followed by the object data.
 *
 * Write Padding:
 * All writes are padded to the flash's write granularity.
 *
 * Flash backend:
 * This layer relies on the same flash backend as wh_Flash, using the whFlashCb
 * interface.
 *
 * Limitations and performance considerations:
 *
 * The implementation favors simplicity over both speed and space.
 *
 * Regarding space:
 * - An area of RAM as big as one partition is allocated to cache the
 * partition.
 *
 * Regarding speed:
 * - Each updates to the NVM (create, write, delete) requires copying all the
 * objects from one partition of the flash to the other + erase operations.
 *
 * Possible future improvements:
 *
 * - cache only the metadata in RAM, access data on the FLASH as needed
 * - use a true append log format to avoid copying all objects on each update
 *
 * Right now the implementation works well for read-heavy workloads with few
 * updates.
 *
 * Alignment consideration:
 *
 * The implementation assure that writes are aligned to WRITE_GRANULARITY in FLASH memory space.
 * The source data passed on the flash layer might not be aligned.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"

#include "wolfhsm/wh_nvm_flash_log.h"

#define PAD_SIZE(size)                                   \
    (((size) + WH_NVM_FLASH_LOG_WRITE_GRANULARITY - 1) & \
     ~(WH_NVM_FLASH_LOG_WRITE_GRANULARITY - 1))

typedef struct {
    union {
        whNvmMetadata meta;
        uint8_t       WH_PAD[PAD_SIZE(sizeof(whNvmMetadata))];
    };
} whNvmFlashLogMetadata;

/* do a blank check + program + verify */
static int nfl_FlashProgramHelper(whNvmFlashLogContext* ctx, uint32_t off,
                                  const uint8_t* data, uint32_t len)
{
    int ret;

    if (ctx == NULL || (data == NULL && len > 0))
        return WH_ERROR_BADARGS;

    ret = ctx->flash_cb->BlankCheck(ctx->flash_ctx, off, len);
    if (ret != 0)
        return ret;
    ret = ctx->flash_cb->Program(ctx->flash_ctx, off, len, data);
    if (ret != 0)
        return ret;
    ret = ctx->flash_cb->Verify(ctx->flash_ctx, off, len, data);
    if (ret != 0)
        return ret;
    return WH_ERROR_OK;
}

/* do a erase + blank check */
static int nfl_FlashEraseHelper(whNvmFlashLogContext* ctx, uint32_t off,
                                uint32_t len)
{
    int ret;

    if (ctx == NULL)
        return WH_ERROR_BADARGS;
    ret = ctx->flash_cb->Erase(ctx->flash_ctx, off, len);
    if (ret != 0)
        return ret;
    ret = ctx->flash_cb->BlankCheck(ctx->flash_ctx, off, len);
    if (ret != 0)
        return ret;

    return WH_ERROR_OK;
}

static whNvmFlashLogMetadata* nfl_ObjNext(whNvmFlashLogContext*  ctx,
                                          whNvmFlashLogMetadata* obj)
{
    if (obj == NULL || ctx == NULL)
        return NULL;
    uint8_t* next = (uint8_t*)obj + sizeof(whNvmFlashLogMetadata) +
                    PAD_SIZE(obj->meta.len);
    if (next >= ctx->directory.data + ctx->directory.header.size)
        return NULL;
    return (whNvmFlashLogMetadata*)next;
}

static int nfl_PartitionErase(whNvmFlashLogContext* ctx, uint32_t partition)
{
    uint32_t off;

    if (ctx == NULL || partition > 1)
        return WH_ERROR_BADARGS;

    off = partition * ctx->partition_size;
    return nfl_FlashEraseHelper(ctx, off, ctx->partition_size);
}

static int nfl_PartitionWrite(whNvmFlashLogContext* ctx, uint32_t partition)
{
    uint32_t off;
    int      ret;

    if (ctx == NULL || partition > 1)
        return WH_ERROR_BADARGS;

    off = partition * ctx->partition_size;

    if (ctx->directory.header.size % WH_NVM_FLASH_LOG_WRITE_GRANULARITY != 0)
        return WH_ERROR_ABORTED;

    if (ctx->directory.header.size > 0) {
        ret = nfl_FlashProgramHelper(
            ctx, off + sizeof(whNvmFlashLogPartitionHeader),
            ctx->directory.data, ctx->directory.header.size);
        if (ret != 0)
            return ret;
    }

    return WH_ERROR_OK;
}

static int nfl_PartitionCommit(whNvmFlashLogContext* ctx, uint32_t partition)
{
    const whFlashCb* f_cb = ctx->flash_cb;
    uint32_t         off;
    int              ret;

    if (ctx == NULL || partition > 1)
        return WH_ERROR_BADARGS;

    off = partition * ctx->partition_size;

    ret = f_cb->BlankCheck(ctx->flash_ctx, off,
                           sizeof(whNvmFlashLogPartitionHeader));
    if (ret != 0)
        return ret;

    ret = nfl_FlashProgramHelper(ctx, off, (uint8_t*)&ctx->directory.header,
                                 sizeof(whNvmFlashLogPartitionHeader));
    if (ret != 0)
        return ret;

    return WH_ERROR_OK;
}

static int nfl_PartitionChoose(whNvmFlashLogContext* ctx)
{
    whNvmFlashLogPartitionHeader header0, header1;
    const whFlashCb*             f_cb = ctx->flash_cb;
    uint32_t                     part1_offset;
    int                          part0_blank, part1_blank;
    int                          ret;

    if (ctx == NULL)
        return WH_ERROR_BADARGS;

    part1_offset = ctx->partition_size;

    ret = f_cb->BlankCheck(ctx->flash_ctx, 0, sizeof(header0));
    if (ret != 0 && ret != WH_ERROR_NOTBLANK) {
        return ret;
    }
    part0_blank = (ret == 0);

    ret = f_cb->BlankCheck(ctx->flash_ctx, part1_offset, sizeof(header0));
    if (ret != 0 && ret != WH_ERROR_NOTBLANK) {
        return ret;
    }
    part1_blank = (ret == 0);

    if (part0_blank && part1_blank) {
        /* Both partitions headers are blank, start with partition 0 */
        ret = nfl_PartitionErase(ctx, 0);
        if (ret != 0)
            return ret;
        ret = nfl_PartitionCommit(ctx, 0);
        if (ret != 0)
            return ret;
        return WH_ERROR_OK;
    }

    if (part0_blank) {
        ctx->active_partition = 1;
        return WH_ERROR_OK;
    }

    if (part1_blank) {
        ctx->active_partition = 0;
        return WH_ERROR_OK;
    }

    /* both partition are programmed */
    ret = f_cb->Read(ctx->flash_ctx, 0, sizeof(header0), (uint8_t*)&header0);
    if (ret != 0) {
        return ret;
    }
    ret = f_cb->Read(ctx->flash_ctx, part1_offset, sizeof(header1),
                     (uint8_t*)&header1);
    if (ret != 0) {
        return ret;
    }

    if (header0.partition_epoch > header1.partition_epoch) {
        ctx->active_partition = 0;
    }
    else {
        ctx->active_partition = 1;
    }

    return WH_ERROR_OK;
}

static whNvmFlashLogMetadata* nfl_ObjectFindById(whNvmFlashLogContext* ctx,
                                                 whNvmId               id)
{
    whNvmFlashLogMetadata* obj;

    if (ctx == NULL || id == WH_NVM_ID_INVALID)
        return NULL;

    obj = (whNvmFlashLogMetadata*)ctx->directory.data;
    while (obj != NULL && obj->meta.id != WH_NVM_ID_INVALID) {
        if (obj->meta.id == id) {
            return obj;
        }
        obj = nfl_ObjNext(ctx, obj);
    }
    return NULL;
}

static int nfl_ObjectDestroy(whNvmFlashLogContext* ctx, whNvmId id)
{
    whNvmFlashLogMetadata* obj;
    uint32_t               len;
    uint32_t               off;
    uint32_t               tail;

    if (ctx == NULL || id == WH_NVM_ID_INVALID)
        return WH_ERROR_BADARGS;

    obj = nfl_ObjectFindById(ctx, id);
    if (obj == NULL)
        return WH_ERROR_OK;

    len  = sizeof(whNvmFlashLogMetadata) + PAD_SIZE(obj->meta.len);
    off  = (uint8_t*)obj - ctx->directory.data;
    tail = ctx->directory.header.size - (off + len);
    memmove(obj, (uint8_t*)obj + len, tail);
    /* be sure to clean-up moved objects from memory */
    memset((uint8_t*)obj + tail, 0, len);
    ctx->directory.header.size -= len;
    return WH_ERROR_OK;
}

static int nfl_ObjectCount(whNvmFlashLogContext*  ctx,
                           whNvmFlashLogMetadata* startObj)
{
    int count = 0;

    if (ctx == NULL)
        return 0;

    if (startObj == NULL) {
        startObj = (whNvmFlashLogMetadata*)ctx->directory.data;
    }

    if ((uint8_t*)startObj < ctx->directory.data ||
        (uint8_t*)startObj >= ctx->directory.data + ctx->directory.header.size) {
        return 0;
    }

    while (startObj != NULL) {
        if (startObj->meta.id == WH_NVM_ID_INVALID) {
            break;
        }
        count++;
        startObj = nfl_ObjNext(ctx, startObj);
    }

    return count;
}

static int nfl_PartitionRead(whNvmFlashLogContext* ctx)
{
    const whFlashCb* f_cb;
    uint32_t         off;
    int              ret;

    if (ctx == NULL)
        return WH_ERROR_BADARGS;

    f_cb = ctx->flash_cb;
    off = ctx->active_partition * ctx->partition_size;

    ret = f_cb->Read(ctx->flash_ctx, off,
                     sizeof(whNvmFlashLogPartitionHeader),
                     (uint8_t*)&ctx->directory.header);
    if (ret != 0)
        return ret;

    if (ctx->directory.header.size >
        ctx->partition_size - sizeof(whNvmFlashLogPartitionHeader)) {
        return WH_ERROR_ABORTED;
    }

    if (ctx->directory.header.size > 0) {
        ret = f_cb->Read(ctx->flash_ctx,
                         off + sizeof(whNvmFlashLogPartitionHeader),
                         ctx->directory.header.size, ctx->directory.data);
        if (ret != 0)
            return ret;
    }

    return WH_ERROR_OK;
}

static int nfl_PartitionNewEpoch(whNvmFlashLogContext* ctx)
{
    int next_active;
    int ret;

    if (ctx == NULL)
        return WH_ERROR_BADARGS;

    next_active = (ctx->active_partition == 0) ? 1 : 0;
    ctx->directory.header.partition_epoch++;
    ret = nfl_PartitionErase(ctx, next_active);
    if (ret != 0)
        return ret;
    ret = nfl_PartitionWrite(ctx, next_active);
    if (ret != 0)
        return ret;
    ret = nfl_PartitionCommit(ctx, next_active);
    if (ret != 0)
        return ret;
    ctx->active_partition = next_active;
    return WH_ERROR_OK;
}

static int nfl_PartitionNewEpochOrFallback(whNvmFlashLogContext* ctx)
{
    int ret;

    if (ctx == NULL)
        return WH_ERROR_BADARGS;
    ret = nfl_PartitionNewEpoch(ctx);

    if (ret != WH_ERROR_OK) {
        /*  swtiching  to new partition failed for a reason, try to restore
         *  back active partition. */
        nfl_PartitionRead(ctx);
    }

    return ret;
}

/* Initialization function */
int wh_NvmFlashLog_Init(void* c, const void* cf)
{
    whNvmFlashLogContext*      context = (whNvmFlashLogContext*)c;
    const whNvmFlashLogConfig* config  = (const whNvmFlashLogConfig*)cf;
    int                        ret;

    if (context == NULL || config == NULL || config->flash_cb == NULL ||
        config->flash_ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (config->flash_cb->PartitionSize == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset(context, 0, sizeof(*context));

    ret = 0;
    if (config->flash_cb->Init != NULL)
        ret = config->flash_cb->Init(config->flash_ctx, config->flash_cfg);
    if (ret != 0)
        return ret;

    context->flash_cb  = config->flash_cb;
    context->flash_ctx = config->flash_ctx;
    context->partition_size =
        context->flash_cb->PartitionSize(context->flash_ctx);

    if (context->partition_size != WH_NVM_FLASH_LOG_PARTITION_SIZE ||
        context->partition_size % WH_NVM_FLASH_LOG_WRITE_GRANULARITY != 0) {
        return WH_ERROR_BADARGS;
    }

    /* unlock partitions */
    if (context->flash_cb->WriteUnlock != NULL) {
        ret = context->flash_cb->WriteUnlock(context->flash_ctx, 0,
                                             context->partition_size);
        if (ret != 0)
            return ret;
        ret = context->flash_cb->WriteUnlock(context->flash_ctx,
                                             context->partition_size,
                                             context->partition_size);
        if (ret != 0)
            return ret;
    }

    ret = nfl_PartitionChoose(context);
    if (ret != 0)
        return ret;
    ret = nfl_PartitionRead(context);
    if (ret != 0)
        return ret;
    ret = nfl_PartitionErase(context, (context->active_partition == 0) ? 1 : 0);
    if (ret != 0)
        return ret;

    context->is_initialized = 1;
    return WH_ERROR_OK;
}

int wh_NvmFlashLog_Cleanup(void* c)
{
    whNvmFlashLogContext* context = (whNvmFlashLogContext*)c;
    int                   ret0, ret1;

    if (context == NULL || !context->is_initialized)
        return WH_ERROR_BADARGS;

    context->is_initialized = 0;

    /* lock partitions */
    if (context->flash_cb->WriteLock == NULL)
        return WH_ERROR_OK;

    ret0 = context->flash_cb->WriteLock(context->flash_ctx, 0,
                                        context->partition_size);
    ret1 = context->flash_cb->WriteLock(
        context->flash_ctx, context->partition_size, context->partition_size);

    if (ret0 != WH_ERROR_OK)
        return ret0;
    if (ret1 != WH_ERROR_OK)
        return ret1;

    return WH_ERROR_OK;
}

/* List objects */
int wh_NvmFlashLog_List(void* c, whNvmAccess access, whNvmFlags flags,
                        whNvmId start_id, whNvmId* out_count, whNvmId* out_id)
{
    whNvmFlashLogContext*  ctx      = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata *next_obj = NULL, *start_obj = NULL;
    uint32_t               count = 0;

    /* TODO: Implement access and flag matching */
    (void)access;
    (void)flags;

    if (ctx == NULL || !ctx->is_initialized)
        return WH_ERROR_BADARGS;

    /* list all obects if start_id is WH_NVM_ID_INVALID */
    if (start_id == WH_NVM_ID_INVALID) {
        next_obj = (whNvmFlashLogMetadata*)ctx->directory.data;
    } else {
        start_obj = nfl_ObjectFindById(ctx, start_id);
        if (start_obj != NULL && start_obj->meta.id != WH_NVM_ID_INVALID)
            next_obj = nfl_ObjNext(ctx, start_obj);
    }

    if (next_obj == NULL || next_obj->meta.id == WH_NVM_ID_INVALID) {
        if (out_count != NULL)
            *out_count = 0;
        if (out_id != NULL)
            *out_id = WH_NVM_ID_INVALID;
        return WH_ERROR_OK;
    }

    count = nfl_ObjectCount(ctx, next_obj);
    if (out_count != NULL)
        *out_count = count;
    if (out_id != NULL)
        *out_id = next_obj->meta.id;

    return WH_ERROR_OK;
}

/* Get available space/objects */
int wh_NvmFlashLog_GetAvailable(void* c, uint32_t* out_avail_size,
                                whNvmId*  out_avail_objects,
                                uint32_t* out_reclaim_size,
                                whNvmId*  out_reclaim_objects)
{
    whNvmFlashLogContext* ctx = (whNvmFlashLogContext*)c;
    uint8_t               count;

    if (ctx == NULL || !ctx->is_initialized)
        return WH_ERROR_BADARGS;
    if (out_avail_size != NULL) {
        *out_avail_size = ctx->partition_size -
                          sizeof(whNvmFlashLogPartitionHeader) -
                          ctx->directory.header.size;
    }

    if (out_avail_objects != NULL) {
        count              = nfl_ObjectCount(ctx, NULL);
        *out_avail_objects = WOLFHSM_CFG_NVM_OBJECT_COUNT - count;
    }

    /* No reclaim in this simple implementation */
    if (out_reclaim_size != NULL) {
        *out_reclaim_size = 0;
    }
    if (out_reclaim_objects != NULL) {
        *out_reclaim_objects = 0;
    }

    return WH_ERROR_OK;
}

/* Get metadata for an object */
int wh_NvmFlashLog_GetMetadata(void* c, whNvmId id, whNvmMetadata* meta)
{
    whNvmFlashLogContext*  ctx = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata* obj;

    if (ctx == NULL || !ctx->is_initialized)
        return WH_ERROR_BADARGS;

    obj = nfl_ObjectFindById(ctx, id);
    if (obj == NULL) {
        return WH_ERROR_NOTFOUND;
    }

    if (meta != NULL)
        memcpy(meta, &obj->meta, sizeof(*meta));
    return WH_ERROR_OK;
}

int wh_NvmFlashLog_AddObject(void* c, whNvmMetadata* meta, whNvmSize data_len,
                             const uint8_t* data)
{
    whNvmFlashLogContext*  ctx = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata *obj, *old_obj;
    uint32_t               available_space;
    int                    ret;
    uint32_t               count;

    if (ctx == NULL || !ctx->is_initialized || meta == NULL || (data_len > 0 && data == NULL))
        return WH_ERROR_BADARGS;

    count = nfl_ObjectCount(ctx, NULL);
    if (count >= WOLFHSM_CFG_NVM_OBJECT_COUNT)
        return WH_ERROR_NOSPACE;

    available_space = ctx->partition_size -
                      sizeof(whNvmFlashLogPartitionHeader) -
                      ctx->directory.header.size;

    old_obj = nfl_ObjectFindById(ctx, meta->id);
    if (old_obj != NULL) {
        available_space +=
            sizeof(whNvmFlashLogMetadata) + PAD_SIZE(old_obj->meta.len);
    }

    if (PAD_SIZE(data_len) + sizeof(whNvmFlashLogMetadata) > available_space)
        return WH_ERROR_NOSPACE;

    if (old_obj) {
        ret = nfl_ObjectDestroy(ctx, meta->id);
        if (ret != WH_ERROR_OK)
            return ret;
    }

    obj       = (whNvmFlashLogMetadata*)(ctx->directory.data +
                                   ctx->directory.header.size);
    meta->len = data_len;
    memcpy(&obj->meta, meta, sizeof(*meta));
    memcpy((uint8_t*)obj + sizeof(whNvmFlashLogMetadata), data, data_len);
    ctx->directory.header.size +=
        sizeof(whNvmFlashLogMetadata) + PAD_SIZE(data_len);

    return nfl_PartitionNewEpochOrFallback(ctx);
}

/* Destroy objects by id list */
int wh_NvmFlashLog_DestroyObjects(void* c, whNvmId list_count,
                                  const whNvmId* id_list)
{
    whNvmFlashLogContext* ctx = (whNvmFlashLogContext*)c;
    int                   i;
    int                   ret;

    if (ctx == NULL || !ctx->is_initialized || (list_count > 0 && id_list == NULL))
        return WH_ERROR_BADARGS;

    if (list_count == 0)
        return WH_ERROR_OK;

    for (i = 0; i < list_count; i++) {
        ret = nfl_ObjectDestroy(ctx, id_list[i]);
        if (ret != WH_ERROR_OK)
            return ret;
    }

    return nfl_PartitionNewEpochOrFallback(ctx);
}

/* Read object data */
int wh_NvmFlashLog_Read(void* c, whNvmId id, whNvmSize offset,
                        whNvmSize data_len, uint8_t* data)
{
    whNvmFlashLogContext*  ctx = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata* obj;
    uint8_t*               obj_data;

    if (ctx == NULL || !ctx->is_initialized || (data_len > 0 && data == NULL))
        return WH_ERROR_BADARGS;

    obj = nfl_ObjectFindById(ctx, id);
    if (obj == NULL)
        return WH_ERROR_NOTFOUND;

    if (offset + data_len > obj->meta.len)
        return WH_ERROR_BADARGS;

    obj_data = (uint8_t*)obj + sizeof(whNvmFlashLogMetadata) + offset;
    memcpy(data, obj_data, data_len);

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */
