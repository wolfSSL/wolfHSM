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
        uint8_t       _pad[PAD_SIZE(sizeof(whNvmMetadata))];
    };
} whNvmFlashLogMetadata;

static int wh_NvmFlashLog_ErasePartition(whNvmFlashLogContext* ctx,
                                         uint32_t              partition)
{
    const whFlashCb* f_cb = ctx->flash_cb;
    uint32_t         part_offset;
    int              ret;

    part_offset = partition * ctx->partition_size;
    ret         = f_cb->Erase(ctx->flash_ctx, part_offset, ctx->partition_size);
    if (ret != 0)
        return ret;
    return WH_ERROR_OK;
}

static int wh_NvmFlashLog_WritePartition(whNvmFlashLogContext* ctx,
                                         uint32_t              partition)
{
    const whFlashCb* f_cb = ctx->flash_cb;
    uint32_t         part_offset;
    int              ret;

    part_offset = partition * ctx->partition_size;

    if (ctx->directory.header.size % WH_NVM_FLASH_LOG_WRITE_GRANULARITY != 0)
        return WH_ERROR_ABORTED;

    if (ctx->directory.header.size > 0) {
        ret = f_cb->Program(ctx->flash_ctx,
                            part_offset + sizeof(whNvmFlashLogPartitionHeader),
                            ctx->directory.header.size, ctx->directory.data);
        if (ret != 0)
            return ret;
    }

    return WH_ERROR_OK;
}

static int wh_NvmFlashLog_CommitPartition(whNvmFlashLogContext* ctx,
                                          uint32_t              partition)
{
    const whFlashCb* f_cb = ctx->flash_cb;
    uint32_t         part_offset;
    int              ret;

    part_offset = partition * ctx->partition_size;

    ret = f_cb->BlankCheck(ctx->flash_ctx, part_offset,
                           sizeof(whNvmFlashLogPartitionHeader));
    if (ret != 0)
        return ret;
    ret = f_cb->Program(ctx->flash_ctx, part_offset,
                        sizeof(whNvmFlashLogPartitionHeader),
                        (uint8_t*)&ctx->directory.header);
    if (ret != 0)
        return ret;

    return WH_ERROR_OK;
}

static int wh_NvmFlashLog_ChoosePartition(whNvmFlashLogContext* ctx)
{
    whNvmFlashLogPartitionHeader header0, header1;
    const whFlashCb*             f_cb = ctx->flash_cb;
    uint32_t                     part1_offset;
    int                          part0_blank, part1_blank;
    int                          ret;

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
        /* Both partitions are blank, start with partition 0 */
        ret = wh_NvmFlashLog_ErasePartition(ctx, 0);
        if (ret != 0)
            return ret;
        ret = wh_NvmFlashLog_CommitPartition(ctx, 0);
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

    return 0;
}

static whNvmFlashLogMetadata*
wh_NvmFlashLog_FindObjectById(whNvmFlashLogContext* ctx, whNvmId id)
{
    whNvmFlashLogMetadata* obj;
    uint8_t*               idx;

    if (ctx == NULL)
        return NULL;

    idx = ctx->directory.data;
    while (idx < ctx->directory.data + ctx->directory.header.size) {
        obj = (whNvmFlashLogMetadata*)idx;
        if (obj->meta.id == id) {
            return obj;
        }
        idx += sizeof(whNvmFlashLogMetadata) + PAD_SIZE(obj->meta.len);
    }
    return NULL;
}

static int wh_NvmFlashLog_DestroyObject(whNvmFlashLogContext* ctx, whNvmId id)
{
    whNvmFlashLogMetadata* obj;
    uint32_t               obj_len;
    uint32_t               obj_off;

    obj = wh_NvmFlashLog_FindObjectById(ctx, id);
    if (obj == NULL)
        return WH_ERROR_OK;

    obj_len = sizeof(whNvmFlashLogMetadata) + PAD_SIZE(obj->meta.len);
    obj_off = (uint8_t*)obj - ctx->directory.data;
    /* zero out the object to prevent leaking */
    memset(obj, 0, obj_len);
    memmove(obj, (uint8_t*)obj + obj_len,
            ctx->directory.header.size - (obj_off + obj_len));
    ctx->directory.header.size -= obj_len;
    return WH_ERROR_OK;
}

static int wh_NvmFlashLog_CountObjects(whNvmFlashLogContext*  ctx,
                                       whNvmFlashLogMetadata* start_obj)
{
    whNvmFlashLogMetadata* obj;
    uint8_t*               idx;
    int                    count = 0;

    if (ctx == NULL)
        return 0;

    idx = (start_obj != NULL) ? (uint8_t*)start_obj : ctx->directory.data;
    if (idx < ctx->directory.data ||
        idx >= ctx->directory.data + ctx->directory.header.size) {
        return 0;
    }

    while (idx < ctx->directory.data + ctx->directory.header.size) {
        obj = (whNvmFlashLogMetadata*)idx;
        if (obj->meta.id == WH_NVM_ID_INVALID) {
            break;
        }
        count++;
        idx += sizeof(whNvmFlashLogMetadata) + PAD_SIZE(obj->meta.len);
    }
    return count;
}

static int wh_NvmFlashLog_ReadPartition(whNvmFlashLogContext* ctx)
{
    const whFlashCb* f_cb = ctx->flash_cb;
    uint32_t         part_offset;
    int              ret;

    part_offset = ctx->active_partition * ctx->partition_size;

    ret = f_cb->Read(ctx->flash_ctx, part_offset,
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
                         part_offset + sizeof(whNvmFlashLogPartitionHeader),
                         ctx->directory.header.size, ctx->directory.data);
        if (ret != 0)
            return ret;
    }

    return WH_ERROR_OK;
}

static int wh_NvmFlashLog_NewEpoch(whNvmFlashLogContext* ctx)
{
    int next_active;
    int ret;

    next_active = (ctx->active_partition == 0) ? 1 : 0;
    ctx->directory.header.partition_epoch++;
    ret = wh_NvmFlashLog_ErasePartition(ctx, next_active);
    if (ret != 0)
        return ret;
    ret = wh_NvmFlashLog_WritePartition(ctx, next_active);
    if (ret != 0)
        return ret;
    ret = wh_NvmFlashLog_CommitPartition(ctx, next_active);
    if (ret != 0)
        return ret;
    ctx->active_partition = next_active;
    return WH_ERROR_OK;
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
    ret = context->flash_cb->WriteUnlock(context->flash_ctx, 0,
                                         context->partition_size);
    if (ret != 0)
        return ret;
    ret = context->flash_cb->WriteUnlock(
        context->flash_ctx, context->partition_size, context->partition_size);
    if (ret != 0)
        return ret;

    ret = wh_NvmFlashLog_ChoosePartition(context);
    if (ret != 0)
        return ret;
    ret = wh_NvmFlashLog_ReadPartition(context);
    if (ret != 0)
        return ret;

    return WH_ERROR_OK;
}

int wh_NvmFlashLog_Cleanup(void* c)
{
    int ret;
    whNvmFlashLogContext* context = (whNvmFlashLogContext*)c;
    if (context == NULL)
        return WH_ERROR_BADARGS;

    /* lock partitions */
    ret = context->flash_cb->WriteLock(context->flash_ctx, 0,
                                       context->partition_size);
    if (ret != 0)
        return ret;
    ret = context->flash_cb->WriteLock(
        context->flash_ctx, context->partition_size, context->partition_size);
    if (ret != 0)
        return ret;

    return WH_ERROR_OK;
}

/* List objects */
int wh_NvmFlashLog_List(void* c, whNvmAccess access, whNvmFlags flags,
                        whNvmId start_id, whNvmId* out_count, whNvmId* out_id)
{
    /* TODO: Implement access and flag matching */
    (void)access;
    (void)flags;
    whNvmFlashLogContext*  ctx = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata* obj;
    uint32_t               count;

    if (ctx == NULL)
        return WH_ERROR_BADARGS;

    obj = wh_NvmFlashLog_FindObjectById(ctx, start_id);
    if (obj == NULL) {
        if (out_count != NULL)
            *out_count = 0;
        if (out_id != NULL)
            *out_id = WH_NVM_ID_INVALID;
        return WH_ERROR_OK;
    }

    /* check next object */
    obj =
        (whNvmFlashLogMetadata*)((uint8_t*)obj + sizeof(whNvmFlashLogMetadata) +
                                 PAD_SIZE(obj->meta.len));
    if (obj >= (whNvmFlashLogMetadata*)(ctx->directory.data +
                                        ctx->directory.header.size) ||
        obj->meta.id == WH_NVM_ID_INVALID) {
        if (out_count != NULL)
            *out_count = 0;
        if (out_id != NULL)
            *out_id = WH_NVM_ID_INVALID;
        return WH_ERROR_OK;
    }
    count = wh_NvmFlashLog_CountObjects(ctx, obj);
    if (out_count != NULL)
        *out_count = count;
    if (out_id != NULL)
        *out_id = obj->meta.id;

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

    if (ctx == NULL)
        return WH_ERROR_BADARGS;
    if (out_avail_size != NULL) {
        *out_avail_size = ctx->partition_size -
                          sizeof(whNvmFlashLogPartitionHeader) -
                          ctx->directory.header.size;
    }

    if (out_avail_objects != NULL) {
        count              = wh_NvmFlashLog_CountObjects(ctx, NULL);
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

    if (ctx == NULL || meta == NULL)
        return WH_ERROR_BADARGS;

    obj = wh_NvmFlashLog_FindObjectById(ctx, id);
    if (obj == NULL) {
        return WH_ERROR_NOTFOUND;
    }

    memcpy(meta, &obj->meta, sizeof(*meta));
    return WH_ERROR_OK;
}

int wh_NvmFlashLog_AddObject(void* c, whNvmMetadata* meta, whNvmSize data_len,
                             const uint8_t* data)
{
    whNvmFlashLogContext*  ctx = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata *obj, *old_obj;
    uint32_t               available_space;
    uint32_t               ret;
    uint32_t               count;

    if (ctx == NULL || meta == NULL || (data_len > 0 && data == NULL))
        return WH_ERROR_BADARGS;

    count = wh_NvmFlashLog_CountObjects(ctx, NULL);
    if (count >= WOLFHSM_CFG_NVM_OBJECT_COUNT)
        return WH_ERROR_NOSPACE;

    available_space = ctx->partition_size -
                      sizeof(whNvmFlashLogPartitionHeader) -
                      ctx->directory.header.size;

    old_obj = wh_NvmFlashLog_FindObjectById(ctx, meta->id);
    if (old_obj != NULL) {
        available_space +=
            sizeof(whNvmFlashLogMetadata) + PAD_SIZE(old_obj->meta.len);
    }

    if (PAD_SIZE(data_len) + sizeof(whNvmFlashLogMetadata) > available_space)
        return WH_ERROR_NOSPACE;

    if (old_obj) {
        ret = wh_NvmFlashLog_DestroyObject(ctx, meta->id);
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

    return wh_NvmFlashLog_NewEpoch(ctx);
}

/* Destroy objects by id list */
int wh_NvmFlashLog_DestroyObjects(void* c, whNvmId list_count,
                                  const whNvmId* id_list)
{
    whNvmFlashLogContext* ctx = (whNvmFlashLogContext*)c;
    int                   i;
    int                   ret;

    if (ctx == NULL || (list_count > 0 && id_list == NULL))
        return WH_ERROR_BADARGS;

    if (list_count == 0)
        return WH_ERROR_OK;

    for (i = 0; i < list_count; i++) {
        ret = wh_NvmFlashLog_DestroyObject(ctx, id_list[i]);
        if (ret != WH_ERROR_OK)
            return ret;
    }

    return wh_NvmFlashLog_NewEpoch(ctx);
}

/* Read object data */
int wh_NvmFlashLog_Read(void* c, whNvmId id, whNvmSize offset,
                        whNvmSize data_len, uint8_t* data)
{
    whNvmFlashLogContext*  ctx = (whNvmFlashLogContext*)c;
    whNvmFlashLogMetadata* obj;
    uint8_t*               obj_data;

    if (ctx == NULL || (data_len > 0 && data == NULL))
        return WH_ERROR_BADARGS;

    obj = wh_NvmFlashLog_FindObjectById(ctx, id);
    if (obj == NULL)
        return WH_ERROR_NOTFOUND;

    if (offset + data_len > obj->meta.len)
        return WH_ERROR_BADARGS;

    obj_data = (uint8_t*)obj + sizeof(whNvmFlashLogMetadata) + offset;
    memcpy(data, obj_data, data_len);

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */
