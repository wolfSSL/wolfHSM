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
 * src/wh_nvm_flash.c
 *
 * NVM object management on top of generic flash layer
 *
 */

#include <stddef.h>     /* For NULL */
#include <string.h>     /* For memset, memcpy */

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_unit.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"

enum {
    NF_COPY_OBJECT_BUFFER_LEN = 8 * WHFU_BYTES_PER_UNIT,
};

/* MSW of state variables (nfState) must be set to this pattern when written
 * to flash to prevent hardware on certain chipsets from confusing zero values
 * with erased flash */
static const whFlashUnit BASE_STATE = 0x1234567800000000ull;

/* On-flash layout of the state of an Object or Directory*/
typedef struct {
    whFlashUnit epoch;   /* Not Erased: counter */
    whFlashUnit start;   /* Not Erased: unit offset to start of data */
    whFlashUnit count;   /* Not Erased: unit count of data written */
} nfState;
#define NF_UNITS_PER_STATE WHFU_BYTES2UNITS(sizeof(nfState))
#define NF_STATE_EPOCH_OFFSET WHFU_BYTES2UNITS(offsetof(nfState, epoch))
#define NF_STATE_START_OFFSET WHFU_BYTES2UNITS(offsetof(nfState, start))
#define NF_STATE_COUNT_OFFSET WHFU_BYTES2UNITS(offsetof(nfState, count))

#define NF_UNITS_PER_METADATA WHFU_BYTES2UNITS(sizeof(whNvmMetadata))

/* On-flash layout of an Object */
typedef struct {
    nfState state;
    union {
        whFlashUnit units[NF_UNITS_PER_METADATA];    /* Pad to units */
        whNvmMetadata metadata;
    } u;
} nfObject;
#define NF_UNITS_PER_OBJECT WHFU_BYTES2UNITS(sizeof(nfObject))
#define NF_OBJECT_STATE_OFFSET WHFU_BYTES2UNITS(offsetof(nfObject, state))
#define NF_OBJECT_METADATA_OFFSET WHFU_BYTES2UNITS(offsetof(nfObject, u.metadata))

/* On-flash layout of a Directory */
typedef struct {
    nfObject objects[NF_OBJECT_COUNT];
} nfDirectory;
#define NF_UNITS_PER_DIRECTORY WHFU_BYTES2UNITS(sizeof(nfDirectory))
#define NF_DIRECTORY_OBJECTS_OFFSET WHFU_BYTES2UNITS(offsetof(nfDirectory, objects))
#define NF_DIRECTORY_OBJECT_OFFSET(_n) \
                    (NF_DIRECTORY_OBJECTS_OFFSET + (NF_UNITS_PER_OBJECT * _n))

/* On-flash layout of a Partition */
typedef struct {
    nfState state;
    nfDirectory directory;
} nfPartition;
#define NF_PARTITION_STATE_OFFSET WHFU_BYTES2UNITS(offsetof(nfPartition, state))
#define NF_PARTITION_DIRECTORY_OFFSET WHFU_BYTES2UNITS(offsetof(nfPartition, directory))
#define NF_PARTITION_DATA_OFFSET WHFU_BYTES2UNITS(sizeof(nfPartition))

/** Local declarations */
static int nfMemState_Read(whNvmFlashContext* context, uint32_t offset,
        nfMemState* state);
static int nfMemObject_Read(whNvmFlashContext* context, uint32_t offset,
        nfMemObject* object);

static uint32_t nfPartition_Offset(whNvmFlashContext* context, int partition);
static uint32_t nfPartition_DataOffset(whNvmFlashContext* context,
        int partition);
static int nfPartition_WriteLock(whNvmFlashContext* context, int partition);
static int nfPartition_WriteUnlock(whNvmFlashContext* context, int partition);
static int nfPartition_BlankCheck(whNvmFlashContext* context, int partition);
static int nfPartition_Erase(whNvmFlashContext* context, int partition);
static int nfPartition_ReadMemState(whNvmFlashContext* context, int partition,
        nfMemState* state);
static int nfPartition_ReadMemDirectory(whNvmFlashContext* context,
        int partition, nfMemDirectory* directory);
static int nfPartition_ReadParseMemDirectory(whNvmFlashContext* context,
        int partition, nfMemDirectory* directory);
static int nfPartition_ProgramEpoch(whNvmFlashContext* context, int partition,
        uint32_t epoch);
static int nfPartition_ProgramStart(whNvmFlashContext* context, int partition,
        uint32_t start);
static int nfPartition_ProgramCount(whNvmFlashContext* context, int partition,
        uint32_t count);
static int nfPartition_ProgramInit(whNvmFlashContext* context, int partition);
static int nfPartition_CheckDataRange(whNvmFlashContext* context,
                                       int partition,
                                       uint32_t byte_offset,
                                       uint32_t byte_count);

static uint32_t nfObject_Offset(whNvmFlashContext* context, int partition,
        int object_index);
static int nfObject_ProgramBegin(whNvmFlashContext* context, int partition,
        int object_index, uint32_t epoch, uint32_t start, whNvmMetadata* meta);
static int nfObject_ProgramDataBytes(whNvmFlashContext* context, int partition,
        uint32_t offset, uint32_t byte_count, const uint8_t* data);
static int nfObject_ProgramFinish(whNvmFlashContext* context, int partition,
        int object_index, uint32_t byte_count);
static int nfObject_Program(whNvmFlashContext* context, int partition,
        int object_index, uint32_t epoch, whNvmMetadata* meta, uint32_t start,
        const uint8_t* data);
static int nfObject_ReadDataBytes(whNvmFlashContext* context, int partition,
        int object_index, uint32_t byte_offset, uint32_t byte_count,
        uint8_t* out_data);
static int nfObject_Copy(whNvmFlashContext* context, int object_index,
        int partition, uint32_t *inout_next_object, uint32_t *inout_next_data);

static int nfMemDirectory_Parse(nfMemDirectory* d);
static int nfMemDirectory_FindObjectIndexById(nfMemDirectory* d, whNvmId id,
        int *out_object_index);


static int nfMemState_Read(whNvmFlashContext* context, uint32_t offset,
        nfMemState* state)
{
    nfState buffer;
    int ret = 0;
    int blank_count = 0;
    int blank_start = 0;
    int blank_epoch = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(state, 0, sizeof(*state));
    state->status = NF_STATUS_UNKNOWN;

    blank_epoch = wh_FlashUnit_BlankCheck(
            context->cb,
            context->flash,
            offset + NF_STATE_EPOCH_OFFSET,
            1);
    if((blank_epoch != WH_ERROR_NOTBLANK) && (blank_epoch != 0)) {
        /* Error blankchecking epoch */
        return blank_epoch;
    }

    blank_start = wh_FlashUnit_BlankCheck(
            context->cb,
            context->flash,
            offset + NF_STATE_START_OFFSET,
            1);
    if((blank_start != WH_ERROR_NOTBLANK) && (blank_start != 0)) {
        /* Error blankchecking start */
        return blank_start;
    }

    blank_count = wh_FlashUnit_BlankCheck(
            context->cb,
            context->flash,
            offset + NF_STATE_COUNT_OFFSET,
            1);
    if((blank_count != WH_ERROR_NOTBLANK) && (blank_count != 0)) {
        /* Error blankchecking count */
        return blank_count;
    }

    /* No errors blank checking.  Read all the nfState from flash */
    ret = wh_FlashUnit_Read(
                context->cb,
                context->flash,
                offset,
                NF_UNITS_PER_STATE,
                (whFlashUnit*) &buffer);
    if (ret != 0) {
        /* Error reading state*/
        return ret;
    }

    /* Ok to copy all data members into memState, even if blank */
    state->epoch = buffer.epoch;
    state->start = buffer.start;
    state->count = buffer.count;

    /* Compute status based on which state members are blank */
    if (    (blank_epoch == WH_ERROR_NOTBLANK) &&
            (blank_start == WH_ERROR_NOTBLANK) &&
            (blank_count == WH_ERROR_NOTBLANK)) {
        /* Used */
        state->status = NF_STATUS_USED;
    } else  if (    (blank_epoch == WH_ERROR_NOTBLANK) &&
                    (blank_start == WH_ERROR_NOTBLANK)){
        state->status = NF_STATUS_DATA_BAD;
    } else if (blank_epoch == WH_ERROR_NOTBLANK) {
        state->status = NF_STATUS_META_BAD;
    } else {
        state->status = NF_STATUS_FREE;
    }
    return ret;
}

static int nfMemObject_Read(whNvmFlashContext* context,
        uint32_t offset, nfMemObject* object)
{
    whFlashUnit buffer[NF_UNITS_PER_METADATA];
    int clear_metadata = 1;
    int rc = 0;

    if ((context == NULL) || (object == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = nfMemState_Read(
                context,
                offset + NF_OBJECT_STATE_OFFSET,
                &object->state);

    /* Read the metadata if it is intact, clear if not */
    if( (rc == 0) &&
        ((object->state.status == NF_STATUS_USED) ||
         (object->state.status == NF_STATUS_DATA_BAD))) {
        rc = wh_FlashUnit_Read(
                context->cb,
                context->flash,
                offset + NF_OBJECT_METADATA_OFFSET,
                NF_UNITS_PER_METADATA,
                buffer);
        if (rc == 0) {
            /* Copy the metadata out of the buffer */
            memcpy(&object->metadata, buffer, sizeof(object->metadata));
            clear_metadata = 0;
        }
    }
    if (clear_metadata != 0){
        /* Clear the object metadata */
        memset(&object->metadata, 0, sizeof(object->metadata));
    }
    return rc;
}

static uint32_t nfPartition_Offset(whNvmFlashContext* context, int partition)
{
    if (context == NULL) {
        /* Invalid.  Have to return something */
        return 0;
    }

    return context->partition_units * partition;
}

static uint32_t nfPartition_DataOffset(whNvmFlashContext* context, int partition)
{
    if (context == NULL) {
        /* Invalid.  Have to return something */
        return 0;
    }

    return nfPartition_Offset(context, partition) + NF_PARTITION_DATA_OFFSET;
}

static int nfPartition_WriteLock(whNvmFlashContext* context, int partition)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_WriteLock(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition),
            context->partition_units);
}

static int nfPartition_WriteUnlock(whNvmFlashContext* context, int partition)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_WriteUnlock(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition),
            context->partition_units);
}

static int nfPartition_BlankCheck(whNvmFlashContext* context, int partition)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_BlankCheck(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition),
            context->partition_units);
}

static int nfPartition_Erase(whNvmFlashContext* context, int partition)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_Erase(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition),
            context->partition_units);
}

static int nfPartition_ReadMemState(whNvmFlashContext* context, int partition,
        nfMemState* state)
{
    uint32_t offset = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    offset = nfPartition_Offset(context, partition);
    return nfMemState_Read(
            context,
            offset + NF_PARTITION_STATE_OFFSET,
            state);
}

static int nfPartition_ReadMemDirectory(whNvmFlashContext* context, int partition,
            nfMemDirectory* directory)
{
    int ret = 0;
    int index = 0;
    uint32_t offset = 0;

    if ((context == NULL) || (directory == NULL)) {
        return WH_ERROR_BADARGS;
    }

    offset = nfPartition_Offset(context, partition) +
                NF_PARTITION_DIRECTORY_OFFSET;
    memset(directory, 0, sizeof(*directory));

    for(index = 0; (index < NF_OBJECT_COUNT) && (ret == 0); index++) {
        /* TODO: Handle errors better here.  Break out of loop? */
        ret = nfMemObject_Read(
                context,
                offset + NF_DIRECTORY_OBJECT_OFFSET(index),
                &directory->objects[index]);
    }
    return ret;
}

static int nfPartition_ReadParseMemDirectory(whNvmFlashContext* context, int partition,
            nfMemDirectory* directory)
{
    int ret = nfPartition_ReadMemDirectory(context, partition, directory);
    if (ret != 0) {
        return ret;
    }
    return nfMemDirectory_Parse(directory);
}

static int nfPartition_ProgramEpoch(whNvmFlashContext* context,
        int partition, uint32_t epoch)
{
    whFlashUnit unit = BASE_STATE | epoch;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_Program(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition) +
                NF_PARTITION_STATE_OFFSET + NF_STATE_EPOCH_OFFSET,
            1,
            &unit);
}

static int nfPartition_ProgramStart(whNvmFlashContext* context,
        int partition, uint32_t start)
{
    whFlashUnit unit = BASE_STATE | start;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_Program(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition) +
                NF_PARTITION_STATE_OFFSET + NF_STATE_START_OFFSET,
            1,
            &unit);
}

static int nfPartition_ProgramCount(whNvmFlashContext* context,
        int partition, uint32_t count)
{
    whFlashUnit unit = BASE_STATE | count;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_Program(
            context->cb,
            context->flash,
            nfPartition_Offset(context, partition) +
                NF_PARTITION_STATE_OFFSET + NF_STATE_COUNT_OFFSET,
            1,
            &unit);

}

static int nfPartition_ProgramInit(whNvmFlashContext* context, int partition)
{
    /* Valid initial state values for a partition */
    nfMemState init_state =
    {
        .status = NF_STATUS_USED,
        .epoch = 0,
        .start = NF_PARTITION_DATA_OFFSET,
        .count = context->partition_units,
    };
    int ret = 0;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Blankcheck/Erase partition */
    ret = nfPartition_BlankCheck(context, partition);
    if (ret == WH_ERROR_NOTBLANK) {
        ret = nfPartition_Erase(context, partition);
    }
    if (ret == 0) {
        ret = nfPartition_ProgramEpoch(context, partition, init_state.epoch);
        if (ret== 0) {
            ret = nfPartition_ProgramStart(context, partition,
                    init_state.start);
            if (ret == 0) {
                ret = nfPartition_ProgramCount(context, partition,
                        init_state.count);
                if (ret == 0) {
                    context->state = init_state;
                } else {
                    context->state.status = NF_STATUS_DATA_BAD;
                }
            } else {
                context->state.status = NF_STATUS_META_BAD;
            }
        } else {
            context->state.status = NF_STATUS_FREE;
        }
    }
    return ret;
}

/*
 * Checks that the range of bytes specified by byte_offset +  byte_count
 * is located inside the specified partition's data area
 */
static int nfPartition_CheckDataRange(whNvmFlashContext* context,
                                       int partition,
                                       uint32_t byte_offset,
                                       uint32_t byte_count)
{
    uint32_t maxOffset;
    uint32_t partDataBase;

    partDataBase = nfPartition_DataOffset(context, partition) * WHFU_BYTES_PER_UNIT;
    maxOffset = (nfPartition_Offset(context, partition)
               + context->partition_units) * WHFU_BYTES_PER_UNIT;

    if (byte_offset < partDataBase) {
        return WH_ERROR_BADARGS;
    }

    if (byte_offset + byte_count > maxOffset) {
        return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static uint32_t nfObject_Offset(whNvmFlashContext* context, int partition,
        int object_index)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    return nfPartition_Offset(context,partition) +
            NF_PARTITION_DIRECTORY_OFFSET +
            NF_DIRECTORY_OBJECT_OFFSET(object_index);
}

static int nfObject_ProgramBegin(whNvmFlashContext* context, int partition,
        int object_index, uint32_t epoch, uint32_t start,
                whNvmMetadata* meta)
{
    int rc = 0;
    uint32_t object_offset = 0;
    whFlashUnit state_epoch = BASE_STATE | epoch;
    whFlashUnit state_start = BASE_STATE | start;

    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (meta == NULL)) {
        return WH_ERROR_BADARGS;
    }

    object_offset = nfObject_Offset(context, partition, object_index);

    /* Program the object epoch */
    rc = wh_FlashUnit_Program(
            context->cb,
            context->flash,
            object_offset + NF_OBJECT_STATE_OFFSET + NF_STATE_EPOCH_OFFSET,
            1,
            &state_epoch);

    if (rc == 0) {
        /* Program the object metadata */
        rc = wh_FlashUnit_Program(
                context->cb,
                context->flash,
                object_offset + NF_OBJECT_METADATA_OFFSET,
                NF_UNITS_PER_METADATA,
                (whFlashUnit*)meta);

        if (rc == 0) {
            /* Program the object start */
            rc = wh_FlashUnit_Program(
                    context->cb,
                    context->flash,
                    object_offset + NF_OBJECT_STATE_OFFSET + NF_STATE_START_OFFSET,
                    1,
                    &state_start);
        }
    }
    return rc;
}

static int nfObject_ProgramDataBytes(whNvmFlashContext* context, int partition,
        uint32_t offset, uint32_t byte_count, const uint8_t* data)
{
    uint32_t data_offset = 0;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    data_offset = nfPartition_DataOffset(context, partition) + offset;

    /* Ensure we don't program outside of the active partition */
    if (WH_ERROR_OK != nfPartition_CheckDataRange(context, partition,
                                    data_offset * WHFU_BYTES_PER_UNIT,
                                    byte_count)) {
        return WH_ERROR_BADARGS;
    }

    /* Program the data */
    return wh_FlashUnit_ProgramBytes(
            context->cb,
            context->flash,
            data_offset * WHFU_BYTES_PER_UNIT,
            byte_count,
            data);
}

static int nfObject_ProgramFinish(whNvmFlashContext* context, int partition,
        int object_index, uint32_t byte_count)
{
    uint32_t object_offset = 0;
    whFlashUnit state_count = BASE_STATE | WHFU_BYTES2UNITS(byte_count);

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    object_offset = nfObject_Offset(context, partition, object_index);

    /* Program the object flag->state_count */
    return wh_FlashUnit_Program(
            context->cb,
            context->flash,
            object_offset + NF_OBJECT_STATE_OFFSET + NF_STATE_COUNT_OFFSET,
            1,
            &state_count);
}

static int nfObject_Program(whNvmFlashContext* context, int partition,
        int object_index, uint32_t epoch,
        whNvmMetadata* meta,
        uint32_t start, const uint8_t* data)
{
    int rc = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc = nfObject_ProgramBegin(context, partition, object_index,
            epoch, start, meta);
    if (rc == 0) {
        /* allow metadata only entries for things like counters */
        if (data != NULL) {
            rc = nfObject_ProgramDataBytes(context, partition,
                    start, meta->len, data);
        }
        if (rc == 0) {
            rc = nfObject_ProgramFinish(context, partition, object_index,
                    meta->len);
        }
    }
    return rc;
}

static int nfObject_ReadDataBytes(whNvmFlashContext* context, int partition,
        int object_index,
        uint32_t byte_offset, uint32_t byte_count, uint8_t* out_data)
{
    int start = 0;
    uint32_t startOffset = 0;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    start = context->directory.objects[object_index].state.start;
    startOffset = nfPartition_DataOffset(context, partition) + start;

    /* Ensure we don't read off the end of the active partition */
    if (WH_ERROR_OK != nfPartition_CheckDataRange(context, partition,
                                    startOffset * WHFU_BYTES_PER_UNIT + byte_offset,
                                   byte_count)) {
        return WH_ERROR_BADARGS;
    }

    return wh_FlashUnit_ReadBytes(
            context->cb,
            context->flash,
            startOffset * WHFU_BYTES_PER_UNIT + byte_offset,
            byte_count,
            out_data);
}

static int nfObject_Copy(whNvmFlashContext* context, int object_index,
        int partition, uint32_t *inout_next_object, uint32_t *inout_next_data)
{
    int ret = 0;
    uint32_t dest_object = 0;
    uint32_t dest_data = 0;
    nfMemDirectory* d = NULL;
    uint32_t data_len = 0;
    uint32_t data_offset = 0;

    if (    (context == NULL) ||
            (inout_next_object == NULL) ||
            (inout_next_data == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dest_object = *inout_next_object;
    dest_data = *inout_next_data;
    d = &context->directory;

    data_len = d->objects[object_index].metadata.len;

    /* Copy the object to the new partition */
    ret = nfObject_ProgramBegin(context, partition, dest_object,
            d->objects[object_index].state.epoch,
            dest_data, &d->objects[object_index].metadata);
    if (ret != 0) return ret;

    /* Loop through reading the old data into buffer */
    while (data_offset < data_len) {
        uint8_t buffer[NF_COPY_OBJECT_BUFFER_LEN];
        uint32_t this_len = sizeof(buffer);

        if((data_len - data_offset) < this_len) {
            this_len = data_len - data_offset;
        }

        /* Read the data from the old object. */
        ret = nfObject_ReadDataBytes(
                context,
                context->active,
                object_index,
                data_offset,
                this_len,
                buffer);
        if (ret != 0) return ret;

        /* Write the data to the new object. */
        ret = nfObject_ProgramDataBytes(
                context,
                partition,
                dest_data,
                this_len,
                buffer);
        if (ret != 0) return ret;

        data_offset += this_len;
        dest_data += WHFU_BYTES2UNITS(this_len);
    }
    ret = nfObject_ProgramFinish(context, partition, dest_object, data_len);
    if (ret != 0) return ret;
    dest_object++;

    if (ret == 0) {
        *inout_next_object = dest_object;
        *inout_next_data = dest_data;
    }
    return ret;
}


static int nfMemDirectory_Parse(nfMemDirectory* d)
{
    int done = 0;
    int this_entry = 0;
    int that_entry = 0;

    if (d == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Compute next free unit and free entry based on metadata*/
    d->next_free_data = 0;
    d->reclaimable_data = 0;
    d->reclaimable_entries = 0;
    for (   d->next_free_object = 0;
            d->next_free_object < NF_OBJECT_COUNT;
            d->next_free_object++)
    {
        switch(d->objects[d->next_free_object].state.status) {
        case NF_STATUS_FREE:
            /* This must be the last. We are done */
            done = 1;
            break;
        case NF_STATUS_USED:
            /* Advance the data pointer to after this data and keep looking */
            d->next_free_data =
                d->objects[d->next_free_object].state.start +
                d->objects[d->next_free_object].state.count;
            break;
        case NF_STATUS_META_BAD:
            /* Metadata is incomplete.  Skip it*/
            d->reclaimable_entries++;
            break;
        case NF_STATUS_DATA_BAD:
            /* Data is incomplete, but we must advance the pointer */
            d->reclaimable_entries++;
            d->reclaimable_data +=
                d->objects[d->next_free_object].state.count;
            d->next_free_data =
                d->objects[d->next_free_object].state.start +
                d->objects[d->next_free_object].state.count;
            break;
        default:
            /* Unknown state.  Better barf */
            return WH_ERROR_ABORTED;
        }
        if (done) break;
    }

    /* Now walk through backwards and reclaim any duplicate meta->id data counts */
    for (this_entry = NF_OBJECT_COUNT - 1; this_entry >= 0; this_entry --) {
        if (d->objects[this_entry].state.status == NF_STATUS_USED) {
            whNvmId this_id = d->objects[this_entry].metadata.id;
            for (that_entry = this_entry - 1; that_entry >= 0; that_entry --) {
                if (    (d->objects[that_entry].state.status == NF_STATUS_USED) &&
                        (d->objects[that_entry].metadata.id == this_id)) {
                    /* Found duplicate.  Mark it as reclaimable and break out of this loop */
                    d->reclaimable_entries++;
                    d->reclaimable_data += d->objects[that_entry].state.count;
                    d->objects[that_entry].state.status = NF_STATUS_DATA_BAD;
                }
            }
        }
    }
    return 0;
}

static int nfMemDirectory_FindObjectIndexById(nfMemDirectory* d, whNvmId id,
        int *out_object_index)
{
    int index = 0;
    int ret = WH_ERROR_NOTFOUND;

    if (d == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Find first used index that matches the id. */
    for (index = 0; index< d->next_free_object; index++) {
        if ((d->objects[index].state.status == NF_STATUS_USED) &&
                (d->objects[index].metadata.id == id)) {
            if (out_object_index != NULL) *out_object_index = index;
            ret = 0;
            break;
        }
    }
    return ret;
}



/*************  WolfHSM NVM Interfaces  ***********/

int wh_NvmFlash_Init(void* c, const void* cf)
{
    whNvmFlashContext* context = c;
    const whNvmFlashConfig* config = cf;
    int ret = 0;

    if (    (context == NULL) ||
            (config == NULL) ||
            (config->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (config->cb->Init != NULL) {
        ret = config->cb->Init(config->context, config->config);
    }
    if(ret == 0) {
        /* Initialize and setup context */
        memset(context, 0, sizeof(*context));
        context->cb = config->cb;
        context->flash = config->context;

        /* Get partition size from flash device */
        if (context->cb->PartitionSize != NULL) {
            context->partition_units =
                    context->cb->PartitionSize(context->flash) /
                    WHFU_BYTES_PER_UNIT;
        }

        /* Unlock the both partitions */
        nfPartition_WriteUnlock(context, 0);
        nfPartition_WriteUnlock(context, 1);

        nfMemState part_states[2];

        /* Recover the partition states to determine which should be active */
        nfPartition_ReadMemState(context, 0 , &part_states[0]);
        nfPartition_ReadMemState(context, 1 , &part_states[1]);

        /* Decide which directory should be active */
        if (        (part_states[0].status == NF_STATUS_USED) &&
                    (part_states[1].status != NF_STATUS_USED)) {
            context->active = 0;
            context->state = part_states[context->active];
        } else if ( (part_states[0].status != NF_STATUS_USED) &&
                    (part_states[1].status == NF_STATUS_USED)) {
            context->active = 1;
            context->state = part_states[context->active];
        } else if ( (part_states[0].status == NF_STATUS_USED) &&
                    (part_states[1].status == NF_STATUS_USED)) {
            /* Check which has larger epoch */
            context->active =
                    (part_states[1].epoch > part_states[0].epoch);
            context->state = part_states[context->active];
        } else if ( (part_states[0].status == NF_STATUS_FREE) &&
                    (part_states[1].status == NF_STATUS_FREE)) {
            /* Both are blank.  Set active to 0 and initialize */
            context->active = 0;
            nfPartition_ProgramInit(context,
                    context->active);
        }

        ret = nfPartition_ReadMemDirectory(
                context,
                context->active,
                &context->directory);
        ret = nfMemDirectory_Parse(&context->directory);

        context->initialized = 1;
        return 0;
    }
    return ret;
}

int wh_NvmFlash_Cleanup(void* c)
{
    whNvmFlashContext* context = c;
    int rc = 0;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->initialized == 0) {
        /* Already cleaned up*/
        return 0;
    }

    /* Ignore errors here */
    (void)nfPartition_WriteLock(context, 0);
    (void)nfPartition_WriteLock(context, 1);

    if (context->cb->Cleanup != NULL) {
        rc = context->cb->Cleanup(context->flash);
    }
    return rc;
}

int wh_NvmFlash_List(void* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        whNvmId *out_count, whNvmId *out_id)
{
    /* TODO: Implement access and flag matching */
    (void)access; (void)flags;

    whNvmFlashContext* context = c;
    int this_entry;
    int this_count = 0;
    whNvmId this_id = 0;
    nfMemDirectory* d = NULL;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    d = &context->directory;

    /* Find the starting id */
    for (this_entry = 0; this_entry < d->next_free_object; this_entry++) {
        if (d->objects[this_entry].state.status == NF_STATUS_USED) {
            this_id = d->objects[this_entry].metadata.id;
            if ((start_id == 0) || (start_id == this_id)) {
                break;
            }
        }
    }
    if (this_entry >= d->next_free_object) {
        /* None found */
        this_count = 0;
        this_id = 0;
    } else {
        /* III id is NOT allowed to be 0, so this is simply stopping a loop */
        if (this_id != 0) {
            this_count = 1;
        }
        if (start_id != 0) {
            /* Find the next one */
            this_entry++;
            for (; this_entry < d->next_free_object; this_entry++) {
                if (d->objects[this_entry].state.status == NF_STATUS_USED) {
                    this_id = d->objects[this_entry].metadata.id;
                    break;
                }
            }
            if (this_entry >= d->next_free_object) {
                /* None found */
                this_count = 0;
                this_id = 0;
            }
        }

        /* Now count how many more there are */
        for (this_entry++; this_entry < d->next_free_object; this_entry++) {
            if (d->objects[this_entry].state.status == NF_STATUS_USED) {
                this_count++;
            }
        }
    }
    if (out_count != NULL) *out_count = this_count;
    if (out_id != NULL) *out_id = this_id;
    return 0;
}

int wh_NvmFlash_GetAvailable(void* c,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects)
{
    whNvmFlashContext* context = c;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    nfMemDirectory *d = &context->directory;
    if (out_avail_size != NULL) {
        *out_avail_size = (context->partition_units -
                NF_PARTITION_DATA_OFFSET - d->next_free_data) *
                WHFU_BYTES_PER_UNIT;
    }
    if (out_avail_objects != NULL) {
        *out_avail_objects = NF_OBJECT_COUNT - d->next_free_object;
    }
    if (out_reclaim_size != NULL) {
            *out_reclaim_size = (d->reclaimable_data) * WHFU_BYTES_PER_UNIT;
        }
        if (out_reclaim_objects != NULL) {
            *out_reclaim_objects = d->reclaimable_entries;
        }
    return 0;
}

int wh_NvmFlash_GetMetadata(void* c, whNvmId id, whNvmMetadata* meta)
{
    whNvmFlashContext* context = c;
    int entry = 0;
    int ret = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = nfMemDirectory_FindObjectIndexById(&context->directory, id, &entry);
    if (ret == 0) {
        if (meta != NULL) {
           memcpy(  meta,
                    &context->directory.objects[entry].metadata,
                    sizeof(*meta));
        }
    }
    return ret;
}

/* Add a new object. Duplicate ids are allowed, but only the most recent
 * version will be accessible.
 */
int wh_NvmFlash_AddObject(void* c, whNvmMetadata *meta,
        whNvmSize data_len, const uint8_t* data)
{
    whNvmFlashContext* context = c;
    nfMemDirectory* d = NULL;
    int oldentry = -1;
    int ret = 0;
    uint32_t epoch = 0;
    uint32_t count = 0;

    if (    (context == NULL) ||
            (meta == NULL) ||
            ((data_len > 0) && (data == NULL)) ) {
        return WH_ERROR_BADARGS;
    }

    d = &context->directory;
    if (    (d->next_free_object == NF_OBJECT_COUNT) ||
            (d->next_free_data * WHFU_BYTES_PER_UNIT + data_len >
                context->partition_units * WHFU_BYTES_PER_UNIT) ) {
        return WH_ERROR_NOSPACE;
    }

    /* Find existing object so we can increment the epoch */
    ret = nfMemDirectory_FindObjectIndexById(d, meta->id, &oldentry);
    if (oldentry >= 0) {
        epoch = d->objects[oldentry].state.epoch + 1;
    }

    /* Update meta with data size */
    meta->len = data_len;
    count = WHFU_BYTES2UNITS(meta->len);

    ret = nfObject_Program(context,
            context->active,
            d->next_free_object,
            epoch,
            meta,
            d->next_free_data,
            data);

    if (ret == 0) {
        /* Update directory with new object */
        d->objects[d->next_free_object].state.status = NF_STATUS_USED;
        d->objects[d->next_free_object].state.epoch = epoch;
        d->objects[d->next_free_object].state.start = d->next_free_data;
        d->objects[d->next_free_object].state.count = count;
        memcpy(&d->objects[d->next_free_object].metadata, meta, sizeof(*meta));
        d->next_free_data += count;
        d->next_free_object++;

        /* Update directory to reclaim old entry */
        if (oldentry >= 0) {
            d->objects[oldentry].state.status = NF_STATUS_DATA_BAD;
            d->reclaimable_entries++;
            d->reclaimable_data += d->objects[oldentry].state.count;
        }
    }
    return ret;
}

/* Destroy a list of objects by replicating the current state without the id's
 * in the provided list.  Id's in the list that are not present do not cause an
 * error.
 */
int wh_NvmFlash_DestroyObjects(void* c, whNvmId list_count,
        const whNvmId* id_list)
{
    int ret = 0;
    whNvmFlashContext* context = c;
    nfMemDirectory* d = NULL;
    nfMemState new_state =  {0};
    int list_entry = 0;
    int entry = 0;
    int src_part = 0;
    int dest_part = 0;
    uint32_t dest_object = 0;
    uint32_t dest_data = 0;

    if (    (context == NULL) ||
            ((list_count > 0) && (id_list == NULL)) ) {
        return WH_ERROR_BADARGS;
    }

    /* Context is valid.  Generate helper values */
    d = &context->directory;
    src_part = context->active;
    dest_part = !context->active;
    new_state =  (nfMemState)   {
                                    .status = NF_STATUS_FREE,
                                    .epoch = context->state.epoch + 1,
                                    .start = context->state.start,
                                    .count = context->state.count,
                                };

    /* Go through the current directory and mark the listed id's as bad */
    for (list_entry = 0; list_entry < list_count; list_entry++) {
        /* Mark all matching entries as bad.  Should only be 1. */
        do {
            entry = -1;
            ret = nfMemDirectory_FindObjectIndexById(d, id_list[list_entry],
                    &entry);
            if ((ret == 0) && (entry >= 0)) {
                d->objects[entry].state.status = NF_STATUS_DATA_BAD;
            }
        } while (entry >= 0);
    }

    /* Blank check the inactive partition and erase if not blank */
    ret = nfPartition_BlankCheck(context, dest_part);
    if (ret == WH_ERROR_NOTBLANK) {
        ret = nfPartition_Erase(context, dest_part);
    }
    if (ret != 0) {
        return ret;
    }

    ret = nfPartition_ProgramEpoch(context, dest_part, new_state.epoch);
    if (ret != 0) {
        return ret;
    }

    /* Write partition start */
    ret = nfPartition_ProgramStart(context, dest_part, new_state.start);
    if (ret != 0) {
        return ret;
    }

    /* Write each used object to new partition */
    for (entry = 0; entry < NF_OBJECT_COUNT; entry++) {
        if (d->objects[entry].state.status == NF_STATUS_USED) {
            /* TODO: Handle errors here better. Break out of loop? */
            ret = nfObject_Copy(context, entry,
                    dest_part, &dest_object, &dest_data);
        }
    }

    /* Write partition count */
    ret = nfPartition_ProgramCount(context, dest_part, new_state.count);
    if (ret != 0) {
        return ret;
    }

    /* Read and parse the new directory */
    ret = nfPartition_ReadParseMemDirectory(context,
            dest_part, &context->directory);
    if (ret != 0) {
        /* Failed to reread the directory.  Read the previous one instead */
        (void)nfPartition_ReadParseMemDirectory(context,
                src_part, &context->directory);
        return ret;
    }

    /* Update to use new partition */
    context->active = dest_part;
    new_state.status = NF_STATUS_USED;
    context->state = new_state;

    /* Erase the old directory */
    ret = nfPartition_Erase(context, src_part);

    return ret;
}

/* Read the data of the object starting at the byte offset */
int wh_NvmFlash_Read(void* c, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* data)
{
    whNvmFlashContext* context = c;
    int ret = 0;
    int object_index = -1;

    if (    (context == NULL) ||
            ((data_len > 0) && (data == NULL)) ){
        return WH_ERROR_BADARGS;
    }

    ret = nfMemDirectory_FindObjectIndexById(
            &context->directory,
            id,
            &object_index);
    if (ret == 0) {
        ret = nfObject_ReadDataBytes(
                context,
                context->active,
                object_index,
                offset,
                data_len,
                data);
    }
    return ret;
}
