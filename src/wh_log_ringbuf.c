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
 * src/wh_log_ringbuf.c
 *
 * Ring buffer logging backend implementation
 */

#include <stddef.h> /* For NULL */
#include <string.h> /* For memset, memcpy */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"
#include "wolfhsm/wh_log_ringbuf.h"

#ifdef WOLFHSM_CFG_LOGGING

int whLogRingbuf_Init(void* c, const void* cf)
{
    whLogRingbufContext*      context = (whLogRingbufContext*)c;
    const whLogRingbufConfig* config  = (const whLogRingbufConfig*)cf;
    size_t                    capacity;

    if (context == NULL || config == NULL || config->buffer == NULL ||
        config->buffer_size < sizeof(whLogEntry)) {
        return WH_ERROR_BADARGS;
    }

    /* Calculate capacity (number of complete entries that fit in buffer) */
    capacity = config->buffer_size / sizeof(whLogEntry);

    /* Initialize context */
    memset(context, 0, sizeof(*context));
    context->entries     = (whLogEntry*)config->buffer;
    context->capacity    = capacity;
    context->count       = 0;
    context->initialized = 1;

    return WH_ERROR_OK;
}

int whLogRingbuf_Cleanup(void* c)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->initialized) {
        (void)whLogRingbuf_Clear(context);
        context->initialized = 0;
    }

    return WH_ERROR_OK;
}

int whLogRingbuf_AddEntry(void* c, const whLogEntry* entry)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;
    size_t               head;

    if ((context == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized) {
        return WH_ERROR_ABORTED;
    }

    /* Calculate head position from count */
    head = context->count % context->capacity;

    /* Copy entry to ring buffer at head position */
    memcpy(&context->entries[head], entry, sizeof(whLogEntry));

    /* Increment count freely to track total messages written */
    context->count++;

    return WH_ERROR_OK;
}

int whLogRingbuf_Export(void* c, void* export_arg)
{
    (void)c;
    (void)export_arg;
    return WH_ERROR_OK;
}

int whLogRingbuf_Iterate(void* c, whLogIterateCb iterate_cb, void* iterate_arg)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;
    size_t               capacity;
    size_t               num_entries;
    size_t               start_idx;
    size_t               i;
    int                  ret = 0;

    if ((context == NULL) || (iterate_cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!context->initialized) {
        return WH_ERROR_ABORTED;
    }

    /* If buffer is empty, nothing to iterate */
    if (context->count == 0) {
        return WH_ERROR_OK;
    }

    capacity = context->capacity;

    /* Calculate actual number of entries in buffer (capped at capacity) */
    num_entries = (context->count < capacity) ? context->count : capacity;

    /* Determine starting index for iteration:
     * - If not full: start at 0 (oldest entry)
     * - If full: start at head (oldest entry, about to be overwritten)
     *   head = count % capacity
     */
    if (context->count < capacity) {
        start_idx = 0;
    }
    else {
        start_idx = context->count % capacity;
    }

    /* Iterate through entries in chronological order */
    for (i = 0; i < num_entries; i++) {
        size_t idx = (start_idx + i) % capacity;
        ret        = iterate_cb(iterate_arg, &context->entries[idx]);
        if (ret != 0) {
            /* User callback requested early termination */
            break;
        }
    }

    return ret;
}

int whLogRingbuf_Clear(void* c)
{
    whLogRingbufContext* context = (whLogRingbufContext*)c;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Reset ring buffer state */
    context->count = 0;

    /* Zero the log entries */
    memset(context->entries, 0, context->capacity * sizeof(whLogEntry));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_LOGGING */
