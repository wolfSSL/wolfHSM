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

int whLogRingbuf_Init(void* context, const void* config)
{
    whLogRingbufContext*      ctx = (whLogRingbufContext*)context;
    const whLogRingbufConfig* cfg  = (const whLogRingbufConfig*)config;
    size_t                    capacity;

    if (ctx == NULL || cfg == NULL || cfg->buffer == NULL ||
        cfg->buffer_size < sizeof(whLogEntry)) {
        return WH_ERROR_BADARGS;
    }

    /* Calculate capacity (number of complete entries that fit in buffer) */
    capacity = cfg->buffer_size / sizeof(whLogEntry);
    /* Capacity must be able to hold at least one log entry, specifically to
     * prevent divide-by-zeros in the rollover logic */
    if (capacity == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));
    ctx->entries     = (whLogEntry*)cfg->buffer;
    ctx->capacity    = capacity;
    ctx->count       = 0;
    ctx->initialized = 1;

    return WH_ERROR_OK;
}

int whLogRingbuf_Cleanup(void* c)
{
    whLogRingbufContext* ctx = (whLogRingbufContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->initialized) {
        (void)whLogRingbuf_Clear(ctx);
        ctx->initialized = 0;
    }

    return WH_ERROR_OK;
}

int whLogRingbuf_AddEntry(void* c, const whLogEntry* entry)
{
    whLogRingbufContext* ctx = (whLogRingbufContext*)c;
    size_t               head;

    if ((ctx == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized) {
        return WH_ERROR_ABORTED;
    }

    /* Calculate head position from count */
    head = ctx->count % ctx->capacity;

    /* Copy entry to ring buffer at head position */
    memcpy(&ctx->entries[head], entry, sizeof(whLogEntry));

    /* Increment count freely to track total messages written */
    ctx->count++;

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
    whLogRingbufContext* ctx = (whLogRingbufContext*)c;
    size_t               capacity;
    size_t               num_entries;
    size_t               start_idx;
    size_t               i;
    int                  ret = 0;

    if ((ctx == NULL) || (iterate_cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized) {
        return WH_ERROR_ABORTED;
    }

    /* If buffer is empty, nothing to iterate */
    if (ctx->count == 0) {
        return WH_ERROR_OK;
    }

    capacity = ctx->capacity;

    /* Calculate actual number of entries in buffer (capped at capacity) */
    num_entries = (ctx->count < capacity) ? ctx->count : capacity;

    /* Determine starting index for iteration:
     * - If not full: start at 0 (oldest entry)
     * - If full: start at head (oldest entry, about to be overwritten)
     *   head = count % capacity
     */
    if (ctx->count < capacity) {
        start_idx = 0;
    }
    else {
        start_idx = ctx->count % capacity;
    }

    /* Iterate through entries in chronological order */
    for (i = 0; i < num_entries; i++) {
        size_t idx = (start_idx + i) % capacity;
        ret        = iterate_cb(iterate_arg, &ctx->entries[idx]);
        if (ret != 0) {
            /* User callback requested early termination */
            break;
        }
    }

    return ret;
}

int whLogRingbuf_Clear(void* c)
{
    whLogRingbufContext* ctx = (whLogRingbufContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Reset ring buffer state */
    ctx->count = 0;

    /* Zero the log entries */
    memset(ctx->entries, 0, ctx->capacity * sizeof(whLogEntry));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_LOGGING */
