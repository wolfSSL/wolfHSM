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
 * src/wh_log.c
 *
 * Generic logging frontend implementation
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_log.h"

#ifdef WOLFHSM_CFG_LOGGING

void wh_Log_InternalSubmit(whLogContext* ctx, whLogLevel level,
                           const char* file, const char* function,
                           uint32_t line, const char* src, size_t src_len)
{
    uint64_t timestamp = WH_GETTIME_US();
    size_t   max_len =
        (WOLFHSM_CFG_LOG_MSG_MAX > 0) ? (WOLFHSM_CFG_LOG_MSG_MAX - 1) : 0;
    size_t     copy_len = (src_len < max_len) ? src_len : max_len;
    whLogEntry entry    = {.timestamp = timestamp,
                           .level     = level,
                           .file      = file,
                           .function  = function,
                           .line      = line,
                           .msg_len   = (uint32_t)copy_len};

    if ((src != NULL) && (copy_len > 0)) {
        memcpy(entry.msg, src, copy_len);
    }
    entry.msg[copy_len] = '\0';

    wh_Log_AddEntry(ctx, &entry);
}

void wh_Log_InternalFormat(whLogContext* ctx, whLogLevel level,
                           const char* file, const char* function,
                           uint32_t line, const char* fmt, ...)
{
    char    buf[WOLFHSM_CFG_LOG_MSG_MAX];
    va_list args;
    int     ret;
    size_t  formatted_len;

    va_start(args, fmt);
    ret = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* vsnprintf returns the number of characters that would have been written
     * (excluding null terminator) if the buffer was large enough.
     * If ret < 0, there was an error; treat as empty string.
     * If ret >= sizeof(buf), output was truncated. */
    if (ret < 0) {
        formatted_len = 0;
    }
    else if ((size_t)ret >= sizeof(buf)) {
        /* Truncated - actual length is sizeof(buf) - 1 */
        formatted_len = sizeof(buf) - 1;
    }
    else {
        formatted_len = (size_t)ret;
    }

    wh_Log_InternalSubmit(ctx, level, file, function, line, buf, formatted_len);
}

int wh_Log_Init(whLogContext* ctx, const whLogConfig* config)
{
    int rc = 0;

    if ((ctx == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Callback table is required */
    if (config->cb == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->cb      = config->cb;
    ctx->context = config->context;

    /* Backend doesn't support this operation. OK to fail here if desired */
    if (config->cb->Init == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    /* Init the backend */
    rc = ctx->cb->Init(ctx->context, config->config);
    if (rc != WH_ERROR_OK) {
        /* Init failed, deinitialized context */
        ctx->cb      = NULL;
        ctx->context = NULL;
    }

    return rc;
}

int wh_Log_Cleanup(whLogContext* ctx)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Init hasn't been called yet */
    if (ctx->cb == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Cleanup == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Cleanup(ctx->context);
}

int wh_Log_AddEntry(whLogContext* ctx, const whLogEntry* entry)
{
    if ((ctx == NULL) || (entry == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Init hasn't been called yet */
    if (ctx->cb == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->AddEntry == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->AddEntry(ctx->context, entry);
}

int wh_Log_Export(whLogContext* ctx, void* export_arg)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Init hasn't been called yet */
    if (ctx->cb == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Export == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Export(ctx->context, export_arg);
}

int wh_Log_Iterate(whLogContext* ctx, whLogIterateCb iterate_cb,
                   void* iterate_arg)
{
    if ((ctx == NULL) || (iterate_cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Init hasn't been called yet */
    if (ctx->cb == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Iterate == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Iterate(ctx->context, iterate_cb, iterate_arg);
}

int wh_Log_Clear(whLogContext* ctx)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Init hasn't been called yet */
    if (ctx->cb == NULL) {
        return WH_ERROR_ABORTED;
    }

    /* Backend doesn't support this operation */
    if (ctx->cb->Clear == NULL) {
        return WH_ERROR_NOTIMPL;
    }

    return ctx->cb->Clear(ctx->context);
}

#endif /* WOLFHSM_CFG_LOGGING */
