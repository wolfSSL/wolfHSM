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
 * port/posix/posix_lock.c
 *
 * POSIX pthread_mutex-based implementation of the wolfHSM lock abstraction.
 * Each lock context contains a single mutex for one shared resource.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_THREADSAFE

#include <pthread.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_lock.h"

#include "port/posix/posix_lock.h"

int posixLock_Init(void* context, const void* config)
{
    posixLockContext*          ctx  = (posixLockContext*)context;
    const posixLockConfig*     cfg  = (const posixLockConfig*)config;
    const pthread_mutexattr_t* attr = NULL;
    int                        rc;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Already initialized? */
    if (ctx->initialized) {
        return WH_ERROR_OK;
    }

    /* Use attributes from config if provided */
    if (cfg != NULL) {
        attr = cfg->attr;
    }

    rc = pthread_mutex_init(&ctx->mutex, attr);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    ctx->initialized = 1;
    return WH_ERROR_OK;
}

int posixLock_Cleanup(void* context)
{
    posixLockContext* ctx = (posixLockContext*)context;
    int               rc;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Not initialized? */
    if (!ctx->initialized) {
        return WH_ERROR_OK;
    }

    rc = pthread_mutex_destroy(&ctx->mutex);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    ctx->initialized = 0;
    return WH_ERROR_OK;
}

int posixLock_Acquire(void* context)
{
    posixLockContext* ctx = (posixLockContext*)context;
    int               rc;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Not initialized? */
    if (!ctx->initialized) {
        return WH_ERROR_NOTREADY;
    }

    rc = pthread_mutex_lock(&ctx->mutex);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

int posixLock_Release(void* context)
{
    posixLockContext* ctx = (posixLockContext*)context;
    int               rc;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Not initialized? */
    if (!ctx->initialized) {
        return WH_ERROR_NOTREADY;
    }

    rc = pthread_mutex_unlock(&ctx->mutex);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_THREADSAFE */
