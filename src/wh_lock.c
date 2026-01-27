/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * src/wh_lock.c
 *
 * Implementation of platform-agnostic lock abstraction for thread-safe
 * access to shared resources. Each lock instance protects exactly one
 * resource, allowing arbitrary sharing topologies.
 */

#include "wolfhsm/wh_settings.h"

#include <stddef.h> /* For NULL */
#include <string.h> /* For memset */

#include "wolfhsm/wh_lock.h"
#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_THREADSAFE

int wh_Lock_Init(whLock* lock, const whLockConfig* config)
{
    int ret = WH_ERROR_OK;

    if (lock == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Allow NULL config for single-threaded mode (no-op locking) */
    if ((config == NULL) || (config->cb == NULL)) {
        lock->cb      = NULL;
        lock->context = NULL;
        lock->initialized = 1; /* Mark as initialized even in no-op mode */
        return WH_ERROR_OK;
    }

    lock->cb      = config->cb;
    lock->context = config->context;

    /* Initialize the lock if callback provided */
    if (lock->cb->init != NULL) {
        ret = lock->cb->init(lock->context, config->config);
        if (ret != WH_ERROR_OK) {
            lock->cb      = NULL;
            lock->context = NULL;
            /* Do not set initialized on failure */
            return ret;
        }
    }

    lock->initialized = 1; /* Mark as initialized after successful init */
    return WH_ERROR_OK;
}

int wh_Lock_Cleanup(whLock* lock)
{
    if (lock == NULL) {
        return WH_ERROR_BADARGS;
    }

    if ((lock->cb != NULL) && (lock->cb->cleanup != NULL)) {
        (void)lock->cb->cleanup(lock->context);
    }

    /* Zero the entire structure to make post-cleanup state distinguishable */
    memset(lock, 0, sizeof(*lock));

    return WH_ERROR_OK;
}

int wh_Lock_Acquire(whLock* lock)
{
    /* Return error if lock is NULL */
    if (lock == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Return error if lock is not initialized */
    if (lock->initialized == 0) {
        return WH_ERROR_BADARGS;
    }

    /* No-op if not configured (no callbacks) */
    if ((lock->cb == NULL) || (lock->cb->acquire == NULL)) {
        return WH_ERROR_OK;
    }

    return lock->cb->acquire(lock->context);
}

int wh_Lock_Release(whLock* lock)
{
    /* Return error if lock is NULL */
    if (lock == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Return error if lock is not initialized */
    if (lock->initialized == 0) {
        return WH_ERROR_BADARGS;
    }

    /* No-op if not configured (no callbacks) */
    if ((lock->cb == NULL) || (lock->cb->release == NULL)) {
        return WH_ERROR_OK;
    }

    return lock->cb->release(lock->context);
}

#endif /* WOLFHSM_CFG_THREADSAFE */
