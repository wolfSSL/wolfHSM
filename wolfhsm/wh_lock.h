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
 * wolfhsm/wh_lock.h
 *
 * Platform-agnostic lock abstraction for thread-safe access to shared
 * resources. This module provides a callback-based locking mechanism
 * that allows platform-specific implementations (pthreads, FreeRTOS,
 * bare-metal spinlocks, etc.) without introducing OS dependencies in the
 * core wolfHSM code.
 *
 * Each shared resource (NVM, crypto) embeds its own whLock instance,
 * allowing independent locking and arbitrary sharing topologies.
 *
 * When WOLFHSM_CFG_THREADSAFE is defined:
 * - Lock operations use platform callbacks for actual synchronization
 * - NULL lockConfig results in no-op locking (single-threaded mode)
 *
 * When WOLFHSM_CFG_THREADSAFE is not defined:
 * - All lock operations are no-ops with zero overhead
 */

#ifndef WOLFHSM_WH_LOCK_H_
#define WOLFHSM_WH_LOCK_H_


/**
 * Lock callback function signatures.
 *
 * All callbacks receive a user-provided context pointer (from whLockConfig).
 * Each lock instance protects exactly one resource.
 *
 * Return: WH_ERROR_OK on success, negative error code on failure
 */

/** Initialize a lock - called once during setup */
typedef int (*whLockInitCb)(void* context, const void* config);

/** Cleanup a lock - called once during teardown */
typedef int (*whLockCleanupCb)(void* context);

/** Acquire exclusive lock (blocking) */
typedef int (*whLockAcquireCb)(void* context);

/** Release exclusive lock */
typedef int (*whLockReleaseCb)(void* context);

/**
 * Lock callback table
 *
 * Platforms provide implementations of these callbacks. If the entire
 * callback table is NULL, all locking operations become no-ops
 * (single-threaded mode). Individual callbacks may also be NULL to
 * skip specific operations.
 */
typedef struct whLockCb_t {
    whLockInitCb    init;    /* Initialize lock resources */
    whLockCleanupCb cleanup; /* Free lock resources */
    whLockAcquireCb acquire; /* Acquire exclusive lock */
    whLockReleaseCb release; /* Release exclusive lock */
} whLockCb;

/**
 * Lock instance structure
 *
 * Holds callback table and platform-specific context.
 * The context pointer is passed to all callbacks.
 */
typedef struct whLock_t {
    const whLockCb* cb;      /* Platform callbacks (may be NULL) */
    void*           context; /* Platform context (e.g., mutex pointer) */
} whLock;

/**
 * Lock configuration for initialization
 */
typedef struct whLockConfig_t {
    const whLockCb* cb;      /* Callback table */
    void*           context; /* Platform context */
    const void*     config;  /* Backend-specific config (passed to init cb) */
} whLockConfig;

/**
 * @brief Initializes a lock instance.
 *
 * This function initializes the lock by calling the init callback.
 * If config is NULL or config->cb is NULL, locking is disabled
 * (single-threaded mode) and all lock operations become no-ops.
 *
 * @param[in] lock Pointer to the lock structure.
 * @param[in] config Pointer to the lock configuration (may be NULL).
 * @return int Returns WH_ERROR_OK on success, or a negative error code on
 *         failure.
 */
int wh_Lock_Init(whLock* lock, const whLockConfig* config);

/**
 * @brief Cleans up a lock instance.
 *
 * This function cleans up the lock by calling the cleanup callback.
 *
 * @param[in] lock Pointer to the lock structure.
 * @return int Returns WH_ERROR_OK on success, or WH_ERROR_BADARGS if lock
 *         is NULL.
 */
int wh_Lock_Cleanup(whLock* lock);

/**
 * @brief Acquires exclusive access to a lock.
 *
 * This function blocks until the lock is acquired. If no callbacks are
 * configured, this is a no-op that returns WH_ERROR_OK.
 *
 * @param[in] lock Pointer to the lock structure.
 * @return int Returns WH_ERROR_OK on success, or a negative error code on
 *         failure (e.g., WH_ERROR_LOCKED if acquisition failed).
 */
int wh_Lock_Acquire(whLock* lock);

/**
 * @brief Releases exclusive access to a lock.
 *
 * This function releases a previously acquired lock. If no callbacks are
 * configured, this is a no-op that returns WH_ERROR_OK.
 *
 * @param[in] lock Pointer to the lock structure.
 * @return int Returns WH_ERROR_OK on success, or a negative error code on
 *         failure.
 */
int wh_Lock_Release(whLock* lock);


#endif /* WOLFHSM_WH_LOCK_H_ */
