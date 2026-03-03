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
 * wolfhsm/wh_timeout.h
 *
 * Platform-agnostic timeout abstraction using a callback-based mechanism
 * that allows platform-specific implementations (POSIX, RTOS, bare-metal,
 * etc.) without introducing OS dependencies in the core wolfHSM code.
 *
 * When WOLFHSM_CFG_ENABLE_TIMEOUT is defined:
 * - Timeout operations use platform callbacks for actual time measurement
 * - NULL config results in no-op timeout (never expires)
 *
 * When WOLFHSM_CFG_ENABLE_TIMEOUT is not defined:
 * - No timeout types or functions are available
 */

#ifndef WOLFHSM_WH_TIMEOUT_H_
#define WOLFHSM_WH_TIMEOUT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

/* Time conversion macros */
#define WH_MSEC_TO_USEC(ms) ((ms) * (1000ULL))
#define WH_SEC_TO_USEC(sec) ((sec) * (1000000ULL))
#define WH_MIN_TO_USEC(min) ((min) * (WH_SEC_TO_USEC(60)))


/**
 * Platform callback function signatures.
 *
 * All callbacks receive a user-provided context pointer (from whTimeoutConfig).
 * Return: WH_ERROR_OK on success, negative error code on failure.
 */

/** Initialize timeout resources - called once during setup */
typedef int (*whTimeoutInitCb)(void* context, const void* config);

/** Cleanup timeout resources - called once during teardown */
typedef int (*whTimeoutCleanupCb)(void* context);

/** Set the timeout duration in microseconds */
typedef int (*whTimeoutSetCb)(void* context, uint64_t timeoutUs);

/** Start or restart the timeout timer */
typedef int (*whTimeoutStartCb)(void* context);

/** Stop the timeout timer */
typedef int (*whTimeoutStopCb)(void* context);

/**
 * Check whether the timeout has expired.
 * Writes 1 to *expired if elapsed, 0 if not.
 * Return: WH_ERROR_OK on success, negative error code on failure.
 */
typedef int (*whTimeoutCheckExpiredCb)(void* context, int* expired);

/**
 * Timeout callback table.
 *
 * Platforms provide implementations of these callbacks. If the entire
 * callback table is NULL, all timeout operations become no-ops
 * (disabled mode). Individual callbacks may also be NULL to skip
 * specific operations.
 */
typedef struct whTimeoutCb_t {
    whTimeoutInitCb         init;    /* Initialize timeout resources */
    whTimeoutCleanupCb      cleanup; /* Free timeout resources */
    whTimeoutSetCb          set;     /* Set timeout duration */
    whTimeoutStartCb        start;   /* Start/restart timer */
    whTimeoutStopCb         stop;    /* Stop timer */
    whTimeoutCheckExpiredCb expired; /* Check if timer expired */
} whTimeoutCb;


/* Forward declare so the application callback typedef can reference it */
typedef struct whTimeout_t whTimeout;

/**
 * Application-level callback invoked when a timeout expires. The callback may
 * override the expiration by setting *isExpired to 0 (e.g. to extend the
 * timeout by calling wh_Timeout_Start() to restart the timer). Returning a
 * non-zero error code from the callback will cause wh_Timeout_Expired() to
 * propagate that error to its caller.
 *
 * @param timeout The timeout instance that expired.
 * @param isExpired Pointer to the expired flag; set to 0 to suppress
 *                  expiration.
 * @return 0 on success, or a negative error code to signal failure.
 */
typedef int (*whTimeoutExpiredCb)(whTimeout* timeout, int* isExpired);

/**
 * Timeout instance structure.
 *
 * Holds callback table, platform-specific context, and an optional
 * application-level expired callback. The context pointer is passed to all
 * platform callbacks.
 */
struct whTimeout_t {
    const whTimeoutCb* cb;         /* Platform callbacks (may be NULL) */
    void*              context;    /* Platform context */
    whTimeoutExpiredCb expiredCb;  /* Application expired callback */
    void*              expiredCtx; /* Application callback context */
    int                initialized;
    uint8_t            WH_PAD[4];
};

/**
 * Timeout configuration for initialization.
 */
typedef struct whTimeoutConfig_t {
    const whTimeoutCb* cb;         /* Callback table */
    void*              context;    /* Platform context */
    const void*        config;     /* Backend-specific config */
    whTimeoutExpiredCb expiredCb;  /* Application expired callback */
    void*              expiredCtx; /* Application callback context */
} whTimeoutConfig;


/**
 * @brief Initializes a timeout instance.
 *
 * If config is NULL or config->cb is NULL, the timeout is disabled
 * (no-op mode) and all operations become no-ops with Expired() always
 * returning 0.
 *
 * @param[in] timeout Pointer to the timeout structure. Must not be NULL.
 * @param[in] config Pointer to the timeout configuration (may be NULL for
 *                   no-op mode).
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if timeout is NULL,
 *         or negative error code on callback failure.
 */
int wh_Timeout_Init(whTimeout* timeout, const whTimeoutConfig* config);

/**
 * @brief Cleans up a timeout instance.
 *
 * Calls the cleanup callback and then zeros the entire structure.
 * Idempotent - calling cleanup on an already cleaned up or uninitialized
 * timeout returns WH_ERROR_OK.
 *
 * @param[in] timeout Pointer to the timeout structure.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if timeout is NULL.
 */
int wh_Timeout_Cleanup(whTimeout* timeout);

/**
 * @brief Set the timeout duration.
 *
 * @param[in] timeout The timeout instance.
 * @param[in] timeoutUs Timeout duration in microseconds; 0 disables.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Set(whTimeout* timeout, uint64_t timeoutUs);

/**
 * @brief Start or reset a timeout window.
 *
 * @param[in] timeout The timeout instance.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Start(whTimeout* timeout);

/**
 * @brief Stop a timeout and clear its timer state.
 *
 * @param[in] timeout The timeout instance.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Stop(whTimeout* timeout);

/**
 * @brief Check whether a timeout has expired.
 *
 * Delegates to the platform callback to check expiration. If expired and
 * an application expired callback is configured, the callback is invoked
 * before returning. The callback may set *isExpired to 0 to override
 * (suppress) the expiration.
 *
 * @param[in] timeout The timeout instance.
 * @return 1 if expired, 0 if not expired or disabled, or negative error code.
 */
int wh_Timeout_Expired(whTimeout* timeout);

#endif /* !WOLFHSM_WH_TIMEOUT_H_ */
