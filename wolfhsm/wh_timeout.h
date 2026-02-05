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
 * Generic timeout helpers based on WH_GETTIME_US().
 */

#ifndef WOLFHSM_WH_TIMEOUT_H_
#define WOLFHSM_WH_TIMEOUT_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#define WH_MSEC_TO_USEC(usec) (usec * 1000ULL)
#define WH_SEC_TO_USEC(sec) (sec * 1000000ULL)
#define WH_MIN_TO_USEC(min) (min * WH_SEC_TO_USEC(60))

#include <stdint.h>

typedef void (*whTimeoutExpiredCb)(void* ctx);

typedef struct {
    uint64_t           startUs;
    uint64_t           timeoutUs;
    whTimeoutExpiredCb expiredCb;
    void*              cbCtx;
} whTimeoutCtx;

typedef struct {
    uint64_t           timeoutUs;
    whTimeoutExpiredCb expiredCb;
    void*              cbCtx;
} whTimeoutConfig;

/**
 * Initialize a timeout context from a configuration.
 *
 * @param timeout The timeout context to initialize.
 * @param config The timeout configuration to apply.
 * @return 0 on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Init(whTimeoutCtx* timeout, const whTimeoutConfig* config);

/**
 * Configure a timeout value.
 *
 * @param timeout The timeout context to update.
 * @param timeoutUs Timeout duration in microseconds; 0 disables the timeout.
 * @return 0 on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Set(whTimeoutCtx* timeout, uint64_t timeoutUs);

/**
 * Start or reset a timeout window using the configured timeoutUs.
 *
 * @param timeout The timeout context to start.
 * @return 0 on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Start(whTimeoutCtx* timeout);

/**
 * Disable a timeout and clear its bookkeeping.
 *
 * @param timeout The timeout context to stop.
 * @return 0 on success, WH_ERROR_BADARGS on invalid input.
 */
int wh_Timeout_Stop(whTimeoutCtx* timeout);

/**
 * Check whether a timeout has expired.
 *
 * If the timeout is expired and an expired callback is configured, the
 * callback is invoked before returning.
 *
 * @param timeout The timeout context to check.
 * @return 1 if expired, 0 if not expired or disabled.
 */
int wh_Timeout_Expired(const whTimeoutCtx* timeout);

#endif /* !WOLFHSM_WH_TIMEOUT_H_ */
