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
 * port/posix/posix_timeout.c
 *
 * POSIX implementation of the wolfHSM timeout abstraction.
 * Uses CLOCK_MONOTONIC for time measurement.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT

#include <stddef.h>
#include <time.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_timeout.h"

#include "port/posix/posix_timeout.h"

/* Use CLOCK_MONOTONIC for timeout measurement to avoid issues with wall-clock
 * adjustments (NTP, manual changes, etc.) that could cause spurious expirations
 * or overly long timeouts. */
static uint64_t _getMonotonicTimeUs(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000);
}

int posixTimeout_Init(void* context, const void* config)
{
    posixTimeoutContext*      ctx = (posixTimeoutContext*)context;
    const posixTimeoutConfig* cfg = (const posixTimeoutConfig*)config;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->startUs   = 0;
    ctx->timeoutUs = (cfg != NULL) ? cfg->timeoutUs : 0;
    ctx->running   = 0;

    ctx->initialized = 1;
    return WH_ERROR_OK;
}

int posixTimeout_Cleanup(void* context)
{
    posixTimeoutContext* ctx = (posixTimeoutContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ctx->startUs     = 0;
    ctx->timeoutUs   = 0;
    ctx->running     = 0;
    ctx->initialized = 0;

    return WH_ERROR_OK;
}

int posixTimeout_Set(void* context, uint64_t timeoutUs)
{
    posixTimeoutContext* ctx = (posixTimeoutContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    ctx->timeoutUs = timeoutUs;

    return WH_ERROR_OK;
}

int posixTimeout_Start(void* context)
{
    posixTimeoutContext* ctx = (posixTimeoutContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    ctx->startUs = _getMonotonicTimeUs();
    if (ctx->startUs == 0) {
        return WH_ERROR_ABORTED;
    }
    ctx->running = 1;

    return WH_ERROR_OK;
}

int posixTimeout_Stop(void* context)
{
    posixTimeoutContext* ctx = (posixTimeoutContext*)context;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    ctx->startUs = 0;
    ctx->running = 0;

    return WH_ERROR_OK;
}

int posixTimeout_Expired(void* context, int* expired)
{
    posixTimeoutContext* ctx = (posixTimeoutContext*)context;
    uint64_t             nowUs;

    if ((ctx == NULL) || (expired == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (!ctx->initialized) {
        return WH_ERROR_BADARGS;
    }

    /* Not started or no timeout configured = not expired */
    if (!ctx->running || (ctx->timeoutUs == 0)) {
        *expired = 0;
        return WH_ERROR_OK;
    }

    nowUs = _getMonotonicTimeUs();
    if (nowUs == 0) {
        return WH_ERROR_ABORTED;
    }
    *expired = ((nowUs - ctx->startUs) >= ctx->timeoutUs) ? 1 : 0;

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_TIMEOUT */
