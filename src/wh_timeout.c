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
 * src/wh_timeout.c
 *
 * Platform-agnostic timeout abstraction. Each wrapper validates arguments,
 * checks initialization state, and delegates to platform callbacks.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_TIMEOUT

#include <stddef.h> /* For NULL */
#include <string.h> /* For memset */

#include "wolfhsm/wh_timeout.h"
#include "wolfhsm/wh_error.h"

int wh_Timeout_Init(whTimeout* timeout, const whTimeoutConfig* config)
{
    int ret = WH_ERROR_OK;

    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Allow NULL config for disabled mode (no-op timeout) */
    if ((config == NULL) || (config->cb == NULL)) {
        timeout->cb          = NULL;
        timeout->context     = NULL;
        timeout->expiredCb   = NULL;
        timeout->expiredCtx  = NULL;
        timeout->initialized = 1; /* Mark as initialized even in no-op mode */
        return WH_ERROR_OK;
    }

    timeout->cb         = config->cb;
    timeout->context    = config->context;
    timeout->expiredCb  = config->expiredCb;
    timeout->expiredCtx = config->expiredCtx;

    /* Initialize the platform timeout if callback provided */
    if (timeout->cb->init != NULL) {
        ret = timeout->cb->init(timeout->context, config->config);
        if (ret != WH_ERROR_OK) {
            timeout->cb      = NULL;
            timeout->context = NULL;
            /* Do not set initialized on failure */
            return ret;
        }
    }

    timeout->initialized = 1;
    return WH_ERROR_OK;
}

int wh_Timeout_Cleanup(whTimeout* timeout)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    if ((timeout->cb != NULL) && (timeout->cb->cleanup != NULL)) {
        (void)timeout->cb->cleanup(timeout->context);
    }

    /* Zero the entire structure to make post-cleanup state distinguishable */
    memset(timeout, 0, sizeof(*timeout));

    return WH_ERROR_OK;
}

int wh_Timeout_Set(whTimeout* timeout, uint64_t timeoutUs)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (timeout->initialized == 0) {
        return WH_ERROR_BADARGS;
    }

    /* No-op if not configured (no callbacks) */
    if ((timeout->cb == NULL) || (timeout->cb->set == NULL)) {
        return WH_ERROR_OK;
    }

    return timeout->cb->set(timeout->context, timeoutUs);
}

int wh_Timeout_Start(whTimeout* timeout)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (timeout->initialized == 0) {
        return WH_ERROR_BADARGS;
    }

    /* No-op if not configured (no callbacks) */
    if ((timeout->cb == NULL) || (timeout->cb->start == NULL)) {
        return WH_ERROR_OK;
    }

    return timeout->cb->start(timeout->context);
}

int wh_Timeout_Stop(whTimeout* timeout)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (timeout->initialized == 0) {
        return WH_ERROR_BADARGS;
    }

    /* No-op if not configured (no callbacks) */
    if ((timeout->cb == NULL) || (timeout->cb->stop == NULL)) {
        return WH_ERROR_OK;
    }

    return timeout->cb->stop(timeout->context);
}

int wh_Timeout_Expired(whTimeout* timeout)
{
    int expired = 0;
    int ret     = 0;

    if (timeout == NULL) {
        return 0;
    }

    /* Not initialized or no callbacks = never expired */
    if ((timeout->initialized == 0) || (timeout->cb == NULL) ||
        (timeout->cb->expired == NULL)) {
        return 0;
    }

    ret = timeout->cb->expired(timeout->context, &expired);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* If expired and application callback is set, invoke it */
    if (expired && (timeout->expiredCb != NULL)) {
        /* Allow the callback to overwrite the expired value. If the callback
         * returns an error, propagate it to the caller. */
        ret = timeout->expiredCb(timeout, &expired);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    return expired;
}

#endif /* WOLFHSM_CFG_ENABLE_TIMEOUT */
