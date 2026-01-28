/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include "wolfhsm/wh_timeout.h"
#include "wolfhsm/wh_error.h"

int wh_Timeout_Init(whTimeoutCtx* timeout, const whTimeoutConfig* config)
{
    if ((timeout == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    timeout->startUs = 0;
    timeout->timeoutUs = config->timeoutUs;
    timeout->expiredCb = config->expiredCb;
    timeout->cbCtx = config->cbCtx;

    return WH_ERROR_OK;
}

int wh_Timeout_Set(whTimeoutCtx* timeout, uint64_t timeoutUs)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    timeout->timeoutUs = timeoutUs;

    return WH_ERROR_OK;
}

int wh_Timeout_Start(whTimeoutCtx* timeout)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    timeout->startUs = WH_GETTIME_US();

    return WH_ERROR_OK;
}

int wh_Timeout_Stop(whTimeoutCtx* timeout)
{
    if (timeout == NULL) {
        return WH_ERROR_BADARGS;
    }

    timeout->startUs = 0;
    timeout->timeoutUs = 0;

    return WH_ERROR_OK;
}

int wh_Timeout_Expired(const whTimeoutCtx* timeout)
{
    uint64_t nowUs = 0;
    int expired = 0;

    if (timeout == NULL) {
        return 0;
    }

    if (timeout->timeoutUs == 0) {
        return 0;
    }

    nowUs = WH_GETTIME_US();
    expired = (nowUs - timeout->startUs) >= timeout->timeoutUs;
    if (expired && (timeout->expiredCb != NULL)) {
        timeout->expiredCb(timeout->cbCtx);
    }
    return expired;
}
