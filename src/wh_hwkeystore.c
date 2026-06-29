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
 * src/wh_hwkeystore.c
 *
 * Hardware keystore front-end implementation. Dispatches to a backend callback
 * table (whHwKeystoreCb) with argument validation and lock serialization. See
 * wolfhsm/wh_hwkeystore.h for the module description.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_HWKEYSTORE

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_hwkeystore.h"

int wh_HwKeystore_Init(whHwKeystoreContext*      context,
                       const whHwKeystoreConfig* config)
{
    if ((context == NULL) || (config == NULL) || (config->cb == NULL) ||
        (config->cb->GetKey == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->cb      = config->cb;
    context->context = config->context;

    /* Initialize the lock before the backend so that, on a backend Init
     * failure, teardown is a simple lock cleanup with no backend state to
     * undo. This keeps init and cleanup symmetric: wh_HwKeystore_Cleanup tears
     * down the backend then the lock, the reverse of the order here */
#ifdef WOLFHSM_CFG_THREADSAFE
    {
        int rc = wh_Lock_Init(&context->lock, config->lockConfig);
        if (rc != WH_ERROR_OK) {
            memset(context, 0, sizeof(*context));
            return rc;
        }
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    /* Initialize the backend if it provides an Init callback. Done last so it
     * is the only fallible step after the lock: on failure, undo the lock so a
     * successful backend Init is never left without a paired Cleanup */
    if (context->cb->Init != NULL) {
        int rc = context->cb->Init(context->context, config->config);
        if (rc != WH_ERROR_OK) {
#ifdef WOLFHSM_CFG_THREADSAFE
            (void)wh_Lock_Cleanup(&context->lock);
#endif /* WOLFHSM_CFG_THREADSAFE */
            memset(context, 0, sizeof(*context));
            return rc;
        }
    }

    context->initialized = 1;
    return WH_ERROR_OK;
}

int wh_HwKeystore_Cleanup(whHwKeystoreContext* context)
{
    int rc = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Capture the backend teardown result but always finish releasing the lock
     * and zeroing the context, then surface the backend error. */
    if ((context->cb != NULL) && (context->cb->Cleanup != NULL)) {
        rc = context->cb->Cleanup(context->context);
    }

#ifdef WOLFHSM_CFG_THREADSAFE
    {
        /* Only let a lock-release failure surface when the backend cleanup
         * itself succeeded, so a real backend error is not hidden */
        int relRc = wh_Lock_Cleanup(&context->lock);
        if (rc == WH_ERROR_OK) {
            rc = relRc;
        }
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    memset(context, 0, sizeof(*context));
    return rc;
}

int wh_HwKeystore_GetKey(whHwKeystoreContext* context, whKeyId keyId,
                         uint8_t* out, uint16_t* inout_len)
{
    int rc;

    if ((context == NULL) || (context->initialized == 0) ||
        (context->cb == NULL) || (context->cb->GetKey == NULL) ||
        (out == NULL) || (inout_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_THREADSAFE
    rc = wh_Lock_Acquire(&context->lock);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    rc = context->cb->GetKey(context->context, keyId, out, inout_len);

#ifdef WOLFHSM_CFG_THREADSAFE
    {
        /* Preserve the backend result; only surface a release failure when the
         * GetKey call itself succeeded so a real lock error is not hidden */
        int relRc = wh_Lock_Release(&context->lock);
        if (rc == WH_ERROR_OK) {
            rc = relRc;
        }
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    return rc;
}

#endif /* WOLFHSM_CFG_HWKEYSTORE */
