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
 * port/autosar/classic/src/Crypto_Keystore.c
 *
 * Keystore client and Crypto Key to wolfHSM key id mapping. The defaults
 * use driver object 0's client and are weak so integrators can replace them.
 */

#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"

WH_AUTOSAR_WEAK int wh_Autosar_KeystoreInit(void)
{
    return WH_ERROR_OK;
}

WH_AUTOSAR_WEAK int wh_Autosar_KeystoreCleanup(void)
{
    return WH_ERROR_OK;
}

WH_AUTOSAR_WEAK whClientContext* wh_Autosar_KeystoreClient(void)
{
    wh_AutosarDriverObject* obj = wh_Autosar_GetDriverObject(0u);
    if (obj == NULL || !obj->initialised) {
        return NULL;
    }
    return &obj->client;
}

static wh_AutosarDriverObject* clientOwner(const whClientContext* ctx)
{
    uint32 i;
    for (i = 0u; i < CRYPTO_DRIVER_OBJECT_COUNT; ++i) {
        wh_AutosarDriverObject* obj = wh_Autosar_GetDriverObject(i);
        if (obj != NULL && &obj->client == ctx) {
            return obj;
        }
    }
    return NULL;
}

/* Serialises the keystore client when it belongs to no driver object. */
static boolean s_keystoreBusy = FALSE;

Std_ReturnType wh_Autosar_KeystoreBegin(whClientContext** outCtx)
{
    whClientContext*        ctx = wh_Autosar_KeystoreClient();
    wh_AutosarDriverObject* obj;
    Std_ReturnType          ret = E_OK;

    if (ctx == NULL) {
        return E_NOT_OK;
    }
    obj = clientOwner(ctx);
    if (obj != NULL) {
        ret = wh_Autosar_WireAcquire(obj);
    }
    else {
        wh_Autosar_LockKeys();
        if (s_keystoreBusy) {
            ret = CRYPTO_E_BUSY;
        }
        else {
            s_keystoreBusy = TRUE;
        }
        wh_Autosar_UnlockKeys();
    }
    if (ret != E_OK) {
        return CRYPTO_E_BUSY;
    }
    *outCtx = ctx;
    return E_OK;
}

void wh_Autosar_KeystoreEnd(whClientContext* ctx)
{
    wh_AutosarDriverObject* obj = clientOwner(ctx);
    if (obj != NULL) {
        wh_Autosar_WireRelease(obj);
    }
    else {
        wh_Autosar_LockKeys();
        s_keystoreBusy = FALSE;
        wh_Autosar_UnlockKeys();
    }
}

/* Several driver objects use different clients, so their keys must live in
 * the server's global namespace to be shared. */
#if CRYPTO_DRIVER_OBJECT_COUNT > 1
#ifndef WOLFHSM_CFG_GLOBAL_KEYS
#error "CRYPTO_DRIVER_OBJECT_COUNT > 1 needs WOLFHSM_CFG_GLOBAL_KEYS"
#endif
#define WH_AUTOSAR_KEYID_FLAGS WH_KEYID_CLIENT_GLOBAL_FLAG
#else
#define WH_AUTOSAR_KEYID_FLAGS 0u
#endif

WH_AUTOSAR_WEAK whKeyId wh_Autosar_ComposeKeyId(uint32 cryptoKeyId,
                                                uint32 keyElementId)
{
    if (cryptoKeyId == 0u || cryptoKeyId > 0xFFu || keyElementId != 1u) {
        return (whKeyId)0u;
    }
    return (whKeyId)((cryptoKeyId & WH_KEYID_MASK) | WH_AUTOSAR_KEYID_FLAGS);
}
