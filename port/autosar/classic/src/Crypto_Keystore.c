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
 * Keystore client lookup and (cryptoKeyId, keyElementId) → whKeyId
 * mapping.
 *
 * AUTOSAR Crypto Keys are global to the driver (per SWS — keys live in
 * the driver, not in a Crypto Driver Object), so callers reach them
 * through a dedicated entry point rather than driver-object 0
 * directly. The default implementation aliases driver object 0's
 * client, which suits single-transport deployments. Integrators with
 * multi-client transports override wh_Autosar_KeystoreInit / Cleanup /
 * Client with strong definitions.
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

Std_ReturnType wh_Autosar_KeystoreBegin(whClientContext** outCtx)
{
    whClientContext*        ctx = wh_Autosar_KeystoreClient();
    wh_AutosarDriverObject* obj;

    if (ctx == NULL) {
        return E_NOT_OK;
    }
    obj = clientOwner(ctx);
    if (obj != NULL && wh_Autosar_WireAcquire(obj) != E_OK) {
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

/* (cryptoKeyId, keyElementId) → 16-bit whKeyId.
 *
 * Packing:
 *   bits 15..10   reserved zero (server-side flags only)
 *   bit  9        WH_KEYID_CLIENT_WRAPPED_FLAG  (must stay 0 here)
 *   bit  8        WH_KEYID_CLIENT_GLOBAL_FLAG   (must stay 0 here)
 *   bits  7..0    cryptoKeyId (8 bits, supports 256 distinct keys)
 *
 * Only keyElementId == 1 (CRYPTO_KE_MATERIAL) gets a wolfHSM keystore
 * slot. The wire format reserves bits 8 and 9 for client-to-server
 * GLOBAL/WRAPPED flags (see wolfhsm/wh_keyid.h) and the server masks
 * everything else with WH_KEYID_MASK (0x00FF), so the previous scheme
 * that packed keyElementId into bits 11..8 silently re-routed every
 * material-key request to the global namespace under
 * WOLFHSM_CFG_GLOBAL_KEYS and discarded bits 10..11 entirely.
 *
 * Non-material elements (ALGORITHM / KEYSIZE / IV / ...) are AUTOSAR
 * metadata that ride on the CSM/CryIf side, not as separate wolfHSM
 * cache slots: the key material is the only thing the HSM holds.
 * cryptoKeyId > 255, keyElementId != 1, or cryptoKeyId == 0 return 0
 * (an invalid id which every wh_Client_* call rejects).
 *
 * Integrators needing more than 256 keys, or independent storage of
 * non-material elements, provide a strong override of this function
 * that consults a richer mapping (typically a generator-emitted lookup
 * table indexed by (cryptoKeyId, keyElementId)).
 */
WH_AUTOSAR_WEAK whKeyId wh_Autosar_ComposeKeyId(uint32 cryptoKeyId,
                                                uint32 keyElementId)
{
    if (cryptoKeyId == 0u || cryptoKeyId > 0xFFu || keyElementId != 1u) {
        return (whKeyId)0u;
    }
    return (whKeyId)WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, /*user*/ 0u,
                                  (uint16)(cryptoKeyId & 0xFFu));
}
