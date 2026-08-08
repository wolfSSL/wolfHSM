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

/* --- Key id composition --------------------------------------------- */

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
