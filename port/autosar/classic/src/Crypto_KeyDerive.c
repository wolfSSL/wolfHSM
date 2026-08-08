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
 * port/autosar/classic/src/Crypto_KeyDerive.c
 *
 * Crypto_KeyDerive — HKDF / CMAC-KDF dispatch driven by the target Crypto
 * Key's descriptor (hashType for HKDF, family for which KDF variant).
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"

Std_ReturnType Crypto_KeyDerive(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    whClientContext*                ctx = wh_Autosar_KeystoreClient();
    const Crypto_KeyDescriptorType* tgt =
        wh_Autosar_LookupKeyDescriptor(targetCryptoKeyId);
    whKeyId srcId = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    whKeyId dstId = wh_Autosar_ComposeKeyId(targetCryptoKeyId, 1u);
    uint8   label[WH_NVM_LABEL_LEN] = {0};
    int     rc                      = WH_ERROR_NOTIMPL;

    if (ctx == NULL || tgt == NULL) {
        return E_NOT_OK;
    }

#ifndef WOLFHSM_CFG_NO_CRYPTO
    switch (tgt->family) {
#ifdef HAVE_HKDF
        case CRYPTO_ALGOFAM_HKDF:
            rc = wh_Client_HkdfMakeCacheKey(
                ctx, tgt->hashType, srcId, NULL, 0u, NULL, 0u, NULL, 0u, &dstId,
                0u, label, (uint32)sizeof(label), tgt->keyLength / 8u);
            break;
#endif
#ifdef HAVE_CMAC_KDF
        case CRYPTO_ALGOFAM_CMAC_KDF:
            rc = wh_Client_CmacKdfMakeCacheKey(
                ctx, srcId, NULL, 0u, srcId, NULL, 0u, NULL, 0u, &dstId, 0u,
                label, (uint32)sizeof(label), tgt->keyLength / 8u);
            break;
#endif
        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
#else
    (void)srcId;
    (void)dstId;
    (void)label;
#endif
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}
