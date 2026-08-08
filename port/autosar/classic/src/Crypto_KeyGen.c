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
 * port/autosar/classic/src/Crypto_KeyGen.c
 *
 * Crypto_KeyGenerate dispatches by the algorithm metadata in the
 * Crypto_KeyDescriptorType for the target Crypto Key. The descriptor
 * table is supplied by the integrator via Crypto_PBcfg (generator
 * output in a real BSW project).
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/ecc.h"
#endif

const Crypto_KeyDescriptorType*
wh_Autosar_LookupKeyDescriptor(uint32 cryptoKeyId)
{
    uint32 i;
    if (Crypto_KeyDescriptorTable == NULL) {
        return NULL;
    }
    for (i = 0u; i < Crypto_KeyDescriptorCount; ++i) {
        if (Crypto_KeyDescriptorTable[i].cryptoKeyId == cryptoKeyId) {
            return &Crypto_KeyDescriptorTable[i];
        }
    }
    return NULL;
}

Std_ReturnType Crypto_KeyGenerate(uint32 cryptoKeyId)
{
    whClientContext*                ctx = wh_Autosar_KeystoreClient();
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    /* Material element id is 1 per AUTOSAR. */
    whKeyId outId                   = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    uint8   label[WH_NVM_LABEL_LEN] = {0};
    int     rc                      = WH_ERROR_NOTIMPL;

    if (ctx == NULL || desc == NULL) {
        return E_NOT_OK;
    }

#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)outId;
    (void)label;
#else
    switch (desc->family) {
#ifdef HAVE_ECC
        case CRYPTO_ALGOFAM_ECCNIST:
            rc = wh_Client_EccMakeCacheKey(ctx, (int)(desc->keyLength / 8u),
                                           desc->eccCurveId, &outId,
                                           (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY,
                                           (uint16)sizeof(label), label);
            break;
#endif
#ifdef HAVE_ED25519
        case CRYPTO_ALGOFAM_ED25519:
            rc = wh_Client_Ed25519MakeCacheKey(
                ctx, &outId, (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY,
                (uint16)sizeof(label), label);
            break;
#endif
#ifdef HAVE_CURVE25519
        case CRYPTO_ALGOFAM_X25519:
            rc = wh_Client_Curve25519MakeCacheKey(
                ctx, (uint16)(desc->keyLength / 8u), &outId,
                (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY, label,
                (uint16)sizeof(label));
            break;
#endif
#ifndef NO_RSA
        case CRYPTO_ALGOFAM_RSA:
            rc = wh_Client_RsaMakeCacheKey(ctx, desc->keyLength, 65537u, &outId,
                                           (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY,
                                           (uint32)sizeof(label), label);
            break;
#endif
        case CRYPTO_ALGOFAM_AES: {
            uint8  mat[64];
            uint32 keyBytes = desc->keyLength / 8u;
            if (keyBytes == 0u || keyBytes > sizeof(mat)) {
                return E_NOT_OK;
            }
            rc = wh_Client_RngGenerate(ctx, mat, keyBytes);
            if (rc == WH_ERROR_OK) {
                rc = wh_Client_KeyCache(ctx, (uint32)WH_NVM_FLAGS_USAGE_ANY,
                                        label, (uint16)sizeof(label), mat,
                                        (uint16)keyBytes, &outId);
            }
            break;
        }
        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
#endif
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}
