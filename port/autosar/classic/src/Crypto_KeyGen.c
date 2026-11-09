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
 * Crypto_KeyGenerate, dispatched by the target key's descriptor.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_utils.h"

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

Std_ReturnType wh_Autosar_KeyGenerateImpl(whClientContext* ctx,
                                          uint32           cryptoKeyId)
{
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    whKeyId    outId = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    uint8      label[WH_NVM_LABEL_LEN] = {0};
    int        rc                      = WH_ERROR_NOTIMPL;
    whNvmFlags flags;

    if (desc == NULL || outId == 0u) {
        return E_NOT_OK;
    }
    if (wh_Autosar_KeyMarkWritten(cryptoKeyId) != E_OK) {
        return CRYPTO_E_KEY_WRITE_FAIL;
    }
    flags = wh_Autosar_KeyFlags(cryptoKeyId);

#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)ctx;
    (void)label;
    (void)flags;
#else
    switch (desc->family) {
#ifdef HAVE_ECC
        case CRYPTO_ALGOFAM_ECCNIST:
        case CRYPTO_ALGOFAM_ECDH:
            rc = wh_Client_EccMakeCacheKey(ctx, (int)(desc->keyLength / 8u),
                                           desc->eccCurveId, &outId, flags,
                                           (uint16)sizeof(label), label);
            break;
#endif
#ifdef HAVE_ED25519
        case CRYPTO_ALGOFAM_ED25519:
            rc = wh_Client_Ed25519MakeCacheKey(ctx, &outId, flags,
                                               (uint16)sizeof(label), label);
            break;
#endif
#ifdef HAVE_CURVE25519
        case CRYPTO_ALGOFAM_X25519:
            rc = wh_Client_Curve25519MakeCacheKey(
                ctx, (uint16)(desc->keyLength / 8u), &outId, flags, label,
                (uint16)sizeof(label));
            break;
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)
        case CRYPTO_ALGOFAM_RSA:
            rc = wh_Client_RsaMakeCacheKey(ctx, desc->keyLength, 65537u, &outId,
                                           flags, (uint32)sizeof(label), label);
            break;
#endif
#ifdef WOLFSSL_HAVE_MLDSA
        case WH_AUTOSAR_ALGOFAM_MLDSA:
            rc = wh_Client_MlDsaMakeCacheKey(ctx, 0, desc->mlDsaLevel, &outId,
                                             flags, (uint16)sizeof(label),
                                             label);
            break;
#endif
        case CRYPTO_ALGOFAM_AES:
            if (desc->keyLength == 0u || desc->keyLength > 512u) {
                return E_NOT_OK;
            }
            rc = wh_Client_KeyCacheRandom(
                ctx, (uint32)flags, label, (uint16)sizeof(label),
                (uint16)(desc->keyLength / 8u), &outId);
            break;
        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
#endif
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}

Std_ReturnType Crypto_KeyGenerate(uint32 cryptoKeyId)
{
    whClientContext* ctx = NULL;
    Std_ReturnType   ret = wh_Autosar_KeystoreBegin(&ctx);

    if (ret != E_OK) {
        return ret;
    }
    ret = wh_Autosar_KeyGenerateImpl(ctx, cryptoKeyId);
    wh_Autosar_KeystoreEnd(ctx);
    return ret;
}
