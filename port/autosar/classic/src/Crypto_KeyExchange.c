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
 * port/autosar/classic/src/Crypto_KeyExchange.c
 *
 * Crypto_KeyExchangeCalcPubVal / CalcSecret — ECDH (NIST curves) and
 * X25519. The curve choice comes from the Crypto_KeyDescriptorType for
 * the named cryptoKeyId.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#endif

Std_ReturnType Crypto_KeyExchangeCalcPubVal(uint32  cryptoKeyId,
                                            uint8*  publicValuePtr,
                                            uint32* publicValueLengthPtr)
{
    whClientContext*                ctx = wh_Autosar_KeystoreClient();
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    uint8   label[WH_NVM_LABEL_LEN] = {0};
    whKeyId whId                    = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    int     rc                      = WH_ERROR_NOTIMPL;
    uint16  outLen;

    if (ctx == NULL || desc == NULL || publicValuePtr == NULL ||
        publicValueLengthPtr == NULL) {
        return E_NOT_OK;
    }
    if (*publicValueLengthPtr == 0u) {
        return E_NOT_OK;
    }

    outLen = (*publicValueLengthPtr > 0xFFFFu)
                 ? 0xFFFFu
                 : (uint16)(*publicValueLengthPtr);

#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)label;
    (void)whId;
#else
    switch (desc->family) {
#ifdef HAVE_ECC
        case CRYPTO_ALGOFAM_ECCNIST:
            rc = wh_Client_EccMakeCacheKey(ctx, (int)(desc->keyLength / 8u),
                                           desc->eccCurveId, &whId,
                                           (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY,
                                           (uint16)sizeof(label), label);
            if (rc == WH_ERROR_OK) {
                rc = wh_Client_KeyExportPublic(ctx, whId, WH_KEY_ALGO_ECC,
                                               label, (uint16)sizeof(label),
                                               publicValuePtr, &outLen);
            }
            break;
#endif
#ifdef HAVE_CURVE25519
        case CRYPTO_ALGOFAM_X25519:
            rc = wh_Client_Curve25519MakeCacheKey(
                ctx, (uint16)(desc->keyLength / 8u), &whId,
                (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY, label,
                (uint16)sizeof(label));
            if (rc == WH_ERROR_OK) {
                rc = wh_Client_KeyExportPublic(
                    ctx, whId, WH_KEY_ALGO_CURVE25519, label,
                    (uint16)sizeof(label), publicValuePtr, &outLen);
            }
            break;
#endif
        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
#endif

    if (rc == WH_ERROR_OK) {
        *publicValueLengthPtr = outLen;
        return E_OK;
    }
    return E_NOT_OK;
}

Std_ReturnType Crypto_KeyExchangeCalcSecret(uint32       cryptoKeyId,
                                            const uint8* partnerPublicValuePtr,
                                            uint32 partnerPublicValueLength)
{
    whClientContext*                ctx = wh_Autosar_KeystoreClient();
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    uint8  secret[64];
    uint16 secretLen               = (uint16)sizeof(secret);
    int    rc                      = WH_ERROR_NOTIMPL;
    uint16 peerId                  = 0u;
    uint8  label[WH_NVM_LABEL_LEN] = {0};

    if (ctx == NULL || desc == NULL || partnerPublicValuePtr == NULL ||
        partnerPublicValueLength == 0u) {
        return E_NOT_OK;
    }

#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)secret;
    (void)secretLen;
    (void)peerId;
    (void)label;
#else
    {
        whKeyId privId = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);

        rc = wh_Client_KeyCache(ctx, (uint32)WH_NVM_FLAGS_USAGE_ANY, label,
                                (uint16)sizeof(label), partnerPublicValuePtr,
                                (uint16)partnerPublicValueLength, &peerId);
        if (rc != WH_ERROR_OK) {
            return E_NOT_OK;
        }
        if (desc->family == CRYPTO_ALGOFAM_ECCNIST) {
            rc = wh_Client_EccSharedSecretRequest(ctx, privId, peerId);
            if (rc == WH_ERROR_OK) {
                int rsp;
                do {
                    rsp = wh_Client_EccSharedSecretResponse(ctx, secret,
                                                            &secretLen);
                } while (rsp == WH_ERROR_NOTREADY);
                rc = rsp;
            }
        }
        else {
            rc = WH_ERROR_NOTIMPL;
        }
        /* Always best-effort evict the peer key so a failed shared
         * secret doesn't leak it. */
        (void)wh_Client_KeyEvict(ctx, peerId);
    }
#endif

    if (rc != WH_ERROR_OK) {
        (void)memset(secret, 0, sizeof(secret));
        return E_NOT_OK;
    }
    /* Store the secret as element id 1 of the named key, per SWS. */
    {
        Std_ReturnType ret =
            Crypto_KeyElementSet(cryptoKeyId, 1u, secret, secretLen);
        /* Zeroize the raw DH secret on our stack regardless of outcome:
         * the bytes were just shipped to the wolfHSM keystore (or the
         * Set failed), and the caller never sees this buffer. Leaving
         * it readable in a future call's stack frame is CWE-244. */
        (void)memset(secret, 0, sizeof(secret));
        return ret;
    }
}
