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
 * Crypto_KeyExchange*: ECDH and X25519. Public values are raw X || Y for
 * ECDH and the RFC 7748 little-endian u-coordinate for X25519.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_utils.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#endif

#ifndef CRYPTO_PUBKEY_DER_BUF_SIZE
#define CRYPTO_PUBKEY_DER_BUF_SIZE 160u
#endif

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(HAVE_ECC)
static int eccPubValue(whClientContext* ctx, whKeyId id, int curveId,
                       uint8* out, uint32* outLen)
{
    uint8   der[CRYPTO_PUBKEY_DER_BUF_SIZE];
    uint16  derLen = (uint16)sizeof(der);
    uint8   label[WH_NVM_LABEL_LEN];
    word32  idx = 0u;
    word32  xLen;
    word32  yLen;
    ecc_key key;
    int     rc;

    rc = wh_Client_KeyExportPublic(ctx, id, WH_KEY_ALGO_ECC, label,
                                   (uint16)sizeof(label), der, &derLen);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    rc = wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
    if (rc != 0) {
        return rc;
    }
    rc = wc_EccPublicKeyDecode(der, &idx, &key, derLen);
    if (rc == 0 && (key.dp == NULL || key.dp->id != curveId)) {
        rc = WH_ERROR_ABORTED;
    }
    if (rc == 0) {
        xLen = (word32)wc_ecc_get_curve_size_from_id(curveId);
        yLen = xLen;
        if (*outLen < 2u * xLen) {
            rc = WH_ERROR_BUFFER_SIZE;
        }
    }
    if (rc == 0) {
        rc = wc_ecc_export_public_raw(&key, out, &xLen, out + xLen, &yLen);
    }
    if (rc == 0) {
        *outLen = xLen + yLen;
    }
    (void)wc_ecc_free(&key);
    return rc;
}

static int eccSecret(whClientContext* ctx, whKeyId privId, int curveId,
                     const uint8* peer, uint32 peerLen, uint8* out,
                     uint16* outLen)
{
    ecc_key priv;
    ecc_key pub;
    word32  half = (word32)wc_ecc_get_curve_size_from_id(curveId);
    int     rc;

    if (half == 0u || peerLen != 2u * half) {
        return WH_ERROR_BADARGS;
    }
    rc = wc_ecc_init_ex(&pub, NULL, INVALID_DEVID);
    if (rc != 0) {
        return rc;
    }
    rc = wc_ecc_init_ex(&priv, NULL, WH_CLIENT_DEVID(ctx));
    if (rc == 0) {
        rc = wc_ecc_import_unsigned(&pub, peer, peer + half, NULL, curveId);
        if (rc == 0) {
            rc = wc_ecc_set_curve(&priv, (int)half, curveId);
        }
        if (rc == 0) {
            rc = wh_Client_EccSetKeyId(&priv, privId);
        }
        if (rc == 0) {
            rc = wh_Client_EccSharedSecret(ctx, &priv, &pub, out, outLen);
        }
        (void)wc_ecc_free(&priv);
    }
    (void)wc_ecc_free(&pub);
    return rc;
}
#endif

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(HAVE_CURVE25519)
static int x25519PubValue(whClientContext* ctx, whKeyId id, uint8* out,
                          uint32* outLen)
{
    uint8          der[CRYPTO_PUBKEY_DER_BUF_SIZE];
    uint16         derLen = (uint16)sizeof(der);
    uint8          label[WH_NVM_LABEL_LEN];
    word32         idx = 0u;
    word32         len = *outLen;
    curve25519_key key;
    int            rc;

    rc = wh_Client_KeyExportPublic(ctx, id, WH_KEY_ALGO_CURVE25519, label,
                                   (uint16)sizeof(label), der, &derLen);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    rc = wc_curve25519_init_ex(&key, NULL, INVALID_DEVID);
    if (rc != 0) {
        return rc;
    }
    rc = wc_Curve25519PublicKeyDecode(der, &idx, &key, derLen);
    if (rc == 0) {
        rc = wc_curve25519_export_public_ex(&key, out, &len,
                                            EC25519_LITTLE_ENDIAN);
    }
    if (rc == 0) {
        *outLen = len;
    }
    wc_curve25519_free(&key);
    return rc;
}

static int x25519Secret(whClientContext* ctx, whKeyId privId, const uint8* peer,
                        uint32 peerLen, uint8* out, uint16* outLen)
{
    curve25519_key priv;
    curve25519_key pub;
    int            rc;

    if (peerLen != CURVE25519_KEYSIZE) {
        return WH_ERROR_BADARGS;
    }
    rc = wc_curve25519_init_ex(&pub, NULL, INVALID_DEVID);
    if (rc != 0) {
        return rc;
    }
    rc = wc_curve25519_init_ex(&priv, NULL, WH_CLIENT_DEVID(ctx));
    if (rc == 0) {
        rc = wc_curve25519_import_public_ex(peer, peerLen, &pub,
                                            EC25519_LITTLE_ENDIAN);
        if (rc == 0) {
            rc = wh_Client_Curve25519SetKeyId(&priv, privId);
        }
        if (rc == 0) {
            rc = wh_Client_Curve25519SharedSecret(
                ctx, &priv, &pub, EC25519_LITTLE_ENDIAN, out, outLen);
        }
        wc_curve25519_free(&priv);
    }
    wc_curve25519_free(&pub);
    return rc;
}
#endif

Std_ReturnType
wh_Autosar_KeyExchangeCalcPubValImpl(whClientContext* ctx, uint32 cryptoKeyId,
                                     uint8*  publicValuePtr,
                                     uint32* publicValueLengthPtr)
{
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    uint8   label[WH_NVM_LABEL_LEN] = {0};
    whKeyId whId                    = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    int     rc                      = WH_ERROR_NOTIMPL;

    if (desc == NULL || whId == 0u || publicValuePtr == NULL ||
        publicValueLengthPtr == NULL || *publicValueLengthPtr == 0u) {
        return E_NOT_OK;
    }
    if (wh_Autosar_KeyMarkWritten(cryptoKeyId) != E_OK) {
        return CRYPTO_E_KEY_WRITE_FAIL;
    }

#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)ctx;
    (void)label;
#else
    switch (desc->family) {
#ifdef HAVE_ECC
        case CRYPTO_ALGOFAM_ECCNIST:
        case CRYPTO_ALGOFAM_ECDH:
            rc = wh_Client_EccMakeCacheKey(
                ctx, (int)(desc->keyLength / 8u), desc->eccCurveId, &whId,
                wh_Autosar_KeyFlags(cryptoKeyId) | WH_NVM_FLAGS_NONEXPORTABLE,
                (uint16)sizeof(label), label);
            if (rc == WH_ERROR_OK) {
                rc = eccPubValue(ctx, whId, desc->eccCurveId, publicValuePtr,
                                 publicValueLengthPtr);
            }
            break;
#endif
#ifdef HAVE_CURVE25519
        case CRYPTO_ALGOFAM_X25519:
            rc = wh_Client_Curve25519MakeCacheKey(
                ctx, (uint16)CURVE25519_KEYSIZE, &whId,
                wh_Autosar_KeyFlags(cryptoKeyId) | WH_NVM_FLAGS_NONEXPORTABLE,
                label, (uint16)sizeof(label));
            if (rc == WH_ERROR_OK) {
                rc = x25519PubValue(ctx, whId, publicValuePtr,
                                    publicValueLengthPtr);
            }
            break;
#endif
        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
#endif
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}

Std_ReturnType
wh_Autosar_KeyExchangeCalcSecretImpl(whClientContext* ctx, uint32 cryptoKeyId,
                                     const uint8* partnerPublicValuePtr,
                                     uint32       partnerPublicValueLength)
{
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    whKeyId        privId = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    uint8          secret[66];
    uint16         secretLen = (uint16)sizeof(secret);
    int            rc        = WH_ERROR_NOTIMPL;
    Std_ReturnType ret;

    if (desc == NULL || privId == 0u || partnerPublicValuePtr == NULL ||
        partnerPublicValueLength == 0u) {
        return E_NOT_OK;
    }
    if (wh_Autosar_KeyIsRevoked(cryptoKeyId)) {
        return CRYPTO_E_KEY_NOT_VALID;
    }

#ifdef WOLFHSM_CFG_NO_CRYPTO
    (void)ctx;
#else
    switch (desc->family) {
#ifdef HAVE_ECC
        case CRYPTO_ALGOFAM_ECCNIST:
        case CRYPTO_ALGOFAM_ECDH:
            rc = eccSecret(ctx, privId, desc->eccCurveId, partnerPublicValuePtr,
                           partnerPublicValueLength, secret, &secretLen);
            break;
#endif
#ifdef HAVE_CURVE25519
        case CRYPTO_ALGOFAM_X25519:
            rc = x25519Secret(ctx, privId, partnerPublicValuePtr,
                              partnerPublicValueLength, secret, &secretLen);
            break;
#endif
        default:
            rc = WH_ERROR_NOTIMPL;
            break;
    }
#endif

    /* The shared value replaces the private key in element 1
     * (CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE). */
    ret = (rc == WH_ERROR_OK) ? wh_Autosar_KeyElementSetImpl(
                                    ctx, cryptoKeyId, 1u, secret, secretLen)
                              : E_NOT_OK;
    wh_Utils_ForceZero(secret, sizeof(secret));
    return ret;
}

Std_ReturnType Crypto_KeyExchangeCalcPubVal(uint32  cryptoKeyId,
                                            uint8*  publicValuePtr,
                                            uint32* publicValueLengthPtr)
{
    whClientContext* ctx = NULL;
    Std_ReturnType   ret = wh_Autosar_KeystoreBegin(&ctx);

    if (ret != E_OK) {
        return ret;
    }
    ret = wh_Autosar_KeyExchangeCalcPubValImpl(ctx, cryptoKeyId, publicValuePtr,
                                               publicValueLengthPtr);
    wh_Autosar_KeystoreEnd(ctx);
    return ret;
}

Std_ReturnType Crypto_KeyExchangeCalcSecret(uint32       cryptoKeyId,
                                            const uint8* partnerPublicValuePtr,
                                            uint32 partnerPublicValueLength)
{
    whClientContext* ctx = NULL;
    Std_ReturnType   ret = wh_Autosar_KeystoreBegin(&ctx);

    if (ret != E_OK) {
        return ret;
    }
    ret = wh_Autosar_KeyExchangeCalcSecretImpl(
        ctx, cryptoKeyId, partnerPublicValuePtr, partnerPublicValueLength);
    wh_Autosar_KeystoreEnd(ctx);
    return ret;
}
