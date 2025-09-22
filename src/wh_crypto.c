/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * src/wh_crypto.c
 *
 * Common crypto functions for both the client and server
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/dilithium.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "wolfhsm/wh_crypto.h"

#ifndef NO_RSA
int wh_Crypto_RsaSerializeKeyDer(const RsaKey* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size)
{
    int ret = 0;
    int der_size = 0;

    if (    (key == NULL) ||
            (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (key->type == RSA_PUBLIC) {
        der_size = wc_RsaKeyToPublicDer((RsaKey*)key, (byte*)buffer, (word32)max_size);
    } else if (key->type == RSA_PRIVATE) {
        /* TODO: Update wc to use a const here */
        der_size = wc_RsaKeyToDer((RsaKey*)key, (byte*)buffer, (word32)max_size);
    } else {
        return WH_ERROR_BADARGS;
    }

    if (der_size >= 0) {
        ret = 0;
        if (out_size != NULL) {
            *out_size = der_size;
        }
    } else {
        /* Error serializing.  Clear the buffer */
        ret = der_size;
        memset(buffer, 0, max_size);
    }
    return ret;
}

int wh_Crypto_RsaDeserializeKeyDer(uint16_t size, const uint8_t* buffer,
        RsaKey* key)
{
    int ret;
    word32 idx = 0;

    if (    (size == 0) ||
            (buffer == NULL) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }
    /* Deserialize the RSA key. Since there is no good way to determine if it is
     * public or private with only the DER, try to decode as private first, and
     * if that fails, assume it is public and try to decode again */
    ret = wc_RsaPrivateKeyDecode(buffer, &idx, key, size);
    if (ret == ASN_PARSE_E) {
        idx = 0;
        ret = wc_RsaPublicKeyDecode(buffer, &idx, key, size);
    }
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
int wh_Crypto_EccSerializeKeyDer(ecc_key* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size)
{
    int ret = 0;

    if (    (key == NULL) ||
            (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (key->type) {
    case ECC_PUBLICKEY:
        ret = wc_EccPublicKeyToDer(key, (byte*)buffer, (word32)max_size, 1);
        break;
    case ECC_PRIVATEKEY:
        ret = wc_EccKeyToDer(key, (byte*)buffer, (word32)max_size);
        break;
    case ECC_PRIVATEKEY_ONLY:
        ret = wc_EccPrivateKeyToDer(key, (byte*)buffer, (word32)max_size);
        break;
    default:
        ret = WH_ERROR_BADARGS;
    }
    if (ret >= 0) {
        if (out_size != NULL) {
            *out_size = (uint16_t)ret;
        }
        ret = WH_ERROR_OK;
    }
    return ret;
}

int wh_Crypto_EccDeserializeKeyDer(const uint8_t* buffer, uint16_t size,
        ecc_key* key)
{
    int ret;
    word32 idx = 0;

    if (    (size == 0) ||
            (buffer == NULL) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Try decoding as a key pair or private only */
    ret = wc_EccPrivateKeyDecode(buffer, &idx, key, size);
    if (ret != 0) {
        /* Try it as a public only */
        idx = 0;
        ret = wc_EccPublicKeyDecode(buffer, &idx, key, size);
    }
    return ret;
}

int wh_Crypto_EccUpdatePrivateOnlyKeyDer(ecc_key* key, uint16_t pub_size,
        const uint8_t* pub_buffer)
{
    int ret = 0;
    ecc_key pub_only[1];
    word32 idx = 0;
    uint8_t x[ECC_MAXSIZE];
    word32 x_len = sizeof(x);
    uint8_t y[ECC_MAXSIZE];
    word32 y_len = sizeof(y);
    uint8_t d[ECC_MAXSIZE];
    word32 d_len = sizeof(d);
    int curve_id;

    if (    (key == NULL) ||
            ((pub_size > 0) && (pub_buffer == NULL)) ) {
        return WH_ERROR_BADARGS;
    }
    if (key->type != ECC_PRIVATEKEY_ONLY) {
        /* No need to update anything */
        return 0;
    }

    curve_id = wc_ecc_get_curve_id(key->idx);
    if (curve_id < 0) {
        ret = curve_id;
    }
    /* TODO: Find more efficient way to doing this */
    if (ret == 0) {
        ret = wc_ecc_export_private_only(key, d, &d_len);
    }
    if (ret == 0) {
        ret = wc_ecc_init(pub_only);
        if (ret == 0) {
            ret = wc_EccPublicKeyDecode(pub_buffer, &idx, pub_only, pub_size);
        }
        if (ret == 0) {
            ret = wc_ecc_export_public_raw(pub_only, x, &x_len, y, &y_len);
        }
        if (ret == 0) {
            ret = wc_ecc_import_unsigned(key, x, y, d, curve_id);
        }
        wc_ecc_free(pub_only);
    }

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519

/* Store a curve25519_key to a byte sequence in DER format */
int wh_Crypto_Curve25519SerializeKey(curve25519_key* key, uint8_t* buffer,
                                     uint16_t* outDerSize)
{
    int ret = 0;
    /* We must include the algorithm identifier in the DER encoding, or we will
     * not be able to deserialize it properly in the public key only case*/
    const int WITH_ALG_ENABLE_SUBJECT_PUBLIC_KEY_INFO = 1;

    if ((key == NULL) || (buffer == NULL) || (outDerSize == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_Curve25519KeyToDer(key, buffer, *outDerSize,
                                WITH_ALG_ENABLE_SUBJECT_PUBLIC_KEY_INFO);

    /* ASN.1 functions return the size of the DER encoded key on success */
    if (ret > 0) {
        *outDerSize = ret;
        ret      = WH_ERROR_OK;
    }
    return ret;
}

/* Restore a curve25519_key from a byte sequence in DER format */
int wh_Crypto_Curve25519DeserializeKey(const uint8_t* derBuffer,
                                       uint16_t derSize, curve25519_key* key)
{
    word32 idx = 0;

    if ((derBuffer == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return wc_Curve25519KeyDecode(derBuffer, &idx, key, derSize);
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_DILITHIUM
int wh_Crypto_MlDsaSerializeKeyDer(MlDsaKey* key, uint16_t max_size,
                                   uint8_t* buffer, uint16_t* out_size)
{
    int ret = 0;

    if ((key == NULL) || (buffer == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Choose appropriate serialization based on key flags */
    if (key->prvKeySet && key->pubKeySet) {
#if defined(WOLFSSL_DILITHIUM_PRIVATE_KEY) && \
    defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        /* Full keypair - use KeyToDer */
        ret = wc_Dilithium_KeyToDer(key, buffer, max_size);
#else
        ret = WH_ERROR_BADARGS;
#endif
    }
    else if (key->pubKeySet) {
#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
        /* Public key only - use PublicKeyToDer with SPKI format */
        ret = wc_Dilithium_PublicKeyToDer(key, buffer, max_size, 1);
#else
        ret = WH_ERROR_BADARGS;
#endif
    }
    else if (key->prvKeySet) {
#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
        /* Private key only */
        ret = wc_Dilithium_PrivateKeyToDer(key, buffer, max_size);
#else
        ret = WH_ERROR_BADARGS;
#endif
    }
    else {
        /* No key data set */
        return WH_ERROR_BADARGS;
    }

    /* ASN.1 functions return the size of the DER encoded key on success */
    if (ret > 0) {
        *out_size = ret;
        ret       = WH_ERROR_OK;
    }
    return ret;
}

int wh_Crypto_MlDsaDeserializeKeyDer(const uint8_t* buffer, uint16_t size,
        MlDsaKey* key)
{
    word32 idx = 0;
    int ret;

    if ((buffer == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

#if defined(WOLFSSL_DILITHIUM_PRIVATE_KEY) && \
    defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
    /* Try private key first, if that fails try public key */
    ret = wc_Dilithium_PrivateKeyDecode(buffer, &idx, key, size);
    if (ret != 0) {
        /* Reset index before trying public key */
        idx = 0;
        ret = wc_Dilithium_PublicKeyDecode(buffer, &idx, key, size);
    }
#elif defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
    ret = wc_Dilithium_PublicKeyDecode(buffer, &idx, key, size);
#elif defined(WOLFSSL_DILITHIUM_PRIVATE_KEY)
    ret = wc_Dilithium_PrivateKeyDecode(buffer, &idx, key, size);
#else
    ret = WH_ERROR_BADARGS;
#endif
    return ret;
}
#endif /* HAVE_DILITHIUM */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
