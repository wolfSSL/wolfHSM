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

#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#if defined(WOLFSSL_HAVE_LMS)
#include "wolfssl/wolfcrypt/wc_lms.h"
#endif
#if defined(WOLFSSL_HAVE_XMSS)
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif
#include "wolfssl/wolfcrypt/memory.h"

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

#ifdef HAVE_ED25519
int wh_Crypto_Ed25519SerializeKeyDer(const ed25519_key* key, uint16_t max_size,
                                     uint8_t* buffer, uint16_t* out_size)
{
    int ret = 0;

    if ((key == NULL) || (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (key->privKeySet) {
        ret = wc_Ed25519KeyToDer(key, buffer, max_size);
    }
    else if (key->pubKeySet) {
        ret = wc_Ed25519PublicKeyToDer(key, buffer, max_size, 1);
    }
    else {
        ret = WH_ERROR_BADARGS;
    }

    if (ret > 0) {
        if (out_size != NULL) {
            *out_size = (uint16_t)ret;
        }
        ret = WH_ERROR_OK;
    }
    return ret;
}

int wh_Crypto_Ed25519DeserializeKeyDer(const uint8_t* buffer, uint16_t size,
                                       ed25519_key* key)
{
    word32 idx = 0;
    int    ret;

    if ((buffer == NULL) || (key == NULL) || (size == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Try private key first; fall back to public key */
    ret = wc_Ed25519PrivateKeyDecode(buffer, &idx, key, size);
    if (ret != 0) {
        idx = 0;
        ret = wc_Ed25519PublicKeyDecode(buffer, &idx, key, size);
    }
    return ret;
}
#endif /* HAVE_ED25519 */

#ifdef WOLFSSL_HAVE_MLDSA
int wh_Crypto_MlDsaSerializeKeyDer(wc_MlDsaKey* key, uint16_t max_size,
                                   uint8_t* buffer, uint16_t* out_size)
{
    int ret = 0;

    if ((key == NULL) || (buffer == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Choose appropriate serialization based on key flags */
    if (key->prvKeySet && key->pubKeySet) {
#if defined(WOLFSSL_MLDSA_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_PUBLIC_KEY)
        /* Full keypair - use KeyToDer */
        ret = wc_MlDsaKey_KeyToDer(key, buffer, max_size);
#else
        ret = WH_ERROR_BADARGS;
#endif
    }
    else if (key->pubKeySet) {
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
        /* Public key only - use PublicKeyToDer with SPKI format */
        ret = wc_MlDsaKey_PublicKeyToDer(key, buffer, max_size, 1);
#else
        ret = WH_ERROR_BADARGS;
#endif
    }
    else if (key->prvKeySet) {
#ifdef WOLFSSL_MLDSA_PRIVATE_KEY
        /* Private key only */
        ret = wc_MlDsaKey_PrivateKeyToDer(key, buffer, max_size);
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
        wc_MlDsaKey* key)
{
    word32 idx = 0;
    int ret;

    if ((buffer == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

#if defined(WOLFSSL_MLDSA_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_PUBLIC_KEY)
    /* Try private key first, if that fails try public key */
    ret = wc_MlDsaKey_PrivateKeyDecode(key, buffer, size, &idx);
    if (ret != 0) {
        /* Reset index before trying public key */
        idx = 0;
        ret = wc_MlDsaKey_PublicKeyDecode(key, buffer, size, &idx);
    }
#elif defined(WOLFSSL_MLDSA_PUBLIC_KEY)
    ret = wc_MlDsaKey_PublicKeyDecode(key, buffer, size, &idx);
#elif defined(WOLFSSL_MLDSA_PRIVATE_KEY)
    ret = wc_MlDsaKey_PrivateKeyDecode(key, buffer, size, &idx);
#else
    ret = WH_ERROR_BADARGS;
#endif
    return ret;
}
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
int wh_Crypto_MlKemSerializeKey(MlKemKey* key, uint16_t max_size,
                                uint8_t* buffer, uint16_t* out_size)
{
    int    ret     = WH_ERROR_OK;
    word32 keySize = 0;

    if ((key == NULL) || (buffer == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Try to encode the private key first. wc_MlKemKey_PrivateKeySize()
     * returns the size regardless of whether a private key is present, so we
     * must attempt encoding and check the return to detect public-only keys. */
    ret = wc_MlKemKey_PrivateKeySize(key, &keySize);
    if (ret == WH_ERROR_OK) {
        if (keySize > max_size) {
            return WH_ERROR_BADARGS;
        }
        ret = wc_MlKemKey_EncodePrivateKey(key, buffer, keySize);
    }
    if (ret != WH_ERROR_OK) {
        /* Private key encoding failed - try public key only */
        ret = wc_MlKemKey_PublicKeySize(key, &keySize);
        if (ret == WH_ERROR_OK) {
            if (keySize > max_size) {
                return WH_ERROR_BADARGS;
            }
            ret = wc_MlKemKey_EncodePublicKey(key, buffer, keySize);
        }
    }

    if (ret == WH_ERROR_OK) {
        *out_size = (uint16_t)keySize;
    }
    else {
        /* Clear buffer to avoid leaking partial key material on error */
        wc_ForceZero(buffer, keySize);
    }

    return ret;
}

int wh_Crypto_MlKemDeserializeKey(const uint8_t* buffer, uint16_t size,
                                  MlKemKey* key)
{
    static const uint8_t levels[] = {
        WC_ML_KEM_512,
        WC_ML_KEM_768,
        WC_ML_KEM_1024,
    };
    int    ret;
    int    origLevel;
    int    origDevId;
    void*  origHeap;
    word32 i;

    if ((buffer == NULL) || (key == NULL) || (size == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Save original key properties so we can restore on failure. The key's
     * level (type) may be updated below if a different ML-KEM parameter set
     * matches the encoded buffer. Callers that depend on the configured level
     * should read key->type after a successful return. */
    origLevel = key->type;
    origDevId = key->devId;
    origHeap  = key->heap;

    /* First, try decoding with the level already set in the key */
    ret = wc_MlKemKey_DecodePrivateKey(key, buffer, size);
    if (ret == WH_ERROR_OK) {
        return ret;
    }
    ret = wc_MlKemKey_DecodePublicKey(key, buffer, size);
    if (ret == WH_ERROR_OK) {
        return ret;
    }

    /* Current level didn't work, try other levels in place */
    for (i = 0; i < XELEM_CNT(levels); i++) {
        if ((int)levels[i] == origLevel) {
            continue;
        }
        wc_MlKemKey_Free(key);
        ret = wc_MlKemKey_Init(key, (int)levels[i], origHeap, origDevId);
        if (ret != WH_ERROR_OK) {
            continue;
        }
        ret = wc_MlKemKey_DecodePrivateKey(key, buffer, size);
        if (ret == WH_ERROR_OK) {
            return ret;
        }
        ret = wc_MlKemKey_DecodePublicKey(key, buffer, size);
        if (ret == WH_ERROR_OK) {
            return ret;
        }
    }

    /* None of the levels worked, restore original level and devId. We return an
     * in ret anyway. So we ignore the return value of wc_MlKemKey_Init(). */
    wc_MlKemKey_Free(key);
    (void)wc_MlKemKey_Init(key, origLevel, origHeap, origDevId);
    return ret;
}
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
/* Stateful hash-based signature key serialization helpers (LMS / XMSS).
 *
 * Slot blob layout:
 *   whCryptoStatefulSigHeader header;   (fixed fields, see wh_crypto.h)
 *   uint8_t  paramDescriptor[header.paramLen];
 *   uint8_t  pub[header.pubLen];
 *   uint8_t  priv[header.privLen];
 *
 * paramDescriptor encodes the parameter set:
 *   LMS  : 3 bytes (levels, height, winternitz) - paramLen == 3
 *   XMSS : NUL-terminated parameter string, paramLen == strlen+1
 *
 * The blob is server-internal (NVM-stored), never traverses the wire, and uses
 * native byte order. */

#define WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_LMS  0x4C4D5301u /* 'LMS\1' */
#define WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_XMSS 0x584D5301u /* 'XMS\1' */

int wh_Crypto_IsStatefulSigPrivBlob(const uint8_t* buffer, uint16_t size)
{
    whCryptoStatefulSigHeader hdr;

    /* Need the full fixed header to inspect magic and privLen. */
    if ((buffer == NULL) || (size < sizeof(hdr))) {
        return 0;
    }
    memcpy(&hdr, buffer, sizeof(hdr));
    /* Match what deserialize requires before it would accept the blob. */
    if ((hdr.magic != WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_LMS) &&
        (hdr.magic != WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_XMSS)) {
        return 0;
    }
    /* Only blobs carrying private key state are import-forbidden; a
     * public-only blob (privLen == 0) is a verify key and is allowed. The
     * deserialize path reads this same field to decide priv vs pub. */
    return (hdr.privLen > 0) ? 1 : 0;
}

static int _StatefulSigEncodeHeader(uint8_t* buffer, uint32_t magic,
                                    uint16_t pubLen, uint16_t privLen,
                                    uint16_t paramLen)
{
    whCryptoStatefulSigHeader hdr;
    hdr.magic    = magic;
    hdr.pubLen   = pubLen;
    hdr.privLen  = privLen;
    hdr.paramLen = paramLen;
    hdr.reserved = 0;
    /* Copy via a local struct so the on-blob bytes are not assumed to be
     * struct-aligned. */
    memcpy(buffer, &hdr, sizeof(hdr));
    return WH_ERROR_OK;
}

static int _StatefulSigDecodeHeader(const uint8_t* buffer, uint16_t size,
                                    uint32_t expectMagic, uint16_t* pubLen,
                                    uint16_t* privLen, uint16_t* paramLen)
{
    whCryptoStatefulSigHeader hdr;

    if (size < sizeof(hdr)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(&hdr, buffer, sizeof(hdr));
    /* Magic and the zeroed reserved field together validate the header. */
    if ((hdr.magic != expectMagic) || (hdr.reserved != 0)) {
        return WH_ERROR_BADARGS;
    }
    if ((uint32_t)sizeof(hdr) + hdr.paramLen + hdr.pubLen + hdr.privLen > size) {
        return WH_ERROR_BADARGS;
    }
    *pubLen   = hdr.pubLen;
    *privLen  = hdr.privLen;
    *paramLen = hdr.paramLen;
    return WH_ERROR_OK;
}
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */

#ifdef WOLFSSL_HAVE_LMS
/* Serializing the private key is meaningless without it; gate out verify-only,
 * where wolfCrypt omits LmsKey.priv_raw. */
#ifndef WOLFSSL_LMS_VERIFY_ONLY
int wh_Crypto_LmsSerializeKey(LmsKey* key, uint16_t max_size, uint8_t* buffer,
                              uint16_t* out_size)
{
    word32   pubLen32  = 0;
    uint16_t pubLen;
    uint16_t privLen;
    uint16_t paramLen = 3;          /* levels, height, winternitz */
    uint32_t totalLen;
    int      ret;

    if ((key == NULL) || (buffer == NULL) || (out_size == NULL) ||
        (key->params == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_LmsKey_GetPubLen(key, &pubLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }
    if (pubLen32 > UINT16_MAX) {
        return WH_ERROR_BADARGS;
    }
    pubLen  = (uint16_t)pubLen32;
    privLen = (uint16_t)HSS_PRIVATE_KEY_LEN(key->params->hash_len);

    totalLen = (uint32_t)WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen + pubLen +
               privLen;
    if (totalLen > max_size) {
        return WH_ERROR_BUFFER_SIZE;
    }

    (void)_StatefulSigEncodeHeader(buffer,
                                   WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_LMS,
                                   pubLen, privLen, paramLen);

    /* paramDescriptor: levels, height, winternitz */
    buffer[WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 0] = key->params->levels;
    buffer[WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 1] = key->params->height;
    buffer[WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 2] = key->params->width;

    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen,
           key->pub, pubLen);
    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen + pubLen,
           key->priv_raw, privLen);

    *out_size = (uint16_t)totalLen;
    return WH_ERROR_OK;
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

int wh_Crypto_LmsDeserializeKey(const uint8_t* buffer, uint16_t size,
                                LmsKey* key)
{
    uint16_t pubLen;
    uint16_t privLen;
    uint16_t paramLen;
    word32   expectPubLen = 0;
    int      ret;
    int      levels;
    int      height;
    int      winternitz;
    const uint8_t* p;

    if ((buffer == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _StatefulSigDecodeHeader(buffer, size,
                                   WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_LMS,
                                   &pubLen, &privLen, &paramLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    if (paramLen != 3) {
        return WH_ERROR_BADARGS;
    }

    p = buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ;
    levels     = (int)p[0];
    height     = (int)p[1];
    winternitz = (int)p[2];

    ret = wc_LmsKey_SetParameters(key, levels, height, winternitz);
    if (ret != 0) {
        return ret;
    }

    /* Sanity-check pub size against the bound parameter set */
    ret = wc_LmsKey_GetPubLen(key, &expectPubLen);
    if ((ret != 0) || (expectPubLen != pubLen)) {
        return WH_ERROR_BADARGS;
    }
    /* privLen == 0 denotes a public-only (verify) key: load pub, no priv. */
#ifndef WOLFSSL_LMS_VERIFY_ONLY
    if ((privLen != 0) &&
        (privLen != (uint16_t)HSS_PRIVATE_KEY_LEN(key->params->hash_len))) {
        return WH_ERROR_BADARGS;
    }
#else
    /* Verify-only builds have no private key storage. */
    if (privLen != 0) {
        return WH_ERROR_BADARGS;
    }
#endif

    p = buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen;
    memcpy(key->pub, p, pubLen);
#ifndef WOLFSSL_LMS_VERIFY_ONLY
    if (privLen > 0) {
        p += pubLen;
        /* SigsLeft path does not reload, so copy priv_raw into the key.
         * For the Sign path in software, this is a duplicate read. */
        memcpy(key->priv_raw, p, privLen);
    }
#endif

    return WH_ERROR_OK;
}

int wh_Crypto_LmsSerializePubKey(LmsKey* key, uint16_t max_size,
                                 uint8_t* buffer, uint16_t* out_size)
{
    word32   pubLen32 = 0;
    uint16_t pubLen;
    uint16_t paramLen = 3;          /* levels, height, winternitz */
    uint32_t totalLen;
    int      ret;

    if ((key == NULL) || (buffer == NULL) || (out_size == NULL) ||
        (key->params == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_LmsKey_GetPubLen(key, &pubLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }
    if (pubLen32 > UINT16_MAX) {
        return WH_ERROR_BADARGS;
    }
    pubLen = (uint16_t)pubLen32;

    totalLen = (uint32_t)WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen + pubLen;
    if (totalLen > max_size) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Public-only blob: privLen == 0, no private section follows. */
    (void)_StatefulSigEncodeHeader(buffer,
                                   WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_LMS,
                                   pubLen, 0, paramLen);

    buffer[WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 0] = key->params->levels;
    buffer[WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 1] = key->params->height;
    buffer[WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 2] = key->params->width;

    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen,
           key->pub, pubLen);

    *out_size = (uint16_t)totalLen;
    return WH_ERROR_OK;
}
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
/* The private-key serializers are unavailable in verify-only, where wolfCrypt
 * omits XmssKey.sk and wc_XmssKey_GetPrivLen. */
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Serialize an XMSS slot blob: header, parameter string, and public key, plus
 * the private key when priv is non-NULL. The keygen path passes priv == NULL
 * because its write callback stores the private key into the buffer separately
 * (wolfCrypt zeroizes key->sk right after that callback). */
static int _XmssSerializeSlot(XmssKey* key, const char* paramStr,
                              const uint8_t* priv, uint16_t privLen,
                              uint16_t max_size, uint8_t* buffer,
                              uint16_t* out_size)
{
    word32   pubLen32 = 0;
    uint16_t pubLen;
    uint16_t paramLen;
    uint32_t totalLen;
    size_t   strLen;
    int      ret;

    if ((key == NULL) || (paramStr == NULL) || (buffer == NULL) ||
        (out_size == NULL) || (key->params == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_XmssKey_GetPubLen(key, &pubLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }
    if (pubLen32 > UINT16_MAX) {
        return WH_ERROR_BADARGS;
    }
    pubLen = (uint16_t)pubLen32;

    strLen = strlen(paramStr);
    if (strLen >= UINT16_MAX) {
        return WH_ERROR_BADARGS;
    }
    paramLen = (uint16_t)(strLen + 1);  /* include NUL */

    totalLen = (uint32_t)WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen + pubLen +
               privLen;
    if (totalLen > max_size) {
        return WH_ERROR_BUFFER_SIZE;
    }

    (void)_StatefulSigEncodeHeader(buffer,
                                   WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_XMSS,
                                   pubLen, privLen, paramLen);

    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ, paramStr, paramLen);
    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen,
           key->pk, pubLen);
    if (priv != NULL) {
        memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen + pubLen,
               priv, privLen);
    }

    *out_size = (uint16_t)totalLen;
    return WH_ERROR_OK;
}

int wh_Crypto_XmssSerializeKey(XmssKey* key, const char* paramStr,
                               uint16_t max_size, uint8_t* buffer,
                               uint16_t* out_size)
{
    word32 privLen32 = 0;
    int    ret;

    if ((key == NULL) || (key->sk == NULL)) {
        return WH_ERROR_BADARGS;
    }
    ret = wc_XmssKey_GetPrivLen(key, &privLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }
    if (privLen32 > UINT16_MAX) {
        return WH_ERROR_BADARGS;
    }
    return _XmssSerializeSlot(key, paramStr, key->sk, (uint16_t)privLen32,
                              max_size, buffer, out_size);
}

int wh_Crypto_XmssSerializeKeyNoPriv(XmssKey* key, const char* paramStr,
                                     uint16_t privLen, uint16_t max_size,
                                     uint8_t* buffer, uint16_t* out_size)
{
    return _XmssSerializeSlot(key, paramStr, NULL, privLen, max_size, buffer,
                              out_size);
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

int wh_Crypto_XmssDeserializeKey(const uint8_t* buffer, uint16_t size,
                                 XmssKey* key)
{
    uint16_t pubLen;
    uint16_t privLen;
    uint16_t paramLen;
    word32   expectPubLen = 0;
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
    word32   expectPrivLen = 0;
#endif
    int      ret;
    const char* paramStr;
    const uint8_t* p;

    if ((buffer == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _StatefulSigDecodeHeader(buffer, size,
                                   WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_XMSS,
                                   &pubLen, &privLen, &paramLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    if (paramLen == 0) {
        return WH_ERROR_BADARGS;
    }

    /* paramDescriptor must be NUL-terminated and within paramLen */
    paramStr = (const char*)(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ);
    if (paramStr[paramLen - 1] != '\0') {
        return WH_ERROR_BADARGS;
    }

    /* SetParamStr binds key->params; sk is allocated later by Reload via
     * the read callback path (or directly if the caller wants to pre-load
     * it). */
    ret = wc_XmssKey_SetParamStr(key, paramStr);
    if (ret != 0) {
        return ret;
    }

    ret = wc_XmssKey_GetPubLen(key, &expectPubLen);
    if ((ret != 0) || (expectPubLen != pubLen)) {
        return WH_ERROR_BADARGS;
    }
    /* privLen == 0 denotes a public-only (verify) key. */
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
    if (privLen != 0) {
        ret = wc_XmssKey_GetPrivLen(key, &expectPrivLen);
        if ((ret != 0) || (expectPrivLen != privLen)) {
            return WH_ERROR_BADARGS;
        }
    }
#else
    /* Verify-only builds have no private key storage. */
    if (privLen != 0) {
        return WH_ERROR_BADARGS;
    }
#endif

    p = buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen;
    memcpy(key->pk, p, pubLen);
    /* The private key (if any) is left in the slot blob; downstream paths
     * read it via the slot ReadCb against the cached slot (sk is allocated
     * by Reload, not by deserialize). */
    (void)privLen;

    return WH_ERROR_OK;
}

int wh_Crypto_XmssSerializePubKey(XmssKey* key, const char* paramStr,
                                  uint16_t max_size, uint8_t* buffer,
                                  uint16_t* out_size)
{
    word32   pubLen32 = 0;
    uint16_t pubLen;
    uint16_t paramLen;
    uint32_t totalLen;
    size_t   strLen;
    int      ret;

    if ((key == NULL) || (paramStr == NULL) || (buffer == NULL) ||
        (out_size == NULL) || (key->params == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_XmssKey_GetPubLen(key, &pubLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }
    if (pubLen32 > UINT16_MAX) {
        return WH_ERROR_BADARGS;
    }
    pubLen = (uint16_t)pubLen32;

    strLen = strlen(paramStr);
    if (strLen >= 0xFFFFu) {
        return WH_ERROR_BADARGS;
    }
    paramLen = (uint16_t)(strLen + 1);  /* include NUL */

    totalLen = (uint32_t)WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen + pubLen;
    if (totalLen > max_size) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Public-only blob: privLen == 0, no private section follows. */
    (void)_StatefulSigEncodeHeader(buffer,
                                   WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_XMSS,
                                   pubLen, 0, paramLen);

    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ, paramStr, paramLen);
    memcpy(buffer + WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + paramLen,
           key->pk, pubLen);

    *out_size = (uint16_t)totalLen;
    return WH_ERROR_OK;
}
#endif /* WOLFSSL_HAVE_XMSS */


#ifdef WOLFSSL_CMAC
void wh_Crypto_CmacAesSaveStateToMsg(whMessageCrypto_CmacAesState* state,
                                     const Cmac*                   cmac)
{
    memcpy(state->buffer, cmac->buffer, AES_BLOCK_SIZE);
    memcpy(state->digest, cmac->digest, AES_BLOCK_SIZE);
    state->bufferSz = cmac->bufferSz;
    state->totalSz  = cmac->totalSz;
}

int wh_Crypto_CmacAesRestoreStateFromMsg(
    Cmac* cmac, const whMessageCrypto_CmacAesState* state)
{
    if (state->bufferSz > AES_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }
    memcpy(cmac->buffer, state->buffer, AES_BLOCK_SIZE);
    memcpy(cmac->digest, state->digest, AES_BLOCK_SIZE);
    cmac->bufferSz = state->bufferSz;
    cmac->totalSz  = state->totalSz;
    return 0;
}
#endif /* WOLFSSL_CMAC */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
