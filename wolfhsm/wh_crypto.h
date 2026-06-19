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
 * wolfhsm/wh_crypto.h
 *
 * Common crypto functions for both the client and server
 *
 */

#ifndef WOLFHSM_WH_CRYPTO_H_
#define WOLFHSM_WH_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#include "wolfhsm/wh_message_crypto.h"

#ifdef WOLFSSL_CMAC
/* Save portable CMAC state from a Cmac context into a message state struct */
void wh_Crypto_CmacAesSaveStateToMsg(whMessageCrypto_CmacAesState* state,
                                     const Cmac*                   cmac);
/* Restore portable CMAC state from a message state struct into a Cmac context
 */
int wh_Crypto_CmacAesRestoreStateFromMsg(
    Cmac* cmac, const whMessageCrypto_CmacAesState* state);
#endif /* WOLFSSL_CMAC */

#ifndef NO_AES
int wh_Crypto_SerializeAesKey(Aes* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
int wh_Crypto_DeserializeAesKey(uint16_t size, const uint8_t* buffer,
        Aes* key);
#endif /* !NO_AES */

#ifndef NO_RSA
/* Store a RsaKey to a byte sequence (currently DER format) */
int wh_Crypto_RsaSerializeKeyDer(const RsaKey* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
/* Restore a RsaKey from a byte sequence (currently DER format) */
int wh_Crypto_RsaDeserializeKeyDer(uint16_t size, const uint8_t* buffer,
        RsaKey* key);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/* Store an ecc_key to a byte sequence */
int wh_Crypto_EccSerializeKeyDer(ecc_key* key,
        uint16_t max_size, uint8_t* buffer, uint16_t *out_size);

/* Restore an ecc_key from a byte sequence */
int wh_Crypto_EccDeserializeKeyDer(const uint8_t* buffer, uint16_t pub_size,
        ecc_key* key);

/* Helper to update an ECC private-only key with the corresponding public key,
 * similar to wc_ecc_make_pub().  The incoming byte array of the public key is
 * expected to have been exported using wc_EccPublicKeyToDer().
 */
int wh_Crypto_EccUpdatePrivateOnlyKeyDer(ecc_key* key, uint16_t pub_size,
        const uint8_t* pub_buffer);

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Store a curve25519_key to a byte sequence */
int wh_Crypto_Curve25519SerializeKey(curve25519_key* key, uint8_t* buffer,
                                     uint16_t* outDerSize);
/* Restore a curve25519_key from a byte sequence */
int wh_Crypto_Curve25519DeserializeKey(const uint8_t* derBuffer,
                                       uint16_t derSize, curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
#define WH_CRYPTO_ED25519_MAX_CTX_LEN (255U)
int wh_Crypto_Ed25519SerializeKeyDer(const ed25519_key* key, uint16_t max_size,
                                     uint8_t* buffer, uint16_t* out_size);

int wh_Crypto_Ed25519DeserializeKeyDer(const uint8_t* buffer, uint16_t size,
                                       ed25519_key* key);
#endif /* HAVE_ED25519 */

#ifdef WOLFSSL_HAVE_MLDSA
#define WH_CRYPTO_MLDSA_MAX_CTX_LEN (255U)
/* Store a wc_MlDsaKey to a byte sequence */
int wh_Crypto_MlDsaSerializeKeyDer(wc_MlDsaKey* key, uint16_t max_size,
                                   uint8_t* buffer, uint16_t* out_size);
/* Restore a wc_MlDsaKey from a byte sequence */
int wh_Crypto_MlDsaDeserializeKeyDer(const uint8_t* buffer, uint16_t size,
                                     wc_MlDsaKey* key);
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
/* Store a MlKemKey to a byte sequence */
int wh_Crypto_MlKemSerializeKey(MlKemKey* key, uint16_t max_size,
                                uint8_t* buffer, uint16_t* out_size);
/* Restore a MlKemKey from a byte sequence. Tries the level already set in the
 * key first, then probes other supported ML-KEM levels if needed. */
int wh_Crypto_MlKemDeserializeKey(const uint8_t* buffer, uint16_t size,
                                  MlKemKey* key);
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
/* Fixed header of a stateful-sig (LMS/XMSS) slot blob.
 * The full blob layout is documented in wh_crypto.c. */
typedef struct {
    uint32_t magic;
    uint16_t pubLen;
    uint16_t privLen;
    uint16_t paramLen;
    uint16_t reserved;    /* must be 0 */
} whCryptoStatefulSigHeader;

/* Ensure the header stays a fixed size for ABI compatibility. */
#define WH_CRYPTO_STATEFUL_SIG_HEADER_SZ 12
WH_UTILS_STATIC_ASSERT(
    sizeof(whCryptoStatefulSigHeader) == WH_CRYPTO_STATEFUL_SIG_HEADER_SZ, "");

/* Returns 1 if buffer is an LMS/XMSS stateful-sig slot-blob that carries
 * private key state (privLen > 0), else 0. Used to reject client attempts to
 * import (and thereby roll back) private state through the generic
 * keystore/NVM paths. A public-only blob (privLen == 0) is a verify key and
 * returns 0 so it may be imported. */
int wh_Crypto_IsStatefulSigPrivBlob(const uint8_t* buffer, uint16_t size);
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */

#ifdef WOLFSSL_HAVE_LMS
/* WOLFSSL_WC_LMS_SERIALIZE_STATE makes the key size much larger and is 
 * not supported by wolfHSM */
#ifdef WOLFSSL_WC_LMS_SERIALIZE_STATE
#error "wolfHSM LMS key storage does not support WOLFSSL_WC_LMS_SERIALIZE_STATE"
#endif

/* Store an LmsKey (parameter set + public key + priv_raw) into a byte
 * sequence.
 *
 * @param [in]      key       LmsKey to serialize.
 * @param [in]      max_size  Capacity of buffer in bytes.
 * @param [out]     buffer    Destination buffer.
 * @param [in,out]  out_size  On success, total blob size.
 * @return WH_ERROR_OK on success, WH_ERROR_BUFFER_SIZE if max_size is too
 *         small, WH_ERROR_BADARGS otherwise. */
#ifndef WOLFSSL_LMS_VERIFY_ONLY
int wh_Crypto_LmsSerializeKey(LmsKey* key, uint16_t max_size, uint8_t* buffer,
                              uint16_t* out_size);
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

/* Restore an LmsKey from a byte sequence.
 *
 * @param [in]      buffer  Source blob.
 * @param [in]      size    Blob size in bytes.
 * @param [in,out]  key     Initialized LmsKey to populate.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on malformed blob. */
int wh_Crypto_LmsDeserializeKey(const uint8_t* buffer, uint16_t size,
                                LmsKey* key);

/* Store the public half of an LmsKey (parameter set + public key, no private
 * state) into a byte sequence. Produces a public-only slot blob (privLen == 0)
 * suitable for importing a verify-only key. */
int wh_Crypto_LmsSerializePubKey(LmsKey* key, uint16_t max_size,
                                 uint8_t* buffer, uint16_t* out_size);
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
/* The private-key serializers are unavailable in verify-only builds. */
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Store an XmssKey (param string + public key + secret state) into a byte
 * sequence. */
int wh_Crypto_XmssSerializeKey(XmssKey* key, const char* paramStr,
                               uint16_t max_size, uint8_t* buffer,
                               uint16_t* out_size);

/* Write the header, parameter string, and public key of an XmssKey slot blob,
 * leaving the trailing privLen-byte private-key region untouched. Used by the
 * keygen path: wolfCrypt hands the private key to a write callback and then
 * zeroizes key->sk, so the secret state is written by that callback and only
 * the public portion is filled in here. out_size returns the full blob length
 * including the private-key region. */
int wh_Crypto_XmssSerializeKeyNoPriv(XmssKey* key, const char* paramStr,
                                     uint16_t privLen, uint16_t max_size,
                                     uint8_t* buffer, uint16_t* out_size);
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

/* Restore an XmssKey from a byte sequence */
int wh_Crypto_XmssDeserializeKey(const uint8_t* buffer, uint16_t size,
                                 XmssKey* key);

/* Store the public half of an XmssKey (param string + public key, no secret
 * state) into a byte sequence. Produces a public-only slot blob
 * (privLen == 0) suitable for importing a verify-only key. */
int wh_Crypto_XmssSerializePubKey(XmssKey* key, const char* paramStr,
                                  uint16_t max_size, uint8_t* buffer,
                                  uint16_t* out_size);
#endif /* WOLFSSL_HAVE_XMSS */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_WH_CRYPTO_H_ */
