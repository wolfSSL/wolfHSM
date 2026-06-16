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
/* Size of the fixed header at the start of a stateful-sig (LMS/XMSS) slot blob:
 * magic(4) + pubLen(2) + privLen(2) + paramLen(2) + reserved(2). Shared so the
 * server bridge can locate the variable-length sections that follow it. The
 * full blob layout is documented in wh_crypto.c. */
#define WH_CRYPTO_STATEFUL_SIG_HEADER_SZ 12

/* Returns 1 if buffer begins with an LMS/XMSS stateful-sig slot-blob magic,
 * else 0. Used to reject client attempts to import (and thereby roll back)
 * stateful private key state through the generic keystore/NVM paths. Only the
 * on-HSM keygen may produce these blobs. */
int wh_Crypto_IsStatefulSigBlob(const uint8_t* buffer, uint16_t size);
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */

#ifdef WOLFSSL_HAVE_LMS
/* Store an LmsKey (parameter set + public key + priv_raw) into a byte
 * sequence.
 *
 * @param [in]      key       LmsKey to serialize.
 * @param [in]      max_size  Capacity of buffer in bytes.
 * @param [out]     buffer    Destination buffer.
 * @param [in,out]  out_size  On success, total blob size.
 * @return WH_ERROR_OK on success, WH_ERROR_BUFFER_SIZE if max_size is too
 *         small, WH_ERROR_BADARGS otherwise. */
int wh_Crypto_LmsSerializeKey(LmsKey* key, uint16_t max_size, uint8_t* buffer,
                              uint16_t* out_size);

/* Restore an LmsKey from a byte sequence.
 *
 * @param [in]      buffer  Source blob.
 * @param [in]      size    Blob size in bytes.
 * @param [in,out]  key     Initialized LmsKey to populate.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on malformed blob. */
int wh_Crypto_LmsDeserializeKey(const uint8_t* buffer, uint16_t size,
                                LmsKey* key);
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
/* Store an XmssKey (param string + public key + secret state) into a byte
 * sequence. */
int wh_Crypto_XmssSerializeKey(XmssKey* key, const char* paramStr,
                               uint16_t max_size, uint8_t* buffer,
                               uint16_t* out_size);

/* Restore an XmssKey from a byte sequence */
int wh_Crypto_XmssDeserializeKey(const uint8_t* buffer, uint16_t size,
                                 XmssKey* key);
#endif /* WOLFSSL_HAVE_XMSS */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_WH_CRYPTO_H_ */
