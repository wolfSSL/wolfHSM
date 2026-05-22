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
 * wolfhsm/wh_client_crypto.h
 */

#ifndef WOLFHSM_WH_CLIENT_CRYPTO_H_
#define WOLFHSM_WH_CLIENT_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>
#include <stdbool.h>

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"

/* Component includes */
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#include "wolfssl/wolfcrypt/hmac.h"

/**
 * @brief Generate random bytes
 *
 * This function requests the server to generate random bytes by repeatedly
 * requesting the maximum block size of data from the server at a time
 *
 * @param[in] ctx Pointer to the client context
 * @param[out] out Pointer to where the bytes are to be placed. Must not be
 *                 NULL.
 * @param[in] size Number of bytes to generate.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size);

/**
 * @brief Async request half of a non-DMA RNG generate.
 *
 * Serializes and sends a request for size bytes of random data. Does NOT wait
 * for a reply. Single-shot per call: chunking large requests is the caller's
 * responsibility. The blocking wrapper wh_Client_RngGenerate handles chunking
 * automatically.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_RngGenerateResponse before
 * issuing any other async Request on the same ctx.
 *
 * @param[in] ctx  Client context.
 * @param[in] size Number of random bytes to request. Must be > 0 and must not
 *                 exceed WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or a size
 *         exceeding the per-call inline capacity, or a negative error from the
 *         transport.
 */
int wh_Client_RngGenerateRequest(whClientContext* ctx, uint32_t size);

/**
 * @brief Async response half of a non-DMA RNG generate.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, copies up to *inout_size random bytes into out and
 * updates *inout_size to the actual number received.
 *
 * @param[in]     ctx        Client context.
 * @param[out]    out        Buffer to receive random bytes. May be NULL only if
 *                           *inout_size is 0.
 * @param[in,out] inout_size On entry: capacity of out (typically equals the
 *                           size passed to wh_Client_RngGenerateRequest). On
 *                           success: number of bytes actually written to out.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_ABORTED if the server returned more bytes than the buffer
 *         can hold, WH_ERROR_BADARGS for invalid args.
 */
int wh_Client_RngGenerateResponse(whClientContext* ctx, uint8_t* out,
                                  uint32_t* inout_size);

#ifdef WOLFHSM_CFG_DMA
/**
 * @brief Generate random bytes using DMA
 *
 * This function requests the server to generate random bytes directly into
 * client memory using DMA, eliminating the need for chunking and copying
 * through the communication buffer.
 *
 * @param[in] ctx Pointer to the client context
 * @param[out] out Pointer to where the bytes are to be placed
 * @param[in] size Number of bytes to generate
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_RngGenerateDma(whClientContext* ctx, uint8_t* out, uint32_t size);

/**
 * @brief Async request half of a DMA RNG generate.
 *
 * Performs PRE address translation for the output buffer, sends the DMA
 * request, and stashes the translated address for POST cleanup in the
 * matching Response. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_RngGenerateDmaResponse
 * before issuing any other async Request on the same ctx, and must keep out
 * valid until the Response completes.
 *
 * @param[in]  ctx  Client context.
 * @param[out] out  Client buffer that will receive the random bytes via DMA.
 * @param[in]  size Number of random bytes to generate. Must be > 0.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args, or a
 *         negative error from the DMA layer or transport. On failure any
 *         acquired DMA mapping is released before returning.
 */
int wh_Client_RngGenerateDmaRequest(whClientContext* ctx, uint8_t* out,
                                    uint32_t size);

/**
 * @brief Async response half of a DMA RNG generate.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. The random bytes are written by the server directly to the
 * client buffer passed to wh_Client_RngGenerateDmaRequest. POST DMA cleanup
 * for the output buffer is performed on every non-NOTREADY return so the
 * client buffer is safe to read regardless of error.
 */
int wh_Client_RngGenerateDmaResponse(whClientContext* ctx);
#endif /* WOLFHSM_CFG_DMA */

#ifdef HAVE_CURVE25519
/**
 * @brief Associates a Curve25519 key with a specific key ID.
 *
 * This function sets the device context of a Curve25519 key to the specified
 * key ID. On the server side, this key ID is used to reference the key stored
 * in the HSM
 *
 * @param[in] key Pointer to the Curve25519 key structure.
 * @param[in] keyId Key ID to be associated with the Curve25519 key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Curve25519SetKeyId(curve25519_key* key, whKeyId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a Curve25519 key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyCurve25519.
 *
 * @param[in] key Pointer to the Curve25519 key structure.
 * @param[out] outId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Curve25519GetKeyId(curve25519_key* key, whKeyId* outId);

/**
 * @brief Imports wolfCrypt Curve25519 key as a raw byte array into the
 * wolfHSM server key cache.
 *
 * This function converts the curve25519_key struct to serialized format,
 * installs into the server's key cache, and provides the server-allocated keyId
 * for reference.
 *
 * @param[in] ctx Pointer to the wolfHSM client structure.
 * @param[in] key Pointer to the curve25519 key structure.
 * @param[in,out] inout_keyId Pointer to the key ID. Set to WH_KEYID_ERASED to
 *                  have the server allocate a unique id.  May be NULL.
 * @param[in] flags Value of flags to indicate server usage
 * @param[in] label_len Length of the optional label in bytes, Valid values are
 *              0 to WH_NVM_LABEL_LEN.
 * @param[in] label pointer to the optional label byte array. May be NULL.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Curve25519ImportKey(whClientContext* ctx, curve25519_key* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint16_t label_len, uint8_t* label);

/**
 * @brief Exports a serialized curve25519 key from the wolfHSM server keycache
 * and decodes it into the wolfCrypt curve25519 key structure.
 *
 * This function exports the specified key from wolfHSM server key cache as a
 * serialized byte array and decodes the key into the wolfCrypt curve25519_key
 * structure, optionally copying out the associated label as well.
 *
 * @param[in] ctx Pointer to the wolfHSM client structure.
 * @param[out] out_keyId Server key ID to export.
 * @param[in] key Pointer to the Curve25519 key structure.
 * @param[in] label_len Length of the optional label in bytes, Valid values are
 *              0 to WH_NVM_LABEL_LEN.
 * @param[in] label pointer to the optional label byte array. May be NULL.
 * @return int Returns 0 on success or a negative error code on failure.
 */

int wh_Client_Curve25519ExportKey(whClientContext* ctx, whKeyId keyId,
        curve25519_key* key, uint16_t label_len, uint8_t* label);

/**
 * @brief Exports only the public part of a cached Curve25519 key.
 *
 * Instructs the server to emit only the public portion of a cached
 * Curve25519 key as SubjectPublicKeyInfo DER. The private scalar stays
 * inside the HSM. The decoded key will have only the public part set.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive. The caller is responsible for initializing
 * key (e.g. wc_curve25519_init_ex) prior to calling this function.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized curve25519_key. On
 *                    success, the public portion is populated.
 * @param[in] label_len Size of the optional label buffer in bytes. Values
 *                      larger than WH_NVM_LABEL_LEN are truncated. Set to
 *                      0 if label is not needed.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure (e.g. WH_ERROR_NOTFOUND, WH_ERROR_BADARGS).
 */
int wh_Client_Curve25519ExportPublicKey(whClientContext* ctx, whKeyId keyId,
        curve25519_key* key, uint16_t label_len, uint8_t* label);

/**
 * @brief Generate a Curve25519 key in the server key cache
 *
 * This function requests the server to generate a new Curve25519 key and insert
 * it into the server's key cache.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] size Size of the key to generate in bytes, normally set to
 *                 CURVE25519_KEY_SIZE.
 * @param[in,out] inout_key_id. Set to WH_KEYID_ERASED to have the server
 *                select a unique id for this key.
 * @param[in] flags Optional flags to be associated with the key while in the
 *                  key cache or after being committed. Set to WH_NVM_FLAGS_NONE
 *                  if not used.
 * @param[in] label Optional label to be associated with the key while in the
 *                  key cache or after being committed. Set to NULL if not used.
 * @param[in] label_len Size of the label up to WH_NVM_LABEL_SIZE. Set to 0 if
 *                      not used.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Curve25519MakeCacheKey(whClientContext* ctx,
        uint16_t size,
        whKeyId *inout_key_id, whNvmFlags flags,
        const uint8_t* label, uint16_t label_len);

/**
 * @brief Generate a Curve25519 key by the server and export to the client
 *
 * This function requests the server to generate a new Curve25519 key pair and
 * export it to the client, without using any key cache or additional resources
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] size Size of the key to generate in bytes, normally set to
 *                 CURVE25519_KEY_SIZE.
 * @param[in] key Pointer to a wolfCrypt key structure, which will be
 *                initialized to the new key pair when successful
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Curve25519MakeExportKey(whClientContext* ctx,
        uint16_t size, curve25519_key* key);

/**
 * @brief Compute an X25519 shared secret using a public and private key
 *
 * This function requests the server compute the shared secret using the
 * provided wolfCrypt private and public keys.  Note, the client will
 * temporarily import any missing key material to the server as required.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] priv_key Pointer to a wolfCrypt key structure that holds the
 *                     private key
 * @param[in] pub_key Pointer to a wolfCrypt key structure that holds the
 *                    public key
 * @param[in] endian Endianness of the values.  EC25519_BIG_ENDIAN (typical) or
 *                   EC25519_LITTLE_ENDIAN
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Curve25519SharedSecret(whClientContext* ctx,
        curve25519_key* priv_key, curve25519_key* pub_key,
        int endian, uint8_t* out, uint16_t *out_size);

#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
/**
 * @brief Associates a Ecc key with a specific key ID.
 *
 * This function sets the device context of a Ecc key to the specified
 * key ID. On the server side, this key ID is used to reference the key stored
 * in the HSM
 *
 * @param[in] key Pointer to the Ecc key structure.
 * @param[in] keyId Key ID to be associated with the Ecc key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccSetKeyId(ecc_key* key, whKeyId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a Ecc key that was previously
 * set by either the crypto callback layer or wh_Client_EccSetKeyId.
 *
 * @param[in] key Pointer to the Ecc key structure.
 * @param[out] outId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccGetKeyId(ecc_key* key, whKeyId* outId);

/**
 * @brief Imports a wolfCrypt ECC key as a DER-formatted blob into the wolfHSM
 * server key cache.
 *
 * This function serializes the ecc_key struct to DER format, installs it into
 * the server's key cache, and provides the server-allocated keyId for
 * reference.
 *
 * @param[in] ctx Pointer to the wolfHSM client structure.
 * @param[in] key Pointer to the ECC key structure.
 * @param[in,out] inout_keyId Pointer to the key ID. Set to WH_KEYID_ERASED to
 *                  have the server allocate a unique id.  May be NULL.
 * @param[in] flags Value of flags to indicate server usage
 * @param[in] label_len Length of the optional label in bytes, Valid values are
 *              0 to WH_NVM_LABEL_LEN.
 * @param[in] label pointer to the optional label byte array. May be NULL.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccImportKey(whClientContext* ctx, ecc_key* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint16_t label_len, uint8_t* label);

/**
 * @brief Exports a DER-formatted ECC key from the wolfHSM server keycache and
 * decodes it into the wolfCrypt ECC key structure.
 *
 * This function exports the specified key from the wolfHSM server key cache as
 * a DER blob and decodes it into the wolfCrypt ecc_key structure, optionally
 * copying out the associated label as well.
 *
 * @param[in] ctx Pointer to the wolfHSM client structure.
 * @param[in] keyId Server key ID to export.
 * @param[out] key Pointer to the ECC key structure to populate.
 * @param[in] label_len Length of the optional label in bytes, Valid values are
 *              0 to WH_NVM_LABEL_LEN.
 * @param[out] label pointer to the optional label byte array. May be NULL.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccExportKey(whClientContext* ctx, whKeyId keyId,
        ecc_key* key,
        uint16_t label_len, uint8_t* label);

/**
 * @brief Exports only the public part of a cached ECC key.
 *
 * Instructs the server to emit only the public portion (SubjectPublicKeyInfo
 * DER with curve parameters) of a cached ECC key. The private scalar stays
 * inside the HSM. The decoded key is written into the caller-initialized
 * ecc_key struct and will report type == ECC_PUBLICKEY.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive. The caller is responsible for initializing
 * key (e.g. wc_ecc_init_ex) prior to calling this function.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized ecc_key. On success,
 *                    the public point is populated and key->type is set
 *                    to ECC_PUBLICKEY.
 * @param[in] label_len Size of the optional label buffer in bytes. Values
 *                      larger than WH_NVM_LABEL_LEN are truncated. Set to
 *                      0 if label is not needed.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure (e.g. WH_ERROR_NOTFOUND, WH_ERROR_BADARGS).
 */
 int wh_Client_EccExportPublicKey(whClientContext* ctx, whKeyId keyId,
        ecc_key* key, uint16_t label_len, uint8_t* label);

/**
 * @brief Generate an ECC key pair on the server and export it to the client.
 *
 * This function requests the server to generate a new ECC key pair and export
 * it to the client, without using any key cache or additional resources.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] size Size of the key to generate in bytes (e.g. 32 for P-256).
 * @param[in] curveId wolfCrypt curve identifier (e.g. ECC_SECP256R1).
 * @param[out] key Pointer to a wolfCrypt ECC key structure, which will be
 *                 populated with the new key pair when successful.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccMakeExportKey(whClientContext* ctx,
        int size, int curveId, ecc_key* key);

/**
 * @brief Generate an ECC key pair in the server key cache.
 *
 * This function requests the server to generate a new ECC key pair and insert
 * it into the server's key cache. The generated key material is not returned
 * to the client.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] size Size of the key to generate in bytes (e.g. 32 for P-256).
 * @param[in] curveId wolfCrypt curve identifier (e.g. ECC_SECP256R1).
 * @param[in,out] inout_key_id Pointer to the key ID. Set to WH_KEYID_ERASED to
 *                  have the server allocate a unique id. Must not be NULL.
 * @param[in] flags Optional flags to be associated with the key while in the
 *                  key cache or after being committed. Set to WH_NVM_FLAGS_NONE
 *                  if not used.
 * @param[in] label_len Size of the label up to WH_NVM_LABEL_LEN. Set to 0 if
 *                      not used.
 * @param[in] label Optional label to be associated with the key while in the
 *                  key cache or after being committed. Set to NULL if not used.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccMakeCacheKey(whClientContext* ctx,
        int size, int curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint16_t label_len, uint8_t* label);

/**
 * @brief Compute an ECDH shared secret using a public and private ECC key.
 *
 * This function requests the server to compute the shared secret using the
 * provided wolfCrypt private and public keys. Either key context may carry
 * actual key material or refer to a server-cached key by keyId via its devCtx
 * (associated by wh_Client_EccSetKeyId or returned from a server-side keygen).
 * For any context that does not reference a cached keyId, the client will
 * temporarily import its material to the server for the duration of the
 * operation and evict it afterwards.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] priv_key Pointer to a wolfCrypt key structure that either holds
 *                     the private key material or references a server-cached
 *                     private key via its devCtx (keyId).
 * @param[in] pub_key Pointer to a wolfCrypt key structure that either holds
 *                    the public key material or references a server-cached
 *                    public key via its devCtx (keyId).
 * @param[out] out Buffer to receive the computed shared secret. May be NULL
 *                 to query the required size, in which case inout_size must be
 *                 non-NULL and the required size will be written to
 *                 *inout_size with WH_ERROR_BUFFER_SIZE returned.
 * @param[in,out] inout_size On input, the capacity of the out buffer in bytes
 *                  when out is non-NULL. On output, the number of bytes
 *                  written on success, or the required buffer size when
 *                  WH_ERROR_BUFFER_SIZE is returned. Must not be NULL when
 *                  out is non-NULL; may be NULL only when out is also NULL.
 * @return int Returns 0 on success, WH_ERROR_BUFFER_SIZE if the caller's out
 *             buffer is too small to hold the shared secret (with required
 *             size written to *inout_size), or a negative error code on
 *             failure.
 */
int wh_Client_EccSharedSecret(whClientContext* ctx, ecc_key* priv_key,
                              ecc_key* pub_key, uint8_t* out,
                              uint16_t* inout_size);

/**
 * @brief Generate an ECDSA signature of the provided hash on the server.
 *
 * This function requests the server to sign the provided hash using the
 * specified ECC key. The key context may either carry actual key material or
 * refer to a server-cached key by keyId via its devCtx (associated by
 * wh_Client_EccSetKeyId or returned from a server-side keygen). If the key
 * does not reference a cached keyId, the client will temporarily import its
 * material to the server for the duration of the operation and evict it
 * afterwards.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to a wolfCrypt ECC key structure that either holds
 *                the private key material or references a server-cached
 *                private key via its devCtx (keyId).
 * @param[in] hash Hash data to sign. May be NULL only if hash_len is 0.
 * @param[in] hash_len Length of hash in bytes.
 * @param[out] sig Buffer to receive the generated signature. May be NULL to
 *                 query the required size, in which case inout_sig_len must be
 *                 non-NULL and the required size will be written to
 *                 *inout_sig_len with WH_ERROR_BUFFER_SIZE returned.
 * @param[in,out] inout_sig_len On input, the capacity of the sig buffer in
 *                  bytes when sig is non-NULL. On output, the number of
 *                  bytes written on success, or the required buffer size
 *                  when WH_ERROR_BUFFER_SIZE is returned. Must not be NULL
 *                  when sig is non-NULL; may be NULL only when sig is also
 *                  NULL.
 * @return int Returns 0 on success, WH_ERROR_BUFFER_SIZE if the caller's sig
 *             buffer is too small to hold the signature (with required size
 *             written to *inout_sig_len), or a negative error code on
 *             failure.
 */
int wh_Client_EccSign(whClientContext* ctx,
        ecc_key* key,
        const uint8_t* hash, uint16_t hash_len,
        uint8_t* sig, uint16_t *inout_sig_len);

/**
 * @brief Verify an ECDSA signature of the provided hash on the server.
 *
 * This function requests the server to verify the provided signature against
 * the provided hash using the specified ECC key. The key context may either
 * carry actual key material or refer to a server-cached key by keyId via its
 * devCtx (associated by wh_Client_EccSetKeyId or returned from a server-side
 * keygen). If the key does not reference a cached keyId, the client will
 * temporarily import its material to the server for the duration of the
 * operation and evict it afterwards. If the supplied key is private-only, the
 * server will derive the public key as needed.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to a wolfCrypt ECC key structure that either holds
 *                the public key material or references a server-cached public
 *                key via its devCtx (keyId).
 * @param[in] sig Signature bytes.
 * @param[in] sig_len Length of sig in bytes.
 * @param[in] hash Hash bytes that were signed.
 * @param[in] hash_len Length of hash in bytes.
 * @param[out] out_res Pointer to receive the verification result. Set to 1 if
 *                     the signature is valid, 0 otherwise. Must not be NULL.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_EccVerify(whClientContext* ctx, ecc_key* key,
        const uint8_t* sig, uint16_t sig_len,
        const uint8_t* hash, uint16_t hash_len,
        int *out_res);

/**
 * @brief Async request half of an ECC sign operation.
 *
 * Serializes and sends a sign request for the hash using the server-cached
 * private key identified by keyId. Does NOT wait for a reply. The key must
 * already be cached on the server; auto-import is only available via the
 * blocking wrapper wh_Client_EccSign.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_EccSignResponse before
 * issuing any other async Request on the same ctx.
 *
 * @param[in] ctx      Client context.
 * @param[in] keyId    Key ID of a cached ECC private key. Must not be erased.
 * @param[in] hash     Hash data to sign (may be NULL only if hash_len == 0).
 * @param[in] hash_len Length of hash in bytes.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or erased
 *         keyId, or a negative error from the transport.
 */
int wh_Client_EccSignRequest(whClientContext* ctx, whKeyId keyId,
                             const uint8_t* hash, uint16_t hash_len);

/**
 * @brief Async response half of an ECC sign operation.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, copies the signature into sig and updates
 * *inout_sig_len. If the server-reported signature is larger than the
 * caller's *inout_sig_len capacity, returns WH_ERROR_BUFFER_SIZE with the
 * required size written to *inout_sig_len.
 *
 * @param[in] ctx Client context.
 * @param[out] sig Buffer to receive the generated signature. May be NULL to
 *                 query the required size, in which case inout_sig_len must be
 *                 non-NULL and the required size will be written to
 *                 *inout_sig_len with WH_ERROR_BUFFER_SIZE returned.
 * @param[in,out] inout_sig_len On input, the capacity of the sig buffer in
 *                  bytes when sig is non-NULL. On output, the number of
 *                  bytes written on success, or the required buffer size
 *                  when WH_ERROR_BUFFER_SIZE is returned. Must not be NULL
 *                  when sig is non-NULL; may be NULL only when sig is also
 *                  NULL.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_BUFFER_SIZE if sig is too small (required size written to
 *         *inout_sig_len), WH_ERROR_BADARGS for invalid args, or a negative
 *         error code from the transport.
 */
int wh_Client_EccSignResponse(whClientContext* ctx, uint8_t* sig,
                              uint16_t* inout_sig_len);

/**
 * @brief Async request half of an ECC verify operation.
 *
 * Serializes and sends a verify request for (sig, hash) using the server-cached
 * public key identified by keyId. Does NOT wait for a reply. The key must
 * already be cached on the server; auto-import is only available via the
 * blocking wrapper wh_Client_EccVerify.
 *
 * Note: the async API does not support the EXPORTPUB convenience (deriving
 * a public key from a private-only key) — that stays a blocking-wrapper
 * convenience.
 *
 * @param[in] ctx      Client context.
 * @param[in] keyId    Key ID of a cached ECC public key. Must not be erased.
 * @param[in] sig      Signature bytes.
 * @param[in] sig_len  Length of sig.
 * @param[in] hash     Hash bytes.
 * @param[in] hash_len Length of hash.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or erased
 *         keyId, or a negative error from the transport.
 */
int wh_Client_EccVerifyRequest(whClientContext* ctx, whKeyId keyId,
                               const uint8_t* sig, uint16_t sig_len,
                               const uint8_t* hash, uint16_t hash_len);

/**
 * @brief Async response half of an ECC verify operation.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, writes the verify result (1 = valid, 0 = invalid)
 * to *out_res.
 *
 * @param[in] ctx     Client context.
 * @param[in,out] opt_key Optional ecc_key whose public half should be updated
 *                  from the server-supplied DER bytes when the matching
 *                  Request had EXPORTPUB set. Pass NULL when no key update
 *                  is desired. The async Request half does not currently
 *                  expose EXPORTPUB, so this parameter is primarily for the
 *                  blocking wrapper wh_Client_EccVerify.
 * @param[out] out_res 1 if the signature is valid, 0 otherwise.
 */
int wh_Client_EccVerifyResponse(whClientContext* ctx, ecc_key* opt_key,
                                int* out_res);

/**
 * @brief Async request half of an ECDH shared-secret operation.
 *
 * Serializes and sends a shared-secret request using two server-cached keys
 * (private and public). Does NOT wait for a reply. Both keys must already be
 * cached on the server; auto-import is only available via the blocking
 * wrapper wh_Client_EccSharedSecret.
 *
 * @param[in] ctx        Client context.
 * @param[in] prv_key_id Key ID of the cached private key. Must not be erased.
 * @param[in] pub_key_id Key ID of the cached public key. Must not be erased.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or erased
 *         keyIds, or a negative error from the transport.
 */
int wh_Client_EccSharedSecretRequest(whClientContext* ctx, whKeyId prv_key_id,
                                     whKeyId pub_key_id);

/**
 * @brief Async response half of an ECDH shared-secret operation.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, copies the shared secret into out and updates
 * *inout_size. *inout_size is in/out: when out is non-NULL, callers must
 * initialize it to the capacity of the out buffer. If the server-reported
 * secret is larger than the caller's capacity, returns WH_ERROR_BUFFER_SIZE
 * with the required size written to *inout_size — the partial buffer is NOT
 * written, since truncated key material would be unsafe to use.
 *
 * @param[in] ctx Client context.
 * @param[out] out Buffer to receive the computed shared secret. May be NULL
 *                 to query the required size, in which case inout_size must be
 *                 non-NULL and the required size will be written to
 *                 *inout_size with WH_ERROR_BUFFER_SIZE returned.
 * @param[in,out] inout_size On input, the capacity of the out buffer in bytes
 *                  when out is non-NULL. On output, the number of bytes
 *                  written on success, or the required buffer size when
 *                  WH_ERROR_BUFFER_SIZE is returned. Must not be NULL when
 *                  out is non-NULL; may be NULL only when out is also NULL.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_BUFFER_SIZE if out is too small (required size written to
 *         *inout_size), WH_ERROR_BADARGS for invalid args, or a negative
 *         error code from the transport.
 */
int wh_Client_EccSharedSecretResponse(whClientContext* ctx, uint8_t* out,
                                      uint16_t* inout_size);

/**
 * @brief Async request half of an ECC server-side keygen that caches the new
 * key in the server.
 *
 * Serializes and sends a keygen request that asks the server to generate a new
 * ECC key pair on the specified curve and insert it into the server key cache.
 * Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_EccMakeCacheKeyResponse
 * before issuing any other async Request on the same ctx.
 *
 * @param[in] ctx       Client context.
 * @param[in] size      Size of the key to generate in bytes (e.g. 32 for
 * P-256).
 * @param[in] curveId   wolfCrypt curve identifier (e.g. ECC_SECP256R1).
 * @param[in] key_id    Suggested key ID. Pass WH_KEYID_ERASED to have the
 *                      server allocate one.
 * @param[in] flags     Optional NVM flags. Must NOT include
 *                      WH_NVM_FLAGS_EPHEMERAL — use the MakeExportKey async
 *                      pair for ephemeral (export) keygen instead.
 * @param[in] label_len Size of the label up to WH_NVM_LABEL_LEN. Set to 0 if
 *                      not used.
 * @param[in] label     Optional label byte array. May be NULL when label_len
 *                      is 0.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args (including
 *         EPHEMERAL flag), or a negative error from the transport.
 */
int wh_Client_EccMakeCacheKeyRequest(whClientContext* ctx, int size,
                                     int curveId, whKeyId key_id,
                                     whNvmFlags flags, uint16_t label_len,
                                     uint8_t* label);

/**
 * @brief Async response half of an ECC server-side keygen that caches the new
 * key in the server.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, writes the server-allocated key ID into
 * *out_key_id.
 *
 * @param[in] ctx          Client context.
 * @param[out] out_key_id  Pointer to receive the assigned key ID. Must not be
 *                         NULL.
 */
int wh_Client_EccMakeCacheKeyResponse(whClientContext* ctx,
                                      whKeyId*         out_key_id);

/**
 * @brief Async request half of an ECC server-side keygen that exports the new
 * key back to the client.
 *
 * Serializes and sends an ephemeral keygen request that asks the server to
 * generate a new ECC key pair on the specified curve and return its DER
 * encoding to the client (the server does not retain the key). Does NOT wait
 * for a reply.
 *
 * @param[in] ctx     Client context.
 * @param[in] size    Size of the key to generate in bytes.
 * @param[in] curveId wolfCrypt curve identifier.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args, or a
 *         negative error from the transport.
 */
int wh_Client_EccMakeExportKeyRequest(whClientContext* ctx, int size,
                                      int curveId);

/**
 * @brief Async response half of an ECC server-side keygen that exports the new
 * key back to the client.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, deserializes the DER blob returned by the server
 * into the supplied wolfCrypt ecc_key.
 *
 * @param[in]  ctx Client context.
 * @param[out] key Pointer to a wolfCrypt ECC key structure that will be
 *                 populated with the new key pair. Must not be NULL.
 */
int wh_Client_EccMakeExportKeyResponse(whClientContext* ctx, ecc_key* key);

#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
/**
 * @brief Associates an Ed25519 key with a specific key ID.
 *
 * Sets the device context of an Ed25519 key to the provided key ID.
 */
int wh_Client_Ed25519SetKeyId(ed25519_key* key, whKeyId keyId);

/**
 * @brief Retrieves the key ID from an Ed25519 key device context.
 */
int wh_Client_Ed25519GetKeyId(ed25519_key* key, whKeyId* outId);

/**
 * @brief Import an Ed25519 key into the server keystore/cache.
 */
int wh_Client_Ed25519ImportKey(whClientContext* ctx, ed25519_key* key,
                               whKeyId* inout_keyId, whNvmFlags flags,
                               uint16_t label_len, uint8_t* label);

/**
 * @brief Export an Ed25519 key from the server to the client.
 */
int wh_Client_Ed25519ExportKey(whClientContext* ctx, whKeyId keyId,
                               ed25519_key* key, uint16_t label_len,
                               uint8_t* label);

/**
 * @brief Exports only the public part of a cached Ed25519 key.
 *
 * Instructs the server to emit only the public portion of a cached Ed25519
 * key as SubjectPublicKeyInfo DER. The private seed stays inside the HSM.
 * The decoded key will have pubKeySet == 1 and privKeySet == 0.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive. The caller is responsible for initializing
 * key (e.g. wc_ed25519_init_ex) prior to calling this function.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized ed25519_key. On
 *                    success, only the public half is populated
 *                    (pubKeySet == 1, privKeySet == 0).
 * @param[in] label_len Size of the optional label buffer in bytes. Values
 *                      larger than WH_NVM_LABEL_LEN are truncated. Set to
 *                      0 if label is not needed.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure (e.g. WH_ERROR_NOTFOUND, WH_ERROR_BADARGS).
 */
int wh_Client_Ed25519ExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                     ed25519_key* key, uint16_t label_len,
                                     uint8_t* label);

/**
 * @brief Create a new Ed25519 key on the server and export it without caching.
 */
int wh_Client_Ed25519MakeExportKey(whClientContext* ctx, ed25519_key* key);

/**
 * @brief Create a new Ed25519 key on the server and store it in cache/NVM.
 */
int wh_Client_Ed25519MakeCacheKey(whClientContext* ctx, whKeyId* inout_key_id,
                                  whNvmFlags flags, uint16_t label_len,
                                  uint8_t* label);

/**
 * @brief Sign a message using an Ed25519 key on the server.
 */
int wh_Client_Ed25519Sign(whClientContext* ctx, ed25519_key* key,
                          const uint8_t* msg, uint32_t msgLen, uint8_t type,
                          const uint8_t* context, uint32_t contextLen,
                          uint8_t* sig, uint32_t* inout_sig_len);

/**
 * @brief Verify a message signature using an Ed25519 key on the server.
 */
int wh_Client_Ed25519Verify(whClientContext* ctx, ed25519_key* key,
                            const uint8_t* sig, uint32_t sigLen,
                            const uint8_t* msg, uint32_t msgLen, uint8_t type,
                            const uint8_t* context, uint32_t contextLen,
                            int* out_res);

#ifdef WOLFHSM_CFG_DMA
/**
 * @brief Sign a message using an Ed25519 key via DMA.
 */
int wh_Client_Ed25519SignDma(whClientContext* ctx, ed25519_key* key,
                             const uint8_t* msg, uint32_t msgLen, uint8_t type,
                             const uint8_t* context, uint32_t contextLen,
                             uint8_t* sig, uint32_t* inout_sig_len);

/**
 * @brief Verify a signature using an Ed25519 key via DMA.
 */
int wh_Client_Ed25519VerifyDma(whClientContext* ctx, ed25519_key* key,
                               const uint8_t* sig, uint32_t sigLen,
                               const uint8_t* msg, uint32_t msgLen,
                               uint8_t type, const uint8_t* context,
                               uint32_t contextLen, int* out_res);
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifndef NO_RSA
/**
 * @brief Associates an RSA key with a specific key ID.
 *
 * This function sets the device context of an RSA key to the specified key ID.
 * On the server side, this key ID is used to reference the key stored in the
 * HSM.
 *
 * @param[in] key Pointer to the RSA key structure.
 * @param[in] keyId Key ID to be associated with the RSA key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_RsaSetKeyId(RsaKey* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a RSA key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyRsa.
 *
 * @param[in] key Pointer to the RSA key structure.
 * @param[out] outId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_RsaGetKeyId(RsaKey* key, whNvmId* outId);

/**
 * @brief Imports wolfCrypt RSA key as a PCKS1 DER-formatted file into the
 * wolfHSM server key cache.
 *
 * This function converts the RsaKey struct to DER format, installs into the
 * server's key cache, and provides the server-allocated keyId for reference.
 *
 * @param[in] ctx Pointer to the wolfHSM client structure.
 * @param[in] key Pointer to the RSA key structure.
 * @param[in] flags Value of flags to indicate server usage
 * @param[in] label_len Length of the optional label in bytes, Valid values are
 *              0 to WH_NVM_LABEL_LEN.
 * @param[in] label pointer to the optional label byte array. May be NULL.
 * @param[out] out_keyId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_RsaImportKey(whClientContext* ctx, const RsaKey* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint32_t label_len, uint8_t* label);

/**
 * @brief Exports a PKCS1 DER-formated RSA key from the wolfHSM server keycache
 * and decodes it into the wolfCrypt RSA key structure.
 *
 * This function exports the specified key from wolfHSM server key cache as a
 * PCKS1 DER file and decodes the key into the wolfCrypt RsaKey structure,
 * optionally copying out the associated label as well.
 *
 * @param[in] ctx Pointer to the wolfHSM client structure.
 * @param[out] out_keyId Server key ID to export.
 * @param[in] key Pointer to the RSA key structure.
 * @param[in] label_len Length of the optional label in bytes, Valid values are
 *              0 to WH_NVM_LABEL_LEN.
 * @param[in] label pointer to the optional label byte array. May be NULL.
 * @return int Returns 0 on success or a negative error code on failure.
 */

int wh_Client_RsaExportKey(whClientContext* ctx, whKeyId keyId,
        RsaKey* key, uint32_t label_len, uint8_t* label);

/**
 * @brief Exports only the public part of a cached RSA key.
 *
 * Unlike wh_Client_RsaExportKey(), which returns the full cached key
 * (including private material), this function instructs the server to emit
 * only the public portion as a PKCS#1 DER blob. The private key stays
 * inside the HSM. The decoded key is written into the caller-initialized
 * RsaKey struct and will report type == RSA_PUBLIC.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive.
 *
 * The caller is responsible for initializing key (e.g. wc_InitRsaKey_ex)
 * prior to calling this function.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized RsaKey. On success,
 *                    the modulus and public exponent are populated and
 *                    key->type is set to RSA_PUBLIC.
 * @param[in] label_len Size of the optional label buffer in bytes. Values
 *                      larger than WH_NVM_LABEL_LEN are truncated. Set to
 *                      0 if label is not needed.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure (e.g. WH_ERROR_NOTFOUND, WH_ERROR_BADARGS).
 */
int wh_Client_RsaExportPublicKey(whClientContext* ctx, whKeyId keyId,
        RsaKey* key, uint32_t label_len, uint8_t* label);

/* Generate an RSA key on the server and export it inta an RSA struct */
int wh_Client_RsaMakeExportKey(whClientContext* ctx,
        uint32_t size, uint32_t e, RsaKey* rsa);

/* Generate an RSA key on the server and put it in the server keycache */
int wh_Client_RsaMakeCacheKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whKeyId* inout_key_id, whNvmFlags flags,
        uint32_t label_len, uint8_t* label);

/* TODO: Request server to perform the RSA function */
int wh_Client_RsaFunction(whClientContext* ctx,
        RsaKey* key, int rsa_type,
        const uint8_t* in, uint16_t in_len,
        uint8_t* out, uint16_t *inout_out_len);

/* TODO: Request server to get the RSA size */
int wh_Client_RsaGetSize(whClientContext* ctx,
        const RsaKey* key, int* out_size);

/**
 * @brief Send an async RSA encrypt/decrypt/sign/verify request.
 *
 * The key must already be cached on the server; auto-import is only available
 * via the blocking wrapper wh_Client_RsaFunction. Server-side eviction in the
 * same round trip is also only available via the blocking wrapper — async
 * callers that want the key evicted must pair this with wh_Client_KeyEvict.
 * Only one async request may be in flight per ctx — caller must pair this
 * with a matching Response call before issuing another async request.
 *
 * @param[in] ctx           Client context.
 * @param[in] keyId         Cached RSA key ID. Must not be erased.
 * @param[in] rsa_type      RSA_PUBLIC_ENCRYPT, RSA_PRIVATE_ENCRYPT,
 *                          RSA_PUBLIC_DECRYPT, or RSA_PRIVATE_DECRYPT.
 * @param[in] in            Input bytes (may be NULL only if in_len == 0).
 * @param[in] in_len        Length of in.
 * @param[in] out_capacity  Maximum number of output bytes the server is
 *                          allowed to produce for this operation (forwarded
 *                          as the wc_RsaFunction outLen cap). Typically the
 *                          RSA modulus size in bytes. This is independent of
 *                          the client-side response buffer passed to
 *                          wh_Client_RsaFunctionResponse.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or erased
 *         keyId, or a negative error from the transport.
 */
int wh_Client_RsaFunctionRequest(whClientContext* ctx, whKeyId keyId,
                                 int rsa_type, const uint8_t* in,
                                 uint16_t in_len, uint16_t out_capacity);

/**
 * @brief Receive the reply to an async RSA operation.
 *
 * Single-shot receive: returns WH_ERROR_NOTREADY if no reply yet. On success,
 * copies the output into out and writes the byte count to *inout_out_len. If
 * the output is larger than *inout_out_len, returns WH_ERROR_BUFFER_SIZE with
 * the required size written and out left untouched.
 *
 * @param[in]     ctx           Client context.
 * @param[out]    out           Buffer for the output. May be NULL to discard
 *                              the bytes (the server has already done the
 *                              work — this is not a pre-flight size query).
 *                              If non-NULL, inout_out_len must be non-NULL.
 * @param[in,out] inout_out_len In: capacity of out (when out is non-NULL).
 *                              Out: bytes written, or required size on
 *                              WH_ERROR_BUFFER_SIZE. May be NULL when out is
 *                              NULL to discard the count.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_BUFFER_SIZE if out is too small, WH_ERROR_BADARGS for
 *         invalid args, or a negative error from the transport.
 */
int wh_Client_RsaFunctionResponse(whClientContext* ctx, uint8_t* out,
                                  uint16_t* inout_out_len);

/**
 * @brief Send an async RSA key-size query.
 *
 * The key must already be cached on the server; auto-import is only available
 * via the blocking wrapper wh_Client_RsaGetSize.
 *
 * @param[in] ctx   Client context.
 * @param[in] keyId Cached RSA key ID. Must not be erased.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or erased
 *         keyId, or a negative error from the transport.
 */
int wh_Client_RsaGetSizeRequest(whClientContext* ctx, whKeyId keyId);

/**
 * @brief Receive the reply to an async RSA key-size query.
 *
 * Single-shot receive: returns WH_ERROR_NOTREADY if no reply yet. On success,
 * writes the key size in bytes to *out_size.
 *
 * @param[in]  ctx      Client context.
 * @param[out] out_size Receives the key size in bytes.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_BADARGS for invalid args, or a negative error from the
 *         transport.
 */
int wh_Client_RsaGetSizeResponse(whClientContext* ctx, int* out_size);

/**
 * @brief Ask the server to generate an RSA key and cache it.
 *
 * Rejects WH_NVM_FLAGS_EPHEMERAL — ephemeral keygen belongs to the export
 * pair (wh_Client_RsaMakeExportKey{Request,Response}). Only one async request
 * may be in flight per ctx — caller must pair this with a matching Response
 * call before issuing another.
 *
 * @param[in] ctx       Client context.
 * @param[in] size      RSA modulus size in bits (e.g. 2048).
 * @param[in] e         RSA public exponent (e.g. WC_RSA_EXPONENT).
 * @param[in] key_id    Suggested keyId for the new key, or WH_KEYID_ERASED
 *                      to let the server choose.
 * @param[in] flags     NVM flags (must NOT include WH_NVM_FLAGS_EPHEMERAL).
 * @param[in] label_len Length of the optional label, 0..WH_NVM_LABEL_LEN.
 * @param[in] label     Optional label bytes. May be NULL when label_len == 0.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or
 *         EPHEMERAL flag set, or a negative error from the transport.
 */
int wh_Client_RsaMakeCacheKeyRequest(whClientContext* ctx, uint32_t size,
                                     uint32_t e, whKeyId key_id,
                                     whNvmFlags flags, uint32_t label_len,
                                     uint8_t* label);

/**
 * @brief Receive the reply to an async cache-keygen request.
 *
 * Single-shot receive: returns WH_ERROR_NOTREADY if no reply yet. On success,
 * writes the server-assigned key ID to *out_key_id.
 *
 * @param[in]  ctx        Client context.
 * @param[out] out_key_id Receives the assigned key ID.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_BADARGS for invalid args, or a negative error from the
 *         transport.
 */
int wh_Client_RsaMakeCacheKeyResponse(whClientContext* ctx,
                                      whKeyId*         out_key_id);

/**
 * @brief Ask the server to generate an RSA key and return it as DER.
 *
 * The server does NOT cache the key — it emits it back as a DER blob.
 *
 * @param[in] ctx  Client context.
 * @param[in] size RSA modulus size in bits (e.g. 2048).
 * @param[in] e    RSA public exponent (e.g. WC_RSA_EXPONENT).
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args, or a
 *         negative error from the transport.
 */
int wh_Client_RsaMakeExportKeyRequest(whClientContext* ctx, uint32_t size,
                                      uint32_t e);

/**
 * @brief Receive the reply to an async export-keygen request.
 *
 * Single-shot receive: returns WH_ERROR_NOTREADY if no reply yet. On success,
 * deserializes the returned PKCS#1 DER blob into rsa.
 *
 * @param[in]     ctx Client context.
 * @param[in,out] rsa Caller-initialized RsaKey. Populated with the
 *                    server-generated key material on success.
 * @return WH_ERROR_OK on success, WH_ERROR_NOTREADY if no reply yet,
 *         WH_ERROR_BADARGS for invalid args, or a negative error from the
 *         transport.
 */
int wh_Client_RsaMakeExportKeyResponse(whClientContext* ctx, RsaKey* rsa);


#endif /* !NO_RSA */

#ifdef HAVE_HKDF
/**
 * @brief Generate HKDF output and store in the server key cache
 *
 * This function requests the server to generate HKDF output and store it in
 * the server's key cache. The generated key material is not returned to the
 * client.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] hashType Hash type (WC_SHA256, WC_SHA384, WC_SHA512, etc.)
 * @param[in] keyIdIn Key ID of input key material from cache. Set to
 *                    WH_KEYID_ERASED to use inKey/inKeySz instead.
 * @param[in] inKey Input keying material (can be NULL if keyIdIn is set)
 * @param[in] inKeySz Size of input keying material (must be 0 if using keyIdIn)
 * @param[in] salt Optional salt (can be NULL)
 * @param[in] saltSz Size of salt (0 if NULL)
 * @param[in] info Optional info (can be NULL)
 * @param[in] infoSz Size of info (0 if NULL)
 * @param[in,out] inout_key_id. Set to WH_KEYID_ERASED to have the server
 *                select a unique id for this key.
 * @param[in] flags NVM flags to be associated with the key metadata
 * @param[in] label Label to be associated with the key metadata
 * @param[in] label_len Size of the label up to WH_NVM_LABEL_SIZE. Set to 0 if
 *                      not used.
 * @param[in] outSz Size of key material to generate and cache
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_HkdfMakeCacheKey(whClientContext* ctx, int hashType,
                               whKeyId keyIdIn, const uint8_t* inKey,
                               uint32_t inKeySz, const uint8_t* salt,
                               uint32_t saltSz, const uint8_t* info,
                               uint32_t infoSz, whKeyId* inout_key_id,
                               whNvmFlags flags, const uint8_t* label,
                               uint32_t label_len, uint32_t outSz);

/**
 * @brief Generate HKDF output and export to the client
 *
 * This function requests the server to generate HKDF output and export it to
 * the client, without using any key cache or additional resources
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] hashType Hash type (WC_SHA256, WC_SHA384, WC_SHA512, etc.)
 * @param[in] keyIdIn Key ID of input key material from cache. Set to
 *                    WH_KEYID_ERASED to use inKey/inKeySz instead.
 * @param[in] inKey Input keying material (can be NULL if keyIdIn is set)
 * @param[in] inKeySz Size of input keying material (must be 0 if using keyIdIn)
 * @param[in] salt Optional salt (can be NULL)
 * @param[in] saltSz Size of salt (0 if NULL)
 * @param[in] info Optional info (can be NULL)
 * @param[in] infoSz Size of info (0 if NULL)
 * @param[out] out Output buffer for key material
 * @param[in] outSz Size of output buffer
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_HkdfMakeExportKey(whClientContext* ctx, int hashType,
                                whKeyId keyIdIn, const uint8_t* inKey,
                                uint32_t inKeySz, const uint8_t* salt,
                                uint32_t saltSz, const uint8_t* info,
                                uint32_t infoSz, uint8_t* out, uint32_t outSz);

#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
/**
 * @brief Generate CMAC two-step KDF output and store it in the server cache
 *
 * This function requests the server to run the NIST SP 800-56C two-step CMAC
 * KDF. The derived key material is cached on the server and not returned to the
 * client.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] saltKeyId Key ID of the salt material. Set to WH_KEYID_ERASED to
 *                      use the salt buffer instead.
 * @param[in] salt Pointer to the salt buffer. May be NULL when saltKeyId is
 *                 provided.
 * @param[in] saltSz Size of the salt buffer in bytes.
 * @param[in] zKeyId Key ID of the Z shared secret. Set to WH_KEYID_ERASED to
 *                   use the z buffer instead.
 * @param[in] z Pointer to the shared secret buffer. May be NULL when zKeyId is
 *              provided.
 * @param[in] zSz Size of the shared secret buffer in bytes.
 * @param[in] fixedInfo Optional fixed info buffer (may be NULL).
 * @param[in] fixedInfoSz Size of the fixed info buffer in bytes.
 * @param[in,out] inout_key_id Pointer to the key ID to use or update. Set to
 *                             WH_KEYID_ERASED to have the server allocate one.
 * @param[in] flags NVM flags to associate with the generated key.
 * @param[in] label Optional label metadata to store alongside the key.
 * @param[in] label_len Length of the optional label in bytes.
 * @param[in] outSz Desired size of the derived key material.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CmacKdfMakeCacheKey(whClientContext* ctx, whKeyId saltKeyId,
                                  const uint8_t* salt, uint32_t saltSz,
                                  whKeyId zKeyId, const uint8_t* z,
                                  uint32_t zSz, const uint8_t* fixedInfo,
                                  uint32_t fixedInfoSz, whKeyId* inout_key_id,
                                  whNvmFlags flags, const uint8_t* label,
                                  uint32_t label_len, uint32_t outSz);

/**
 * @brief Generate CMAC two-step KDF output and export to the client
 *
 * This function requests the server to run the NIST SP 800-56C two-step CMAC
 * KDF and return the derived key material directly to the client.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] saltKeyId Key ID of the salt material. Set to WH_KEYID_ERASED to
 *                      use the salt buffer instead.
 * @param[in] salt Pointer to the salt buffer. May be NULL when saltKeyId is
 *                 provided.
 * @param[in] saltSz Size of the salt buffer in bytes.
 * @param[in] zKeyId Key ID of the Z shared secret. Set to WH_KEYID_ERASED to
 *                   use the z buffer instead.
 * @param[in] z Pointer to the shared secret buffer. May be NULL when zKeyId is
 *              provided.
 * @param[in] zSz Size of the shared secret buffer in bytes.
 * @param[in] fixedInfo Optional fixed info buffer (may be NULL).
 * @param[in] fixedInfoSz Size of the fixed info buffer in bytes.
 * @param[out] out Output buffer for the derived key material.
 * @param[in] outSz Size of the output buffer in bytes.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CmacKdfMakeExportKey(whClientContext* ctx, whKeyId saltKeyId,
                                   const uint8_t* salt, uint32_t saltSz,
                                   whKeyId zKeyId, const uint8_t* z,
                                   uint32_t zSz, const uint8_t* fixedInfo,
                                   uint32_t fixedInfoSz, uint8_t* out,
                                   uint32_t outSz);
#endif /* HAVE_CMAC_KDF */

#ifndef NO_AES
/**
 * @brief Associates an AES key with a specific key ID.
 *
 * This function sets the device context of an AES key to the specified key ID.
 * On the server side, this key ID is used to reference the key stored in the
 * HSM
 *
 * @param[in] key Pointer to the AES key structure.
 * @param[in] keyId Key ID to be associated with the AES key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesSetKeyId(Aes* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a AES key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyAes.
 *
 * @param[in] key Pointer to the AES key structure.
 * @param[out] outId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesGetKeyId(Aes* key, whNvmId* outId);

#ifdef WOLFSSL_AES_COUNTER
/**
 * @brief Performs an AES-CTR operation.
 *
 * This function performs an AES-CTR encrypt or decrypt operation on the input
 * data and stores the result in the output buffer.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesCtr(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out);

/**
 * @brief Performs an AES-CTR operation using DMA.
 *
 * This function performs an AES-CTR encrypt or decrypt operation on the input
 * data and stores the result in the output buffer using direct memory access
 * when communicating with the wolfHSM server.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesCtrDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, uint8_t* out);

/**
 * @brief Send an AES-CTR encrypt/decrypt request to the server (non-blocking)
 *
 * Sends a single AES-CTR request to the server. The key material is read from
 * the Aes struct (set via wc_AesSetKey or wh_Client_AesSetKeyId). The counter
 * state (IV register and partial-block remainder) is carried on the Aes
 * struct across the Request/Response boundary; callers must not mutate the
 * Aes struct between the two halves. Use wh_Client_AesCtrResponse to
 * retrieve the result.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesCtrResponse before
 * issuing any other async Request on the same ctx.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] aes Pointer to the AES structure with key and counter state
 * @param[in] enc 1 for encrypt, 0 for decrypt (ignored by CTR, present for API
 *                symmetry with the other modes)
 * @param[in] in  Pointer to the input data (may be NULL only if len == 0)
 * @param[in] len Length of the input data in bytes
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesCtrRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len);

/**
 * @brief Receive the server's AES-CTR response (non-blocking)
 *
 * Retrieves the result of a prior wh_Client_AesCtrRequest call. The counter
 * state (IV register and partial-block remainder) in the Aes struct is
 * updated from the server response so subsequent CTR calls continue from the
 * correct counter. Returns WH_ERROR_NOTREADY if the response is not yet
 * available.
 *
 * @param[in]     ctx      Pointer to the client context
 * @param[in,out] aes      Pointer to the AES structure (counter state updated)
 * @param[out]    out      Pointer to where the output data is placed. Must
 *                         not be NULL.
 * @param[out]    out_size Set to the number of bytes produced. May be NULL.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if the response is not
 *             yet available, or a negative error code on failure.
 */
int wh_Client_AesCtrResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t* out_size);

/**
 * @brief Send an AES-CTR encrypt/decrypt DMA request to the server
 *        (non-blocking)
 *
 * Performs PRE address translation for the input and output buffers, stashes
 * the translated addresses in ctx->dma.asyncCtx.aes for POST cleanup, and
 * sends the DMA request to the server. Does NOT wait for a reply. Caller
 * must keep in and out valid until the matching wh_Client_AesCtrDmaResponse
 * completes.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesCtrDmaResponse before
 * issuing any other async Request on the same ctx.
 *
 * @param[in]  ctx Pointer to the client context
 * @param[in]  aes Pointer to the AES structure with key and counter state
 * @param[in]  enc 1 for encrypt, 0 for decrypt
 * @param[in]  in  Pointer to the input data (may be NULL only if len == 0)
 * @param[in]  len Length of the input data in bytes
 * @param[out] out Pointer to the output buffer
 * @return int Returns 0 on success, WH_ERROR_REQUEST_PENDING if the
 *             transport is still busy with a prior request, or a negative
 *             error code on failure. On failure any acquired DMA mapping is
 *             released before returning.
 */
int wh_Client_AesCtrDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out);

/**
 * @brief Receive the server's AES-CTR DMA response (non-blocking)
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. The output data is written by the server directly to the
 * client buffer passed to wh_Client_AesCtrDmaRequest. POST DMA cleanup for
 * both input and output buffers is performed on every non-NOTREADY return
 * so the client buffer is safe to read regardless of error. The counter
 * state on the Aes struct is updated on success.
 */
int wh_Client_AesCtrDmaResponse(whClientContext* ctx, Aes* aes);
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
/**
 * @brief Performs an AES-ECB operation.
 *
 * This function performs an AES-ECB encrypt or decrypt operation on the input
 * data and stores the result in the output buffer.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesEcb(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out);

/**
 * @brief Performs an AES-ECB operation using DMA.
 *
 * This function performs an AES-ECB encrypt or decrypt operation on the input
 * data and stores the result in the output buffer using direct memory access
 * when communicating with the wolfHSM server.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesEcbDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, uint8_t* out);

/**
 * @brief Send an AES-ECB encrypt/decrypt request to the server (non-blocking)
 *
 * Sends a single AES-ECB request to the server. The key material is read
 * from the Aes struct (set via wc_AesSetKey or wh_Client_AesSetKeyId). Use
 * wh_Client_AesEcbResponse to retrieve the result.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesEcbResponse before
 * issuing any other async Request on the same ctx. As a special case,
 * len == 0 is a no-op: this function returns WH_ERROR_OK without sending,
 * and the caller MUST NOT call wh_Client_AesEcbResponse afterwards (no
 * response will arrive).
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] aes Pointer to the AES structure with key state
 * @param[in] enc 1 for encrypt, 0 for decrypt
 * @param[in] in  Pointer to the input data (must be block-aligned)
 * @param[in] len Length of the input data in bytes (must be a multiple of
 *                AES_BLOCK_SIZE)
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesEcbRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len);

/**
 * @brief Receive the server's AES-ECB response (non-blocking)
 *
 * Retrieves the result of a prior wh_Client_AesEcbRequest call. Returns
 * WH_ERROR_NOTREADY if the response is not yet available.
 *
 * @param[in]  ctx      Pointer to the client context
 * @param[in]  aes      Pointer to the AES structure
 * @param[out] out      Pointer to where the output data is placed. Must not
 *                      be NULL.
 * @param[out] out_size Set to the number of bytes produced. May be NULL.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if the response is
 *             not yet available, or a negative error code on failure.
 */
int wh_Client_AesEcbResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t* out_size);

/**
 * @brief Send an AES-ECB DMA request to the server (non-blocking)
 *
 * Performs PRE address translation for the input and output buffers, stashes
 * the translated addresses in ctx->dma.asyncCtx.aes for POST cleanup, and
 * sends the DMA request to the server. Does NOT wait for a reply. Caller
 * must keep in and out valid until the matching wh_Client_AesEcbDmaResponse
 * completes.
 *
 * @return int Returns 0 on success, WH_ERROR_REQUEST_PENDING if the
 *             transport is still busy with a prior request, or a negative
 *             error code on failure. On failure any acquired DMA mapping is
 *             released before returning.
 */
int wh_Client_AesEcbDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out);

/**
 * @brief Receive the server's AES-ECB DMA response (non-blocking)
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. The output data is written by the server directly to the
 * client buffer passed to wh_Client_AesEcbDmaRequest. POST DMA cleanup for
 * both input and output buffers is performed on every non-NOTREADY return
 * so the client buffer is safe to read regardless of error.
 */
int wh_Client_AesEcbDmaResponse(whClientContext* ctx, Aes* aes);
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
/**
 * @brief Performs an AES-CBC operation.
 *
 * This function performs an AES-CBC encrypt or decrypt operation on the input
 * data and stores the result in the output buffer.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesCbc(whClientContext* ctx,
        Aes* aes, int enc,
        const uint8_t* in, uint32_t len,
        uint8_t* out);

/**
 * @brief Performs an AES-CBC operation using DMA.
 *
 * This function performs an AES-CBC encrypt or decrypt operation on the input
 * data and stores the result in the output buffer using direct memory access
 * when communicating with the wolfHSM server.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesCbcDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, uint8_t* out);

/**
 * @brief Send an AES-CBC encrypt/decrypt request to the server (non-blocking)
 *
 * Sends a single AES-CBC request to the server. The key material is read from
 * the Aes struct (set via wc_AesSetKey or wh_Client_AesSetKeyId). The IV state
 * on the Aes struct is updated only after the matching wh_Client_AesCbcResponse
 * succeeds; a failed Request leaves aes->reg unchanged so callers can retry.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesCbcResponse before
 * issuing any other async Request on the same ctx. As a special case,
 * len == 0 is a no-op: this function returns WH_ERROR_OK without sending,
 * and the caller MUST NOT call wh_Client_AesCbcResponse afterwards (no
 * response will arrive).
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] aes Pointer to the AES structure with key and IV state
 * @param[in] enc 1 for encrypt, 0 for decrypt
 * @param[in] in Pointer to the input data (must be block-aligned)
 * @param[in] len Length of the input data in bytes (must be a multiple of
 *                AES_BLOCK_SIZE)
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesCbcRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len);

/**
 * @brief Receive the server's AES-CBC response (non-blocking)
 *
 * Retrieves the result of a prior wh_Client_AesCbcRequest call. For
 * encryption, the IV in the Aes struct is updated with the last ciphertext
 * block for CBC chaining. Returns WH_ERROR_NOTREADY if the response is not
 * yet available.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in,out] aes Pointer to the AES structure (IV updated on encrypt)
 * @param[out] out Pointer to where the output data is placed. Must not be NULL.
 * @param[out] out_size Set to the number of bytes produced. May be NULL.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if the response is not
 *             yet available, or a negative error code on failure.
 */
int wh_Client_AesCbcResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t* out_size);

/**
 * @brief Send an AES-CBC DMA request to the server (non-blocking)
 *
 * Performs PRE address translation for the input and output buffers, stashes
 * the translated addresses in ctx->dma.asyncCtx.aes for POST cleanup, and
 * sends the DMA request to the server. Does NOT wait for a reply. Caller
 * must keep in and out valid until the matching wh_Client_AesCbcDmaResponse
 * completes.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesCbcDmaResponse before
 * issuing any other async Request on the same ctx.
 *
 * @return int Returns 0 on success, WH_ERROR_REQUEST_PENDING if the
 *             transport is still busy with a prior request, or a negative
 *             error code on failure. On failure any acquired DMA mapping is
 *             released before returning.
 */
int wh_Client_AesCbcDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out);

/**
 * @brief Receive the server's AES-CBC DMA response (non-blocking)
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. The output data is written by the server directly to the
 * client buffer passed to wh_Client_AesCbcDmaRequest; the updated IV is
 * returned inline and copied back onto the Aes struct for CBC chaining.
 * POST DMA cleanup for both input and output buffers is performed on every
 * non-NOTREADY return so the client buffer is safe to read regardless of
 * error.
 */
int wh_Client_AesCbcDmaResponse(whClientContext* ctx, Aes* aes);
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
/**
 * @brief Performs an AES-GCM operation.
 *
 * This function performs an AES-GCM encrypt or decrypt operation on the input
 * data and stores the result in the output buffer.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[in] iv Pointer to the IV data.
 * @param[in] iv_len Length of the IV data in bytes.
 * @param[in] authin Pointer to the authentication data.
 * @param[in] authin_len Length of the authentication data in bytes.
 * @param[in] dec_tag Pointer to the decryption tag data.
 * @param[in] enc_tag Pointer to the encryption tag data.
 * @param[in] tag_len Length of the tag data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesGcm(whClientContext* ctx,
        Aes* aes, int enc,
        const uint8_t* in, uint32_t len,
        const uint8_t* iv, uint32_t iv_len,
        const uint8_t* authin, uint32_t authin_len,
        const uint8_t* dec_tag, uint8_t* enc_tag, uint32_t tag_len,
        uint8_t* out);

/**
 * @brief Performs an AES-GCM operation using DMA.
 *
 * This function performs an AES-GCM encrypt or decrypt operation on the input
 * data and stores the result in the output buffer using direct memory access
 * when communicating with the wolfHSM server.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] aes Pointer to the AES structure.
 * @param[in] enc 1 for encrypt, 0 for decrypt.
 * @param[in] in Pointer to the input data.
 * @param[in] len Length of the input and output data in bytes.
 * @param[in] iv Pointer to the IV data.
 * @param[in] iv_len Length of the IV data in bytes.
 * @param[in] authin Pointer to the authentication data.
 * @param[in] authin_len Length of the authentication data in bytes.
 * @param[in] dec_tag Pointer to the decryption tag data.
 * @param[in] enc_tag Pointer to the encryption tag data.
 * @param[in] tag_len Length of the tag data in bytes.
 * @param[out] out Pointer to the output data.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesGcmDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, const uint8_t* iv,
                        uint32_t iv_len, const uint8_t* authin,
                        uint32_t authin_len, const uint8_t* dec_tag,
                        uint8_t* enc_tag, uint32_t tag_len, uint8_t* out);

/**
 * @brief Send an AES-GCM encrypt/decrypt request to the server (non-blocking)
 *
 * Sends a single AES-GCM request to the server. The key material is read
 * from the Aes struct (set via wc_AesSetKey or wh_Client_AesSetKeyId). The
 * ciphertext, AAD, and decrypt tag (if any) are inlined in the request. Use
 * wh_Client_AesGcmResponse to retrieve the output ciphertext/plaintext and
 * (for encrypt) the auth tag.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesGcmResponse before
 * issuing any other async Request on the same ctx.
 *
 * @param[in] ctx        Pointer to the client context
 * @param[in] aes        Pointer to the AES structure with key state
 * @param[in] enc        1 for encrypt, 0 for decrypt
 * @param[in] in         Pointer to the input data (may be NULL only if
 *                       len == 0)
 * @param[in] len        Length of the input data in bytes
 * @param[in] iv         Pointer to the IV (may be NULL only if iv_len == 0)
 * @param[in] iv_len     Length of the IV in bytes
 * @param[in] authin     Pointer to the AAD (may be NULL only if
 *                       authin_len == 0)
 * @param[in] authin_len Length of the AAD in bytes
 * @param[in] dec_tag    For decrypt: pointer to the expected auth tag (NULL
 *                       only if enc == 1). Ignored for encrypt.
 * @param[in] tag_len    Length of the auth tag in bytes
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_AesGcmRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len, const uint8_t* iv,
                            uint32_t iv_len, const uint8_t* authin,
                            uint32_t authin_len, const uint8_t* dec_tag,
                            uint32_t tag_len);

/**
 * @brief Receive the server's AES-GCM response (non-blocking)
 *
 * Retrieves the result of a prior wh_Client_AesGcmRequest call. For encrypt,
 * the auth tag is copied into enc_tag. Returns WH_ERROR_NOTREADY if the
 * response is not yet available. For decrypt, a failing tag comparison is
 * surfaced as a negative error from the server (AES_GCM_AUTH_E).
 *
 * @param[in]  ctx          Pointer to the client context
 * @param[in]  aes          Pointer to the AES structure
 * @param[out] out          Pointer to where the output data is placed. May be
 *                          NULL for GMAC (tag-only) operations, in which case
 *                          out_capacity must be 0.
 * @param[in]  out_capacity Capacity of the out buffer in bytes. If the server
 *                          reports a larger payload, the call returns
 *                          WH_ERROR_ABORTED instead of writing past out.
 * @param[out] out_size     Set to the number of bytes produced. May be NULL.
 * @param[out] enc_tag      For encrypt: buffer to receive the auth tag.
 *                          Ignored for decrypt (may be NULL).
 * @param[in]  tag_len      Length of the enc_tag buffer in bytes.
 * @return int Returns 0 on success, WH_ERROR_NOTREADY if the response is
 *             not yet available, WH_ERROR_ABORTED if the server's reported
 *             payload size exceeds out_capacity, or a negative error code on
 *             failure.
 */
int wh_Client_AesGcmResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t out_capacity, uint32_t* out_size,
                             uint8_t* enc_tag, uint32_t tag_len);

/**
 * @brief Send an AES-GCM DMA request to the server (non-blocking)
 *
 * Performs PRE address translation for the input, output, and AAD buffers,
 * stashes the translated addresses in ctx->dma.asyncCtx.aes for POST
 * cleanup, and sends the DMA request to the server. Does NOT wait for a
 * reply. The IV, auth tag (for decrypt), and key are passed inline. Caller
 * must keep in, out, and authin valid until the matching
 * wh_Client_AesGcmDmaResponse completes.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_AesGcmDmaResponse before
 * issuing any other async Request on the same ctx.
 *
 * @return int Returns 0 on success, WH_ERROR_REQUEST_PENDING if the
 *             transport is still busy with a prior request, or a negative
 *             error code on failure. On failure any acquired DMA mapping is
 *             released before returning.
 */
int wh_Client_AesGcmDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out,
                               const uint8_t* iv, uint32_t iv_len,
                               const uint8_t* authin, uint32_t authin_len,
                               const uint8_t* dec_tag, uint32_t tag_len);

/**
 * @brief Receive the server's AES-GCM DMA response (non-blocking)
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. The output data is written by the server directly to the
 * client buffer passed to wh_Client_AesGcmDmaRequest; for encrypt the auth
 * tag is returned inline and copied into enc_tag. POST DMA cleanup for
 * input, output, and AAD buffers is performed on every non-NOTREADY return.
 *
 * @param[in]  ctx     Pointer to the client context
 * @param[in]  aes     Pointer to the AES structure
 * @param[out] enc_tag For encrypt: buffer to receive the auth tag. Ignored
 *                     for decrypt (may be NULL).
 * @param[in]  tag_len Length of the enc_tag buffer in bytes.
 */
int wh_Client_AesGcmDmaResponse(whClientContext* ctx, Aes* aes,
                                uint8_t* enc_tag, uint32_t tag_len);
#endif /* HAVE_AESGCM */

#endif /* !NO_AES */


#ifdef WOLFSSL_CMAC

/**
 * @brief Performs a CMAC operation on the input data.
 *
 * This function performs a CMAC operation with the specified parameters.
 * It can be used for initialization, update, or finalization of CMAC
 * operations, depending on the input arguments.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in,out] cmac Pointer to the CMAC structure.
 * @param[in] type The type of CMAC operation.
 * @param[in] key Pointer to the key buffer, or NULL if using a key stored in
 * HSM.
 * @param[in] keyLen Length of the key in bytes.
 * @param[in] in Pointer to the input data buffer, or NULL for finalization.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] outMac Pointer to the output buffer for the CMAC tag.
 * @param[in,out] outMacLen Pointer to the size of the output buffer, updated
 * with actual size.
 * @return int Returns WH_ERROR_OK (0) on success, or a negative error code on
 * failure.
 */
int wh_Client_Cmac(whClientContext* ctx, Cmac* cmac, CmacType type,
                   const uint8_t* key, uint32_t keyLen, const uint8_t* in,
                   uint32_t inLen, uint8_t* outMac, uint32_t* outMacLen);

/**
 * @brief Async request half of a non-DMA CMAC oneshot generate.
 *
 * Serializes and sends a single request that performs init + update + final
 * on the server in one round trip. The server returns the MAC in the matching
 * Response. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_CmacGenerateResponse before
 * issuing any other async Request on the same ctx. Any existing streaming
 * state in the cmac struct is silently reset — this is a oneshot, equivalent
 * to wc_AesCmacGenerate_ex.
 *
 * @param[in] ctx       Client context.
 * @param[in,out] cmac  CMAC context (type and non-HSM key bytes are cached on
 *                      success).
 * @param[in] type      CMAC type (e.g., WC_CMAC_AES).
 * @param[in] key       Inline key bytes, or NULL if using a cached/HSM key.
 * @param[in] keyLen    Key length in bytes (0 if using a cached/HSM key).
 * @param[in] in        Input data. Must not be NULL.
 * @param[in] inLen     Input length. Must be > 0 and must not exceed
 *                      WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_GENERATE_SZ.
 * @param[in] outMacLen Requested MAC length in bytes. Must be > 0.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS for invalid args or
 *         oversize input, or a negative error from the transport. On any
 *         error the cmac struct is left unchanged.
 */
int wh_Client_CmacGenerateRequest(whClientContext* ctx, Cmac* cmac,
                                  CmacType type, const uint8_t* key,
                                  uint32_t keyLen, const uint8_t* in,
                                  uint32_t inLen, uint32_t outMacLen);

/**
 * @brief Async response half of a non-DMA CMAC oneshot generate.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, restores state from the response, copies the MAC
 * into outMac (truncated to *outMacLen) and updates *outMacLen to the actual
 * number of bytes written.
 */
int wh_Client_CmacGenerateResponse(whClientContext* ctx, Cmac* cmac,
                                   uint8_t* outMac, uint32_t* outMacLen);

/**
 * @brief Async request half of a non-DMA CMAC streaming Update.
 *
 * Serializes and sends an Update request carrying inLen bytes of inline
 * input plus the full CMAC state (digest + buffer + bookkeeping) via
 * resumeState. The server runs wc_CmacUpdate against the round-tripped
 * state, so all partial-block accounting happens server-side and the
 * post-Update state is returned in the matching Response. Does NOT wait
 * for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext (enforced by the comm layer). If *requestSent is true, the
 * caller MUST call wh_Client_CmacUpdateResponse before issuing any other
 * async Request on the same ctx.
 *
 * Key handling: if key/keyLen are provided, the bytes are cached client-side
 * so subsequent Update/Final calls can replay them. If using an HSM-cached
 * key, set it via wh_Client_CmacSetKeyId before the first Update and pass
 * NULL / 0 for key/keyLen.
 *
 * @param[in] ctx          Client context.
 * @param[in,out] cmac     CMAC context (full state round-tripped on success,
 *                         type and cached key bytes updated on SendRequest
 *                         success).
 * @param[in] type         CMAC type (written to cmac->type on success).
 * @param[in] key          Optional inline key bytes (NULL for cached/HSM key).
 * @param[in] keyLen       Key length in bytes (must not exceed
 *                         AES_256_KEY_SIZE; 0 for cached/HSM key).
 * @param[in] in           Input data (may be NULL only if inLen == 0).
 * @param[in] inLen        Input length. Must fit in the comm buffer alongside
 *                         the request header and key bytes.
 * @param[out] requestSent Set to true if a server request was sent and a
 *                         matching Response call is required; false only
 *                         when inLen == 0 and keyLen == 0 (no-op).
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on invalid arguments or
 *         when inLen exceeds the per-call capacity.
 */
int wh_Client_CmacUpdateRequest(whClientContext* ctx, Cmac* cmac, CmacType type,
                                const uint8_t* key, uint32_t keyLen,
                                const uint8_t* in, uint32_t inLen,
                                bool* requestSent);

/**
 * @brief Async response half of a non-DMA CMAC streaming Update.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, restores the full CMAC state (buffer, bufferSz,
 * digest, totalSz) from the response — the server may leave a partial or
 * whole block in its buffer after wc_CmacUpdate (CMAC's last block has
 * special handling), so that bookkeeping is round-tripped back to the
 * client. MUST only be called if the matching Request returned
 * requestSent == true.
 */
int wh_Client_CmacUpdateResponse(whClientContext* ctx, Cmac* cmac);

/**
 * @brief Async request half of a non-DMA CMAC streaming Final.
 *
 * Sends a Final request with no inline input — the round-tripped
 * resumeState carries the current cmac->buffer (0..AES_BLOCK_SIZE-1 bytes)
 * as the trailing partial block for the server to finalize. Key material
 * travels with the request when available.
 */
int wh_Client_CmacFinalRequest(whClientContext* ctx, Cmac* cmac);

/**
 * @brief Async response half of a non-DMA CMAC streaming Final.
 *
 * Single-shot RecvResponse. Restores final state from the response, then
 * copies the MAC into outMac (truncated to *outMacLen) and updates
 * *outMacLen.
 */
int wh_Client_CmacFinalResponse(whClientContext* ctx, Cmac* cmac,
                                uint8_t* outMac, uint32_t* outMacLen);


/**
 * @brief Associates a CMAC key with a specific key ID.
 *
 * This function sets the device context of a CMAC key to the specified key ID.
 * On the server side, this key ID is used to reference the key stored in the
 * HSM
 *
 * @param[in] key Pointer to the CMAC key structure.
 * @param[in] keyId Key ID to be associated with the CMAC key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CmacSetKeyId(Cmac* key, whNvmId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a CMAC key that was previously
 * set by either the crypto callback layer or wh_Client_SetKeyCmac.
 *
 * @param[in] key Pointer to the CMAC key structure.
 * @param[out] outId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CmacGetKeyId(Cmac* key, whNvmId* outId);

#ifdef WOLFHSM_CFG_DMA
/**
 * @brief Performs CMAC operations using DMA for data transfer.
 *
 * This function performs CMAC operations (initialize, update, finalize) using
 * DMA for efficient data transfer between client and server. The operation
 * performed depends on which parameters are non-NULL.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in,out] cmac Pointer to the CMAC structure to be used.
 * @param[in] type The type of CMAC operation (e.g., WC_CMAC_AES).
 * @param[in] key Pointer to the key data. NULL if using a stored key.
 * @param[in] keyLen Length of the key in bytes.
 * @param[in] in Pointer to the input data. NULL if not performing an update.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] outMac Pointer to store the CMAC result. NULL if not finalizing.
 * @param[in,out] outMacLen Pointer to the size of the outMac buffer. Updated
 * with actual size on return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_CmacDma(whClientContext* ctx, Cmac* cmac, CmacType type,
                      const uint8_t* key, uint32_t keyLen, const uint8_t* in,
                      uint32_t inLen, uint8_t* outMac, uint32_t* outMacLen);

/**
 * @brief Async request half of a DMA CMAC oneshot generate.
 *
 * Performs PRE address translation for the input buffer, sends the DMA
 * request, and stashes the translated address for POST cleanup in the
 * matching Response. Does NOT wait for a reply. The server processes the
 * oneshot in a single round trip via wc_AesCmacGenerate_ex.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. The caller MUST call wh_Client_CmacGenerateDmaResponse
 * before issuing any other async Request on the same ctx, and must keep in
 * valid until the Response completes. Any existing streaming state in the
 * cmac struct is silently reset — this is a oneshot, equivalent to
 * wc_AesCmacGenerate_ex.
 */
int wh_Client_CmacGenerateDmaRequest(whClientContext* ctx, Cmac* cmac,
                                     CmacType type, const uint8_t* key,
                                     uint32_t keyLen, const uint8_t* in,
                                     uint32_t inLen, uint32_t outMacLen);

/**
 * @brief Async response half of a DMA CMAC oneshot generate.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On any non-NOTREADY exit, performs POST DMA cleanup on the
 * input buffer. On success, copies the MAC into outMac (truncated to
 * *outMacLen), updates *outMacLen, and restores the post-finalization CMAC
 * state (buffer, bufferSz, digest, totalSz) from the response. The AES
 * round key and CMAC subkey material in cmac are NOT reset — callers
 * recycling the cmac struct must reinitialize it via wc_InitCmac_ex.
 */
int wh_Client_CmacGenerateDmaResponse(whClientContext* ctx, Cmac* cmac,
                                      uint8_t* outMac, uint32_t* outMacLen);

/**
 * @brief Async request half of a DMA CMAC streaming Update.
 *
 * Performs PRE address translation for the input buffer, round-trips the
 * full CMAC state to the server via resumeState, and sends every byte of
 * the input via DMA. No client-side partial-block buffering and no inline
 * trailing data — the server runs wc_CmacUpdate against the round-tripped
 * state. Stashes the translated input address for POST cleanup in the
 * matching Response. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext. If *requestSent is true, the caller MUST keep in valid
 * and call wh_Client_CmacDmaUpdateResponse before issuing any other async
 * Request. *requestSent is false only when inLen == 0 and keyLen == 0
 * (no-op).
 */
int wh_Client_CmacDmaUpdateRequest(whClientContext* ctx, Cmac* cmac,
                                   CmacType type, const uint8_t* key,
                                   uint32_t keyLen, const uint8_t* in,
                                   uint32_t inLen, bool* requestSent);

/**
 * @brief Async response half of a DMA CMAC streaming Update.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has
 * not yet replied. On any non-NOTREADY exit, performs POST DMA cleanup
 * for the input buffer. On success, restores the full CMAC state (buffer,
 * bufferSz, digest, totalSz) from the response — including any
 * partial/whole block left in the server's wc_CmacUpdate buffer.
 */
int wh_Client_CmacDmaUpdateResponse(whClientContext* ctx, Cmac* cmac);

/**
 * @brief Async request half of a DMA CMAC streaming Final.
 *
 * Sends a Final request with no DMA addresses and no inline input — the
 * round-tripped resumeState carries the partial-block tail
 * (0..AES_BLOCK_SIZE-1 bytes) for the server to finalize. Key material
 * travels with the request when available.
 */
int wh_Client_CmacDmaFinalRequest(whClientContext* ctx, Cmac* cmac);

/**
 * @brief Async response half of a DMA CMAC streaming Final.
 *
 * Single-shot RecvResponse. Copies the MAC into outMac (truncated to
 * *outMacLen), updates *outMacLen, and restores the post-finalization
 * CMAC state (buffer, bufferSz, digest, totalSz) from the response. The
 * AES round key and CMAC subkey material in cmac are NOT reset — callers
 * recycling the cmac struct must reinitialize it via wc_InitCmac_ex. No
 * DMA cleanup is needed (Final doesn't use DMA addresses).
 */
int wh_Client_CmacDmaFinalResponse(whClientContext* ctx, Cmac* cmac,
                                   uint8_t* outMac, uint32_t* outMacLen);
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_CMAC */

#ifndef NO_SHA256

/**
 * @brief Performs a SHA-256 hash operation on the input data.
         *
 * This function performs a SHA-256 hash operation on the input data and stores
 * the result in the output buffer.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-256 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha256(whClientContext* ctx, wc_Sha256* sha, const uint8_t* in,
                     uint32_t inLen, uint8_t* out);


/**
 * @brief Async request half of a non-DMA SHA-256 Update.
 *
 * Serializes and sends an Update request carrying as many full blocks as
 * fit in the comm buffer (up to WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ
 * bytes), absorbing any leading bytes already buffered in sha->buffer. Any
 * tail (<64 bytes) remaining after this call is stored in sha->buffer for the
 * next call. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext (enforced by the comm layer's pending-request tracking).
 * If *requestSent is true, the caller MUST call wh_Client_Sha256UpdateResponse
 * before issuing any other async Request on the same ctx, including a Request
 * using a different wc_Sha256 instance or a different algorithm.
 *
 * @param[in] ctx          Client context.
 * @param[in,out] sha      SHA-256 context (buffer/buffLen updated on success).
 * @param[in] in           Input data (may be NULL only if inLen == 0).
 * @param[in] inLen        Input length. Must not exceed the per-call capacity
 *                         (max inline + remaining buffer slack); use the
 *                         blocking wrapper for arbitrary lengths.
 * @param[out] requestSent Set to true if a server request was sent and a
 *                         matching Response call is required; false if the
 *                         input was fully absorbed into sha->buffer and no
 *                         round-trip was issued.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if inLen exceeds the
 *         per-call capacity (sha is left unchanged in that case).
 */
int wh_Client_Sha256UpdateRequest(whClientContext* ctx, wc_Sha256* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent);

/**
 * @brief Async response half of a non-DMA SHA-256 Update.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, updates sha->digest/hiLen/loLen from the reply.
 * MUST only be called if the matching Request returned requestSent == true.
 */
int wh_Client_Sha256UpdateResponse(whClientContext* ctx, wc_Sha256* sha);

/**
 * @brief Async request half of a non-DMA SHA-256 Final.
 *
 * Sends the current sha->buffer (0..63 bytes) as the last block.
 */
int wh_Client_Sha256FinalRequest(whClientContext* ctx, wc_Sha256* sha);

/**
 * @brief Async response half of a non-DMA SHA-256 Final.
 *
 * Single-shot RecvResponse. Copies final digest into out, then resets sha
 * state via wc_InitSha256_ex (preserving devId).
 */
int wh_Client_Sha256FinalResponse(whClientContext* ctx, wc_Sha256* sha,
                                  uint8_t* out);

/**
 * @brief Performs a SHA-256 hash operation on the input data using DMA.
 *
 * This function performs a SHA-256 hash operation on the input data and stores
 * the result in the output buffer using DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-256 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha256Dma(whClientContext* ctx, wc_Sha256* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out);

#ifdef WOLFHSM_CFG_DMA
/**
 * @brief Async request half of a DMA SHA-256 Update.
 *
 * Buffers partial blocks on the client. Sends whole blocks via DMA to the
 * server, with any assembled first block (from the partial buffer) as inline
 * trailing data. Sets *requestSent to indicate whether a message was sent
 * (false when all input was absorbed into the partial-block buffer).
 */
int wh_Client_Sha256DmaUpdateRequest(whClientContext* ctx, wc_Sha256* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent);

/**
 * @brief Async response half of a DMA SHA-256 Update.
 *
 * Receives the server response and restores the updated SHA state from the
 * inline response. Runs POST DMA cleanup for the input buffer.
 */
int wh_Client_Sha256DmaUpdateResponse(whClientContext* ctx, wc_Sha256* sha);

/**
 * @brief Async request half of a DMA SHA-256 Final.
 *
 * Sends the partial-block tail as inline data with the resume state. No DMA
 * addresses are used (the final hash is returned inline in the response).
 */
int wh_Client_Sha256DmaFinalRequest(whClientContext* ctx, wc_Sha256* sha);

/**
 * @brief Async response half of a DMA SHA-256 Final.
 *
 * Receives the final hash from the inline response and copies it to out.
 */
int wh_Client_Sha256DmaFinalResponse(whClientContext* ctx, wc_Sha256* sha,
                                     uint8_t* out);
#endif /* WOLFHSM_CFG_DMA */

#endif /* !NO_SHA256 */

#if defined(WOLFSSL_SHA224)
/**
 * @brief Performs a SHA-224 hash operation on the input data.
 *
 * This function performs a SHA-224 hash operation on the input data and stores
 * the result in the output buffer.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-224 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha224(whClientContext* ctx, wc_Sha224* sha, const uint8_t* in,
                     uint32_t inLen, uint8_t* out);

/**
 * @brief Async request half of a non-DMA SHA-224 Update.
 *
 * Serializes and sends an Update request carrying as many full blocks as
 * fit in the comm buffer (up to WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ
 * bytes), absorbing any leading bytes already buffered in sha->buffer. Any
 * tail (<64 bytes) remaining after this call is stored in sha->buffer for the
 * next call. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext (enforced by the comm layer's pending-request tracking).
 * If *requestSent is true, the caller MUST call wh_Client_Sha224UpdateResponse
 * before issuing any other async Request on the same ctx, including a Request
 * using a different wc_Sha224 instance or a different algorithm.
 *
 * @param[in] ctx          Client context.
 * @param[in,out] sha      SHA-224 context (buffer/buffLen updated on success).
 * @param[in] in           Input data (may be NULL only if inLen == 0).
 * @param[in] inLen        Input length. Must not exceed the per-call capacity
 *                         (max inline + remaining buffer slack); use the
 *                         blocking wrapper for arbitrary lengths.
 * @param[out] requestSent Set to true if a server request was sent and a
 *                         matching Response call is required; false if the
 *                         input was fully absorbed into sha->buffer and no
 *                         round-trip was issued.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if inLen exceeds the
 *         per-call capacity (sha is left unchanged in that case).
 */
int wh_Client_Sha224UpdateRequest(whClientContext* ctx, wc_Sha224* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent);

/**
 * @brief Async response half of a non-DMA SHA-224 Update.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, updates sha->digest/hiLen/loLen from the reply.
 * MUST only be called if the matching Request returned requestSent == true.
 */
int wh_Client_Sha224UpdateResponse(whClientContext* ctx, wc_Sha224* sha);

/**
 * @brief Async request half of a non-DMA SHA-224 Final.
 *
 * Sends the current sha->buffer (0..63 bytes) as the last block.
 */
int wh_Client_Sha224FinalRequest(whClientContext* ctx, wc_Sha224* sha);

/**
 * @brief Async response half of a non-DMA SHA-224 Final.
 *
 * Single-shot RecvResponse. Copies final digest into out, then resets sha
 * state via wc_InitSha224_ex (preserving devId).
 */
int wh_Client_Sha224FinalResponse(whClientContext* ctx, wc_Sha224* sha,
                                  uint8_t* out);

/**
 * @brief Performs a SHA-224 hash operation on the input data using DMA.
 *
 * This function performs a SHA-224 hash operation on the input data and stores
 * the result in the output buffer using DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-224 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha224Dma(whClientContext* ctx, wc_Sha224* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out);

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha224DmaUpdateRequest(whClientContext* ctx, wc_Sha224* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent);
int wh_Client_Sha224DmaUpdateResponse(whClientContext* ctx, wc_Sha224* sha);
int wh_Client_Sha224DmaFinalRequest(whClientContext* ctx, wc_Sha224* sha);
int wh_Client_Sha224DmaFinalResponse(whClientContext* ctx, wc_Sha224* sha,
                                     uint8_t* out);
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA224 */

#if defined(WOLFSSL_SHA384)
/**
 * @brief Performs a SHA-384 hash operation on the input data.
 *
 * This function performs a SHA-384 hash operation on the input data and stores
 * the result in the output buffer.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-384 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha384(whClientContext* ctx, wc_Sha384* sha, const uint8_t* in,
                     uint32_t inLen, uint8_t* out);

/**
 * @brief Async request half of a non-DMA SHA-384 Update.
 *
 * Serializes and sends an Update request carrying as many full blocks as
 * fit in the comm buffer (up to WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ
 * bytes), absorbing any leading bytes already buffered in sha->buffer. Any
 * tail (<128 bytes) remaining after this call is stored in sha->buffer for
 * the next call. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext (enforced by the comm layer's pending-request tracking).
 * If *requestSent is true, the caller MUST call wh_Client_Sha384UpdateResponse
 * before issuing any other async Request on the same ctx, including a Request
 * using a different wc_Sha384 instance or a different algorithm.
 *
 * @param[in] ctx          Client context.
 * @param[in,out] sha      SHA-384 context (buffer/buffLen updated on success).
 * @param[in] in           Input data (may be NULL only if inLen == 0).
 * @param[in] inLen        Input length. Must not exceed the per-call capacity
 *                         (max inline + remaining buffer slack); use the
 *                         blocking wrapper for arbitrary lengths.
 * @param[out] requestSent Set to true if a server request was sent and a
 *                         matching Response call is required; false if the
 *                         input was fully absorbed into sha->buffer and no
 *                         round-trip was issued.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if inLen exceeds the
 *         per-call capacity (sha is left unchanged in that case).
 */
int wh_Client_Sha384UpdateRequest(whClientContext* ctx, wc_Sha384* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent);

/**
 * @brief Async response half of a non-DMA SHA-384 Update.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, updates sha->digest/hiLen/loLen from the reply.
 * MUST only be called if the matching Request returned requestSent == true.
 */
int wh_Client_Sha384UpdateResponse(whClientContext* ctx, wc_Sha384* sha);

/**
 * @brief Async request half of a non-DMA SHA-384 Final.
 *
 * Sends the current sha->buffer (0..127 bytes) as the last block.
 */
int wh_Client_Sha384FinalRequest(whClientContext* ctx, wc_Sha384* sha);

/**
 * @brief Async response half of a non-DMA SHA-384 Final.
 *
 * Single-shot RecvResponse. Copies final digest into out, then resets sha
 * state via wc_InitSha384_ex (preserving devId).
 */
int wh_Client_Sha384FinalResponse(whClientContext* ctx, wc_Sha384* sha,
                                  uint8_t* out);

/**
 * @brief Performs a SHA-384 hash operation on the input data using DMA.
 *
 * This function performs a SHA-384 hash operation on the input data and stores
 * the result in the output buffer using DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-384 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha384Dma(whClientContext* ctx, wc_Sha384* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out);

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha384DmaUpdateRequest(whClientContext* ctx, wc_Sha384* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent);
int wh_Client_Sha384DmaUpdateResponse(whClientContext* ctx, wc_Sha384* sha);
int wh_Client_Sha384DmaFinalRequest(whClientContext* ctx, wc_Sha384* sha);
int wh_Client_Sha384DmaFinalResponse(whClientContext* ctx, wc_Sha384* sha,
                                     uint8_t* out);
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_SHA512)
/**
 * @brief Performs a SHA-512 hash operation on the input data.
 *
 * This function performs a SHA-512 hash operation on the input data and stores
 * the result in the output buffer.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-512 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha512(whClientContext* ctx, wc_Sha512* sha, const uint8_t* in,
                     uint32_t inLen, uint8_t* out);

/**
 * @brief Async request half of a non-DMA SHA-512 Update.
 *
 * Serializes and sends an Update request carrying as many full blocks as
 * fit in the comm buffer (up to WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ
 * bytes), absorbing any leading bytes already buffered in sha->buffer. Any
 * tail (<128 bytes) remaining after this call is stored in sha->buffer for
 * the next call. Does NOT wait for a reply.
 *
 * Contract: at most one outstanding async request may be in flight per
 * whClientContext (enforced by the comm layer's pending-request tracking).
 * If *requestSent is true, the caller MUST call wh_Client_Sha512UpdateResponse
 * before issuing any other async Request on the same ctx, including a Request
 * using a different wc_Sha512 instance or a different algorithm.
 *
 * @param[in] ctx          Client context.
 * @param[in,out] sha      SHA-512 context (buffer/buffLen updated on success).
 * @param[in] in           Input data (may be NULL only if inLen == 0).
 * @param[in] inLen        Input length. Must not exceed the per-call capacity
 *                         (max inline + remaining buffer slack); use the
 *                         blocking wrapper for arbitrary lengths.
 * @param[out] requestSent Set to true if a server request was sent and a
 *                         matching Response call is required; false if the
 *                         input was fully absorbed into sha->buffer and no
 *                         round-trip was issued.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS if inLen exceeds the
 *         per-call capacity (sha is left unchanged in that case).
 */
int wh_Client_Sha512UpdateRequest(whClientContext* ctx, wc_Sha512* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent);

/**
 * @brief Async response half of a non-DMA SHA-512 Update.
 *
 * Single-shot RecvResponse; returns WH_ERROR_NOTREADY if the server has not
 * yet replied. On success, updates sha->digest/hiLen/loLen from the reply.
 * MUST only be called if the matching Request returned requestSent == true.
 */
int wh_Client_Sha512UpdateResponse(whClientContext* ctx, wc_Sha512* sha);

/**
 * @brief Async request half of a non-DMA SHA-512 Final.
 *
 * Sends the current sha->buffer (0..127 bytes) as the last block.
 */
int wh_Client_Sha512FinalRequest(whClientContext* ctx, wc_Sha512* sha);

/**
 * @brief Async response half of a non-DMA SHA-512 Final.
 *
 * Single-shot RecvResponse. Copies final digest into out, then resets sha
 * state via wc_InitSha512_ex (preserving devId and hashType).
 */
int wh_Client_Sha512FinalResponse(whClientContext* ctx, wc_Sha512* sha,
                                  uint8_t* out);

/**
 * @brief Performs a SHA-512 hash operation on the input data using DMA.
 *
 * This function performs a SHA-512 hash operation on the input data and stores
 * the result in the output buffer using DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sha Pointer to the SHA-512 context structure.
 * @param[in] in Pointer to the input data.
 * @param[in] inLen Length of the input data in bytes.
 * @param[out] out Pointer to the output buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_Sha512Dma(whClientContext* ctx, wc_Sha512* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out);

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha512DmaUpdateRequest(whClientContext* ctx, wc_Sha512* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent);
int wh_Client_Sha512DmaUpdateResponse(whClientContext* ctx, wc_Sha512* sha);
int wh_Client_Sha512DmaFinalRequest(whClientContext* ctx, wc_Sha512* sha);
int wh_Client_Sha512DmaFinalResponse(whClientContext* ctx, wc_Sha512* sha,
                                     uint8_t* out);
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA512 */

#ifdef WOLFSSL_HAVE_MLDSA

/**
 * @brief Associates a ML-DSA key with a specific key ID.
 *
 * This function sets the device context of a ML-DSA key to the specified
 * key ID. On the server side, this key ID is used to reference the key stored
 * in the HSM
 *
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[in] keyId Key ID to be associated with the ML-DSA key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlDsaSetKeyId(wc_MlDsaKey* key, whKeyId keyId);

/**
 * @brief Gets the wolfHSM keyId being used by the wolfCrypt struct.
 *
 * This function gets the device context of a ML-DSA key that was previously
 * set by either the crypto callback layer or wh_Client_MlDsaSetKeyId.
 *
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[out] outId Pointer to the key ID to return.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlDsaGetKeyId(wc_MlDsaKey* key, whKeyId* outId);

/**
 * @brief Import a ML-DSA key to the server key cache.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] key Pointer to the key to import
 * @param[in,out] inout_keyId Pointer to key ID to use/receive
 * @param[in] flags Flags to control key persistence
 * @param[in] label_len Length of optional label
 * @param[in] label Optional label to associate with key
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlDsaImportKey(whClientContext* ctx, wc_MlDsaKey* key,
                             whKeyId* inout_keyId, whNvmFlags flags,
                             uint16_t label_len, uint8_t* label);

/**
 * @brief Export a ML-DSA key from the server.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] keyId ID of key to export
 * @param[out] key Pointer to receive exported key
 * @param[in] label_len Length of optional label buffer
 * @param[in] label Optional buffer to receive key label
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlDsaExportKey(whClientContext* ctx, whKeyId keyId, wc_MlDsaKey* key,
                             uint16_t label_len, uint8_t* label);

/**
 * @brief Exports only the public part of a cached ML-DSA key.
 *
 * Instructs the server to emit only the public portion of a cached ML-DSA
 * key as SubjectPublicKeyInfo DER. The private key stays inside the HSM.
 * The decoded key will have pubKeySet == 1 and prvKeySet == 0.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive. The caller is responsible for initializing
 * key (e.g. wc_MlDsaKey_Init) and, if required, setting the ML-DSA
 * parameter level via wc_MlDsaKey_SetParams prior to calling this function.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized wc_MlDsaKey. On success,
 *                    only the public half is populated
 *                    (pubKeySet == 1, prvKeySet == 0).
 * @param[in] label_len Size of the optional label buffer in bytes. Values
 *                      larger than WH_NVM_LABEL_LEN are truncated. Set to
 *                      0 if label is not needed.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure (e.g. WH_ERROR_NOTFOUND, WH_ERROR_BADARGS).
 */
int wh_Client_MlDsaExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                   wc_MlDsaKey* key, uint16_t label_len,
                                   uint8_t* label);

/**
 * @brief Generate a new ML-DSA key pair and export the public key.
 *
 * This function generates a new ML-DSA key pair in the HSM and exports the
 * public key to the client. The private key remains securely stored in the HSM.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] type The ML-DSA algorithm type.
 * @param[in] size Size of the key in bits.
 * @param[in,out] key Pointer to the ML-DSA key structure to store the key.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaMakeExportKey(whClientContext* ctx, int level, int size,
                                 wc_MlDsaKey* key);
/**
 * @brief Create and cache a new ML-DSA key on the server.
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] size Size of key to generate
 * @param[in] level ML-DSA security level of the key to generate
 * @param[in,out] inout_key_id Pointer to key ID to use/receive
 * @param[in] flags Flags to control key persistence
 * @param[in] label_len Length of optional label
 * @param[in] label Optional label to associate with key
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlDsaMakeCacheKey(whClientContext* ctx, int size, int level,
                                whKeyId* inout_key_id, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label);
/**
 * @brief Sign a message using a ML-DSA private key.
 *
 * This function signs a message using a ML-DSA private key stored in the
 * HSM.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] in Pointer to the message to sign.
 * @param[in] in_len Length of the message in bytes.
 * @param[out] out Buffer to store the signature.
 * @param[in,out] out_len Pointer to size of output buffer, updated with actual
 * size.
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[in] context Optional FIPS 204 context string for domain separation,
 * or NULL for no context.
 * @param[in] contextLen Length of the context string (max 255).
 * @param[in] preHashType Hash type for HashML-DSA (e.g. WC_HASH_TYPE_SHA256),
 * or WC_HASH_TYPE_NONE for pure ML-DSA.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaSign(whClientContext* ctx, const byte* in, word32 in_len,
                            byte* out, word32* out_len, wc_MlDsaKey* key,
                            const byte* context, byte contextLen,
                            word32 preHashType);
/**
 * @brief Verify a ML-DSA signature.
 *
 * This function verifies a ML-DSA signature using the HSM.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sig Pointer to the signature to verify.
 * @param[in] sig_len Length of the signature in bytes.
 * @param[in] msg Pointer to the original message.
 * @param[in] msg_len Length of the message in bytes.
 * @param[out] res Pointer to store verification result (1=success, 0=failure).
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[in] context Optional FIPS 204 context string for domain separation,
 * or NULL for no context.
 * @param[in] contextLen Length of the context string (max 255).
 * @param[in] preHashType Hash type for HashML-DSA (e.g. WC_HASH_TYPE_SHA256),
 * or WC_HASH_TYPE_NONE for pure ML-DSA.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaVerify(whClientContext* ctx, const byte* sig,
                              word32 sig_len, const byte* msg, word32 msg_len,
                              int* res, wc_MlDsaKey* key, const byte* context,
                              byte contextLen, word32 preHashType);

/**
 * @brief Check a ML-DSA private key.
 *
 * This function validates a ML-DSA private key against its public key using
 * the HSM.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[in] pubKey Pointer to the public key data.
 * @param[in] pubKeySz Size of the public key in bytes.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaCheckPrivKey(whClientContext* ctx, wc_MlDsaKey* key,
                                const byte* pubKey, word32 pubKeySz);


#ifdef WOLFHSM_CFG_DMA
/**
 * @brief Import a ML-DSA key using DMA.
 *
 * This function imports a ML-DSA key into the HSM using DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] key Pointer to the ML-DSA key structure representing the key to
 * import.
 * @param[in,out] inout_keyId Pointer to store/provide the key ID.
 * @param[in] flags NVM flags for key storage.
 * @param[in] label_len Length of the key label in bytes.
 * @param[in] label Pointer to the key label.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaImportKeyDma(whClientContext* ctx, wc_MlDsaKey* key,
                                whKeyId* inout_keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label);

/**
 * @brief Export a ML-DSA key using DMA.
 *
 * This function exports a ML-DSA key from the HSM using DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] keyId ID of the key to export.
 * @param[out] key Pointer to the ML-DSA key structure to hold the exported key.
 * @param[in] label_len Length of the key label in bytes.
 * @param[in] label Pointer to the key label.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaExportKeyDma(whClientContext* ctx, whKeyId keyId,
                                wc_MlDsaKey* key, uint16_t label_len,
                                uint8_t* label);

/**
 * @brief Export only the public part of a cached ML-DSA key using DMA.
 *
 * DMA counterpart to wh_Client_MlDsaExportPublicKey. The server emits the
 * public-only DER and DMAs it directly into a client-side staging buffer;
 * the wrapper then deserializes it into the caller-provided wc_MlDsaKey.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive. The caller is responsible for initializing
 * key (e.g. wc_MlDsaKey_Init + wc_MlDsaKey_SetParams) prior to calling.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized wc_MlDsaKey. On success,
 *                    only the public half is populated
 *                    (pubKeySet == 1, prvKeySet == 0).
 * @param[in] label_len Size of the optional label buffer in bytes.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaExportPublicKeyDma(whClientContext* ctx, whKeyId keyId,
                                      wc_MlDsaKey* key, uint16_t label_len,
                                      uint8_t* label);

/**
 * @brief Generate a new ML-DSA key pair and export it using DMA.
 *
 * This function generates a new ML-DSA key pair in the HSM and exports it using
 * DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] level The ML-DSA security level.
 * @param[out] key Pointer to the ML-DSA key structure to store the key.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaMakeExportKeyDma(whClientContext* ctx, int level,
                                    wc_MlDsaKey* key);


/**
 * @brief Sign a message using ML-DSA with DMA.
 *
 * This function signs a message using ML-DSA with DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] in Pointer to the message to sign.
 * @param[in] in_len Length of the message in bytes.
 * @param[out] out Pointer to store the signature.
 * @param[in,out] out_len On input, size of out buffer. On output, length of
 * signature.
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[in] context Optional FIPS 204 context string for domain separation,
 * or NULL for no context.
 * @param[in] contextLen Length of the context string (max 255).
 * @param[in] preHashType Hash type for HashML-DSA (e.g. WC_HASH_TYPE_SHA256),
 * or WC_HASH_TYPE_NONE for pure ML-DSA.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaSignDma(whClientContext* ctx, const byte* in,
                               word32 in_len, byte* out, word32* out_len,
                               wc_MlDsaKey* key, const byte* context,
                               byte contextLen, word32 preHashType);

/**
 * @brief Verify a ML-DSA signature with DMA.
 *
 * This function verifies a ML-DSA signature with DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] sig Pointer to the signature to verify.
 * @param[in] sig_len Length of the signature in bytes.
 * @param[in] msg Pointer to the message that was signed.
 * @param[in] msg_len Length of the message in bytes.
 * @param[out] res Result of verification (1 = success, 0 = failure).
 * @param[in] key Pointer to the ML-DSA key structure.
 * @param[in] context Optional FIPS 204 context string for domain separation,
 * or NULL for no context.
 * @param[in] contextLen Length of the context string (max 255).
 * @param[in] preHashType Hash type for HashML-DSA (e.g. WC_HASH_TYPE_SHA256),
 * or WC_HASH_TYPE_NONE for pure ML-DSA.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaVerifyDma(whClientContext* ctx, const byte* sig,
                                 word32 sig_len, const byte* msg,
                                 word32 msg_len, int* res, wc_MlDsaKey* key,
                                 const byte* context, byte contextLen,
                                 word32 preHashType);

/**
 * @brief Check a ML-DSA private key against public key with DMA.
 *
 * This function checks if a ML-DSA private key matches a public key with DMA.
 *
 * @param[in] ctx Pointer to the client context structure.
 * @param[in] key Pointer to the ML-DSA private key structure.
 * @param[in] pubKey Pointer to the public key to check against.
 * @param[in] pubKeySz Size of the public key in bytes.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaCheckPrivKeyDma(whClientContext* ctx, wc_MlDsaKey* key,
                                   const byte* pubKey, word32 pubKeySz);

#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM

/**
 * @brief Associate a ML-KEM key with a specific key ID.
 *
 * Sets the device context of a ML-KEM key to the specified key ID. On the
 * server side, this key ID is used to reference the key stored in the HSM.
 *
 * @param[in] key Pointer to the ML-KEM key structure.
 * @param[in] keyId Key ID to be associated with the ML-KEM key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemSetKeyId(MlKemKey* key, whKeyId keyId);

/**
 * @brief Retrieve the key ID associated with a ML-KEM key.
 *
 * @param[in] key Pointer to the ML-KEM key structure.
 * @param[out] outId Pointer to store the retrieved key ID.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemGetKeyId(MlKemKey* key, whKeyId* outId);

/**
 * @brief Import a ML-KEM key to the server key cache.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to the ML-KEM key to import.
 * @param[in,out] inout_keyId Pointer to key ID to use/receive.
 * @param[in] flags Flags to control key persistence.
 * @param[in] label_len Length of optional label in bytes.
 * @param[in] label Optional label to associate with the key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemImportKey(whClientContext* ctx, MlKemKey* key,
                             whKeyId* inout_keyId, whNvmFlags flags,
                             uint16_t label_len, uint8_t* label);

/**
 * @brief Export a ML-KEM key from the server key cache.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] keyId Key ID of the key to export.
 * @param[out] key Pointer to the ML-KEM key structure to populate.
 * @param[in] label_len Length of optional label in bytes.
 * @param[out] label Optional label buffer to receive the key label.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemExportKey(whClientContext* ctx, whKeyId keyId, MlKemKey* key,
                             uint16_t label_len, uint8_t* label);

/**
 * @brief Exports only the public part of a cached ML-KEM key.
 *
 * Instructs the server to emit only the public portion of a cached ML-KEM
 * key as raw FIPS 203 wire-format bytes (not DER). The private key stays
 * inside the HSM. The decoded key will have MLKEM_FLAG_PUB_SET set and
 * MLKEM_FLAG_PRIV_SET clear.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive. The caller is responsible for initializing
 * key (e.g. wc_MlKemKey_Init).
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized MlKemKey. On success,
 *                    only the public half is populated.
 * @param[in] label_len Size of the optional label buffer in bytes. Values
 *                      larger than WH_NVM_LABEL_LEN are truncated. Set to
 *                      0 if label is not needed.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure (e.g. WH_ERROR_NOTFOUND, WH_ERROR_BADARGS,
 *             WH_ERROR_NOSPACE).
 */
int wh_Client_MlKemExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                   MlKemKey* key, uint16_t label_len,
                                   uint8_t* label);

/**
 * @brief Generate a ML-KEM key pair and return it as an ephemeral key.
 *
 * The key pair is generated on the server, serialized, and returned to the
 * client without being cached.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] level ML-KEM security level (WC_ML_KEM_512/768/1024).
 * @param[out] key Pointer to the ML-KEM key to populate with the generated key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemMakeExportKey(whClientContext* ctx, int level,
                                 MlKemKey* key);

/**
 * @brief Generate a ML-KEM key pair and cache it on the server.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] level ML-KEM security level (WC_ML_KEM_512/768/1024).
 * @param[in,out] inout_key_id Pointer to key ID to use/receive.
 * @param[in] flags Flags to control key persistence and usage.
 * @param[in] label_len Length of optional label in bytes.
 * @param[in] label Optional label to associate with the key.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemMakeCacheKey(whClientContext* ctx, int level,
                                whKeyId* inout_key_id, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label);

/**
 * @brief Perform ML-KEM encapsulation using a server-cached public key.
 *
 * Generates a shared secret and ciphertext using the public key identified by
 * the key ID stored in the provided MlKemKey. If the key is not yet cached,
 * it will be auto-imported and evicted after use.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to the ML-KEM key (must have key ID set).
 * @param[out] ct Buffer to receive the ciphertext.
 * @param[in,out] inout_ct_len On input, size of ct buffer; on output, actual
 *                ciphertext length.
 * @param[out] ss Buffer to receive the shared secret.
 * @param[in,out] inout_ss_len On input, size of ss buffer; on output, actual
 *                shared secret length.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemEncapsulate(whClientContext* ctx, MlKemKey* key,
                               uint8_t* ct, uint32_t* inout_ct_len,
                               uint8_t* ss, uint32_t* inout_ss_len);

/**
 * @brief Perform ML-KEM decapsulation using a server-cached private key.
 *
 * Recovers the shared secret from the ciphertext using the private key
 * identified by the key ID stored in the provided MlKemKey. If the key is not
 * yet cached, it will be auto-imported and evicted after use.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to the ML-KEM key (must have key ID set).
 * @param[in] ct Pointer to the ciphertext.
 * @param[in] ct_len Length of the ciphertext in bytes.
 * @param[out] ss Buffer to receive the shared secret.
 * @param[in,out] inout_ss_len On input, size of ss buffer; on output, actual
 *                shared secret length.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemDecapsulate(whClientContext* ctx, MlKemKey* key,
                               const uint8_t* ct, uint32_t ct_len, uint8_t* ss,
                               uint32_t* inout_ss_len);

#ifdef WOLFHSM_CFG_DMA

/**
 * @brief Import a ML-KEM key using DMA.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to the ML-KEM key to import.
 * @param[in,out] inout_keyId Pointer to store/provide the key ID.
 * @param[in] flags NVM flags for key storage.
 * @param[in] label_len Length of the key label in bytes.
 * @param[in] label Pointer to the key label.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemImportKeyDma(whClientContext* ctx, MlKemKey* key,
                                whKeyId* inout_keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label);

/**
 * @brief Export a ML-KEM key from the server using DMA.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] keyId Key ID of the key to export.
 * @param[out] key Pointer to the ML-KEM key structure to populate.
 * @param[in] label_len Length of the key label in bytes.
 * @param[out] label Pointer to the key label buffer.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemExportKeyDma(whClientContext* ctx, whKeyId keyId,
                                MlKemKey* key, uint16_t label_len,
                                uint8_t* label);

/**
 * @brief Exports only the public part of a cached ML-KEM key using DMA.
 *
 * DMA counterpart to wh_Client_MlKemExportPublicKey. The server writes the
 * raw FIPS 203 wire-format public bytes directly into the client-provided
 * buffer.
 *
 * The NONEXPORTABLE key flag does NOT block this call because public
 * material is non-sensitive.
 *
 * @param[in] ctx Pointer to the wolfHSM client context.
 * @param[in] keyId Server key ID whose public key should be exported. Must
 *                  not be WH_KEYID_ERASED.
 * @param[in,out] key Pointer to a caller-initialized MlKemKey. On success,
 *                    only the public half is populated.
 * @param[in] label_len Size of the optional label buffer in bytes.
 * @param[out] label Optional buffer to receive the key's label. May be NULL.
 * @return int Returns 0 on success or a negative wolfHSM/wolfCrypt error
 *             code on failure.
 */
int wh_Client_MlKemExportPublicKeyDma(whClientContext* ctx, whKeyId keyId,
                                      MlKemKey* key, uint16_t label_len,
                                      uint8_t* label);

/**
 * @brief Generate an ephemeral ML-KEM key pair using DMA.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] level ML-KEM security level (WC_ML_KEM_512/768/1024).
 * @param[out] key Pointer to the ML-KEM key to populate.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemMakeExportKeyDma(whClientContext* ctx, int level,
                                    MlKemKey* key);

/**
 * @brief Perform ML-KEM encapsulation using DMA.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to the ML-KEM key (must have key ID set).
 * @param[out] ct Buffer to receive the ciphertext.
 * @param[in,out] inout_ct_len On input, size of ct buffer; on output, actual
 *                ciphertext length.
 * @param[out] ss Buffer to receive the shared secret.
 * @param[in,out] inout_ss_len On input, size of ss buffer; on output, actual
 *                shared secret length.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemEncapsulateDma(whClientContext* ctx, MlKemKey* key,
                                  uint8_t* ct, uint32_t* inout_ct_len,
                                  uint8_t* ss, uint32_t* inout_ss_len);

/**
 * @brief Perform ML-KEM decapsulation using DMA.
 *
 * @param[in] ctx Pointer to the client context.
 * @param[in] key Pointer to the ML-KEM key (must have key ID set).
 * @param[in] ct Pointer to the ciphertext.
 * @param[in] ct_len Length of the ciphertext in bytes.
 * @param[out] ss Buffer to receive the shared secret.
 * @param[in,out] inout_ss_len On input, size of ss buffer; on output, actual
 *                shared secret length.
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_MlKemDecapsulateDma(whClientContext* ctx, MlKemKey* key,
                                  const uint8_t* ct, uint32_t ct_len,
                                  uint8_t* ss, uint32_t* inout_ss_len);
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_HAVE_MLKEM */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#endif /* !WOLFHSM_WH_CLIENT_CRYPTO_H_ */
