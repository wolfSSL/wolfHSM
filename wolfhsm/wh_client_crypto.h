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
#include "wolfssl/wolfcrypt/dilithium.h"

/**
 * @brief Generate random bytes
 *
 * This function requests the server to generate random bytes by repeatedly
 * requesting the maximum block size of data from the server at a time
 *
 * @param[in] ctx Pointer to the client context
 * @param[in] out Pointer to the where the bytes are to be placed.  May be NULL.
 * @param[in] size Number of bytes to generate. *
 * @return int Returns 0 on success or a negative error code on failure.
 */
int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size);

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

/* TODO: Send key to server */
int wh_Client_EccImportKey(whClientContext* ctx, ecc_key* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint16_t label_len, uint8_t* label);
/* TODO: Recv key from server */
int wh_Client_EccExportKey(whClientContext* ctx, whKeyId keyId,
        ecc_key* key,
        uint16_t label_len, uint8_t* label);

/* TODO: Server creates and exports a key, without caching */
int wh_Client_EccMakeExportKey(whClientContext* ctx,
        int size, int curveId, ecc_key* key);
/* TODO: Server creates and imports the key to cache. */
int wh_Client_EccMakeCacheKey(whClientContext* ctx,
        int size, int curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint16_t label_len, uint8_t* label);

/* TODO: Perform shared secret computation (ECDH) */
int wh_Client_EccSharedSecret(whClientContext* ctx,
                                ecc_key* priv_key, ecc_key* pub_key,
                                uint8_t* sig, uint16_t *out_size);

/* TODO: Server generates signature of input hash */
int wh_Client_EccSign(whClientContext* ctx,
        ecc_key* key,
        const uint8_t* hash, uint16_t hash_len,
        uint8_t* sig, uint16_t *inout_sig_len);

/* TODO: Server verifies the signature of the provided hash */
int wh_Client_EccVerify(whClientContext* ctx, ecc_key* key,
        const uint8_t* sig, uint16_t sig_len,
        const uint8_t* hash, uint16_t hash_len,
        int *out_res);

#endif /* HAVE_ECC */

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

/* Generate an RSA key on the server and export it inta an RSA struct */
int wh_Client_RsaMakeExportKey(whClientContext* ctx,
        uint32_t size, uint32_t e, RsaKey* key);

/* Generate an RSA key on the server and put it in the server keycache */
int wh_Client_RsaMakeCacheKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint32_t label_len, uint8_t* label);

/* TODO: Request server to perform the RSA function */
int wh_Client_RsaFunction(whClientContext* ctx,
        RsaKey* key, int rsa_type,
        const uint8_t* in, uint16_t in_len,
        uint8_t* out, uint16_t *inout_out_len);

/* TODO: Request server to get the RSA size */
int wh_Client_RsaGetSize(whClientContext* ctx,
        const RsaKey* key, int* out_size);


#endif /* !NO_RSA */

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

#ifdef HAVE_AES_CBC
int wh_Client_AesCbc(whClientContext* ctx,
        Aes* aes, int enc,
        const uint8_t* in, uint32_t len,
        uint8_t* out);
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
/* TODO: Add documentation */
int wh_Client_AesGcm(whClientContext* ctx,
        Aes* aes, int enc,
        const uint8_t* in, uint32_t len,
        const uint8_t* iv, uint32_t iv_len,
        const uint8_t* authin, uint32_t authin_len,
        const uint8_t* dec_tag, uint8_t* enc_tag, uint32_t tag_len,
        uint8_t* out);
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
 * @brief Handle cancelable CMAC response.
 *
 * This function handles a CMAC operation response from the server when
 * cancellation has been enabled, since wolfCrypt won't automatically block and
 * wait for the response. Note that DMA-based CMAC operations are NOT
 * cancellable and if a cancel is requested, the cancellation will be aborted.
 *
 * @param[in] c Pointer to the client context structure.
 * @param[in] cmac Pointer to the CMAC key structure.
 * @param[out] out Buffer to store the CMAC result, only required after
 *    wc_CmacFinal.
 * @param[in,out] outSz Pointer to the size of the out buffer in bytes, will be
 *    set to the size returned by the server on return.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_CmacCancelableResponse(whClientContext* c, Cmac* cmac,
    uint8_t* sig, uint16_t* outSz);

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

#endif /* !NO_SHA256 */

#ifdef HAVE_DILITHIUM

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
int wh_Client_MlDsaSetKeyId(MlDsaKey* key, whKeyId keyId);

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
int wh_Client_MlDsaGetKeyId(MlDsaKey* key, whKeyId* outId);

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
int wh_Client_MlDsaImportKey(whClientContext* ctx, MlDsaKey* key,
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
int wh_Client_MlDsaExportKey(whClientContext* ctx, whKeyId keyId, MlDsaKey* key,
                             uint16_t label_len, uint8_t* label);

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
int wh_Client_MlDsaMakeExportKey(whClientContext* ctx, int type, int size,
                                 MlDsaKey* key);
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
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaSign(whClientContext* ctx, const byte* in, word32 in_len,
                        byte* out, word32* out_len, MlDsaKey* key);

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
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaVerify(whClientContext* ctx, const byte* sig, word32 sig_len,
                          const byte* msg, word32 msg_len, int* res,
                          MlDsaKey* key);

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
int wh_Client_MlDsaCheckPrivKey(whClientContext* ctx, MlDsaKey* key,
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
int wh_Client_MlDsaImportKeyDma(whClientContext* ctx, MlDsaKey* key,
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
                                MlDsaKey* key, uint16_t label_len,
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
                                    MlDsaKey* key);


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
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaSignDma(whClientContext* ctx, const byte* in, word32 in_len,
                           byte* out, word32* out_len, MlDsaKey* key);

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
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_MlDsaVerifyDma(whClientContext* ctx, const byte* sig,
                             word32 sig_len, const byte* msg, word32 msg_len,
                             int* res, MlDsaKey* key);

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
int wh_Client_MlDsaCheckPrivKeyDma(whClientContext* ctx, MlDsaKey* key,
                                   const byte* pubKey, word32 pubKeySz);

#endif /* WOLFHSM_CFG_DMA */

#endif /* HAVE_DILITHIUM */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#endif /* !WOLFHSM_WH_CLIENT_CRYPTO_H_ */
