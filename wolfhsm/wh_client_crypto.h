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
 * serailized byte array and decodes the key into the wolfCrypt curve25519_key
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

/* TODO: Generate a Curve25519 key on the server and put it in the server keycache */
int wh_Client_Curve25519MakeCacheKey(whClientContext* ctx,
        uint16_t size,
        whKeyId *inout_key_Id, whNvmFlags flags,
        uint16_t label_len, uint8_t* label);

/* TODO: Generate a Curve25519 key on the server and export it inta a local struct */
int wh_Client_Curve25519MakeExportKey(whClientContext* ctx,
        uint16_t size,
        curve25519_key* key);

/* TODO: Compute an X25519 shared secret */
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
int wh_Client_SetKeyIdRsa(RsaKey* key, whNvmId keyId);

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
int wh_Client_GetKeyIdRsa(RsaKey* key, whNvmId* outId);

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
int wh_Client_ImportRsaKey(whClientContext* ctx, RsaKey* key,
        whNvmFlags flags, uint32_t label_len, uint8_t* label,
        whKeyId *out_keyId);

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

int wh_Client_ExportRsaKey(whClientContext* ctx, whKeyId keyId, RsaKey* key,
        uint32_t label_len, uint8_t* label);

/* Generate an RSA key on the server and export it inta an RSA struct */
int wh_Client_MakeExportRsaKey(whClientContext* ctx,
        uint32_t size, uint32_t e, RsaKey* key);

/* Generate an RSA key on the server and put it in the server keycache */
int wh_Client_MakeCacheRsaKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whNvmFlags flags,  uint32_t label_len, uint8_t* label,
        whKeyId *out_keyId);

/* Make an RSA key on the server based on the flags */
int wh_Client_MakeRsaKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whNvmFlags flags,  uint32_t label_len, uint8_t* label,
        whKeyId *inout_key_id, RsaKey* rsa);


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
int wh_Client_SetKeyIdAes(Aes* key, whNvmId keyId);

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
int wh_Client_GetKeyIdAes(Aes* key, whNvmId* outId);

#ifdef WOLFSSL_CMAC
/**
 * @brief Runs the AES CMAC operation in a single call with a wolfHSM keyId.
 *
 * This function does entire cmac operation in one function call with a key
 * already stored in the HSM. This operation evicts the key from the HSM cache
 * after the operation though it will still be in the HSM's NVM if it was
 * commited
 *
 * @param[in] cmac Pointer to the CMAC key structure.
 * @param[out] out Output buffer for the CMAC tag.
 * @param[out] outSz Size of the output buffer in bytes.
 * @param[in] in Input buffer to be hashed.
 * @param[in] inSz Size of the input buffer in bytes.
 * @param[in] keyId ID of the key inside the HSM.
 * @param[in] heap Heap pointer for the cmac struct.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Client_AesCmacGenerate(Cmac* cmac, byte* sig, word32* outSz,
    const byte* hash, word32 inSz, whNvmId keyId, void* heap);

/**
 * @brief Verifies a AES CMAC tag in a single call with a wolfHSM keyId.
 *
 * This function does entire cmac verify in one function call with a key
 * already stored in the HSM. This operation evicts the key from the HSM cache
 * after the operation though it will still be in the HSM's NVM if it was
 * commited
 *
 * @param[in] cmac Pointer to the CMAC key structure.
 * @param[out] check Cmac tag to check against.
 * @param[out] checkSz Size of the check buffer in bytes.
 * @param[in] in Input buffer to be hashed.
 * @param[in] inSz Size of the input buffer in bytes.
 * @param[in] keyId ID of the key inside the HSM.
 * @param[in] heap Heap pointer for the cmac struct.
 * @return int Returns 0 on success, 1 on tag mismatch, or a negative error
 *    code on failure.
 */
int wh_Client_AesCmacVerify(Cmac* cmac, const byte* check, word32 checkSz,
    const byte* hash, word32 inSz, whNvmId keyId, void* heap);

/**
 * @brief Handle cancelable CMAC response.
 *
 * This function handles a CMAC operation response from the server when
 * cancellation has been enabled, since wolfCrypt won't automatically block and
 * wait for the response.
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
int wh_Client_SetKeyIdCmac(Cmac* key, whNvmId keyId);

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
int wh_Client_GetKeyIdCmac(Cmac* key, whNvmId* outId);
#endif /* WOLFSSL_CMAC */
#endif /* !NO_AES */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#endif /* !WOLFHSM_WH_CLIENT_CRYPTO_H_ */
