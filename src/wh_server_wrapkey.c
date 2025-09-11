/*
 * Copyright (C) 2025 wolfSSL Inc.
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

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"
#ifdef WOLFHSM_CFG_WRAPKEY

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_SERVER)

/* System libraries */
#include <stdint.h>
#include <stddef.h> /* For NULL */
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_wrapkey.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server.h"

#define WOLFHSM_WRAPKEY_AES_GCM_TAG_SIZE 16
#define WOLFHSM_WRAPKEY_AES_GCM_IV_SIZE 16
#define WOLFHSM_WRAPKEY_MAX_KEY_SIZE 4096

static int _AesGcmWrapKey(whServerContext* server, whKeyId serverKeyId,
                          uint8_t* keyIn, uint16_t keySz,
                          whNvmMetadata* metadataIn, uint8_t* wrappedKeyOut,
                          uint16_t wrappedKeySz)
{
    int      ret = 0;
    Aes      aes[1];
    WC_RNG   rng[1];
    uint8_t  authTag[WOLFHSM_WRAPKEY_AES_GCM_TAG_SIZE];
    uint8_t  iv[WOLFHSM_WRAPKEY_AES_GCM_IV_SIZE];
    uint8_t  serverKey[AES_MAX_KEY_SIZE];
    uint32_t serverKeySz = sizeof(serverKey);

    if (server == NULL || keyIn == NULL || metadataIn == NULL ||
        wrappedKeyOut == NULL)
        return WH_ERROR_BADARGS;

    /* Check if the buffer is big enough to hold the wrapped key */
    if (wrappedKeySz <
        sizeof(iv) + sizeof(authTag) + sizeof(*metadataIn) + keySz)
        return WH_ERROR_BUFFER_SIZE;

    /* Initialize RNG context */
    ret = wc_InitRng_ex(rng, NULL, server->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    /* Get the server side key */
    ret = wh_Server_KeystoreReadKey(
        server,
        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, serverKeyId),
        NULL, serverKey, &serverKeySz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->crypto->devId);
    if (ret != 0) {
        wc_FreeRng(rng);
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_FreeRng(rng);
        return ret;
    }

    /* Generate the IV */
    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_FreeRng(rng);
        wc_AesFree(aes);
        return ret;
    }

    /* Combine key and metadata into one blob */
    uint8_t* encBlob = (uint8_t*)wrappedKeyOut + sizeof(iv) + sizeof(authTag);
    uint8_t  plainBlob[sizeof(*metadataIn) + keySz];
    memcpy(plainBlob, metadataIn, sizeof(*metadataIn));
    memcpy(plainBlob + sizeof(*metadataIn), keyIn, keySz);

    /* Encrypt the blob */
    ret = wc_AesGcmEncrypt(aes, encBlob, plainBlob, sizeof(plainBlob), iv,
                           sizeof(iv), authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_FreeRng(rng);
        wc_AesFree(aes);
        return ret;
    }

    /* Prepend IV + authTag to encrypted blob */
    memcpy(wrappedKeyOut, iv, sizeof(iv));
    memcpy(wrappedKeyOut + sizeof(iv), authTag, sizeof(authTag));

    wc_FreeRng(rng);
    wc_AesFree(aes);

    return WH_ERROR_OK;
}

static int _AesGcmUnwrapKey(whServerContext* server, uint16_t serverKeyId,
                            void* wrappedKeyIn, uint16_t wrappedKeySz,
                            whNvmMetadata* metadataOut, void* keyOut,
                            uint16_t keySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WOLFHSM_WRAPKEY_AES_GCM_TAG_SIZE];
    uint8_t  iv[WOLFHSM_WRAPKEY_AES_GCM_IV_SIZE];
    uint8_t  serverKey[AES_MAX_KEY_SIZE];
    uint32_t serverKeySz = sizeof(serverKey);
    uint8_t* encBlob   = (uint8_t*)wrappedKeyIn + sizeof(iv) + sizeof(authTag);
    uint16_t encBlobSz = wrappedKeySz - sizeof(iv) - sizeof(authTag);
    uint8_t  plainBlob[sizeof(*metadataOut) + keySz];

    if (server == NULL || wrappedKeyIn == NULL || metadataOut == NULL ||
        keyOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key */
    ret = wh_Server_KeystoreReadKey(
        server,
        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, serverKeyId),
        NULL, serverKey, &serverKeySz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        return ret;
    }

    /* Extract IV and authTag from wrappedKeyIn */
    memcpy(iv, wrappedKeyIn, sizeof(iv));
    memcpy(authTag, wrappedKeyIn + sizeof(iv), sizeof(authTag));

    /* Decrypt the encrypted blob */
    ret = wc_AesGcmDecrypt(aes, plainBlob, encBlob, encBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Extract metadata and key from the decrypted blob */
    memcpy(metadataOut, plainBlob, sizeof(*metadataOut));
    memcpy(keyOut, plainBlob + sizeof(*metadataOut), keySz);

    wc_AesFree(aes);
    return WH_ERROR_OK;
}

static int _HandleWrapKeyRequest(whServerContext*              server,
                                 whMessageWrapKey_WrapRequest* req,
                                 uint8_t* reqData, uint32_t reqDataSz,
                                 whMessageWrapKey_WrapResponse* resp,
                                 uint8_t* respData, uint32_t respDataSz)
{
    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL)
        return WH_ERROR_BADARGS;

    if (req->keySz > WOLFHSM_WRAPKEY_MAX_KEY_SIZE)
        return WH_ERROR_BADARGS;

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata;
    uint8_t       key[req->keySz];

    /* Check if the reqData is big enough to hold the metadata and key */
    if (reqDataSz < sizeof(metadata) + req->keySz)
        return WH_ERROR_BUFFER_SIZE;

    /* Extract the metadata and key from reqData */
    memcpy(&metadata, reqData, sizeof(metadata));
    memcpy(key, reqData + sizeof(metadata), req->keySz);

    /* Store the wrapped key in the response data */
    wrappedKey = respData;

    switch (req->cipherType) {
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedKeySz = WOLFHSM_WRAPKEY_AES_GCM_IV_SIZE +
                                    WOLFHSM_WRAPKEY_AES_GCM_TAG_SIZE +
                                    sizeof(metadata) + req->keySz;

            /* Check if the response data can fit the wrapped key */
            if (respDataSz < wrappedKeySz)
                return WH_ERROR_BUFFER_SIZE;

            /* Wrap the key */
            ret = _AesGcmWrapKey(server, req->serverKeyId, key, req->keySz,
                                 &metadata, wrappedKey, wrappedKeySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the wrapped key is */
            resp->wrappedKeySz = wrappedKeySz;
            resp->cipherType = WC_CIPHER_AES_GCM;

        } break;
        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _HandleUnwrapKeyRequest(whServerContext*                server,
                                   whMessageWrapKey_UnwrapRequest* req,
                                   uint8_t* reqData, uint32_t reqDataSz,
                                   whMessageWrapKey_UnwrapResponse* resp,
                                   uint8_t* respData, uint32_t respDataSz)
{
    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL)
        return WH_ERROR_BADARGS;

    int            ret;
    uint8_t*       wrappedKey;
    whNvmMetadata* metadata;
    uint8_t*       key;

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz)
        return WH_ERROR_BUFFER_SIZE;

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Store the metadata and key in the respData */
    metadata = (whNvmMetadata*)respData;
    key      = respData + sizeof(*metadata);

    switch (req->cipherType) {
        case WC_CIPHER_AES_GCM: {
            uint16_t keySz =
                req->wrappedKeySz - WOLFHSM_WRAPKEY_AES_GCM_IV_SIZE -
                WOLFHSM_WRAPKEY_AES_GCM_TAG_SIZE - sizeof(*metadata);

            /* Check if the response data can fit the metadata + key  */
            if (respDataSz < sizeof(*metadata) + keySz)
                return WH_ERROR_BUFFER_SIZE;

            /* Unwrap the key */
            ret = _AesGcmUnwrapKey(server, req->serverKeyId, wrappedKey,
                                   req->wrappedKeySz, metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the key is */
            resp->keySz = keySz;
            resp->cipherType = WC_CIPHER_AES_GCM;

        } break;
        default:
            return WH_ERROR_BADARGS;
    }

    return ret;
}

static int _CacheKey(whServerContext* server, whNvmMetadata* metadata,
                     void* key, uint16_t keySz, whKeyId* keyIdOut)
{
    int ret;

    /* Verify the key size argument and key size from the the metadata match */
    if (keySz != metadata->len) {
        return WH_ERROR_BADARGS;
    }

    /* Get a new id if one wasn't provided */
    if (WH_KEYID_ISERASED(metadata->id)) {
        ret = wh_Server_KeystoreGetUniqueId(server, &metadata->id);
    }

    if (ret != WH_ERROR_OK) {
        return ret;
    }

    *keyIdOut = metadata->id;

    /* Write the key */
    return wh_Server_KeystoreCacheKey(server, metadata, key);
}

static int _HandleCacheKeyRequest(whServerContext*               server,
                                  whMessageWrapKey_CacheRequest* req,
                                  uint8_t* reqData, uint32_t reqDataSz,
                                  whMessageWrapKey_CacheResponse* resp,
                                  uint8_t* respData, uint32_t respDataSz)
{
    /* The server doesn't have any extra response data to send back to the
     * client */
    (void)respData;
    (void)respDataSz;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata;

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz)
        return WH_ERROR_BUFFER_SIZE;

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Unwrap the key based on the cipher type */
    switch (req->cipherType) {
        case WC_CIPHER_AES_GCM: {
            whKeyId  keyId;
            uint16_t keySz =
                req->wrappedKeySz - WOLFHSM_WRAPKEY_AES_GCM_IV_SIZE -
                WOLFHSM_WRAPKEY_AES_GCM_TAG_SIZE - sizeof(metadata);
            uint8_t* key[keySz];

            ret = _AesGcmUnwrapKey(server, req->serverKeyId, wrappedKey,
                                   req->wrappedKeySz, &metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            ret = _CacheKey(server, &metadata, key, keySz, &keyId);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            resp->keyId = keyId;
            resp->cipherType = WC_CIPHER_AES_GCM;

        } break;
        default:
            return WH_ERROR_BADARGS;
    }

    return ret;
}
int wh_Server_HandleWrapKeyRequest(whServerContext* server, uint16_t magic,
                                   uint16_t action, uint16_t reqSz,
                                   const void* req, uint16_t* respSz,
                                   void* resp)
{
    int ret = WH_ERROR_OK;

    if (server == NULL || req == NULL || respSz == NULL || resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_WRAPKEY_WRAP: {
            whMessageWrapKey_WrapRequest  wrapReq;
            whMessageWrapKey_WrapResponse wrapResp;
            uint8_t*                      reqData;
            uint8_t*                      respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < reqSz)
                return WH_ERROR_BUFFER_SIZE;

            /* Translate request */
            (void)wh_MessageWrapKey_TranslateWrapRequest(magic, req, &wrapReq);


            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req + sizeof(whMessageWrapKey_WrapRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp + sizeof(whMessageWrapKey_WrapResponse);

            ret = _HandleWrapKeyRequest(server, &wrapReq, reqData, reqDataSz,
                                        &wrapResp, respData, respDataSz);
            wrapResp.rc = ret;

            (void)wh_MessageWrapKey_TranslateWrapResponse(magic, &wrapResp,
                                                          resp);
            *respSz = sizeof(wrapResp) + wrapResp.wrappedKeySz;

        } break;

        case WH_WRAPKEY_UNWRAP: {
            whMessageWrapKey_UnwrapRequest  unwrapReq;
            whMessageWrapKey_UnwrapResponse unwrapResp;
            uint8_t*                        reqData;
            uint8_t*                        respData;
            uint32_t reqDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapReq);
            uint32_t respDataSz =
                WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < reqSz)
                return WH_ERROR_BUFFER_SIZE;

            /* Translate request */
            (void)wh_MessageWrapKey_TranslateUnwrapRequest(magic, req,
                                                           &unwrapReq);

            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req + sizeof(whMessageWrapKey_UnwrapRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp + sizeof(whMessageWrapKey_UnwrapResponse);

            ret =
                _HandleUnwrapKeyRequest(server, &unwrapReq, reqData, reqDataSz,
                                        &unwrapResp, respData, respDataSz);
            unwrapResp.rc = ret;

            (void)wh_MessageWrapKey_TranslateUnwrapResponse(magic, &unwrapResp,
                                                            resp);
            *respSz =
                sizeof(unwrapResp) + sizeof(whNvmMetadata) + unwrapResp.keySz;

        } break;

        case WH_WRAPKEY_CACHE: {
            whMessageWrapKey_CacheRequest  cacheReq;
            whMessageWrapKey_CacheResponse cacheResp;
            uint8_t*                       reqData;
            uint8_t*                       respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < reqSz)
                return WH_ERROR_BUFFER_SIZE;

            /* Translate request */
            (void)wh_MessageWrapKey_TranslateCacheRequest(magic, req,
                                                          &cacheReq);

            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req + sizeof(whMessageWrapKey_CacheRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp + sizeof(whMessageWrapKey_CacheResponse);

            ret = _HandleCacheKeyRequest(server, &cacheReq, reqData, reqDataSz,
                                         &cacheResp, respData, respDataSz);
            cacheResp.rc = ret;

            (void)wh_MessageWrapKey_TranslateCacheResponse(magic, &cacheResp,
                                                           resp);
            *respSz = sizeof(cacheResp);

        } break;

        default:
            return WH_ERROR_BADARGS;
    }

    return ret;
}

#endif /* !defined(WOLFHSM_CFG_NO_CRYPTO) && \
          defined(WOLFHSM_CFG_ENABLE_SERVER) */
#endif /* WOLFHSM_CFG_WRAPKEY */
