/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_KEYWRAP)
#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
#include <stdint.h>
#include <wolfhsm/wh_client.h>
#include <wolfhsm/wh_client_crypto.h>
#include <wolfhsm/wh_error.h>
#include <wolfhsm/wh_message.h>
#include <wolfhsm/wh_message_keystore.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

int wh_Client_KeyWrapRequest(whClientContext*   ctx,
                             enum wc_CipherType cipherType,
                             uint16_t serverKeyId, void* key, uint16_t keySz,
                             whNvmMetadata* metadata)
{
    uint16_t                       group  = WH_MESSAGE_GROUP_KEY;
    uint16_t                          action = WH_KEY_KEYWRAP;
    whMessageKeystore_KeyWrapRequest* req    = NULL;
    uint8_t*                       reqData;

    if (ctx == NULL || key == NULL || metadata == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the request pointer to the shared comm data memory region */
    req =
        (whMessageKeystore_KeyWrapRequest*)wh_CommClient_GetDataPtr(ctx->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize the request */
    req->keySz       = keySz;
    req->serverKeyId = serverKeyId;
    req->cipherType  = cipherType;

    /* Place the metadata + key right after the request */
    reqData = (uint8_t*)(req + 1);
    memcpy(reqData, metadata, sizeof(*metadata));
    memcpy(reqData + sizeof(*metadata), key, keySz);

    return wh_Client_SendRequest(ctx, group, action,
                                 sizeof(*req) + sizeof(*metadata) + keySz,
                                 (uint8_t*)req);
}

int wh_Client_KeyWrapResponse(whClientContext*   ctx,
                              enum wc_CipherType cipherType,
                              void* wrappedKeyOut, uint16_t wrappedKeySz)
{
    int                             ret;
    uint16_t                        group;
    uint16_t                        action;
    uint16_t                        size;
    whMessageKeystore_KeyWrapResponse* resp = NULL;
    uint8_t*                        respData;

    if (ctx == NULL || wrappedKeyOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the response pointer to the shared comm data memory region */
    resp =
        (whMessageKeystore_KeyWrapResponse*)wh_CommClient_GetDataPtr(ctx->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive the response */
    ret = wh_Client_RecvResponse(ctx, &group, &action, &size, (uint8_t*)resp);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (group != WH_MESSAGE_GROUP_KEY || action != WH_KEY_KEYWRAP ||
        size < sizeof(*resp) || size > sizeof(*resp) + wrappedKeySz ||
        resp->wrappedKeySz != wrappedKeySz || resp->cipherType != cipherType) {
        return WH_ERROR_ABORTED;
    }

    if (resp->rc != 0) {
        return resp->rc;
    }

    /* Copy the wrapped key from the response data into wrappedKeyOut */
    respData = (uint8_t*)(resp + 1);
    memcpy(wrappedKeyOut, respData, wrappedKeySz);

    return WH_ERROR_OK;
}

int wh_Client_KeyWrap(whClientContext* ctx, enum wc_CipherType cipherType,
                      uint16_t serverKeyId, void* keyIn, uint16_t keySz,
                      whNvmMetadata* metadataIn, void* wrappedKeyOut,
                      uint16_t wrappedKeySz)
{
    int ret = WH_ERROR_OK;

    if (ctx == NULL || keyIn == NULL || metadataIn == NULL ||
        wrappedKeyOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyWrapRequest(ctx, cipherType, serverKeyId, keyIn, keySz,
                                   metadataIn);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    do {
        ret = wh_Client_KeyWrapResponse(ctx, cipherType, wrappedKeyOut,
                                        wrappedKeySz);
    } while (ret == WH_ERROR_NOTREADY);

    return ret;
}

int wh_Client_KeyUnwrapAndExportRequest(whClientContext*   ctx,
                                        enum wc_CipherType cipherType,
                                        uint16_t           serverKeyId,
                                        void*              wrappedKeyIn,
                                        uint16_t           wrappedKeySz)

{
    uint16_t                                  group  = WH_MESSAGE_GROUP_KEY;
    uint16_t                                  action = WH_KEY_KEYUNWRAPEXPORT;
    whMessageKeystore_KeyUnwrapAndExportRequest* req = NULL;
    uint8_t*                                  reqData;

    if (ctx == NULL || wrappedKeyIn == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the request pointer to the shared comm data memory region */
    req =
        (whMessageKeystore_KeyUnwrapAndExportRequest*)wh_CommClient_GetDataPtr(
            ctx->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize the request */
    req->wrappedKeySz = wrappedKeySz;
    req->serverKeyId  = serverKeyId;
    req->cipherType   = cipherType;

    /* Place the wrapped key right after the request */
    reqData = (uint8_t*)(req + 1);
    memcpy(reqData, wrappedKeyIn, wrappedKeySz);

    return wh_Client_SendRequest(ctx, group, action,
                                 sizeof(*req) + wrappedKeySz, (uint8_t*)req);
}

int wh_Client_KeyUnwrapAndExportResponse(whClientContext*   ctx,
                                         enum wc_CipherType cipherType,
                                         whNvmMetadata*     metadataOut,
                                         void* keyOut, uint16_t keySz)
{
    int                                        ret;
    uint16_t                                   group;
    uint16_t                                   action;
    uint16_t                                   size;
    whMessageKeystore_KeyUnwrapAndExportResponse* resp = NULL;
    uint8_t*                                   respData;

    if (ctx == NULL || metadataOut == NULL || keyOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the response pointer to the shared comm data memory region */
    resp =
        (whMessageKeystore_KeyUnwrapAndExportResponse*)wh_CommClient_GetDataPtr(
            ctx->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive the response */
    ret = wh_Client_RecvResponse(ctx, &group, &action, &size, (uint8_t*)resp);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (group != WH_MESSAGE_GROUP_KEY || action != WH_KEY_KEYUNWRAPEXPORT ||
        size < sizeof(*resp) ||
        size > sizeof(*resp) + sizeof(*metadataOut) + keySz ||
        resp->cipherType != cipherType) {
        return WH_ERROR_ABORTED;
    }

    if (resp->rc != WH_ERROR_OK) {
        return resp->rc;
    }
    else if (resp->keySz != keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Copy the metadata and key from the response data into metadataOut and
     * keyOut */
    respData = (uint8_t*)(resp + 1);
    memcpy(metadataOut, respData, sizeof(*metadataOut));
    memcpy(keyOut, respData + sizeof(*metadataOut), keySz);

    return WH_ERROR_OK;
}

int wh_Client_KeyUnwrapAndExport(whClientContext*   ctx,
                                 enum wc_CipherType cipherType,
                                 uint16_t serverKeyId, void* wrappedKeyIn,
                                 uint16_t       wrappedKeySz,
                                 whNvmMetadata* metadataOut, void* keyOut,
                                 uint16_t keySz)
{
    int ret = WH_ERROR_OK;

    if (ctx == NULL || wrappedKeyIn == NULL || metadataOut == NULL ||
        keyOut == NULL)
        return WH_ERROR_BADARGS;

    ret = wh_Client_KeyUnwrapAndExportRequest(ctx, cipherType, serverKeyId,
                                              wrappedKeyIn, wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    do {
        ret = wh_Client_KeyUnwrapAndExportResponse(ctx, cipherType, metadataOut,
                                                   keyOut, keySz);
    } while (ret == WH_ERROR_NOTREADY);

    return ret;
}

int wh_Client_KeyUnwrapAndCacheRequest(whClientContext*   ctx,
                                       enum wc_CipherType cipherType,
                                       uint16_t serverKeyId, void* wrappedKeyIn,
                                       uint16_t wrappedKeySz)
{
    uint16_t group  = WH_MESSAGE_GROUP_KEY;
    uint16_t action = WH_KEY_KEYUNWRAPCACHE;

    whMessageKeystore_KeyUnwrapAndCacheRequest* req = NULL;
    uint8_t*                                 reqData;

    if (ctx == NULL || wrappedKeyIn == NULL)
        return WH_ERROR_BADARGS;

    /* Set the request pointer to the shared comm data memory region */
    req = (whMessageKeystore_KeyUnwrapAndCacheRequest*)wh_CommClient_GetDataPtr(
        ctx->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize the request */
    req->wrappedKeySz = wrappedKeySz;
    req->serverKeyId  = serverKeyId;
    req->cipherType   = cipherType;

    /* Place the wrapped key right after the request */
    reqData = (uint8_t*)(req + 1);
    memcpy(reqData, wrappedKeyIn, wrappedKeySz);

    return wh_Client_SendRequest(ctx, group, action,
                                 sizeof(*req) + wrappedKeySz, (uint8_t*)req);
}

int wh_Client_KeyUnwrapAndCacheResponse(whClientContext*   ctx,
                                        enum wc_CipherType cipherType,
                                        uint16_t*          keyIdOut)
{
    int                                       ret;
    uint16_t                                  group;
    uint16_t                                  action;
    uint16_t                                  size;
    whMessageKeystore_KeyUnwrapAndCacheResponse* resp = NULL;

    if (ctx == NULL || keyIdOut == NULL)
        return WH_ERROR_BADARGS;

    /* Set the response pointer to the shared comm data memory region */
    resp =
        (whMessageKeystore_KeyUnwrapAndCacheResponse*)wh_CommClient_GetDataPtr(
            ctx->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive the response */
    ret = wh_Client_RecvResponse(ctx, &group, &action, &size, (uint8_t*)resp);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (group != WH_MESSAGE_GROUP_KEY || action != WH_KEY_KEYUNWRAPCACHE ||
        size < sizeof(*resp) || resp->cipherType != cipherType) {
        return WH_ERROR_ABORTED;
    }

    if (resp->rc != 0) {
        return resp->rc;
    }

    /* Server returns ID portion only. Client must track ownership
     * and specify appropriate flags when later using the key. */
    *keyIdOut = resp->keyId;

    return WH_ERROR_OK;
}

int wh_Client_KeyUnwrapAndCache(whClientContext*   ctx,
                                enum wc_CipherType cipherType,
                                uint16_t serverKeyId, void* wrappedKeyIn,
                                uint16_t wrappedKeySz, uint16_t* keyIdOut)
{
    int ret = WH_ERROR_OK;

    if (ctx == NULL || wrappedKeyIn == NULL || keyIdOut == NULL)
        return WH_ERROR_BADARGS;

    ret = wh_Client_KeyUnwrapAndCacheRequest(ctx, cipherType, serverKeyId,
                                             wrappedKeyIn, wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    do {
        ret = wh_Client_KeyUnwrapAndCacheResponse(ctx, cipherType, keyIdOut);
    } while (ret == WH_ERROR_NOTREADY);

    return ret;
}

int wh_Client_DataWrapRequest(whClientContext*   ctx,
                              enum wc_CipherType cipherType,
                              uint16_t serverKeyId, void* dataIn,
                              uint32_t dataInSz)
{
    uint16_t group  = WH_MESSAGE_GROUP_KEY;
    uint16_t action = WH_KEY_DATAWRAP;

    whMessageKeystore_DataWrapRequest* req = NULL;
    uint8_t*                           reqData;

    if (ctx == NULL || dataIn == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the request pointer to the shared comm data memory region */
    req =
        (whMessageKeystore_DataWrapRequest*)wh_CommClient_GetDataPtr(ctx->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }

    req->dataSz      = dataInSz;
    req->serverKeyId = serverKeyId;
    req->cipherType  = cipherType;

    /* Place the wrapped key right after the request */
    reqData = (uint8_t*)(req + 1);
    memcpy(reqData, dataIn, dataInSz);

    return wh_Client_SendRequest(ctx, group, action, sizeof(*req) + dataInSz,
                                 (uint8_t*)req);
}

int wh_Client_DataWrapResponse(whClientContext*   ctx,
                               enum wc_CipherType cipherType,
                               void* wrappedDataOut, uint32_t wrappedDataSz)
{
    int                                 ret;
    uint16_t                            group;
    uint16_t                            action;
    uint16_t                            size;
    whMessageKeystore_DataWrapResponse* resp = NULL;
    uint8_t*                            respData;

    if (ctx == NULL || wrappedDataOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the response pointer to the shared comm data memory region */
    resp = (whMessageKeystore_DataWrapResponse*)wh_CommClient_GetDataPtr(
        ctx->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive the response */
    ret = wh_Client_RecvResponse(ctx, &group, &action, &size, (uint8_t*)resp);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (group != WH_MESSAGE_GROUP_KEY || action != WH_KEY_DATAWRAP ||
        size < sizeof(*resp) || size > sizeof(*resp) + wrappedDataSz ||
        resp->wrappedDataSz != wrappedDataSz ||
        resp->cipherType != cipherType) {
        return WH_ERROR_ABORTED;
    }

    if (resp->rc != 0) {
        return resp->rc;
    }

    /* Copy the wrapped key from the response data into wrappedKeyOut */
    respData = (uint8_t*)(resp + 1);
    memcpy(wrappedDataOut, respData, wrappedDataSz);

    return WH_ERROR_OK;
}

int wh_Client_DataWrap(whClientContext* ctx, enum wc_CipherType cipherType,
                       uint16_t serverKeyId, void* dataIn, uint32_t dataInSz,
                       void* wrappedDataOut, uint32_t wrappedDataOutSz)
{
    int ret;
    if (ctx == NULL || wrappedDataOut == NULL || dataIn == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_DataWrapRequest(ctx, cipherType, serverKeyId, dataIn,
                                    dataInSz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    do {
        ret = wh_Client_DataWrapResponse(ctx, cipherType, wrappedDataOut,
                                         wrappedDataOutSz);

    } while (ret == WH_ERROR_NOTREADY);

    return ret;
}

int wh_Client_DataUnwrapRequest(whClientContext*   ctx,
                                enum wc_CipherType cipherType,
                                uint16_t serverKeyId, void* wrappedDataIn,
                                uint32_t wrappedDataInSz)
{
    uint16_t group  = WH_MESSAGE_GROUP_KEY;
    uint16_t action = WH_KEY_DATAUNWRAP;

    whMessageKeystore_DataUnwrapRequest* req = NULL;
    uint8_t*                             reqData;

    if (ctx == NULL || wrappedDataIn == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the request pointer to the shared comm data memory region */
    req = (whMessageKeystore_DataUnwrapRequest*)wh_CommClient_GetDataPtr(
        ctx->comm);
    if (req == NULL) {
        return WH_ERROR_BADARGS;
    }

    req->wrappedDataSz = wrappedDataInSz;
    req->serverKeyId   = serverKeyId;
    req->cipherType    = cipherType;

    /* Place the wrapped data right after the request */
    reqData = (uint8_t*)(req + 1);
    memcpy(reqData, wrappedDataIn, wrappedDataInSz);

    return wh_Client_SendRequest(ctx, group, action,
                                 sizeof(*req) + wrappedDataInSz, (uint8_t*)req);
}

int wh_Client_DataUnwrapResponse(whClientContext*   ctx,
                                 enum wc_CipherType cipherType, void* dataOut,
                                 uint32_t dataSz)
{
    int                                   ret;
    uint16_t                              group;
    uint16_t                              action;
    uint16_t                              size;
    whMessageKeystore_DataUnwrapResponse* resp = NULL;
    uint8_t*                              respData;

    if (ctx == NULL || dataOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Set the response pointer to the shared comm data memory region */
    resp = (whMessageKeystore_DataUnwrapResponse*)wh_CommClient_GetDataPtr(
        ctx->comm);
    if (resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Receive the response */
    ret = wh_Client_RecvResponse(ctx, &group, &action, &size, (uint8_t*)resp);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (group != WH_MESSAGE_GROUP_KEY || action != WH_KEY_DATAUNWRAP ||
        size < sizeof(*resp) || size > sizeof(*resp) + dataSz ||
        resp->dataSz != dataSz || resp->cipherType != cipherType) {
        return WH_ERROR_ABORTED;
    }

    if (resp->rc != 0) {
        return resp->rc;
    }

    /* Copy the wrapped key from the response data into wrappedKeyOut */
    respData = (uint8_t*)(resp + 1);
    memcpy(dataOut, respData, dataSz);

    return WH_ERROR_OK;
}
int wh_Client_DataUnwrap(whClientContext* ctx, enum wc_CipherType cipherType,
                         uint16_t serverKeyId, void* wrappedDataIn,
                         uint32_t wrappedDataInSz, void* dataOut,
                         uint32_t dataOutSz)
{
    int ret;
    if (ctx == NULL || wrappedDataIn == NULL || dataOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_DataUnwrapRequest(ctx, cipherType, serverKeyId,
                                      wrappedDataIn, wrappedDataInSz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    do {
        ret = wh_Client_DataUnwrapResponse(ctx, cipherType, dataOut, dataOutSz);

    } while (ret == WH_ERROR_NOTREADY);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
#endif /* WOLFHSM_CFG_KEYWRAP */
