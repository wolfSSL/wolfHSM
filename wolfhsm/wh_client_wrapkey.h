#ifndef WOLFHSM_WH_CLIENT_WRAPKEY_H_
#define WOLFHSM_WH_CLIENT_WRAPKEY_H_

#include <stdint.h>
#include <wolfhsm/wh_client.h>

int wh_Client_AesGcmWrapKey(whClientContext* ctx, uint16_t serverKeyId,
                            void* keyIn, uint16_t keySz,
                            whNvmMetadata* metadataIn, void* wrappedKeyOut,
                            uint16_t wrappedKeySz);

int wh_Client_AesGcmWrapKeyRequest(whClientContext* ctx, uint16_t serverKeyId,
                                   void* key, uint16_t keySz,
                                   whNvmMetadata* metadata);

int wh_Client_AesGcmWrapKeyResponse(whClientContext* ctx, void* wrappedKeyOut,
                                    uint16_t wrappedKeySz);


int wh_Client_AesGcmUnwrapKey(whClientContext* ctx, uint16_t serverKeyId,
                              void* wrappedKeyIn, uint16_t wrappedKeySz,
                              whNvmMetadata* metadataOut, void* keyOut,
                              uint16_t keySz);

int wh_Client_AesGcmUnwrapKeyRequest(whClientContext* ctx, uint16_t serverKeyId,
                                     void* wrappedKeyIn, uint16_t wrappedKeySz);

int wh_Client_AesGcmUnwrapKeyResponse(whClientContext* ctx,
                                      whNvmMetadata* metadataOut, void* keyOut,
                                      uint16_t keySz);

int wh_Client_AesGcmWrapKeyCache(whClientContext* ctx, uint16_t serverKeyId,
                                 void* wrappedKeyIn, uint16_t wrappedKeySz,
                                 uint16_t* keyIdOut);

int wh_Client_AesGcmWrapKeyCacheRequest(whClientContext* ctx,
                                        uint16_t         serverKeyId,
                                        void*            wrappedKeyIn,
                                        uint16_t         wrappedKeySz);

int wh_Client_AesGcmWrapKeyCacheResponse(whClientContext* ctx,
                                         uint16_t*        keyIdOut);
#endif
