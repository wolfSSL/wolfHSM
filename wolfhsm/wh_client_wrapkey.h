#ifndef WOLFHSM_WH_CLIENT_WRAPKEY_H_
#define WOLFHSM_WH_CLIENT_WRAPKEY_H_

#include <stdint.h>
#include <wolfhsm/wh_client.h>
#include <wolfssl/wolfcrypt/types.h>

int wh_Client_WrapKey(whClientContext* ctx, enum wc_CipherType cipherType,
                      uint16_t serverKeyId,
                      void* keyIn, uint16_t keySz,
                      whNvmMetadata* metadataIn, void* wrappedKeyOut,
                      uint16_t wrappedKeySz);

int wh_Client_WrapKeyRequest(whClientContext* ctx, enum wc_CipherType cipherType,
                             uint16_t serverKeyId,
                             void* key, uint16_t keySz,
                             whNvmMetadata* metadata);

int wh_Client_WrapKeyResponse(whClientContext* ctx, enum wc_CipherType cipherType,
                              void* wrappedKeyOut,
                              uint16_t wrappedKeySz);


int wh_Client_UnwrapKeyExport(whClientContext* ctx, enum wc_CipherType cipherType,
                              uint16_t serverKeyId,
                              void* wrappedKeyIn, uint16_t wrappedKeySz,
                              whNvmMetadata* metadataOut, void* keyOut,
                              uint16_t keySz);

int wh_Client_UnwrapKeyExportRequest(whClientContext* ctx, enum wc_CipherType cipherType,
                                     uint16_t serverKeyId,
                                     void* wrappedKeyIn, uint16_t wrappedKeySz);

int wh_Client_UnwrapKeyExportResponse(whClientContext* ctx,
                                      enum wc_CipherType cipherType,
                                      whNvmMetadata* metadataOut, void* keyOut,
                                      uint16_t keySz);

int wh_Client_UnwrapKeyCache(whClientContext* ctx, enum wc_CipherType cipherType,
                             uint16_t serverKeyId,
                             void* wrappedKeyIn, uint16_t wrappedKeySz,
                             uint16_t* keyIdOut);

int wh_Client_UnwrapKeyCacheRequest(whClientContext* ctx,
                                    enum wc_CipherType cipherType,
                                    uint16_t         serverKeyId,
                                    void*            wrappedKeyIn,
                                    uint16_t         wrappedKeySz);

int wh_Client_UnrapKeyCacheResponse(whClientContext* ctx,
                                    enum wc_CipherType cipherType,
                                    uint16_t*        keyIdOut);
#endif
