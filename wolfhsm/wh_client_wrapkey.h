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


int wh_Client_UnwrapKey(whClientContext* ctx, enum wc_CipherType cipherType,
                        uint16_t serverKeyId,
                        void* wrappedKeyIn, uint16_t wrappedKeySz,
                        whNvmMetadata* metadataOut, void* keyOut,
                        uint16_t keySz);

int wh_Client_UnwrapKeyRequest(whClientContext* ctx, enum wc_CipherType cipherType,
                               uint16_t serverKeyId,
                               void* wrappedKeyIn, uint16_t wrappedKeySz);

int wh_Client_UnwrapKeyResponse(whClientContext* ctx,
                                enum wc_CipherType cipherType,
                                whNvmMetadata* metadataOut, void* keyOut,
                                uint16_t keySz);

int wh_Client_WrapKeyCache(whClientContext* ctx, enum wc_CipherType cipherType,
                           uint16_t serverKeyId,
                           void* wrappedKeyIn, uint16_t wrappedKeySz,
                           uint16_t* keyIdOut);

int wh_Client_WrapKeyCacheRequest(whClientContext* ctx,
                                  enum wc_CipherType cipherType,
                                  uint16_t         serverKeyId,
                                  void*            wrappedKeyIn,
                                  uint16_t         wrappedKeySz);

int wh_Client_WrapKeyCacheResponse(whClientContext* ctx,
                                   enum wc_CipherType cipherType,
                                   uint16_t*        keyIdOut);
#endif
