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
 * wolfhsm/wh_server_crypto.h
 *
 */

#ifndef WOLFHSM_WH_SERVER_CRYPTO_H_
#define WOLFHSM_WH_SERVER_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_server.h"

int wh_Server_HandleCryptoRequest(whServerContext* ctx, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet);

int wh_Server_HandleCryptoDmaRequest(whServerContext* ctx, uint16_t magic,
                                     uint16_t action, uint16_t seq,
                                     uint16_t req_size, const void* req_packet,
                                     uint16_t* out_resp_size,
                                     void*     resp_packet);

#ifndef NO_RSA

/* Store a RsaKey into a server key cache with optional metadata */
int wh_Server_CacheImportRsaKey(whServerContext* ctx, RsaKey* key,
        whKeyId keyId, whNvmFlags flags, uint32_t label_len, uint8_t* label);

/* Restore a RsaKey from a server key cache */
int wh_Server_CacheExportRsaKey(whServerContext* ctx, whKeyId keyId,
        RsaKey* key);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
int wh_Server_EccKeyCacheImport(whServerContext* ctx, ecc_key* key,
        whKeyId keyId, whNvmFlags flags, uint16_t label_len, uint8_t* label);

int wh_Server_EccKeyCacheExport(whServerContext* ctx, whKeyId keyId,
        ecc_key* key);
#endif

#ifdef HAVE_ED25519
int wh_Server_CacheImportEd25519Key(whServerContext* ctx, ed25519_key* key,
                                    whKeyId keyId, whNvmFlags flags,
                                    uint16_t label_len, uint8_t* label);

int wh_Server_CacheExportEd25519Key(whServerContext* ctx, whKeyId keyId,
                                    ed25519_key* key);
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519

/* Store a curve25519_key into a server key cache with optional metadata */
int wh_Server_CacheImportCurve25519Key(whServerContext* server,
        curve25519_key* key,
        whKeyId keyId, whNvmFlags flags, uint16_t label_len, uint8_t* label);
/* Restore a curve25519_key from a server key cache */
int wh_Server_CacheExportCurve25519Key(whServerContext* server, whKeyId keyId,
        curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifdef WOLFSSL_HAVE_MLDSA
/* Store a wc_MlDsaKey into a server key cache with optional metadata */
int wh_Server_MlDsaKeyCacheImport(whServerContext* ctx, wc_MlDsaKey* key,
                                  whKeyId keyId, whNvmFlags flags,
                                  uint16_t label_len, uint8_t* label);
/* Restore a wc_MlDsaKey from a server key cache */
int wh_Server_MlDsaKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                  wc_MlDsaKey* key);
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
/* Store a MlKemKey into a server key cache with optional metadata */
int wh_Server_MlKemKeyCacheImport(whServerContext* ctx, MlKemKey* key,
                                  whKeyId keyId, whNvmFlags flags,
                                  uint16_t label_len, uint8_t* label);
/* Restore a MlKemKey from a server key cache */
int wh_Server_MlKemKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                  MlKemKey* key);
#endif /* WOLFSSL_HAVE_MLKEM */

#ifdef WOLFSSL_HAVE_LMS
/* Persist an LmsKey (param descriptor + pub + priv_raw) into the server key
 * cache. Subsequent sign operations reload state from this slot via
 * wh_Server_LmsKeyCacheExport. */
int wh_Server_LmsKeyCacheImport(whServerContext* ctx, LmsKey* key,
                                whKeyId keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label);
/* Restore an LmsKey from a server key cache slot. The key is left in a state
 * suitable for installing read/write callbacks before invoking
 * wc_LmsKey_Reload. */
int wh_Server_LmsKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                LmsKey* key);
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
int wh_Server_XmssKeyCacheImport(whServerContext* ctx, XmssKey* key,
                                 const char* paramStr, whKeyId keyId,
                                 whNvmFlags flags, uint16_t label_len,
                                 uint8_t* label);
int wh_Server_XmssKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                 XmssKey* key);
#endif /* WOLFSSL_HAVE_XMSS */

#ifdef HAVE_HKDF
/* Store HKDF output into a server key cache with optional metadata */
int wh_Server_HkdfKeyCacheImport(whServerContext* ctx, const uint8_t* keyData,
                                 uint32_t keySize, whKeyId keyId,
                                 whNvmFlags flags, uint16_t label_len,
                                 uint8_t* label);
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
/* Store CMAC KDF output into a server key cache with optional metadata */
int wh_Server_CmacKdfKeyCacheImport(whServerContext* ctx,
                                    const uint8_t* keyData, uint32_t keySize,
                                    whKeyId keyId, whNvmFlags flags,
                                    uint16_t label_len, uint8_t* label);
#endif /* HAVE_CMAC_KDF */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* !WOLFHSM_WH_SERVER_CRYPTO_H_ */
