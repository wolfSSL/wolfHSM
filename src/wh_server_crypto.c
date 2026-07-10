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
 * src/wh_server/cryptocb.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_SERVER)

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#ifdef WOLFSSL_SHA3
#include "wolfssl/wolfcrypt/sha3.h"
#endif
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#if defined(WOLFSSL_HAVE_LMS)
#include "wolfssl/wolfcrypt/wc_lms.h"
#endif
#if defined(WOLFSSL_HAVE_XMSS)
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/kdf.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wolfhsm/wh_server.h"

#include "wolfhsm/wh_message_crypto.h"

/** Forward declarations */
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
/* Process a Generate RsaKey request packet and produce a response packet */
static int _HandleRsaKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
#endif /* WOLFSSL_KEY_GEN */

/* Process a Rng request packet and produce a response packet */
static int _HandleRng(whServerContext* ctx, uint16_t magic, int devId,
                      const void* cryptoDataIn, uint16_t inSize,
                      void* cryptoDataOut, uint16_t* outSize);

/* Process a Rsa Function request packet and produce a response packet */
static int _HandleRsaFunction(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);

/* Process a Rsa Get Size request packet and produce a response packet */
static int _HandleRsaGetSize(whServerContext* ctx, uint16_t magic, int devId,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize);
#endif /* !NO_RSA */

#ifdef HAVE_HKDF
/* Process an HKDF request packet and produce a response packet */
static int _HandleHkdf(whServerContext* ctx, uint16_t magic, int devId,
                       const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_HKDF */

#ifndef NO_AES

#ifdef WOLFSSL_AES_COUNTER
/* Process a AES CBC request packet and produce a response packet */
static int _HandleAesCtr(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_ECB
static int _HandleAesEcb(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
static int _HandleAesCbc(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
static int _HandleAesGcm(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#ifdef HAVE_ECC
static int _HandleEccKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
#ifdef HAVE_ECC_DHE
static int _HandleEccSharedSecret(whServerContext* ctx, uint16_t magic,
                                  int devId, const void* cryptoDataIn,
                                  uint16_t inSize, void* cryptoDataOut,
                                  uint16_t* outSize);
#endif /* HAVE_ECC_DHE */
#ifdef HAVE_ECC_SIGN
static int _HandleEccSign(whServerContext* ctx, uint16_t magic, int devId,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_ECC_SIGN */
#ifdef HAVE_ECC_VERIFY
static int _HandleEccVerify(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_ECC_VERIFY */
static int _HandleEccMakePub(whServerContext* ctx, uint16_t magic, int devId,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize);
#ifdef HAVE_ECC_CHECK_KEY
static int _HandleEccCheckPubKey(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize);
#endif /* HAVE_ECC_CHECK_KEY */
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Process a Generate curve25519_key request packet and produce a response */
static int _HandleCurve25519KeyGen(whServerContext* ctx, uint16_t magic,
                                   int devId, const void* cryptoDataIn,
                                   uint16_t inSize, void* cryptoDataOut,
                                   uint16_t* outSize);

/* Process a curve25519_key Function request packet and produce a response */
static int _HandleCurve25519SharedSecret(whServerContext* ctx, uint16_t magic,
                                         int devId, const void* cryptoDataIn,
                                         uint16_t inSize, void* cryptoDataOut,
                                         uint16_t* outSize);
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
static int _HandleEd25519KeyGen(whServerContext* ctx, uint16_t magic, int devId,
                                const void* cryptoDataIn, uint16_t inSize,
                                void* cryptoDataOut, uint16_t* outSize);
static int _HandleEd25519Sign(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
static int _HandleEd25519Verify(whServerContext* ctx, uint16_t magic, int devId,
                                const void* cryptoDataIn, uint16_t inSize,
                                void* cryptoDataOut, uint16_t* outSize);
#ifdef WOLFHSM_CFG_DMA
static int _HandleEd25519SignDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize);
static int _HandleEd25519VerifyDma(whServerContext* ctx, uint16_t magic,
                                   int devId, const void* cryptoDataIn,
                                   uint16_t inSize, void* cryptoDataOut,
                                   uint16_t* outSize);
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifdef WOLFSSL_HAVE_MLDSA
/* Process an ML-DSA KeyGen request packet and produce a response packet */
static int _HandleMlDsaKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
/* Process an ML-DSA Sign request packet and produce a response packet */
static int _HandleMlDsaSign(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
/* Process an ML-DSA Verify request packet and produce a response packet */
static int _HandleMlDsaVerify(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
/* Process an ML-DSA Check PrivKey request packet and produce a response
 * packet */
static int _HandleMlDsaCheckPrivKey(whServerContext* ctx, uint16_t magic,
                                    int devId, const void* cryptoDataIn,
                                    uint16_t inSize, void* cryptoDataOut,
                                    uint16_t* outSize);
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
static int _HandleMlKemKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
static int _HandleMlKemEncaps(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
static int _HandleMlKemDecaps(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
#ifdef WOLFHSM_CFG_DMA
static int _HandleMlKemKeyGenDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize);
static int _HandleMlKemEncapsDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize);
static int _HandleMlKemDecapsDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize);
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_HAVE_MLKEM */

/** Public server crypto functions */

#ifndef NO_RSA
int wh_Server_CacheImportRsaKey(whServerContext* ctx, RsaKey* key,
        whKeyId keyId, whNvmFlags flags, uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t max_size;
    uint16_t der_size;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            (WH_KEYID_ISERASED(keyId)) ||
            ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    /* wc_RsaKeyToDer doesn't have a length check option so we need to just pass
     * the big key size if compiled */
    /* TODO: Change this to use an estimate of the DER size based on key len */
    if(WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT > 0) {
        max_size = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    } else {
        max_size = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE;
    }

    /* get a free slot */
    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, max_size, &cacheBuf,
                                                &cacheMeta);
    if (ret == 0) {
        ret = wh_Crypto_RsaSerializeKeyDer(key, max_size, cacheBuf, &der_size);
    }

    if (ret == 0) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = der_size;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if (    (label != NULL) &&
                (label_len > 0) ) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }
    return ret;
}

int wh_Server_CacheExportRsaKey(whServerContext* ctx, whKeyId keyId,
        RsaKey* key)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = 0;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }
    /* Load key from NVM into a cache slot if necessary */
    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);

    if (ret == 0) {
        ret = wh_Crypto_RsaDeserializeKeyDer(cacheMeta->len, cacheBuf, key);
    }
    return ret;
}

#ifdef WOLFSSL_KEY_GEN
static int _HandleRsaKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    int    ret    = 0;
    RsaKey rsa[1] = {0};
    whMessageCrypto_RsaKeyGenRequest req;
    whMessageCrypto_RsaKeyGenResponse res;
    if (inSize < sizeof(whMessageCrypto_RsaKeyGenRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateRsaKeyGenRequest(
        magic, (const whMessageCrypto_RsaKeyGenRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    int  key_size = req.size;
    long e        = req.e;

    /* Force incoming key_id to have current user/type */
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    whNvmFlags flags      = req.flags;
    uint8_t*   label      = req.label;
    uint32_t   label_size = WH_NVM_LABEL_LEN;

    /* Get pointer to where key data would be stored (after response struct) */
    uint8_t* out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_RsaKeyGenResponse);
    uint16_t max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                                   ((uint8_t*)out - (uint8_t*)cryptoDataOut));
    uint16_t der_size = 0;

    /* init the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    if (ret == 0) {
        /* make the rsa key with the given params */
        ret = wc_MakeRsaKey(rsa, key_size, e, ctx->crypto->rng);
        WH_DEBUG_SERVER_VERBOSE("MakeRsaKey: size:%d, e:%ld, ret:%d\n", key_size, e, ret);

        if (ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response packet */
                ret =
                    wh_Crypto_RsaSerializeKeyDer(rsa, max_size, out, &der_size);
                if (ret == 0) {
                    res.keyId = 0;
                    res.len   = der_size;
                }
            }
            else {
                /* Must import the key into the cache and return keyid */
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                    WH_DEBUG_SERVER_VERBOSE("RsaKeyGen UniqueId: keyId:%u, ret:%d\n", key_id, ret);
                    if (ret != WH_ERROR_OK) {
                        /* Early return on unique ID generation failure */
                        wc_FreeRsaKey(rsa);
                        return ret;
                    }
                }

                if (ret == 0) {
                    ret = wh_Server_CacheImportRsaKey(ctx, rsa, key_id, flags,
                                                      label_size, label);
                }
                WH_DEBUG_SERVER_VERBOSE("RsaKeyGen CacheKeyRsa: keyId:%u, ret:%d\n", key_id, ret);
                if (ret == 0) {
                    /* Best-effort public key export: when the serialized
                     * public key fits in the response body, return it so the
                     * client can skip a separate ExportPublicKey call. When it
                     * does not fit (small comm buffer or a large key), leave the
                     * body empty and keep the cached key. Plain MakeCacheKey
                     * callers ignore the body and see no regression;
                     * MakeCacheKeyAndExportPublic callers detect the empty body
                     * and evict the key themselves. */
                    int pub_ret = wc_RsaKeyToPublicDer(rsa, out, max_size);
                    if (pub_ret > 0) {
                        der_size = (uint16_t)pub_ret;
                    }
                    else {
                        der_size = 0;
                    }
                }
                if (ret == 0) {
                    res.keyId = wh_KeyId_TranslateToClient(key_id);
                    res.len   = der_size;
                }
            }
        }
        wc_FreeRsaKey(rsa);
    }

    if (ret == 0) {
        wh_MessageCrypto_TranslateRsaKeyGenResponse(
            magic, &res, (whMessageCrypto_RsaKeyGenResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_RsaKeyGenResponse) + res.len;
    }

    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

static int _HandleRsaFunction(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
    int                        ret;
    RsaKey                     rsa[1];
    whMessageCrypto_RsaRequest req;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_RsaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateRsaRequest(
        magic, (const whMessageCrypto_RsaRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    int      op_type = (int)(req.opType);
    uint32_t options = req.options;
    int      evict   = !!(options & WH_MESSAGE_CRYPTO_RSA_OPTIONS_EVICT);
    whKeyId  key_id  = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    word32 in_len  = (word32)(req.inLen);
    word32 out_len = (word32)(req.outLen);

    /* Ensure input data fits within request payload */
    uint32_t available = inSize - sizeof(whMessageCrypto_RsaRequest);
    if (in_len > available) {
        return WH_ERROR_BADARGS;
    }

    /* in and out are after the fixed size fields */
    const byte* in  = (const byte*)cryptoDataIn + sizeof(whMessageCrypto_RsaRequest);
    byte*       out = (byte*)cryptoDataOut + sizeof(whMessageCrypto_RsaResponse);

    WH_DEBUG_SERVER_VERBOSE("HandleRsaFunction opType:%d inLen:%u keyId:%u outLen:%u\n",
            op_type, in_len, key_id, out_len);
    switch (op_type)
    {
    case RSA_PUBLIC_ENCRYPT:
    case RSA_PUBLIC_DECRYPT:
    case RSA_PRIVATE_ENCRYPT:
    case RSA_PRIVATE_DECRYPT:
        /* Valid op_types */
        break;
    default:
        /* Invalid opType */
        WH_DEBUG_SERVER_VERBOSE("Unknown opType:%d\n", op_type);

        return BAD_FUNC_ARG;
    }

    /* Validate key usage policy based on RSA operation type */
    if (!WH_KEYID_ISERASED(key_id)) {
        whNvmFlags requiredUsage = WH_NVM_FLAGS_NONE;
        switch (op_type) {
            case RSA_PUBLIC_ENCRYPT:
            case RSA_PRIVATE_ENCRYPT:
                requiredUsage = WH_NVM_FLAGS_USAGE_ENCRYPT;
                break;
            case RSA_PUBLIC_DECRYPT:
            case RSA_PRIVATE_DECRYPT:
                requiredUsage = WH_NVM_FLAGS_USAGE_DECRYPT;
                break;
        }
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id, requiredUsage);
        if (ret != WH_ERROR_OK) {
            /* Currently wolfCrypt doesn't have a way for crypto callbacks to
            distinguish if a low level RSA operation (like encrypt/decrypt) is
            being performed as part of a higher level operation like
            sign/verify. Until that information is propagated to the
            callback, the usage flags are treated as equivalent. */
            if (ret == WH_ERROR_USAGE) {
                if (op_type == RSA_PUBLIC_DECRYPT) {
                    /* Decrypt usage flag wasn't set so this might be a verify
                     * operation. Attempt to enforce against the verify flag */
                    ret = wh_Server_KeystoreFindEnforceKeyUsage(
                        ctx, key_id, WH_NVM_FLAGS_USAGE_VERIFY);
                }
                else if (op_type == RSA_PRIVATE_ENCRYPT) {
                    /* Encrypt usage flag wasn't set so this might be a sign
                     * operation. Attempt to enforce against the sign flag */
                    ret = wh_Server_KeystoreFindEnforceKeyUsage(
                        ctx, key_id, WH_NVM_FLAGS_USAGE_SIGN);
                }
            }
            if (ret != WH_ERROR_OK) {
                goto cleanup;
            }
        }
    }

    /* init rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = wh_Server_CacheExportRsaKey(ctx, key_id, rsa);
        WH_DEBUG_SERVER_VERBOSE("CacheExportRsaKey keyid:%u, ret:%d\n", key_id, ret);
        if (ret == 0) {
            /* do the rsa operation */
            ret = wc_RsaFunction(in, in_len, out, &out_len,
                op_type, rsa, ctx->crypto->rng);
            WH_DEBUG_SERVER_VERBOSE("RsaFunction in:%p %u, out:%p, opType:%d, outLen:%d, ret:%d\n",
                    in, in_len, out, op_type, out_len, ret);
        }
        /* free the key */
        wc_FreeRsaKey(rsa);
    }
cleanup:
    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        whMessageCrypto_RsaResponse res;
        /*set outLen and outgoing message size */
        res.outLen = out_len;
        wh_MessageCrypto_TranslateRsaResponse(
            magic, &res, (whMessageCrypto_RsaResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_RsaResponse) + out_len;
    }
    return ret;
}

static int _HandleRsaGetSize(whServerContext* ctx, uint16_t magic, int devId,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize)
{
    int                                ret;
    RsaKey                             rsa[1];
    whMessageCrypto_RsaGetSizeRequest  req;
    whMessageCrypto_RsaGetSizeResponse res;
    int                                key_size = 0;

    if (inSize < sizeof(whMessageCrypto_RsaGetSizeRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateRsaGetSizeRequest(
        magic, (const whMessageCrypto_RsaGetSizeRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint32_t options = req.options;
    int      evict = !!(options & WH_MESSAGE_CRYPTO_RSA_GET_SIZE_OPTIONS_EVICT);

    /* init rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = wh_Server_CacheExportRsaKey(ctx, key_id, rsa);
        /* get the size */
        if (ret == 0) {
            key_size = wc_RsaEncryptSize(rsa);
            if (key_size < 0) {
                ret = key_size;
            }
        }
        wc_FreeRsaKey(rsa);
    }
    if (evict != 0) {
        WH_DEBUG_SERVER_VERBOSE("evicting temp key:%x options:%u evict:%u\n",
               key_id, options, evict);
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res.keySize = key_size;

        wh_MessageCrypto_TranslateRsaGetSizeResponse(
            magic, &res, (whMessageCrypto_RsaGetSizeResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_RsaGetSizeResponse);
    }
    WH_DEBUG_SERVER_VERBOSE("keyId:%d, key_size:%d, ret:%d\n", key_id,
           key_size, ret);
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
int wh_Server_EccKeyCacheImport(whServerContext* ctx, ecc_key* key,
        whKeyId keyId, whNvmFlags flags, uint16_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    /* Maximum size of an ecc key der file */
    uint16_t max_size = ECC_BUFSIZE;
    uint16_t der_size;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            WH_KEYID_ISERASED(keyId) ||
            ((label != NULL) && (label_len > sizeof(cacheMeta->label))) ) {
        return WH_ERROR_BADARGS;
    }
    /* get a free slot */
    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, max_size, &cacheBuf,
                                                &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_EccSerializeKeyDer(key, max_size, cacheBuf, &der_size);
    }

    if (ret == WH_ERROR_OK) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = der_size;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if (    (label != NULL) &&
                (label_len > 0) ) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }
    return ret;
}

int wh_Server_EccKeyCacheExport(whServerContext* ctx, whKeyId keyId,
        ecc_key* key)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = WH_ERROR_OK;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            WH_KEYID_ISERASED(keyId) ) {
        return WH_ERROR_BADARGS;
    }
    /* Load key from NVM into a cache slot if necessary */
    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);

    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_EccDeserializeKeyDer(cacheBuf, cacheMeta->len, key);
    }
    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
int wh_Server_CacheImportEd25519Key(whServerContext* ctx, ed25519_key* key,
                                    whKeyId keyId, whNvmFlags flags,
                                    uint16_t label_len, uint8_t* label)
{
    int            ret      = WH_ERROR_OK;
    uint8_t*       cacheBuf = NULL;
    whNvmMetadata* cacheMeta;
    /* Ed25519 DER (private key) is small; 128 bytes is ample headroom */
    uint16_t max_size = 128;
    uint16_t der_size = 0;

    if ((ctx == NULL) || (key == NULL) || WH_KEYID_ISERASED(keyId) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, max_size, &cacheBuf,
                                                &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_Ed25519SerializeKeyDer(key, max_size, cacheBuf,
                                               &der_size);
    }

    if (ret == WH_ERROR_OK) {
        cacheMeta->id     = keyId;
        cacheMeta->len    = der_size;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}

int wh_Server_CacheExportEd25519Key(whServerContext* ctx, whKeyId keyId,
                                    ed25519_key* key)
{
    uint8_t*       cacheBuf = NULL;
    whNvmMetadata* cacheMeta;
    int            ret = WH_ERROR_OK;

    if ((ctx == NULL) || (key == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_Ed25519DeserializeKeyDer(cacheBuf, cacheMeta->len, key);
    }
    return ret;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_CURVE25519
int wh_Server_CacheImportCurve25519Key(whServerContext* server,
                                       curve25519_key* key, whKeyId keyId,
                                       whNvmFlags flags, uint16_t label_len,
                                       uint8_t* label)
{
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    int            ret;
    uint8_t        der_buf[CURVE25519_MAX_KEY_TO_DER_SZ];
    uint16_t       keySz = sizeof(der_buf);

    if ((server == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    /* Serialize the key into the temporary buffer so we can get the size */
    ret = wh_Crypto_Curve25519SerializeKey(key, der_buf, &keySz);

    /* if successful, find a free cache slot and copy in the key data */
    if (ret == 0) {
        ret = wh_Server_KeystoreGetCacheSlotChecked(server, keyId, keySz,
                                                    &cacheBuf, &cacheMeta);
        if (ret == 0) {
            memcpy(cacheBuf, der_buf, keySz);
            /* Update metadata to cache the key */
            cacheMeta->id     = keyId;
            cacheMeta->len    = keySz;
            /* clients can't set server-only flags (e.g. trusted KEK) */
            cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
            cacheMeta->access = WH_NVM_ACCESS_ANY;
            if ((label != NULL) && (label_len > 0)) {
                memcpy(cacheMeta->label, label, label_len);
            }
        }
    }
    return ret;
}

int wh_Server_CacheExportCurve25519Key(whServerContext* server, whKeyId keyId,
        curve25519_key* key)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = 0;

    if (    (server == NULL) ||
            (key == NULL) ||
            (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }
    /* Load key from NVM into a cache slot if necessary */
    ret = wh_Server_KeystoreFreshenKey(server, keyId, &cacheBuf, &cacheMeta);

    if (ret == 0) {
        ret = wh_Crypto_Curve25519DeserializeKey(cacheBuf, cacheMeta->len, key);
        WH_DEBUG_SERVER_VERBOSE("Export25519Key id:%u ret:%d\n", keyId, ret);
        WH_DEBUG_SERVER_VERBOSE("export key:\n");
        WH_DEBUG_VERBOSE_HEXDUMP("[server] export key:", cacheBuf, cacheMeta->len);
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef WOLFSSL_HAVE_MLDSA
/* The big key cache buffer must be able to hold a full ML-DSA keypair DER,
 * otherwise wh_Server_MlDsaKeyCacheImport() can never succeed. */
WH_UTILS_STATIC_ASSERT(
    WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE >= MLDSA_MAX_BOTH_KEY_DER_SIZE,
    "WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE too small for ML-DSA keypair DER");

int wh_Server_MlDsaKeyCacheImport(whServerContext* ctx, wc_MlDsaKey* key,
                                  whKeyId keyId, whNvmFlags flags,
                                  uint16_t label_len, uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t       der_size;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    /* The key may hold a full keypair, in which case
     * wh_Crypto_MlDsaSerializeKeyDer() encodes both the public and private key
     * (wc_MlDsaKey_KeyToDer()), so size for both keys, not just the private key. */
    ret = wh_Server_KeystoreGetCacheSlotChecked(
        ctx, keyId, MLDSA_MAX_BOTH_KEY_DER_SIZE, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlDsaSerializeKeyDer(key, MLDSA_MAX_BOTH_KEY_DER_SIZE,
                                             cacheBuf, &der_size);
        WH_DEBUG_SERVER_VERBOSE("keyId:%u, ret:%d\n", keyId, ret);
    }

    if (ret == WH_ERROR_OK) {
        cacheMeta->id     = keyId;
        cacheMeta->len    = der_size;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}

int wh_Server_MlDsaKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                  wc_MlDsaKey* key)
{
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    int            ret = WH_ERROR_OK;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);

    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlDsaDeserializeKeyDer(cacheBuf, cacheMeta->len, key);
        WH_DEBUG_SERVER_VERBOSE("keyId:%u, ret:%d\n", keyId, ret);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
int wh_Server_MlKemKeyCacheImport(whServerContext* ctx, MlKemKey* key,
                                  whKeyId keyId, whNvmFlags flags,
                                  uint16_t label_len, uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t       keySize = WC_ML_KEM_MAX_PRIVATE_KEY_SIZE;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, keySize, &cacheBuf,
                                                &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlKemSerializeKey(key, keySize, cacheBuf, &keySize);
    }

    if (ret == WH_ERROR_OK) {
        cacheMeta->id     = keyId;
        cacheMeta->len    = keySize;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;
        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}

int wh_Server_MlKemKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                  MlKemKey* key)
{
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    int            ret = WH_ERROR_OK;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlKemDeserializeKey(cacheBuf, cacheMeta->len, key);
        WH_DEBUG_SERVER_VERBOSE("keyId:%u, ret:%d\n", keyId, ret);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_MLKEM */

/* The sign path (and its slot callbacks) is unavailable in verify-only builds;
 * gate on at least one non-verify-only stateful algorithm being enabled. */
#if ((defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)) ||     \
     (defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY))) &&  \
    defined(WOLFHSM_CFG_DMA)
/* Stateful-key persistence context.
 *
 * wolfCrypt's wc_LmsKey_Sign and wc_XmssKey_Sign require write/read callbacks
 * for the software path. We wire write_private_key directly to atomic NVM
 * commit (wh_Nvm_AddObjectWithReclaim): wolfCrypt's contract is to advance
 * the index, call write_cb, and only emit the signature if write_cb returned
 * success. That gives us pre-commit-then-emit ordering for free.
 *
 * This context keeps a pointer into the server's cache slot blob (laid out by
 * wh_Crypto_{Lms,Xmss}SerializeKey). Each write_cb invocation overwrites the
 * priv region of the slot in place and re-commits the entire slot. */
typedef struct whServerStatefulSigCtx {
    whServerContext* server;
    whKeyId          keyId;
    whNvmMetadata*   meta;        /* points at the cache slot's metadata */
    uint8_t*         slotBuf;     /* points at the cache slot's data buffer */
    uint16_t         hdrSz;       /* fixed header size (offset to params) */
    uint16_t         pubLen;      /* priv begins at hdrSz + paramLen + pubLen */
    uint16_t         paramLen;
    uint16_t         slotCapacity;
} whServerStatefulSigCtx;

/* Compute the priv-region offset inside the slot blob from the context. */
static uint16_t _StatefulSigPrivOffset(const whServerStatefulSigCtx* b)
{
    return (uint16_t)(b->hdrSz + b->paramLen + b->pubLen);
}

/* Update the slot blob's privLen header field in place. */
static void _StatefulSigWritePrivLen(uint8_t* slotBuf, uint16_t privLen)
{
    uint8_t* p = slotBuf + offsetof(whCryptoStatefulSigHeader, privLen);
    memcpy(p, &privLen, sizeof(privLen));
}

#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFHSM_CFG_DMA) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY)
static int _LmsSlotWriteCb(const byte* priv, word32 privSz, void* context)
{
    whServerStatefulSigCtx* b = (whServerStatefulSigCtx*)context;
    uint16_t                   privOff;
    uint32_t                   newLen;
    int                        rc;

    if ((b == NULL) || (priv == NULL) || (b->slotBuf == NULL) ||
        (b->meta == NULL)) {
        return WC_LMS_RC_BAD_ARG;
    }

    privOff = _StatefulSigPrivOffset(b);
    newLen  = (uint32_t)privOff + privSz;
    if (newLen > b->slotCapacity) {
        return WC_LMS_RC_WRITE_FAIL;
    }

    memcpy(b->slotBuf + privOff, priv, privSz);
    _StatefulSigWritePrivLen(b->slotBuf, (uint16_t)privSz);
    b->meta->len = (whNvmSize)newLen;

    /* Atomic dual-partition commit. Wolfcrypt aborts the sign if this
     * returns anything other than _SAVED_TO_NV_MEMORY, so the signature
     * never escapes for an un-persisted index. */
    rc = wh_Nvm_AddObjectWithReclaim(b->server->nvm, b->meta, b->meta->len,
                                     b->slotBuf);
    return (rc == WH_ERROR_OK) ? WC_LMS_RC_SAVED_TO_NV_MEMORY
                               : WC_LMS_RC_WRITE_FAIL;
}

static int _LmsSlotReadCb(byte* priv, word32 privSz, void* context)
{
    whServerStatefulSigCtx* b = (whServerStatefulSigCtx*)context;
    uint16_t                   privOff;

    if ((b == NULL) || (priv == NULL) || (b->slotBuf == NULL)) {
        return WC_LMS_RC_BAD_ARG;
    }

    privOff = _StatefulSigPrivOffset(b);
    if ((uint32_t)privOff + privSz > b->meta->len) {
        return WC_LMS_RC_READ_FAIL;
    }

    memcpy(priv, b->slotBuf + privOff, privSz);
    return WC_LMS_RC_READ_TO_MEMORY;
}
#endif /* WOLFSSL_HAVE_LMS && WOLFHSM_CFG_DMA && !WOLFSSL_LMS_VERIFY_ONLY */

#if defined(WOLFSSL_HAVE_XMSS) && defined(WOLFHSM_CFG_DMA) && \
    !defined(WOLFSSL_XMSS_VERIFY_ONLY)
static enum wc_XmssRc _XmssSlotWriteCb(const byte* priv, word32 privSz,
                                         void* context)
{
    whServerStatefulSigCtx* b = (whServerStatefulSigCtx*)context;
    uint16_t                   privOff;
    uint32_t                   newLen;
    int                        rc;

    if ((b == NULL) || (priv == NULL) || (b->slotBuf == NULL) ||
        (b->meta == NULL)) {
        return WC_XMSS_RC_BAD_ARG;
    }

    privOff = _StatefulSigPrivOffset(b);
    newLen  = (uint32_t)privOff + privSz;
    if (newLen > b->slotCapacity) {
        return WC_XMSS_RC_WRITE_FAIL;
    }

    memcpy(b->slotBuf + privOff, priv, privSz);
    _StatefulSigWritePrivLen(b->slotBuf, (uint16_t)privSz);
    b->meta->len = (whNvmSize)newLen;

    rc = wh_Nvm_AddObjectWithReclaim(b->server->nvm, b->meta, b->meta->len,
                                     b->slotBuf);
    return (rc == WH_ERROR_OK) ? WC_XMSS_RC_SAVED_TO_NV_MEMORY
                               : WC_XMSS_RC_WRITE_FAIL;
}

static enum wc_XmssRc _XmssSlotReadCb(byte* priv, word32 privSz,
                                        void* context)
{
    whServerStatefulSigCtx* b = (whServerStatefulSigCtx*)context;
    uint16_t                   privOff;

    if ((b == NULL) || (priv == NULL) || (b->slotBuf == NULL)) {
        return WC_XMSS_RC_BAD_ARG;
    }

    privOff = _StatefulSigPrivOffset(b);
    if ((uint32_t)privOff + privSz > b->meta->len) {
        return WC_XMSS_RC_READ_FAIL;
    }

    memcpy(priv, b->slotBuf + privOff, privSz);
    return WC_XMSS_RC_READ_TO_MEMORY;
}
#endif /* WOLFSSL_HAVE_XMSS && WOLFHSM_CFG_DMA && !WOLFSSL_XMSS_VERIFY_ONLY */
#endif /* stateful sign path enabled && WOLFHSM_CFG_DMA */

#ifdef WOLFSSL_HAVE_LMS
/* Import serializes the private key, so it is unavailable in verify-only. */
#ifndef WOLFSSL_LMS_VERIFY_ONLY
int wh_Server_LmsKeyCacheImport(whServerContext* ctx, LmsKey* key,
                                whKeyId keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t       slotCapacity = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    uint16_t       blobSize;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, slotCapacity,
                                                &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_LmsSerializeKey(key, slotCapacity, cacheBuf, &blobSize);
    }
    if (ret == WH_ERROR_OK) {
        cacheMeta->id  = keyId;
        cacheMeta->len = blobSize;
        /* Stateful private key state must never leave the HSM; reuse of a
         * one-time signature index breaks the scheme. Force non-exportable.
         * Strip server-only flags a client may never set (e.g. trusted KEK). */
        cacheMeta->flags =
            (flags & ~WH_NVM_FLAGS_SERVER_ONLY) | WH_NVM_FLAGS_NONEXPORTABLE;
        cacheMeta->access = WH_NVM_ACCESS_ANY;
        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }
    return ret;
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

int wh_Server_LmsKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                LmsKey* key)
{
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    int            ret;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_LmsDeserializeKey(cacheBuf, (uint16_t)cacheMeta->len,
                                          key);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
/* Import serializes the private key, so it is unavailable in verify-only. */
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
int wh_Server_XmssKeyCacheImport(whServerContext* ctx, XmssKey* key,
                                 const char* paramStr, whKeyId keyId,
                                 whNvmFlags flags, uint16_t label_len,
                                 uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t       slotCapacity = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    uint16_t       blobSize;

    if ((ctx == NULL) || (key == NULL) || (paramStr == NULL) ||
        (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, slotCapacity,
                                                &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_XmssSerializeKey(key, paramStr, slotCapacity, cacheBuf,
                                         &blobSize);
    }
    if (ret == WH_ERROR_OK) {
        cacheMeta->id  = keyId;
        cacheMeta->len = blobSize;
        /* Stateful private key state must never leave the HSM; reuse of a
         * one-time signature index breaks the scheme. Force non-exportable.
         * Strip server-only flags a client may never set (e.g. trusted KEK). */
        cacheMeta->flags =
            (flags & ~WH_NVM_FLAGS_SERVER_ONLY) | WH_NVM_FLAGS_NONEXPORTABLE;
        cacheMeta->access = WH_NVM_ACCESS_ANY;
        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }
    return ret;
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

int wh_Server_XmssKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                 XmssKey* key)
{
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    int            ret;

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_XmssDeserializeKey(cacheBuf, (uint16_t)cacheMeta->len,
                                           key);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_XMSS */


/** Request/Response Handling functions */

#ifdef HAVE_ECC
static int _HandleEccKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                               ret = WH_ERROR_OK;
    ecc_key                           key[1];
    whMessageCrypto_EccKeyGenRequest  req;
    whMessageCrypto_EccKeyGenResponse res;

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccKeyGenRequest(
        magic, (const whMessageCrypto_EccKeyGenRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    int     key_size = req.sz;
    int     curve_id = req.curveId;
    whKeyId key_id   = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    whNvmFlags flags      = req.flags;
    uint8_t*   label      = req.label;
    uint16_t   label_size = WH_NVM_LABEL_LEN;

    /* Response message */
    uint8_t* res_out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_EccKeyGenResponse);
    uint16_t max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                                   (res_out - (uint8_t*)cryptoDataOut));
    uint16_t res_size = 0;

    /* init ecc key */
    ret = wc_ecc_init_ex(key, NULL, devId);
    if (ret == 0) {
        /* generate the key */
        ret = wc_ecc_make_key_ex(ctx->crypto->rng, key_size, key, curve_id);
        if (ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response message. */
                key_id = WH_KEYID_ERASED;
                ret    = wh_Crypto_EccSerializeKeyDer(key, max_size, res_out,
                                                      &res_size);
            }
            else {
                /* Must import the key into the cache and return keyid
                 */
                res_size = 0;
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                    WH_DEBUG_SERVER("UniqueId: keyId:%u, ret:%d\n", key_id, ret);
                    if (ret != WH_ERROR_OK) {
                        /* Early return on unique ID generation failure */
                        wc_ecc_free(key);
                        return ret;
                    }
                }
                if (ret == 0) {
                    ret = wh_Server_EccKeyCacheImport(ctx, key, key_id, flags,
                                                      label_size, label);
                }
                WH_DEBUG_SERVER("CacheImport: keyId:%u, ret:%d\n", key_id, ret);
                if (ret == 0) {
                    /* Best-effort public key export: when the serialized
                     * public key fits in the response body, return it so the
                     * client can skip a separate ExportPublicKey call. When it
                     * does not fit (small comm buffer or a large key), leave the
                     * body empty and keep the cached key. Plain MakeCacheKey
                     * callers ignore the body and see no regression;
                     * MakeCacheKeyAndExportPublic callers detect the empty body
                     * and evict the key themselves. */
                    int pub_ret =
                        wc_EccPublicKeyToDer(key, res_out, max_size, 1);
                    if (pub_ret > 0) {
                        res_size = (uint16_t)pub_ret;
                    }
                    else {
                        res_size = 0;
                    }
                }
            }
        }
        wc_ecc_free(key);
    }

    if (ret == WH_ERROR_OK) {
        res.keyId = wh_KeyId_TranslateToClient(key_id);
        res.len   = res_size;

        wh_MessageCrypto_TranslateEccKeyGenResponse(
            magic, &res, (whMessageCrypto_EccKeyGenResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EccKeyGenResponse) + res_size;
    }
    return ret;
}

#ifdef HAVE_ECC_DHE
static int _HandleEccSharedSecret(whServerContext* ctx, uint16_t magic,
                                  int devId, const void* cryptoDataIn,
                                  uint16_t inSize, void* cryptoDataOut,
                                  uint16_t* outSize)
{
    int                         ret = WH_ERROR_OK;
    ecc_key                     pub_key[1];
    ecc_key                     prv_key[1];
    whMessageCrypto_EcdhRequest req;
    whKeyId                     out_key_id = WH_KEYID_ERASED;

    if (inSize < sizeof(whMessageCrypto_EcdhRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEcdhRequest(
        magic, (const whMessageCrypto_EcdhRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    uint32_t options   = req.options;
    int      evict_pub = !!(options & WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPUB);
    int      evict_prv = !!(options & WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPRV);
    whKeyId  pub_key_id = wh_KeyId_TranslateFromClient(
         WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.publicKeyId);
    whKeyId prv_key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.privateKeyId);
    whNvmFlags flags = (whNvmFlags)req.flags;
    int        cache = !(flags & WH_NVM_FLAGS_EPHEMERAL);

    /* Validate key usage policy for key derivation (private key) */
    if (!WH_KEYID_ISERASED(prv_key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, prv_key_id,
                                                    WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    /* Response message */
    byte* res_out =
        (byte*)cryptoDataOut + sizeof(whMessageCrypto_EcdhResponse);
    word32 max_len = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                              (res_out - (uint8_t*)cryptoDataOut));
    word32 res_len = 0;

    /* init ecc keys */
    ret = wc_ecc_init_ex(pub_key, NULL, devId);
    if (ret == 0) {
        ret = wc_ecc_init_ex(prv_key, NULL, devId);
        if (ret == 0) {
            /* set rng */
            ret = wc_ecc_set_rng(prv_key, ctx->crypto->rng);
            if (ret == 0) {
                /* load the private key */
                ret = wh_Server_EccKeyCacheExport(ctx, prv_key_id, prv_key);
            }
            if (ret == WH_ERROR_OK) {
                /* load the public key */
                ret = wh_Server_EccKeyCacheExport(ctx, pub_key_id, pub_key);
            }
            if (ret == WH_ERROR_OK) {
                /* make shared secret */
                res_len = max_len;
                ret = wc_ecc_shared_secret(prv_key, pub_key, res_out, &res_len);
            }
            wc_ecc_free(prv_key);
        }
        wc_ecc_free(pub_key);
    }

    /* If caching, move the secret out of the response buffer into a cache
     * slot and return only its keyId. */
    if ((ret == WH_ERROR_OK) && cache) {
        out_key_id = wh_KeyId_TranslateFromClient(
            WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
        /* Hold the NVM lock so id allocation and cache import are atomic
         * with respect to other server contexts under THREADSAFE. */
        ret = WH_SERVER_NVM_LOCK(ctx);
        if (ret == WH_ERROR_OK) {
            if (WH_KEYID_ISERASED(out_key_id)) {
                ret = wh_Server_KeystoreGetUniqueId(ctx, &out_key_id);
            }
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_KeyCacheImportRaw(ctx, res_out, res_len,
                                                  out_key_id, flags,
                                                  WH_NVM_LABEL_LEN, req.label);
            }
            (void)WH_SERVER_NVM_UNLOCK(ctx);
        } /* WH_SERVER_NVM_LOCK() */
        /* Scrub the secret from the response buffer regardless of import
         * success/failure. */
        memset(res_out, 0, res_len);
        /* If the cached output id collides with an auto-imported input id,
         * suppress the matching eviction so cleanup does not delete the
         * just-cached secret. */
        if (ret == WH_ERROR_OK) {
            if (evict_pub && (out_key_id == pub_key_id)) {
                evict_pub = 0;
            }
            if (evict_prv && (out_key_id == prv_key_id)) {
                evict_prv = 0;
            }
        }
    }
cleanup:
    if (evict_pub) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, pub_key_id);
    }
    if (evict_prv) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, prv_key_id);
    }
    if (ret == 0) {
        whMessageCrypto_EcdhResponse res;
        uint16_t                     payload_len;
        if (cache) {
            res.sz      = 0;
            res.keyId   = wh_KeyId_TranslateToClient(out_key_id);
            payload_len = 0;
        }
        else {
            res.sz      = res_len;
            res.keyId   = 0;
            payload_len = (uint16_t)res_len;
        }

        wh_MessageCrypto_TranslateEcdhResponse(
            magic, &res, (whMessageCrypto_EcdhResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EcdhResponse) + payload_len;
    }
    return ret;
}
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_SIGN
static int _HandleEccSign(whServerContext* ctx, uint16_t magic, int devId,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize)
{
    int                            ret;
    ecc_key                        key[1];
    whMessageCrypto_EccSignRequest req;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_EccSignRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccSignRequest(
        magic, (const whMessageCrypto_EccSignRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate variable-length fields fit within inSize */
    if (req.sz > inSize - sizeof(whMessageCrypto_EccSignRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Extract parameters from translated request */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_EccSignRequest);
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    word32   in_len  = req.sz;
    uint32_t options = req.options;
    int      evict   = !!(options & WH_MESSAGE_CRYPTO_ECCSIGN_OPTIONS_EVICT);

    /* Validate key usage policy for signing */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_SIGN);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    /* Response message */
    byte* res_out =
        (byte*)cryptoDataOut + sizeof(whMessageCrypto_EccSignResponse);
    word32 max_len = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                              (res_out - (uint8_t*)cryptoDataOut));
    word32 res_len = max_len;

    /* init private key */
    ret = wc_ecc_init_ex(key, NULL, devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE("EccSign: key_id=%x, in_len=%u, res_len=%u, ret=%d\n",
                key_id, (unsigned)in_len, (unsigned)res_len, ret);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] EccSign in:", in, in_len);
            /* sign the input */
            ret = wc_ecc_sign_hash(in, in_len, res_out, &res_len,
                                   ctx->crypto->rng, key);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] EccSign res:", res_out, res_len);
        }
        wc_ecc_free(key);
    }
cleanup:
    if (evict != 0) {
        /* typecasting to void so that not overwrite ret */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        whMessageCrypto_EccSignResponse res;
        res.sz = res_len;

        wh_MessageCrypto_TranslateEccSignResponse(
            magic, &res, (whMessageCrypto_EccSignResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EccSignResponse) + res_len;
    }
    return ret;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
static int _HandleEccVerify(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    int                               ret;
    ecc_key                           key[1];
    whMessageCrypto_EccVerifyRequest  req;
    whMessageCrypto_EccVerifyResponse res;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_EccVerifyRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccVerifyRequest(
        magic, (const whMessageCrypto_EccVerifyRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate variable-length fields fit within inSize */
    uint32_t available = inSize - sizeof(whMessageCrypto_EccVerifyRequest);
    if (req.sigSz > available) {
        return WH_ERROR_BADARGS;
    }
    available -= req.sigSz;
    if (req.hashSz > available) {
        return WH_ERROR_BADARGS;
    }

    /* Extract parameters from translated request */
    uint32_t options = req.options;
    whKeyId  key_id  = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint32_t hash_len = req.hashSz;
    uint32_t sig_len  = req.sigSz;
    uint8_t* req_sig =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_EccVerifyRequest);
    uint8_t* req_hash = req_sig + sig_len;
    int      evict    = !!(options & WH_MESSAGE_CRYPTO_ECCVERIFY_OPTIONS_EVICT);
    int      export_pub_key =
        !!(options & WH_MESSAGE_CRYPTO_ECCVERIFY_OPTIONS_EXPORTPUB);

    /* Validate key usage policy for verification */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_VERIFY);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    /* Response message */
    byte* res_pub =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_EccVerifyResponse);
    word32   max_size = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                               (res_pub - (uint8_t*)cryptoDataOut));
    uint32_t pub_size = 0;
    int      result   = 0;

    /* init public key */
    ret = wc_ecc_init_ex(key, NULL, devId);
    if (ret == 0) {
        /* load the public key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* verify the signature */
            ret = wc_ecc_verify_hash(req_sig, sig_len, req_hash, hash_len,
                                     &result, key);
            WH_DEBUG_SERVER_VERBOSE("EccVerify: key_id=%x, sig_len=%u, hash_len=%u, "
                   "result=%d, ret=%d\n",
                   key_id, (unsigned)sig_len, (unsigned)hash_len, result, ret);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] EccVerify hash:", req_hash, hash_len);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] EccVerify sig:", req_sig, sig_len);

            if ((ret == 0) && (export_pub_key != 0)) {
                /* Export the public key to the result message*/
                ret = wc_EccPublicKeyToDer(key, (byte*)res_pub, max_size, 1);
                if (ret < 0) {
                    /* Problem dumping the public key.  Set to 0 length */
                    pub_size = 0;
                }
                else {
                    pub_size = ret;
                    ret      = 0;
                }
            }
        }
        wc_ecc_free(key);
    }

cleanup:
    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res.pubSz = pub_size;
        res.res   = result;

        wh_MessageCrypto_TranslateEccVerifyResponse(
            magic, &res, (whMessageCrypto_EccVerifyResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EccVerifyResponse) + pub_size;
    }
    return ret;
}
#endif /* HAVE_ECC_VERIFY */

static int _HandleEccMakePub(whServerContext* ctx, uint16_t magic, int devId,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize)
{
    int                                ret;
    ecc_key                            key[1];
    whMessageCrypto_EccMakePubRequest  req;
    whMessageCrypto_EccMakePubResponse res;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_EccMakePubRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccMakePubRequest(
        magic, (const whMessageCrypto_EccMakePubRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    int evict = !!(req.options & WH_MESSAGE_CRYPTO_ECCMAKEPUB_OPTIONS_EVICT);

    /* Response message */
    byte* res_pub =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_EccMakePubResponse);
    word32 pub_size = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                               sizeof(whMessageCrypto_GenericResponseHeader) -
                               sizeof(whMessageCrypto_EccMakePubResponse));

    /* Deliberately no wh_Server_KeystoreFindEnforceKeyUsage(): this operation
     * only produces public material, which keystore policy treats as
     * always-exportable (see _KeystoreCheckPolicy / WH_KS_OP_EXPORT_PUBLIC).
     * The private scalar is used solely to derive the public point. */
    ret = wc_ecc_init_ex(key, NULL, devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* Always derive Q = d*G rather than returning whatever public point
             * the cached key happens to carry, so the result cannot be steered
             * by a cache entry whose stored point disagrees with its scalar.
             * This also matches software wc_ecc_make_pub(), which fails on a
             * key that holds no private scalar. The RNG blinds the multiply
             * on the multi-precision path (SP builds ignore it). */
            ret = wc_ecc_make_pub_ex(key, NULL, ctx->crypto->rng);
            if (ret == 0) {
                ret = wc_ecc_export_x963(key, res_pub, &pub_size);
            }
            WH_DEBUG_SERVER_VERBOSE("EccMakePub: key_id=%x, pub_size=%u, "
                                    "ret=%d\n",
                                    key_id, (unsigned)pub_size, ret);
        }
        wc_ecc_free(key);
    }

    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res.pubSz = pub_size;

        wh_MessageCrypto_TranslateEccMakePubResponse(
            magic, &res, (whMessageCrypto_EccMakePubResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EccMakePubResponse) + pub_size;
    }
    return ret;
}

#ifdef HAVE_ECC_CHECK_KEY
static int _HandleEccCheckPubKey(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
    int                              ret;
    ecc_key                          key[1];
    whMessageCrypto_EccCheckRequest  req;
    whMessageCrypto_EccCheckResponse res;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_EccCheckRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccCheckRequest(
        magic, (const whMessageCrypto_EccCheckRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate variable-length fields fit within inSize */
    if (req.pubSz > inSize - sizeof(whMessageCrypto_EccCheckRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Extract parameters from translated request */
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    const uint8_t* req_pub = (const uint8_t*)(cryptoDataIn) +
                             sizeof(whMessageCrypto_EccCheckRequest);
    int evict = !!(req.options & WH_MESSAGE_CRYPTO_ECCCHECK_OPTIONS_EVICT);

    /* The curve travels with the key's DER encoding, so curveId is redundant.
     * checkOrder and checkPriv are carried on the wire but clamped to a full
     * wc_ecc_check_key() here rather than honored, because:
     *  - wc_ecc_check_key() is wolfCrypt's only public validation entry point;
     *    partial validation lives in a static
     *    function reachable only from the import APIs. It is also the only
     *    route to this server's own crypto callback (the key is bound to the
     *    server devId). */
    (void)req.curveId;
    (void)req.checkOrder;
    (void)req.checkPriv;

    /* no need to enforce flags for pub key operation */
    ret = wc_ecc_init_ex(key, NULL, devId);
    if (ret == 0) {
        /* load the key to validate */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* A private-only key has no point to validate yet. Unlike make-pub
             * we derive only when one is missing: validating a key means
             * checking the point it actually carries. The RNG blinds the
             * multiply on the multi-precision path (SP builds ignore it). */
            if (key->type == ECC_PRIVATEKEY_ONLY) {
                ret = wc_ecc_make_pub_ex(key, NULL, ctx->crypto->rng);
            }
            if (ret == 0) {
                ret = wc_ecc_check_key(key);
            }
            /* Reject a key whose caller-held public point disagrees with the
             * point that actually belongs to the resident key. ECC_PRIV_KEY_E
             * matches what software wc_ecc_check_key() returns for exactly
             * this condition (ecc_check_privkey_gen: d*G != Q). */
            if ((ret == 0) && (req.pubSz > 0)) {
                byte   pub[1 + 2 * MAX_ECC_BYTES];
                word32 pub_size = sizeof(pub);

                ret = wc_ecc_export_x963(key, pub, &pub_size);
                if ((ret == 0) && ((pub_size != req.pubSz) ||
                                   (memcmp(pub, req_pub, pub_size) != 0))) {
                    ret = ECC_PRIV_KEY_E;
                }
            }
            WH_DEBUG_SERVER_VERBOSE("EccCheckPubKey: key_id=%x, pubSz=%u, "
                                    "ret=%d\n",
                                    key_id, (unsigned)req.pubSz, ret);
        }
        wc_ecc_free(key);
    }

    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    /* The validation verdict itself travels in the response header rc, which
     * is what wolfCrypt's crypto callback contract expects. */
    if (ret == 0) {
        res.ok = 1;

        wh_MessageCrypto_TranslateEccCheckResponse(
            magic, &res, (whMessageCrypto_EccCheckResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EccCheckResponse);
    }
    return ret;
}
#endif /* HAVE_ECC_CHECK_KEY */
#endif /* HAVE_ECC */


#ifndef WC_NO_RNG
static int _HandleRng(whServerContext* ctx, uint16_t magic, int devId,
                      const void* cryptoDataIn, uint16_t inSize,
                      void* cryptoDataOut, uint16_t* outSize)
{
    int                         ret = WH_ERROR_OK;
    whMessageCrypto_RngRequest  req;
    whMessageCrypto_RngResponse res;
    (void)devId;

    if (inSize < sizeof(whMessageCrypto_RngRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateRngRequest(
        magic, (const whMessageCrypto_RngRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Calculate maximum data size server can respond with (subtract headers) */
    const uint32_t server_max_data =
        WOLFHSM_CFG_COMM_DATA_LEN -
        sizeof(whMessageCrypto_GenericResponseHeader) -
        sizeof(whMessageCrypto_RngResponse);

    /* Server responds with minimum of requested size and server max capacity */
    uint32_t actual_size =
        (req.sz < server_max_data) ? req.sz : server_max_data;

    /* Generate the random data directly into response buffer */
    uint8_t* res_out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_RngResponse);
    ret = wc_RNG_GenerateBlock(ctx->crypto->rng, res_out, actual_size);
    if (ret != 0) {
        return ret;
    }

    /* Translate response with actual size generated */
    res.sz = actual_size;
    ret    = wh_MessageCrypto_TranslateRngResponse(
        magic, &res, (whMessageCrypto_RngResponse*)cryptoDataOut);
    if (ret != 0) {
        return ret;
    }

    /* set the output size */
    *outSize = sizeof(whMessageCrypto_RngResponse) + actual_size;

    return ret;
}
#endif /* WC_NO_RNG */

int wh_Server_KeyCacheImportRaw(whServerContext* ctx, const uint8_t* keyData,
                                uint32_t keySize, whKeyId keyId,
                                whNvmFlags flags, uint16_t label_len,
                                uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;

    if ((ctx == NULL) || (keyData == NULL) || (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    /* Get a free slot */
    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, keySize, &cacheBuf,
                                                &cacheMeta);
    if (ret == WH_ERROR_OK) {
        memcpy(cacheBuf, keyData, keySize);

        cacheMeta->id     = keyId;
        cacheMeta->len    = keySize;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}

#ifdef HAVE_HKDF
int wh_Server_HkdfKeyCacheImport(whServerContext* ctx, const uint8_t* keyData,
                                 uint32_t keySize, whKeyId keyId,
                                 whNvmFlags flags, uint16_t label_len,
                                 uint8_t* label)
{
    return wh_Server_KeyCacheImportRaw(ctx, keyData, keySize, keyId, flags,
                                       label_len, label);
}

#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
int wh_Server_CmacKdfKeyCacheImport(whServerContext* ctx,
                                    const uint8_t* keyData, uint32_t keySize,
                                    whKeyId keyId, whNvmFlags flags,
                                    uint16_t label_len, uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;

    if ((ctx == NULL) || (keyData == NULL) || WH_KEYID_ISERASED(keyId) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, keySize, &cacheBuf,
                                                &cacheMeta);
    if (ret == WH_ERROR_OK) {
        memcpy(cacheBuf, keyData, keySize);
    }

    if (ret == WH_ERROR_OK) {
        cacheMeta->id     = keyId;
        cacheMeta->len    = keySize;
        /* clients can't set server-only flags (e.g. trusted KEK) */
        cacheMeta->flags  = flags & ~WH_NVM_FLAGS_SERVER_ONLY;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}
#endif /* HAVE_CMAC_KDF */

#ifdef HAVE_HKDF
static int _HandleHkdf(whServerContext* ctx, uint16_t magic, int devId,
                       const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize)
{
    int                          ret = WH_ERROR_OK;
    whMessageCrypto_HkdfRequest  req;
    whMessageCrypto_HkdfResponse res;
    (void)devId;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_HkdfRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateHkdfRequest(
        magic, (const whMessageCrypto_HkdfRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    int      hashType = req.hashType;
    uint32_t inKeySz  = req.inKeySz;
    uint32_t saltSz   = req.saltSz;
    uint32_t infoSz   = req.infoSz;
    uint32_t outSz    = req.outSz;
    whKeyId  key_id   = wh_KeyId_TranslateFromClient(
           WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyIdOut);
    whKeyId keyIdIn = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyIdIn);
    whNvmFlags flags      = req.flags;
    uint8_t*   label      = req.label;
    uint16_t   label_size = WH_NVM_LABEL_LEN;

    /* Validate variable-length fields fit within input buffer */
    uint32_t available = inSize - sizeof(whMessageCrypto_HkdfRequest);
    if (inKeySz > available) {
        return WH_ERROR_BADARGS;
    }
    if (saltSz > (available - inKeySz)) {
        return WH_ERROR_BADARGS;
    }
    if (infoSz > (available - inKeySz - saltSz)) {
        return WH_ERROR_BADARGS;
    }

    /* Get pointers to variable-length input data */
    const uint8_t* inKey =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_HkdfRequest);
    const uint8_t* salt = inKey + inKeySz;
    const uint8_t* info = salt + saltSz;

    /* Buffer for cached key if needed */
    uint8_t*       cachedKeyBuf  = NULL;
    whNvmMetadata* cachedKeyMeta = NULL;

    /* Check if we should use cached key as input */
    if (inKeySz == 0 && !WH_KEYID_ISERASED(keyIdIn)) {
        /* Grab references to key in the cache */
        ret = wh_Server_KeystoreFreshenKey(ctx, keyIdIn, &cachedKeyBuf,
                                           &cachedKeyMeta);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
        /* Validate key usage policy for key derivation (input key) */
        ret = wh_Server_KeystoreEnforceKeyUsage(cachedKeyMeta,
                                                WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
        /* Update inKey pointer and size to use cached key */
        inKey   = cachedKeyBuf;
        inKeySz = cachedKeyMeta->len;
    }

    /* Get pointer to where output data would be stored (after response struct)
     */
    uint8_t* out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_HkdfResponse);
    uint16_t max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                                   ((uint8_t*)out - (uint8_t*)cryptoDataOut));

    /* Check if output size is valid */
    if (outSz > max_size) {
        return WH_ERROR_BADARGS;
    }

    /* Generate the key into the output buffer */
    ret = wc_HKDF(hashType, inKey, inKeySz, (saltSz > 0) ? salt : NULL, saltSz,
                  (infoSz > 0) ? info : NULL, infoSz, out, outSz);
    if (ret == 0) {
        /* Check incoming flags */
        if (flags & WH_NVM_FLAGS_EPHEMERAL) {
            /* Key should not be cached/stored on the server */
            key_id    = WH_KEYID_ERASED;
            res.keyIdOut = WH_KEYID_ERASED;
            res.outSz = outSz;
        }
        else {
            /* Must import the key into the cache and return keyid */
            if (WH_KEYID_ISERASED(key_id)) {
                /* Generate a new id */
                ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                WH_DEBUG_SERVER_VERBOSE("HkdfKeyGen UniqueId: keyId:%u, ret:%d\n", key_id, ret);
                if (ret != WH_ERROR_OK) {
                    /* Early return on unique ID generation failure */
                    return ret;
                }
            }

            if (ret == 0) {
                ret = wh_Server_HkdfKeyCacheImport(ctx, out, outSz, key_id,
                                                   flags, label_size, label);
            }
            WH_DEBUG_SERVER_VERBOSE("HkdfKeyGen CacheImport: keyId:%u, ret:%d\n", key_id, ret);
            if (ret == WH_ERROR_OK) {
                res.keyIdOut = wh_KeyId_TranslateToClient(key_id);
                res.outSz = 0;
                /* clear the output buffer */
                memset(out, 0, outSz);
            }
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Translate response */
        ret = wh_MessageCrypto_TranslateHkdfResponse(
            magic, &res, (whMessageCrypto_HkdfResponse*)cryptoDataOut);
        if (ret == 0) {
            /* Set the output size (response header + output data) */
            *outSize = sizeof(whMessageCrypto_HkdfResponse) + res.outSz;
        }
    }

    return ret;
}
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
static int _HandleCmacKdf(whServerContext* ctx, uint16_t magic, int devId,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize)
{
    int                             ret = WH_ERROR_OK;
    whMessageCrypto_CmacKdfRequest  req;
    whMessageCrypto_CmacKdfResponse res;

    memset(&res, 0, sizeof(res));

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_CmacKdfRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateCmacKdfRequest(
        magic, (const whMessageCrypto_CmacKdfRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    uint32_t saltSz      = req.saltSz;
    uint32_t zSz         = req.zSz;
    uint32_t fixedInfoSz = req.fixedInfoSz;
    uint32_t outSz       = req.outSz;
    whKeyId  keyIdOut    = wh_KeyId_TranslateFromClient(
            WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyIdOut);
    whKeyId saltKeyId = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyIdSalt);
    whKeyId zKeyId = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyIdZ);
    whNvmFlags flags      = (whNvmFlags)req.flags;
    uint8_t*   label      = req.label;
    uint16_t   label_size = WH_NVM_LABEL_LEN;

    /* Validate variable-length fields fit within input buffer */
    uint32_t available = inSize - sizeof(whMessageCrypto_CmacKdfRequest);
    if (saltSz > available) {
        return WH_ERROR_BADARGS;
    }
    if (zSz > (available - saltSz)) {
        return WH_ERROR_BADARGS;
    }
    if (fixedInfoSz > (available - saltSz - zSz)) {
        return WH_ERROR_BADARGS;
    }

    const uint8_t* salt =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_CmacKdfRequest);
    const uint8_t* z         = salt + saltSz;
    const uint8_t* fixedInfo = z + zSz;

    uint8_t*       cachedSaltBuf  = NULL;
    whNvmMetadata* cachedSaltMeta = NULL;
    uint8_t*       cachedZBuf     = NULL;
    whNvmMetadata* cachedZMeta    = NULL;

    if (saltSz == 0) {
        if (WH_KEYID_ISERASED(saltKeyId)) {
            return WH_ERROR_BADARGS;
        }
        ret = wh_Server_KeystoreFreshenKey(ctx, saltKeyId, &cachedSaltBuf,
                                           &cachedSaltMeta);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
        /* Validate key usage policy for cached salt */
        ret = wh_Server_KeystoreEnforceKeyUsage(cachedSaltMeta,
                                                WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
        salt   = cachedSaltBuf;
        saltSz = cachedSaltMeta->len;
    }

    if (zSz == 0) {
        if (WH_KEYID_ISERASED(zKeyId)) {
            return WH_ERROR_BADARGS;
        }
        ret = wh_Server_KeystoreFreshenKey(ctx, zKeyId, &cachedZBuf,
                                           &cachedZMeta);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
        /* Validate key usage policy for key derivation (Z key) */
        ret = wh_Server_KeystoreEnforceKeyUsage(cachedZMeta,
                                                WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
        z   = cachedZBuf;
        zSz = cachedZMeta->len;
    }

    if ((salt == NULL) || (z == NULL) || (outSz == 0)) {
        return WH_ERROR_BADARGS;
    }

    uint8_t* out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_CmacKdfResponse);
    uint16_t max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                                   ((uint8_t*)out - (uint8_t*)cryptoDataOut));

    if (outSz > max_size) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_KDA_KDF_twostep_cmac(salt, saltSz, z, zSz,
                                  (fixedInfoSz > 0) ? fixedInfo : NULL,
                                  fixedInfoSz, out, outSz, NULL, devId);
    if (ret == 0) {
        if (flags & WH_NVM_FLAGS_EPHEMERAL) {
            keyIdOut     = WH_KEYID_ERASED;
            res.keyIdOut = WH_KEYID_ERASED;
            res.outSz    = outSz;
        }
        else {
            if (WH_KEYID_ISERASED(keyIdOut)) {
                ret = wh_Server_KeystoreGetUniqueId(ctx, &keyIdOut);
                if (ret != WH_ERROR_OK) {
                    return ret;
                }
            }

            ret = wh_Server_CmacKdfKeyCacheImport(ctx, out, outSz, keyIdOut,
                                                  flags, label_size, label);
            if (ret == WH_ERROR_OK) {
                res.keyIdOut = wh_KeyId_TranslateToClient(keyIdOut);
                res.outSz    = 0;
                memset(out, 0, outSz);
            }
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_MessageCrypto_TranslateCmacKdfResponse(
            magic, &res, (whMessageCrypto_CmacKdfResponse*)cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(whMessageCrypto_CmacKdfResponse) + res.outSz;
        }
    }

    return ret;
}
#endif /* HAVE_CMAC_KDF */

#ifdef HAVE_CURVE25519
static int _HandleCurve25519KeyGen(whServerContext* ctx, uint16_t magic,
                                   int devId, const void* cryptoDataIn,
                                   uint16_t inSize, void* cryptoDataOut,
                                   uint16_t* outSize)
{
    (void)inSize;

    int                                      ret = WH_ERROR_OK;
    curve25519_key                           key[1];
    whMessageCrypto_Curve25519KeyGenRequest  req;
    whMessageCrypto_Curve25519KeyGenResponse res;

    /* Translate request */
    ret = wh_MessageCrypto_TranslateCurve25519KeyGenRequest(
        magic, (const whMessageCrypto_Curve25519KeyGenRequest*)cryptoDataIn,
        &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    int     key_size = req.sz;
    whKeyId key_id   = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    whNvmFlags flags      = req.flags;
    uint8_t*   label      = req.label;
    uint16_t   label_size = WH_NVM_LABEL_LEN;

    /* Response Message */
    uint8_t* out = (uint8_t*)cryptoDataOut +
                   sizeof(whMessageCrypto_Curve25519KeyGenResponse);
    /* Initialize the key size to the max size of the buffer */
    uint16_t ser_size =
        (word32)(WOLFHSM_CFG_COMM_DATA_LEN - (out - (uint8_t*)cryptoDataOut));

    /* init key */
    ret = wc_curve25519_init_ex(key, NULL, devId);
    if (ret == 0) {
        /* make the key */
        ret = wc_curve25519_make_key(ctx->crypto->rng, key_size, key);
        if (ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response packet */
                key_id = WH_KEYID_ERASED;
                ret    = wh_Crypto_Curve25519SerializeKey(key, out, &ser_size);
            }
            else {
                uint16_t max_size =
                    (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                               (out - (uint8_t*)cryptoDataOut));
                ser_size = 0;
                /* Must import the key into the cache and return keyid */
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                    WH_DEBUG_SERVER("UniqueId: keyId:%u, ret:%d\n",
                           key_id, ret);
                    if (ret != WH_ERROR_OK) {
                        /* Early return on unique ID generation failure */
                        wc_curve25519_free(key);
                        return ret;
                    }
                }

                if (ret == 0) {
                    ret = wh_Server_CacheImportCurve25519Key(
                        ctx, key, key_id, flags, label_size, label);
                }
                WH_DEBUG_SERVER_VERBOSE("CacheImport: keyId:%u, ret:%d\n",
                       key_id, ret);
                if (ret == 0) {
                    /* Best-effort public key export: when the serialized
                     * public key fits in the response body, return it so the
                     * client can skip a separate ExportPublicKey call. When it
                     * does not fit (small comm buffer or a large key), leave the
                     * body empty and keep the cached key. Plain MakeCacheKey
                     * callers ignore the body and see no regression;
                     * MakeCacheKeyAndExportPublic callers detect the empty body
                     * and evict the key themselves. */
                    int pub_ret =
                        wc_Curve25519PublicKeyToDer(key, out, max_size, 1);
                    if (pub_ret > 0) {
                        ser_size = (uint16_t)pub_ret;
                    }
                    else {
                        ser_size = 0;
                    }
                }
            }
        }
        wc_curve25519_free(key);
    }

    if (ret == 0) {
        res.keyId = wh_KeyId_TranslateToClient(key_id);
        res.len   = ser_size;

        /* Translate response */
        wh_MessageCrypto_TranslateCurve25519KeyGenResponse(
            magic, &res,
            (whMessageCrypto_Curve25519KeyGenResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_Curve25519KeyGenResponse) + ser_size;
    }
    return ret;
}

static int _HandleCurve25519SharedSecret(whServerContext* ctx, uint16_t magic,
                                         int devId, const void* cryptoDataIn,
                                         uint16_t inSize, void* cryptoDataOut,
                                         uint16_t* outSize)
{
    int ret;
    curve25519_key priv[1] = {0};
    curve25519_key pub[1] = {0};

    whMessageCrypto_Curve25519Request  req;
    whMessageCrypto_Curve25519Response res;
    whKeyId                            out_key_id = WH_KEYID_ERASED;

    if (inSize < sizeof(whMessageCrypto_Curve25519Request)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateCurve25519Request(
        magic, (const whMessageCrypto_Curve25519Request*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    uint32_t options    = req.options;
    int evict_pub = !!(options & WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPUB);
    int evict_prv = !!(options & WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPRV);
    whKeyId pub_key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.publicKeyId);
    whKeyId prv_key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.privateKeyId);
    int endian          = req.endian;
    whNvmFlags flags           = (whNvmFlags)req.flags;
    int        cache           = !(flags & WH_NVM_FLAGS_EPHEMERAL);

    /* Validate key usage policy for key derivation (private key) */
    if (!WH_KEYID_ISERASED(prv_key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, prv_key_id,
                                                    WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    /* Response message */
    uint8_t* res_out       = (uint8_t*)cryptoDataOut +
                             sizeof(whMessageCrypto_Curve25519Response);
    uint16_t max_len      = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (res_out - (uint8_t*)cryptoDataOut));
    word32 res_len      = max_len;

    /* init private key */
    ret = wc_curve25519_init_ex(priv, NULL, devId);
    if (ret == 0) {
        /* init public key */
        ret = wc_curve25519_init_ex(pub, NULL, devId);
        if (ret == 0) {
#ifdef WOLFSSL_CURVE25519_BLINDING
            ret = wc_curve25519_set_rng(priv, ctx->crypto->rng);
            if (ret == 0) {
                ret = wc_curve25519_set_rng(pub, ctx->crypto->rng);
            }
#endif
            if (ret == 0) {
                ret = wh_Server_CacheExportCurve25519Key(ctx, prv_key_id, priv);
            }
            if (ret == 0) {
                ret = wh_Server_CacheExportCurve25519Key(ctx, pub_key_id, pub);
            }
            if (ret == 0) {
                ret = wc_curve25519_shared_secret_ex(priv, pub, res_out,
                                                     &res_len, endian);
            }
            wc_curve25519_free(pub);
        }
        wc_curve25519_free(priv);
    }

    /* If caching, move the secret out of the response buffer into a cache
     * slot and return only its keyId. */
    if ((ret == WH_ERROR_OK) && cache) {
        out_key_id = wh_KeyId_TranslateFromClient(
            WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
        /* Hold the NVM lock so id allocation and cache import are atomic
         * with respect to other server contexts under THREADSAFE. */
        ret = WH_SERVER_NVM_LOCK(ctx);
        if (ret == WH_ERROR_OK) {
            if (WH_KEYID_ISERASED(out_key_id)) {
                ret = wh_Server_KeystoreGetUniqueId(ctx, &out_key_id);
            }
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_KeyCacheImportRaw(ctx, res_out, res_len,
                                                  out_key_id, flags,
                                                  WH_NVM_LABEL_LEN, req.label);
            }
            (void)WH_SERVER_NVM_UNLOCK(ctx);
        } /* WH_SERVER_NVM_LOCK() */
        /* Scrub the secret from the response buffer regardless of import
         * success/failure. */
        memset(res_out, 0, res_len);
        /* If the cached output id collides with an auto-imported input id,
         * suppress the matching eviction so cleanup does not delete the
         * just-cached secret. */
        if (ret == WH_ERROR_OK) {
            if (evict_pub && (out_key_id == pub_key_id)) {
                evict_pub = 0;
            }
            if (evict_prv && (out_key_id == prv_key_id)) {
                evict_prv = 0;
            }
        }
    }
cleanup:
    if (evict_pub) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, pub_key_id);
    }
    if (evict_prv) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, prv_key_id);
    }
    if (ret == 0) {
        uint16_t payload_len;
        if (cache) {
            res.sz      = 0;
            res.keyId   = wh_KeyId_TranslateToClient(out_key_id);
            payload_len = 0;
        }
        else {
            res.sz      = res_len;
            res.keyId   = 0;
            payload_len = (uint16_t)res_len;
        }

        wh_MessageCrypto_TranslateCurve25519Response(
            magic, &res,
            (whMessageCrypto_Curve25519Response*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_Curve25519Response) + payload_len;
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
static int _HandleEd25519KeyGen(whServerContext* ctx, uint16_t magic, int devId,
                                const void* cryptoDataIn, uint16_t inSize,
                                void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                                   ret = WH_ERROR_OK;
    ed25519_key                           key[1];
    whMessageCrypto_Ed25519KeyGenRequest  req;
    whMessageCrypto_Ed25519KeyGenResponse res;

    ret = wh_MessageCrypto_TranslateEd25519KeyGenRequest(
        magic, (const whMessageCrypto_Ed25519KeyGenRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    whNvmFlags flags      = req.flags;
    uint8_t*   label      = req.label;
    uint16_t   label_size = WH_NVM_LABEL_LEN;

    uint8_t* res_out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_Ed25519KeyGenResponse);
    uint16_t max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                                   (res_out - (uint8_t*)cryptoDataOut));
    uint16_t ser_size = 0;

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret == 0) {
        ret = wc_ed25519_make_key(ctx->crypto->rng, ED25519_KEY_SIZE, key);
        if (ret == 0) {
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                key_id = WH_KEYID_ERASED;
                ret = wh_Crypto_Ed25519SerializeKeyDer(key, max_size, res_out,
                                                       &ser_size);
            }
            else {
                ser_size = 0;
                if (WH_KEYID_ISERASED(key_id)) {
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                    if (ret != WH_ERROR_OK) {
                        wc_ed25519_free(key);
                        return ret;
                    }
                }
                if (ret == 0) {
                    ret = wh_Server_CacheImportEd25519Key(
                        ctx, key, key_id, flags, label_size, label);
                }
                if (ret == 0) {
                    /* Best-effort public key export: when the serialized
                     * public key fits in the response body, return it so the
                     * client can skip a separate ExportPublicKey call. When it
                     * does not fit (small comm buffer or a large key), leave the
                     * body empty and keep the cached key. Plain MakeCacheKey
                     * callers ignore the body and see no regression;
                     * MakeCacheKeyAndExportPublic callers detect the empty body
                     * and evict the key themselves. */
                    int pub_ret =
                        wc_Ed25519PublicKeyToDer(key, res_out, max_size, 1);
                    if (pub_ret > 0) {
                        ser_size = (uint16_t)pub_ret;
                    }
                    else {
                        ser_size = 0;
                    }
                }
            }
        }
        wc_ed25519_free(key);
    }

    if (ret == WH_ERROR_OK) {
        if (flags & WH_NVM_FLAGS_EPHEMERAL) {
            res.keyId = WH_KEYID_ERASED;
        }
        else {
            res.keyId = wh_KeyId_TranslateToClient(key_id);
        }
        res.outSz = ser_size;

        wh_MessageCrypto_TranslateEd25519KeyGenResponse(
            magic, &res, (whMessageCrypto_Ed25519KeyGenResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_Ed25519KeyGenResponse) + ser_size;
    }

    return ret;
}

static int _HandleEd25519Sign(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
    int                                ret;
    ed25519_key                        key[1];
    whMessageCrypto_Ed25519SignRequest req;
    uint8_t                            sig[ED25519_SIG_SIZE];

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateEd25519SignRequest(
        magic, (const whMessageCrypto_Ed25519SignRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    uint32_t available = inSize - sizeof(req);
    if (req.msgSz > available) {
        return WH_ERROR_BADARGS;
    }
    available -= req.msgSz;
    if (req.ctxSz > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }
    if (req.ctxSz > available) {
        return WH_ERROR_BADARGS;
    }

    if ((req.type != (byte)Ed25519) && (req.type != (byte)Ed25519ctx) &&
        (req.type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }

    if (req.type == (byte)Ed25519 && (req.ctxSz != 0U)) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint32_t msg_len = req.msgSz;
    uint8_t* req_msg = (uint8_t*)cryptoDataIn + sizeof(req);
    uint8_t* req_ctx = req_msg + msg_len;
    int evict = !!(req.options & WH_MESSAGE_CRYPTO_ED25519_SIGN_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_SIGN);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    uint8_t* res_sig =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_Ed25519SignResponse);
    word32 sig_len = sizeof(sig);

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret == 0) {
        ret = wh_Server_CacheExportEd25519Key(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            ret = wc_ed25519_sign_msg_ex(req_msg, msg_len, sig, &sig_len, key,
                                         (byte)req.type, req_ctx,
                                         (byte)req.ctxSz);
        }
        wc_ed25519_free(key);
    }
    if (sig_len > WOLFHSM_CFG_COMM_DATA_LEN -
                      sizeof(whMessageCrypto_Ed25519SignResponse) -
                      sizeof(whMessageCrypto_GenericResponseHeader)) {
        ret = WH_ERROR_ABORTED;
    }
    if (ret == 0) {
        memcpy(res_sig, sig, sig_len);
    }

cleanup:
    if (evict) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }

    if (ret == 0) {
        whMessageCrypto_Ed25519SignResponse res;
        res.sigSz = sig_len;

        wh_MessageCrypto_TranslateEd25519SignResponse(
            magic, &res, (whMessageCrypto_Ed25519SignResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_Ed25519SignResponse) + sig_len;
    }

    return ret;
}

static int _HandleEd25519Verify(whServerContext* ctx, uint16_t magic, int devId,
                                const void* cryptoDataIn, uint16_t inSize,
                                void* cryptoDataOut, uint16_t* outSize)
{
    int                                   ret;
    ed25519_key                           key[1];
    whMessageCrypto_Ed25519VerifyRequest  req;
    whMessageCrypto_Ed25519VerifyResponse res;

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateEd25519VerifyRequest(
        magic, (const whMessageCrypto_Ed25519VerifyRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    uint32_t available = inSize - sizeof(req);
    if (req.sigSz > available) {
        return WH_ERROR_BADARGS;
    }
    available -= req.sigSz;
    if (req.msgSz > available) {
        return WH_ERROR_BADARGS;
    }
    available -= req.msgSz;
    if (req.ctxSz > available) {
        return WH_ERROR_BADARGS;
    }
    if (req.ctxSz > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }

    if ((req.type != (byte)Ed25519) && (req.type != (byte)Ed25519ctx) &&
        (req.type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint32_t sig_len = req.sigSz;
    uint32_t msg_len = req.msgSz;
    uint8_t* req_sig =
        (uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Ed25519VerifyRequest);
    uint8_t* req_msg = req_sig + sig_len;
    uint8_t* req_ctx = req_msg + msg_len;
    int      evict =
        !!(req.options & WH_MESSAGE_CRYPTO_ED25519_VERIFY_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_VERIFY);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    int result = 0;

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret == 0) {
        ret = wh_Server_CacheExportEd25519Key(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            ret = wc_ed25519_verify_msg_ex(req_sig, sig_len, req_msg, msg_len,
                                           &result, key, (byte)req.type,
                                           req_ctx, (byte)req.ctxSz);
        }
        wc_ed25519_free(key);
    }

cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }

    if (ret == 0) {
        res.res = result;

        wh_MessageCrypto_TranslateEd25519VerifyResponse(
            magic, &res, (whMessageCrypto_Ed25519VerifyResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_Ed25519VerifyResponse);
    }

    return ret;
}
#ifdef WOLFHSM_CFG_DMA
static int _HandleEd25519SignDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
    int                                    ret = 0;
    ed25519_key                            key[1];
    void*                                  msgAddr = NULL;
    void*                                  sigAddr = NULL;
    whMessageCrypto_Ed25519SignDmaRequest  req;
    whMessageCrypto_Ed25519SignDmaResponse res;
    word32                                 sigLen = 0;

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateEd25519SignDmaRequest(
        magic, (const whMessageCrypto_Ed25519SignDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t available = inSize - sizeof(req);
    if (req.ctxSz > available) {
        return WH_ERROR_BADARGS;
    }
    if (req.ctxSz > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }
    uint8_t* req_ctx = (uint8_t*)cryptoDataIn + sizeof(req);

    if ((req.type != (byte)Ed25519) && (req.type != (byte)Ed25519ctx) &&
        (req.type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    int evict = !!(req.options & WH_MESSAGE_CRYPTO_ED25519_SIGN_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_SIGN);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    memset(&res, 0, sizeof(res));

    sigLen = req.sig.sz;
    ret    = wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
        WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        res.dmaAddrStatus.badAddr = req.msg;
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.sig;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wc_ed25519_init_ex(key, NULL, devId);
        if (ret == 0) {
            ret = wh_Server_CacheExportEd25519Key(ctx, key_id, key);
            if (ret == WH_ERROR_OK) {
                ret = wc_ed25519_sign_msg_ex(msgAddr, req.msg.sz, sigAddr,
                                             &sigLen, key, (byte)req.type,
                                             req_ctx, (byte)req.ctxSz);
                if (ret == WH_ERROR_OK) {
                    res.sigSz = sigLen;
                }
            }
            if ((ret != WH_ERROR_OK) && (res.dmaAddrStatus.badAddr.sz == 0)) {
                res.dmaAddrStatus.badAddr = req.sig;
            }
        }
        wc_ed25519_free(key);
    }

    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.sig.addr, &sigAddr, sigLen,
        WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});

cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }

    if (ret == WH_ERROR_OK) {
        (void)wh_MessageCrypto_TranslateEd25519SignDmaResponse(
            magic, &res,
            (whMessageCrypto_Ed25519SignDmaResponse*)cryptoDataOut);
        *outSize = sizeof(res);
    }

    return ret;
}

static int _HandleEd25519VerifyDma(whServerContext* ctx, uint16_t magic,
                                   int devId, const void* cryptoDataIn,
                                   uint16_t inSize, void* cryptoDataOut,
                                   uint16_t* outSize)
{
    int                                      ret = 0;
    ed25519_key                              key[1];
    void*                                    msgAddr = NULL;
    void*                                    sigAddr = NULL;
    whMessageCrypto_Ed25519VerifyDmaRequest  req;
    whMessageCrypto_Ed25519VerifyDmaResponse res;

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateEd25519VerifyDmaRequest(
        magic, (const whMessageCrypto_Ed25519VerifyDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t available = inSize - sizeof(req);
    if (req.ctxSz > available) {
        return WH_ERROR_BADARGS;
    }
    if (req.ctxSz > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }
    uint8_t* req_ctx = (uint8_t*)cryptoDataIn + sizeof(req);

    if ((req.type != (byte)Ed25519) && (req.type != (byte)Ed25519ctx) &&
        (req.type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    int evict =
        !!(req.options & WH_MESSAGE_CRYPTO_ED25519_VERIFY_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_VERIFY);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    memset(&res, 0, sizeof(res));

    ret = wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
        WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
    if (ret == WH_ERROR_ACCESS) {
        res.dmaAddrStatus.badAddr = req.sig;
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.msg;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_ed25519_init_ex(key, NULL, devId);
        if (ret == 0) {
            ret = wh_Server_CacheExportEd25519Key(ctx, key_id, key);
            if (ret == WH_ERROR_OK) {
                int verified = 0;
                ret          = wc_ed25519_verify_msg_ex(
                    sigAddr, req.sig.sz, msgAddr, req.msg.sz, &verified, key,
                    (byte)req.type, req_ctx, (byte)req.ctxSz);
                if (ret == WH_ERROR_OK) {
                    res.verifyResult = verified;
                }
            }
            wc_ed25519_free(key);
        }
    }

    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});

cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }

    if (ret == WH_ERROR_OK) {
        (void)wh_MessageCrypto_TranslateEd25519VerifyDmaResponse(
            magic, &res,
            (whMessageCrypto_Ed25519VerifyDmaResponse*)cryptoDataOut);
        *outSize = sizeof(res);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifndef NO_AES
#ifdef WOLFSSL_AES_COUNTER
static int _HandleAesCtr(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                            ret    = WH_ERROR_OK;
    Aes                            aes[1] = {0};
    whMessageCrypto_AesCtrRequest  req;
    whMessageCrypto_AesCtrResponse res;
    uint8_t*                       cachedKey = NULL;
    whNvmMetadata*                 keyMeta   = NULL;

    if (inSize < sizeof(whMessageCrypto_AesCtrRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesCtrRequest(
        magic, (const whMessageCrypto_AesCtrRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    uint32_t enc         = req.enc;
    uint32_t key_len     = req.keyLen;
    uint32_t len         = req.sz;
    uint32_t left        = req.left;
    uint64_t needed_size = sizeof(whMessageCrypto_AesCtrRequest) + len +
                           key_len + AES_IV_SIZE + AES_BLOCK_SIZE;
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

    /* in, key, iv, and out are after fixed size fields */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_AesCtrRequest);
    uint8_t* key = in + len;
    uint8_t* iv  = key + key_len;
    uint8_t* tmp = iv + AES_BLOCK_SIZE;
    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_AesCtrResponse);
    uint8_t* out_reg = out + len;
    uint8_t* out_tmp = out_reg + AES_BLOCK_SIZE;

    /* Debug printouts */
    WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Input data ", in, len);
    WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] IV ", iv, AES_BLOCK_SIZE);
    WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] tmp ", tmp, AES_BLOCK_SIZE);
    /* Freshen key and validate usage policy if key is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFreshenKey(ctx, key_id, &cachedKey, &keyMeta);
        if (ret == WH_ERROR_OK) {
            /* Validate key usage policy */
            ret = wh_Server_KeystoreEnforceKeyUsage(
                keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                  : WH_NVM_FLAGS_USAGE_DECRYPT);
        }
        if (ret == WH_ERROR_OK) {
            /* override the incoming values with cached key */
            key     = cachedKey;
            key_len = keyMeta->len;
            WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Key from HSM", key, key_len);
        }
    }
    else {
        WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Key ", key, key_len);
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && key_len != AES_128_KEY_SIZE &&
        key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesCtr] Invalid key size: %d", key_len);
        ret = WH_ERROR_BADARGS;
    }
    if (ret == WH_ERROR_OK) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, devId);
    }
    if (ret == WH_ERROR_OK) {
        /* load the key */
        ret = wc_AesSetKeyDirect(aes, (byte*)key, (word32)key_len, (byte*)iv,
                                 enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == WH_ERROR_OK) {
            /* Reject client-supplied left values outside the valid range.
             * wc_AesCtrEncrypt indexes aes->tmp via AES_BLOCK_SIZE - aes->left;
             * an out-of-range value causes an out-of-bounds read that could
             * disclose server-side memory across the HSM trust boundary. */
            if (left > AES_BLOCK_SIZE) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                /* Restore streaming CTR context from the previous call. */
                aes->left = left;
                memcpy(aes->tmp, tmp, sizeof(aes->tmp));
                if (enc != 0) {
                    ret = wc_AesCtrEncrypt(aes, (byte*)out, (byte*)in,
                                           (word32)len);
                    if (ret == WH_ERROR_OK) {
                        WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Encrypted output",
                                                 out, len);
                    }
                }
                else {
                    /* CTR uses the same function for encrypt and decrypt */
                    ret = wc_AesCtrEncrypt(aes, (byte*)out, (byte*)in,
                                           (word32)len);
                    if (ret == WH_ERROR_OK) {
                        WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Decrypted output",
                                                 out, len);
                    }
                }
            }
        }
        left = aes->left;
        memcpy(out_reg, aes->reg, AES_BLOCK_SIZE);
        memcpy(out_tmp, aes->tmp, sizeof(aes->tmp));
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == WH_ERROR_OK) {
        /* set sz */
        res.sz   = len;
        res.left = left;
        *outSize =
            sizeof(whMessageCrypto_AesCtrResponse) + len + (AES_BLOCK_SIZE * 2);
        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesCtrResponse(
            magic, &res, (whMessageCrypto_AesCtrResponse*)cryptoDataOut);
    }
    return ret;
}


#ifdef WOLFHSM_CFG_DMA
static int _HandleAesCtrDma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    int                               ret = WH_ERROR_OK;
    whMessageCrypto_AesCtrDmaRequest  req;
    whMessageCrypto_AesCtrDmaResponse res;
    Aes                               aes[1] = {0};

    void*  inAddr  = NULL;
    void*  outAddr = NULL;
    word32 outSz   = 0;

    whKeyId        keyId;
    uint8_t*       cachedKey = NULL;
    whNvmMetadata* keyMeta   = NULL;

    (void)seq;

    if (inSize < sizeof(whMessageCrypto_AesCtrDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesCtrDmaRequest(
        magic, (whMessageCrypto_AesCtrDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t enc         = req.enc;
    uint32_t keyLen      = req.keySz;
    uint32_t len         = req.input.sz;
    uint32_t left        = req.left;
    uint64_t needed_size = sizeof(whMessageCrypto_AesCtrDmaRequest) + keyLen +
                           AES_IV_SIZE + AES_BLOCK_SIZE;
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }
    if (req.input.sz != req.output.sz) {
        return WH_ERROR_BADARGS;
    }

    /* iv and tmp are after fixed size fields, key is optional and variable
     * length */
    uint8_t* key     = NULL;
    uint8_t* iv      = (uint8_t*)(cryptoDataIn) +
                       sizeof(whMessageCrypto_AesCtrDmaRequest);
    uint8_t* tmp     = iv + AES_IV_SIZE;
    uint8_t* out_iv = (uint8_t*)(cryptoDataOut) +
                       sizeof(whMessageCrypto_AesCtrDmaResponse);
    uint8_t* out_tmp = out_iv + AES_IV_SIZE;

    memset(&res, 0, sizeof(res));

    /* Handle key operations */
    if (ret == WH_ERROR_OK && keyLen > 0) {
        key = tmp + AES_BLOCK_SIZE;
        WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Key ", key, keyLen);
    }
    else if (ret == WH_ERROR_OK && keyLen == 0) {
        /* Handle keyId-based keys if no direct key was provided */
        keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             ctx->comm->client_id, req.keyId);

        /* Freshen key and validate usage policy if key is not erased */
        if (!WH_KEYID_ISERASED(keyId)) {
            ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cachedKey,
                                               &keyMeta);
            if (ret == WH_ERROR_OK) {
                /* Validate key usage policy */
                ret = wh_Server_KeystoreEnforceKeyUsage(
                    keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                    : WH_NVM_FLAGS_USAGE_DECRYPT);
            }
            if (ret == WH_ERROR_OK) {
                key    = cachedKey;
                keyLen = keyMeta->len;
                WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Key from HSM", key, keyLen);
            }
        }
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && keyLen != AES_128_KEY_SIZE &&
        keyLen != AES_192_KEY_SIZE && keyLen != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesCtr] Invalid key size: %d", keyLen);
        ret = WH_ERROR_BADARGS;
    }

    /* Handle input data */
    if (ret == WH_ERROR_OK && req.input.sz > 0) {
        /* Process client address for input data */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    /* Handle output buffer */
    if (ret == WH_ERROR_OK && req.output.sz > 0) {
        /* Process client address for output buffer */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesInit(aes, NULL, devId);
    }

    if (ret == WH_ERROR_OK) {
        /* load the key */
        ret = wc_AesSetKeyDirect(aes, (byte*)key, (word32)keyLen, (byte*)iv,
                                 enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == WH_ERROR_OK) {
            /* Reject client-supplied left values outside the valid range.
             * wc_AesCtrEncrypt indexes aes->tmp via AES_BLOCK_SIZE - aes->left;
             * an out-of-range value causes an out-of-bounds read that could
             * disclose server-side memory across the HSM trust boundary. */
            if (left > AES_BLOCK_SIZE) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                /* Restore streaming CTR context from the previous call. */
                aes->left = left;
                memcpy(aes->tmp, tmp, sizeof(aes->tmp));
                if (enc != 0) {
                    ret = wc_AesCtrEncrypt(aes, (byte*)outAddr, (byte*)inAddr,
                                           (word32)len);
                    if (ret == WH_ERROR_OK) {
                        WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Encrypted output",
                                                 outAddr, len);
                    }
                }
                else {
                    /* CTR uses the same function for encrypt and decrypt */
                    ret = wc_AesCtrEncrypt(aes, (byte*)outAddr, (byte*)inAddr,
                                           (word32)len);
                    if (ret == WH_ERROR_OK) {
                        WH_DEBUG_VERBOSE_HEXDUMP("[AesCtr] Decrypted output",
                                                 outAddr, len);
                    }
                }
                if (ret == WH_ERROR_OK) {
                    left = aes->left;
                    outSz = len;
                    memcpy(out_tmp, aes->tmp, AES_BLOCK_SIZE);
                    memcpy(out_iv, aes->reg, AES_IV_SIZE);
                }
            }
        }
    }

    /* Post-write DMA address processing for out (on success) */
    if (ret == WH_ERROR_OK && req.output.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }
    /* Clean up DMA input address (unconditionally) */
    if (inAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE(
                "[AesCtr] Error cleaning up input DMA address\n");
        }
    }

    wc_AesFree(aes);

    /* Set response */
    res.outSz = outSz;
    res.left = left;

    /* Translate response back */
    (void)wh_MessageCrypto_TranslateAesCtrDmaResponse(
        magic, &res, (whMessageCrypto_AesCtrDmaResponse*)cryptoDataOut);
    *outSize = sizeof(whMessageCrypto_AesCtrDmaResponse) +
               AES_IV_SIZE + AES_BLOCK_SIZE;

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
static int _HandleAesEcb(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                            ret    = WH_ERROR_OK;
    Aes                            aes[1] = {0};
    whMessageCrypto_AesEcbRequest  req;
    whMessageCrypto_AesEcbResponse res;
    uint8_t*                       cachedKey = NULL;
    whNvmMetadata*                 keyMeta   = NULL;

    if (inSize < sizeof(whMessageCrypto_AesEcbRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesEcbRequest(
        magic, (const whMessageCrypto_AesEcbRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t enc     = req.enc;
    uint32_t key_len = req.keyLen;
    uint32_t len     = req.sz;
    uint64_t needed_size =
        sizeof(whMessageCrypto_AesEcbRequest) + len + key_len;
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

    /* in, key, and out are after fixed size fields */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_AesEcbRequest);
    uint8_t* key = in + len;

    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_AesEcbResponse);

    /* Debug printouts */
    WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Input data", in, len);

    /* Freshen key and validate usage policy if key is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFreshenKey(ctx, key_id, &cachedKey, &keyMeta);
        if (ret == WH_ERROR_OK) {
            /* Validate key usage policy */
            ret = wh_Server_KeystoreEnforceKeyUsage(
                keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                  : WH_NVM_FLAGS_USAGE_DECRYPT);
        }
        if (ret == WH_ERROR_OK) {
            /* override the incoming values with cached key */
            key     = cachedKey;
            key_len = keyMeta->len;
            WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Key from HSM", key, key_len);
        }
    }
    else {
        WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Key ", key, key_len);
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && key_len != AES_128_KEY_SIZE &&
        key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesEcb] Invalid key size: %d", key_len);
        ret = WH_ERROR_BADARGS;
    }
    if (ret == WH_ERROR_OK) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, devId);
    }
    if (ret == WH_ERROR_OK) {
        /* load the key. AES-ECB does not use IV */
        ret = wc_AesSetKey(aes, (byte*)key, (word32)key_len, NULL,
                           enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == WH_ERROR_OK) {
            /* do the crypto operation */
            if (enc != 0) {
                ret = wc_AesEcbEncrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == WH_ERROR_OK) {
                    WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Encrypted output",
                                             out, len);
                }
            }
            else {
                ret = wc_AesEcbDecrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == WH_ERROR_OK) {
                    WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Decrypted output",
                                             out, len);
                }
            }
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == WH_ERROR_OK) {
        /* set sz */
        res.sz   = len;
        *outSize = sizeof(whMessageCrypto_AesEcbResponse) + len;

        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesEcbResponse(
            magic, &res, (whMessageCrypto_AesEcbResponse*)cryptoDataOut);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _HandleAesEcbDma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    int                               ret = WH_ERROR_OK;
    whMessageCrypto_AesEcbDmaRequest  req;
    whMessageCrypto_AesEcbDmaResponse res;
    Aes                               aes[1] = {0};

    void*  inAddr  = NULL;
    void*  outAddr = NULL;
    word32 outSz   = 0;

    whKeyId        keyId;
    uint8_t*       cachedKey = NULL;
    whNvmMetadata* keyMeta   = NULL;

    (void)seq;

    if (inSize < sizeof(whMessageCrypto_AesEcbDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesEcbDmaRequest(
        magic, (whMessageCrypto_AesEcbDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t keyLen      = req.keySz;
    uint32_t len         = req.input.sz;
    uint64_t needed_size = sizeof(whMessageCrypto_AesEcbDmaRequest) + keyLen;
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }
    if (req.input.sz != req.output.sz) {
        return WH_ERROR_BADARGS;
    }

    uint8_t* key = (uint8_t*)(cryptoDataIn) +
                   sizeof(whMessageCrypto_AesEcbDmaRequest);

    memset(&res, 0, sizeof(res));

    /* Handle key operations */
    if (ret == WH_ERROR_OK && keyLen > 0) {
        WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Key ", key, keyLen);
    }
    else if (ret == WH_ERROR_OK && keyLen == 0) {
        /* Handle keyId-based keys if no direct key was provided */
        keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             ctx->comm->client_id, req.keyId);

        /* Freshen key and validate usage policy if key is not erased */
        if (!WH_KEYID_ISERASED(keyId)) {
            ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cachedKey,
                                               &keyMeta);
            if (ret == WH_ERROR_OK) {
                /* Validate key usage policy */
                ret = wh_Server_KeystoreEnforceKeyUsage(
                    keyMeta, req.enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                        : WH_NVM_FLAGS_USAGE_DECRYPT);
            }
            if (ret == WH_ERROR_OK) {
                key    = cachedKey;
                keyLen = keyMeta->len;
                WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Key from HSM", key, keyLen);
            }
        }
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && keyLen != AES_128_KEY_SIZE &&
        keyLen != AES_192_KEY_SIZE && keyLen != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesEcb] Invalid key size: %d", keyLen);
        ret = WH_ERROR_BADARGS;
    }

    /* Handle input data */
    if (ret == WH_ERROR_OK && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    /* Handle output data */
    if (ret == WH_ERROR_OK && req.output.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesInit(aes, NULL, devId);
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesSetKey(aes, (byte*)key, (word32)keyLen, NULL,
                           req.enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
    }

    if (ret == WH_ERROR_OK) {
        /* do the crypto operation */
        if (req.enc != 0) {
            ret = wc_AesEcbEncrypt(aes, (byte*)outAddr, (byte*)inAddr,
                                   (word32)len);
            if (ret == WH_ERROR_OK) {
                WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Encrypted output",
                                         outAddr, len);
            }
        }
        else {
            ret = wc_AesEcbDecrypt(aes, (byte*)outAddr, (byte*)inAddr,
                                   (word32)len);
            if (ret == WH_ERROR_OK) {
                WH_DEBUG_VERBOSE_HEXDUMP("[AesEcb] Decrypted output",
                                         outAddr, len);
            }
        }
        if (ret == WH_ERROR_OK) {
            outSz = len;
        }
    }

    /* Post-write DMA address processing for output (on success) */
    if (ret == WH_ERROR_OK) {
        if (req.output.sz > 0) {
            ret = wh_Server_DmaProcessClientAddress(
                    ctx, req.output.addr, &outAddr, req.output.sz,
                    WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.output;
            }
        }
    }
    /* Clean up DMA input address (unconditionally) */
    if (inAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE(
                "[AesEcb] Error cleaning up input DMA address\n");
        }
    }

    wc_AesFree(aes);

    /* Set response */
    res.outSz = outSz;

    /* Translate response back */
    (void)wh_MessageCrypto_TranslateAesEcbDmaResponse(
        magic, &res, (whMessageCrypto_AesEcbDmaResponse*)cryptoDataOut);
    *outSize  = sizeof(whMessageCrypto_AesEcbDmaResponse);

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
static int _HandleAesCbc(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                            ret    = WH_ERROR_OK;
    Aes                            aes[1] = {0};
    whMessageCrypto_AesCbcRequest  req;
    whMessageCrypto_AesCbcResponse res;
    uint8_t*                       cachedKey = NULL;
    whNvmMetadata*                 keyMeta   = NULL;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_AesCbcRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesCbcRequest(
        magic, (const whMessageCrypto_AesCbcRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Validate variable-length fields fit within inSize */
    uint32_t enc         = req.enc;
    uint32_t key_len     = req.keyLen;
    uint32_t len         = req.sz;
    uint64_t needed_size = sizeof(whMessageCrypto_AesCbcRequest) + len +
                           key_len + AES_BLOCK_SIZE;
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

    /* in, key, iv, and out are after fixed size fields */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_AesCbcRequest);
    uint8_t* key = in + len;
    uint8_t* iv  = key + key_len;

    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_AesCbcResponse);
    uint8_t* out_iv = out + len;

    /* Debug printouts */
    WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Input data", in, len);
    WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] IV", iv, AES_BLOCK_SIZE);
    /* Freshen key and validate usage policy if key is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFreshenKey(ctx, key_id, &cachedKey, &keyMeta);
        if (ret == WH_ERROR_OK) {
            /* Validate key usage policy */
            ret = wh_Server_KeystoreEnforceKeyUsage(
                keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                  : WH_NVM_FLAGS_USAGE_DECRYPT);
        }
        if (ret == WH_ERROR_OK) {
            /* override the incoming values with cached key */
            key     = cachedKey;
            key_len = keyMeta->len;
            WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Key from HSM", key, key_len);
        }
    }
    else {
        WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Key ", key, key_len);
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && key_len != AES_128_KEY_SIZE &&
        key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesCbc] Invalid key size: %d", key_len);
        ret = WH_ERROR_BADARGS;
    }
    if (ret == WH_ERROR_OK) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, devId);
    }
    if (ret == WH_ERROR_OK) {
        /* load the key */
        ret = wc_AesSetKey(aes, (byte*)key, (word32)key_len, (byte*)iv,
                           enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == WH_ERROR_OK) {
            /* do the crypto operation */
            if (enc != 0) {
                ret = wc_AesCbcEncrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == WH_ERROR_OK) {
                    WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Encrypted output", out, len);
                }
            }
            else {
                ret = wc_AesCbcDecrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == WH_ERROR_OK) {
                    WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Decrypted output", out, len);
                }
            }
        }
        if (ret == WH_ERROR_OK) {
            memcpy(out_iv, aes->reg, AES_IV_SIZE);
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == WH_ERROR_OK) {
        /* set sz */
        res.sz   = len;
        *outSize = sizeof(whMessageCrypto_AesCbcResponse) + len + AES_IV_SIZE;

        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesCbcResponse(
            magic, &res, (whMessageCrypto_AesCbcResponse*)cryptoDataOut);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _HandleAesCbcDma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    int                               ret = WH_ERROR_OK;
    whMessageCrypto_AesCbcDmaRequest  req;
    whMessageCrypto_AesCbcDmaResponse res;
    Aes                               aes[1] = {0};

    void*  inAddr  = NULL;
    void*  outAddr = NULL;
    word32 outSz   = 0;

    whKeyId        keyId;
    uint8_t*       cachedKey = NULL;
    whNvmMetadata* keyMeta   = NULL;

    (void)seq;

    if (inSize < sizeof(whMessageCrypto_AesCbcDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesCbcDmaRequest(
        magic, (whMessageCrypto_AesCbcDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t enc         = req.enc;
    uint32_t keyLen      = req.keySz;
    uint32_t len         = req.input.sz;
    uint64_t needed_size = sizeof(whMessageCrypto_AesCbcDmaRequest) + keyLen +
                           AES_IV_SIZE;
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }
    if (req.input.sz != req.output.sz) {
        return WH_ERROR_BADARGS;
    }

    /* iv is a fixed size field, key is optional and variable length */
    uint8_t* key    = NULL;
    uint8_t* iv     = (uint8_t*)(cryptoDataIn) +
                      sizeof(whMessageCrypto_AesCbcDmaRequest);
    uint8_t* out_iv = (uint8_t*)(cryptoDataOut) +
                      sizeof(whMessageCrypto_AesCbcDmaResponse);

    memset(&res, 0, sizeof(res));

    /* Handle key operations */
    if (ret == WH_ERROR_OK && keyLen > 0) {
        key = iv + AES_IV_SIZE;
        WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Key ", key, keyLen);
    }
    else if (ret == WH_ERROR_OK && keyLen == 0) {
        /* Handle keyId-based keys if no direct key was provided */
        keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             ctx->comm->client_id, req.keyId);

        /* Freshen key and validate usage policy if key is not erased */
        if (!WH_KEYID_ISERASED(keyId)) {
            ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cachedKey,
                                               &keyMeta);
            if (ret == WH_ERROR_OK) {
                /* Validate key usage policy */
                ret = wh_Server_KeystoreEnforceKeyUsage(
                    keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                    : WH_NVM_FLAGS_USAGE_DECRYPT);
            }
            if (ret == WH_ERROR_OK) {
                key    = cachedKey;
                keyLen = keyMeta->len;
                WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Key from HSM", key, keyLen);
            }
        }
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && keyLen != AES_128_KEY_SIZE &&
        keyLen != AES_192_KEY_SIZE && keyLen != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesCbc] Invalid key size: %d", keyLen);
        ret = WH_ERROR_BADARGS;
    }

    /* Handle input data */
    if (ret == WH_ERROR_OK && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    /* Handle output data */
    if (ret == WH_ERROR_OK && req.output.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesInit(aes, NULL, devId);
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesSetKey(aes, (byte*)key, keyLen, (byte*)iv,
                           req.enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
    }

    if (ret == WH_ERROR_OK) {
        if (enc != 0) {
            ret = wc_AesCbcEncrypt(aes, (byte*)outAddr, (byte*)inAddr,
                                   (word32)len);
            if (ret == WH_ERROR_OK) {
                WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Encrypted output",
                                         outAddr, len);
            }
        }
        else {
            ret = wc_AesCbcDecrypt(aes, (byte*)outAddr, (byte*)inAddr,
                                   (word32)len);
            if (ret == WH_ERROR_OK) {
                WH_DEBUG_VERBOSE_HEXDUMP("[AesCbc] Decrypted output",
                                         outAddr, len);
            }
        }
        if (ret == WH_ERROR_OK) {
            outSz = len;
            memcpy(out_iv, aes->reg, AES_IV_SIZE);
        }
    }

    /* Post-write DMA address processing for output (on success) */
    if (ret == WH_ERROR_OK) {
        if (req.output.sz > 0) {
            ret = wh_Server_DmaProcessClientAddress(
                    ctx, req.output.addr, &outAddr, req.output.sz,
                    WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.output;
            }
        }
    }
    /* Clean up DMA input address (unconditionally) */
    if (inAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE(
                "[AesCbc] Error cleaning up input DMA address\n");
        }
    }

    wc_AesFree(aes);

    /* Set response */
    res.outSz = outSz;

    /* Translate response back */
    (void)wh_MessageCrypto_TranslateAesCbcDmaResponse(
        magic, &res, (whMessageCrypto_AesCbcDmaResponse*)cryptoDataOut);
    *outSize  = sizeof(whMessageCrypto_AesCbcDmaResponse) + AES_IV_SIZE;

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
static int _HandleAesGcm(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int            ret       = WH_ERROR_OK;
    Aes            aes[1]    = {0};
    uint8_t*       cachedKey = NULL;
    whNvmMetadata* keyMeta   = NULL;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_AesGcmRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    whMessageCrypto_AesGcmRequest req;
    ret = wh_MessageCrypto_TranslateAesGcmRequest(
        magic, (const whMessageCrypto_AesGcmRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t enc         = req.enc;
    uint32_t key_len     = req.keyLen;
    uint32_t len         = req.sz;
    uint32_t iv_len      = req.ivSz;
    uint32_t authin_len  = req.authInSz;
    uint32_t tag_len     = req.authTagSz;
    whKeyId  key_id      = wh_KeyId_TranslateFromClient(
             WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint64_t needed_size = sizeof(whMessageCrypto_AesGcmRequest) + len +
                           key_len + iv_len + authin_len +
                           ((enc == 0) ? tag_len : 0);
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }

    /* in, key, iv, authin, tag, and out are after fixed size fields */
    uint8_t* in = (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_AesGcmRequest);
    uint8_t* key = in + len;
    uint8_t* iv = key + key_len;
    uint8_t* authin = iv + iv_len;
    uint8_t* tag = authin + authin_len;

    /* Translate response */
    whMessageCrypto_AesGcmResponse res;
    res.sz        = req.sz;
    res.authTagSz = (req.enc == 0) ? 0 : req.authTagSz;

    /* Set up response pointers */
    uint8_t* out = (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_AesGcmResponse);
    uint8_t* out_tag = out + len;

    uint32_t res_len = sizeof(whMessageCrypto_AesGcmResponse) + len +
                       ((enc == 0) ? 0 : tag_len);

    WH_DEBUG_SERVER_VERBOSE("AESGCM: enc:%d keylen:%d ivsz:%d insz:%d authinsz:%d "
            "authtagsz:%d reqsz:%u ressz:%u\n",
            enc, key_len, iv_len, len, authin_len, tag_len, (uint32_t)needed_size,
            res_len);
    WH_DEBUG_SERVER_VERBOSE("AESGCM: req:%p in:%p key:%p iv:%p authin:%p tag:%p res:%p "
            "out:%p out_tag:%p\n",
            &req, in, key, iv, authin, tag, &res, out, out_tag);
    WH_DEBUG_VERBOSE_HEXDUMP("[server] AESGCM req packet: \n", (uint8_t*)cryptoDataIn,
            (uint32_t)needed_size);

    /* Freshen key and validate usage policy if key is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFreshenKey(ctx, key_id, &cachedKey, &keyMeta);
        WH_DEBUG_SERVER_VERBOSE("AesGcm FreshenKey key_id:%u ret:%d\n", key_id, ret);
        if (ret == WH_ERROR_OK) {
            /* Validate key usage policy */
            ret = wh_Server_KeystoreEnforceKeyUsage(
                keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                  : WH_NVM_FLAGS_USAGE_DECRYPT);
        }
        if (ret == WH_ERROR_OK) {
            /* override the incoming values with cached key */
            key     = cachedKey;
            key_len = keyMeta->len;
        }
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && key_len != AES_128_KEY_SIZE &&
        key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesGcm] Invalid key size: %d", key_len);
        ret = WH_ERROR_BADARGS;
    }
    if (ret == WH_ERROR_OK) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, devId);
    }
    if (ret == WH_ERROR_OK) {
        /* load the key */
        ret = wc_AesGcmSetKey(aes, (byte*)key, (word32)key_len);
        WH_DEBUG_SERVER_VERBOSE("AesGcmSetKey key_id:%u key_len:%u ret:%d\n", key_id,
               key_len, ret);
        WH_DEBUG_VERBOSE_HEXDUMP("[server] key: ", key, key_len);
        if (ret == WH_ERROR_OK) {
            /* do the crypto operation */
            WH_DEBUG_SERVER_VERBOSE("enc:%d len:%d, ivSz:%d authTagSz:%d, authInSz:%d\n",
                enc, len, iv_len, tag_len, authin_len);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] in: ", in, len);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] iv: ", iv, iv_len);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] authin: ", authin, authin_len);
            if (enc != 0) {
                /* For encryption, write tag to the response output tag area */
                ret = wc_AesGcmEncrypt(aes, (byte*)out, (byte*)in, (word32)len,
                                       (byte*)iv, (word32)iv_len, (byte*)out_tag,
                                       (word32)tag_len, (byte*)authin,
                                       (word32)authin_len);
                WH_DEBUG_SERVER_VERBOSE("enc ret:%d\n", ret);
                WH_DEBUG_VERBOSE_HEXDUMP("[server] out: \n", out, len);
                WH_DEBUG_VERBOSE_HEXDUMP("[server] enc tag: ", out_tag, tag_len);
            }
            else {
                /* set authTag as a packet input */
                WH_DEBUG_VERBOSE_HEXDUMP("[server] dec tag: ", tag, tag_len);
                ret = wc_AesGcmDecrypt(aes, (byte*)out, (byte*)in, (word32)len,
                                       (byte*)iv, (word32)iv_len, (byte*)tag,
                                       (word32)tag_len, (byte*)authin,
                                       (word32)authin_len);
                WH_DEBUG_SERVER_VERBOSE("dec ret:%d\n", ret);
                WH_DEBUG_VERBOSE_HEXDUMP("[server] out: \n", out, len);
            }
            WH_DEBUG_VERBOSE_HEXDUMP("[server] post iv: ", iv, iv_len);
            WH_DEBUG_VERBOSE_HEXDUMP("[server] post authin: ", authin, authin_len);
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == WH_ERROR_OK) {
        /* set sz */
        res.sz        = len;
        res.authTagSz = (enc == 0) ? 0 : tag_len;
        *outSize      = res_len;
        WH_DEBUG_SERVER_VERBOSE("res out_size:%d\n", *outSize);
        WH_DEBUG_VERBOSE_HEXDUMP("[server] AESGCM res packet: \n",
                                 (uint8_t*)cryptoDataOut, res_len);

        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesGcmResponse(
            magic, &res, (whMessageCrypto_AesGcmResponse*)cryptoDataOut);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _HandleAesGcmDma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    int                               ret = WH_ERROR_OK;
    whMessageCrypto_AesGcmDmaRequest  req;
    whMessageCrypto_AesGcmDmaResponse res;
    Aes                               aes[1] = {0};

    void*  inAddr      = NULL;
    void*  outAddr     = NULL;
    void*  aadAddr     = NULL;
    word32 outSz       = 0;

    whKeyId        keyId;
    uint8_t*       cachedKey = NULL;
    whNvmMetadata* keyMeta   = NULL;

    (void)seq;

    if (inSize < sizeof(whMessageCrypto_AesGcmDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesGcmDmaRequest(
        magic, (whMessageCrypto_AesGcmDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint32_t enc         = req.enc;
    uint32_t keyLen      = req.keySz;
    uint32_t len         = req.input.sz;
    uint32_t ivLen       = req.ivSz;
    uint32_t tagLen      = req.authTagSz;
    uint64_t needed_size = sizeof(whMessageCrypto_AesGcmDmaRequest) + keyLen +
                           ivLen + (enc != 0 ? 0 : tagLen);
    if (needed_size != inSize) {
        return WH_ERROR_BADARGS;
    }
    if (req.input.sz != req.output.sz) {
        return WH_ERROR_BADARGS;
    }

    /* iv is a fixed size field, key and authTag are optional (key is variable
     * length) */
    uint8_t* key     = NULL;
    uint8_t* iv      = (uint8_t*)(cryptoDataIn) +
                       sizeof(whMessageCrypto_AesGcmDmaRequest);
    uint8_t* tag     = iv + ivLen;
    uint8_t* out_tag = (uint8_t*)(cryptoDataOut) +
                       sizeof(whMessageCrypto_AesGcmDmaResponse);

    memset(&res, 0, sizeof(res));

    if (ret == WH_ERROR_OK && keyLen > 0) {
        key = tag + (enc != 0 ? 0 : tagLen);
        WH_DEBUG_VERBOSE_HEXDUMP("[AesGcm] Key ", key, keyLen);
    }
    else if (ret == WH_ERROR_OK && keyLen == 0) {
        /* Handle keyId-based keys if no direct key was provided */
        keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             ctx->comm->client_id, req.keyId);

        /* Freshen key and validate usage policy if key is not erased */
        if (!WH_KEYID_ISERASED(keyId)) {
            ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cachedKey,
                                               &keyMeta);
            if (ret == WH_ERROR_OK) {
                /* Validate key usage policy */
                ret = wh_Server_KeystoreEnforceKeyUsage(
                    keyMeta, enc != 0 ? WH_NVM_FLAGS_USAGE_ENCRYPT
                                    : WH_NVM_FLAGS_USAGE_DECRYPT);
            }
            if (ret == WH_ERROR_OK) {
                key    = cachedKey;
                keyLen = keyMeta->len;
                WH_DEBUG_VERBOSE_HEXDUMP("[AesGcm] Key from HSM", key, keyLen);
            }
        }
    }
    /* Verify key size is valid for AES */
    if (ret == WH_ERROR_OK && keyLen != AES_128_KEY_SIZE &&
        keyLen != AES_192_KEY_SIZE && keyLen != AES_256_KEY_SIZE) {
        WH_DEBUG_SERVER("[AesGcm] Invalid key size: %d", keyLen);
        ret = WH_ERROR_BADARGS;
    }

    /* Handle input data */
    if (ret == WH_ERROR_OK && req.input.sz > 0) {
        /* Process client address for input data */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    /* Handle AAD */
    if (ret == WH_ERROR_OK && req.aad.sz > 0) {
        /* Process client address for AAD */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.aad.addr, &aadAddr, req.aad.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.aad;
        }
    }

    /* Handle output buffer */
    if (ret == WH_ERROR_OK && req.output.sz > 0) {
        /* Process client address for output buffer */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesInit(aes, NULL, devId);
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesGcmSetKey(aes, (byte*)key, (word32)keyLen);
    }

    if (ret == WH_ERROR_OK) {
        if (enc != 0) {
            ret = wc_AesGcmEncrypt(
                aes, (byte*)outAddr, (byte*)inAddr, (word32)len,
                (byte*)iv, (word32)ivLen, (byte*)out_tag, (word32)tagLen,
                (byte*)aadAddr, (word32)req.aad.sz);
        }
        else {
            ret = wc_AesGcmDecrypt(
                aes, (byte*)outAddr, (byte*)inAddr, (word32)len,
                (byte*)iv, (word32)ivLen, (byte*)tag, (word32)tagLen,
                (byte*)aadAddr, (word32)req.aad.sz);
        }
        if (ret == WH_ERROR_OK) {
            outSz = len;
        }
    }

    /* Post-write DMA address processing for output (on success) */
    if (ret == WH_ERROR_OK) {
        if (req.output.sz > 0) {
            ret = wh_Server_DmaProcessClientAddress(
                    ctx, req.output.addr, &outAddr, req.output.sz,
                    WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.output;
            }
        }
    }
    /* Clean up DMA input and aad address (unconditionally) */
    if (inAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE(
                "[AesGcm] Error cleaning up input DMA address\n");
        }
    }
    if (aadAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.aad.addr, &aadAddr, req.aad.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE(
                "[AesGcm] Error cleaning up aad DMA address\n");
        }
    }

    wc_AesFree(aes);

    /* Set response */
    res.outSz = outSz;
    res.authTagSz = (enc == 0) ? 0 : tagLen;

    /* Translate response back */
    (void)wh_MessageCrypto_TranslateAesGcmDmaResponse(
        magic, &res, (whMessageCrypto_AesGcmDmaResponse*)cryptoDataOut);
    *outSize = sizeof(whMessageCrypto_AesGcmDmaResponse) + res.authTagSz;

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)

/* Resolve CMAC key from request (inline key or keystore ID).
 * outKey must be at least AES_256_KEY_SIZE bytes. */
static int _CmacResolveKey(whServerContext* ctx, const uint8_t* requestKey,
                           uint32_t requestKeySz, whKeyId clientKeyId,
                           uint8_t* outKey, uint32_t* outKeyLen)
{
    int ret = WH_ERROR_OK;

    if (requestKeySz != 0) {
        /* Client provided the key directly in the request */
        memcpy(outKey, requestKey, requestKeySz);
        *outKeyLen = requestKeySz;
    }
    else if (!WH_KEYID_ISERASED(clientKeyId)) {
        /* Load key from keystore by ID */
        whKeyId keyId = wh_KeyId_TranslateFromClient(
            WH_KEYTYPE_CRYPTO, ctx->comm->client_id, clientKeyId);

        /* Validate key usage policy - CMAC accepts sign or verify */
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, keyId,
                                                    WH_NVM_FLAGS_USAGE_SIGN);
        if (ret == WH_ERROR_USAGE) {
            ret = wh_Server_KeystoreFindEnforceKeyUsage(
                ctx, keyId, WH_NVM_FLAGS_USAGE_VERIFY);
        }

        if (ret == WH_ERROR_OK) {
            ret =
                wh_Server_KeystoreReadKey(ctx, keyId, NULL, outKey, outKeyLen);
        }

        if (ret == WH_ERROR_OK) {
            /* Validate AES key size */
            if (*outKeyLen != AES_128_KEY_SIZE &&
                *outKeyLen != AES_192_KEY_SIZE &&
                *outKeyLen != AES_256_KEY_SIZE) {
                ret = WH_ERROR_ABORTED;
            }
        }
    }
    else {
        /* No key provided - error */
        ret = WH_ERROR_BADARGS;
    }

    return ret;
}

static int _HandleCmac(whServerContext* ctx, uint16_t magic, int devId,
                       uint16_t seq, const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;

    int                             ret;
    whMessageCrypto_CmacAesRequest  req;
    whMessageCrypto_CmacAesResponse res;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_CmacAesRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateCmacAesRequest(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate variable-length fields fit within inSize */
    uint32_t available = inSize - sizeof(whMessageCrypto_CmacAesRequest);
    if (req.inSz > available) {
        return WH_ERROR_BADARGS;
    }
    available -= req.inSz;
    if (req.keySz > available) {
        return WH_ERROR_BADARGS;
    }
    if (req.keySz > AES_256_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }


    /* Setup fixed size fields */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_CmacAesRequest);
    uint8_t* key = in + req.inSz;
    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_CmacAesResponse);

    memset(&res, 0, sizeof(res));

    uint8_t tmpKey[AES_256_KEY_SIZE];
    uint32_t tmpKeyLen = sizeof(tmpKey);
    Cmac    cmac[1];

    /* Resolve the key to use */
    ret = _CmacResolveKey(ctx, key, req.keySz, req.keyId, tmpKey, &tmpKeyLen);

    /* Oneshot: input and output are both present */
    if (ret == 0 && req.inSz != 0 && req.outSz != 0) {
        word32 len = (word32)req.outSz;

        WH_DEBUG_SERVER_VERBOSE("cmac generate oneshot\n");

        ret = wc_AesCmacGenerate_ex(cmac, out, &len, in, req.inSz, tmpKey,
                                    (word32)tmpKeyLen, NULL, devId);

        if (ret == 0) {
            res.outSz = len;
            res.keyId = WH_KEYID_ERASED;
        }
    }
    else if (ret == 0) {
        /* Multi-step: init/update/final */
        WH_DEBUG_SERVER_VERBOSE(
            "cmac begin keySz:%d inSz:%d outSz:%d keyId:%x\n", req.keySz,
            req.inSz, req.outSz, req.keyId);

        /* Initialize CMAC context with key (re-derives k1/k2 subkeys) */
        ret = wc_InitCmac_ex(cmac, tmpKey, tmpKeyLen, WC_CMAC_AES, NULL, NULL,
                             devId);
        WH_DEBUG_SERVER_VERBOSE("cmac init with keylen:%d ret:%d\n", tmpKeyLen,
                                ret);

        /* Restore non-sensitive state from client. On the first call
         * (init), the client sends zeroed state which is effectively a
         * no-op since wc_InitCmac_ex already zeroed the struct. On
         * subsequent calls (update/final), this restores the running
         * intermediate state. */
        if (ret == 0) {
            ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &req.resumeState);
        }

        /* Handle CMAC update */
        if (ret == 0 && req.inSz != 0) {
            ret = wc_CmacUpdate(cmac, in, req.inSz);
            WH_DEBUG_SERVER_VERBOSE("cmac update done. ret:%d\n", ret);
        }

        if (ret == 0 && req.outSz != 0) {
            /* Finalize CMAC operation */
            word32 len = (word32)req.outSz;
            WH_DEBUG_SERVER_VERBOSE("cmac final len:%d\n", len);
            ret       = wc_CmacFinal(cmac, out, &len);
            res.outSz = (uint32_t)len;
            res.keyId = WH_KEYID_ERASED;
        }
        else if (ret == 0) {
            /* Not finalizing - return updated state to client */
            wh_Crypto_CmacAesSaveStateToMsg(&res.resumeState, cmac);
            res.keyId = req.keyId;
            res.outSz = 0;
        }
    }

    if (ret == 0) {
        ret = wh_MessageCrypto_TranslateCmacAesResponse(magic, &res,
                                                        cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res) + res.outSz;
        }
    }
    WH_DEBUG_SERVER_VERBOSE("cmac end ret:%d\n", ret);
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifndef NO_SHA256
static int _HandleSha256(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha256                     sha256[1];
    whMessageCrypto_Sha256Request req;
    whMessageCrypto_Sha2Response  res = {0};
    const uint8_t*                inData;

    (void)ctx;

    res.hashType = WC_HASH_TYPE_SHA256;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_Sha256Request)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha256Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate inSz fits inside the received payload */
    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha256Request))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final updates must be multiples of WC_SHA256_BLOCK_SIZE */
    if (!req.isLastBlock && (req.inSz % WC_SHA256_BLOCK_SIZE) != 0) {
        return WH_ERROR_BADARGS;
    }
    /* Final block must be strictly less than one block (client always buffers
     * full blocks and sends only the partial tail on finalize). */
    if (req.isLastBlock && req.inSz >= WC_SHA256_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    inData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha256Request);

    /* always init sha2 struct with the devid */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Restore intermediate state from client; server is stateless otherwise.
     * The partial-block buffer lives only on the client. */
    memcpy(sha256->digest, req.resumeState.hash, WC_SHA256_DIGEST_SIZE);
    sha256->loLen   = req.resumeState.loLen;
    sha256->hiLen   = req.resumeState.hiLen;
    sha256->buffLen = 0;

    if (req.inSz > 0) {
        ret = wc_Sha256Update(sha256, inData, req.inSz);
    }
    if (ret == 0) {
        if (req.isLastBlock) {
            /* wolfCrypt is responsible for last block padding */
            ret = wc_Sha256Final(sha256, res.hash);
        }
        else {
            /* Post-condition: non-final updates MUST leave buffLen == 0,
             * since we validated inSz is a multiple of the block size. */
            if (sha256->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
                res.loLen = sha256->loLen;
                res.hiLen = sha256->hiLen;
            }
        }
    }

    /* Translate the response */
    if (ret == 0) {
        ret =
            wh_MessageCrypto_TranslateSha2Response(magic, &res, cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res);
        }
    }

    return ret;
}
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224
static int _HandleSha224(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha224                     sha224[1];
    whMessageCrypto_Sha256Request req;
    whMessageCrypto_Sha2Response  res = {0};
    const uint8_t*                inData;

    (void)ctx;

    res.hashType = WC_HASH_TYPE_SHA224;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_Sha256Request)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha256Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate inSz fits inside the received payload */
    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha256Request))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final updates must be multiples of WC_SHA224_BLOCK_SIZE */
    if (!req.isLastBlock && (req.inSz % WC_SHA224_BLOCK_SIZE) != 0) {
        return WH_ERROR_BADARGS;
    }
    /* Final block must be strictly less than one block */
    if (req.isLastBlock && req.inSz >= WC_SHA224_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    inData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha256Request);

    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    /* sha224 is a part of sha256. It expects to have sha256 digest size of
     * intermediate hash data.
     */
    memcpy(sha224->digest, req.resumeState.hash, WC_SHA256_DIGEST_SIZE);
    sha224->loLen   = req.resumeState.loLen;
    sha224->hiLen   = req.resumeState.hiLen;
    sha224->buffLen = 0;

    if (req.inSz > 0) {
        ret = wc_Sha224Update(sha224, inData, req.inSz);
    }
    if (ret == 0) {
        if (req.isLastBlock) {
            /* wolfCrypt is responsible for last block padding */
            ret = wc_Sha224Final(sha224, res.hash);
        }
        else {
            /* Post-condition: non-final updates MUST leave buffLen == 0 */
            if (sha224->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                /* return back the digest which has the same length of sha256
                 * for further operation */
                memcpy(res.hash, sha224->digest, WC_SHA256_DIGEST_SIZE);
                res.loLen = sha224->loLen;
                res.hiLen = sha224->hiLen;
            }
        }
    }

    /* Translate the response */
    if (ret == 0) {
        ret =
            wh_MessageCrypto_TranslateSha2Response(magic, &res, cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res);
        }
    }

    return ret;
}
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
static int _HandleSha384(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha384                     sha384[1];
    whMessageCrypto_Sha512Request req;
    whMessageCrypto_Sha2Response  res = {0};
    const uint8_t*                inData;

    (void)ctx;

    res.hashType = WC_HASH_TYPE_SHA384;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_Sha512Request)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha512Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate inSz fits inside the received payload */
    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha512Request))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final updates must be multiples of WC_SHA384_BLOCK_SIZE */
    if (!req.isLastBlock && (req.inSz % WC_SHA384_BLOCK_SIZE) != 0) {
        return WH_ERROR_BADARGS;
    }
    /* Final block must be strictly less than one block (client always buffers
     * full blocks and sends only the partial tail on finalize). */
    if (req.isLastBlock && req.inSz >= WC_SHA384_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    inData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha512Request);

    /* init sha2 struct with the devid */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Restore intermediate state from client; server is stateless otherwise.
     * The partial-block buffer lives only on the client.
     * sha384 is a part of sha512. It expects to have sha512 digest
     * size of intermediate hash data. */
    memcpy(sha384->digest, req.resumeState.hash, WC_SHA512_DIGEST_SIZE);
    sha384->loLen   = req.resumeState.loLen;
    sha384->hiLen   = req.resumeState.hiLen;
    sha384->buffLen = 0;

    if (req.inSz > 0) {
        ret = wc_Sha384Update(sha384, inData, req.inSz);
    }
    if (ret == 0) {
        if (req.isLastBlock) {
            /* wolfCrypt is responsible for last block padding */
            ret = wc_Sha384Final(sha384, res.hash);
        }
        else {
            /* Post-condition: non-final updates MUST leave buffLen == 0,
             * since we validated inSz is a multiple of the block size. */
            if (sha384->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                /* return back the digest which has the same length of sha512
                 * for further operation */
                memcpy(res.hash, sha384->digest, WC_SHA512_DIGEST_SIZE);
                res.loLen = sha384->loLen;
                res.hiLen = sha384->hiLen;
            }
        }
    }

    /* Translate the response */
    if (ret == 0) {
        ret =
            wh_MessageCrypto_TranslateSha2Response(magic, &res, cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res);
        }
    }

    return ret;
}
#endif /* WOLFSSL_SHA384 */
#ifdef WOLFSSL_SHA512
static int _HandleSha512(whServerContext* ctx, uint16_t magic, int devId,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha512                     sha512[1];
    whMessageCrypto_Sha512Request req;
    whMessageCrypto_Sha2Response  res      = {0};
    int                           hashType = WC_HASH_TYPE_SHA512;
    const uint8_t*                inData;

    (void)ctx;

    /* Validate minimum size */
    if (inSize < sizeof(whMessageCrypto_Sha512Request)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha512Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Validate inSz fits inside the received payload */
    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha512Request))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final updates must be multiples of WC_SHA512_BLOCK_SIZE */
    if (!req.isLastBlock && (req.inSz % WC_SHA512_BLOCK_SIZE) != 0) {
        return WH_ERROR_BADARGS;
    }
    /* Final block must be strictly less than one block */
    if (req.isLastBlock && req.inSz >= WC_SHA512_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    inData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha512Request);

    /* init sha2 struct with devid. If the client requested a variant the
     * server does not have compiled in, we normalize hashType to plain SHA512
     * so the response reflects what was actually executed; the client detects
     * the mismatch against its own hashType and returns an error. */
    hashType = req.resumeState.hashType;
    switch (hashType) {
#ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
            ret = wc_InitSha512_224_ex(sha512, NULL, devId);
            break;
#endif
#ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
            ret = wc_InitSha512_256_ex(sha512, NULL, devId);
            break;
#endif
        default:
            ret      = wc_InitSha512_ex(sha512, NULL, devId);
            hashType = WC_HASH_TYPE_SHA512;
            break;
    }
    if (ret != 0) {
        return ret;
    }

    res.hashType = hashType;

    /* Restore intermediate state from client; server is stateless otherwise.
     * The partial-block buffer lives only on the client. */
    memcpy(sha512->digest, req.resumeState.hash, WC_SHA512_DIGEST_SIZE);
    sha512->loLen   = req.resumeState.loLen;
    sha512->hiLen   = req.resumeState.hiLen;
    sha512->buffLen = 0;

    if (req.inSz > 0) {
        ret = wc_Sha512Update(sha512, inData, req.inSz);
    }
    if (ret == 0) {
        if (req.isLastBlock) {
            /* wolfCrypt is responsible for last block padding */
            switch (hashType) {
#ifndef WOLFSSL_NOSHA512_224
                case WC_HASH_TYPE_SHA512_224:
                    ret = wc_Sha512_224Final(sha512, res.hash);
                    break;
#endif
#ifndef WOLFSSL_NOSHA512_256
                case WC_HASH_TYPE_SHA512_256:
                    ret = wc_Sha512_256Final(sha512, res.hash);
                    break;
#endif
                default:
                    ret = wc_Sha512Final(sha512, res.hash);
                    break;
            }
        }
        else {
            /* Post-condition: non-final updates MUST leave buffLen == 0,
             * since we validated inSz is a multiple of the block size. */
            if (sha512->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.hash, sha512->digest, WC_SHA512_DIGEST_SIZE);
                res.loLen = sha512->loLen;
                res.hiLen = sha512->hiLen;
            }
        }
    }

    /* Translate the response */
    if (ret == 0) {
        ret =
            wh_MessageCrypto_TranslateSha2Response(magic, &res, cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res);
        }
    }

    return ret;
}
#endif /* WOLFSSL_SHA512 */

#if defined(WOLFSSL_SHA3)
/* SHA3 - one handler dispatches all four variants on hashType. */

typedef struct {
    uint32_t blockSize;
    uint32_t digestSize;
    int (*initFn)(wc_Sha3* sha, void* heap, int devId);
    int (*updateFn)(wc_Sha3* sha, const byte* data, word32 len);
    int (*finalFn)(wc_Sha3* sha, byte* hash);
} _Sha3VariantOps;

static int _Sha3LookupOps(int hashType, _Sha3VariantOps* ops)
{
    switch (hashType) {
#ifndef WOLFSSL_NOSHA3_224
        case WC_HASH_TYPE_SHA3_224:
            ops->blockSize  = WC_SHA3_224_BLOCK_SIZE;
            ops->digestSize = WC_SHA3_224_DIGEST_SIZE;
            ops->initFn     = wc_InitSha3_224;
            ops->updateFn   = wc_Sha3_224_Update;
            ops->finalFn    = wc_Sha3_224_Final;
            return 0;
#endif
#ifndef WOLFSSL_NOSHA3_256
        case WC_HASH_TYPE_SHA3_256:
            ops->blockSize  = WC_SHA3_256_BLOCK_SIZE;
            ops->digestSize = WC_SHA3_256_DIGEST_SIZE;
            ops->initFn     = wc_InitSha3_256;
            ops->updateFn   = wc_Sha3_256_Update;
            ops->finalFn    = wc_Sha3_256_Final;
            return 0;
#endif
#ifndef WOLFSSL_NOSHA3_384
        case WC_HASH_TYPE_SHA3_384:
            ops->blockSize  = WC_SHA3_384_BLOCK_SIZE;
            ops->digestSize = WC_SHA3_384_DIGEST_SIZE;
            ops->initFn     = wc_InitSha3_384;
            ops->updateFn   = wc_Sha3_384_Update;
            ops->finalFn    = wc_Sha3_384_Final;
            return 0;
#endif
#ifndef WOLFSSL_NOSHA3_512
        case WC_HASH_TYPE_SHA3_512:
            ops->blockSize  = WC_SHA3_512_BLOCK_SIZE;
            ops->digestSize = WC_SHA3_512_DIGEST_SIZE;
            ops->initFn     = wc_InitSha3_512;
            ops->updateFn   = wc_Sha3_512_Update;
            ops->finalFn    = wc_Sha3_512_Final;
            return 0;
#endif
        default:
            return WH_ERROR_BADARGS;
    }
}

static int _HandleSha3(whServerContext* ctx, int hashType, uint16_t magic,
                       int devId, const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize)
{
    int                          ret = 0;
    wc_Sha3                      sha3[1];
    whMessageCrypto_Sha3Request  req;
    whMessageCrypto_Sha3Response res = {0};
    const uint8_t*               inData;
    _Sha3VariantOps              ops;

    (void)ctx;

    ret = _Sha3LookupOps(hashType, &ops);
    if (ret != 0) {
        return ret;
    }

    if (inSize < sizeof(whMessageCrypto_Sha3Request)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateSha3Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha3Request))) {
        return WH_ERROR_BADARGS;
    }
    if (!req.isLastBlock && (req.inSz % ops.blockSize) != 0) {
        return WH_ERROR_BADARGS;
    }
    if (req.isLastBlock && req.inSz >= ops.blockSize) {
        return WH_ERROR_BADARGS;
    }

    inData = (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha3Request);

    ret = ops.initFn(sha3, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Restore Keccak state from client. initFn already zeroed t[] and i. */
    memcpy(sha3->s, req.resumeState.s, sizeof(sha3->s));

    if (req.inSz > 0) {
        ret = ops.updateFn(sha3, inData, req.inSz);
    }
    if (ret == 0) {
        if (req.isLastBlock) {
            ret = ops.finalFn(sha3, res.hash);
        }
        else {
            /* Post-condition: whole-block input must leave i == 0. */
            if (sha3->i != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.resumeState.s, sha3->s, sizeof(res.resumeState.s));
            }
        }
    }

    if (ret == 0) {
        ret =
            wh_MessageCrypto_TranslateSha3Response(magic, &res, cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res);
        }
    }

    return ret;
}
#endif /* WOLFSSL_SHA3 */

#ifdef WOLFSSL_HAVE_MLDSA

#ifndef WOLFSSL_MLDSA_NO_MAKE_KEY
/* Check if the ML-DSA security level is supported
 * returns 1 if supported, 0 otherwise */
static int _IsMlDsaLevelSupported(int level)
{
    int ret = 0;

    switch (level) {
#ifndef WOLFSSL_NO_ML_DSA_44
        case WC_ML_DSA_44:
            ret = 1;
            break;
#endif /* !WOLFSSL_NO_ML_DSA_44 */
#ifndef WOLFSSL_NO_ML_DSA_65
        case WC_ML_DSA_65:
            ret = 1;
            break;
#endif /* !WOLFSSL_NO_ML_DSA_65 */
#ifndef WOLFSSL_NO_ML_DSA_87
        case WC_ML_DSA_87:
            ret = 1;
            break;
#endif /* !WOLFSSL_NO_ML_DSA_87 */
        default:
            ret = 0;
            break;
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_NO_MAKE_KEY */

static int _HandleMlDsaKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLDSA_NO_MAKE_KEY
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    (void)inSize;

    int                                 ret = WH_ERROR_OK;
    wc_MlDsaKey                         key[1];
    whMessageCrypto_MlDsaKeyGenRequest  req;
    whMessageCrypto_MlDsaKeyGenResponse res;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaKeyGenRequest(
        magic, (whMessageCrypto_MlDsaKeyGenRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    int     key_size = req.sz;
    whKeyId key_id   = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    int        level      = req.level;
    whNvmFlags flags      = req.flags;
    uint8_t*   label      = req.label;
    uint16_t   label_size = WH_NVM_LABEL_LEN;

    /* Response message */
    uint8_t* res_out =
        (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_MlDsaKeyGenResponse);
    uint16_t max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                                   (res_out - (uint8_t*)cryptoDataOut));
    uint16_t res_size = 0;

    /* TODO key_sz is not used. Should this instead be used as max_size? Figure
     * out the relation between all three */
    (void)key_size;

    /* Check the ML-DSA security level is valid and supported */
    if (0 == _IsMlDsaLevelSupported(level)) {
        ret = WH_ERROR_BADARGS;
    }
    else {
        /* init mldsa key */
        ret = wc_MlDsaKey_Init(key, NULL, devId);
        if (ret == 0) {
            /* Set the ML-DSA security level */
            ret = wc_MlDsaKey_SetParams(key, level);
            if (ret == 0) {
                /* generate the key */
                ret = wc_MlDsaKey_MakeKey(key, ctx->crypto->rng);
                if (ret == 0) {
                    /* Check incoming flags */
                    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                        /* Must serialize the key into the response message. */
                        key_id = WH_KEYID_ERASED;
                        ret    = wh_Crypto_MlDsaSerializeKeyDer(
                            key, max_size, res_out, &res_size);
                    }
                    else {
                        /* Must import the key into the cache and return keyid
                         */
                        res_size = 0;
                        if (WH_KEYID_ISERASED(key_id)) {
                            /* Generate a new id */
                            ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                            WH_DEBUG_SERVER("UniqueId: keyId:%u, ret:%d\n",
                                   key_id, ret);
                            if (ret != WH_ERROR_OK) {
                                /* Early return on unique ID generation failure
                                 */
                                wc_MlDsaKey_Free(key);
                                return ret;
                            }
                        }
                        if (ret == 0) {
                            ret = wh_Server_MlDsaKeyCacheImport(
                                ctx, key, key_id, flags, label_size, label);
                        }
                        WH_DEBUG_SERVER("CacheImport: keyId:%u, ret:%d\n",
                               key_id, ret);
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
                        if (ret == 0) {
                            /* Best-effort public key export: when the
                             * serialized public key fits in the response body,
                             * return it so the client can skip a separate
                             * ExportPublicKey call. When it does not fit (small
                             * comm buffer or a large key), leave the body empty
                             * and keep the cached key. Plain MakeCacheKey callers
                             * ignore the body and see no regression;
                             * MakeCacheKeyAndExportPublic callers detect the
                             * empty body and evict the key themselves. */
                            int pub_ret = wc_MlDsaKey_PublicKeyToDer(
                                key, res_out, max_size, 1);
                            if (pub_ret > 0) {
                                res_size = (uint16_t)pub_ret;
                            }
                            else {
                                res_size = 0;
                            }
                        }
#endif /* WOLFSSL_MLDSA_PUBLIC_KEY */
                    }
                }
            }
            wc_MlDsaKey_Free(key);
        }

        if (ret == WH_ERROR_OK) {
            res.keyId = wh_KeyId_TranslateToClient(key_id);
            res.len   = res_size;

            wh_MessageCrypto_TranslateMlDsaKeyGenResponse(magic, &res,
                                                          cryptoDataOut);

            *outSize = sizeof(whMessageCrypto_MlDsaKeyGenResponse) + res_size;
        }
    }
    return ret;
#endif /* WOLFSSL_MLDSA_NO_MAKE_KEY */
}

static int _HandleMlDsaSign(whServerContext* ctx, uint16_t magic, int devId,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLDSA_NO_SIGN
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    (void)inSize;

    int                                 ret;
    wc_MlDsaKey                         key[1];
    whMessageCrypto_MlDsaSignRequest    req;
    whMessageCrypto_MlDsaSignResponse   res;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaSignRequest(
        magic, (whMessageCrypto_MlDsaSignRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    byte*    in      = (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_MlDsaSignRequest);
    whKeyId  key_id  = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    word32   in_len      = req.sz;
    uint32_t contextSz   = req.contextSz;
    uint32_t preHashType = req.preHashType;
    uint32_t options     = req.options;
    int      evict       = !!(options & WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT);

    /* Validate key usage policy for signing */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_SIGN);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    /* Validate input length against available data to prevent buffer overread
     */
    if (inSize < sizeof(whMessageCrypto_MlDsaSignRequest)) {
        return WH_ERROR_BADARGS;
    }
    word32 available_data = inSize - sizeof(whMessageCrypto_MlDsaSignRequest);
    if (in_len > available_data) {
        return WH_ERROR_BADARGS;
    }
    if (contextSz > (available_data - in_len)) {
        return WH_ERROR_BADARGS;
    }
    if (contextSz > WH_CRYPTO_MLDSA_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }
    byte* req_context = (contextSz > 0) ? (in + in_len) : NULL;

    /* Response message */
    byte* res_out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_MlDsaSignResponse);
    const word32 max_len = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                                    (res_out - (uint8_t*)cryptoDataOut));
    word32       res_len = max_len;

    /* init private key */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_MlDsaKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* sign the input using appropriate FIPS 204 API */
            if (preHashType != WC_HASH_TYPE_NONE) {
                ret = wc_MlDsaKey_SignCtxHash(
                    key, req_context, (byte)contextSz, res_out, &res_len,
                    in, in_len, preHashType, ctx->crypto->rng);
            }
            else {
                ret = wc_MlDsaKey_SignCtx(
                    key, req_context, (byte)contextSz, res_out, &res_len,
                    in, in_len, ctx->crypto->rng);
            }
        }
        wc_MlDsaKey_Free(key);
    }
cleanup:
    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res.sz   = res_len;

        wh_MessageCrypto_TranslateMlDsaSignResponse(
            magic, &res, (whMessageCrypto_MlDsaSignResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_MlDsaSignResponse) + res_len;
    }
    return ret;
#endif /* WOLFSSL_MLDSA_NO_SIGN */
}

static int _HandleMlDsaVerify(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLDSA_NO_VERIFY
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                 ret;
    wc_MlDsaKey                         key[1];
    whMessageCrypto_MlDsaVerifyRequest  req;
    whMessageCrypto_MlDsaVerifyResponse res;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaVerifyRequest(
        magic, (whMessageCrypto_MlDsaVerifyRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    uint32_t options     = req.options;
    whKeyId  key_id      = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint32_t hash_len    = req.hashSz;
    uint32_t sig_len     = req.sigSz;
    uint32_t contextSz   = req.contextSz;
    uint32_t preHashType = req.preHashType;
    byte*    req_sig =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_MlDsaVerifyRequest);
    int evict = !!(options & WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT);

    /* Validate key usage policy for verification */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_VERIFY);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    /* Validate lengths against available payload (overflow-safe) */
    if (inSize < sizeof(whMessageCrypto_MlDsaVerifyRequest)) {
        return WH_ERROR_BADARGS;
    }
    uint32_t available = inSize - sizeof(whMessageCrypto_MlDsaVerifyRequest);
    if ((sig_len > available) || (hash_len > available) ||
        (sig_len > (available - hash_len))) {
        return WH_ERROR_BADARGS;
    }
    if (contextSz > (available - sig_len - hash_len)) {
        return WH_ERROR_BADARGS;
    }
    if (contextSz > WH_CRYPTO_MLDSA_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }

    byte* req_hash    = req_sig + sig_len;
    byte* req_context = (contextSz > 0) ? (req_hash + hash_len) : NULL;

    /* Response message */
    int result = 0;

    /* init public key */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret == 0) {
        /* load the public key */
        ret = wh_Server_MlDsaKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* verify the signature using appropriate FIPS 204 API */
            if (preHashType != WC_HASH_TYPE_NONE) {
                ret = wc_MlDsaKey_VerifyCtxHash(
                    key, req_sig, sig_len, req_context, (byte)contextSz,
                    req_hash, hash_len, preHashType, &result);
            }
            else {
                ret = wc_MlDsaKey_VerifyCtx(
                    key, req_sig, sig_len, req_context, (byte)contextSz,
                    req_hash, hash_len, &result);
            }
        }
        wc_MlDsaKey_Free(key);
    }
cleanup:
    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res.res  = result;

        wh_MessageCrypto_TranslateMlDsaVerifyResponse(
            magic, &res, (whMessageCrypto_MlDsaVerifyResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_MlDsaVerifyResponse);
    }
    return ret;
#endif /* WOLFSSL_MLDSA_NO_VERIFY */
}

static int _HandleMlDsaCheckPrivKey(whServerContext* ctx, uint16_t magic,
                                    int devId, const void* cryptoDataIn,
                                    uint16_t inSize, void* cryptoDataOut,
                                    uint16_t* outSize)
{
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
}
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
static int _IsMlKemLevelSupported(int level)
{
    int ret = 0;

    switch (level) {
#ifndef WOLFSSL_NO_ML_KEM_512
        case WC_ML_KEM_512:
            ret = 1;
            break;
#endif
#ifndef WOLFSSL_NO_ML_KEM_768
        case WC_ML_KEM_768:
            ret = 1;
            break;
#endif
#ifndef WOLFSSL_NO_ML_KEM_1024
        case WC_ML_KEM_1024:
            ret = 1;
            break;
#endif
        default:
            ret = 0;
            break;
    }

    return ret;
}

static int _HandleMlKemKeyGen(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLKEM_NO_MAKE_KEY
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                 ret = WH_ERROR_OK;
    MlKemKey                            key[1];
    whMessageCrypto_MlKemKeyGenRequest  req;
    whMessageCrypto_MlKemKeyGenResponse res;
    uint16_t                            res_size = 0;
    uint8_t*                            res_out;
    uint16_t                            max_size;
    whKeyId                             key_id;
    uint16_t                            label_size = WH_NVM_LABEL_LEN;

    if (inSize < sizeof(whMessageCrypto_MlKemKeyGenRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateMlKemKeyGenRequest(
        magic, (whMessageCrypto_MlKemKeyGenRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, ctx->comm->client_id,
                                          req.keyId);
    res_out = (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_MlKemKeyGenResponse);
    max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                          (res_out - (uint8_t*)cryptoDataOut));

    if (!_IsMlKemLevelSupported((int)req.level)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_MlKemKey_Init(key, (int)req.level, NULL, devId);
    if (ret == 0) {
        ret = wc_MlKemKey_MakeKey(key, ctx->crypto->rng);
        if (ret == 0) {
            if ((req.flags & WH_NVM_FLAGS_EPHEMERAL) != 0) {
                key_id = WH_KEYID_ERASED;
                ret = wh_Crypto_MlKemSerializeKey(key, max_size, res_out,
                                                  &res_size);
            }
            else {
                if (WH_KEYID_ISERASED(key_id)) {
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
                }
                if (ret == WH_ERROR_OK) {
                    ret = wh_Server_MlKemKeyCacheImport(ctx, key, key_id,
                                                        req.flags, label_size,
                                                        req.label);
                }
                if (ret == WH_ERROR_OK) {
                    /* Best-effort public key export: when the serialized
                     * public key fits in the response body, return it so the
                     * client can skip a separate ExportPublicKey call. When it
                     * does not fit (small comm buffer or a large key), leave the
                     * body empty and keep the cached key. Plain MakeCacheKey
                     * callers ignore the body and see no regression;
                     * MakeCacheKeyAndExportPublic callers detect the empty body
                     * and evict the key themselves. */
                    word32 pubSize = 0;
                    if ((wc_MlKemKey_PublicKeySize(key, &pubSize) == 0) &&
                        ((uint32_t)pubSize <= (uint32_t)max_size) &&
                        (wc_MlKemKey_EncodePublicKey(key, res_out, pubSize) ==
                         0)) {
                        res_size = (uint16_t)pubSize;
                    }
                    else {
                        res_size = 0;
                    }
                }
            }
        }
        wc_MlKemKey_Free(key);
    }

    if (ret == WH_ERROR_OK) {
        res.keyId = wh_KeyId_TranslateToClient(key_id);
        res.len   = res_size;
        (void)wh_MessageCrypto_TranslateMlKemKeyGenResponse(
            magic, &res, (whMessageCrypto_MlKemKeyGenResponse*)cryptoDataOut);
        *outSize = sizeof(whMessageCrypto_MlKemKeyGenResponse) + res_size;
    }

    return ret;
#endif /* WOLFSSL_MLKEM_NO_MAKE_KEY */
}

static int _HandleMlKemEncaps(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLKEM_NO_ENCAPSULATE
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                  ret = WH_ERROR_OK;
    MlKemKey                             key[1];
    whMessageCrypto_MlKemEncapsRequest   req;
    whMessageCrypto_MlKemEncapsResponse  res;
    whKeyId                              key_id;
    uint8_t*                             res_ct;
    uint8_t*                             res_ss;
    word32                               ct_len;
    word32                               ss_len;
    word32                               max_out;
    int                                  evict = 0;
    int                                  keyInited = 0;

    if (inSize < sizeof(whMessageCrypto_MlKemEncapsRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateMlKemEncapsRequest(
        magic, (whMessageCrypto_MlKemEncapsRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, ctx->comm->client_id,
                                          req.keyId);
    evict = !!(req.options & WH_MESSAGE_CRYPTO_MLKEM_ENCAPS_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    if (!_IsMlKemLevelSupported((int)req.level)) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }

    ret = wc_MlKemKey_Init(key, (int)req.level, NULL, devId);
    if (ret == 0) {
        keyInited = 1;
        ret = wh_Server_MlKemKeyCacheExport(ctx, key_id, key);
    }

    /* Verify the exported key matches the requested level */
    if (ret == WH_ERROR_OK && key->type != (int)req.level) {
        ret = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_CipherTextSize(key, &ct_len);
        if (ret == WH_ERROR_OK) {
            ret = wc_MlKemKey_SharedSecretSize(key, &ss_len);
        }
    }

    if (ret == WH_ERROR_OK) {
        res_ct = (uint8_t*)cryptoDataOut + sizeof(whMessageCrypto_MlKemEncapsResponse);
        res_ss = res_ct + ct_len;
        max_out = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
            ((uint8_t*)res_ct - (uint8_t*)cryptoDataOut));
        if (ct_len + ss_len > max_out) {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_Encapsulate(key, res_ct, res_ss, ctx->crypto->rng);
        if (ret == WH_ERROR_OK) {
            res.ctSz = ct_len;
            res.ssSz = ss_len;
            (void)wh_MessageCrypto_TranslateMlKemEncapsResponse(
                magic, &res, (whMessageCrypto_MlKemEncapsResponse*)cryptoDataOut);
            *outSize = sizeof(whMessageCrypto_MlKemEncapsResponse) + ct_len + ss_len;
        }
        else {
            /* Zero sensitive data on failure */
            wc_ForceZero(res_ss, ss_len);
        }
    }

    if (keyInited) {
        wc_MlKemKey_Free(key);
    }
cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    return ret;
#endif /* WOLFSSL_MLKEM_NO_ENCAPSULATE */
}

static int _HandleMlKemDecaps(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLKEM_NO_DECAPSULATE
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                 ret = WH_ERROR_OK;
    MlKemKey                            key[1];
    whMessageCrypto_MlKemDecapsRequest  req;
    whMessageCrypto_MlKemDecapsResponse res;
    whKeyId                             key_id;
    byte*                               req_ct;
    byte*                               res_ss;
    uint32_t                            available;
    word32                              ss_len;
    word32                              max_out;
    int                                 evict = 0;
    int                                 keyInited = 0;

    if (inSize < sizeof(whMessageCrypto_MlKemDecapsRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateMlKemDecapsRequest(
        magic, (whMessageCrypto_MlKemDecapsRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, ctx->comm->client_id,
                                          req.keyId);
    evict = !!(req.options & WH_MESSAGE_CRYPTO_MLKEM_DECAPS_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    if (!_IsMlKemLevelSupported((int)req.level)) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }

    available = inSize - sizeof(whMessageCrypto_MlKemDecapsRequest);
    if (req.ctSz > available) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }
    req_ct = (byte*)cryptoDataIn + sizeof(whMessageCrypto_MlKemDecapsRequest);

    ret = wc_MlKemKey_Init(key, (int)req.level, NULL, devId);
    if (ret == WH_ERROR_OK) {
        keyInited = 1;
        ret = wh_Server_MlKemKeyCacheExport(ctx, key_id, key);
    }

    /* Verify the exported key matches the requested level */
    if (ret == WH_ERROR_OK && key->type != (int)req.level) {
        ret = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_SharedSecretSize(key, &ss_len);
    }

    if (ret == WH_ERROR_OK) {
        res_ss = (byte*)cryptoDataOut + sizeof(whMessageCrypto_MlKemDecapsResponse);
        max_out = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
            ((uint8_t*)res_ss - (uint8_t*)cryptoDataOut));
        if (ss_len > max_out) {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_Decapsulate(key, res_ss, req_ct, req.ctSz);
        if (ret == WH_ERROR_OK) {
            res.ssSz = ss_len;
            (void)wh_MessageCrypto_TranslateMlKemDecapsResponse(
                magic, &res, (whMessageCrypto_MlKemDecapsResponse*)cryptoDataOut);
            *outSize = sizeof(whMessageCrypto_MlKemDecapsResponse) + ss_len;
        }
        else {
            /* Zero sensitive data on failure */
            wc_ForceZero(res_ss, ss_len);
        }
    }

    if (keyInited) {
        wc_MlKemKey_Free(key);
    }
cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    return ret;
#endif /* WOLFSSL_MLKEM_NO_DECAPSULATE */
}
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFSSL_HAVE_MLDSA) || defined(HAVE_FALCON)
static int _HandlePqcSigAlgorithm(whServerContext* ctx, uint16_t magic,
                                  int devId, const void* cryptoDataIn,
                                  uint16_t cryptoInSize, void* cryptoDataOut,
                                  uint16_t* cryptoOutSize, uint32_t pkAlgoType,
                                  uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    /* Dispatch the appropriate algorithm handler based on the requested PK type
     * and the algorithm type. */
    switch (pqAlgoType) {
#ifdef WOLFSSL_HAVE_MLDSA
        case WC_PQC_SIG_TYPE_MLDSA: {
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                    ret = _HandleMlDsaKeyGen(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_SIGN:
                    ret = _HandleMlDsaSign(ctx, magic, devId, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                    ret = _HandleMlDsaVerify(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandleMlDsaCheckPrivKey(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
        } break;
#endif /* WOLFSSL_HAVE_MLDSA */
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif

#if defined(WOLFSSL_HAVE_MLKEM)
static int _HandlePqcKemAlgorithm(whServerContext* ctx, uint16_t magic,
                                  int devId, const void* cryptoDataIn,
                                  uint16_t cryptoInSize, void* cryptoDataOut,
                                  uint16_t* cryptoOutSize, uint32_t pkAlgoType,
                                  uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    switch (pqAlgoType) {
        case WC_PQC_KEM_TYPE_KYBER: {
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_KEM_KEYGEN:
                    ret = _HandleMlKemKeyGen(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_KEM_ENCAPS:
                    ret = _HandleMlKemEncaps(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_KEM_DECAPS:
                    ret = _HandleMlKemDecaps(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
        } break;
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif

int wh_Server_HandleCryptoRequest(whServerContext* ctx, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet)
{
    int                                   ret        = 0;
    int                                   devId      = INVALID_DEVID;
    whMessageCrypto_GenericRequestHeader  rqstHeader = {0};
    whMessageCrypto_GenericResponseHeader respHeader = {0};

    const void* cryptoDataIn =
        (uint8_t*)req_packet + sizeof(whMessageCrypto_GenericRequestHeader);
    void* cryptoDataOut =
        (uint8_t*)resp_packet + sizeof(whMessageCrypto_GenericResponseHeader);

    /* Input and output sizes for data passed to crypto handlers. cryptoOutSize
     * should be set by the crypto handler as an output parameter */
    uint16_t cryptoInSize =
        req_size - sizeof(whMessageCrypto_GenericResponseHeader);
    uint16_t cryptoOutSize = 0;

    if ((ctx == NULL) || (ctx->crypto == NULL) || (req_packet == NULL) ||
        (resp_packet == NULL) || (out_resp_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Validate req_size to prevent integer underflow */
    if (req_size < sizeof(whMessageCrypto_GenericResponseHeader)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request message to get the algo type */
    wh_MessageCrypto_TranslateGenericRequestHeader(
        magic, (whMessageCrypto_GenericRequestHeader*)req_packet, &rqstHeader);

#if defined(WOLFHSM_CFG_CRYPTO_AFFINITY)
    /* Compute devId from the per-message affinity field */
    devId = (rqstHeader.affinity == WH_CRYPTO_AFFINITY_HW &&
             ctx->devId != INVALID_DEVID)
                ? ctx->devId
                : INVALID_DEVID;
#else
    /* Crypto affinity disabled: always use the server's configured devId and
     * ignore the request header affinity field. */
    devId = ctx->devId;
#endif /* WOLFHSM_CFG_CRYPTO_AFFINITY */

    WH_DEBUG_SERVER_VERBOSE("HandleCryptoRequest. Action:%u\n", action);
    WH_DEBUG_VERBOSE_HEXDUMP("[server] Crypto Request:\n", (const uint8_t*)req_packet,
                     req_size);
    switch (action) {
        case WC_ALGO_TYPE_CIPHER:
            switch (rqstHeader.algoType) {
#ifndef NO_AES
#ifdef WOLFSSL_AES_COUNTER
                case WC_CIPHER_AES_CTR:
                    ret = _HandleAesCtr(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    break;
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_ECB
                case WC_CIPHER_AES_ECB:
                    ret = _HandleAesEcb(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    break;
#endif /* HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
                case WC_CIPHER_AES_CBC:
                    ret = _HandleAesCbc(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
                case WC_CIPHER_AES_GCM:
                    ret = _HandleAesGcm(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break;
        case WC_ALGO_TYPE_PK: {
            WH_DEBUG_SERVER_VERBOSE("PK type:%d\n", rqstHeader.algoType);
            switch (rqstHeader.algoType) {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
                case WC_PK_TYPE_RSA_KEYGEN:
                    ret = _HandleRsaKeyGen(ctx, magic, devId, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* WOLFSSL_KEY_GEN */
                case WC_PK_TYPE_RSA:
                    ret = _HandleRsaFunction(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             &cryptoOutSize);
                    break;

                case WC_PK_TYPE_RSA_GET_SIZE:
                    ret = _HandleRsaGetSize(ctx, magic, devId, cryptoDataIn,
                                            cryptoInSize, cryptoDataOut,
                                            &cryptoOutSize);
                    break;
#endif /* !NO_RSA */

#ifdef HAVE_ECC
                case WC_PK_TYPE_EC_KEYGEN:
                    ret = _HandleEccKeyGen(ctx, magic, devId, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#ifdef HAVE_ECC_DHE
                case WC_PK_TYPE_ECDH:
                    ret = _HandleEccSharedSecret(ctx, magic, devId,
                                                 cryptoDataIn, cryptoInSize,
                                                 cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_DHE */
#ifdef HAVE_ECC_SIGN
                case WC_PK_TYPE_ECDSA_SIGN:
                    ret = _HandleEccSign(ctx, magic, devId, cryptoDataIn,
                                         cryptoInSize, cryptoDataOut,
                                         &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_SIGN */
#ifdef HAVE_ECC_VERIFY
                case WC_PK_TYPE_ECDSA_VERIFY:
                    ret = _HandleEccVerify(ctx, magic, devId, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_VERIFY */
                case WC_PK_TYPE_EC_MAKE_PUB:
                    ret = _HandleEccMakePub(ctx, magic, devId, cryptoDataIn,
                                            cryptoInSize, cryptoDataOut,
                                            &cryptoOutSize);
                    break;
#ifdef HAVE_ECC_CHECK_KEY
                case WC_PK_TYPE_EC_CHECK_PUB_KEY:
                    ret = _HandleEccCheckPubKey(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_CHECK_KEY */
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
                case WC_PK_TYPE_CURVE25519_KEYGEN:
                    ret = _HandleCurve25519KeyGen(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize);
                    break;
                case WC_PK_TYPE_CURVE25519:
                    ret = _HandleCurve25519SharedSecret(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
                case WC_PK_TYPE_ED25519_KEYGEN:
                    ret = _HandleEd25519KeyGen(ctx, magic, devId, cryptoDataIn,
                                               cryptoInSize, cryptoDataOut,
                                               &cryptoOutSize);
                    break;
                case WC_PK_TYPE_ED25519_SIGN:
                    ret = _HandleEd25519Sign(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             &cryptoOutSize);
                    break;
                case WC_PK_TYPE_ED25519_VERIFY:
                    ret = _HandleEd25519Verify(ctx, magic, devId, cryptoDataIn,
                                               cryptoInSize, cryptoDataOut,
                                               &cryptoOutSize);
                    break;
#endif /* HAVE_ED25519 */

#if defined(WOLFSSL_HAVE_MLDSA) || defined(HAVE_FALCON)
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                case WC_PK_TYPE_PQC_SIG_SIGN:
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandlePqcSigAlgorithm(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize, rqstHeader.algoType,
                        rqstHeader.algoSubType);
                    break;
#endif

#if defined(WOLFSSL_HAVE_MLKEM)
                case WC_PK_TYPE_PQC_KEM_KEYGEN:
                case WC_PK_TYPE_PQC_KEM_ENCAPS:
                case WC_PK_TYPE_PQC_KEM_DECAPS:
                    ret = _HandlePqcKemAlgorithm(ctx, magic, devId,
                                                 cryptoDataIn, cryptoInSize,
                                                 cryptoDataOut, &cryptoOutSize,
                                                 rqstHeader.algoType,
                                                 rqstHeader.algoSubType);
                    break;
#endif

                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
        }; break;

#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_RNG:
            ret = _HandleRng(ctx, magic, devId, cryptoDataIn, cryptoInSize,
                             cryptoDataOut, &cryptoOutSize);
            break;
#endif /* !WC_NO_RNG */

#if defined(HAVE_HKDF) || defined(HAVE_CMAC_KDF)
        case WC_ALGO_TYPE_KDF:
            switch (rqstHeader.algoSubType) {
#ifdef HAVE_HKDF
                case WC_KDF_TYPE_HKDF:
                    ret = _HandleHkdf(ctx, magic, devId, cryptoDataIn,
                                      cryptoInSize, cryptoDataOut,
                                      &cryptoOutSize);
                    break;
#endif /* HAVE_HKDF */
#ifdef HAVE_CMAC_KDF
                case WC_KDF_TYPE_TWOSTEP_CMAC:
                    ret = _HandleCmacKdf(ctx, magic, devId, cryptoDataIn,
                                         cryptoInSize, cryptoDataOut,
                                         &cryptoOutSize);
                    break;
#endif /* HAVE_CMAC_KDF */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break;
#endif /* HAVE_HKDF || HAVE_CMAC_KDF */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
        case WC_ALGO_TYPE_CMAC:
            ret = _HandleCmac(ctx, magic, devId, seq, cryptoDataIn,
                              cryptoInSize, cryptoDataOut, &cryptoOutSize);
            break;
#endif

        case WC_ALGO_TYPE_HASH:
            switch (rqstHeader.algoType) {
#ifndef NO_SHA256
                case WC_HASH_TYPE_SHA256:
                    WH_DEBUG_SERVER("SHA256 req recv. type:%u\n",
                           rqstHeader.algoType);
                    ret = _HandleSha256(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("SHA256 ret = %d\n", ret);
                    }
                    break;
#endif /* !NO_SHA256 */
#if defined(WOLFSSL_SHA224)
                case WC_HASH_TYPE_SHA224:
                    WH_DEBUG_SERVER("SHA224 req recv. type:%u\n",
                           rqstHeader.algoType);
                    ret = _HandleSha224(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("SHA224 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA224 */
#if defined(WOLFSSL_SHA384)
                case WC_HASH_TYPE_SHA384:
                    WH_DEBUG_SERVER("SHA384 req recv. type:%u\n",
                           rqstHeader.algoType);
                    ret = _HandleSha384(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("SHA384 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA384 */
#if defined(WOLFSSL_SHA512)
                case WC_HASH_TYPE_SHA512:
                    WH_DEBUG_SERVER("SHA512 req recv. type:%u\n",
                           rqstHeader.algoType);
                    ret = _HandleSha512(ctx, magic, devId, cryptoDataIn,
                                        cryptoInSize, cryptoDataOut,
                                        &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("SHA512 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA512 */
#if defined(WOLFSSL_SHA3)
                case WC_HASH_TYPE_SHA3_224:
                case WC_HASH_TYPE_SHA3_256:
                case WC_HASH_TYPE_SHA3_384:
                case WC_HASH_TYPE_SHA3_512:
                    WH_DEBUG_SERVER("SHA3 req recv. type:%u\n",
                                    rqstHeader.algoType);
                    ret = _HandleSha3(ctx, rqstHeader.algoType, magic, devId,
                                      cryptoDataIn, cryptoInSize, cryptoDataOut,
                                      &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("SHA3 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA3 */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break;

        case WC_ALGO_TYPE_NONE:
        default:
            ret = NOT_COMPILED_IN;
            break;
    }

    /* Propagate error code to client in response packet header. Crypto handlers
     * have already populated the response packet with the output data. */
    respHeader.rc       = ret;
    respHeader.algoType = rqstHeader.algoType;
    wh_MessageCrypto_TranslateGenericResponseHeader(
        magic, &respHeader,
        (whMessageCrypto_GenericResponseHeader*)resp_packet);

    /* Update the size of the response packet if crypto handler didn't fail */
    if (ret != WH_ERROR_OK) {
        *out_resp_size = sizeof(whMessageCrypto_GenericResponseHeader);
    }
    else {
        *out_resp_size =
            sizeof(whMessageCrypto_GenericResponseHeader) + cryptoOutSize;
    }

    WH_DEBUG_SERVER_VERBOSE("End ret:%d\n", ret);

    return ret;
}

#ifdef WOLFHSM_CFG_DMA

#ifndef NO_SHA256
static int _HandleSha256Dma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    (void)seq;

    int                              ret   = 0;
    int                              preOk = 0;
    whMessageCrypto_Sha256DmaRequest req;
    whMessageCrypto_Sha2DmaResponse  res = {0};
    wc_Sha256                        sha256[1];
    const uint8_t*                   inlineData;
    void*                            inAddr = NULL;

    res.hashType = WC_HASH_TYPE_SHA256;

    if (inSize < sizeof(whMessageCrypto_Sha256DmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateSha256DmaRequest(
        magic, (const whMessageCrypto_Sha256DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Validate inSz fits inside the received payload */
    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha256DmaRequest))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final: inline and DMA input must be multiples of block size */
    if (!req.isLastBlock && ((req.inSz % WC_SHA256_BLOCK_SIZE) != 0 ||
                             (req.input.sz % WC_SHA256_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Final: inline data must be less than one block, no DMA input */
    if (req.isLastBlock &&
        (req.inSz >= WC_SHA256_BLOCK_SIZE || req.input.sz != 0)) {
        return WH_ERROR_BADARGS;
    }

    inlineData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha256DmaRequest);

    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Restore intermediate state from request */
    memcpy(sha256->digest, req.resumeState.hash, WC_SHA256_DIGEST_SIZE);
    sha256->loLen   = req.resumeState.loLen;
    sha256->hiLen   = req.resumeState.hiLen;
    sha256->buffLen = 0;

    /* Process inline trailing data (assembled first block or final tail) */
    if (ret == 0 && req.inSz > 0) {
        ret = wc_Sha256Update(sha256, inlineData, req.inSz);
    }

    /* Process DMA input (whole blocks from Update) */
    if (ret == 0 && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            preOk = 1;
            ret   = wc_Sha256Update(sha256, inAddr, req.input.sz);
        }
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }
    /* Pair every successful PRE with a POST so DMA callbacks can release any
     * resources they acquired, even if the Update failed. */
    if (preOk) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (ret == 0) {
        if (req.isLastBlock) {
            ret = wc_Sha256Final(sha256, res.hash);
        }
        else {
            if (sha256->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
                res.loLen = sha256->loLen;
                res.hiLen = sha256->hiLen;
            }
        }
    }

    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    return ret;
}
#endif /* ! NO_SHA256 */

#ifdef WOLFSSL_SHA224
static int _HandleSha224Dma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    (void)seq;
    int                              ret   = 0;
    int                              preOk = 0;
    whMessageCrypto_Sha256DmaRequest req;
    whMessageCrypto_Sha2DmaResponse  res = {0};
    wc_Sha224                        sha224[1];
    const uint8_t*                   inlineData;
    void*                            inAddr = NULL;

    res.hashType = WC_HASH_TYPE_SHA224;

    if (inSize < sizeof(whMessageCrypto_Sha256DmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateSha256DmaRequest(
        magic, (const whMessageCrypto_Sha256DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha256DmaRequest))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final: inline and DMA input must be multiples of block size */
    if (!req.isLastBlock && ((req.inSz % WC_SHA224_BLOCK_SIZE) != 0 ||
                             (req.input.sz % WC_SHA224_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Final: inline data must be less than one block, no DMA input */
    if (req.isLastBlock &&
        (req.inSz >= WC_SHA224_BLOCK_SIZE || req.input.sz != 0)) {
        return WH_ERROR_BADARGS;
    }

    inlineData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha256DmaRequest);

    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* SHA224 shares SHA256's internal 32-byte digest state */
    memcpy(sha224->digest, req.resumeState.hash, WC_SHA256_DIGEST_SIZE);
    sha224->loLen   = req.resumeState.loLen;
    sha224->hiLen   = req.resumeState.hiLen;
    sha224->buffLen = 0;

    if (ret == 0 && req.inSz > 0) {
        ret = wc_Sha224Update(sha224, inlineData, req.inSz);
    }

    if (ret == 0 && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            preOk = 1;
            ret   = wc_Sha224Update(sha224, inAddr, req.input.sz);
        }
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }
    /* Pair every successful PRE with a POST so DMA callbacks can release any
     * resources they acquired, even if the Update failed. */
    if (preOk) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (ret == 0) {
        if (req.isLastBlock) {
            ret = wc_Sha224Final(sha224, res.hash);
        }
        else {
            if (sha224->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.hash, sha224->digest, WC_SHA256_DIGEST_SIZE);
                res.loLen = sha224->loLen;
                res.hiLen = sha224->hiLen;
            }
        }
    }

    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    return ret;
}
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
static int _HandleSha384Dma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    (void)seq;
    int                              ret   = 0;
    int                              preOk = 0;
    whMessageCrypto_Sha512DmaRequest req;
    whMessageCrypto_Sha2DmaResponse  res = {0};
    wc_Sha384                        sha384[1];
    const uint8_t*                   inlineData;
    void*                            inAddr = NULL;

    res.hashType = WC_HASH_TYPE_SHA384;

    if (inSize < sizeof(whMessageCrypto_Sha512DmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateSha512DmaRequest(
        magic, (const whMessageCrypto_Sha512DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha512DmaRequest))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final: inline and DMA input must be multiples of block size */
    if (!req.isLastBlock && ((req.inSz % WC_SHA384_BLOCK_SIZE) != 0 ||
                             (req.input.sz % WC_SHA384_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Final: inline data must be less than one block, no DMA input */
    if (req.isLastBlock &&
        (req.inSz >= WC_SHA384_BLOCK_SIZE || req.input.sz != 0)) {
        return WH_ERROR_BADARGS;
    }

    inlineData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha512DmaRequest);

    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* SHA384 shares SHA512's internal 64-byte digest state */
    memcpy(sha384->digest, req.resumeState.hash, WC_SHA512_DIGEST_SIZE);
    sha384->loLen   = req.resumeState.loLen;
    sha384->hiLen   = req.resumeState.hiLen;
    sha384->buffLen = 0;

    if (ret == 0 && req.inSz > 0) {
        ret = wc_Sha384Update(sha384, inlineData, req.inSz);
    }

    if (ret == 0 && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            preOk = 1;
            ret   = wc_Sha384Update(sha384, inAddr, req.input.sz);
        }
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }
    /* Pair every successful PRE with a POST so DMA callbacks can release any
     * resources they acquired, even if the Update failed. */
    if (preOk) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (ret == 0) {
        if (req.isLastBlock) {
            ret = wc_Sha384Final(sha384, res.hash);
        }
        else {
            if (sha384->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.hash, sha384->digest, WC_SHA512_DIGEST_SIZE);
                res.loLen = sha384->loLen;
                res.hiLen = sha384->hiLen;
            }
        }
    }

    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    return ret;
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static int _HandleSha512Dma(whServerContext* ctx, uint16_t magic, int devId,
                            uint16_t seq, const void* cryptoDataIn,
                            uint16_t inSize, void* cryptoDataOut,
                            uint16_t* outSize)
{
    (void)seq;
    int                              ret   = 0;
    int                              preOk = 0;
    whMessageCrypto_Sha512DmaRequest req;
    whMessageCrypto_Sha2DmaResponse  res = {0};
    wc_Sha512                        sha512[1];
    const uint8_t*                   inlineData;
    void*                            inAddr = NULL;
    int                              hashType;

    if (inSize < sizeof(whMessageCrypto_Sha512DmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateSha512DmaRequest(
        magic, (const whMessageCrypto_Sha512DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha512DmaRequest))) {
        return WH_ERROR_BADARGS;
    }
    /* Non-final: inline and DMA input must be multiples of block size */
    if (!req.isLastBlock && ((req.inSz % WC_SHA512_BLOCK_SIZE) != 0 ||
                             (req.input.sz % WC_SHA512_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Final: inline data must be less than one block, no DMA input */
    if (req.isLastBlock &&
        (req.inSz >= WC_SHA512_BLOCK_SIZE || req.input.sz != 0)) {
        return WH_ERROR_BADARGS;
    }

    inlineData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha512DmaRequest);
    hashType = req.resumeState.hashType;

    /* If the client requested a variant the server does not have compiled in,
     * normalize hashType to plain SHA512 so the response reflects what was
     * actually executed; the client detects the mismatch against its own
     * hashType and returns an error. */
    switch (hashType) {
#ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
            ret = wc_InitSha512_224_ex(sha512, NULL, devId);
            break;
#endif
#ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
            ret = wc_InitSha512_256_ex(sha512, NULL, devId);
            break;
#endif
        default:
            ret      = wc_InitSha512_ex(sha512, NULL, devId);
            hashType = WC_HASH_TYPE_SHA512;
            break;
    }
    if (ret != 0) {
        return ret;
    }

    res.hashType = hashType;

    memcpy(sha512->digest, req.resumeState.hash, WC_SHA512_DIGEST_SIZE);
    sha512->loLen    = req.resumeState.loLen;
    sha512->hiLen    = req.resumeState.hiLen;
    sha512->buffLen  = 0;

    if (ret == 0 && req.inSz > 0) {
        ret = wc_Sha512Update(sha512, inlineData, req.inSz);
    }

    if (ret == 0 && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            preOk = 1;
            ret   = wc_Sha512Update(sha512, inAddr, req.input.sz);
        }
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }
    /* Pair every successful PRE with a POST so DMA callbacks can release any
     * resources they acquired, even if the Update failed. */
    if (preOk) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (ret == 0) {
        if (req.isLastBlock) {
            switch (hashType) {
#ifndef WOLFSSL_NOSHA512_224
                case WC_HASH_TYPE_SHA512_224:
                    ret = wc_Sha512_224Final(sha512, res.hash);
                    break;
#endif
#ifndef WOLFSSL_NOSHA512_256
                case WC_HASH_TYPE_SHA512_256:
                    ret = wc_Sha512_256Final(sha512, res.hash);
                    break;
#endif
                default:
                    ret = wc_Sha512Final(sha512, res.hash);
                    break;
            }
        }
        else {
            if (sha512->buffLen != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.hash, sha512->digest, WC_SHA512_DIGEST_SIZE);
                res.loLen = sha512->loLen;
                res.hiLen = sha512->hiLen;
            }
        }
    }

    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    return ret;
}
#endif /* WOLFSSL_SHA512 */

#if defined(WOLFSSL_SHA3)
static int _HandleSha3Dma(whServerContext* ctx, int hashType, uint16_t magic,
                          int devId, uint16_t seq, const void* cryptoDataIn,
                          uint16_t inSize, void* cryptoDataOut,
                          uint16_t* outSize)
{
    (void)seq;
    int                             ret   = 0;
    int                             preOk = 0;
    whMessageCrypto_Sha3DmaRequest  req;
    whMessageCrypto_Sha3DmaResponse res = {0};
    wc_Sha3                         sha3[1];
    const uint8_t*                  inlineData;
    void*                           inAddr = NULL;
    _Sha3VariantOps                 ops;

    ret = _Sha3LookupOps(hashType, &ops);
    if (ret != 0) {
        return ret;
    }

    if (inSize < sizeof(whMessageCrypto_Sha3DmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateSha3DmaRequest(
        magic, (const whMessageCrypto_Sha3DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if ((uint32_t)req.inSz >
        (uint32_t)(inSize - sizeof(whMessageCrypto_Sha3DmaRequest))) {
        return WH_ERROR_BADARGS;
    }
    if (!req.isLastBlock && ((req.inSz % ops.blockSize) != 0 ||
                             (req.input.sz % ops.blockSize) != 0)) {
        return WH_ERROR_BADARGS;
    }
    if (req.isLastBlock && (req.inSz >= ops.blockSize || req.input.sz != 0)) {
        return WH_ERROR_BADARGS;
    }

    inlineData =
        (const uint8_t*)cryptoDataIn + sizeof(whMessageCrypto_Sha3DmaRequest);

    ret = ops.initFn(sha3, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Restore Keccak state from client. initFn already zeroed t[] and i. */
    memcpy(sha3->s, req.resumeState.s, sizeof(sha3->s));

    if (ret == 0 && req.inSz > 0) {
        ret = ops.updateFn(sha3, inlineData, req.inSz);
    }

    if (ret == 0 && req.input.sz > 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            preOk = 1;
            ret   = ops.updateFn(sha3, inAddr, req.input.sz);
        }
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }
    if (preOk) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (ret == 0) {
        if (req.isLastBlock) {
            ret = ops.finalFn(sha3, res.hash);
        }
        else {
            if (sha3->i != 0) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(res.resumeState.s, sha3->s, sizeof(res.resumeState.s));
            }
        }
    }

    (void)wh_MessageCrypto_TranslateSha3DmaResponse(
        magic, &res, (whMessageCrypto_Sha3DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    return ret;
}
#endif /* WOLFSSL_SHA3 */

#if defined(WOLFSSL_HAVE_MLDSA)

static int _HandleMlDsaKeyGenDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
#ifdef WOLFSSL_MLDSA_NO_MAKE_KEY
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int         ret = WH_ERROR_OK;
    wc_MlDsaKey key[1];
    void*       clientOutAddr = NULL;
    uint16_t    keySize       = 0;

    whMessageCrypto_MlDsaKeyGenDmaRequest req;
    whMessageCrypto_MlDsaKeyGenDmaResponse res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(whMessageCrypto_MlDsaKeyGenDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaKeyGenDmaRequest(
        magic, (whMessageCrypto_MlDsaKeyGenDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Check the ML-DSA security level is valid and supported */
    if (0 == _IsMlDsaLevelSupported(req.level)) {
        ret = WH_ERROR_BADARGS;
    }
    else {
        /* init mldsa key */
        ret = wc_MlDsaKey_Init(key, NULL, devId);
        if (ret == 0) {
            /* Set the ML-DSA security level */
            ret = wc_MlDsaKey_SetParams(key, req.level);
            if (ret == 0) {
                /* generate the key */
                ret = wc_MlDsaKey_MakeKey(key, ctx->crypto->rng);
                if (ret == 0) {
                    /* Check incoming flags */
                    if (req.flags & WH_NVM_FLAGS_EPHEMERAL) {
                        /* Must serialize the key into client memory */
                        ret = wh_Server_DmaProcessClientAddress(
                            ctx, req.key.addr, &clientOutAddr, req.key.sz,
                            WH_DMA_OPER_CLIENT_WRITE_PRE,
                            (whServerDmaFlags){0});

                        if (ret == 0) {
                            ret = wh_Crypto_MlDsaSerializeKeyDer(
                                key, req.key.sz, clientOutAddr, &keySize);
                            if (ret == 0) {
                                res.keyId   = WH_KEYID_ERASED;
                                res.keySize = keySize;
                            }
                        }

                        if (ret == 0) {
                            ret = wh_Server_DmaProcessClientAddress(
                                ctx, req.key.addr, &clientOutAddr, keySize,
                                WH_DMA_OPER_CLIENT_WRITE_POST,
                                (whServerDmaFlags){0});
                        }
                    }
                    else {
                        /* Must import the key into the cache and return keyid
                         */
                        whKeyId keyId = wh_KeyId_TranslateFromClient(
                            WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

                        if (WH_KEYID_ISERASED(keyId)) {
                            /* Generate a new id */
                            ret = wh_Server_KeystoreGetUniqueId(ctx, &keyId);
                            WH_DEBUG_SERVER("UniqueId: keyId:%u, ret:%d\n",
                                   keyId, ret);
                            if (ret != WH_ERROR_OK) {
                                /* Early return on unique ID generation failure
                                 */
                                wc_MlDsaKey_Free(key);
                                return ret;
                            }
                        }

                        if (ret == 0) {
                            ret = wh_Server_MlDsaKeyCacheImport(
                                ctx, key, keyId, req.flags, req.labelSize,
                                req.label);
                            WH_DEBUG_SERVER("CacheImport: keyId:%u, ret:%d\n",
                                keyId, ret);
                        }
#ifdef WOLFSSL_MLDSA_PUBLIC_KEY
                        /* Stream the public key back through the client's DMA
                         * buffer so it gets the pubkey without a separate
                         * ExportPublicKey call. A freshly generated key must
                         * serialize, so treat a failure as fatal: evict the
                         * just-committed key and propagate the error rather
                         * than returning a keyId with no public key. */
                        if (ret == 0) {
                            int rc = wh_Server_DmaProcessClientAddress(
                                ctx, req.key.addr, &clientOutAddr, req.key.sz,
                                WH_DMA_OPER_CLIENT_WRITE_PRE,
                                (whServerDmaFlags){0});
                            if (rc == 0) {
                                int pub_ret = wc_MlDsaKey_PublicKeyToDer(
                                    key, (byte*)clientOutAddr,
                                    (word32)req.key.sz, 1);
                                if (pub_ret > 0) {
                                    keySize = (uint16_t)pub_ret;
                                }
                                else {
                                    ret = (pub_ret < 0) ? pub_ret
                                                        : WH_ERROR_ABORTED;
                                }
                                (void)wh_Server_DmaProcessClientAddress(
                                    ctx, req.key.addr, &clientOutAddr, keySize,
                                    WH_DMA_OPER_CLIENT_WRITE_POST,
                                    (whServerDmaFlags){0});
                            }
                            else {
                                ret = rc;
                            }
                            if (ret != 0) {
                                (void)wh_Server_KeystoreEvictKey(ctx, keyId);
                            }
                        }
#endif /* WOLFSSL_MLDSA_PUBLIC_KEY */
                        if (ret == 0) {
                            res.keyId   = wh_KeyId_TranslateToClient(keyId);
                            res.keySize = keySize;
                        }
                    }
                }
            }
            wc_MlDsaKey_Free(key);
        }
    }

    if (ret == WH_ERROR_ACCESS) {
        res.dmaAddrStatus.badAddr = req.key;
    }

    /* Translate the response */
    (void)wh_MessageCrypto_TranslateMlDsaKeyGenDmaResponse(
        magic, &res, (whMessageCrypto_MlDsaKeyGenDmaResponse*)cryptoDataOut);

    *outSize = sizeof(res);

    return ret;
#endif /* WOLFSSL_MLDSA_NO_MAKE_KEY */
}

static int _HandleMlDsaSignDma(whServerContext* ctx, uint16_t magic, int devId,
                               const void* cryptoDataIn, uint16_t inSize,
                               void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_MLDSA_NO_SIGN
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int         ret = 0;
    wc_MlDsaKey key[1];
    void*       msgAddr = NULL;
    void*       sigAddr = NULL;
    word32      sigLen   = 0;

    whMessageCrypto_MlDsaSignDmaRequest req;
    whMessageCrypto_MlDsaSignDmaResponse res;

    if (inSize < sizeof(whMessageCrypto_MlDsaSignDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaSignDmaRequest(
        magic, (whMessageCrypto_MlDsaSignDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;


    /* Get key ID and evict flag */
    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                          ctx->comm->client_id, req.keyId);
    evict  = !!(req.options & WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT);

    /* Extract context from inline data after the struct */
    uint32_t contextSz   = req.contextSz;
    uint32_t preHashType = req.preHashType;
    byte*    req_context  = NULL;
    if (contextSz > WH_CRYPTO_MLDSA_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }
    if (contextSz > 0) {
        if (inSize < sizeof(whMessageCrypto_MlDsaSignDmaRequest) + contextSz) {
            return WH_ERROR_BADARGS;
        }
        req_context = (uint8_t*)(cryptoDataIn) +
                      sizeof(whMessageCrypto_MlDsaSignDmaRequest);
    }

    /* Initialize key */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret == 0) {
        /* Export key from cache */
        /* TODO: sanity check security level against key pulled from cache? */
        ret = wh_Server_MlDsaKeyCacheExport(ctx, key_id, key);
        if (ret == 0) {
            /* Process client message buffer address */
            ret = wh_Server_DmaProcessClientAddress(
                ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

            if (ret == 0) {
                /* Process client signature buffer address */
                ret = wh_Server_DmaProcessClientAddress(
                    ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
                    WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});

                if (ret == 0) {
                    /* Sign the message using appropriate FIPS 204 API */
                    sigLen = req.sig.sz;
                    if (preHashType != WC_HASH_TYPE_NONE) {
                        ret = wc_MlDsaKey_SignCtxHash(
                            key, req_context, (byte)contextSz,
                            sigAddr, &sigLen, msgAddr, req.msg.sz,
                            preHashType, ctx->crypto->rng);
                    }
                    else {
                        ret = wc_MlDsaKey_SignCtx(
                            key, req_context, (byte)contextSz,
                            sigAddr, &sigLen, msgAddr, req.msg.sz,
                            ctx->crypto->rng);
                    }
                }

                if (sigAddr != NULL) {
                    /* Post-write processing of signature buffer */
                    (void)wh_Server_DmaProcessClientAddress(
                        ctx, (uintptr_t)req.sig.addr, &sigAddr, sigLen,
                        WH_DMA_OPER_CLIENT_WRITE_POST,
                        (whServerDmaFlags){0});
                }
                if (msgAddr != NULL) {
                    /* Post-read processing of message buffer */
                    (void)wh_Server_DmaProcessClientAddress(
                        ctx, (uintptr_t)req.msg.addr, &msgAddr,
                        req.msg.sz, WH_DMA_OPER_CLIENT_READ_POST,
                        (whServerDmaFlags){0});
                }
            }

            /* Evict key if requested */
            if (evict) {
                /* User requested to evict from cache, even if the call failed
                 */
                (void)wh_Server_KeystoreEvictKey(ctx, key_id);
            }
        }
        wc_MlDsaKey_Free(key);
    }

    if (ret == 0) {
        /* Set response signature length */
        res.sigLen = sigLen;
        *outSize   = sizeof(res);

        /* Translate the response */
        (void)wh_MessageCrypto_TranslateMlDsaSignDmaResponse(
            magic, &res, (whMessageCrypto_MlDsaSignDmaResponse*)cryptoDataOut);
    }

    return ret;
#endif /* WOLFSSL_MLDSA_NO_SIGN */
}

static int _HandleMlDsaVerifyDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
#ifdef WOLFSSL_MLDSA_NO_VERIFY
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int         ret = 0;
    wc_MlDsaKey key[1];
    void*       msgAddr  = NULL;
    void*       sigAddr  = NULL;
    int         verified = 0;

    whMessageCrypto_MlDsaVerifyDmaRequest req;
    whMessageCrypto_MlDsaVerifyDmaResponse res;

    if (inSize < sizeof(whMessageCrypto_MlDsaVerifyDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaVerifyDmaRequest(
        magic, (whMessageCrypto_MlDsaVerifyDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    /* Get key ID and evict flag */
    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                          ctx->comm->client_id, req.keyId);
    evict  = !!(req.options & WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT);

    /* Extract context from inline data after the struct */
    uint32_t contextSz   = req.contextSz;
    uint32_t preHashType = req.preHashType;
    byte*    req_context  = NULL;
    if (contextSz > WH_CRYPTO_MLDSA_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }
    if (contextSz > 0) {
        if (inSize < sizeof(whMessageCrypto_MlDsaVerifyDmaRequest) + contextSz) {
            return WH_ERROR_BADARGS;
        }
        req_context = (uint8_t*)(cryptoDataIn) +
                      sizeof(whMessageCrypto_MlDsaVerifyDmaRequest);
    }

    /* Initialize key */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Export key from cache */
    ret = wh_Server_MlDsaKeyCacheExport(ctx, key_id, key);
    if (ret == 0) {
        /* Process client signature buffer address */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

        if (ret == 0) {
            /* Process client message buffer address */
            ret = wh_Server_DmaProcessClientAddress(
                ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

            if (ret == 0) {
                /* Verify the signature using appropriate FIPS 204 API */
                if (preHashType != WC_HASH_TYPE_NONE) {
                    ret = wc_MlDsaKey_VerifyCtxHash(
                        key, sigAddr, req.sig.sz, req_context, (byte)contextSz,
                        msgAddr, req.msg.sz, preHashType, &verified);
                }
                else {
                    ret = wc_MlDsaKey_VerifyCtx(
                        key, sigAddr, req.sig.sz, req_context, (byte)contextSz,
                        msgAddr, req.msg.sz, &verified);
                }
            }

            if (sigAddr != NULL) {
                /* Post-read processing of signature buffer */
                (void)wh_Server_DmaProcessClientAddress(
                    ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
                    WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
            }

            if (msgAddr != NULL) {
                /* Post-read processing of message buffer */
                (void)wh_Server_DmaProcessClientAddress(
                    ctx, (uintptr_t)req.msg.addr, &msgAddr,
                    req.msg.sz, WH_DMA_OPER_CLIENT_READ_POST,
                    (whServerDmaFlags){0});
            }
        }

        /* Evict key if requested */
        if (evict) {
            /* User requested to evict from cache, even if the call failed */
            (void)wh_Server_KeystoreEvictKey(ctx, key_id);
        }
    }

    if (ret == 0) {
        /* Set verification result */
        res.verifyResult = verified;

        /* Translate the response */
        (void)wh_MessageCrypto_TranslateMlDsaVerifyDmaResponse(
            magic, &res,
            (whMessageCrypto_MlDsaVerifyDmaResponse*)cryptoDataOut);

        *outSize = sizeof(res);
    }

    wc_MlDsaKey_Free(key);
    return ret;
#endif /* WOLFSSL_MLDSA_NO_VERIFY */
}

static int _HandleMlDsaCheckPrivKeyDma(whServerContext* ctx, uint16_t magic,
                                       int devId, const void* cryptoDataIn,
                                       uint16_t inSize, void* cryptoDataOut,
                                       uint16_t* outSize)
{
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
}
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_MLDSA) || defined(HAVE_FALCON)
static int _HandlePqcSigAlgorithmDma(whServerContext* ctx, uint16_t magic,
                                     int devId, const void* cryptoDataIn,
                                     uint16_t cryptoInSize, void* cryptoDataOut,
                                     uint16_t* cryptoOutSize,
                                     uint32_t pkAlgoType, uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    /* Dispatch the appropriate algorithm handler based on the requested PK type
     * and the algorithm type. */
    switch (pqAlgoType) {
#ifdef WOLFSSL_HAVE_MLDSA
        case WC_PQC_SIG_TYPE_MLDSA: {
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                    ret = _HandleMlDsaKeyGenDma(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_SIGN:
                    ret = _HandleMlDsaSignDma(ctx, magic, devId, cryptoDataIn,
                                              cryptoInSize, cryptoDataOut,
                                              cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                    ret = _HandleMlDsaVerifyDma(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandleMlDsaCheckPrivKeyDma(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
        } break;
#endif /* WOLFSSL_HAVE_MLDSA */
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_MLDSA || HAVE_FALCON */

#if defined(WOLFSSL_HAVE_MLKEM)
static int _HandleMlKemKeyGenDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
#ifdef WOLFSSL_MLKEM_NO_MAKE_KEY
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                  ret = WH_ERROR_OK;
    MlKemKey                             key[1];
    void*                                clientOutAddr = NULL;
    uint16_t                             keySize = 0;
    whMessageCrypto_MlKemKeyGenDmaRequest req;
    whMessageCrypto_MlKemKeyGenDmaResponse res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(whMessageCrypto_MlKemKeyGenDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateMlKemKeyGenDmaRequest(
        magic, (whMessageCrypto_MlKemKeyGenDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (!_IsMlKemLevelSupported((int)req.level)) {
        ret = WH_ERROR_BADARGS;
    }
    else {
        ret = wc_MlKemKey_Init(key, (int)req.level, NULL, devId);
        if (ret == WH_ERROR_OK) {
            ret = wc_MlKemKey_MakeKey(key, ctx->crypto->rng);
            if (ret == WH_ERROR_OK) {
                if ((req.flags & WH_NVM_FLAGS_EPHEMERAL) != 0) {
                    ret = wh_Server_DmaProcessClientAddress(
                        ctx, req.key.addr, &clientOutAddr, req.key.sz,
                        WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
                    if (ret == WH_ERROR_OK) {
                        ret = wh_Crypto_MlKemSerializeKey(
                            key, req.key.sz, (uint8_t*)clientOutAddr, &keySize);
                        if (ret == WH_ERROR_OK) {
                            res.keyId   = WH_KEYID_ERASED;
                            res.keySize = keySize;
                        }
                    }
                    if (ret == WH_ERROR_OK) {
                        ret = wh_Server_DmaProcessClientAddress(
                            ctx, req.key.addr, &clientOutAddr, keySize,
                            WH_DMA_OPER_CLIENT_WRITE_POST,
                            (whServerDmaFlags){0});
                    }
                }
                else {
                    whKeyId keyId = wh_KeyId_TranslateFromClient(
                        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

                    if (WH_KEYID_ISERASED(keyId)) {
                        ret = wh_Server_KeystoreGetUniqueId(ctx, &keyId);
                    }
                    if (ret == WH_ERROR_OK) {
                        ret = wh_Server_MlKemKeyCacheImport(
                            ctx, key, keyId, req.flags, req.labelSize,
                            req.label);
                    }
                    /* Stream the public key back through the client's DMA
                     * buffer so it gets the pubkey without a separate
                     * ExportPublicKey call. A freshly generated key must
                     * serialize, so treat a failure as fatal: evict the
                     * just-committed key and propagate the error rather than
                     * returning a keyId with no public key. */
                    if (ret == WH_ERROR_OK) {
                        word32 pubSize = 0;
                        if ((wc_MlKemKey_PublicKeySize(key, &pubSize) != 0) ||
                            ((uint64_t)pubSize > req.key.sz)) {
                            ret = WH_ERROR_ABORTED;
                        }
                        else {
                            ret = wh_Server_DmaProcessClientAddress(
                                ctx, req.key.addr, &clientOutAddr, pubSize,
                                WH_DMA_OPER_CLIENT_WRITE_PRE,
                                (whServerDmaFlags){0});
                            if (ret == WH_ERROR_OK) {
                                if (wc_MlKemKey_EncodePublicKey(
                                        key, (uint8_t*)clientOutAddr, pubSize) ==
                                    0) {
                                    keySize = (uint16_t)pubSize;
                                }
                                else {
                                    ret = WH_ERROR_ABORTED;
                                }
                                (void)wh_Server_DmaProcessClientAddress(
                                    ctx, req.key.addr, &clientOutAddr, keySize,
                                    WH_DMA_OPER_CLIENT_WRITE_POST,
                                    (whServerDmaFlags){0});
                            }
                        }
                        if (ret != WH_ERROR_OK) {
                            (void)wh_Server_KeystoreEvictKey(ctx, keyId);
                        }
                    }
                    if (ret == WH_ERROR_OK) {
                        res.keyId   = wh_KeyId_TranslateToClient(keyId);
                        res.keySize = keySize;
                    }
                }
            }
            wc_MlKemKey_Free(key);
        }
    }

    if (ret == WH_ERROR_ACCESS) {
        res.dmaAddrStatus.badAddr = req.key;
    }

    (void)wh_MessageCrypto_TranslateMlKemKeyGenDmaResponse(
        magic, &res, (whMessageCrypto_MlKemKeyGenDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif
}

static int _HandleMlKemEncapsDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
#ifdef WOLFSSL_MLKEM_NO_ENCAPSULATE
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                   ret = WH_ERROR_OK;
    MlKemKey                              key[1];
    void*                                 ctAddr = NULL;
    word32                                ctLen = 0;
    word32                                ssLen = 0;
    whKeyId                               key_id;
    int                                   evict = 0;
    int                                   keyInited = 0;
    uint8_t*                              res_ss;
    word32                                max_ss;
    whMessageCrypto_MlKemEncapsDmaRequest req;
    whMessageCrypto_MlKemEncapsDmaResponse res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(whMessageCrypto_MlKemEncapsDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateMlKemEncapsDmaRequest(
        magic, (whMessageCrypto_MlKemEncapsDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                          ctx->comm->client_id, req.keyId);
    evict  = !!(req.options & WH_MESSAGE_CRYPTO_MLKEM_ENCAPS_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    if (!_IsMlKemLevelSupported((int)req.level)) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }

    ret = wc_MlKemKey_Init(key, (int)req.level, NULL, devId);
    if (ret == WH_ERROR_OK) {
        keyInited = 1;
        ret = wh_Server_MlKemKeyCacheExport(ctx, key_id, key);
    }

    /* Verify the exported key matches the requested level */
    if (ret == WH_ERROR_OK && key->type != (int)req.level) {
        ret = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_CipherTextSize(key, &ctLen);
    }
    if (ret == WH_ERROR_OK && ctLen > req.ct.sz) {
        ret = WH_ERROR_BADARGS;
        goto cleanup_key;
    }
    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_SharedSecretSize(key, &ssLen);
    }

    /* Validate that the inline shared secret fits in the comm buffer */
    if (ret == WH_ERROR_OK) {
        res_ss = (uint8_t*)cryptoDataOut +
                 sizeof(whMessageCrypto_MlKemEncapsDmaResponse);
        max_ss = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
            ((uint8_t*)res_ss - (uint8_t*)cryptoDataOut));
        if (ssLen > max_ss) {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.ct.addr, &ctAddr, ctLen,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.ct;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Shared secret goes inline in response, not via DMA */
        res_ss = (uint8_t*)cryptoDataOut +
                 sizeof(whMessageCrypto_MlKemEncapsDmaResponse);
        ret = wc_MlKemKey_Encapsulate(key, (byte*)ctAddr, res_ss,
                                      ctx->crypto->rng);
        if (ret != WH_ERROR_OK) {
            /* Zero sensitive data on failure */
            wc_ForceZero(res_ss, ssLen);
        }
    }

    if (ctAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.ct.addr, &ctAddr, ctLen,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
    }

    if (ret == WH_ERROR_OK) {
        res.ctLen = ctLen;
        res.ssLen = ssLen;
    }

cleanup_key:
    if (keyInited) {
        wc_MlKemKey_Free(key);
    }
cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }

    (void)wh_MessageCrypto_TranslateMlKemEncapsDmaResponse(
        magic, &res, (whMessageCrypto_MlKemEncapsDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res) + ssLen;
    return ret;
#endif
}

static int _HandleMlKemDecapsDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
#ifdef WOLFSSL_MLKEM_NO_DECAPSULATE
    (void)ctx;
    (void)magic;
    (void)devId;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                   ret = WH_ERROR_OK;
    MlKemKey                              key[1];
    void*                                 ctAddr = NULL;
    word32                                ssLen = 0;
    whKeyId                               key_id;
    int                                   evict = 0;
    int                                   keyInited = 0;
    uint8_t*                              res_ss;
    word32                                max_ss;
    whMessageCrypto_MlKemDecapsDmaRequest req;
    whMessageCrypto_MlKemDecapsDmaResponse res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(whMessageCrypto_MlKemDecapsDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateMlKemDecapsDmaRequest(
        magic, (whMessageCrypto_MlKemDecapsDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    key_id = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                          ctx->comm->client_id, req.keyId);
    evict  = !!(req.options & WH_MESSAGE_CRYPTO_MLKEM_DECAPS_OPTIONS_EVICT);

    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreFindEnforceKeyUsage(ctx, key_id,
                                                    WH_NVM_FLAGS_USAGE_DERIVE);
        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    if (!_IsMlKemLevelSupported((int)req.level)) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }

    ret = wc_MlKemKey_Init(key, (int)req.level, NULL, devId);
    if (ret == WH_ERROR_OK) {
        keyInited = 1;
        ret = wh_Server_MlKemKeyCacheExport(ctx, key_id, key);
    }

    /* Verify the exported key matches the requested level */
    if (ret == WH_ERROR_OK && key->type != (int)req.level) {
        ret = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_MlKemKey_SharedSecretSize(key, &ssLen);
    }

    /* Validate that the inline shared secret fits in the comm buffer */
    if (ret == WH_ERROR_OK) {
        res_ss = (uint8_t*)cryptoDataOut +
                 sizeof(whMessageCrypto_MlKemDecapsDmaResponse);
        max_ss = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
            ((uint8_t*)res_ss - (uint8_t*)cryptoDataOut));
        if (ssLen > max_ss) {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.ct.addr, &ctAddr, req.ct.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.ct;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Shared secret goes inline in response, not via DMA */
        res_ss = (uint8_t*)cryptoDataOut +
                 sizeof(whMessageCrypto_MlKemDecapsDmaResponse);
        ret = wc_MlKemKey_Decapsulate(key, res_ss, (const byte*)ctAddr,
                                      (word32)req.ct.sz);
        if (ret != WH_ERROR_OK) {
            /* Zero sensitive data on failure */
            wc_ForceZero(res_ss, ssLen);
        }
    }

    if (ctAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.ct.addr, &ctAddr, req.ct.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (ret == WH_ERROR_OK) {
        res.ssLen = ssLen;
    }

    if (keyInited) {
        wc_MlKemKey_Free(key);
    }
cleanup:
    if (evict != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }

    (void)wh_MessageCrypto_TranslateMlKemDecapsDmaResponse(
        magic, &res, (whMessageCrypto_MlKemDecapsDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res) + ssLen;
    return ret;
#endif
}

static int _HandlePqcKemAlgorithmDma(whServerContext* ctx, uint16_t magic,
                                     int devId, const void* cryptoDataIn,
                                     uint16_t cryptoInSize, void* cryptoDataOut,
                                     uint16_t* cryptoOutSize,
                                     uint32_t pkAlgoType, uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    switch (pqAlgoType) {
        case WC_PQC_KEM_TYPE_KYBER: {
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_KEM_KEYGEN:
                    ret = _HandleMlKemKeyGenDma(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_KEM_ENCAPS:
                    ret = _HandleMlKemEncapsDma(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_KEM_DECAPS:
                    ret = _HandleMlKemDecapsDma(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
        } break;
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
/* Decode the slot blob's header lengths into the context struct. Sign-path
 * only, so it is gated out of verify-only builds. */
#if (defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)) ||      \
    (defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY))
static int _StatefulSigFromSlot(whServerStatefulSigCtx* b,
                                   whServerContext*           server,
                                   whKeyId                    keyId,
                                   uint8_t* slotBuf, whNvmMetadata* meta,
                                   uint16_t slotCapacity)
{
    whCryptoStatefulSigHeader hdr;

    if ((b == NULL) || (server == NULL) || (slotBuf == NULL) || (meta == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(&hdr, slotBuf, sizeof(hdr));

    b->server       = server;
    b->keyId        = keyId;
    b->meta         = meta;
    b->slotBuf      = slotBuf;
    b->hdrSz        = WH_CRYPTO_STATEFUL_SIG_HEADER_SZ;
    b->paramLen     = hdr.paramLen;
    b->pubLen       = hdr.pubLen;
    b->slotCapacity = slotCapacity;
    return WH_ERROR_OK;
}
#endif /* stateful sign path enabled */

/* Keygen persistence context for XMSS. wolfCrypt zeroizes key->sk right after
 * the keygen write callback returns, so the callback is the only point where
 * the private key is live. The callback copies the private key it is handed
 * into the private-key region of the handler-owned cache buffer; the handler
 * then fills in the public portion and commits to NVM. The cb can only return
 * wolfCrypt's coarse pass/fail code, so status carries the WH_ERROR_* detail
 * back to the handler. LMS does not use this: its private state survives
 * MakeKey, so its handler serializes directly. */
typedef struct whServerStatefulSigKeygenCtx {
    uint8_t* slotBuf;       /* handler-owned cache slot buffer */
    uint16_t slotCapacity;
    uint16_t privOff;       /* offset of the private-key region in slotBuf */
    uint16_t privLen;       /* out: private key length the cb received */
    int      status;        /* WH_ERROR_* from the cb */
} whServerStatefulSigKeygenCtx;
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */

#ifdef WOLFSSL_HAVE_LMS
#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Capture the private key from wc_LmsKey_MakeKey to mirror the XMSS path.
 * For LMS, additional private state resides in key->priv_raw, so that is
 * serialized after the call to wc_LmsKey_MakeKey. */
static int _LmsKeygenWriteCb(const byte* priv, word32 privSz, void* context)
{
    whServerStatefulSigKeygenCtx* b =
        (whServerStatefulSigKeygenCtx*)context;

    if ((b == NULL) || (priv == NULL) || (b->slotBuf == NULL)) {
        return WC_LMS_RC_BAD_ARG;
    }

    /* Copy the private key wolfCrypt handed us into the slot's priv region. */
    if ((uint32_t)b->privOff + privSz > b->slotCapacity) {
        b->status = WH_ERROR_BUFFER_SIZE;
        return WC_LMS_RC_WRITE_FAIL;
    }
    memcpy(b->slotBuf + b->privOff, priv, privSz);
    b->privLen = (uint16_t)privSz;
    b->status  = WH_ERROR_OK;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}
static int _LmsDummyReadCb(byte* priv, word32 privSz, void* context)
{
    (void)priv; (void)privSz; (void)context;
    return WC_LMS_RC_READ_TO_MEMORY;
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

static int _HandleLmsKeyGenDma(whServerContext* ctx, uint16_t magic, int devId,
                               const void* cryptoDataIn, uint16_t inSize,
                               void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_LMS_VERIFY_ONLY
    (void)ctx; (void)magic; (void)devId; (void)cryptoDataIn; (void)inSize;
    (void)cryptoDataOut; (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                              ret;
    LmsKey                                           key[1];
    void*                                            clientPubAddr = NULL;
    word32                                           pubLen32 = 0;
    whKeyId                                          keyId;
    int                                              locked = 0;
    uint8_t*                                         cacheBuf;
    whNvmMetadata*                                   cacheMeta;
    uint16_t   slotCapacity = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    uint16_t   blobSize;
    whServerStatefulSigKeygenCtx                     sigCtx;
    whMessageCrypto_PqcStatefulSigKeyGenDmaRequest   req;
    whMessageCrypto_PqcStatefulSigKeyGenDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslatePqcStatefulSigKeyGenDmaRequest(
        magic, (whMessageCrypto_PqcStatefulSigKeyGenDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Reject EPHEMERAL keys since keygen itself is stateful */
    if ((req.flags & WH_NVM_FLAGS_EPHEMERAL) != 0) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_LmsKey_SetParameters(key, (int)req.lmsLevels, (int)req.lmsHeight,
                                  (int)req.lmsWinternitz);

    /* Validate the buffer size and resolve the keyId before keygen. */
    if (ret == 0) {
        ret = wc_LmsKey_GetPubLen(key, &pubLen32);
    }
    if (ret == 0 && req.pub.sz < pubLen32) {
        ret = WH_ERROR_BUFFER_SIZE;
    }
    if (ret == 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.pub.addr, &clientPubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != 0) {
            res.dmaAddrStatus.badAddr = req.pub;
        }
    }
    /* Reject labels that won't fit the slot metadata. */
    if (ret == 0 && req.labelSize > sizeof(cacheMeta->label)) {
        ret = WH_ERROR_BADARGS;
    }
    /* Lock from keyID allocation until the slot is committed to NVM. */
    if (ret == 0) {
        ret    = WH_SERVER_NVM_LOCK(ctx);
        locked = (ret == WH_ERROR_OK);
    }
    if (ret == 0) {
        keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             ctx->comm->client_id, req.keyId);
        if (WH_KEYID_ISERASED(keyId)) {
            ret = wh_Server_KeystoreGetUniqueId(ctx, &keyId);
        }
    }

    /* Grab the cache slot up front; the keygen write cb captures priv into it. */
    if (ret == 0) {
        ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, slotCapacity,
                                                    &cacheBuf, &cacheMeta);
    }

    /* The write cb copies the private key into the slot's priv region: after
     * the header, the 3-byte parameter descriptor, and the public key. */
    if (ret == 0) {
        sigCtx.slotBuf      = cacheBuf;
        sigCtx.slotCapacity = slotCapacity;
        sigCtx.privOff      = (uint16_t)(WH_CRYPTO_STATEFUL_SIG_HEADER_SZ + 3 +
                                         pubLen32);
        sigCtx.status       = WH_ERROR_OK;
        ret = wc_LmsKey_SetWriteCb(key, _LmsKeygenWriteCb);
    }
    if (ret == 0) {
        ret = wc_LmsKey_SetReadCb(key, _LmsDummyReadCb);
    }
    if (ret == 0) {
        ret = wc_LmsKey_SetContext(key, &sigCtx);
    }
    if (ret == 0) {
        ret = wc_LmsKey_MakeKey(key, ctx->crypto->rng);
        /* MakeKey fails if the cb could not store priv; surface that error. */
        if ((ret != 0) && (sigCtx.status != WH_ERROR_OK)) {
            ret = sigCtx.status;
        }
    }

    /* Priv state survives in key->priv_raw, so serialize the full slot. */
    if (ret == 0) {
        ret = wh_Crypto_LmsSerializeKey(key, slotCapacity, cacheBuf, &blobSize);
    }
    if (ret == 0) {
        cacheMeta->id  = keyId;
        cacheMeta->len = blobSize;
        /* Stateful private key state must never leave the HSM; reuse of a
         * one-time signature index breaks the scheme. Force non-exportable.
         * Strip server-only flags a client may never set (e.g. trusted KEK). */
        cacheMeta->flags = (req.flags & ~WH_NVM_FLAGS_SERVER_ONLY) |
                           WH_NVM_FLAGS_NONEXPORTABLE;
        cacheMeta->access = WH_NVM_ACCESS_ANY;
        if (req.labelSize > 0) {
            memcpy(cacheMeta->label, req.label, req.labelSize);
        }
        ret = wh_Server_KeystoreCommitKey(ctx, keyId);
    }

    if (locked) {
        (void)WH_SERVER_NVM_UNLOCK(ctx);
        locked = 0;
    }

    /* Key is committed. Stream the public key out via the pre-validated DMA
     * buffer; the copy cannot fail, so the client always receives its keyId. */
    if (ret == 0) {
        memcpy(clientPubAddr, key->pub, pubLen32);
        res.keyId   = wh_KeyId_TranslateToClient(keyId);
        res.pubSize = pubLen32;
    }
    if (clientPubAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.pub.addr, &clientPubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
    }

    wc_LmsKey_Free(key);

    (void)wh_MessageCrypto_TranslatePqcStatefulSigKeyGenDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigKeyGenDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif /* WOLFSSL_LMS_VERIFY_ONLY */
}

static int _HandleLmsSignDma(whServerContext* ctx, uint16_t magic, int devId,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_LMS_VERIFY_ONLY
    (void)ctx; (void)magic; (void)devId; (void)cryptoDataIn; (void)inSize;
    (void)cryptoDataOut; (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                            ret;
    LmsKey                                         key[1];
    int                                            keyInited = 0;
    void*                                          msgAddr = NULL;
    void*                                          sigAddr = NULL;
    word32                                         sigLen;
    whKeyId                                        keyId;
    uint8_t*                                       cacheBuf;
    whNvmMetadata*                                 cacheMeta;
    whServerStatefulSigCtx                         sigCtx;
    whMessageCrypto_PqcStatefulSigSignDmaRequest   req;
    whMessageCrypto_PqcStatefulSigSignDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigSignDmaRequest(
        magic, (whMessageCrypto_PqcStatefulSigSignDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                         ctx->comm->client_id, req.keyId);
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    sigLen = (word32)req.sig.sz;

    /* Hold the NVM lock for the entire load -> sign -> commit sequence so
     * concurrent sign requests on the same keyId can't race past each other.
     * Pattern from wh_server_counter.c. */
    ret = WH_SERVER_NVM_LOCK(ctx);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wc_LmsKey_Init(key, NULL, devId);
        if (ret == 0) {
            keyInited = 1;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_LmsDeserializeKey(cacheBuf, (uint16_t)cacheMeta->len,
                                          key);
    }
    if (ret == WH_ERROR_OK) {
        ret = _StatefulSigFromSlot(
            &sigCtx, ctx, keyId, cacheBuf, cacheMeta,
            WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE);
    }
    if (ret == WH_ERROR_OK) {
        (void)wc_LmsKey_SetWriteCb(key, _LmsSlotWriteCb);
        (void)wc_LmsKey_SetReadCb(key, _LmsSlotReadCb);
        (void)wc_LmsKey_SetContext(key, &sigCtx);
        ret = wc_LmsKey_Reload(key);
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.msg;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.sig;
        }
    }
    if (ret == WH_ERROR_OK) {
        /* wolfCrypt's flow:
         *   1. wc_hss_sign computes the signature into sig and advances
         *      key->priv_raw in memory.
         *   2. write_private_key (our slot write cb) is called with the new
         *      priv_raw and atomically commits it to NVM.
         *   3. If the cb returns anything other than
         *      WC_LMS_RC_SAVED_TO_NV_MEMORY, wolfCrypt does ForceZero(sig)
         *      and returns IO_FAILED_E.
         * Net effect: a signature is exposed to the caller only if the NVM
         * commit succeeded. A process crash anywhere in the sequence either
         * (a) leaves the old state in NVM with no signature exposed, or
         * (b) commits the new state with the signature lost in transit -
         * one wasted index but never an index reused with a fresh sig. */
        ret = wc_LmsKey_Sign(key, sigAddr, &sigLen, msgAddr, (int)req.msg.sz);
        if (ret == 0) {
            res.sigLen = sigLen;
        }
    }
    if (sigAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, sigLen,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
    }
    if (msgAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (keyInited) {
        wc_LmsKey_Free(key);
    }

    if ((req.options & WH_MESSAGE_CRYPTO_STATEFUL_SIG_OPTIONS_EVICT) != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, keyId);
    }

    (void)WH_SERVER_NVM_UNLOCK(ctx);

    (void)wh_MessageCrypto_TranslatePqcStatefulSigSignDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigSignDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif /* WOLFSSL_LMS_VERIFY_ONLY */
}

static int _HandleLmsVerifyDma(whServerContext* ctx, uint16_t magic, int devId,
                               const void* cryptoDataIn, uint16_t inSize,
                               void* cryptoDataOut, uint16_t* outSize)
{
    int                                              ret;
    LmsKey                                           key[1];
    int                                              keyInited = 0;
    void*                                            sigAddr = NULL;
    void*                                            msgAddr = NULL;
    whKeyId                                          keyId;
    whMessageCrypto_PqcStatefulSigVerifyDmaRequest   req;
    whMessageCrypto_PqcStatefulSigVerifyDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigVerifyDmaRequest(
        magic, (whMessageCrypto_PqcStatefulSigVerifyDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                         ctx->comm->client_id, req.keyId);
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret == 0) {
        keyInited = 1;
        /* Lock while reading the key in case of concurrent sign op */
        ret = WH_SERVER_NVM_LOCK(ctx);
        if (ret == WH_ERROR_OK) {
            ret = wh_Server_LmsKeyCacheExport(ctx, keyId, key);
            (void)WH_SERVER_NVM_UNLOCK(ctx);
        }
    }
    if (ret == WH_ERROR_OK) {
        /* Deserialize leaves the key in PARMSET; wc_LmsKey_Verify needs
         * OK or VERIFYONLY. Pub is populated and that's all verify uses. */
        key->state = WC_LMS_STATE_VERIFYONLY;
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.sig;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.msg;
        }
    }
    if (ret == WH_ERROR_OK) {
        int verifyRet = wc_LmsKey_Verify(key, sigAddr, (word32)req.sig.sz,
                                         msgAddr, (int)req.msg.sz);
        if (verifyRet == 0) {
            res.res = 1;
        }
        else if (verifyRet == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            res.res = 0;
        }
        else {
            ret = verifyRet;
        }
    }

    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});

    if (keyInited) {
        wc_LmsKey_Free(key);
    }

    if ((req.options & WH_MESSAGE_CRYPTO_STATEFUL_SIG_OPTIONS_EVICT) != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, keyId);
    }

    (void)wh_MessageCrypto_TranslatePqcStatefulSigVerifyDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigVerifyDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
}

/* wc_LmsKey_SigsLeft reads key->priv_raw directly - no key state machine and no
 * read callback - so deserializing the cached blob into the key is enough; no
 * Reload is needed. Contrast the heavier _HandleXmssSigsLeftDma. */
static int _HandleLmsSigsLeftDma(whServerContext* ctx, uint16_t magic,
                                 int devId, const void* cryptoDataIn,
                                 uint16_t inSize, void* cryptoDataOut,
                                 uint16_t* outSize)
{
#ifdef WOLFSSL_LMS_VERIFY_ONLY
    (void)ctx; (void)magic; (void)devId; (void)cryptoDataIn; (void)inSize;
    (void)cryptoDataOut; (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                                ret;
    LmsKey                                             key[1];
    int                                                keyInited = 0;
    whKeyId                                            keyId;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest   req;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigSigsLeftDmaRequest(
        magic,
        (whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                         ctx->comm->client_id, req.keyId);
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret == 0) {
        keyInited = 1;
        /* Lock while reading the key in case of concurrent sign op */
        ret = WH_SERVER_NVM_LOCK(ctx);
        if (ret == WH_ERROR_OK) {
            ret = wh_Server_LmsKeyCacheExport(ctx, keyId, key);
            (void)WH_SERVER_NVM_UNLOCK(ctx);
        }
    }
    if (ret == WH_ERROR_OK) {
        res.sigsLeft = (uint32_t)wc_LmsKey_SigsLeft(key);
    }

    if (keyInited) {
        wc_LmsKey_Free(key);
    }

    (void)wh_MessageCrypto_TranslatePqcStatefulSigSigsLeftDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif /* WOLFSSL_LMS_VERIFY_ONLY */
}
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
#ifndef WOLFSSL_XMSS_VERIFY_ONLY
/* Keygen write cb: wc_XmssKey_MakeKey hands us the private key, which it
 * zeroizes immediately after. Copy it into the slot's priv region and capture
 * any error into the context for the caller of MakeKey to surface. */
static enum wc_XmssRc _XmssKeygenWriteCb(const byte* priv, word32 privSz,
                                         void* context)
{
    whServerStatefulSigKeygenCtx* b =
        (whServerStatefulSigKeygenCtx*)context;

    if ((b == NULL) || (priv == NULL) || (b->slotBuf == NULL)) {
        return WC_XMSS_RC_BAD_ARG;
    }

    /* Copy the private key wolfCrypt handed us into the slot's priv region;
     * the key object is zeroized once this returns, so use priv/privSz here. */
    if ((uint32_t)b->privOff + privSz > b->slotCapacity) {
        b->status = WH_ERROR_BUFFER_SIZE;
        return WC_XMSS_RC_WRITE_FAIL;
    }
    memcpy(b->slotBuf + b->privOff, priv, privSz);
    b->privLen = (uint16_t)privSz;
    b->status  = WH_ERROR_OK;
    return WC_XMSS_RC_SAVED_TO_NV_MEMORY;
}
static enum wc_XmssRc _XmssDummyReadCb(byte* priv, word32 privSz,
                                       void* context)
{
    (void)priv; (void)privSz; (void)context;
    return WC_XMSS_RC_READ_TO_MEMORY;
}
#endif /* !WOLFSSL_XMSS_VERIFY_ONLY */

static int _HandleXmssKeyGenDma(whServerContext* ctx, uint16_t magic,
                                int devId, const void* cryptoDataIn,
                                uint16_t inSize, void* cryptoDataOut,
                                uint16_t* outSize)
{
#ifdef WOLFSSL_XMSS_VERIFY_ONLY
    (void)ctx; (void)magic; (void)devId; (void)cryptoDataIn; (void)inSize;
    (void)cryptoDataOut; (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                              ret;
    XmssKey                                          key[1];
    void*                                            clientPubAddr = NULL;
    word32                                           pubLen32 = 0;
    whKeyId                                          keyId;
    int                                              locked = 0;
    uint8_t*                                         cacheBuf;
    whNvmMetadata*                                   cacheMeta;
    uint16_t   slotCapacity = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    uint16_t   blobSize;
    whServerStatefulSigKeygenCtx                     sigCtx;
    whMessageCrypto_PqcStatefulSigKeyGenDmaRequest   req;
    whMessageCrypto_PqcStatefulSigKeyGenDmaResponse  res;

    memset(&res, 0, sizeof(res));
    memset(&sigCtx, 0, sizeof(sigCtx));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigKeyGenDmaRequest(
        magic, (whMessageCrypto_PqcStatefulSigKeyGenDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Reject EPHEMERAL keys since keygen itself is stateful */
    if ((req.flags & WH_NVM_FLAGS_EPHEMERAL) != 0) {
        return WH_ERROR_BADARGS;
    }

    /* xmssParamStr arrives via the request struct (populated by the client in
     * wh_Client_XmssMakeKeyDma). Defensively enforce NUL-termination before
     * passing it to wolfCrypt, since it originates from the client. */
    req.xmssParamStr[sizeof(req.xmssParamStr) - 1] = '\0';

    ret = wc_XmssKey_Init(key, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_XmssKey_SetParamStr(key, req.xmssParamStr);

    /* Validate the buffer size and resolve the keyId before keygen. */
    if (ret == 0) {
        ret = wc_XmssKey_GetPubLen(key, &pubLen32);
    }
    if (ret == 0 && req.pub.sz < pubLen32) {
        ret = WH_ERROR_BUFFER_SIZE;
    }
    if (ret == 0) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.pub.addr, &clientPubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != 0) {
            res.dmaAddrStatus.badAddr = req.pub;
        }
    }
    /* Reject labels that won't fit the slot metadata. */
    if (ret == 0 && req.labelSize > sizeof(cacheMeta->label)) {
        ret = WH_ERROR_BADARGS;
    }
    /* Lock from keyID allocation until the slot is committed to NVM. */
    if (ret == 0) {
        ret    = WH_SERVER_NVM_LOCK(ctx);
        locked = (ret == WH_ERROR_OK);
    }
    if (ret == 0) {
        keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             ctx->comm->client_id, req.keyId);
        if (WH_KEYID_ISERASED(keyId)) {
            ret = wh_Server_KeystoreGetUniqueId(ctx, &keyId);
        }
    }
    /* Grab the cache slot up front; the write cb writes priv into it. */
    if (ret == 0) {
        ret = wh_Server_KeystoreGetCacheSlotChecked(ctx, keyId, slotCapacity,
                                                    &cacheBuf, &cacheMeta);
    }

    /* The write cb copies the private key into the slot's priv region (key->sk
     * is valid only during that callback). Tell it where that region begins:
     * after the header, parameter string, and public key. */
    if (ret == 0) {
        size_t pStrLen = strlen(req.xmssParamStr);
        if (pStrLen >= 0xFFFFu) {
            ret = WH_ERROR_BADARGS;
        }
        else {
            sigCtx.slotBuf      = cacheBuf;
            sigCtx.slotCapacity = slotCapacity;
            sigCtx.privOff      = (uint16_t)(WH_CRYPTO_STATEFUL_SIG_HEADER_SZ +
                                             (pStrLen + 1) + pubLen32);
            sigCtx.status       = WH_ERROR_OK;
            ret = wc_XmssKey_SetWriteCb(key, _XmssKeygenWriteCb);
        }
    }
    if (ret == 0) {
        ret = wc_XmssKey_SetReadCb(key, _XmssDummyReadCb);
    }
    if (ret == 0) {
        ret = wc_XmssKey_SetContext(key, &sigCtx);
    }
    if (ret == 0) {
        ret = wc_XmssKey_MakeKey(key, ctx->crypto->rng);
        /* MakeKey fails if the cb could not store priv; surface that error. */
        if ((ret != 0) && (sigCtx.status != WH_ERROR_OK)) {
            ret = sigCtx.status;
        }
    }

    /* Priv is in the slot; fill in the header and public key, then commit. */
    if (ret == 0) {
        ret = wh_Crypto_XmssSerializeKeyNoPriv(key, req.xmssParamStr,
                                               sigCtx.privLen, slotCapacity,
                                               cacheBuf, &blobSize);
    }
    if (ret == 0) {
        cacheMeta->id  = keyId;
        cacheMeta->len = blobSize;
        /* Stateful private key state must never leave the HSM; reuse of a
         * one-time signature index breaks the scheme. Force non-exportable.
         * Strip server-only flags a client may never set (e.g. trusted KEK). */
        cacheMeta->flags = (req.flags & ~WH_NVM_FLAGS_SERVER_ONLY) |
                           WH_NVM_FLAGS_NONEXPORTABLE;
        cacheMeta->access = WH_NVM_ACCESS_ANY;
        if (req.labelSize > 0) {
            memcpy(cacheMeta->label, req.label, req.labelSize);
        }
        ret = wh_Server_KeystoreCommitKey(ctx, keyId);
    }

    if (locked) {
        (void)WH_SERVER_NVM_UNLOCK(ctx);
        locked = 0;
    }

    /* Key is committed. Stream the public key out via the pre-validated DMA
     * buffer; the copy cannot fail, so the client always receives its keyId. */
    if (ret == 0) {
        memcpy(clientPubAddr, key->pk, pubLen32);
        res.keyId   = wh_KeyId_TranslateToClient(keyId);
        res.pubSize = pubLen32;
    }
    if (clientPubAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.pub.addr, &clientPubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
    }

    wc_XmssKey_Free(key);

    (void)wh_MessageCrypto_TranslatePqcStatefulSigKeyGenDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigKeyGenDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif /* WOLFSSL_XMSS_VERIFY_ONLY */
}

static int _HandleXmssSignDma(whServerContext* ctx, uint16_t magic, int devId,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_XMSS_VERIFY_ONLY
    (void)ctx; (void)magic; (void)devId; (void)cryptoDataIn; (void)inSize;
    (void)cryptoDataOut; (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                            ret;
    XmssKey                                        key[1];
    int                                            keyInited = 0;
    void*                                          msgAddr = NULL;
    void*                                          sigAddr = NULL;
    word32                                         sigLen;
    whKeyId                                        keyId;
    uint8_t*                                       cacheBuf;
    whNvmMetadata*                                 cacheMeta;
    whServerStatefulSigCtx                         sigCtx;
    whMessageCrypto_PqcStatefulSigSignDmaRequest   req;
    whMessageCrypto_PqcStatefulSigSignDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigSignDmaRequest(
        magic, (whMessageCrypto_PqcStatefulSigSignDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                         ctx->comm->client_id, req.keyId);
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    sigLen = (word32)req.sig.sz;

    /* See _HandleLmsSignDma for the NVM-lock rationale. */
    ret = WH_SERVER_NVM_LOCK(ctx);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wc_XmssKey_Init(key, NULL, devId);
        if (ret == 0) {
            keyInited = 1;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_XmssDeserializeKey(cacheBuf, (uint16_t)cacheMeta->len,
                                           key);
    }
    if (ret == WH_ERROR_OK) {
        ret = _StatefulSigFromSlot(
            &sigCtx, ctx, keyId, cacheBuf, cacheMeta,
            WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE);
    }
    if (ret == WH_ERROR_OK) {
        (void)wc_XmssKey_SetWriteCb(key, _XmssSlotWriteCb);
        (void)wc_XmssKey_SetReadCb(key, _XmssSlotReadCb);
        (void)wc_XmssKey_SetContext(key, &sigCtx);
        ret = wc_XmssKey_Reload(key);
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.msg;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.sig;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wc_XmssKey_Sign(key, sigAddr, &sigLen, msgAddr, (int)req.msg.sz);
        if (ret == 0) {
            res.sigLen = sigLen;
        }
    }

    if (sigAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, sigLen,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
    }
    if (msgAddr != NULL) {
        (void)wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }

    if (keyInited) {
        wc_XmssKey_Free(key);
    }

    if ((req.options & WH_MESSAGE_CRYPTO_STATEFUL_SIG_OPTIONS_EVICT) != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, keyId);
    }

    (void)WH_SERVER_NVM_UNLOCK(ctx);

    (void)wh_MessageCrypto_TranslatePqcStatefulSigSignDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigSignDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif /* WOLFSSL_XMSS_VERIFY_ONLY */
}

static int _HandleXmssVerifyDma(whServerContext* ctx, uint16_t magic,
                                int devId, const void* cryptoDataIn,
                                uint16_t inSize, void* cryptoDataOut,
                                uint16_t* outSize)
{
    int                                              ret;
    XmssKey                                          key[1];
    int                                              keyInited = 0;
    void*                                            sigAddr = NULL;
    void*                                            msgAddr = NULL;
    whKeyId                                          keyId;
    whMessageCrypto_PqcStatefulSigVerifyDmaRequest   req;
    whMessageCrypto_PqcStatefulSigVerifyDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigVerifyDmaRequest(
        magic, (whMessageCrypto_PqcStatefulSigVerifyDmaRequest*)cryptoDataIn,
        &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                         ctx->comm->client_id, req.keyId);
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_XmssKey_Init(key, NULL, devId);
    if (ret == 0) {
        keyInited = 1;
        /* Lock while reading the key in case of concurrent sign op */
        ret = WH_SERVER_NVM_LOCK(ctx);
        if (ret == WH_ERROR_OK) {
            ret = wh_Server_XmssKeyCacheExport(ctx, keyId, key);
            (void)WH_SERVER_NVM_UNLOCK(ctx);
        }
    }
    if (ret == WH_ERROR_OK) {
        /* Deserialize leaves the key in PARMSET; wc_XmssKey_Verify needs
         * OK or VERIFYONLY. Pub is populated and that's all verify uses. */
        key->state = WC_XMSS_STATE_VERIFYONLY;
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.sig;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.msg;
        }
    }
    if (ret == WH_ERROR_OK) {
        int verifyRet = wc_XmssKey_Verify(key, sigAddr, (word32)req.sig.sz,
                                          msgAddr, (int)req.msg.sz);
        if (verifyRet == 0) {
            res.res = 1;
        }
        else if (verifyRet == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            res.res = 0;
        }
        else {
            ret = verifyRet;
        }
    }

    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    (void)wh_Server_DmaProcessClientAddress(
        ctx, (uintptr_t)req.msg.addr, &msgAddr, req.msg.sz,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});

    if (keyInited) {
        wc_XmssKey_Free(key);
    }

    if ((req.options & WH_MESSAGE_CRYPTO_STATEFUL_SIG_OPTIONS_EVICT) != 0) {
        (void)wh_Server_KeystoreEvictKey(ctx, keyId);
    }

    (void)wh_MessageCrypto_TranslatePqcStatefulSigVerifyDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigVerifyDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
}

static int _HandleXmssSigsLeftDma(whServerContext* ctx, uint16_t magic,
                                  int devId, const void* cryptoDataIn,
                                  uint16_t inSize, void* cryptoDataOut,
                                  uint16_t* outSize)
{
#ifdef WOLFSSL_XMSS_VERIFY_ONLY
    (void)ctx; (void)magic; (void)devId; (void)cryptoDataIn; (void)inSize;
    (void)cryptoDataOut; (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    int                                                ret;
    XmssKey                                            key[1];
    int                                                keyInited = 0;
    whKeyId                                            keyId;
    uint8_t*                                           cacheBuf;
    whNvmMetadata*                                     cacheMeta;
    whServerStatefulSigCtx                             sigCtx;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest   req;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse  res;

    memset(&res, 0, sizeof(res));

    if (inSize < sizeof(req)) {
        return WH_ERROR_BADARGS;
    }
    ret = wh_MessageCrypto_TranslatePqcStatefulSigSigsLeftDmaRequest(
        magic,
        (whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                         ctx->comm->client_id, req.keyId);
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    /* Lock during load+reload in case of concurrent sign op */
    ret = WH_SERVER_NVM_LOCK(ctx);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Server_KeystoreFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wc_XmssKey_Init(key, NULL, devId);
        if (ret == 0) {
            keyInited = 1;
        }
    }
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_XmssDeserializeKey(cacheBuf, (uint16_t)cacheMeta->len,
                                           key);
    }
    if (ret == WH_ERROR_OK) {
        ret = _StatefulSigFromSlot(
            &sigCtx, ctx, keyId, cacheBuf, cacheMeta,
            WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE);
    }
    if (ret == WH_ERROR_OK) {
        /* Reload uses the slot ReadCb to populate sk from the cached blob,
         * then transitions state to OK so SigsLeft can run. */
        (void)wc_XmssKey_SetWriteCb(key, _XmssSlotWriteCb);
        (void)wc_XmssKey_SetReadCb(key, _XmssSlotReadCb);
        (void)wc_XmssKey_SetContext(key, &sigCtx);
        ret = wc_XmssKey_Reload(key);
    }
    if (ret == WH_ERROR_OK) {
        res.sigsLeft = (uint32_t)wc_XmssKey_SigsLeft(key);
    }

    if (keyInited) {
        wc_XmssKey_Free(key);
    }

    (void)WH_SERVER_NVM_UNLOCK(ctx);

    (void)wh_MessageCrypto_TranslatePqcStatefulSigSigsLeftDmaResponse(
        magic, &res,
        (whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);
    return ret;
#endif /* WOLFSSL_XMSS_VERIFY_ONLY */
}
#endif /* WOLFSSL_HAVE_XMSS */

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
static int _HandlePqcStatefulSigAlgorithmDma(
    whServerContext* ctx, uint16_t magic, int devId, const void* cryptoDataIn,
    uint16_t cryptoInSize, void* cryptoDataOut, uint16_t* cryptoOutSize,
    uint32_t pkAlgoType, uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    switch (pqAlgoType) {
#ifdef WOLFSSL_HAVE_LMS
        case WC_PQC_STATEFUL_SIG_TYPE_LMS:
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN:
                    ret = _HandleLmsKeyGenDma(ctx, magic, devId, cryptoDataIn,
                                              cryptoInSize, cryptoDataOut,
                                              cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN:
                    ret = _HandleLmsSignDma(ctx, magic, devId, cryptoDataIn,
                                            cryptoInSize, cryptoDataOut,
                                            cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY:
                    ret = _HandleLmsVerifyDma(ctx, magic, devId, cryptoDataIn,
                                              cryptoInSize, cryptoDataOut,
                                              cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT:
                    ret = _HandleLmsSigsLeftDma(ctx, magic, devId,
                                                cryptoDataIn, cryptoInSize,
                                                cryptoDataOut, cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
            break;
#endif /* WOLFSSL_HAVE_LMS */
#ifdef WOLFSSL_HAVE_XMSS
        case WC_PQC_STATEFUL_SIG_TYPE_XMSS:
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN:
                    ret = _HandleXmssKeyGenDma(ctx, magic, devId, cryptoDataIn,
                                               cryptoInSize, cryptoDataOut,
                                               cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN:
                    ret = _HandleXmssSignDma(ctx, magic, devId, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY:
                    ret = _HandleXmssVerifyDma(ctx, magic, devId, cryptoDataIn,
                                               cryptoInSize, cryptoDataOut,
                                               cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT:
                    ret = _HandleXmssSigsLeftDma(ctx, magic, devId,
                                                 cryptoDataIn, cryptoInSize,
                                                 cryptoDataOut, cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
            break;
#endif /* WOLFSSL_HAVE_XMSS */
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
static int _HandleCmacDma(whServerContext* ctx, uint16_t magic, int devId,
                          uint16_t seq, const void* cryptoDataIn,
                          uint16_t inSize, void* cryptoDataOut,
                          uint16_t* outSize)
{
    (void)seq;

    int ret = 0;
    whMessageCrypto_CmacAesDmaRequest  req;
    whMessageCrypto_CmacAesDmaResponse res;

    if (inSize < sizeof(whMessageCrypto_CmacAesDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate request */
    ret = wh_MessageCrypto_TranslateCmacAesDmaRequest(
        magic, (whMessageCrypto_CmacAesDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Validate variable-length fields fit within inSize. Trailing layout:
     *   uint8_t in[inlineInSz]
     *   uint8_t key[keySz]
     */
    uint32_t available = inSize - sizeof(whMessageCrypto_CmacAesDmaRequest);
    if (req.inlineInSz > available) {
        return WH_ERROR_BADARGS;
    }
    available -= req.inlineInSz;
    if (req.keySz > available) {
        return WH_ERROR_BADARGS;
    }
    if (req.keySz > AES_256_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }

    word32 len;

    /* Pointers to inline trailing data */
    uint8_t* inlineIn =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_CmacAesDmaRequest);
    uint8_t* key = inlineIn + req.inlineInSz;
    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_CmacAesDmaResponse);

    memset(&res, 0, sizeof(res));

    /* DMA translated address for input */
    void* inAddr = NULL;

    uint8_t tmpKey[AES_256_KEY_SIZE];
    uint32_t tmpKeyLen = sizeof(tmpKey);
    Cmac    cmac[1];

    /* Oneshot fast path: DMA input only (no inline), output requested. The
     * streaming protocol never produces outSz>0 with DMA input (Final is
     * inline-only), so this branch is only taken by CmacGenerateDma. */
    if (req.inlineInSz == 0 && req.input.sz != 0 && req.outSz != 0) {
        len = req.outSz;

        /* Translate DMA address for input */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }

        /* Resolve key */
        if (ret == WH_ERROR_OK) {
            ret = _CmacResolveKey(ctx, key, req.keySz, req.keyId, tmpKey,
                                  &tmpKeyLen);
        }

        if (ret == WH_ERROR_OK && req.keySz != 0) {
            /* Client-supplied key - direct one-shot */
            WH_DEBUG_SERVER_VERBOSE("dma cmac generate oneshot\n");

            ret = wc_AesCmacGenerate_ex(cmac, out, &len, inAddr, req.input.sz,
                                        tmpKey, (word32)tmpKeyLen, NULL, devId);
        }
        else if (ret == WH_ERROR_OK) {
            /* HSM-local key via keyId - init then generate */
            WH_DEBUG_SERVER_VERBOSE("dma cmac generate oneshot with keyId:%x\n",
                                    req.keyId);

            ret = wc_InitCmac_ex(cmac, tmpKey, (word32)tmpKeyLen, WC_CMAC_AES,
                                 NULL, NULL, devId);

            if (ret == WH_ERROR_OK) {
                ret = wc_AesCmacGenerate_ex(cmac, out, &len, inAddr,
                                            req.input.sz, NULL, 0, NULL, devId);
            }
        }

        if (ret == 0) {
            res.outSz = len;
            res.keyId = WH_KEYID_ERASED;
        }
    }
    else {
        /* Streaming update/final with optional client-side assembled first
         * block (inline) plus DMA whole blocks. Final carries partial tail
         * inline only. */
        WH_DEBUG_SERVER_VERBOSE(
            "dma cmac begin keySz:%d inlineInSz:%d dmaInSz:%d outSz:%d "
            "keyId:%x\n",
            (int)req.keySz, (int)req.inlineInSz, (int)req.input.sz,
            (int)req.outSz, req.keyId);

        /* Resolve key */
        ret =
            _CmacResolveKey(ctx, key, req.keySz, req.keyId, tmpKey, &tmpKeyLen);

        /* Initialize CMAC context with key (re-derives k1/k2 subkeys) */
        if (ret == 0) {
            ret = wc_InitCmac_ex(cmac, tmpKey, (word32)tmpKeyLen, WC_CMAC_AES,
                                 NULL, NULL, devId);
            WH_DEBUG_SERVER_VERBOSE("dma cmac init with keylen:%d ret:%d\n",
                                    tmpKeyLen, ret);
        }

        /* Restore non-sensitive state from client */
        if (ret == 0) {
            ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &req.resumeState);
        }

        /* Feed inline input first (assembled first block on Update, or
         * partial tail on Final). */
        if (ret == 0 && req.inlineInSz != 0) {
            ret = wc_CmacUpdate(cmac, inlineIn, req.inlineInSz);
            WH_DEBUG_SERVER_VERBOSE("dma cmac inline update done. ret:%d\n",
                                    ret);
        }

        /* Feed DMA input (whole blocks on Update; never present on Final). */
        if (ret == 0 && req.input.sz != 0) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.input;
            }
            if (ret == WH_ERROR_OK) {
                ret = wc_CmacUpdate(cmac, inAddr, req.input.sz);
                WH_DEBUG_SERVER_VERBOSE("dma cmac dma update done. ret:%d\n",
                                        ret);
            }
        }

        if (ret == 0 && req.outSz != 0) {
            /* Finalize CMAC operation */
            len = req.outSz;
            WH_DEBUG_SERVER_VERBOSE("dma cmac final len:%d\n", len);
            ret       = wc_CmacFinal(cmac, out, &len);
            res.outSz = len;
            res.keyId = WH_KEYID_ERASED;
        }
        else if (ret == 0) {
            /* Not finalizing - return updated state to client */
            wh_Crypto_CmacAesSaveStateToMsg(&res.resumeState, cmac);
            res.keyId = req.keyId;
            res.outSz = 0;
        }
    }

    /* Clean up DMA input address */
    if (inAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
            WH_DEBUG_SERVER_VERBOSE("Error cleaning up input DMA address\n");
        }
    }

    if (ret == 0) {
        ret = wh_MessageCrypto_TranslateCmacAesDmaResponse(
            magic, &res, (whMessageCrypto_CmacAesDmaResponse*)cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res) + res.outSz;
        }
    }

    WH_DEBUG_SERVER_VERBOSE("dma cmac end ret:%d\n", ret);
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifndef WC_NO_RNG
static int _HandleRngDma(whServerContext* ctx, uint16_t magic, int devId,
                         uint16_t seq, const void* cryptoDataIn,
                         uint16_t inSize, void* cryptoDataOut,
                         uint16_t* outSize)
{
    (void)seq;
    (void)devId;

    int                            ret = 0;
    whMessageCrypto_RngDmaRequest  req;
    whMessageCrypto_RngDmaResponse res;
    void*                          outAddr = NULL;

    if (inSize < sizeof(whMessageCrypto_RngDmaRequest)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateRngDmaRequest(
        magic, (whMessageCrypto_RngDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Process the output address (PRE operation) */
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }

    /* Generate random bytes directly into client memory */
    if (ret == WH_ERROR_OK) {
        WH_DEBUG_SERVER_VERBOSE("RNG DMA: generating %llu bytes to addr=%p\n",
               (long long unsigned int)req.output.sz, outAddr);
        ret = wc_RNG_GenerateBlock(ctx->crypto->rng, outAddr, req.output.sz);
    }

    /* Process the output address (POST operation) */
    if (ret == WH_ERROR_OK) {
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }

    /* Translate the response */
    (void)wh_MessageCrypto_TranslateRngDmaResponse(
        magic, &res, (whMessageCrypto_RngDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    /* return value populates rc in response message */
    return ret;
}
#endif /* !WC_NO_RNG */
#endif /* WOLFHSM_CFG_DMA */

#ifdef WOLFHSM_CFG_DMA
int wh_Server_HandleCryptoDmaRequest(whServerContext* ctx, uint16_t magic,
                                     uint16_t action, uint16_t seq,
                                     uint16_t req_size, const void* req_packet,
                                     uint16_t* out_resp_size, void* resp_packet)
{
    int                                   ret        = 0;
    int                                   devId      = INVALID_DEVID;
    whMessageCrypto_GenericRequestHeader  rqstHeader = {0};
    whMessageCrypto_GenericResponseHeader respHeader = {0};

    const void* cryptoDataIn =
        (uint8_t*)req_packet + sizeof(whMessageCrypto_GenericRequestHeader);
    void* cryptoDataOut =
        (uint8_t*)resp_packet + sizeof(whMessageCrypto_GenericResponseHeader);

    /* Input and output sizes for data passed to crypto handlers. cryptoOutSize
     * should be set by the crypto handler as an output parameter */
    uint16_t cryptoInSize =
        req_size - sizeof(whMessageCrypto_GenericResponseHeader);
    uint16_t cryptoOutSize = 0;

    if ((ctx == NULL) || (ctx->crypto == NULL) || (req_packet == NULL) ||
        (resp_packet == NULL) || (out_resp_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Validate req_size to prevent integer underflow */
    if (req_size < sizeof(whMessageCrypto_GenericResponseHeader)) {
        return WH_ERROR_BADARGS;
    }

    /* Translate the request message to get the algo type */
    wh_MessageCrypto_TranslateGenericRequestHeader(
        magic, (whMessageCrypto_GenericRequestHeader*)req_packet, &rqstHeader);

#if defined(WOLFHSM_CFG_CRYPTO_AFFINITY)
    /* Compute devId from the per-message affinity field */
    devId = (rqstHeader.affinity == WH_CRYPTO_AFFINITY_HW &&
             ctx->devId != INVALID_DEVID)
                ? ctx->devId
                : INVALID_DEVID;
#else
    /* Crypto affinity disabled: always use the server's configured devId and
     * ignore the request header affinity field. */
    devId = ctx->devId;
#endif /* WOLFHSM_CFG_CRYPTO_AFFINITY */

    switch (action) {
        case WC_ALGO_TYPE_HASH:
            switch (rqstHeader.algoType) {
#ifndef NO_SHA256
                case WC_HASH_TYPE_SHA256:
                    ret = _HandleSha256Dma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("DMA SHA256 ret = %d\n", ret);
                    }
                    break;
#endif /* !NO_SHA256 */
#ifdef WOLFSSL_SHA224
                case WC_HASH_TYPE_SHA224:
                    ret = _HandleSha224Dma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("DMA SHA224 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA224 */
#ifdef WOLFSSL_SHA384
                case WC_HASH_TYPE_SHA384:
                    ret = _HandleSha384Dma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("DMA SHA384 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA384 */
#ifdef WOLFSSL_SHA512
                case WC_HASH_TYPE_SHA512:
                    ret = _HandleSha512Dma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("DMA SHA512 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA512 */
#if defined(WOLFSSL_SHA3)
                case WC_HASH_TYPE_SHA3_224:
                case WC_HASH_TYPE_SHA3_256:
                case WC_HASH_TYPE_SHA3_384:
                case WC_HASH_TYPE_SHA3_512:
                    ret = _HandleSha3Dma(ctx, rqstHeader.algoType, magic, devId,
                                         seq, cryptoDataIn, cryptoInSize,
                                         cryptoDataOut, &cryptoOutSize);
                    if (ret != 0) {
                        WH_DEBUG_SERVER("DMA SHA3 ret = %d\n", ret);
                    }
                    break;
#endif /* WOLFSSL_SHA3 */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break; /* WC_ALGO_TYPE_HASH */

        case WC_ALGO_TYPE_CIPHER:
            switch (rqstHeader.algoType) {
#ifdef HAVE_AESGCM
                case WC_CIPHER_AES_GCM:
                    ret = _HandleAesGcmDma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_COUNTER
                case WC_CIPHER_AES_CTR:
                    ret = _HandleAesCtrDma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_CBC
                case WC_CIPHER_AES_CBC:
                    ret = _HandleAesCbcDma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AES_ECB
                case WC_CIPHER_AES_ECB:
                    ret = _HandleAesEcbDma(ctx, magic, devId, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* HAVE_AES_ECB */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break; /* WC_ALGO_TYPE_CIPHER */

        case WC_ALGO_TYPE_PK:
            switch (rqstHeader.algoType) {
#if defined(WOLFSSL_HAVE_MLDSA) || defined(HAVE_FALCON)
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                case WC_PK_TYPE_PQC_SIG_SIGN:
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandlePqcSigAlgorithmDma(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize, rqstHeader.algoType,
                        rqstHeader.algoSubType);
                    break;
#endif /* WOLFSSL_HAVE_MLDSA || HAVE_FALCON */
#if defined(WOLFSSL_HAVE_MLKEM)
                case WC_PK_TYPE_PQC_KEM_KEYGEN:
                case WC_PK_TYPE_PQC_KEM_ENCAPS:
                case WC_PK_TYPE_PQC_KEM_DECAPS:
                    ret = _HandlePqcKemAlgorithmDma(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize, rqstHeader.algoType,
                        rqstHeader.algoSubType);
                    break;
#endif /* WOLFSSL_HAVE_MLKEM */
#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
                case WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN:
                case WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN:
                case WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY:
                case WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT:
                    ret = _HandlePqcStatefulSigAlgorithmDma(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize, rqstHeader.algoType,
                        rqstHeader.algoSubType);
                    break;
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */
#ifdef HAVE_ED25519
                case WC_PK_TYPE_ED25519_SIGN:
                    ret = _HandleEd25519SignDma(ctx, magic, devId, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                &cryptoOutSize);
                    break;
                case WC_PK_TYPE_ED25519_VERIFY:
                    ret = _HandleEd25519VerifyDma(
                        ctx, magic, devId, cryptoDataIn, cryptoInSize,
                        cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_ED25519 */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break; /* WC_ALGO_TYPE_PK */

#ifdef WOLFSSL_CMAC
        case WC_ALGO_TYPE_CMAC:
            ret = _HandleCmacDma(ctx, magic, devId, seq, cryptoDataIn,
                                 cryptoInSize, cryptoDataOut, &cryptoOutSize);
            break;
#endif /* WOLFSSL_CMAC */

#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_RNG:
            ret = _HandleRngDma(ctx, magic, devId, seq, cryptoDataIn,
                                cryptoInSize, cryptoDataOut, &cryptoOutSize);
            break;
#endif /* !WC_NO_RNG */

        case WC_ALGO_TYPE_NONE:
        default:
            ret = NOT_COMPILED_IN;
            break;
    }

    /* Propagate error code to client in response packet header. Crypto handlers
     * have already populated the response packet with the output data. */
    respHeader.rc       = ret;
    respHeader.algoType = rqstHeader.algoType;
    wh_MessageCrypto_TranslateGenericResponseHeader(
        magic, &respHeader,
        (whMessageCrypto_GenericResponseHeader*)resp_packet);

    /* Update the size of the response packet if crypto handler didn't fail */
    if (ret != WH_ERROR_OK) {
        *out_resp_size = sizeof(whMessageCrypto_GenericResponseHeader);
    }
    else {
        *out_resp_size =
            sizeof(whMessageCrypto_GenericResponseHeader) + cryptoOutSize;
    }


    WH_DEBUG_SERVER_VERBOSE("Crypto DMA request. Action:%u\n", action);

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_SERVER */
