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
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/kdf.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wolfhsm/wh_server.h"

#include "wolfhsm/wh_message_crypto.h"

/** Helper functions */
#ifdef WOLFHSM_CFG_CANCEL_API
/**
 * Check if the current operation should be canceled
 * @param ctx Server context
 * @param seq Sequence number to check against
 * @return WH_ERROR_CANCEL if canceled, 0 if not canceled, or error code
 */
static int _CheckCancellation(whServerContext* ctx, uint16_t seq)
{
    uint16_t cancelSeq;
    int      ret = wh_Server_GetCanceledSequence(ctx, &cancelSeq);
    if (ret == 0 && cancelSeq == seq) {
        return WH_ERROR_CANCEL;
    }
    return ret;
}
#endif

/** Forward declarations */
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
/* Process a Generate RsaKey request packet and produce a response packet */
static int _HandleRsaKeyGen(whServerContext* ctx, uint16_t magic,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
#endif /* WOLFSSL_KEY_GEN */

/* Process a Rng request packet and produce a response packet */
static int _HandleRng(whServerContext* ctx, uint16_t magic,
                      const void* cryptoDataIn, uint16_t inSize,
                      void* cryptoDataOut, uint16_t* outSize);

/* Process a Rsa Function request packet and produce a response packet */
static int _HandleRsaFunction(whServerContext* ctx, uint16_t magic,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);

/* Process a Rsa Get Size request packet and produce a response packet */
static int _HandleRsaGetSize(whServerContext* ctx, uint16_t magic,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize);
#endif /* !NO_RSA */

#ifdef HAVE_HKDF
/* Process an HKDF request packet and produce a response packet */
static int _HandleHkdf(whServerContext* ctx, uint16_t magic,
                       const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_HKDF */

#ifndef NO_AES

#ifdef WOLFSSL_AES_COUNTER
/* Process a AES CBC request packet and produce a response packet */
static int _HandleAesCtr(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_ECB
static int _HandleAesEcb(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
static int _HandleAesCbc(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
static int _HandleAesGcm(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#ifdef HAVE_ECC
static int _HandleEccKeyGen(whServerContext* ctx, uint16_t magic,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
#ifdef HAVE_ECC_DHE
static int _HandleEccSharedSecret(whServerContext* ctx, uint16_t magic,
                                  const void* cryptoDataIn, uint16_t inSize,
                                  void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_ECC_DHE */
#ifdef HAVE_ECC_SIGN
static int _HandleEccSign(whServerContext* ctx, uint16_t magic,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_ECC_SIGN */
#ifdef HAVE_ECC_VERIFY
static int _HandleEccVerify(whServerContext* ctx, uint16_t magic,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_ECC_VERIFY */
#if 0
#ifdef HAVE_ECC_CHECK_KEY
static int _HandleEccCheckPrivKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
#endif /* HAVE_ECC_CHECK_KEY */
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Process a Generate curve25519_key request packet and produce a response */
static int _HandleCurve25519KeyGen(whServerContext* ctx, uint16_t magic,
                                   const void* cryptoDataIn, uint16_t inSize,
                                   void* cryptoDataOut, uint16_t* outSize);

/* Process a curve25519_key Function request packet and produce a response */
static int _HandleCurve25519SharedSecret(whServerContext* ctx, uint16_t magic,
                                         const void* cryptoDataIn,
                                         uint16_t inSize, void* cryptoDataOut,
                                         uint16_t* outSize);
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_DILITHIUM
/* Process a Dilithium KeyGen request packet and produce a response packet */
static int _HandleMlDsaKeyGen(whServerContext* ctx, uint16_t magic,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
/* Process a Dilithium Sign request packet and produce a response packet */
static int _HandleMlDsaSign(whServerContext* ctx, uint16_t magic,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize);
/* Process a Dilithium Verify request packet and produce a response packet */
static int _HandleMlDsaVerify(whServerContext* ctx, uint16_t magic,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize);
/* Process a Dilithium Check PrivKey request packet and produce a response
 * packet */
static int _HandleMlDsaCheckPrivKey(whServerContext* ctx, uint16_t magic,
                                    const void* cryptoDataIn, uint16_t inSize,
                                    void* cryptoDataOut, uint16_t* outSize);
#endif /* HAVE_DILITHIUM */

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
    ret = wh_Server_KeystoreGetCacheSlot(ctx, keyId, max_size, &cacheBuf,
                                         &cacheMeta);
    if (ret == 0) {
        ret = wh_Crypto_RsaSerializeKeyDer(key, max_size, cacheBuf, &der_size);
    }

    if (ret == 0) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = der_size;
        cacheMeta->flags = flags;
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
static int _HandleRsaKeyGen(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int    ret    = 0;
    RsaKey rsa[1] = {0};
    whMessageCrypto_RsaKeyGenRequest req;
    whMessageCrypto_RsaKeyGenResponse res;

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
    ret = wc_InitRsaKey_ex(rsa, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* make the rsa key with the given params */
        ret = wc_MakeRsaKey(rsa, key_size, e, ctx->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] MakeRsaKey: size:%d, e:%ld, ret:%d\n", key_size, e,
               ret);
#endif

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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] RsaKeyGen UniqueId: keyId:%u, ret:%d\n",
                           key_id, ret);
#endif
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] RsaKeyGen CacheKeyRsa: keyId:%u, ret:%d\n",
                       key_id, ret);
#endif
                if (ret == 0) {
                    res.keyId = wh_KeyId_TranslateToClient(key_id);
                    res.len   = 0;
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

static int _HandleRsaFunction( whServerContext* ctx, uint16_t magic,
                      const void* cryptoDataIn, uint16_t inSize,
                      void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                        ret;
    RsaKey                     rsa[1];
    whMessageCrypto_RsaRequest req;

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
    /* in and out are after the fixed size fields */
    byte* in  = (uint8_t*)(cryptoDataIn + sizeof(whMessageCrypto_RsaRequest));
    byte* out = (uint8_t*)(cryptoDataOut + sizeof(whMessageCrypto_RsaResponse));

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] HandleRsaFunction opType:%d inLen:%u keyId:%u outLen:%u\n",
            op_type, in_len, key_id, out_len);
#endif
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] %s Unknown opType:%d\n",
            __func__, op_type);
#endif

        return BAD_FUNC_ARG;
    }

    /* init rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, ctx->crypto->devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = wh_Server_CacheExportRsaKey(ctx, key_id, rsa);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] CacheExportRsaKey keyid:%u, ret:%d\n", key_id, ret);
#endif
        if (ret == 0) {
            /* do the rsa operation */
            ret = wc_RsaFunction(in, in_len, out, &out_len,
                op_type, rsa, ctx->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] RsaFunction in:%p %u, out:%p, opType:%d, outLen:%d, ret:%d\n",
                    in, in_len, out, op_type, out_len, ret);
#endif
        }
        /* free the key */
        wc_FreeRsaKey(rsa);
    }
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

static int _HandleRsaGetSize(whServerContext* ctx, uint16_t magic,
                             const void* cryptoDataIn, uint16_t inSize,
                             void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                                ret;
    RsaKey                             rsa[1];
    whMessageCrypto_RsaGetSizeRequest  req;
    whMessageCrypto_RsaGetSizeResponse res;

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

    int key_size = 0;

    /* init rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, ctx->crypto->devId);
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] %s evicting temp key:%x options:%u evict:%u\n",
               __func__, key_id, options, evict);
#endif
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res.keySize = key_size;

        wh_MessageCrypto_TranslateRsaGetSizeResponse(
            magic, &res, (whMessageCrypto_RsaGetSizeResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_RsaGetSizeResponse);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] %s keyId:%d, key_size:%d, ret:%d\n", __func__, key_id,
           key_size, ret);
#endif
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
    uint16_t max_size = ECC_BUFSIZE;;
    uint16_t der_size;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            WH_KEYID_ISERASED(keyId) ||
            ((label != NULL) && (label_len > sizeof(cacheMeta->label))) ) {
        return WH_ERROR_BADARGS;
    }
    /* get a free slot */
    ret = wh_Server_KeystoreGetCacheSlot(ctx, keyId, max_size, &cacheBuf,
                                         &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_EccSerializeKeyDer(key, max_size, cacheBuf, &der_size);
    }

    if (ret == WH_ERROR_OK) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = der_size;
        cacheMeta->flags = flags;
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
        ret = wh_Server_KeystoreGetCacheSlot(server, keyId, keySz, &cacheBuf,
                                             &cacheMeta);
        if (ret == 0) {
            memcpy(cacheBuf, der_buf, keySz);
            /* Update metadata to cache the key */
            cacheMeta->id     = keyId;
            cacheMeta->len    = keySz;
            cacheMeta->flags  = flags;
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] Export25519Key id:%u ret:%d\n", keyId, ret);
        wh_Utils_Hexdump("[server] export key:", cacheBuf, cacheMeta->len);
#endif
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_DILITHIUM
int wh_Server_MlDsaKeyCacheImport(whServerContext* ctx, MlDsaKey* key,
                                  whKeyId keyId, whNvmFlags flags,
                                  uint16_t label_len, uint8_t* label)
{
    int            ret = WH_ERROR_OK;
    uint8_t*       cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t       der_size;

    const uint16_t MAX_MLDSA_DER_SIZE =
#if !defined(WOLFSSL_NO_ML_DSA_87)
        ML_DSA_LEVEL5_PRV_KEY_DER_SIZE;
#elif !defined(WOLFSSL_NO_ML_DSA_65)
        ML_DSA_LEVEL3_PRV_KEY_DER_SIZE;
#else
        ML_DSA_LEVEL2_PRV_KEY_DER_SIZE;
#endif

    if ((ctx == NULL) || (key == NULL) || (WH_KEYID_ISERASED(keyId)) ||
        ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Server_KeystoreGetCacheSlot(ctx, keyId, MAX_MLDSA_DER_SIZE,
                                         &cacheBuf, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlDsaSerializeKeyDer(key, MAX_MLDSA_DER_SIZE, cacheBuf,
                                             &der_size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] %s keyId:%u, ret:%d\n", __func__, keyId, ret);
#endif
    }

    if (ret == WH_ERROR_OK) {
        cacheMeta->id     = keyId;
        cacheMeta->len    = der_size;
        cacheMeta->flags  = flags;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}

int wh_Server_MlDsaKeyCacheExport(whServerContext* ctx, whKeyId keyId,
                                  MlDsaKey* key)
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] %s keyId:%u, ret:%d\n", __func__, keyId, ret);
#endif
    }
    return ret;
}
#endif /* HAVE_DILITHIUM */


/** Request/Response Handling functions */

#ifdef HAVE_ECC
static int _HandleEccKeyGen(whServerContext* ctx, uint16_t magic,
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
    ret = wc_ecc_init_ex(key, NULL, ctx->crypto->devId);
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
                /* TODO: RSA has the following, should we do the same? */
                /*
                if (ret == 0) {
                    res.keyId = 0;
                    res.len = res_size;
                }
                */
            }
            else {
                /* Must import the key into the cache and return keyid
                 */
                res_size = 0;
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
#ifdef DEBUG_CRYPTOCB
                    printf("[server] %s UniqueId: keyId:%u, ret:%d\n", __func__,
                           key_id, ret);
#endif
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
#ifdef DEBUG_CRYPTOCB
                printf("[server] %s CacheImport: keyId:%u, ret:%d\n", __func__,
                       key_id, ret);
#endif
                /* TODO: RSA has the following, should we do the same? */
                /*
                res.keyId = WH_KEYID_ID(key_id);
                res.len = 0;
                */
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
                                  const void* cryptoDataIn, uint16_t inSize,
                                  void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                         ret = WH_ERROR_OK;
    ecc_key                     pub_key[1];
    ecc_key                     prv_key[1];
    whMessageCrypto_EcdhRequest req;

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

    /* Response message */
    byte* res_out =
        (byte*)cryptoDataOut + sizeof(whMessageCrypto_EcdhResponse);
    word32 max_len = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                              (res_out - (uint8_t*)cryptoDataOut));
    word32 res_len = 0;

    /* init ecc keys */
    ret = wc_ecc_init_ex(pub_key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        ret = wc_ecc_init_ex(prv_key, NULL, ctx->crypto->devId);
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
        res.sz = res_len;

        wh_MessageCrypto_TranslateEcdhResponse(
            magic, &res, (whMessageCrypto_EcdhResponse*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_EcdhResponse) + res_len;
    }
    return ret;
}
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_SIGN
static int _HandleEccSign(whServerContext* ctx, uint16_t magic,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                            ret;
    ecc_key                        key[1];
    whMessageCrypto_EccSignRequest req;

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccSignRequest(
        magic, (const whMessageCrypto_EccSignRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_EccSignRequest);
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    word32   in_len  = req.sz;
    uint32_t options = req.options;
    int      evict   = !!(options & WH_MESSAGE_CRYPTO_ECCSIGN_OPTIONS_EVICT);

    /* Response message */
    byte* res_out =
        (byte*)cryptoDataOut + sizeof(whMessageCrypto_EccSignResponse);
    word32 max_len = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                              (res_out - (uint8_t*)cryptoDataOut));
    word32 res_len = max_len;

    /* init private key */
    ret = wc_ecc_init_ex(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf(
                "[server] EccSign: key_id=%x, in_len=%u, res_len=%u, ret=%d\n",
                key_id, (unsigned)in_len, (unsigned)res_len, ret);
            wh_Utils_Hexdump("[server] EccSign in:", in, in_len);
#endif
            /* sign the input */
            ret = wc_ecc_sign_hash(in, in_len, res_out, &res_len,
                                   ctx->crypto->rng, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[server] EccSign res:", res_out, res_len);
#endif
        }
        wc_ecc_free(key);
    }
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
static int _HandleEccVerify(whServerContext* ctx, uint16_t magic,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                               ret;
    ecc_key                           key[1];
    whMessageCrypto_EccVerifyRequest  req;
    whMessageCrypto_EccVerifyResponse res;

    /* Translate request */
    ret = wh_MessageCrypto_TranslateEccVerifyRequest(
        magic, (const whMessageCrypto_EccVerifyRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
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

    /* Response message */
    byte* res_pub =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_EccVerifyResponse);
    word32   max_size = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                               (res_pub - (uint8_t*)cryptoDataOut));
    uint32_t pub_size = 0;
    int      result   = 0;

    /* init public key */
    ret = wc_ecc_init_ex(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* load the public key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* verify the signature */
            ret = wc_ecc_verify_hash(req_sig, sig_len, req_hash, hash_len,
                                     &result, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] EccVerify: key_id=%x, sig_len=%u, hash_len=%u, "
                   "result=%d, ret=%d\n",
                   key_id, (unsigned)sig_len, (unsigned)hash_len, result, ret);

            wh_Utils_Hexdump("[server] EccVerify hash:", req_hash, hash_len);
            wh_Utils_Hexdump("[server] EccVerify sig:", req_sig, sig_len);
#endif

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

#if 0
#ifdef HAVE_ECC_CHECK_KEY
/* TODO: Implement check key */
static int _HandleEccCheckPrivKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    ecc_key key[1];

    /* Request packet */
    wh_Packet_pk_ecc_check_req* req = &packet->pkEccCheckReq;
    whKeyId key_id = WH_MAKE_KEYID( WH_KEYTYPE_CRYPTO,
                                    server->comm->client_id,
                                    req->keyId);
    uint32_t curve_id = req->curveId;

    /* Response packet */
    wh_Packet_pk_ecc_check_res* res = &packet->pkEccCheckRes;

    ret = wc_ecc_init_ex(key, NULL, server->crypto->devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_EccKeyCacheExport(server, key, key_id);

        if (ret == 0) {
            /* check the key */
            ret = wc_ecc_check_key(key);
            if (ret == 0) {
                res->ok = 1;
                *size = WH_PACKET_STUB_SIZE + sizeof(*res);
            }
        }
        wc_ecc_free(key);
    }
    return ret;
}
#endif /* HAVE_ECC_CHECK_KEY */
#endif
#endif /* HAVE_ECC */


#ifndef WC_NO_RNG
static int _HandleRng(whServerContext* ctx, uint16_t magic,
                      const void* cryptoDataIn, uint16_t inSize,
                      void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                         ret = WH_ERROR_OK;
    whMessageCrypto_RngRequest  req;
    whMessageCrypto_RngResponse res;

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

#ifdef HAVE_HKDF
int wh_Server_HkdfKeyCacheImport(whServerContext* ctx, const uint8_t* keyData,
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
    ret = wh_Server_KeystoreGetCacheSlot(ctx, keyId, keySize, &cacheBuf,
                                         &cacheMeta);
    if (ret == WH_ERROR_OK) {
        /* Copy the key data to cache buffer */
        memcpy(cacheBuf, keyData, keySize);
    }

    if (ret == WH_ERROR_OK) {
        /* Set metadata */
        cacheMeta->id     = keyId;
        cacheMeta->len    = keySize;
        cacheMeta->flags  = flags;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
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

    ret = wh_Server_KeystoreGetCacheSlot(ctx, keyId, keySize, &cacheBuf,
                                         &cacheMeta);
    if (ret == WH_ERROR_OK) {
        memcpy(cacheBuf, keyData, keySize);
    }

    if (ret == WH_ERROR_OK) {
        cacheMeta->id     = keyId;
        cacheMeta->len    = keySize;
        cacheMeta->flags  = flags;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if ((label != NULL) && (label_len > 0)) {
            memcpy(cacheMeta->label, label, label_len);
        }
    }

    return ret;
}
#endif /* HAVE_CMAC_KDF */

#ifdef HAVE_HKDF
static int _HandleHkdf(whServerContext* ctx, uint16_t magic,
                       const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                          ret = WH_ERROR_OK;
    whMessageCrypto_HkdfRequest  req;
    whMessageCrypto_HkdfResponse res;

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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] HkdfKeyGen UniqueId: keyId:%u, ret:%d\n",
                       key_id, ret);
#endif
                if (ret != WH_ERROR_OK) {
                    /* Early return on unique ID generation failure */
                    return ret;
                }
            }

            if (ret == 0) {
                ret = wh_Server_HkdfKeyCacheImport(ctx, out, outSz, key_id,
                                                   flags, label_size, label);
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] HkdfKeyGen CacheImport: keyId:%u, ret:%d\n",
                   key_id, ret);
#endif
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
static int _HandleCmacKdf(whServerContext* ctx, uint16_t magic,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                             ret = WH_ERROR_OK;
    whMessageCrypto_CmacKdfRequest  req;
    whMessageCrypto_CmacKdfResponse res;

    memset(&res, 0, sizeof(res));

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

    ret = wc_KDA_KDF_twostep_cmac(
        salt, saltSz, z, zSz, (fixedInfoSz > 0) ? fixedInfo : NULL, fixedInfoSz,
        out, outSz, NULL, ctx->crypto->devId);
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
                                   const void* cryptoDataIn, uint16_t inSize,
                                   void* cryptoDataOut, uint16_t* outSize)
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
    ret = wc_curve25519_init_ex(key, NULL, ctx->crypto->devId);
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
                ser_size = 0;
                /* Must import the key into the cache and return keyid */
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = wh_Server_KeystoreGetUniqueId(ctx, &key_id);
#ifdef DEBUG_CRYPTOCB
                    printf("[server] %s UniqueId: keyId:%u, ret:%d\n", __func__,
                           key_id, ret);
#endif
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
#ifdef DEBUG_CRYPTOCB
                printf("[server] %s CacheImport: keyId:%u, ret:%d\n", __func__,
                       key_id, ret);
#endif
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
                                         const void* cryptoDataIn,
                                         uint16_t inSize, void* cryptoDataOut,
                                         uint16_t* outSize)
{
    (void)inSize;

    int ret;
    curve25519_key priv[1] = {0};
    curve25519_key pub[1] = {0};

    whMessageCrypto_Curve25519Request  req;
    whMessageCrypto_Curve25519Response res;

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

    /* Response message */
    uint8_t* res_out       = (uint8_t*)cryptoDataOut +
                             sizeof(whMessageCrypto_Curve25519Response);
    uint16_t max_len      = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (res_out - (uint8_t*)cryptoDataOut));
    word32 res_len      = max_len;

    /* init private key */
    ret = wc_curve25519_init_ex(priv, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* init public key */
        ret = wc_curve25519_init_ex(pub, NULL, ctx->crypto->devId);
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
    if (evict_pub) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, pub_key_id);
    }
    if (evict_prv) {
        /* User requested to evict from cache, even if the call failed */
        (void)wh_Server_KeystoreEvictKey(ctx, prv_key_id);
    }
    if (ret == 0) {
        res.sz = res_len;

        wh_MessageCrypto_TranslateCurve25519Response(
            magic, &res,
            (whMessageCrypto_Curve25519Response*)cryptoDataOut);

        *outSize = sizeof(whMessageCrypto_Curve25519Response) + res_len;
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifndef NO_AES
#ifdef WOLFSSL_AES_COUNTER
static int _HandleAesCtr(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;
    int                            ret    = 0;
    Aes                            aes[1] = {0};
    whMessageCrypto_AesCtrRequest  req;
    whMessageCrypto_AesCtrResponse res;
    uint8_t                        read_key[AES_MAX_KEY_SIZE];
    uint32_t                       read_key_len = sizeof(read_key);
    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesCtrRequest(
        magic, (const whMessageCrypto_AesCtrRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }
    uint32_t enc         = req.enc;
    uint32_t key_len     = req.keyLen;
    uint32_t len         = req.sz;
    uint32_t left        = req.left;
    uint64_t needed_size = sizeof(whMessageCrypto_AesCtrResponse) + len +
                           key_len + AES_IV_SIZE + AES_BLOCK_SIZE;
    if (needed_size > inSize) {
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[AesCtr] Input data ", in, len);
    wh_Utils_Hexdump("[AesCtr] IV ", iv, AES_BLOCK_SIZE);
    wh_Utils_Hexdump("[AesCtr] tmp ", tmp, AES_BLOCK_SIZE);
#endif
    /* Read the key if it is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreReadKey(ctx, key_id, NULL, read_key,
                                        &read_key_len);
        if (ret == 0) {
            /* override the incoming values */
            key     = read_key;
            key_len = read_key_len;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[AesCtr] Key from HSM", key, key_len);
#endif
        }
    }
    else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[AesCtr] Key ", key, key_len);
#endif
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, ctx->crypto->devId);
    }
    if (ret == 0) {
        /* load the key */
        ret = wc_AesSetKeyDirect(aes, (byte*)key, (word32)key_len, (byte*)iv,
                                 enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == 0) {
            /* do the crypto operation */
            /* restore previous left */
            aes->left = left;
            memcpy(aes->tmp, tmp, sizeof(aes->tmp));
            if (enc != 0) {
                ret = wc_AesCtrEncrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[AesCtr] Encrypted output", out, len);
#endif
                }
            }
            else {
                /* CTR uses the same function for encrypt and decrypt */
                ret = wc_AesCtrEncrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[AesCtr] Decrypted output", out, len);
#endif
                }
            }
        }
        left = aes->left;
        memcpy(out_reg, aes->reg, AES_BLOCK_SIZE);
        memcpy(out_tmp, aes->tmp, sizeof(aes->tmp));
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
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
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_ECB
static int _HandleAesEcb(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                            ret    = 0;
    Aes                            aes[1] = {0};
    whMessageCrypto_AesEcbRequest  req;
    whMessageCrypto_AesEcbResponse res;
    uint8_t                        read_key[AES_MAX_KEY_SIZE];
    uint32_t                       read_key_len = sizeof(read_key);

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesEcbRequest(
        magic, (const whMessageCrypto_AesEcbRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    uint32_t enc     = req.enc;
    uint32_t key_len = req.keyLen;
    uint32_t len     = req.sz;
    uint64_t needed_size =
        sizeof(whMessageCrypto_AesEcbResponse) + len + key_len + AES_BLOCK_SIZE;
    if (needed_size > inSize) {
        return WH_ERROR_BADARGS;
    }

    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

    /* in, key, iv, and out are after fixed size fields */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_AesEcbRequest);
    uint8_t* key = in + len;
    uint8_t* iv  = key + key_len;

    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_AesEcbResponse);

    /* Debug printouts */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[AesEcb] Input data", in, len);
    wh_Utils_Hexdump("[AesEcb] IV", iv, AES_BLOCK_SIZE);
#endif
    /* Read the key if it is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreReadKey(ctx, key_id, NULL, read_key,
                                        &read_key_len);
        if (ret == 0) {
            /* override the incoming values */
            key     = read_key;
            key_len = read_key_len;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[AesEcb] Key from HSM", key, key_len);
#endif
        }
    }
    else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[AesEcb] Key ", key, key_len);
#endif
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, ctx->crypto->devId);
    }
    if (ret == 0) {
        /* load the key */
        ret = wc_AesSetKey(aes, (byte*)key, (word32)key_len, (byte*)iv,
                           enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == 0) {
            /* do the crypto operation */
            if (enc != 0) {
                ret = wc_AesEcbEncrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[AesEcb] Encrypted output", out, len);
#endif
                }
            }
            else {
                ret = wc_AesEcbDecrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[AesEcb] Decrypted output", out, len);
#endif
                }
            }
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        res.sz   = len;
        *outSize = sizeof(whMessageCrypto_AesEcbResponse) + len;

        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesEcbResponse(
            magic, &res, (whMessageCrypto_AesEcbResponse*)cryptoDataOut);
    }
    return ret;
}
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
static int _HandleAesCbc(whServerContext* ctx, uint16_t magic, const void* cryptoDataIn,
                         uint16_t inSize, void* cryptoDataOut,
                         uint16_t* outSize)
{
    (void)inSize;

    int                            ret    = 0;
    Aes                            aes[1] = {0};
    whMessageCrypto_AesCbcRequest  req;
    whMessageCrypto_AesCbcResponse res;
    uint8_t                        read_key[AES_MAX_KEY_SIZE];
    uint32_t                       read_key_len = sizeof(read_key);

    /* Translate request */
    ret = wh_MessageCrypto_TranslateAesCbcRequest(
        magic, (const whMessageCrypto_AesCbcRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    uint32_t enc     = req.enc;
    uint32_t key_len = req.keyLen;
    uint32_t len     = req.sz;
    uint64_t needed_size = sizeof(whMessageCrypto_AesCbcResponse) + len +
                          key_len + AES_BLOCK_SIZE;
    if (needed_size > inSize) {
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

    /* Debug printouts */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[AesCbc] Input data", in, len);
    wh_Utils_Hexdump("[AesCbc] IV", iv, AES_BLOCK_SIZE);
#endif
    /* Read the key if it is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreReadKey(ctx, key_id, NULL, read_key,
                                        &read_key_len);
        if (ret == 0) {
            /* override the incoming values */
            key     = read_key;
            key_len = read_key_len;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[AesCbc] Key from HSM", key, key_len);
#endif
        }
    }
    else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[AesCbc] Key ", key, key_len);
#endif
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, ctx->crypto->devId);
    }
    if (ret == 0) {
        /* load the key */
        ret = wc_AesSetKey(aes, (byte*)key, (word32)key_len, (byte*)iv,
                           enc != 0 ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == 0) {
            /* do the crypto operation */
            if (enc != 0) {
                ret = wc_AesCbcEncrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[AesCbc] Encrypted output", out, len);
#endif
                }
            }
            else {
                ret = wc_AesCbcDecrypt(aes, (byte*)out, (byte*)in, (word32)len);
                if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[AesCbc] Decrypted output", out, len);
#endif
                }
            }
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        res.sz   = len;
        *outSize = sizeof(whMessageCrypto_AesCbcResponse) + len;

        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesCbcResponse(
            magic, &res, (whMessageCrypto_AesCbcResponse*)cryptoDataOut);
    }
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
static int _HandleAesGcm(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int      ret    = 0;
    Aes      aes[1] = {0};
    uint8_t  read_key[AES_MAX_KEY_SIZE];
    uint32_t read_key_len = sizeof(read_key);

    /* Translate request */
    whMessageCrypto_AesGcmRequest req;
    ret = wh_MessageCrypto_TranslateAesGcmRequest(
        magic, (const whMessageCrypto_AesGcmRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Translate response */
    whMessageCrypto_AesGcmResponse res;
    res.sz        = req.sz;
    res.authTagSz = (req.enc == 0) ? 0 : req.authTagSz;

    uint32_t enc        = req.enc;
    uint32_t key_len    = req.keyLen;
    uint32_t len        = req.sz;
    uint32_t iv_len     = req.ivSz;
    uint32_t authin_len = req.authInSz;
    uint32_t tag_len    = req.authTagSz;
    whKeyId  key_id     = wh_KeyId_TranslateFromClient(
             WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);

    /* in, key, iv, authin, tag, and out are after fixed size fields */
    uint8_t* in = (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_AesGcmRequest);
    uint8_t* key = in + len;
    uint8_t* iv = key + key_len;
    uint8_t* authin = iv + iv_len;
    uint8_t* tag = authin + authin_len;

    /* TODO: This should not include the generic request header, though doesn't
     * matter since it is just a debug printf*/
    uint32_t req_len = sizeof(whMessageCrypto_AesGcmRequest) + len + key_len +
                       iv_len + authin_len + ((enc == 0) ? tag_len : 0);
    (void)req_len;

    /* Set up response pointers */
    uint8_t* out = (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_AesGcmResponse);
    uint8_t* out_tag = out + len;

    uint32_t res_len = sizeof(whMessageCrypto_AesGcmResponse) + len +
                       ((enc == 0) ? 0 : tag_len);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] AESGCM: enc:%d keylen:%d ivsz:%d insz:%d authinsz:%d "
           "authtagsz:%d reqsz:%u ressz:%u\n",
           enc, key_len, iv_len, len, authin_len, tag_len, req_len, res_len);
    printf("[server] AESGCM: req:%p in:%p key:%p iv:%p authin:%p tag:%p res:%p "
           "out:%p out_tag:%p\n",
           &req, in, key, iv, authin, tag, &res, out, out_tag);
    wh_Utils_Hexdump("[server] AESGCM req packet: \n", (uint8_t*)cryptoDataIn,
                     req_len);
#endif

    /* Read the key if it is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = wh_Server_KeystoreReadKey(ctx, key_id, NULL, read_key,
                                        &read_key_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] AesGcm ReadKey key_id:%u, key_len:%d ret:%d\n", key_id,
               read_key_len, ret);
#endif
        if (ret == 0) {
            /* override the incoming values */
            key     = read_key;
            key_len = read_key_len;
        }
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, ctx->crypto->devId);
    }
    if (ret == 0) {
        /* load the key */
        ret = wc_AesGcmSetKey(aes, (byte*)key, (word32)key_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] AesGcmSetKey key_id:%u key_len:%u ret:%d\n", key_id,
               key_len, ret);
        wh_Utils_Hexdump("[server] key: ", key, key_len);
#endif
        if (ret == 0) {
            /* do the crypto operation */
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf(
                "[server] enc:%d len:%d, ivSz:%d authTagSz:%d, authInSz:%d\n",
                enc, len, iv_len, tag_len, authin_len);
            wh_Utils_Hexdump("[server] in: ", in, len);
            wh_Utils_Hexdump("[server] iv: ", iv, iv_len);
            wh_Utils_Hexdump("[server] authin: ", authin, authin_len);
#endif
            if (enc != 0) {
                /* For encryption, write tag to the response output tag area */
                ret = wc_AesGcmEncrypt(aes, (byte*)out, (byte*)in, (word32)len,
                                       (byte*)iv, (word32)iv_len, (byte*)out_tag,
                                       (word32)tag_len, (byte*)authin,
                                       (word32)authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] enc ret:%d\n", ret);
                wh_Utils_Hexdump("[server] out: \n", out, len);
                wh_Utils_Hexdump("[server] enc tag: ", out_tag, tag_len);
#endif
            }
            else {
                /* set authTag as a packet input */
#ifdef DEBUG_CRYPTOCB_VERBOSE
                wh_Utils_Hexdump("[server] dec tag: ", tag, tag_len);
#endif
                ret = wc_AesGcmDecrypt(aes, (byte*)out, (byte*)in, (word32)len,
                                       (byte*)iv, (word32)iv_len, (byte*)tag,
                                       (word32)tag_len, (byte*)authin,
                                       (word32)authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] dec ret:%d\n", ret);
                wh_Utils_Hexdump("[server] out: \n", out, len);
#endif
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[server] post iv: ", iv, iv_len);
            wh_Utils_Hexdump("[server] post authin: ", authin, authin_len);
#endif
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        res.sz        = len;
        res.authTagSz = (enc == 0) ? 0 : tag_len;
        *outSize      = res_len;
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] res out_size:%d\n", *outSize);
        wh_Utils_Hexdump("[server] AESGCM res packet: \n",
                         (uint8_t*)cryptoDataOut, res_len);
#endif

        /* Translate response back */
        ret = wh_MessageCrypto_TranslateAesGcmResponse(
            magic, &res, (whMessageCrypto_AesGcmResponse*)cryptoDataOut);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _HandleAesGcmDma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    int                            ret = 0;
    whMessageCrypto_AesDmaRequest  req;
    whMessageCrypto_AesDmaResponse res;
    byte                           tmpKey[AES_256_KEY_SIZE];
    Aes                            aes[1] = {0};

    void*  inAddr      = NULL;
    void*  outAddr     = NULL;
    void*  authTagAddr = NULL;
    void*  ivAddr      = NULL;
    void*  aadAddr     = NULL;
    word32 outSz       = 0;

    whKeyId  keyId;
    uint32_t keyLen;

    (void)inSize;
    (void)seq;

    ret = wh_MessageCrypto_TranslateAesDmaRequest(
        magic, (whMessageCrypto_AesDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesInit(aes, NULL, ctx->crypto->devId);
    }

    /* Handle key operations */
    if (ret == WH_ERROR_OK && req.key.sz > 0) {
        /* Copy key from client if provided */
        ret = whServerDma_CopyFromClient(ctx, tmpKey, req.key.addr, req.key.sz,
                                         (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.key;
        }
        keyLen = req.key.sz;
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

    /* Handle IV */
    if (ret == WH_ERROR_OK && req.iv.sz > 0) {
        /* Process client address for IV */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.iv.addr, &ivAddr, req.iv.sz, WH_DMA_OPER_CLIENT_READ_PRE,
            (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.iv;
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

    /* Handle auth tag for decryption */
    if (ret == WH_ERROR_OK && req.authTag.sz > 0) {
        /* Process client address for auth tag */
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.authTag.addr, &authTagAddr, req.authTag.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.authTag;
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

    /* Handle keyId-based keys if no direct key was provided */
    if (ret == WH_ERROR_OK && req.key.sz == 0) {
        keyId  = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                              ctx->comm->client_id, req.keyId);
        keyLen = sizeof(tmpKey);
        ret    = wh_Server_KeystoreReadKey(ctx, keyId, NULL, tmpKey, &keyLen);
        if (ret == WH_ERROR_OK) {
            /* Verify key size is valid for AES */
            if (keyLen != AES_128_KEY_SIZE && keyLen != AES_192_KEY_SIZE &&
                keyLen != AES_256_KEY_SIZE) {
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = wc_AesGcmSetKey(aes, tmpKey, keyLen);
    }

    if (ret == WH_ERROR_OK) {
        if (req.enc) {
            ret = wc_AesGcmEncrypt(
                aes, (byte*)outAddr, (byte*)inAddr, (word32)req.input.sz,
                (byte*)ivAddr, (word32)req.iv.sz, (byte*)authTagAddr,
                (word32)req.authTag.sz, (byte*)aadAddr, (word32)req.aad.sz);
            if (ret == 0) {
                outSz = req.input.sz;
            }
        }
        else {
            ret = wc_AesGcmDecrypt(
                aes, (byte*)outAddr, (byte*)inAddr, (word32)req.input.sz,
                (byte*)ivAddr, (word32)req.iv.sz, (byte*)authTagAddr,
                (word32)req.authTag.sz, (byte*)aadAddr, (word32)req.aad.sz);
            if (ret == 0) {
                outSz = req.input.sz;
            }
        }
    }

    /* Post-write DMA address processing for output/authTag (on success) */
    if (ret == WH_ERROR_OK) {
        if (req.output.sz > 0) {
            int rc2 = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            if (rc2 != WH_ERROR_OK) {
                if (rc2 == WH_ERROR_ACCESS) {
                    res.dmaAddrStatus.badAddr = req.output;
                }
                ret = rc2;
            }
        }
        /* During encryption, the auth tag is written to client memory */
        if (ret == WH_ERROR_OK && req.enc && req.authTag.sz > 0) {
            int rc2 = wh_Server_DmaProcessClientAddress(
                ctx, req.authTag.addr, &authTagAddr, req.authTag.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
            if (rc2 != WH_ERROR_OK) {
                if (rc2 == WH_ERROR_ACCESS) {
                    res.dmaAddrStatus.badAddr = req.authTag;
                }
                ret = rc2;
            }
        }
    }

    wc_AesFree(aes);
    res.outSz = outSz;

    (void)wh_MessageCrypto_TranslateAesDmaResponse(
        magic, &res, (whMessageCrypto_AesDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#ifdef WOLFSSL_CMAC
static int _HandleCmac(whServerContext* ctx, uint16_t magic, uint16_t seq,
                       const void* cryptoDataIn, uint16_t inSize,
                       void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int ret;
    whMessageCrypto_CmacRequest req;
    whMessageCrypto_CmacResponse res;

    /* Translate request */
    ret = wh_MessageCrypto_TranslateCmacRequest(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    uint32_t i;
    word32   len;
    whKeyId keyId = WH_KEYID_ERASED;

    /* Setup fixed size fields */
    uint8_t* in =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_CmacRequest);
    uint8_t* key = in + req.inSz;
    uint8_t* out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_CmacResponse);

    switch(req.type) {
#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    case WC_CMAC_AES:
    {
        whNvmMetadata meta[1] = {{0}};
        uint8_t moveToBigCache = 0;
        word32 blockSz = AES_BLOCK_SIZE;
        uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];

        /* attempt oneshot if all fields are present */
        if (req.inSz != 0 && req.keySz != 0 && req.outSz != 0) {
            len = req.outSz;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] cmac generate oneshot\n");
#endif
            ret = wc_AesCmacGenerate_ex(ctx->crypto->algoCtx.cmac, out, &len, in,
                                        req.inSz, key, req.keySz, NULL,
                                        ctx->crypto->devId);
            res.outSz = len;
        } else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] cmac begin keySz:%d inSz:%d outSz:%d keyId:%x\n",
                    req.keySz, req.inSz, req.outSz, req.keyId);
#endif
            /* do each operation based on which fields are set */
            if (req.keySz != 0) {
                /* initialize cmac with key and type */
                ret = wc_InitCmac_ex(ctx->crypto->algoCtx.cmac, key, req.keySz,
                                     req.type, NULL, NULL, ctx->crypto->devId);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac init with key:%p keylen:%d, type:%d ret:%d\n",
                        key, req.keySz, req.type, ret);
#endif
            } else {
                /* Key is not present, meaning client wants to use AES key from
                 * cache/nvm. In order to support multiple sequential CmacUpdate()
                 * calls, we need to cache the whole CMAC struct between invocations
                 * (which also holds the key). To do this we hijack the requested key's
                 * cache slot until CmacFinal() is called, at which point we evict the
                 * struct from the cache. TODO: client should hold CMAC state */
                len   = sizeof(ctx->crypto->algoCtx.cmac);
                keyId = wh_KeyId_TranslateFromClient(
                    WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
                ret   = wh_Server_KeystoreReadKey(
                      ctx, keyId, NULL, (uint8_t*)ctx->crypto->algoCtx.cmac,
                      (uint32_t*)&len);
                if (ret == WH_ERROR_OK) {
                    /* if the key size is a multiple of aes, init the key and
                     * overwrite the existing key on exit */
                    if (len == AES_128_KEY_SIZE || len == AES_192_KEY_SIZE ||
                        len == AES_256_KEY_SIZE) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        printf("[server] cmac readkey got key len:%u\n", len);
#endif
                        moveToBigCache = 1;
                        memcpy(tmpKey, (uint8_t*)ctx->crypto->algoCtx.cmac,
                               len);
                        ret = wc_InitCmac_ex(ctx->crypto->algoCtx.cmac, tmpKey, len,
                            WC_CMAC_AES, NULL, NULL, ctx->crypto->devId);
                    }
                    else if (len != sizeof(ctx->crypto->algoCtx.cmac)) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        printf("[server] cmac bad readkey len:%u. sizeof(cmac):%lu\n",
                                len, sizeof(ctx->crypto->algoCtx.cmac));
#endif
                        ret = BAD_FUNC_ARG;
                    }
                }
                else {
                    /* Initialize the cmac with a NULL key */
                    /* initialize cmac with key and type */
                    ret = wc_InitCmac_ex(ctx->crypto->algoCtx.cmac, NULL,
                        req.keySz, req.type, NULL, NULL, ctx->crypto->devId);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] cmac init with NULL type:%d ret:%d\n",
                            req.type, ret);
#endif
                }
            }
            /* Handle CMAC update, checking for cancellation */
            if (ret == 0 && req.inSz != 0) {
#ifndef WOLFHSM_CFG_CANCEL_API
                (void)seq;
#endif
                for (i = 0; ret == 0 && i < req.inSz; i += AES_BLOCK_SIZE) {
                    if (i + AES_BLOCK_SIZE > req.inSz) {
                        blockSz = req.inSz - i;
                    }
                    ret = wc_CmacUpdate(ctx->crypto->algoCtx.cmac, in + i,
                        blockSz);
#ifdef WOLFHSM_CFG_CANCEL_API
                    if (ret == 0) {
                        ret = _CheckCancellation(ctx, seq);
                    }
#endif
                }
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac update done. ret:%d\n", ret);
#endif
            }

            /* Check if we should finalize and evict, or cache for future calls
             */
            if (ret == 0 && req.outSz != 0) {
                /* Finalize CMAC operation */
                keyId = req.keyId;
                len   = req.outSz;
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac final keyId:%x len:%d\n", keyId, len);
#endif
                ret       = wc_CmacFinal(ctx->crypto->algoCtx.cmac, out, &len);
                res.outSz = len;
                res.keyId = WH_KEYID_ERASED;

                /* Evict the key from cache */
                if (!WH_KEYID_ISERASED(keyId)) {
                    /* Don't override return value except on failure */
                    int tmpRet = wh_Server_KeystoreEvictKey(
                        ctx, wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                          ctx->comm->client_id,
                                                          keyId));
                    if (tmpRet != 0) {
                        ret = tmpRet;
                    }
                }
            }
#ifdef WOLFHSM_CFG_CANCEL_API
            else if (ret == WH_ERROR_CANCEL) {
                /* Handle cancellation - evict key and abandon state */
                if (!WH_KEYID_ISERASED(req.keyId)) {
                    wh_Server_KeystoreEvictKey(
                        ctx, wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                                          ctx->comm->client_id,
                                                          req.keyId));
                }
            }
#endif
            /* Cache the CMAC struct for a future update call */
            else if (ret == 0) {
                /* cache/re-cache updated struct */
                if (req.keySz != 0) {
                    keyId = WH_MAKE_KEYID(  WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            WH_KEYID_ERASED);
                    ret   = wh_Server_KeystoreGetUniqueId(ctx, &keyId);
                    if (ret != WH_ERROR_OK)
                        return ret;
                }
                else {
                    keyId = wh_KeyId_TranslateFromClient(
                        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
                }
                /* evict the aes sized key in the normal cache */
                if (moveToBigCache == 1) {
                    ret = wh_Server_KeystoreEvictKey(ctx, keyId);
                }
                if (ret == 0) {
                    meta->id  = keyId;
                    meta->len = sizeof(ctx->crypto->algoCtx.cmac);
                    ret       = wh_Server_KeystoreCacheKey(
                        ctx, meta, (uint8_t*)ctx->crypto->algoCtx.cmac);
                    if (ret == 0) {
                        res.keyId = wh_KeyId_TranslateToClient(keyId);
                        res.outSz = 0;
                    }
                }
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac saved state in keyid:%x %x len:%u ret:%d type:%d\n",
                        keyId, WH_KEYID_ID(keyId), meta->len, ret, ctx->crypto->algoCtx.cmac->type);
#endif
            }
        }
    } break;
#endif /* !NO_AES && WOLFSSL_AES_DIRECT */
    default:
        /* Type not supported */
        ret = CRYPTOCB_UNAVAILABLE;
    }
    if (ret == 0) {
        ret = wh_MessageCrypto_TranslateCmacResponse(magic, &res, cryptoDataOut);
        if (ret == 0) {
            *outSize = sizeof(res) + res.outSz;
        }
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] cmac end ret:%d\n", ret);
#endif
    return ret;
}
#endif

#ifndef NO_SHA256
static int _HandleSha256(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    (void)inSize;

    int                            ret    = 0;
    wc_Sha256                      sha256[1];
    whMessageCrypto_Sha256Request  req;
    whMessageCrypto_Sha2Response   res = {0};

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha256Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }
    /* always init sha2 struct with the devid */
    ret = wc_InitSha256_ex(sha256, NULL, ctx->crypto->devId);
    if (ret != 0) {
        return ret;
    }
    /* restore the hash state from the client */
    memcpy(sha256->digest, req.resumeState.hash, WC_SHA256_DIGEST_SIZE);
    sha256->loLen = req.resumeState.loLen;
    sha256->hiLen = req.resumeState.hiLen;

    if (req.isLastBlock) {
        /* Validate lastBlockLen to prevent potential buffer overread */
        if ((unsigned int)req.lastBlockLen > WC_SHA256_BLOCK_SIZE) {
            return WH_ERROR_BADARGS;
        }
        /* wolfCrypt (or cryptoCb) is responsible for last block padding */
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, req.inBlock, req.lastBlockLen);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, res.hash);
        }
    }
    else {
        /* Client always sends full blocks, unless it's the last block */
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, req.inBlock, WC_SHA256_BLOCK_SIZE);
        }
        /* Send the hash state back to the client */
        if (ret == 0) {
            memcpy(res.hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
            res.loLen = sha256->loLen;
            res.hiLen = sha256->hiLen;
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
static int _HandleSha224(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha224                     sha224[1];
    whMessageCrypto_Sha256Request req;
    whMessageCrypto_Sha2Response  res;
    (void)inSize;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha256Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }
    ret = wc_InitSha224_ex(sha224, NULL, ctx->crypto->devId);
    if (ret != 0) {
        return ret;
    }
    /* sha224 is a part of sha256. It expects to have sha256 digest size of
     * intermediate hash data.
     */
    memcpy(sha224->digest, req.resumeState.hash, WC_SHA256_DIGEST_SIZE);
    sha224->loLen = req.resumeState.loLen;
    sha224->hiLen = req.resumeState.hiLen;

    if (req.isLastBlock) {
        /* wolfCrypt (or cryptoCb) is responsible for last block padding */
        if (ret == 0) {
            ret = wc_Sha224Update(sha224, req.inBlock, req.lastBlockLen);
        }
        if (ret == 0) {
            ret = wc_Sha224Final(sha224, res.hash);
        }
    }
    else {
        /* Client always sends full blocks, unless it's the last block */
        if (ret == 0) {
            ret = wc_Sha224Update(sha224, req.inBlock, WC_SHA224_BLOCK_SIZE);
        }
        /* Send the hash state back to the client */
        if (ret == 0) {
            /* return back the digest which has the same length of sha256
             * for further operation
             */
            memcpy(res.hash, sha224->digest, WC_SHA256_DIGEST_SIZE);
            res.loLen = sha224->loLen;
            res.hiLen = sha224->hiLen;
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
static int _HandleSha384(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha384                     sha384[1];
    whMessageCrypto_Sha512Request req;
    whMessageCrypto_Sha2Response  res;
    (void)inSize;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha512Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* init sha2 struct with the devid */
    ret = wc_InitSha384_ex(sha384, NULL, ctx->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    /* restore the hash state from the client */
    /* sha384 is a part of sha512. It expects to have sha512 digest
     * size of intermediate hash data.
     */
    memcpy(sha384->digest, req.resumeState.hash, WC_SHA512_DIGEST_SIZE);
    sha384->loLen = req.resumeState.loLen;
    sha384->hiLen = req.resumeState.hiLen;

    if (req.isLastBlock) {
        /* wolfCrypt (or cryptoCb) is responsible for last block padding */
        if (ret == 0) {
            ret = wc_Sha384Update(sha384, req.inBlock, req.lastBlockLen);
        }
        if (ret == 0) {
            ret = wc_Sha384Final(sha384, res.hash);
        }
    }
    else {
        /* Client always sends full blocks, unless it's the last block */
        if (ret == 0) {
            ret = wc_Sha384Update(sha384, req.inBlock, WC_SHA384_BLOCK_SIZE);
        }
        /* Send the hash state back to the client */
        if (ret == 0) {
            /* return back the digest which has the same length of sha512
             * for further operation
             */
            memcpy(res.hash, sha384->digest, WC_SHA512_DIGEST_SIZE);
            res.loLen = sha384->loLen;
            res.hiLen = sha384->hiLen;
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
static int _HandleSha512(whServerContext* ctx, uint16_t magic,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    int                           ret = 0;
    wc_Sha512                     sha512[1];
    whMessageCrypto_Sha512Request req;
    whMessageCrypto_Sha2Response  res;
    int                           hashType = WC_HASH_TYPE_SHA512;
    (void)inSize;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha512Request(magic, cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }
    /* init sha2 struct with devid */
    hashType = req.resumeState.hashType;
    switch (hashType) {
        case WC_HASH_TYPE_SHA512_224:
            ret = wc_InitSha512_224_ex(sha512, NULL, ctx->crypto->devId);
            break;
        case WC_HASH_TYPE_SHA512_256:
            ret = wc_InitSha512_256_ex(sha512, NULL, ctx->crypto->devId);
            break;
        default:
            ret = wc_InitSha512_ex(sha512, NULL, ctx->crypto->devId);
            break;
    }
    if (ret != 0) {
        return ret;
    }

    memcpy(sha512->digest, req.resumeState.hash, WC_SHA512_DIGEST_SIZE);
    sha512->loLen = req.resumeState.loLen;
    sha512->hiLen = req.resumeState.hiLen;

    if (req.isLastBlock) {
        /* wolfCrypt (or cryptoCb) is responsible for last block padding */
        if (ret == 0) {
            ret = wc_Sha512Update(sha512, req.inBlock, req.lastBlockLen);
        }
        if (ret == 0) {
            switch (hashType) {
                case WC_HASH_TYPE_SHA512_224:
                    ret = wc_Sha512_224Final(sha512, res.hash);
                    break;
                case WC_HASH_TYPE_SHA512_256:
                    ret = wc_Sha512_256Final(sha512, res.hash);
                    break;
                default:
                    ret = wc_Sha512Final(sha512, res.hash);
                    break;
            }
        }
    }
    else {
        /* Client always sends full blocks, unless it's the last block */
        if (ret == 0) {
            ret = wc_Sha512Update(sha512, req.inBlock, WC_SHA512_BLOCK_SIZE);
        }
        /* Send the hash state back to the client */
        if (ret == 0) {
            memcpy(res.hash, sha512->digest, WC_SHA512_DIGEST_SIZE);
            res.loLen = sha512->loLen;
            res.hiLen = sha512->hiLen;
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
#ifdef HAVE_DILITHIUM

#ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
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
#endif /* WOLFSSL_DILITHIUM_NO_MAKE_KEY */

static int _HandleMlDsaKeyGen(whServerContext* ctx, uint16_t magic,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_DILITHIUM_NO_MAKE_KEY
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
    MlDsaKey                            key[1];
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
        ret = wc_MlDsaKey_Init(key, NULL, ctx->crypto->devId);
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
#ifdef DEBUG_CRYPTOCB
                            printf("[server] %s UniqueId: keyId:%u, ret:%d\n",
                                   __func__, key_id, ret);
#endif
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
#ifdef DEBUG_CRYPTOCB
                        printf("[server] %s CacheImport: keyId:%u, ret:%d\n",
                               __func__, key_id, ret);
#endif
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
#endif /* WOLFSSL_DILITHIUM_NO_MAKE_KEY */
}

static int _HandleMlDsaSign(whServerContext* ctx, uint16_t magic,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_DILITHIUM_NO_SIGN
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
    MlDsaKey                            key[1];
    whMessageCrypto_MlDsaSignRequest    req;
    whMessageCrypto_MlDsaSignResponse   res;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaSignRequest(
        magic, (whMessageCrypto_MlDsaSignRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    byte*   in = (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_MlDsaSignRequest);
    whKeyId key_id = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    word32   in_len  = req.sz;
    uint32_t options = req.options;
    int      evict   = !!(options & WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT);

    /* Validate input length against available data to prevent buffer overread
     */
    if (inSize < sizeof(whMessageCrypto_MlDsaSignRequest)) {
        return WH_ERROR_BADARGS;
    }
    word32 available_data = inSize - sizeof(whMessageCrypto_MlDsaSignRequest);
    if (in_len > available_data) {
        return WH_ERROR_BADARGS;
    }

    /* Response message */
    byte* res_out =
        (uint8_t*)(cryptoDataOut) + sizeof(whMessageCrypto_MlDsaSignResponse);
    const word32 max_len = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                                    (res_out - (uint8_t*)cryptoDataOut));
    word32       res_len = max_len;

    /* init private key */
    ret = wc_MlDsaKey_Init(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_MlDsaKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* sign the input */
            ret     = wc_MlDsaKey_Sign(key, res_out, &res_len, in, in_len,
                                       ctx->crypto->rng);
        }
        wc_MlDsaKey_Free(key);
    }
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
#endif /* WOLFSSL_DILITHIUM_NO_SIGN */
}

static int _HandleMlDsaVerify(whServerContext* ctx, uint16_t magic,
                              const void* cryptoDataIn, uint16_t inSize,
                              void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_DILITHIUM_NO_VERIFY
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
    MlDsaKey                            key[1];
    whMessageCrypto_MlDsaVerifyRequest  req;
    whMessageCrypto_MlDsaVerifyResponse res;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateMlDsaVerifyRequest(
        magic, (whMessageCrypto_MlDsaVerifyRequest*)cryptoDataIn, &req);
    if (ret != 0) {
        return ret;
    }

    /* Extract parameters from translated request */
    uint32_t options = req.options;
    whKeyId  key_id  = wh_KeyId_TranslateFromClient(
          WH_KEYTYPE_CRYPTO, ctx->comm->client_id, req.keyId);
    uint32_t hash_len = req.hashSz;
    uint32_t sig_len  = req.sigSz;
    byte*    req_sig =
        (uint8_t*)(cryptoDataIn) + sizeof(whMessageCrypto_MlDsaVerifyRequest);

    /* Validate lengths against available payload (overflow-safe) */
    if (inSize < sizeof(whMessageCrypto_MlDsaVerifyRequest)) {
        return WH_ERROR_BADARGS;
    }
    uint32_t available = inSize - sizeof(whMessageCrypto_MlDsaVerifyRequest);
    if ((sig_len > available) || (hash_len > available) ||
        (sig_len > (available - hash_len))) {
        return WH_ERROR_BADARGS;
    }

    byte*    req_hash = req_sig + sig_len;
    int      evict = !!(options & WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT);

    /* Response message */
    int result = 0;

    /* init public key */
    ret = wc_MlDsaKey_Init(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* load the public key */
        ret = wh_Server_MlDsaKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* verify the signature */
            ret = wc_MlDsaKey_Verify(key, req_sig, sig_len, req_hash, hash_len,
                                     &result);
        }
        wc_MlDsaKey_Free(key);
    }
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
#endif /* WOLFSSL_DILITHIUM_NO_VERIFY */
}

static int _HandleMlDsaCheckPrivKey(whServerContext* ctx, uint16_t magic,
                                    const void* cryptoDataIn, uint16_t inSize,
                                    void* cryptoDataOut, uint16_t* outSize)
{
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
}
#endif /* HAVE_DILITHIUM */

#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
static int _HandlePqcSigAlgorithm(whServerContext* ctx, uint16_t magic,
                                  const void* cryptoDataIn,
                                  uint16_t cryptoInSize, void* cryptoDataOut,
                                  uint16_t* cryptoOutSize, uint32_t pkAlgoType,
                                  uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    /* Dispatch the appropriate algorithm handler based on the requested PK type
     * and the algorithm type. */
    switch (pqAlgoType) {
#ifdef HAVE_DILITHIUM
        case WC_PQC_SIG_TYPE_DILITHIUM: {
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                    ret = _HandleMlDsaKeyGen(ctx, magic, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_SIGN:
                    ret =
                        _HandleMlDsaSign(ctx, magic, cryptoDataIn, cryptoInSize,
                                         cryptoDataOut, cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                    ret = _HandleMlDsaVerify(ctx, magic, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandleMlDsaCheckPrivKey(ctx, magic, cryptoDataIn,
                                                   cryptoInSize, cryptoDataOut,
                                                   cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
        } break;
#endif /* HAVE_DILITHIUM */
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif

#if defined(HAVE_KYBER)
static int _HandlePqcKemAlgorithm(whServerContext* ctx, whPacket* packet,
                                  uint16_t* size)
{
    /* Placeholder for KEM algorithm handling */
    return WH_ERROR_NOHANDLER;
}
#endif

int wh_Server_HandleCryptoRequest(whServerContext* ctx, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet)
{
    int                                   ret        = 0;
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

    /* Translate the request message to get the algo type */
    wh_MessageCrypto_TranslateGenericRequestHeader(
        magic, (whMessageCrypto_GenericRequestHeader*)req_packet, &rqstHeader);


#ifdef DEBUG_CRYPTOCB
    printf("[server] HandleCryptoRequest. Action:%u\n", action);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[server] Crypto Request:\n", (const uint8_t*)req_packet,
                     req_size);
#endif
#endif
    switch (action) {
        case WC_ALGO_TYPE_CIPHER:
            switch (rqstHeader.algoType) {
#ifndef NO_AES
#ifdef WOLFSSL_AES_COUNTER
                case WC_CIPHER_AES_CTR:
                    ret = _HandleAesCtr(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_ECB
                case WC_CIPHER_AES_ECB:
                    ret = _HandleAesEcb(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
                case WC_CIPHER_AES_CBC:
                    ret = _HandleAesCbc(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
                case WC_CIPHER_AES_GCM:
                    ret = _HandleAesGcm(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break;
        case WC_ALGO_TYPE_PK: {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] PK type:%d\n", rqstHeader.algoType);
#endif
            switch (rqstHeader.algoType) {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
                case WC_PK_TYPE_RSA_KEYGEN:
                    ret =
                        _HandleRsaKeyGen(ctx, magic, cryptoDataIn, cryptoInSize,
                                         cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* WOLFSSL_KEY_GEN */
                case WC_PK_TYPE_RSA:
                    ret = _HandleRsaFunction(ctx, magic, cryptoDataIn,
                                             cryptoInSize, cryptoDataOut,
                                             &cryptoOutSize);
                    break;

                case WC_PK_TYPE_RSA_GET_SIZE:
                    ret = _HandleRsaGetSize(ctx, magic, cryptoDataIn,
                                            cryptoInSize, cryptoDataOut,
                                            &cryptoOutSize);
                    break;
#endif /* !NO_RSA */

#ifdef HAVE_ECC
                case WC_PK_TYPE_EC_KEYGEN:
                    ret =
                        _HandleEccKeyGen(ctx, magic, cryptoDataIn, cryptoInSize,
                                         cryptoDataOut, &cryptoOutSize);
                    break;
#ifdef HAVE_ECC_DHE
                case WC_PK_TYPE_ECDH:
                    ret = _HandleEccSharedSecret(ctx, magic, cryptoDataIn,
                                                 cryptoInSize, cryptoDataOut,
                                                 &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_DHE */
#ifdef HAVE_ECC_SIGN
                case WC_PK_TYPE_ECDSA_SIGN:
                    ret = _HandleEccSign(ctx, magic, cryptoDataIn, cryptoInSize,
                                         cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_SIGN */
#ifdef HAVE_ECC_VERIFY
                case WC_PK_TYPE_ECDSA_VERIFY:
                    ret = _HandleEccVerify(ctx, magic, cryptoDataIn, cryptoInSize,
                                           cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_ECC_VERIFY */
#if 0
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            ret = _HandleEccCheckPrivKey(ctx, magic, cryptoDataIn, cryptoInSize,
                                          cryptoDataOut, &cryptoOutSize);
            break;
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
                case WC_PK_TYPE_CURVE25519_KEYGEN:
                    ret = _HandleCurve25519KeyGen(ctx, magic, cryptoDataIn,
                                                  cryptoInSize, cryptoDataOut,
                                                  &cryptoOutSize);
                    break;
                case WC_PK_TYPE_CURVE25519:
                    ret = _HandleCurve25519SharedSecret(
                        ctx, magic, cryptoDataIn, cryptoInSize, cryptoDataOut,
                        &cryptoOutSize);
                    break;
#endif /* HAVE_CURVE25519 */

#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                case WC_PK_TYPE_PQC_SIG_SIGN:
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandlePqcSigAlgorithm(
                        ctx, magic, cryptoDataIn, cryptoInSize, cryptoDataOut,
                        &cryptoOutSize, rqstHeader.algoType,
                        rqstHeader.algoSubType);
                    break;
#endif

#if defined(HAVE_KYBER)
                case WC_PK_TYPE_PQC_KEM_KEYGEN:
                case WC_PK_TYPE_PQC_KEM_ENCAPS:
                case WC_PK_TYPE_PQC_KEM_DECAPS:
                    ret =
                        _HandlePqcKemAlgorithm(ctx, magic, cryptoDataIn, cryptoInSize,
                                               cryptoDataOut, &cryptoOutSize);
                    break;
#endif

                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
        }; break;

#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_RNG:
            ret = _HandleRng(ctx, magic, cryptoDataIn, cryptoInSize,
                             cryptoDataOut, &cryptoOutSize);
            break;
#endif /* !WC_NO_RNG */

#if defined(HAVE_HKDF) || defined(HAVE_CMAC_KDF)
        case WC_ALGO_TYPE_KDF:
            switch (rqstHeader.algoSubType) {
#ifdef HAVE_HKDF
                case WC_KDF_TYPE_HKDF:
                    ret = _HandleHkdf(ctx, magic, cryptoDataIn, cryptoInSize,
                                      cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_HKDF */
#ifdef HAVE_CMAC_KDF
                case WC_KDF_TYPE_TWOSTEP_CMAC:
                    ret = _HandleCmacKdf(ctx, magic, cryptoDataIn, cryptoInSize,
                                         cryptoDataOut, &cryptoOutSize);
                    break;
#endif /* HAVE_CMAC_KDF */
                default:
                    ret = NOT_COMPILED_IN;
                    break;
            }
            break;
#endif /* HAVE_HKDF || HAVE_CMAC_KDF */

#ifdef WOLFSSL_CMAC
        case WC_ALGO_TYPE_CMAC:
            ret = _HandleCmac(ctx, magic, seq, cryptoDataIn, cryptoInSize,
                              cryptoDataOut, &cryptoOutSize);
            break;
#endif

        case WC_ALGO_TYPE_HASH:
            switch (rqstHeader.algoType) {
#ifndef NO_SHA256
                case WC_HASH_TYPE_SHA256:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] SHA256 req recv. type:%u\n",
                           rqstHeader.algoType);
#endif
                    ret = _HandleSha256(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] SHA256 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* !NO_SHA256 */
#if defined(WOLFSSL_SHA224)
                case WC_HASH_TYPE_SHA224:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] SHA224 req recv. type:%u\n",
                           rqstHeader.algoType);
#endif
                    ret = _HandleSha224(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] SHA224 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* WOLFSSL_SHA224 */
#if defined(WOLFSSL_SHA384)
                case WC_HASH_TYPE_SHA384:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] SHA384 req recv. type:%u\n",
                           rqstHeader.algoType);
#endif
                    ret = _HandleSha384(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] SHA384 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* WOLFSSL_SHA384 */
#if defined(WOLFSSL_SHA512)
                case WC_HASH_TYPE_SHA512:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] SHA512 req recv. type:%u\n",
                           rqstHeader.algoType);
#endif
                    ret = _HandleSha512(ctx, magic, cryptoDataIn, cryptoInSize,
                                        cryptoDataOut, &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] SHA512 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* WOLFSSL_SHA512 */
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

#ifdef DEBUG_CRYPTOCB
    printf("[server] %s End ret:%d\n", __func__, ret);
#endif

    /* Since crypto error codes are propagated to the client in the response
     * packet, return success to the caller unless a cancellation has occurred
     */
#ifdef WOLFHSM_CFG_CANCEL_API
    if (ret != WH_ERROR_CANCEL) {
        ret = WH_ERROR_OK;
    }
#else
    ret = WH_ERROR_OK;
#endif
    return ret;
}

#ifdef WOLFHSM_CFG_DMA

#ifndef NO_SHA256
static int _HandleSha256Dma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;
    (void)inSize;

    int                             ret = 0;
    whMessageCrypto_Sha2DmaRequest  req;
    whMessageCrypto_Sha2DmaResponse res;
    wc_Sha256                       sha256[1];
    int                             clientDevId;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha2DmaRequest(
        magic, (whMessageCrypto_Sha2DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Ensure state sizes are the same */
    if (req.state.sz != sizeof(*sha256)) {
        res.dmaAddrStatus.badAddr = req.state;
        ret                       = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        /* Copy the SHA256 context from client address space */
        ret = whServerDma_CopyFromClient(ctx, sha256, req.state.addr,
                                         req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
        else {
            /* Save the client devId to be restored later, when the context is
             * copied back into client memory. */
            clientDevId = sha256->devId;
            /* overwrite the devId to that of the server for local crypto */
            sha256->devId = ctx->crypto->devId;
        }
    }

    /* TODO: perhaps we should sequentially update and finalize (need individual
     * flags as 0x0 could be a valid address?) just to future-proof, even though
     * sha256 cryptoCb doesn't currently have a one-shot*/

    /* If finalize requested, finalize the SHA256 operation, wrapping client
     * address accesses with the associated DMA address processing */
    if (ret == WH_ERROR_OK && req.finalize) {
        void* outAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});

        /* Finalize the SHA256 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha256Final: outAddr=%p\n", outAddr);
#endif
            ret = wc_Sha256Final(sha256, outAddr);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }
    else if (ret == WH_ERROR_OK) {
        /* Update requested, update the SHA256 operation, wrapping client
         * address accesses with the associated DMA address processing */
        void* inAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

        /* Update the SHA256 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha256Update: inAddr=%p, sz=%llu\n", inAddr,
                   (long long unsigned int)req.input.sz);
#endif
            ret = wc_Sha256Update(sha256, inAddr, req.input.sz);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Reset the devId in the local context to ensure it isn't copied back
         * to client memory */
        sha256->devId = clientDevId;
        /* Copy SHA256 context back into client memory */
        ret = whServerDma_CopyToClient(ctx, req.state.addr, sha256,
                                       req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
    }

    /* Translate the response */
    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    /* return value populates rc in response message */
    return ret;
}
#endif /* ! NO_SHA256 */

#ifdef WOLFSSL_SHA224
static int _HandleSha224Dma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;
    (void)inSize;
    int                             ret = 0;
    whMessageCrypto_Sha2DmaRequest  req;
    whMessageCrypto_Sha2DmaResponse res;
    wc_Sha224                       sha224[1];
    int                             clientDevId;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha2DmaRequest(
        magic, (whMessageCrypto_Sha2DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Ensure state sizes are the same */
    if (req.state.sz != sizeof(*sha224)) {
        res.dmaAddrStatus.badAddr = req.state;
        ret                       = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        /* Copy the SHA224 context from client address space */
        ret = whServerDma_CopyFromClient(ctx, sha224, req.state.addr,
                                         req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
        else {
            /* Save the client devId to be restored later, when the context is
             * copied back into client memory. */
            clientDevId = sha224->devId;
            /* overwrite the devId to that of the server for local crypto */
            sha224->devId = ctx->crypto->devId;
        }
    }

    /* TODO: perhaps we should sequentially update and finalize (need individual
     * flags as 0x0 could be a valid address?) just to future-proof, even though
     * sha224 cryptoCb doesn't currently have a one-shot*/

    /* If finalize requested, finalize the SHA224 operation, wrapping client
     * address accesses with the associated DMA address processing */
    if (ret == WH_ERROR_OK && req.finalize) {
        void* outAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});

        /* Finalize the SHA224 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha224Final: outAddr=%p\n", outAddr);
#endif
            ret = wc_Sha224Final(sha224, outAddr);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }
    else if (ret == WH_ERROR_OK) {
        /* Update requested, update the SHA224 operation, wrapping client
         * address accesses with the associated DMA address processing */
        void* inAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

        /* Update the SHA224 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha224Update: inAddr=%p, sz=%llu\n", inAddr,
                   (long long unsigned int)req.input.sz);
#endif
            ret = wc_Sha224Update(sha224, inAddr, req.input.sz);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Reset the devId in the local context to ensure it isn't copied back
         * to client memory */
        sha224->devId = clientDevId;
        /* Copy SHA224 context back into client memory */
        ret = whServerDma_CopyToClient(ctx, req.state.addr, sha224,
                                       req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
    }

    /* Translate the response */
    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    /* return value populates rc in response message */
    return ret;
}
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
static int _HandleSha384Dma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;
    (void)inSize;
    int                             ret = 0;
    whMessageCrypto_Sha2DmaRequest  req;
    whMessageCrypto_Sha2DmaResponse res;
    wc_Sha384                       sha384[1];
    int                             clientDevId;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha2DmaRequest(
        magic, (whMessageCrypto_Sha2DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Ensure state sizes are the same */
    if (req.state.sz != sizeof(*sha384)) {
        res.dmaAddrStatus.badAddr = req.state;
        ret                       = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        /* Copy the SHA384 context from client address space */
        ret = whServerDma_CopyFromClient(ctx, sha384, req.state.addr,
                                         req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
        else {
            /* Save the client devId to be restored later, when the context is
             * copied back into client memory. */
            clientDevId = sha384->devId;
            /* overwrite the devId to that of the server for local crypto */
            sha384->devId = ctx->crypto->devId;
        }
    }

    /* TODO: perhaps we should sequentially update and finalize (need individual
     * flags as 0x0 could be a valid address?) just to future-proof, even though
     * sha384 cryptoCb doesn't currently have a one-shot*/

    /* If finalize requested, finalize the SHA384 operation, wrapping client
     * address accesses with the associated DMA address processing */
    if (ret == WH_ERROR_OK && req.finalize) {
        void* outAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});

        /* Finalize the SHA384 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha384Final: outAddr=%p\n", outAddr);
#endif
            ret = wc_Sha384Final(sha384, outAddr);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }
    else if (ret == WH_ERROR_OK) {
        /* Update requested, update the SHA384 operation, wrapping client
         * address accesses with the associated DMA address processing */
        void* inAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

        /* Update the SHA384 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha384Update: inAddr=%p, sz=%llu\n", inAddr,
                   (long long unsigned int)req.input.sz);
#endif
            ret = wc_Sha384Update(sha384, inAddr, req.input.sz);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Reset the devId in the local context to ensure it isn't copied back
         * to client memory */
        sha384->devId = clientDevId;
        /* Copy SHA384 context back into client memory */
        ret = whServerDma_CopyToClient(ctx, req.state.addr, sha384,
                                       req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
    }

    /* Translate the response */
    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    /* return value populates rc in response message */
    return ret;
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static int _HandleSha512Dma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                            const void* cryptoDataIn, uint16_t inSize,
                            void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;
    (void)inSize;
    int                             ret = 0;
    whMessageCrypto_Sha2DmaRequest  req;
    whMessageCrypto_Sha2DmaResponse res;
    wc_Sha512                       sha512[1];
    int                             clientDevId;
    int                             hashType = WC_HASH_TYPE_SHA512;

    /* Translate the request */
    ret = wh_MessageCrypto_TranslateSha2DmaRequest(
        magic, (whMessageCrypto_Sha2DmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    /* Ensure state sizes are the same */
    if (req.state.sz != sizeof(*sha512)) {
        res.dmaAddrStatus.badAddr = req.state;
        ret                       = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        /* Copy the SHA512 context from client address space */
        ret = whServerDma_CopyFromClient(ctx, sha512, req.state.addr,
                                         req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
        else {
            /* Save the client devId to be restored later, when the context is
             * copied back into client memory. */
            clientDevId = sha512->devId;
            /* overwrite the devId to that of the server for local crypto */
            sha512->devId = ctx->crypto->devId;
            /* retrieve hash Type to handle 512, 512-224, or 512-256 */
            hashType = sha512->hashType;
        }
    }

    /* TODO: perhaps we should sequentially update and finalize (need individual
     * flags as 0x0 could be a valid address?) just to future-proof, even though
     * sha512 cryptoCb doesn't currently have a one-shot*/

    /* If finalize requested, finalize the SHA512 operation, wrapping client
     * address accesses with the associated DMA address processing */
    if (ret == WH_ERROR_OK && req.finalize) {
        void* outAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.output.addr, &outAddr, req.output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});

        /* Finalize the SHA512 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha512Final: outAddr=%p\n", outAddr);
            printf("[server]   hashTpe: %d\n", hashType);
#endif
            switch (hashType) {
                case WC_HASH_TYPE_SHA512_224:
                    ret = wc_Sha512_224Final(sha512, outAddr);
                    break;
                case WC_HASH_TYPE_SHA512_256:
                    ret = wc_Sha512_256Final(sha512, outAddr);
                    break;
                default:
                    ret = wc_Sha512Final(sha512, outAddr);
                    break;
            }
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.output;
        }
    }
    else if (ret == WH_ERROR_OK) {
        /* Update requested, update the SHA512 operation, wrapping client
         * address accesses with the associated DMA address processing */
        void* inAddr;
        ret = wh_Server_DmaProcessClientAddress(
            ctx, req.input.addr, &inAddr, req.input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

        /* Update the SHA512 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha512Update: inAddr=%p, sz=%llu\n", inAddr,
                   (long long unsigned int)req.input.sz);
#endif
            ret = wc_Sha512Update(sha512, inAddr, req.input.sz);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res.dmaAddrStatus.badAddr = req.input;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Reset the devId in the local context to ensure it isn't copied back
         * to client memory */
        sha512->devId = clientDevId;
        /* Copy SHA512 context back into client memory */
        ret = whServerDma_CopyToClient(ctx, req.state.addr, sha512,
                                       req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
    }

    /* Translate the response */
    (void)wh_MessageCrypto_TranslateSha2DmaResponse(
        magic, &res, (whMessageCrypto_Sha2DmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    /* return value populates rc in response message */
    return ret;
}
#endif /* WOLFSSL_SHA512 */

#if defined(HAVE_DILITHIUM)

static int _HandleMlDsaKeyGenDma(whServerContext* ctx, uint16_t magic,
                                 const void* cryptoDataIn, uint16_t inSize,
                                 void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_DILITHIUM_NO_MAKE_KEY
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    (void)inSize;

    int      ret = WH_ERROR_OK;
    MlDsaKey key[1];
    void*    clientOutAddr = NULL;
    uint16_t keySize       = 0;

    whMessageCrypto_MlDsaKeyGenDmaRequest req;
    whMessageCrypto_MlDsaKeyGenDmaResponse res;

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
        ret = wc_MlDsaKey_Init(key, NULL, ctx->crypto->devId);
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
#ifdef DEBUG_CRYPTOCB
                            printf("[server] %s UniqueId: keyId:%u, ret:%d\n",
                                   __func__, keyId, ret);
#endif
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
#ifdef DEBUG_CRYPTOCB
                            printf(
                                "[server] %s CacheImport: keyId:%u, ret:%d\n",
                                __func__, keyId, ret);
#endif
                            if (ret == 0) {
                                res.keyId   = wh_KeyId_TranslateToClient(keyId);
                                res.keySize = keySize;
                            }
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
#endif /* WOLFSSL_DILITHIUM_NO_MAKE_KEY */
}

static int _HandleMlDsaSignDma(whServerContext* ctx, uint16_t magic,
                               const void* cryptoDataIn, uint16_t inSize,
                               void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_DILITHIUM_NO_SIGN
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    (void)inSize;

    int      ret = 0;
    MlDsaKey key[1];
    void*    msgAddr = NULL;
    void*    sigAddr = NULL;

    whMessageCrypto_MlDsaSignDmaRequest req;
    whMessageCrypto_MlDsaSignDmaResponse res;

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

    /* Initialize key */
    ret = wc_MlDsaKey_Init(key, NULL, ctx->crypto->devId);
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
                    /* Sign the message */
                    word32 sigLen = req.sig.sz;
                    ret = wc_MlDsaKey_Sign(key, sigAddr, &sigLen, msgAddr,
                                           req.msg.sz, ctx->crypto->rng);

                    if (ret == 0) {
                        /* Post-write processing of signature buffer */
                        ret = wh_Server_DmaProcessClientAddress(
                            ctx, (uintptr_t)req.sig.addr, &sigAddr, sigLen,
                            WH_DMA_OPER_CLIENT_WRITE_POST,
                            (whServerDmaFlags){0});

                        if (ret == 0) {
                            /* Set response signature length */
                            res.sigLen = sigLen;
                            *outSize   = sizeof(res);
                        }

                        /* Post-read processing of message buffer */
                        ret = wh_Server_DmaProcessClientAddress(
                            ctx, (uintptr_t)req.msg.addr, &msgAddr,
                            req.msg.sz, WH_DMA_OPER_CLIENT_READ_POST,
                            (whServerDmaFlags){0});
                    }
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

        /* Translate the response */
        (void)wh_MessageCrypto_TranslateMlDsaSignDmaResponse(
            magic, &res, (whMessageCrypto_MlDsaSignDmaResponse*)cryptoDataOut);

        *outSize = sizeof(res);
    }

    return ret;
#endif /* WOLFSSL_DILITHIUM_NO_SIGN */
}

static int _HandleMlDsaVerifyDma(whServerContext* ctx, uint16_t magic,
                                 const void* cryptoDataIn, uint16_t inSize,
                                 void* cryptoDataOut, uint16_t* outSize)
{
#ifdef WOLFSSL_DILITHIUM_NO_VERIFY
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
#else
    (void)inSize;

    int      ret = 0;
    MlDsaKey key[1];
    void*    msgAddr  = NULL;
    void*    sigAddr  = NULL;
    int      verified = 0;

    whMessageCrypto_MlDsaVerifyDmaRequest req;
    whMessageCrypto_MlDsaVerifyDmaResponse res;

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

    /* Initialize key */
    ret = wc_MlDsaKey_Init(key, NULL, ctx->crypto->devId);
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
                /* Verify the signature */
                ret = wc_MlDsaKey_Verify(key, sigAddr, req.sig.sz, msgAddr,
                                         req.msg.sz, &verified);

                if (ret == 0) {
                    /* Post-read processing of signature buffer */
                    ret = wh_Server_DmaProcessClientAddress(
                        ctx, (uintptr_t)req.sig.addr, &sigAddr, req.sig.sz,
                        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});

                    if (ret == 0) {
                        /* Post-read processing of message buffer */
                        ret = wh_Server_DmaProcessClientAddress(
                            ctx, (uintptr_t)req.msg.addr, &msgAddr,
                            req.msg.sz, WH_DMA_OPER_CLIENT_READ_POST,
                            (whServerDmaFlags){0});

                        if (ret == 0) {
                            /* Set verification result */
                            res.verifyResult = verified;
                        }
                    }
                }
            }
        }

        /* Evict key if requested */
        if (evict) {
            /* User requested to evict from cache, even if the call failed */
            (void)wh_Server_KeystoreEvictKey(ctx, key_id);
        }
    }

    if (ret == 0) {
        /* Translate the response */
        (void)wh_MessageCrypto_TranslateMlDsaVerifyDmaResponse(
            magic, &res,
            (whMessageCrypto_MlDsaVerifyDmaResponse*)cryptoDataOut);

        *outSize = sizeof(res);
    }

    wc_MlDsaKey_Free(key);
    return ret;
#endif /* WOLFSSL_DILITHIUM_NO_VERIFY */
}

static int _HandleMlDsaCheckPrivKeyDma(whServerContext* ctx, uint16_t magic,
                                       const void* cryptoDataIn,
                                       uint16_t inSize, void* cryptoDataOut,
                                       uint16_t* outSize)
{
    (void)ctx;
    (void)magic;
    (void)cryptoDataIn;
    (void)inSize;
    (void)cryptoDataOut;
    (void)outSize;
    return WH_ERROR_NOHANDLER;
}
#endif /* HAVE_DILITHIUM */

#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
static int _HandlePqcSigAlgorithmDma(whServerContext* ctx, uint16_t magic,
                                     const void* cryptoDataIn,
                                     uint16_t cryptoInSize, void* cryptoDataOut,
                                     uint16_t* cryptoOutSize,
                                     uint32_t pkAlgoType, uint32_t pqAlgoType)
{
    int ret = WH_ERROR_NOHANDLER;

    /* Dispatch the appropriate algorithm handler based on the requested PK type
     * and the algorithm type. */
    switch (pqAlgoType) {
#ifdef HAVE_DILITHIUM
        case WC_PQC_SIG_TYPE_DILITHIUM: {
            switch (pkAlgoType) {
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                    ret = _HandleMlDsaKeyGenDma(ctx, magic, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_SIGN:
                    ret = _HandleMlDsaSignDma(ctx, magic, cryptoDataIn,
                                              cryptoInSize, cryptoDataOut,
                                              cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                    ret = _HandleMlDsaVerifyDma(ctx, magic, cryptoDataIn,
                                                cryptoInSize, cryptoDataOut,
                                                cryptoOutSize);
                    break;
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandleMlDsaCheckPrivKeyDma(
                        ctx, magic, cryptoDataIn, cryptoInSize, cryptoDataOut,
                        cryptoOutSize);
                    break;
                default:
                    ret = WH_ERROR_NOHANDLER;
                    break;
            }
        } break;
#endif /* HAVE_DILITHIUM */
        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}
#endif /* HAVE_DILITHIUM || HAVE_FALCON */

#ifdef WOLFSSL_CMAC
static int _HandleCmacDma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                          const void* cryptoDataIn, uint16_t inSize,
                          void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;
    (void)inSize;

    int ret = 0;
    whMessageCrypto_CmacDmaRequest req;
    whMessageCrypto_CmacDmaResponse res;

    /* Translate request */
    ret = wh_MessageCrypto_TranslateCmacDmaRequest(
        magic, (whMessageCrypto_CmacDmaRequest*)cryptoDataIn, &req);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    Cmac*    cmac        = ctx->crypto->algoCtx.cmac;
    int      clientDevId = 0;
    whKeyId  keyId;
    byte     tmpKey[AES_256_KEY_SIZE];
    uint32_t keyLen;
    /* Flag indicating if the CMAC context holds a local key that should not be
     * returned to the client   */
    int ctxHoldsLocalKey = 0;
    /* Flag indicating if the CMAC operation has been finalized */
    int cmacFinalized = 0;

    /* DMA translated addresses */
    void*  inAddr  = NULL;
    void*  outAddr = NULL;
    void*  keyAddr = NULL;
    word32 outSz   = 0;

    /* Ensure state sizes are the same */
    if (req.state.sz != sizeof(*cmac)) {
        res.dmaAddrStatus.badAddr = req.state;
        ret = WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        /* Copy the CMAC context from client address space */
        ret = whServerDma_CopyFromClient(ctx, cmac, req.state.addr,
                                         req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Save the client devId to be restored later */
        clientDevId = cmac->devId;
        /* overwrite the devId to that of the server for local crypto */
        cmac->devId = ctx->crypto->devId;

        /* Print out the state of req */
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] DMA CMAC req recv. type:%u keySz:%u inSz:%u outSz:%u "
               "finalize:%u\n",
               (unsigned int)req.type, (unsigned int)req.key.sz,
               (unsigned int)req.input.sz, (unsigned int)req.output.sz,
               (unsigned int)req.finalize);
#endif

        /* Translate all DMA addresses upfront */
        if (req.input.sz != 0) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.input;
            }
        }

        if (ret == WH_ERROR_OK && req.output.sz != 0) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.output;
            }
        }

        if (ret == WH_ERROR_OK && req.key.sz != 0) {
            ret = wh_Server_DmaProcessClientAddress(
                ctx, req.key.addr, &keyAddr, req.key.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
            if (ret == WH_ERROR_ACCESS) {
                res.dmaAddrStatus.badAddr = req.key;
            }
        }

        if (ret == WH_ERROR_OK) {
            /* Check for one-shot operation (both input and output are
             * non-NULL). There are three distinct cases we need to handle for
             * one-shots:
             * 1. Direct one-shot operation with key provided in request
             * 2. One-shot operation with key referenced by context that needs
             * to be loaded from cache
             * 3. One-shot operation with context already initialized with a key
             */
            if (req.input.sz != 0 && req.output.sz != 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] CMAC one-shot operation detected\n");
#endif

                /* Case 1: Direct one-shot operation with key provided in
                 * request This is the simplest case - we have the key directly
                 * and can use it immediately for the CMAC operation */
                if (req.key.sz != 0) {
                    outSz = req.output.sz;
                    /* Perform one-shot CMAC operation with provided key */
                    ret = wc_AesCmacGenerate_ex(
                        cmac, outAddr, &outSz, inAddr, req.input.sz, keyAddr,
                        req.key.sz, NULL, ctx->crypto->devId);
                    cmacFinalized = 1;
                    res.outSz    = outSz;
                }
                /* Case 2 & 3: One-shot operation with key referenced by context
                 * We need to check if the context is already initialized or
                 * needs to be initialized with a key from cache */
                else {
                    /* Check if there's a keyID in the context that we need to
                     * load
                     */
                    whKeyId clientKeyId = WH_DEVCTX_TO_KEYID(cmac->devCtx);
                    if (clientKeyId != WH_KEYID_ERASED) {
                        /* Case 2: Client-supplied context references a key ID
                         * that needs to be loaded from cache This happens when
                         * the client invokes the one-shot generate on a context
                         * that has been initialized to use a keyId by
                         * reference. We need to load the key from cache and
                         * initialize a new context with it */
                        keyId = wh_KeyId_TranslateFromClient(
                            WH_KEYTYPE_CRYPTO, ctx->comm->client_id,
                            clientKeyId);
                        keyLen = sizeof(tmpKey);

                        /* Load key from cache */
                        ret = wh_Server_KeystoreReadKey(ctx, keyId, NULL,
                                                        tmpKey, &keyLen);
                        if (ret == WH_ERROR_OK) {
                            /* Verify key size is valid for AES */
                            if (keyLen != AES_128_KEY_SIZE &&
                                keyLen != AES_192_KEY_SIZE &&
                                keyLen != AES_256_KEY_SIZE) {
                                ret = WH_ERROR_ABORTED;
                            }
                            else {
                                /* Initialize CMAC with loaded key */
                                ctxHoldsLocalKey = 1;
                                ret = wc_InitCmac_ex(cmac, tmpKey, keyLen,
                                                     WC_CMAC_AES, NULL, NULL,
                                                     ctx->crypto->devId);
                                if (ret == WH_ERROR_OK) {
                                    /* Perform one-shot CMAC operation */
                                    outSz = req.output.sz;
                                    ret   = wc_AesCmacGenerate_ex(
                                        cmac, outAddr, &outSz, inAddr,
                                        req.input.sz, NULL, 0, NULL,
                                        ctx->crypto->devId);
                                    res.outSz    = outSz;
                                    cmacFinalized = 1;
                                }
                            }
                        }
                    }
                    else {
                        /* Case 3: Context is already initialized with a key
                         * This happens when invoking the one-shot generate on a
                         * context that has been initialized with a previous
                         * wc_InitCmac_ex call where the key was already loaded
                         * into the context. We can use the context directly
                         * without needing to load or initialize anything */
                        outSz = req.output.sz;
                        ret   = wc_AesCmacGenerate_ex(
                            cmac, outAddr, &outSz, inAddr, req.input.sz, NULL,
                            0, NULL, ctx->crypto->devId);
                        res.outSz    = outSz;
                        cmacFinalized = 1;
                    }
                }
            }
            /* Otherwise, process the request as an incremental operation */
            else {
                /* Incremental: Initialize CMAC with key if provided */
                if (req.key.sz != 0) {
                    ret = wc_InitCmac_ex(cmac, keyAddr, req.key.sz, req.type,
                                         NULL, NULL, ctx->crypto->devId);
                }
                /* Check for deferred initialization with cached key */
                else if (req.input.sz != 0 || req.finalize) {
                    /* Check if there's a key ID in the context that needs to be
                     * loaded
                     */
                    whNvmId nvmId = WH_DEVCTX_TO_KEYID(cmac->devCtx);
                    if (nvmId != WH_KEYID_ERASED) {
                        /* Get key ID from CMAC context */
                        keyId = wh_KeyId_TranslateFromClient(
                            WH_KEYTYPE_CRYPTO, ctx->comm->client_id, nvmId);
                        keyLen = sizeof(tmpKey);

                        /* Load key from cache */
                        ret = wh_Server_KeystoreReadKey(ctx, keyId, NULL,
                                                        tmpKey, &keyLen);
                        if (ret == WH_ERROR_OK) {
                            /* Verify key size is valid for AES */
                            if (keyLen != AES_128_KEY_SIZE &&
                                keyLen != AES_192_KEY_SIZE &&
                                keyLen != AES_256_KEY_SIZE) {
                                ret = WH_ERROR_ABORTED;
                            }
                            else {
                                ctxHoldsLocalKey = 1;

                                /* Save CMAC state so we can resume operation
                                 * after initialization with key, as reinit will
                                 * clear the state */
                                byte   savedBuffer[AES_BLOCK_SIZE];
                                byte   savedDigest[AES_BLOCK_SIZE];
                                word32 savedBufferSz = cmac->bufferSz;
                                word32 savedTotalSz  = cmac->totalSz;
                                memcpy(savedBuffer, cmac->buffer,
                                       AES_BLOCK_SIZE);
                                memcpy(savedDigest, cmac->digest,
                                       AES_BLOCK_SIZE);

                                ret = wc_InitCmac_ex(cmac, tmpKey, keyLen,
                                                     WC_CMAC_AES, NULL, NULL,
                                                     ctx->crypto->devId);

                                /* Restore CMAC state */
                                memcpy(cmac->buffer, savedBuffer,
                                       AES_BLOCK_SIZE);
                                memcpy(cmac->digest, savedDigest,
                                       AES_BLOCK_SIZE);
                                cmac->bufferSz = savedBufferSz;
                                cmac->totalSz  = savedTotalSz;
                                cmac->devCtx   = (void*)(uintptr_t)nvmId;
                            }
                        }
                    }
                }

                /* Process update if requested */
                if (ret == WH_ERROR_OK && req.input.sz != 0) {
                    ret = wc_CmacUpdate(cmac, inAddr, req.input.sz);
                }

                /* Process finalize if requested */
                if (ret == WH_ERROR_OK && req.finalize) {
                    word32 len    = (word32)req.output.sz;
                    ret           = wc_CmacFinal(cmac, outAddr, &len);
                    cmacFinalized = 1;
                    res.outSz    = len;
                }
            }
        }
    }

    /* Clean up all DMA addresses */
    if (inAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.input.addr, &inAddr, req.input.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] Error cleaning up input DMA address\n");
#endif
        }
    }

    if (outAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.output.addr, &outAddr, req.output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] Error cleaning up output DMA address\n");
#endif
        }
    }

    if (keyAddr != NULL) {
        if (wh_Server_DmaProcessClientAddress(
                ctx, req.key.addr, &keyAddr, req.key.sz,
                WH_DMA_OPER_CLIENT_READ_POST,
                (whServerDmaFlags){0}) != WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] Error cleaning up key DMA address\n");
#endif
        }
    }

    /* Reset the devId and type in the local context */
    cmac->devId = clientDevId;

    /* If we are using HSM-local keys, sanitize the key material from the CMAC
     * state before returning it to the client */
    if (ctxHoldsLocalKey) {
        wc_AesFree(&cmac->aes);
    }

    /* Copy CMAC context back into client memory */
    if (ret == WH_ERROR_OK && !cmacFinalized) {
        ret = whServerDma_CopyToClient(ctx, req.state.addr, cmac,
                                       req.state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res.dmaAddrStatus.badAddr = req.state;
        }
    }

    /* Translate response */
    (void)wh_MessageCrypto_TranslateCmacDmaResponse(
        magic, &res, (whMessageCrypto_CmacDmaResponse*)cryptoDataOut);
    *outSize = sizeof(res);

    /* return value populates rc in response message */
    return ret;
}
#endif /* WOLFSSL_CMAC */

#ifndef WC_NO_RNG
static int _HandleRngDma(whServerContext* ctx, uint16_t magic, uint16_t seq,
                         const void* cryptoDataIn, uint16_t inSize,
                         void* cryptoDataOut, uint16_t* outSize)
{
    (void)seq;
    (void)inSize;

    int                            ret = 0;
    whMessageCrypto_RngDmaRequest  req;
    whMessageCrypto_RngDmaResponse res;
    void*                          outAddr = NULL;

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
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] RNG DMA: generating %llu bytes to addr=%p\n",
               (long long unsigned int)req.output.sz, outAddr);
#endif
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

int wh_Server_HandleCryptoDmaRequest(whServerContext* ctx, uint16_t magic,
                                     uint16_t action, uint16_t seq,
                                     uint16_t req_size, const void* req_packet,
                                     uint16_t* out_resp_size, void* resp_packet)
{
    int                                   ret        = 0;
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

    /* Translate the request message to get the algo type */
    wh_MessageCrypto_TranslateGenericRequestHeader(
        magic, (whMessageCrypto_GenericRequestHeader*)req_packet, &rqstHeader);


    switch (action) {
        case WC_ALGO_TYPE_HASH:
            switch (rqstHeader.algoType) {
#ifndef NO_SHA256
                case WC_HASH_TYPE_SHA256:
                    ret = _HandleSha256Dma(ctx, magic, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] DMA SHA256 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* !NO_SHA256 */
#ifdef WOLFSSL_SHA224
                case WC_HASH_TYPE_SHA224:
                    ret = _HandleSha224Dma(ctx, magic, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] DMA SHA224 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* WOLFSSL_SHA224 */
#ifdef WOLFSSL_SHA384
                case WC_HASH_TYPE_SHA384:
                    ret = _HandleSha384Dma(ctx, magic, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] DMA SHA384 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* WOLFSSL_SHA384 */
#ifdef WOLFSSL_SHA512
                case WC_HASH_TYPE_SHA512:
                    ret = _HandleSha512Dma(ctx, magic, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    if (ret != 0) {
                        printf("[server] DMA SHA512 ret = %d\n", ret);
                    }
#endif
                    break;
#endif /* WOLFSSL_SHA512 */
            }
            break; /* WC_ALGO_TYPE_HASH */

        case WC_ALGO_TYPE_CIPHER:
            switch (rqstHeader.algoType) {
#ifdef HAVE_AESGCM
                case WC_CIPHER_AES_GCM:
                    ret = _HandleAesGcmDma(ctx, magic, seq, cryptoDataIn,
                                           cryptoInSize, cryptoDataOut,
                                           &cryptoOutSize);
                    break;
#endif /* HAVE_AESGCM */
            }
            break; /* WC_ALGO_TYPE_CIPHER */

        case WC_ALGO_TYPE_PK:
            switch (rqstHeader.algoType) {
#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
                case WC_PK_TYPE_PQC_SIG_KEYGEN:
                case WC_PK_TYPE_PQC_SIG_SIGN:
                case WC_PK_TYPE_PQC_SIG_VERIFY:
                case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                    ret = _HandlePqcSigAlgorithmDma(
                        ctx, magic, cryptoDataIn, cryptoInSize, cryptoDataOut,
                        &cryptoOutSize, rqstHeader.algoType,
                        rqstHeader.algoSubType);
                    break;
#endif /* HAVE_DILITHIUM || HAVE_FALCON */
            }
            break; /* WC_ALGO_TYPE_PK */

#ifdef WOLFSSL_CMAC
        case WC_ALGO_TYPE_CMAC:
            ret = _HandleCmacDma(ctx, magic, seq, cryptoDataIn, cryptoInSize,
                                 cryptoDataOut, &cryptoOutSize);
            break;
#endif /* WOLFSSL_CMAC */

#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_RNG:
            ret = _HandleRngDma(ctx, magic, seq, cryptoDataIn, cryptoInSize,
                                cryptoDataOut, &cryptoOutSize);
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


#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] Crypto DMA request. Action:%u\n", action);
#endif
    /* Since crypto error codes are propagated to the client in the response
     * packet, return success to the caller unless a cancellation has occurred
     */
#ifdef WOLFHSM_CFG_CANCEL_API
    if (ret != WH_ERROR_CANCEL) {
        ret = WH_ERROR_OK;
    }
#else
    ret = WH_ERROR_OK;
#endif
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_SERVER */
