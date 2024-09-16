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

#ifndef WOLFHSM_CFG_NO_CRYPTO

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
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wolfhsm/wh_server.h"

/** Forward declarations */
#ifdef HAVE_ECC
static int wh_Server_HandleEccKeyGen(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);

static int wh_Server_HandleEccSharedSecret(whServerContext* ctx,
        whPacket* packet, uint16_t *out_size);

static int wh_Server_HandleEccSign(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);

static int wh_Server_HandleEccVerify(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Process a Generate curve25519_key request packet and produce a response */
static int wh_Server_HandleGenerateCurve25519Key(whServerContext* ctx,
        whPacket* packet, uint16_t *out_size);

/* Process a curve25519_key Function request packet and produce a response */
static int wh_Server_HandleSharedSecretCurve25519(whServerContext* ctx,
        whPacket* packet, uint16_t *out_size);
#endif /* HAVE_CURVE25519 */



/** Public server crypto functions */

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
    ret = hsmCacheFindSlotAndZero(ctx, max_size, &cacheBuf, &cacheMeta);
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
    ret = hsmFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);

    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_EccDeserializeKeyDer(cacheBuf, cacheMeta->len, key);
    }
    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
int wh_Server_CacheImportCurve25519Key(whServerContext* server,
        curve25519_key* key,
        whKeyId keyId, whNvmFlags flags, uint16_t label_len, uint8_t* label)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret;
    const uint16_t keySz = CURVE25519_KEYSIZE * 2;
    uint16_t size = 0;

    if (    (server == NULL) ||
            (key == NULL) ||
            (WH_KEYID_ISERASED(keyId)) ||
            ((label != NULL) && (label_len > sizeof(cacheMeta->label)))) {
        return WH_ERROR_BADARGS;
    }

    /* get a free slot */
    ret = hsmCacheFindSlotAndZero(server, keySz, &cacheBuf, &cacheMeta);
    if (ret == 0) {
        ret = wh_Crypto_SerializeCurve25519Key(key, keySz, cacheBuf, &size);
    }

    if (ret == 0) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = size;
        cacheMeta->flags = flags;
        cacheMeta->access = WH_NVM_ACCESS_ANY;

        if (    (label != NULL) &&
                (label_len > 0) ) {
            memcpy(cacheMeta->label, label, label_len);
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
    ret = hsmFreshenKey(server, keyId, &cacheBuf, &cacheMeta);

    if (ret == 0) {
        ret = wh_Crypto_DeserializeCurve25519Key(cacheMeta->len, cacheBuf, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] Export25519Key id:%u ret:%d\n", keyId, ret);
        wh_Utils_Hexdump("[server] export key:", cacheBuf, cacheMeta->len);
#endif
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifndef NO_RSA
static int hsmCacheKeyRsa(whServerContext* server, RsaKey* key, whKeyId* outId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = 0;
    /* wc_RsaKeyToDer doesn't have a length check option so we need to just pass
     * the big key size if compiled */
    const uint16_t keySz = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    whKeyId keyId = WH_MAKE_KEYID(  WH_KEYTYPE_CRYPTO,
                                    server->comm->client_id,
                                    WH_KEYID_ERASED);
    /* get a free slot */
    ret = hsmCacheFindSlotAndZero(server, keySz, &cacheBuf, &cacheMeta);
    if (ret == 0)
        ret = hsmGetUniqueId(server, &keyId);
    if (ret == 0) {
        /* export key */
        /* TODO: Fix wolfCrypto to allow KeyToDer when KEY_GEN is NOT set */
        ret = wc_RsaKeyToDer(key, cacheBuf, keySz);
    }
    if (ret > 0) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = ret;
        /* export keyId */
        *outId = keyId;
        ret = 0;
    }
    return ret;
}

static int hsmLoadKeyRsa(whServerContext* server, RsaKey* key, whKeyId keyId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = 0;
    uint32_t idx = 0;
    keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                          server->comm->client_id, keyId);
    /* freshen the key */
    ret = hsmFreshenKey(server, keyId, &cacheBuf, &cacheMeta);
    /* decode the key */
    if (ret == 0) {
        ret = wc_RsaPrivateKeyDecode(cacheBuf, (word32*)&idx, key,
            cacheMeta->len);
    }
    return ret;
}

#ifdef WOLFSSL_KEY_GEN
static int hsmCryptoRsaKeyGen(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    whKeyId keyId = WH_MAKE_KEYID(  WH_KEYTYPE_CRYPTO,
                                    server->comm->client_id,
                                    WH_KEYID_ERASED);
    /* init the rsa key */
    ret = wc_InitRsaKey_ex(server->crypto->algoCtx.rsa, NULL,
        server->crypto->devId);
    /* make the rsa key with the given params */
    if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -MakeRsaKey: size:%u, e:%u\n",
                (unsigned int)packet->pkRsakgReq.size,
                (unsigned int)packet->pkRsakgReq.e);
#endif
        ret = wc_MakeRsaKey(server->crypto->algoCtx.rsa,
            (word32)packet->pkRsakgReq.size, (long)packet->pkRsakgReq.e,
            server->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -MakeRsaKey: ret:%d\n", ret);
#endif
    }
    /* cache the generated key, data will be blown away */
    if (ret == 0) {
        ret = hsmCacheKeyRsa(server, server->crypto->algoCtx.rsa, &keyId);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -CacheKey: keyId:%u, ret:%d\n", keyId, ret);
#endif
    }
    wc_FreeRsaKey(server->crypto->algoCtx.rsa);
    if (ret == 0) {
        /* set the assigned id */
        packet->pkRsakgRes.keyId = WH_KEYID_ID(keyId);
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsakgRes);
    }
    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

static int hsmCryptoRsaFunction(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    word32 len;
    /* in and out are after the fixed size fields */
    byte* in = (uint8_t*)(&packet->pkRsaReq + 1);
    byte* out = (uint8_t*)(&packet->pkRsaRes + 1);
    /* init rsa key */
    ret = wc_InitRsaKey_ex(server->crypto->algoCtx.rsa, NULL,
        server->crypto->devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = hsmLoadKeyRsa(server, server->crypto->algoCtx.rsa,
            packet->pkRsaReq.keyId);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -LoadKeyRsa keyid %u:%d\n",
                (unsigned int)packet->pkRsaReq.keyId, ret);
#endif
    }
    /* do the rsa operation */
    if (ret == 0) {
        len = packet->pkRsaReq.outLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -RSAFunction in:%p %u, out:%p, opType:%d\n", in,
                (unsigned int)packet->pkRsaReq.inLen, out,
                (unsigned int)packet->pkRsaReq.opType);
#endif
        ret = wc_RsaFunction(in, packet->pkRsaReq.inLen, out, &len,
            packet->pkRsaReq.opType, server->crypto->algoCtx.rsa, server->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -RSAFunction outLen:%d, ret:%d\n", len, ret);
#endif
    }
    /* free the key */
    wc_FreeRsaKey(server->crypto->algoCtx.rsa);
    if (ret == 0) {
        /*set outLen */
        packet->pkRsaRes.outLen = len;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaRes) + len;
    }
    return ret;
}

static int hsmCryptoRsaGetSize(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    /* init rsa key */
    ret = wc_InitRsaKey_ex(server->crypto->algoCtx.rsa, NULL,
        server->crypto->devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = hsmLoadKeyRsa(server, server->crypto->algoCtx.rsa,
            packet->pkRsaGetSizeReq.keyId);
    }
    /* get the size */
    if (ret == 0)
        ret = wc_RsaEncryptSize(server->crypto->algoCtx.rsa);
    wc_FreeRsaKey(server->crypto->algoCtx.rsa);
    if (ret > 0) {
        /*set keySize */
        packet->pkRsaGetSizeRes.keySize = ret;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeRes);
        ret = 0;
    }
    return ret;
}
#endif /* !NO_RSA */




/** Request/Response Handling functions */

#ifdef HAVE_ECC
static int wh_Server_HandleEccKeyGen(whServerContext* ctx, whPacket* packet,
    uint16_t* out_size)
{
    int ret = WH_ERROR_OK;
    ecc_key key[1];
    wh_Packet_pk_eckg_req* req = &packet->pkEckgReq;
    wh_Packet_pk_eckg_res* res = &packet->pkEckgRes;

    /* Request message */
    int key_size        = req->sz;
    int curve_id        = req->curveId;
    whKeyId key_id      = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            req->keyId);
    whNvmFlags flags    = req->flags;
    uint8_t* label      = req->label;
    uint16_t label_size = WH_NVM_LABEL_LEN;

    /* Response message */
    uint8_t* res_out    = (uint8_t*)(res + 1);
    uint16_t max_size     = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (res_out - (uint8_t*)packet));
    uint16_t res_size   = 0;

    /* init ecc key */
    ret = wc_ecc_init_ex(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* generate the key */
        ret = wc_ecc_make_key_ex(ctx->crypto->rng, key_size, key, curve_id);
        if ( ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response message. */
                key_id = WH_KEYID_ERASED;
                ret = wh_Crypto_EccSerializeKeyDer(key, max_size, res_out,
                        &res_size);
            } else {
                /* Must import the key into the cache and return keyid */
                res_size = 0;
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = hsmGetUniqueId(ctx, &key_id);
    #ifdef DEBUG_CRYPTOCB
                    printf("[server] %s UniqueId: keyId:%u, ret:%d\n",
                            __func__, key_id, ret);
    #endif
                }
                ret = wh_Server_EccKeyCacheImport(ctx, key,
                        key_id, flags, label_size, label);
    #ifdef DEBUG_CRYPTOCB
                printf("[server] %s CacheImport: keyId:%u, ret:%d\n",
                        __func__, key_id, ret);
    #endif
            }
        }
        wc_ecc_free(key);
    }

    if (ret == WH_ERROR_OK) {
        res->keyId  = WH_KEYID_ID(key_id);
        res->len    = res_size;
        *out_size   = WH_PACKET_STUB_SIZE + sizeof(*res) + res_size;
    }
    return ret;
}

static int wh_Server_HandleEccSharedSecret(whServerContext* ctx,
        whPacket* packet, uint16_t *out_size)
{
    int ret = WH_ERROR_OK;
    ecc_key pub_key[1];
    ecc_key prv_key[1];

    wh_Packet_pk_ecdh_req* req = &packet->pkEcdhReq;
    wh_Packet_pk_ecdh_res* res = &packet->pkEcdhRes;

    /* Request message */
    uint32_t options    = req->options;
    int evict_pub       = options & WH_PACKET_PK_ECDH_OPTIONS_EVICTPUB;
    int evict_prv       = options & WH_PACKET_PK_ECDH_OPTIONS_EVICTPRV;
    whKeyId pub_key_id  = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            req->publicKeyId);
    whKeyId prv_key_id  = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            req->privateKeyId);

    /* Response message */
    byte* res_out       = (uint8_t*)(res + 1);
    word32 max_len      = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (res_out - (uint8_t*)packet));
    word32 res_len;

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
        (void)hsmEvictKey(ctx, pub_key_id);
    }
    if (evict_prv) {
        (void)hsmEvictKey(ctx, prv_key_id);
    }
    if (ret == 0) {
        res->sz = res_len;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(*res) + res_len;
    }
    return ret;
}

static int wh_Server_HandleEccSign(whServerContext* ctx, whPacket* packet,
    uint16_t *out_size)
{
    int ret;
    ecc_key key[1];
    wh_Packet_pk_ecc_sign_req* req = &packet->pkEccSignReq;
    wh_Packet_pk_ecc_sign_res* res = &packet->pkEccSignRes;

    /* Request message */
    byte* in        = (uint8_t*)(req + 1);
    whKeyId key_id  = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                        ctx->comm->client_id,
                                        req->keyId);
    word32 in_len   = req->sz;
    uint32_t options = req->options;
    int evict       = options & WH_PACKET_PK_ECCSIGN_OPTIONS_EVICT;

    /* Response message */
    byte* res_out   = (uint8_t*)(res + 1);
    word32 max_len  = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                        (res_out - (uint8_t*)packet));
    word32 res_len;

    /* init private key */
    ret = wc_ecc_init_ex(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* load the private key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* sign the input */
            res_len = max_len;
            ret = wc_ecc_sign_hash(in, in_len, res_out, &res_len,
                    ctx->crypto->rng, key);
        }
        wc_ecc_free(key);
    }
    if (evict != 0) {
        (void)hsmEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res->sz = res_len;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(*res) + res_len;
    }
    return ret;
}

static int wh_Server_HandleEccVerify(whServerContext* ctx,
        whPacket* packet, uint16_t *out_size)
{
    int ret;
    ecc_key key[1];
    wh_Packet_pk_ecc_verify_req* req = &packet->pkEccVerifyReq;
    wh_Packet_pk_ecc_verify_res* res = &packet->pkEccVerifyRes;

    /* Request Message */
    uint32_t options    = req->options;
    whKeyId key_id      = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            req->keyId);
    uint32_t hash_len   = req->hashSz;
    uint32_t sig_len    = req->sigSz;
    byte* req_sig       = (uint8_t*)(req + 1);
    byte* req_hash      = req_sig + sig_len;
    int evict           = options & WH_PACKET_PK_ECCVERIFY_OPTIONS_EVICT;
    int export_pub_key  = options & WH_PACKET_PK_ECCVERIFY_OPTIONS_EXPORTPUB;

    /* Response message */
    byte* res_pub       = (uint8_t*)(res + 1);
    word32 max_size     = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                                (res_pub - (uint8_t*)packet));
    uint16_t pub_size   = 0;
    int result;

    /* init public key */
    ret = wc_ecc_init_ex(key, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* load the public key */
        ret = wh_Server_EccKeyCacheExport(ctx, key_id, key);
        if (ret == WH_ERROR_OK) {
            /* verify the signature */
            ret = wc_ecc_verify_hash(req_sig, sig_len, req_hash, hash_len,
                &result, key);
            if (    (ret == 0) &&
                    (export_pub_key != 0) ) {
                /* Export the public key to the result message*/
                pub_size = wc_EccPublicKeyToDer(key, (byte*)res_pub,
                        max_size, 1);
                if (pub_size < 0) {
                    /* Problem dumping the public key.  Set to 0 length */
                    pub_size = 0;
                }
            }
        }
        wc_ecc_free(key);
    }
    if (evict != 0) {
        /* User requested to evict from cache, even if the call failed */
        (void)hsmEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        res->pubSz  = pub_size;
        res->res    = result;
        *out_size   = WH_PACKET_STUB_SIZE + sizeof(*res) + pub_size;
    }
    return ret;
}

#if 0
/* TODO: Implement check key */
static int hsmCryptoEcCheckPrivKey(whServerContext* server, whPacket* packet,
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
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
static int wh_Server_HandleGenerateCurve25519Key(whServerContext* server, whPacket* packet,
    uint16_t* out_size)
{
    int ret = WH_ERROR_OK;
    curve25519_key key[1];
    wh_Packet_pk_curve25519kg_req* req = &packet->pkCurve25519kgReq;
    wh_Packet_pk_curve25519kg_res* res = &packet->pkCurve25519kgRes;

    /* Request Message */
    int key_size        = req->sz;
    whKeyId key_id      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                            server->comm->client_id,
                            req->keyId);
    whNvmFlags flags    = req->flags;
    uint8_t* label      = req->label;
    uint16_t label_size = WH_NVM_LABEL_LEN;

    /* Response Message */
    uint8_t* out        = (uint8_t*)(res + 1);
    uint16_t max_size   = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (out - (uint8_t*)packet));
    uint16_t res_size   = 0;

    /* init key */
    ret = wc_curve25519_init_ex(key, NULL, server->crypto->devId);
    if (ret == 0) {
        /* make the key */
        ret = wc_curve25519_make_key(server->crypto->rng, key_size, key);
        if ( ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response packet */
                key_id = WH_KEYID_ERASED;
                ret = wh_Crypto_SerializeCurve25519Key(key, max_size,
                        out, &res_size);
            } else {
                /* Must import the key into the cache and return keyid */
                res_size = 0;
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = hsmGetUniqueId(server, &key_id);
#ifdef DEBUG_CRYPTOCB
                    printf("[server] %s UniqueId: keyId:%u, ret:%d\n",
                            __func__, key_id, ret);
#endif
                }

                ret = wh_Server_CacheImportCurve25519Key(server, key,
                        key_id, flags, label_size, label);
#ifdef DEBUG_CRYPTOCB
                    printf("[server] %s CacheImport: keyId:%u, ret:%d\n",
                            __func__, key_id, ret);
#endif
            }
        }
        wc_curve25519_free(key);
    }

    if (ret == 0) {
        res->keyId  = WH_KEYID_ID(key_id);
        res->len    = res_size;
        *out_size   = WH_PACKET_STUB_SIZE + sizeof(*res) + res_size;
    }
    return ret;
}

static int wh_Server_HandleSharedSecretCurve25519(whServerContext* ctx,
        whPacket* packet, uint16_t* out_size)
{
    int ret;
    curve25519_key priv[1] = {0};
    curve25519_key pub[1] = {0};

    wh_Packet_pk_curve25519_req* req = &packet->pkCurve25519Req;
    wh_Packet_pk_curve25519_res* res = &packet->pkCurve25519Res;

    /* Request message */
    uint32_t options    = req->options;
    int evict_pub       = options & WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPUB;
    int evict_prv       = options & WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPRV;
    whKeyId pub_key_id  = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            req->publicKeyId);
    whKeyId prv_key_id  = WH_MAKE_KEYID(    WH_KEYTYPE_CRYPTO,
                                            ctx->comm->client_id,
                                            req->privateKeyId);
    int endian          = req->endian;

    /* Response message */
    byte* res_out       = (uint8_t*)(res + 1);
    word32 max_len      = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (res_out - (uint8_t*)packet));
    word32 res_len      = max_len;

    /* init private key */
    ret = wc_curve25519_init_ex(priv, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* init public key */
        ret = wc_curve25519_init_ex(pub, NULL, ctx->crypto->devId);
        if (ret == 0) {
            ret = wh_Server_CacheExportCurve25519Key(
                    ctx, prv_key_id, priv);
            if (ret == 0) {
                ret = wh_Server_CacheExportCurve25519Key(
                        ctx, pub_key_id, pub);
            }
            if (ret == 0) {
                ret = wc_curve25519_shared_secret_ex(
                    priv, pub, res_out, &res_len, endian);
            }
            wc_curve25519_free(pub);
        }
        wc_curve25519_free(priv);
    }
    if (evict_pub) {
        (void)hsmEvictKey(ctx, pub_key_id);
    }
    if (evict_prv) {
        (void)hsmEvictKey(ctx, prv_key_id);
    }
    if (ret == 0) {
        res->sz = res_len;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(*res) + res_len;
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifndef NO_AES
#ifdef HAVE_AES_CBC
static int hsmCryptoAesCbc(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    word32 len;
    /* key, iv, in, and out are after fixed size fields */
    byte* key = (uint8_t*)(&packet->cipherAesCbcReq + 1);
    byte* iv = key + packet->cipherAesCbcReq.keyLen;
    byte* in = iv + AES_IV_SIZE;
    byte* out = (uint8_t*)(&packet->cipherAesCbcRes + 1);
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];
    /* use keyId and load from keystore if keyId is nonzero, must check for zero
     * since WH_KEYID_ERASED may not be zero while the client always defaults to
     * devCtx 0 */
    if (packet->cipherAesCbcReq.keyId != 0) {
        len = sizeof(tmpKey);
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->cipherAesCbcReq.keyId), NULL,
            tmpKey, (uint32_t*)&len);
        if (ret == 0) {
            /* set key to use tmpKey data */
            key = tmpKey;
            /* overwrite keyLen with internal length */
            packet->cipherAesCbcReq.keyLen = len;
        }
    }
    /* init key with possible hardware */
    if (ret == 0) {
        ret = wc_AesInit(server->crypto->algoCtx.aes, NULL,
            server->crypto->devId);
    }
    /* load the key */
    if (ret == 0) {
        ret = wc_AesSetKey(server->crypto->algoCtx.aes, key,
            (word32)packet->cipherAesCbcReq.keyLen, iv,
            packet->cipherAesCbcReq.enc == 1 ?
            AES_ENCRYPTION : AES_DECRYPTION);
    }
    /* do the crypto operation */
    if (ret == 0) {
        /* store this since it will be overwritten */
        len = packet->cipherAesCbcReq.sz;
        if (packet->cipherAesCbcReq.enc == 1)
            ret = wc_AesCbcEncrypt(server->crypto->algoCtx.aes, out, in, len);
        else
            ret = wc_AesCbcDecrypt(server->crypto->algoCtx.aes, out, in, len);
    }
    wc_AesFree(server->crypto->algoCtx.aes);
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        packet->cipherAesCbcRes.sz = len;
        *size = WH_PACKET_STUB_SIZE +
            sizeof(packet->cipherAesCbcRes) + len;
    }
    return ret;
}
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
static int hsmCryptoAesGcm(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    word32 len;
    /* key, iv, in, authIn, authTag, and out are after fixed size fields */
    byte* key = (uint8_t*)(&packet->cipherAesGcmReq + 1);
    byte* iv = key + packet->cipherAesGcmReq.keyLen;
    byte* in = iv + packet->cipherAesGcmReq.ivSz;
    byte* authIn = in + packet->cipherAesGcmReq.sz;
    byte* out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
    byte* authTag;
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];
    /* use keyId and load from keystore if keyId is nonzero, must check for zero
     * since WH_KEYID_ERASED may not be zero while the client always defaults to
     * devCtx 0 */
    if (packet->cipherAesGcmReq.keyId != 0) {
        len = sizeof(tmpKey);
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->cipherAesGcmReq.keyId),
            NULL, tmpKey, (uint32_t*)&len);
        if (ret == 0) {
            /* set key to use tmpKey data */
            key = tmpKey;
            /* overwrite keyLen with internal length */
            packet->cipherAesGcmReq.keyLen = len;
        }
    }
    /* init key with possible hardware */
    if (ret == 0) {
        ret = wc_AesInit(server->crypto->algoCtx.aes, NULL,
            server->crypto->devId);
    }
    /* load the key */
    if (ret == 0) {
        ret = wc_AesGcmSetKey(server->crypto->algoCtx.aes, key,
            packet->cipherAesGcmReq.keyLen);
    }
    /* do the crypto operation */
    if (ret == 0) {
        /* store this since it will be overwritten */
        len = packet->cipherAesGcmReq.sz;
        *size = 0;
        if (packet->cipherAesGcmReq.enc == 1) {
            /* set authTag as a packet output */
            authTag = out + len;
            *size += packet->cipherAesGcmReq.authTagSz;
            /* copy authTagSz since it will be overwritten */
            packet->cipherAesGcmRes.authTagSz =
                packet->cipherAesGcmReq.authTagSz;
            ret = wc_AesGcmEncrypt(server->crypto->algoCtx.aes, out, in, len,
                iv, packet->cipherAesGcmReq.ivSz, authTag,
                packet->cipherAesGcmReq.authTagSz, authIn,
                packet->cipherAesGcmReq.authInSz);
        }
        else {
            /* set authTag as a packet input */
            authTag = authIn + packet->cipherAesGcmReq.authInSz;
            ret = wc_AesGcmDecrypt(server->crypto->algoCtx.aes, out, in, len,
                iv, packet->cipherAesGcmReq.ivSz, authTag,
                packet->cipherAesGcmReq.authTagSz, authIn,
                packet->cipherAesGcmReq.authInSz);
        }
    }
    wc_AesFree(server->crypto->algoCtx.aes);
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        packet->cipherAesGcmRes.sz = len;
        *size += WH_PACKET_STUB_SIZE +
            sizeof(packet->cipherAesGcmRes) + len;
    }
    return ret;
}
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#ifdef WOLFSSL_CMAC
static int hsmCryptoCmac(whServerContext* server, whPacket* packet,
    uint16_t* size, uint16_t seq)
{
    whKeyId keyId = WH_KEYID_ERASED;
    int ret;
    int i;
    word32 len;
    word32 blockSz = AES_BLOCK_SIZE;
    uint16_t cancelSeq;
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];
    /* in, out and key are after the fixed size fields */
    byte* in = (uint8_t*)(&packet->cmacReq + 1);
    byte* key = in + packet->cmacReq.inSz;
    byte* out = (uint8_t*)(&packet->cmacRes + 1);
    whNvmMetadata meta[1] = {{0}};
    uint8_t moveToBigCache = 0;
    /* do oneshot if all fields are present */
    if (packet->cmacReq.inSz != 0 && packet->cmacReq.keySz != 0 &&
        packet->cmacReq.outSz != 0) {
        len = packet->cmacReq.outSz;
        ret = wc_AesCmacGenerate_ex(server->crypto->algoCtx.cmac, out, &len, in,
            packet->cmacReq.inSz, key, packet->cmacReq.keySz, NULL,
            server->crypto->devId);
        packet->cmacRes.outSz = len;
    }
    else {
        /* do each operation based on which fields are set */
        if (packet->cmacReq.keySz != 0) {
            /* initialize cmac with key and type */
            ret = wc_InitCmac_ex(server->crypto->algoCtx.cmac, key,
                packet->cmacReq.keySz, packet->cmacReq.type, NULL, NULL,
                server->crypto->devId);
        }
        /* Key is not present, meaning client wants to use AES key from
         * cache/nvm. In order to support multiple sequential CmacUpdate()
         * calls, we need to cache the whole CMAC struct between invocations
         * (which also holds the key). To do this we hijack the requested key's
         * cache slot until CmacFinal() is called, at which point we evict the
         * struct from the cache. TODO: client should hold CMAC state */
        else {
            len = sizeof(server->crypto->algoCtx.cmac);
            keyId = packet->cmacReq.keyId;
            ret = hsmReadKey(server,
                WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, keyId),
                NULL,
                (uint8_t*)server->crypto->algoCtx.cmac,
                (uint32_t*)&len);
            /* if the key size is a multiple of aes, init the key and
             * overwrite the existing key on exit */
            if (len == AES_128_KEY_SIZE || len == AES_192_KEY_SIZE ||
                len == AES_256_KEY_SIZE) {
                moveToBigCache = 1;
                XMEMCPY(tmpKey, (uint8_t*)server->crypto->algoCtx.cmac, len);
                ret = wc_InitCmac_ex(server->crypto->algoCtx.cmac, tmpKey, len,
                    WC_CMAC_AES, NULL, NULL, server->crypto->devId);
            }
            else if (len != sizeof(server->crypto->algoCtx.cmac))
                ret = BAD_FUNC_ARG;
        }
        /* Handle CMAC update, checking for cancellation */
        if (ret == 0 && packet->cmacReq.inSz != 0) {
            for (i = 0; ret == 0 && i < packet->cmacReq.inSz; i += AES_BLOCK_SIZE) {
                if (i + AES_BLOCK_SIZE > packet->cmacReq.inSz) {
                    blockSz = packet->cmacReq.inSz - i;
                }
                ret = wc_CmacUpdate(server->crypto->algoCtx.cmac, in + i,
                    blockSz);
                if (ret == 0) {
                    ret = wh_Server_GetCanceledSequence(server, &cancelSeq);
                    if (ret == 0 && cancelSeq == seq) {
                        ret = WH_ERROR_CANCEL;
                    }
                }
            }
        }
        /* do final and evict the struct if outSz is set, otherwise cache the
         * struct for a future call */
        if ((ret == 0 && packet->cmacReq.outSz != 0) || ret == WH_ERROR_CANCEL) {
            if (ret != WH_ERROR_CANCEL) {
                keyId = packet->cmacReq.keyId;
                len = packet->cmacReq.outSz;
                ret = wc_CmacFinal(server->crypto->algoCtx.cmac, out, &len);
                packet->cmacRes.outSz = len;
                packet->cmacRes.keyId = WH_KEYID_ERASED;
            }
            /* evict the key, canceling means abandoning the current state */
            if (ret == 0 || ret == WH_ERROR_CANCEL) {
                /* Don't override return value except on failure */
                int tmpRet = hsmEvictKey(
                    server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                               server->comm->client_id, keyId));
                if (tmpRet != 0) {
                    ret = tmpRet;
                }
            }
        }
        /* Cache the CMAC struct for a future update call */
        else if (ret == 0) {
            /* cache/re-cache updated struct */
            if (packet->cmacReq.keySz != 0) {
                keyId = WH_MAKE_KEYID(  WH_KEYTYPE_CRYPTO,
                                        server->comm->client_id,
                                        WH_KEYID_ERASED);
                ret = hsmGetUniqueId(server, &keyId);
            }
            else {
                keyId = WH_MAKE_KEYID(  WH_KEYTYPE_CRYPTO,
                                        server->comm->client_id,
                                        packet->cmacReq.keyId);
            }
            /* evict the aes sized key in the normal cache */
            if (moveToBigCache == 1) {
                ret = hsmEvictKey(server, keyId);
            }
            meta->id = keyId;
            meta->len = sizeof(server->crypto->algoCtx.cmac);
            ret = hsmCacheKey(server, meta, (uint8_t*)server->crypto->algoCtx.cmac);
            packet->cmacRes.keyId = WH_KEYID_ID(keyId);
            packet->cmacRes.outSz = 0;
        }
    }
    if (ret == 0) {
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->cmacRes) +
            packet->cmacRes.outSz;
    }
    return ret;
}
#endif

#ifndef NO_SHA256
static int hsmCryptoSha256(whServerContext* server, whPacket* packet,
                           uint16_t* size)
{
    int                        ret    = 0;
    wc_Sha256*                 sha256 = server->crypto->algoCtx.sha256;
    wh_Packet_hash_sha256_req* req    = &packet->hashSha256Req;
    wh_Packet_hash_sha256_res* res    = &packet->hashSha256Res;

    /* THe server SHA256 struct doesn't persist state (it is a union), meaning
     * the devId may get blown away between calls. We must restore the server
     * devId each time */
    sha256->devId = server->crypto->devId;

    /* Init the SHA256 context if this is the first time, otherwise restore the
     * hash state from the client */
    if (req->resumeState.hiLen == 0 && req->resumeState.loLen == 0) {
        ret = wc_InitSha256_ex(sha256, NULL, server->crypto->devId);
    }
    else {
        XMEMCPY(sha256->digest, req->resumeState.hash, WC_SHA256_DIGEST_SIZE);
        sha256->loLen = req->resumeState.loLen;
        sha256->hiLen = req->resumeState.hiLen;
    }

    if (req->isLastBlock) {
        /* wolfCrypt (or cryptoCb) is responsible for last block padding */
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, req->inBlock, req->lastBlockLen);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, res->hash);
        }
    }
    else {
        /* Client always sends full blocks, unless it's the last block */
        if (ret == 0) {
            ret = wc_Sha256Update(sha256, req->inBlock, WC_SHA256_BLOCK_SIZE);
        }
        /* Send the hash state back to the client */
        if (ret == 0) {
            XMEMCPY(res->hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
            res->loLen = sha256->loLen;
            res->hiLen = sha256->hiLen;
        }
    }

    return ret;
}
#endif /* !NO_SHA256 */



int wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size, uint16_t seq)
{
    int ret = 0;
    uint8_t* out;
    whPacket* packet = (whPacket*)data;
    if (    (server == NULL) ||
            (server->crypto == NULL) ||
            (data == NULL) ||
            (size == NULL) ) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    printf("[server] %s Begin action:%u\n", __func__, action);
#endif
    switch (action)
    {
    case WC_ALGO_TYPE_CIPHER:
        switch (packet->cipherAnyReq.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            ret = hsmCryptoAesCbc(server, (whPacket*)data, size);
            break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            ret = hsmCryptoAesGcm(server, (whPacket*)data, size);
            break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
    case WC_ALGO_TYPE_PK:
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -PK type:%u\n", (unsigned int)packet->pkAnyReq.type);
#endif
        switch (packet->pkAnyReq.type)
        {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
            ret = hsmCryptoRsaKeyGen(server, (whPacket*)data, size);
            break;
#endif  /* WOLFSSL_KEY_GEN */
        case WC_PK_TYPE_RSA:
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] RSA req recv. opType:%u inLen:%d keyId:%u outLen:%u type:%u\n",
                    (unsigned int)packet->pkRsaReq.opType,
                    (unsigned int)packet->pkRsaReq.inLen,
                    (unsigned int)packet->pkRsaReq.keyId,
                    (unsigned int)packet->pkRsaReq.outLen,
                    (unsigned int)packet->pkRsaReq.type);
#endif
            switch (packet->pkRsaReq.opType)
            {
            case RSA_PUBLIC_ENCRYPT:
            case RSA_PUBLIC_DECRYPT:
            case RSA_PRIVATE_ENCRYPT:
            case RSA_PRIVATE_DECRYPT:
                ret = hsmCryptoRsaFunction(server, (whPacket*)data, size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] RSA req recv. ret:%d type:%d\n",
                        ret, (unsigned int)packet->pkRsaRes.outLen);
#endif
                break;
            default:
                /* Invalid opType */
                ret = BAD_FUNC_ARG;
            }
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            ret = hsmCryptoRsaGetSize(server, (whPacket*)data, size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] RSA req getsize recv.Ret:%d\n", ret);
#endif
            break;
#endif /* !NO_RSA */

#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            ret = wh_Server_HandleEccKeyGen(server, packet, size);
            break;
        case WC_PK_TYPE_ECDH:
            ret = wh_Server_HandleEccSharedSecret(server, packet, size);
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            ret = wh_Server_HandleEccSign(server, packet, size);
            break;
        case WC_PK_TYPE_ECDSA_VERIFY:
            ret = wh_Server_HandleEccVerify(server, packet, size);
            break;
#if 0
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            ret = hsmCryptoEcCheckPrivKey(server, (whPacket*)data, size);
            break;
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
            ret = wh_Server_HandleGenerateCurve25519Key(server,
                    packet, size);
            break;
        case WC_PK_TYPE_CURVE25519:
            ret = wh_Server_HandleSharedSecretCurve25519(server,
                    packet, size);
            break;
#endif /* HAVE_CURVE25519 */
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
#ifndef WC_NO_RNG
    case WC_ALGO_TYPE_RNG:
        /* out is after the fixed size fields */
        out = (uint8_t*)(&packet->rngRes + 1);
        /* generate the bytes */
        ret = wc_RNG_GenerateBlock(server->crypto->rng, out, packet->rngReq.sz);
        if (ret == 0) {
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->rngRes) +
                packet->rngRes.sz;
        }
        break;
#endif /* !WC_NO_RNG */
#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
        ret = hsmCryptoCmac(server, (whPacket*)data, size, seq);
        break;
#endif

    case WC_ALGO_TYPE_HASH:
        switch (packet->hashAnyReq.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] SHA256 req recv. type:%u\n",
                        (unsigned int)packet->hashSha256Req.type);
#endif
                ret = hsmCryptoSha256(server, (whPacket*)data, size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                if (ret != 0) {
                    printf("[server] SHA256 ret = %d\n", ret);
                }
#endif
                break;
#endif /* !NO_SHA256 */

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

    /* Propagate error code to client in response packet */
    packet->rc = ret;

    if (ret != 0)
        *size = WH_PACKET_STUB_SIZE;

#ifdef DEBUG_CRYPTOCB
    printf("[server] %s End ret:%d\n", __func__, ret);
#endif

    /* Since crypto error codes are propagated to the client in the response
     * packet, return success to the caller unless a cancellation has occurred
     */
    if (ret != WH_ERROR_CANCEL) {
        ret = 0;
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA

#ifndef NO_SHA256
static int hsmCryptoSha256Dma(whServerContext* server, whPacket* packet,
                              uint16_t* size)
{
    int ret = 0;
#if WH_DMA_IS_32BIT
    wh_Packet_hash_sha256_Dma32_req* req = &packet->hashSha256Dma32Req;
    wh_Packet_hash_sha256_Dma32_res* res = &packet->hashSha256Dma32Res;
#else
    wh_Packet_hash_sha256_Dma64_req* req = &packet->hashSha256Dma64Req;
    wh_Packet_hash_sha256_Dma64_res* res = &packet->hashSha256Dma64Res;
#endif
    wc_Sha256* sha256 = server->crypto->algoCtx.sha256;
    int        clientDevId;

    /* Ensure state sizes are the same */
    if (req->state.sz != sizeof(*sha256)) {
        res->dmaCryptoRes.badAddr = req->state;
        return WH_ERROR_BADARGS;
    }

    /* Copy the SHA256 context from client address space */
    ret = whServerDma_CopyFromClient(server, sha256, req->state.addr,
                                       req->state.sz, (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        res->dmaCryptoRes.badAddr = req->state;
    }
    /* Save the client devId to be restored later, when the context is copied
     * back into client memory. */
    clientDevId = sha256->devId;
    /* overwrite the devId to that of the server for local crypto */
    sha256->devId = server->crypto->devId;

    /* TODO: perhaps we should sequentially update and finalize (need individual
     * flags as 0x0 could be a valid address?) just to future-proof, even though
     * sha256 cryptoCb doesn't currently have a one-shot*/

    /* If finalize requested, finalize the SHA256 operation, wrapping client
     * address accesses with the associated DMA address processing */
    if (ret == WH_ERROR_OK && req->finalize) {
        void* outAddr;
        ret = wh_Server_DmaProcessClientAddress(
            server, req->output.addr, &outAddr, req->output.sz,
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
                server, req->output.addr, &outAddr, req->output.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res->dmaCryptoRes.badAddr = req->output;
        }
    }
    else if (ret == WH_ERROR_OK) {
        /* Update requested, update the SHA256 operation, wrapping client
         * address accesses with the associated DMA address processing */
        void* inAddr;
        ret = wh_Server_DmaProcessClientAddress(
            server, req->input.addr, &inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});

        /* Update the SHA256 operation */
        if (ret == WH_ERROR_OK) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server]   wc_Sha256Update: inAddr=%p, sz=%llu\n", inAddr,
                   req->input.sz);
#endif
            ret = wc_Sha256Update(sha256, inAddr, req->input.sz);
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Server_DmaProcessClientAddress(
                server, req->input.addr, &inAddr, req->input.sz,
                WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        }

        if (ret == WH_ERROR_ACCESS) {
            res->dmaCryptoRes.badAddr = req->input;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Reset the devId in the local context to ensure it isn't copied back
         * to client memory */
        sha256->devId = clientDevId;
        /* Copy SHA256 context back into client memory */
        ret = whServerDma_CopyToClient(server, req->state.addr, sha256,
                                       req->state.sz, (whServerDmaFlags){0});
        if (ret != WH_ERROR_OK) {
            res->dmaCryptoRes.badAddr = req->state;
        }
    }

    /* return value populates packet->rc */
    return ret;
}
#endif /* ! NO_SHA256 */

int wh_Server_HandleCryptoDmaRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size, uint16_t seq)
{
    int ret = 0;
    whPacket* packet = (whPacket*)data;
    if (server == NULL || server->crypto == NULL || data == NULL || size == NULL)
        return BAD_FUNC_ARG;
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] Crypto DMA request. Action:%u\n", action);
#endif
    switch (action)
    {
    case WC_ALGO_TYPE_HASH:
        switch (packet->hashAnyReq.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] DMA SHA256 req recv. type:%u\n",
                        (unsigned int)packet->hashSha256Req.type);
#endif
                ret = hsmCryptoSha256Dma(server, (whPacket*)data, size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                if (ret != 0) {
                    printf("[server] DMA SHA256 ret = %d\n", ret);
                }
#endif
                break;
#endif /* !NO_SHA256 */

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

    /* Propagate error code to client in response packet */
    packet->rc = ret;

    if (ret != 0)
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->rc);

    /* Since crypto error codes are propagated to the client in the response
     * packet, return success to the caller unless a cancellation has occurred
     */
    if (ret != WH_ERROR_CANCEL) {
        ret = 0;
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
