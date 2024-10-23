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
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
/* Process a Generate RsaKey request packet and produce a response packet */
static int _HandleRsaKeyGen(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);
#endif /* WOLFSSL_KEY_GEN */

/* Process a Rsa Function request packet and produce a response packet */
static int _HandleRsaFunction(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);
/* Process a Rsa Get Size request packet and produce a response packet */
static int _HandleRsaGetSize(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);
#endif /* !NO_RSA */

#ifndef NO_AES

#ifdef HAVE_AESGCM
static int _HandleAesGcm(whServerContext* ctx, whPacket* packet,
        uint16_t* out_size);
#endif

#endif /* !NO_AES */

#ifdef HAVE_ECC
static int _HandleEccKeyGen(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);

static int _HandleEccSharedSecret(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);

static int _HandleEccSign(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);

static int _HandleEccVerify(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);
#if 0
static int _HandleEccCheckPrivKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
#endif

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Process a Generate curve25519_key request packet and produce a response */
static int _HandleCurve25519KeyGen(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);

/* Process a curve25519_key Function request packet and produce a response */
static int _HandleCurve25519SharedSecret(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size);
#endif /* HAVE_CURVE25519 */


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
    ret = hsmCacheFindSlotAndZero(ctx, max_size, &cacheBuf, &cacheMeta);
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
    ret = hsmFreshenKey(ctx, keyId, &cacheBuf, &cacheMeta);

    if (ret == 0) {
        ret = wh_Crypto_RsaDeserializeKeyDer(cacheMeta->len, cacheBuf, key);
    }
    return ret;
}

#ifdef WOLFSSL_KEY_GEN
static int _HandleRsaKeyGen(whServerContext* ctx,
        whPacket* packet, uint16_t *out_size)
{
    int ret = 0;
    RsaKey rsa[1] = {0};
    int key_size        = packet->pkRsakgReq.size;
    long e              = packet->pkRsakgReq.e;

    /* Force incoming key_id to have current user/type */
    whKeyId key_id      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                            ctx->comm->client_id,
                            packet->pkRsakgReq.keyId);
    whNvmFlags flags    = packet->pkRsakgReq.flags;
    uint8_t* label      = packet->pkRsakgReq.label;
    uint32_t label_size = WH_NVM_LABEL_LEN;

    uint8_t* out        = (uint8_t*)(&packet->pkRsakgRes + 1);
    word32 max_size     = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (out - (uint8_t*)packet));
    uint16_t der_size        = 0;

    /* init the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, ctx->crypto->devId);
    if (ret == 0) {
        /* make the rsa key with the given params */
        ret = wc_MakeRsaKey(rsa, key_size, e, ctx->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] MakeRsaKey: size:%d, e:%ld, ret:%d\n",
                key_size, e, ret);
#endif

        if ( ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response packet */
                ret = wh_Crypto_RsaSerializeKeyDer(rsa, max_size, out, &der_size);
                if (ret == 0) {
                    packet->pkRsakgRes.keyId = 0;
                    packet->pkRsakgRes.len = der_size;
                }
            } else {
                /* Must import the key into the cache and return keyid */
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = hsmGetUniqueId(ctx, &key_id);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] RsaKeyGen UniqueId: keyId:%u, ret:%d\n", key_id, ret);
#endif
                }

                ret = wh_Server_CacheImportRsaKey(ctx, rsa,
                        key_id, flags, label_size, label);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] RsaKeyGen CacheKeyRsa: keyId:%u, ret:%d\n", key_id, ret);
#endif
                packet->pkRsakgRes.keyId = (key_id & WH_KEYID_MASK);
                packet->pkRsakgRes.len = 0;
            }
        }
        wc_FreeRsaKey(rsa);
    }

    if (ret == 0) {
        /* set the assigned id */
        *out_size = WH_PACKET_STUB_SIZE +
                sizeof(packet->pkRsakgRes) +
                packet->pkRsakgRes.len;
    }
    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

static int _HandleRsaFunction(whServerContext* ctx, whPacket* packet,
    uint16_t *out_size)
{
    int ret;
    RsaKey rsa[1];

    int op_type         = (int)(packet->pkRsaReq.opType);
    uint32_t options    = packet->pkRsaReq.options;
    int evict           = !!(options & WH_PACKET_PK_ECCSIGN_OPTIONS_EVICT);

    whKeyId key_id      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                            ctx->comm->client_id,
                            packet->pkRsaReq.keyId);
    word32 in_len       = (word32)(packet->pkRsaReq.inLen);
    word32 out_len      = (word32)(packet->pkRsaReq.outLen);
    /* in and out are after the fixed size fields */
    byte* in            = (uint8_t*)(&packet->pkRsaReq + 1);
    byte* out           = (uint8_t*)(&packet->pkRsaRes + 1);

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
        (void)hsmEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        /*set outLen and outgoing message size */
        packet->pkRsaRes.outLen = out_len;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaRes) + out_len;
    }
    return ret;
}

static int _HandleRsaGetSize(whServerContext* ctx, whPacket* packet,
    uint16_t *out_size)
{
    int ret;
    RsaKey rsa[1];
    whKeyId key_id      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                            ctx->comm->client_id,
                            packet->pkRsaGetSizeReq.keyId);
    uint32_t options    = packet->pkRsaGetSizeReq.options;
    int evict           = !!(options & WH_PACKET_PK_RSA_GET_SIZE_OPTIONS_EVICT);

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
        (void)hsmEvictKey(ctx, key_id);
    }
    if (ret == 0) {
        /*set keySize */
        packet->pkRsaGetSizeRes.keySize = key_size;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeRes);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] %s keyId:%d, key_size:%d, ret:%d\n",
                __func__, key_id, key_size, ret);
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
        ret = wh_Crypto_Curve25519SerializeKey(key, keySz, cacheBuf, &size);
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
        ret = wh_Crypto_Curve25519DeserializeKey(cacheMeta->len, cacheBuf, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] Export25519Key id:%u ret:%d\n", keyId, ret);
        wh_Utils_Hexdump("[server] export key:", cacheBuf, cacheMeta->len);
#endif
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */


/** Request/Response Handling functions */

#ifdef HAVE_ECC
static int _HandleEccKeyGen(whServerContext* ctx, whPacket* packet,
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

static int _HandleEccSharedSecret(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size)
{
    int ret = WH_ERROR_OK;
    ecc_key pub_key[1];
    ecc_key prv_key[1];

    wh_Packet_pk_ecdh_req* req = &packet->pkEcdhReq;
    wh_Packet_pk_ecdh_res* res = &packet->pkEcdhRes;

    /* Request message */
    uint32_t options    = req->options;
    int evict_pub       = !!(options & WH_PACKET_PK_ECDH_OPTIONS_EVICTPUB);
    int evict_prv       = !!(options & WH_PACKET_PK_ECDH_OPTIONS_EVICTPRV);
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

static int _HandleEccSign(whServerContext* ctx, whPacket* packet,
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
    int evict       = !!(options & WH_PACKET_PK_ECCSIGN_OPTIONS_EVICT);

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

static int _HandleEccVerify(whServerContext* ctx, whPacket* packet,
        uint16_t *out_size)
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
    int evict           = !!(options & WH_PACKET_PK_ECCVERIFY_OPTIONS_EVICT);
    int export_pub_key  = !!(options & WH_PACKET_PK_ECCVERIFY_OPTIONS_EXPORTPUB);

    /* Response message */
    byte* res_pub       = (uint8_t*)(res + 1);
    word32 max_size     = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                                (res_pub - (uint8_t*)packet));
    uint32_t pub_size   = 0;
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
                ret = wc_EccPublicKeyToDer(key, (byte*)res_pub,
                        max_size, 1);
                if (ret < 0) {
                    /* Problem dumping the public key.  Set to 0 length */
                    pub_size = 0;
                } else {
                    pub_size = ret;
                    ret = 0;
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
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
static int _HandleCurve25519KeyGen(whServerContext* server, whPacket* packet,
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
                ret = wh_Crypto_Curve25519SerializeKey(key, max_size,
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

static int _HandleCurve25519SharedSecret(whServerContext* ctx, whPacket* packet, uint16_t* out_size)
{
    int ret;
    curve25519_key priv[1] = {0};
    curve25519_key pub[1] = {0};

    wh_Packet_pk_curve25519_req* req = &packet->pkCurve25519Req;
    wh_Packet_pk_curve25519_res* res = &packet->pkCurve25519Res;

    /* Request message */
    uint32_t options    = req->options;
    int evict_pub       = !!(options & WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPUB);
    int evict_prv       = !!(options & WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPRV);
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
static int _HandleAesCbc(whServerContext* ctx, whPacket* packet,
        uint16_t* size)
{
    int ret = 0;
    Aes aes[1] = {0};
    uint8_t read_key[AES_MAX_KEY_SIZE];
    uint32_t read_key_len = sizeof(read_key);

    wh_Packet_cipher_aescbc_req* req = &packet->cipherAesCbcReq;
    wh_Packet_cipher_aescbc_res* res = &packet->cipherAesCbcRes;

    uint32_t enc = req->enc;
    uint32_t key_len = req->keyLen;
    uint32_t len = req->sz;
    whKeyId key_id = WH_MAKE_KEYID(
                        WH_KEYTYPE_CRYPTO,
                        ctx->comm->client_id,
                        req->keyId);

    /* in, key, iv, and out are after fixed size fields */
    uint8_t* in = (uint8_t*)(req + 1);
    uint8_t* key = in + len;
    uint8_t* iv = key + key_len;

    uint8_t* out = (uint8_t*)(res + 1);

    /* Read the key if it is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        ret = hsmReadKey(ctx, key_id, NULL, read_key, &read_key_len);
        if (ret == 0) {
            /* override the incoming values */
            key = read_key;
            key_len = read_key_len;
        }
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
            } else {
                ret = wc_AesCbcDecrypt(aes, (byte*)out, (byte*)in, (word32)len);
            }
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        res->sz = len;
        *size = WH_PACKET_STUB_SIZE + sizeof(*res) + len;
    }
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
static int _HandleAesGcm(whServerContext* ctx, whPacket* packet,
        uint16_t* out_size)
{
    int ret = 0;
    Aes aes[1] = {0};

    wh_Packet_cipher_aesgcm_req* req = &packet->cipherAesGcmReq;
    wh_Packet_cipher_aesgcm_res* res = &packet->cipherAesGcmRes;

    uint32_t enc        = req->enc;
    uint32_t key_len    = req->keyLen;
    uint32_t len        = req->sz;
    uint32_t iv_len     = req->ivSz;
    uint32_t authin_len = req->authInSz;
    uint32_t tag_len    = req->authTagSz;
    whKeyId key_id      = WH_MAKE_KEYID(
                            WH_KEYTYPE_CRYPTO,
                            ctx->comm->client_id,
                            req->keyId);

    /* Request packet */
    uint8_t* in         = (uint8_t*)(req + 1);
    uint8_t* key        = in + len;
    uint8_t* iv         = key + key_len;
    uint8_t* authin     = iv + iv_len;
    uint8_t* dec_tag    = authin + authin_len;

    uint32_t req_len    = WH_PACKET_STUB_SIZE + sizeof(*req) + len +
                            key_len + iv_len + authin_len +
                            ((enc == 0) ? tag_len : 0);
    (void)req_len;

    /* Response packet */
    uint8_t* out        = (uint8_t*)(res + 1);
    uint8_t* enc_tag    = out + len;

    uint32_t res_len    = WH_PACKET_STUB_SIZE+ sizeof(*res) + len +
                            ((enc == 0) ? 0: tag_len);

    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];

#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] AESGCM: enc:%d keylen:%d ivsz:%d insz:%d authinsz:%d authtagsz:%d reqsz:%u ressz:%u\n",
                        enc, key_len, iv_len, len, authin_len, tag_len,
                        req_len, res_len);
            printf("[server] AESGCM: req:%p in:%p key:%p iv:%p authin:%p dec_tag:%p res:%p out:%p enc_tag:%p\n",
                    req, in, key, iv, authin, dec_tag, res, out, enc_tag);
            wh_Utils_Hexdump("[server] AESGCM req packet: \n", (uint8_t*)packet, req_len);
#endif
    /* use keyId and load from keystore if keyId is not erased */
    if (!WH_KEYID_ISERASED(key_id)) {
        key_len = sizeof(tmpKey);
        ret = hsmReadKey(ctx, key_id, NULL, tmpKey, &key_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] AesGcm ReadKey key_id:%u, key_len:%d ret:%d\n",
                key_id, key_len, ret);
#endif
        if (ret == 0) {
            /* set key to use tmpKey data */
            key = tmpKey;
        }
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, ctx->crypto->devId);
    }
    if (ret == 0) {
        /* load the key */
        ret = wc_AesGcmSetKey(aes, key, key_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] AesGcmSetKey key_id:%u key_len:%u ret:%d\n",
                key_id, key_len, ret);
        wh_Utils_Hexdump("[server] key: ", key, key_len);
#endif
        if (ret == 0) {
            /* do the crypto operation */
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] enc:%d len:%d, ivSz:%d authTagSz:%d, authInSz:%d\n",
                    enc, len,iv_len, tag_len, authin_len);
            wh_Utils_Hexdump("[server] in: ", in, len);
            wh_Utils_Hexdump("[server] iv: ", iv, iv_len);
            wh_Utils_Hexdump("[server] authin: ", authin,  authin_len);
#endif
            if (enc != 0) {
                ret = wc_AesGcmEncrypt(aes, out,
                    in, len,
                    iv, iv_len,
                    enc_tag, tag_len,
                    authin, authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] enc ret:%d\n",ret);
                wh_Utils_Hexdump("[server] out: \n", out, len);
                wh_Utils_Hexdump("[server] enc tag: ", enc_tag,  tag_len);
#endif
            } else {
                /* set authTag as a packet input */
#ifdef DEBUG_CRYPTOCB_VERBOSE
                wh_Utils_Hexdump("[server] dec tag: ", dec_tag,  tag_len);
#endif
                ret = wc_AesGcmDecrypt(aes, out,
                    in, len,
                    iv, iv_len,
                    dec_tag, tag_len,
                    authin, authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] dec ret:%d\n",ret);
                wh_Utils_Hexdump("[server] out: \n", out, len);

                #endif
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[server] post iv: ", iv, iv_len);
            wh_Utils_Hexdump("[server] post authin: ", authin,  authin_len);
#endif
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
        res->sz = len;
        res->authTagSz = (enc == 0) ? 0 : tag_len;
        *out_size = res_len;
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] res out_size:%d\n", *out_size);
        wh_Utils_Hexdump("[server] AESGCM res packet: \n", (uint8_t*)packet, res_len);

#endif
        /*
        memcpy(packet, res_packet, res_len);
        */
    }
    return ret;
}
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#ifdef WOLFSSL_CMAC
static int _HandleCmac(whServerContext* server, whPacket* packet,
    uint16_t* size, uint16_t seq)
{
    int ret;

    switch(packet->cmacReq.type) {
#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    case WC_CMAC_AES:
    {
        int i;
        whKeyId keyId = WH_KEYID_ERASED;
        word32 len;
        uint16_t cancelSeq;
        /* in, out and key are after the fixed size fields */
        byte* in = (uint8_t*)(&packet->cmacReq + 1);
        byte* key = in + packet->cmacReq.inSz;
        byte* out = (uint8_t*)(&packet->cmacRes + 1);
        whNvmMetadata meta[1] = {{0}};
        uint8_t moveToBigCache = 0;
        word32 blockSz = AES_BLOCK_SIZE;
        uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];

        /* attempt oneshot if all fields are present */
        if (packet->cmacReq.inSz != 0 && packet->cmacReq.keySz != 0 &&
            packet->cmacReq.outSz != 0) {
            len = packet->cmacReq.outSz;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] cmac generate oneshot\n");
#endif
                ret = wc_AesCmacGenerate_ex(server->crypto->algoCtx.cmac, out, &len, in,
                    packet->cmacReq.inSz, key, packet->cmacReq.keySz, NULL,
                    server->crypto->devId);
                packet->cmacRes.outSz = len;
        } else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] cmac begin keySz:%d inSz:%d outSz:%d keyId:%x\n",
                    packet->cmacReq.keySz,
                    packet->cmacReq.inSz,
                    packet->cmacReq.outSz,
                    packet->cmacReq.keyId);
#endif
            /* do each operation based on which fields are set */
            if (packet->cmacReq.keySz != 0) {
                /* initialize cmac with key and type */
                ret = wc_InitCmac_ex(server->crypto->algoCtx.cmac, key,
                    packet->cmacReq.keySz, packet->cmacReq.type, NULL, NULL,
                    server->crypto->devId);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac init with key:%p keylen:%d, type:%d ret:%d\n",
                        key, packet->cmacReq.keySz, packet->cmacReq.type, ret);
#endif
            } else {
                /* Key is not present, meaning client wants to use AES key from
                 * cache/nvm. In order to support multiple sequential CmacUpdate()
                 * calls, we need to cache the whole CMAC struct between invocations
                 * (which also holds the key). To do this we hijack the requested key's
                 * cache slot until CmacFinal() is called, at which point we evict the
                 * struct from the cache. TODO: client should hold CMAC state */
                len = sizeof(server->crypto->algoCtx.cmac);
                keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, packet->cmacReq.keyId);
                ret = hsmReadKey(server,
                    keyId,
                    NULL,
                    (uint8_t*)server->crypto->algoCtx.cmac,
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
                        XMEMCPY(tmpKey, (uint8_t*)server->crypto->algoCtx.cmac, len);
                        ret = wc_InitCmac_ex(server->crypto->algoCtx.cmac, tmpKey, len,
                            WC_CMAC_AES, NULL, NULL, server->crypto->devId);
                    }
                    else if (len != sizeof(server->crypto->algoCtx.cmac)) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        printf("[server] cmac bad readkey len:%u. sizeof(cmac):%lu\n",
                                len, sizeof(server->crypto->algoCtx.cmac));
#endif
                        ret = BAD_FUNC_ARG;
                    }
                } else {
                    /* Initialize the cmac with a NULL key */
                    /* initialize cmac with key and type */
                    ret = wc_InitCmac_ex(server->crypto->algoCtx.cmac, NULL,
                        packet->cmacReq.keySz, packet->cmacReq.type, NULL, NULL,
                        server->crypto->devId);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] cmac init with NULL type:%d ret:%d\n",
                            packet->cmacReq.type, ret);
#endif
                }
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac update done. ret:%d\n", ret);
#endif
            }
            /* do final and evict the struct if outSz is set, otherwise cache the
             * struct for a future call */
            if ((ret == 0 && packet->cmacReq.outSz != 0) || ret == WH_ERROR_CANCEL) {
                if (ret != WH_ERROR_CANCEL) {
                    keyId = packet->cmacReq.keyId;
                    len = packet->cmacReq.outSz;
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] cmac final keyId:%x len:%d\n",keyId, len);
#endif
                    ret = wc_CmacFinal(server->crypto->algoCtx.cmac, out, &len);
                    packet->cmacRes.outSz = len;
                    packet->cmacRes.keyId = WH_KEYID_ERASED;
                }
                /* evict the key, canceling means abandoning the current state */
                if (ret == 0 || ret == WH_ERROR_CANCEL) {
                    if (!WH_KEYID_ISERASED(keyId)) {
                        /* Don't override return value except on failure */
                        int tmpRet = hsmEvictKey(
                            server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                                       server->comm->client_id, keyId));
                        if (tmpRet != 0) {
                            ret = tmpRet;
                        }
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] cmac saved state in keyid:%x %x len:%u ret:%d type:%d\n",
                        keyId, WH_KEYID_ID(keyId), meta->len, ret, server->crypto->algoCtx.cmac->type);
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
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->cmacRes) +
            packet->cmacRes.outSz;
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] cmac end ret:%d\n", ret);
#endif
    return ret;
}
#endif

#ifndef NO_SHA256
static int _HandleSha256(whServerContext* server, whPacket* packet,
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

int wh_Server_HandleCryptoRequest(whServerContext* ctx,
    uint16_t action, uint8_t* data, uint16_t *inout_size, uint16_t seq)
{
    int ret = 0;
    uint8_t* out;
    whPacket* packet = (whPacket*)data;

    if (    (ctx == NULL) ||
            (ctx->crypto == NULL) ||
            (data == NULL) ||
            (inout_size == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] HandleCryptoRequest. Action:%u\n", action);
#endif
    switch (action)
    {
    case WC_ALGO_TYPE_CIPHER:
        switch (packet->cipherAnyReq.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            ret = _HandleAesCbc(ctx, packet, inout_size);
            break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            ret = _HandleAesGcm(ctx, packet, inout_size);
            break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
    case WC_ALGO_TYPE_PK:
    {
        int type = (int)(packet->pkAnyReq.type);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] PK type:%d\n", type);
#endif
        switch (type)
        {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
            ret = _HandleRsaKeyGen(ctx, packet, inout_size);
            break;
#endif  /* WOLFSSL_KEY_GEN */
        case WC_PK_TYPE_RSA:
            ret = _HandleRsaFunction(ctx, packet, inout_size);
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            ret = _HandleRsaGetSize(ctx, packet, inout_size);
            break;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            ret = _HandleEccKeyGen(ctx, packet, inout_size);
            break;
        case WC_PK_TYPE_ECDH:
            ret = _HandleEccSharedSecret(ctx, packet, inout_size);
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            ret = _HandleEccSign(ctx, packet, inout_size);
            break;
        case WC_PK_TYPE_ECDSA_VERIFY:
            ret = _HandleEccVerify(ctx, packet, inout_size);
            break;
#if 0
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            ret = _HandleEccCheckPrivKey(ctx, (whPacket*)data, inout_size);
            break;
#endif
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
            ret = _HandleCurve25519KeyGen(ctx,
                    packet, inout_size);
            break;
        case WC_PK_TYPE_CURVE25519:
            ret = _HandleCurve25519SharedSecret(ctx,
                    packet, inout_size);
            break;
#endif /* HAVE_CURVE25519 */

        default:
            ret = NOT_COMPILED_IN;
            break;
        }
    }; break;

#ifndef WC_NO_RNG
    case WC_ALGO_TYPE_RNG:
        /* out is after the fixed size fields */
        out = (uint8_t*)(&packet->rngRes + 1);
        /* generate the bytes */
        ret = wc_RNG_GenerateBlock(ctx->crypto->rng, out, packet->rngReq.sz);
        if (ret == 0) {
            *inout_size = WH_PACKET_STUB_SIZE + sizeof(packet->rngRes) +
                packet->rngRes.sz;
        }
        break;
#endif /* !WC_NO_RNG */
#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
        ret = _HandleCmac(ctx, packet, inout_size, seq);
        break;
#endif

    case WC_ALGO_TYPE_HASH:
        switch (packet->hashAnyReq.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] SHA256 req recv. type:%u\n",
                       packet->hashSha256Req.type);
#endif
                ret = _HandleSha256(ctx, packet, inout_size);
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
        *inout_size = WH_PACKET_STUB_SIZE;

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
static int _HandleSha256Dma(whServerContext* server, whPacket* packet,
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
                ret = _HandleSha256Dma(server, (whPacket*)data, size);
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
