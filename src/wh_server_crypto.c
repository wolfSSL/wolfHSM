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

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wolfhsm/wh_server.h"

#if defined(DEBUG_CRYPTOCB) || defined(DEBUG_CRYPTOCB_VERBOSE)
#include <stdio.h>
#endif

#ifdef DEBUG_CRYPTOCB_VERBOSE
static void _hexdump(const char* initial,uint8_t* ptr, size_t size)
{
    int count = 0;
    if(initial != NULL)
        printf("%s",initial);
    while(size > 0) {
        printf ("%02X ", *ptr);
        ptr++;
        size --;
        count++;
        if (count %16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}
#endif

#ifndef NO_RSA

/* Store a RsaKey into a server key cache with optional metadata */
static int wh_Server_CacheImportRsaKey(whServerContext* server, RsaKey* key,
        whKeyId keyId, whNvmFlags flags, uint32_t label_len, uint8_t* label);
/* Restore a RsaKey from a server key cache */
static int wh_Server_CacheExportRsaKey(whServerContext* server, whKeyId keyId,
        RsaKey* key);

#ifdef WOLFSSL_KEY_GEN
/* Process a Generate RsaKey request packet and produce a response packet */
static int wh_Server_HandleGenerateRsaKey(whServerContext* server,
        whPacket* packet, uint16_t *out_size);
#endif /* WOLFSSL_KEY_GEN */

/* Process a Rsa Function request packet and produce a response packet */
static int wh_Server_HandleRsaFunction(whServerContext* server,
        whPacket* packet, uint16_t *out_size);
/* Process a Rsa Get Size request packet and produce a response packet */
static int wh_server_HandleRsaGetSize(whServerContext* server,
        whPacket* packet, uint16_t *out_size);



static int wh_Server_CacheImportRsaKey(whServerContext* server, RsaKey* key,
        whKeyId keyId, whNvmFlags flags, uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    uint16_t max_size;
    uint16_t der_size;

    if (    (server == NULL) ||
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
    ret = hsmCacheFindSlotAndZero(server, max_size, &cacheBuf, &cacheMeta);
    if (ret == 0) {
        ret = wh_Crypto_SerializeRsaKey(key, max_size, cacheBuf, &der_size);
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

static int wh_Server_CacheExportRsaKey(whServerContext* server, whKeyId keyId,
        RsaKey* key)
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
        wh_Crypto_DeserializeRsaKey(cacheMeta->len, cacheBuf, key);
    }
    return ret;
}

#ifdef WOLFSSL_KEY_GEN
static int wh_Server_HandleGenerateRsaKey(whServerContext* server,
        whPacket* packet, uint16_t *out_size)
{
    int ret = 0;
    RsaKey rsa[1] = {0};
    int key_size        = packet->pkRsakgReq.size;
    long e              = packet->pkRsakgReq.e;

    /* Force incoming key_id to have current user/type */
    whKeyId key_id      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                            server->comm->client_id,
                            packet->pkRsakgReq.keyId);
    whNvmFlags flags    = packet->pkRsakgReq.flags;
    uint8_t* label      = packet->pkRsakgReq.label;
    uint32_t label_size = WH_NVM_LABEL_LEN;

    uint8_t* out        = (uint8_t*)(&packet->pkRsakgRes + 1);
    word32 max_size     = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (out - (uint8_t*)packet));
    uint16_t der_size        = 0;

    /* init the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, server->crypto->devId);
    if (ret == 0) {
        /* make the rsa key with the given params */
        ret = wc_MakeRsaKey(rsa, key_size, e, server->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] MakeRsaKey: size:%d, e:%ld, ret:%d\n",
                key_size, e, ret);
#endif

        if ( ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response packet */
                ret = wh_Crypto_SerializeRsaKey(rsa, max_size, out, &der_size);
                if (ret == 0) {
                    packet->pkRsakgRes.keyId = 0;
                    packet->pkRsakgRes.len = der_size;
                }
            } else {
                /* Must import the key into the cache and return keyid */
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = hsmGetUniqueId(server, &key_id);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] RsaKeyGen UniqueId: keyId:%u, ret:%d\n", key_id, ret);
#endif
                }

                ret = wh_Server_CacheImportRsaKey(server, rsa,
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

static int wh_Server_HandleRsaFunction(whServerContext* server, whPacket* packet,
    uint16_t *out_size)
{
    int ret;
    RsaKey rsa[1] = {0};

    int op_type     = (int)(packet->pkRsaReq.opType);
    whKeyId key_id  = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                        server->comm->client_id,
                        packet->pkRsaReq.keyId);
    word32 in_len   = (word32)(packet->pkRsaReq.inLen);
    word32 out_len  = (word32)(packet->pkRsaReq.outLen);
    /* in and out are after the fixed size fields */
    byte* in        = (uint8_t*)(&packet->pkRsaReq + 1);
    byte* out       = (uint8_t*)(&packet->pkRsaRes + 1);

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
        return BAD_FUNC_ARG;
    }

    /* init rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, server->crypto->devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = wh_Server_CacheExportRsaKey(server, key_id, rsa);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] CacheExportRsaKey keyid:%u, ret:%d\n", key_id, ret);
#endif
        if (ret == 0) {
            /* do the rsa operation */
            ret = wc_RsaFunction(in, in_len, out, &out_len,
                op_type, rsa, server->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] RsaFunction in:%p %u, out:%p, opType:%d, outLen:%d, ret:%d\n",
                    in, in_len, out, op_type, out_len, ret);
#endif
        }
        /* free the key */
        wc_FreeRsaKey(rsa);
    }
    if (ret == 0) {
        /*set outLen and outgoing message size */
        packet->pkRsaRes.outLen = out_len;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaRes) + out_len;
    }
    return ret;
}

static int wh_server_HandleRsaGetSize(whServerContext* server, whPacket* packet,
    uint16_t *out_size)
{
    int ret;
    RsaKey rsa[1] = {0};
    whKeyId key_id= WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id,
            packet->pkRsaGetSizeReq.keyId);
    int key_size = 0;

    /* init rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, server->crypto->devId);
    /* load the key from the keystore */
    if (ret == 0) {
        ret = wh_Server_CacheExportRsaKey(server, key_id, rsa);
        /* get the size */
        if (ret == 0) {
            key_size = wc_RsaEncryptSize(rsa);
            if (key_size < 0) {
                ret = key_size;
            }
        }
        wc_FreeRsaKey(rsa);
    }
    if (ret == 0) {
        /*set keySize */
        packet->pkRsaGetSizeRes.keySize = key_size;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeRes);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] RsaGetSize keyId:%d, key_size:%d, ret:%d\n",
                key_id, key_size, ret);
#endif
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_CURVE25519

/* Store a curve25519_key into a server key cache with optional metadata */
static int wh_Server_CacheImportCurve25519Key(whServerContext* server,
        curve25519_key* key,
        whKeyId keyId, whNvmFlags flags, uint32_t label_len, uint8_t* label);
/* Restore a curve25519_key from a server key cache */
static int wh_Server_CacheExportCurve25519Key(whServerContext* server, whKeyId keyId,
        curve25519_key* key);

#ifdef WOLFSSL_KEY_GEN
/* Process a Generate curve25519_key request packet and produce a response */
static int wh_Server_HandleGenerateCurve25519Key(whServerContext* server,
        whPacket* packet, uint16_t *out_size);
#endif /* WOLFSSL_KEY_GEN */

/* Process a curve25519_key Function request packet and produce a response */
static int wh_Server_HandleSharedSecretCurve25519(whServerContext* server,
        whPacket* packet, uint16_t *out_size);



static int wh_Server_CacheImportCurve25519Key(whServerContext* server,
        curve25519_key* key,
        whKeyId keyId, whNvmFlags flags, uint32_t label_len, uint8_t* label)
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

static int wh_Server_CacheExportCurve25519Key(whServerContext* server, whKeyId keyId,
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
        wh_Crypto_DeserializeCurve25519Key(cacheMeta->len, cacheBuf, key);
    }
    return ret;
}

static int wh_Server_HandleGenerateCurve25519Key(whServerContext* server, whPacket* packet,
    uint16_t* out_size)
{
    int ret = 0;
    curve25519_key curve25519[1] = {0};
    int key_size        = packet->pkCurve25519kgReq.sz;

    /* Force incoming key_id to have current user/type */
    whKeyId key_id      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                            server->comm->client_id,
                            packet->pkCurve25519kgReq.keyId);
    whNvmFlags flags    = packet->pkCurve25519kgReq.flags;
    uint8_t* label      = packet->pkCurve25519kgReq.label;
    uint32_t label_size = WH_NVM_LABEL_LEN;

    uint8_t* out        = (uint8_t*)(&packet->pkCurve25519kgReq + 1);
    word32 max_size     = (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                            (out - (uint8_t*)packet));
    uint16_t der_size   = 0;

    /* init private key */
    ret = wc_curve25519_init_ex(curve25519, NULL, server->crypto->devId);
    /* make the key */
    if (ret == 0) {
        ret = wc_curve25519_make_key(server->crypto->rng,
            (word32)key_size,
            curve25519);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] MakeCurve25519Key: size:%d, ret:%d\n",
                key_size, ret);
#endif
        if ( ret == 0) {
            /* Check incoming flags */
            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                /* Must serialize the key into the response packet */
                ret = wh_Crypto_SerializeCurve25519Key(curve25519, max_size,
                        out, &der_size);
                if (ret == 0) {
                    packet->pkCurve25519kgRes.keyId = 0;
                    packet->pkCurve25519kgRes.len = der_size;
                }
            } else {
                /* Must import the key into the cache and return keyid */
                if (WH_KEYID_ISERASED(key_id)) {
                    /* Generate a new id */
                    ret = hsmGetUniqueId(server, &key_id);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[server] MakeCurve25519Key UniqueId: keyId:%u, ret:%d\n",
                            key_id, ret);
#endif
                }

                ret = wh_Server_CacheImportCurve25519Key(server, curve25519,
                        key_id, flags, label_size, label);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] MakeCurve25519Key CacheImport: keyId:%u, ret:%d\n",
                        key_id, ret);
#endif
                packet->pkCurve25519kgRes.keyId = (key_id & WH_KEYID_MASK);
                packet->pkCurve25519kgRes.len = 0;
            }
        }
        wc_curve25519_free(curve25519);
    }

    if (ret == 0) {
        /* set the assigned id */
        *out_size = WH_PACKET_STUB_SIZE +
                sizeof(packet->pkCurve25519kgRes) +
                packet->pkCurve25519kgRes.len;
    }
    return ret;
}

static int wh_Server_HandleSharedSecretCurve25519(whServerContext* server, whPacket* packet,
    uint16_t* out_size)
{
    int ret;
    curve25519_key priv[1] = {0};
    curve25519_key pub[1] = {0};

    int endian    = (int)(packet->pkCurve25519Req.endian);
    whKeyId priv_key_id  = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                        server->comm->client_id,
                        packet->pkCurve25519Req.privateKeyId);
    whKeyId pub_key_id  = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                        server->comm->client_id,
                        packet->pkCurve25519Req.publicKeyId);
    word32 len      = CURVE25519_KEYSIZE;
    /* iout is after the fixed size fields */
    byte* out       = (uint8_t*)(&packet->pkCurve25519Res + 1);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] HandleSharedSecretCurve25519 endian:%d privkeyId:%u pubkeyid:%u\n",
            endian, priv_key_id, pub_key_id);
#endif
    /* init private key */
    ret = wc_curve25519_init_ex(priv, NULL, server->crypto->devId);
    if (ret == 0) {
        /* init public key */
        ret = wc_curve25519_init_ex(pub, NULL, server->crypto->devId);
        if (ret == 0) {
            ret = wh_Server_CacheExportCurve25519Key(
                    server, priv_key_id, priv);
            if (ret == 0) {
                ret = wh_Server_CacheExportCurve25519Key(
                        server, pub_key_id, pub);
            }
            if (ret == 0) {
                ret = wc_curve25519_shared_secret_ex(
                    priv, pub, out, &len, endian);
            }
            wc_curve25519_free(pub);
        }
        wc_curve25519_free(priv);
    }
    if (ret == 0) {
        /*set outLen and outgoing message size */
        packet->pkCurve25519Res.sz = len;
        *out_size = WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Res) + len;
    }
    return ret;
}

#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
static int hsmCacheKeyEcc(whServerContext* server, ecc_key* key, whKeyId* outId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret;
    word32 qxLen = 0;
    word32 qyLen = 0;
    word32 qdLen = 0;
    whKeyId keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, WH_KEYID_ERASED);
    byte* qxBuf = NULL;
    byte* qyBuf = NULL;
    byte* qdBuf = NULL;
    /* get a free slot */
    ret = hsmCacheFindSlotAndZero(server, qxLen + qyLen + qdLen, &cacheBuf,
        &cacheMeta);
    if (ret == 0)
        ret = hsmGetUniqueId(server, &keyId);
    /* export key */
    if (ret == 0) {
        if (key->type != ECC_PRIVATEKEY_ONLY) {
            qxLen = qyLen = key->dp->size;
            qxBuf = cacheBuf;
            qyBuf = qxBuf + qxLen;
        }
        if (key->type == ECC_PRIVATEKEY_ONLY || key->type == ECC_PRIVATEKEY) {
            qdLen = key->dp->size;
            if (key->type == ECC_PRIVATEKEY_ONLY) {
                qdBuf = cacheBuf;
            }
            else {
                qdBuf = qyBuf + qyLen;
            }
        }
        ret = wc_ecc_export_private_raw(key, qxBuf, &qxLen, qyBuf, &qyLen,
            qdBuf, &qdLen);
    }
    if (ret == 0) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = qxLen + qyLen + qdLen;
        /* export keyId */
        *outId = keyId;
    }
    return ret;
}

static int hsmLoadKeyEcc(whServerContext* server, ecc_key* key, uint16_t keyId,
    int curveId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret;
    int curveIdx;
    word32 qxLen = 0;
    word32 qyLen = 0;
    word32 qdLen = 0;
    word32 keySz;
    byte* qxBuf = NULL;
    byte* qyBuf = NULL;
    byte* qdBuf = NULL;
    keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, keyId);
    /* freshen the key */
    ret = hsmFreshenKey(server, keyId, &cacheBuf, &cacheMeta);
    /* get the size by curveId */
    if (ret >= 0) {
        ret = curveIdx = wc_ecc_get_curve_idx(curveId);
        if (curveIdx != ECC_CURVE_INVALID) {
            keySz = ecc_sets[curveIdx].size;
        }
    }
    /* decode the key */
    if (ret >= 0) {
        /* determine which buffers should be set by size, wc_ecc_import_unsigned
         * will set the key type accordingly */
        if (cacheMeta->len == keySz * 3) {
            qxLen = qyLen = qdLen = keySz;
            qxBuf = cacheBuf;
            qyBuf = qxBuf + qxLen;
            qdBuf = qyBuf + qyLen;
        }
        else if (cacheMeta->len == keySz * 2) {
            qxLen = qyLen = keySz;
            qxBuf = cacheBuf;
            qyBuf = qxBuf + qxLen;
        }
        else {
            qxLen = qyLen = qdLen = keySz;
            qdBuf = cacheBuf;
        }
        ret = wc_ecc_import_unsigned(key, qxBuf, qyBuf, qdBuf, curveId);
    }
    return ret;
}

static int hsmCryptoEcKeyGen(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    whKeyId keyId = WH_KEYID_ERASED;
    /* init ecc key */
    ret = wc_ecc_init_ex(server->crypto->algoCtx.eccPrivate, NULL,
        server->crypto->devId);
    /* generate the key the key */
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(server->crypto->rng,
            (word32)packet->pkEckgReq.sz, server->crypto->algoCtx.eccPrivate,
            packet->pkEckgReq.curveId);
    }
    /* cache the generated key */
    if (ret == 0) {
        ret = hsmCacheKeyEcc(server, server->crypto->algoCtx.eccPrivate,
            &keyId);
    }
    /* set the assigned id */
    wc_ecc_free(server->crypto->algoCtx.eccPrivate);
    if (ret == 0) {
        packet->pkEckgRes.keyId = keyId;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkEckgRes);
    }
    return ret;
}

static int hsmCryptoEcdh(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    word32 len;
    /* out is after the fixed size fields */
    byte* out = (uint8_t*)(&packet->pkEcdhRes + 1);
    /* init ecc key */
    ret = wc_ecc_init_ex(server->crypto->algoCtx.eccPrivate, NULL,
        server->crypto->devId);
    if (ret == 0) {
        ret = wc_ecc_init_ex(server->crypto->algoCtx.eccPrivate, NULL,
            server->crypto->devId);
    }
    /* load the private key */
    if (ret == 0) {
        ret = hsmLoadKeyEcc(server, server->crypto->algoCtx.eccPrivate,
            packet->pkEcdhReq.privateKeyId, packet->pkEcdhReq.curveId);
    }
    /* set rng */
    if (ret == 0) {
        ret = wc_ecc_set_rng(server->crypto->algoCtx.eccPrivate,
            server->crypto->rng);
    }
    /* load the public key */
    if (ret == 0) {
        ret = hsmLoadKeyEcc(server, server->crypto->pubKey.eccPublic,
            packet->pkEcdhReq.publicKeyId, packet->pkEcdhReq.curveId);
    }
    /* make shared secret */
    if (ret == 0) {
        len = server->crypto->algoCtx.eccPrivate->dp->size;
        ret = wc_ecc_shared_secret(server->crypto->algoCtx.eccPrivate,
            server->crypto->pubKey.eccPublic, out, &len);
    }
    wc_ecc_free(server->crypto->algoCtx.eccPrivate);
    wc_ecc_free(server->crypto->pubKey.eccPublic);
    if (ret == 0) {
        packet->pkEcdhRes.sz = len;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkEcdhRes) + len;
    }
    return ret;
}

static int hsmCryptoEcdsaSign(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    word32 len;
    /* in and out are after the fixed size fields */
    byte* in = (uint8_t*)(&packet->pkEccSignReq + 1);
    byte* out = (uint8_t*)(&packet->pkEccSignRes + 1);
    /* init pivate key */
    ret = wc_ecc_init_ex(server->crypto->algoCtx.eccPrivate, NULL,
        server->crypto->devId);
    /* load the private key */
    if (ret == 0) {
        ret = hsmLoadKeyEcc(server, server->crypto->algoCtx.eccPrivate,
            packet->pkEccSignReq.keyId, packet->pkEccSignReq.curveId);
    }
    /* sign the input */
    if (ret == 0) {
        len = WH_COMM_MTU - sizeof(packet->pkEccSignRes);
        ret = wc_ecc_sign_hash(in, packet->pkEccSignReq.sz, out, &len,
            server->crypto->rng, server->crypto->algoCtx.eccPrivate);
    }
    wc_ecc_free(server->crypto->algoCtx.eccPrivate);
    if (ret == 0) {
        packet->pkEccSignRes.sz = len;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccSignRes) + len;
    }
    return ret;
}

static int hsmCryptoEcdsaVerify(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    int res;
    /* sig and hash are after the fixed size fields */
    byte* sig = (uint8_t*)(&packet->pkEccVerifyReq + 1);
    byte* hash = (uint8_t*)(&packet->pkEccVerifyReq + 1) +
        packet->pkEccVerifyReq.sigSz;
    /* init public key */
    ret = wc_ecc_init_ex(server->crypto->pubKey.eccPublic, NULL,
        server->crypto->devId);
    /* load the public key */
    if (ret == 0) {
        ret = hsmLoadKeyEcc(server, server->crypto->pubKey.eccPublic,
            packet->pkEccVerifyReq.keyId, packet->pkEccVerifyReq.curveId);
    }
    /* verify the signature */
    if (ret == 0) {
        ret = wc_ecc_verify_hash(sig, packet->pkEccVerifyReq.sigSz, hash,
            packet->pkEccVerifyReq.hashSz, &res,
            server->crypto->pubKey.eccPublic);
    }
    wc_ecc_free(server->crypto->pubKey.eccPublic);
    if (ret == 0) {
        packet->pkEccVerifyRes.res = res;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccVerifyRes);
    }
    return ret;
}

static int hsmCryptoEcCheckPrivKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    /* init pivate key */
    ret = wc_ecc_init_ex(server->crypto->algoCtx.eccPrivate, NULL,
        server->crypto->devId);
    /* load the private key */
    if (ret == 0) {
        ret = hsmLoadKeyEcc(server, server->crypto->algoCtx.eccPrivate,
            packet->pkEccCheckReq.keyId, packet->pkEccCheckReq.curveId);
    }
    /* check the key */
    if (ret == 0)
        ret = wc_ecc_check_key(server->crypto->algoCtx.eccPrivate);
    wc_ecc_free(server->crypto->algoCtx.eccPrivate);
    if (ret == 0) {
        packet->pkEccCheckRes.ok = 1;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccCheckRes);
    }
    return ret;
}
#endif /* HAVE_ECC */

#ifndef NO_AES
#ifdef HAVE_AES_CBC
static int hsmCryptoAesCbc(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    Aes aes[1] = {0};

    uint32_t enc = packet->cipherAesCbcReq.enc;
    uint32_t key_len = packet->cipherAesCbcReq.keyLen;
    uint32_t len = packet->cipherAesCbcReq.sz;
    whKeyId key_id = WH_MAKE_KEYID(
                        WH_KEYTYPE_CRYPTO,
                        server->comm->client_id,
                        packet->cipherAesCbcReq.keyId);

    /* in, key, iv, and out are after fixed size fields */
    uint8_t* in = (uint8_t*)(&packet->cipherAesCbcReq + 1);
    uint8_t* key = in + packet->cipherAesCbcReq.sz;
    uint8_t* iv = key + packet->cipherAesCbcReq.keyLen;
    uint8_t* out = (uint8_t*)(&packet->cipherAesCbcRes + 1);

    uint8_t tmpKey[AES_MAX_KEY_SIZE];

    /* use keyId and load from keystore if keyId is nonzero, must check for zero
     * since WH_KEYID_ERASED may not be zero while the client always defaults to
     * devCtx 0 */
    if (!WH_KEYID_ISERASED(key_id)) {
        key_len = sizeof(tmpKey);
        ret = hsmReadKey(server, key_id, NULL, tmpKey, &key_len);
        if (ret == 0) {
            /* set key to use tmpKey data */
            key = tmpKey;
        }
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, server->crypto->devId);
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
        packet->cipherAesCbcRes.sz = len;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->cipherAesCbcRes) + len;
    }
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
static int hsmCryptoAesGcm(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    Aes aes[1] = {0};

    uint32_t enc = packet->cipherAesGcmReq.enc;
    uint32_t key_len = packet->cipherAesGcmReq.keyLen;
    uint32_t len = packet->cipherAesGcmReq.sz;
    uint32_t iv_len = packet->cipherAesGcmReq.ivSz;
    uint32_t authin_len = packet->cipherAesGcmReq.authInSz;
    uint32_t authtag_len = packet->cipherAesGcmReq.authTagSz;
    whKeyId key_id = WH_MAKE_KEYID(
            WH_KEYTYPE_CRYPTO,
            server->comm->client_id,
            packet->cipherAesGcmReq.keyId);

    /* in, key, iv, authIn, authTag, and out are after fixed size fields */
    byte* in = (uint8_t*)(&packet->cipherAesGcmReq + 1);
    byte* key = in + len;
    byte* iv = key + key_len;
    byte* authIn =  iv + iv_len;
    byte* tag_dec = authIn + authin_len;
    byte* out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
    byte* tag_enc = out + len;
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];

    /* use keyId and load from keystore if keyId is nonzero, must check for zero
     * since WH_KEYID_ERASED may not be zero while the client always defaults to
     * devCtx 0 */
    if (!WH_KEYID_ISERASED(key_id)) {
        key_len = sizeof(tmpKey);
        ret = hsmReadKey(server, key_id, NULL, tmpKey, &key_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] AesGcm ReadKey key_id:%u, ret:%d\n", key_id, ret);
#endif
        if (ret == 0) {
            /* set key to use tmpKey data */
            key = tmpKey;
        }
    }
    if (ret == 0) {
        /* init key with possible hardware */
        ret = wc_AesInit(aes, NULL, server->crypto->devId);
    }
    if (ret == 0) {
        /* load the key */
        ret = wc_AesGcmSetKey(aes, key, key_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] AesGcmSetKey key_id:%u key_len:%u ret:%d\n",
                key_id, key_len, ret);
        _hexdump("key: ", key, key_len);
#endif
        if (ret == 0) {
            /* do the crypto operation */
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[server] enc:%d len:%d, ivSz:%d authTagSz:%d, authInSz:%d\n",
                    enc, len,iv_len, authtag_len, authin_len);
            _hexdump("[server] in: ", in, len);
            _hexdump("[server] iv: ", iv, iv_len);
            _hexdump("[server] authin: ", authIn,  authin_len);
#endif
            if (enc != 0) {
                ret = wc_AesGcmEncrypt(aes, out,
                    in, len,
                    iv, iv_len,
                    tag_enc, authtag_len,
                    authIn, authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] enc ret:%d\n",ret);
                _hexdump("[server] out: ", out, len);
                _hexdump("[server] authTag: ", tag_enc,  authtag_len);
#endif
            } else {
                /* set authTag as a packet input */
#ifdef DEBUG_CRYPTOCB_VERBOSE
                _hexdump("[server] authTag: ", tag_dec,  authtag_len);
#endif
                /*uint8_t temp[4096] = {0};*/
                ret = wc_AesGcmDecrypt(aes, out,
                    in, len,
                    iv, iv_len,
                    tag_dec, authtag_len,
                    authIn, authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] dec ret:%d\n",ret);
                _hexdump("[server] out: ", out, len);
#endif
            }
        }
        wc_AesFree(aes);
    }
    /* encode the return sz */
    if (ret == 0) {
        /* set sz */
        packet->cipherAesGcmRes.sz = len;
        *size = WH_PACKET_STUB_SIZE +
                sizeof(packet->cipherAesGcmRes) +
                len;

        if(enc != 0) {
            packet->cipherAesGcmRes.authTagSz = authtag_len;
            *size += authtag_len;
        } else {
            packet->cipherAesGcmRes.authTagSz = 0;
        }
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] res size:%d\n", *size);
#endif
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
                keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                        server->comm->client_id, WH_KEYID_ERASED);
                ret = hsmGetUniqueId(server, &keyId);
            }
            else {
                keyId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                    server->comm->client_id, packet->cmacReq.keyId);
            }
            /* evict the aes sized key in the normal cache */
            if (moveToBigCache == 1) {
                ret = hsmEvictKey(server, keyId);
            }
            meta->id = keyId;
            meta->len = sizeof(server->crypto->algoCtx.cmac);
            ret = hsmCacheKey(server, meta, (uint8_t*)server->crypto->algoCtx.cmac);
            packet->cmacRes.keyId = (keyId & WH_KEYID_MASK);
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

    if (server == NULL || server->crypto == NULL || data == NULL || size == NULL)
        return BAD_FUNC_ARG;
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] Crypto request. Action:%u\n", action);
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
            ret = wh_Server_HandleGenerateRsaKey(server, (whPacket*)data, size);
            break;
#endif  /* WOLFSSL_KEY_GEN */
        case WC_PK_TYPE_RSA:
            ret = wh_Server_HandleRsaFunction(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            ret = wh_server_HandleRsaGetSize(server, (whPacket*)data, size);
            break;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            ret = hsmCryptoEcKeyGen(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_ECDH:
            ret = hsmCryptoEcdh(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            ret = hsmCryptoEcdsaSign(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_ECDSA_VERIFY:
            ret = hsmCryptoEcdsaVerify(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            ret = hsmCryptoEcCheckPrivKey(server, (whPacket*)data, size);
            break;
#endif /* HAVE_ECC */
#ifdef HAVE_CURVE25519




        case WC_PK_TYPE_CURVE25519_KEYGEN:
            ret = wh_Server_HandleGenerateCurve25519Key(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_CURVE25519:
            ret = wh_Server_HandleSharedSecretCurve25519(server, (whPacket*)data, size);
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
            case WC_HASH_TYPE_SHA256:
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] SHA256 req recv. type:%u\n",
                       packet->hashSha256Req.type);
#endif
                ret = hsmCryptoSha256(server, (whPacket*)data, size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                if (ret != 0) {
                    printf("[server] SHA256 ret = %d\n", ret);
                }
#endif
                break;

            default:
                ret = NOT_COMPILED_IN;
                break;
        }
        break;

#ifndef NO_SHA256
#endif /* !NO_SHA256 */


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
#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
