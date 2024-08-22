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
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wolfhsm/wh_server.h"

#ifndef NO_RSA
static int hsmCacheKeyRsa(whServerContext* server, RsaKey* key, whKeyId* outId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = 0;
    /* wc_RsaKeyToDer doesn't have a length check option so we need to just pass
     * the big key size if compiled */
    const uint16_t keySz = WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE;
    whKeyId keyId = WH_KEYTYPE_CRYPTO;
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
    keyId |= (WH_KEYTYPE_CRYPTO | (server->comm->client_id << 8));
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
    whKeyId keyId = WH_KEYID_ERASED;
    /* init the rsa key */
    ret = wc_InitRsaKey_ex(server->crypto->algoCtx.rsa, NULL,
        server->crypto->devId);
    /* make the rsa key with the given params */
    if (ret == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -MakeRsaKey: size:%u, e:%u\n",
                (word32)packet->pkRsakgReq.size, packet->pkRsakgReq.e);
#endif
        ret = wc_MakeRsaKey(server->crypto->algoCtx.rsa,
            (word32)packet->pkRsakgReq.size, (long)packet->pkRsakgReq.e,
            server->crypto->rng);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -MakeRsaKey: ret:%d\n",ret);
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
        packet->pkRsakgRes.keyId = (keyId & WH_KEYID_MASK);
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
        printf("[server] -LoadKeyRsa keyid %u:%d\n", packet->pkRsaReq.keyId,ret);
#endif
    }
    /* do the rsa operation */
    if (ret == 0) {
        len = packet->pkRsaReq.outLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -RSAFunction in:%p %u, out:%p, opType:%d\n",
                in, packet->pkRsaReq.inLen, out, packet->pkRsaReq.opType);
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

#ifdef HAVE_CURVE25519
static int hsmCacheKeyCurve25519(whServerContext* server, curve25519_key* key,
    whKeyId* outId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_KEYSIZE;
    whKeyId keyId = WH_KEYTYPE_CRYPTO;
    const uint16_t keySz = CURVE25519_KEYSIZE * 2;
    /* get a free slot */
    ret = hsmCacheFindSlotAndZero(server, keySz, &cacheBuf,
        &cacheMeta);
    if (ret == 0)
        ret = hsmGetUniqueId(server, &keyId);
    if (ret == 0) {
        /* export key */
        ret = wc_curve25519_export_key_raw(key, cacheBuf + CURVE25519_KEYSIZE,
            &privSz, cacheBuf, &pubSz);
    }
    if (ret == 0) {
        /* set meta */
        cacheMeta->id = keyId;
        cacheMeta->len = keySz;
        /* export keyId */
        *outId = keyId;
    }
    return ret;
}

static int hsmLoadKeyCurve25519(whServerContext* server, curve25519_key* key,
    whKeyId keyId)
{
    uint8_t* cacheBuf;
    whNvmMetadata* cacheMeta;
    int ret = 0;
    uint32_t privSz = CURVE25519_KEYSIZE;
    uint32_t pubSz = CURVE25519_KEYSIZE;
    keyId |= WH_KEYTYPE_CRYPTO;
    /* freshen the key */
    ret = hsmFreshenKey(server, keyId, &cacheBuf, &cacheMeta);
    /* decode the key */
    if (ret == 0)
        ret = wc_curve25519_import_public(cacheBuf, (word32)pubSz, key);
    /* only import private if what we got back holds 2 keys */
    if (ret == 0 && cacheMeta->len == CURVE25519_KEYSIZE * 2) {
        ret = wc_curve25519_import_private( cacheBuf + pubSz, (word32)privSz,
            key);
    }
    return ret;
}

static int hsmCryptoCurve25519KeyGen(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    whKeyId keyId = WH_KEYID_ERASED;
    /* init private key */
    ret = wc_curve25519_init_ex(server->crypto->algoCtx.curve25519Private, NULL,
        server->crypto->devId);
    /* make the key */
    if (ret == 0) {
        ret = wc_curve25519_make_key(server->crypto->rng,
            (word32)packet->pkCurve25519kgReq.sz,
            server->crypto->algoCtx.curve25519Private);
    }
    /* cache the generated key */
    if (ret == 0) {
        ret = hsmCacheKeyCurve25519(server,
            server->crypto->algoCtx.curve25519Private, &keyId);
    }
    /* set the assigned id */
    wc_curve25519_free(server->crypto->algoCtx.curve25519Private);
    if (ret == 0) {
        /* send only keyId */
        packet->pkCurve25519kgRes.keyId = (keyId & WH_KEYID_MASK);
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519kgRes);
    }
    return ret;
}

static int hsmCryptoCurve25519(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    word32 len;
    /* out is after the fixed size fields */
    byte* out = (uint8_t*)(&packet->pkCurve25519Res + 1);
    /* init ecc key */
    ret = wc_curve25519_init_ex(server->crypto->algoCtx.curve25519Private, NULL,
        server->crypto->devId);
    if (ret == 0) {
        ret = wc_curve25519_init_ex(server->crypto->pubKey.curve25519Public,
            NULL, server->crypto->devId);
    }
    /* load the private key */
    if (ret == 0) {
        ret = hsmLoadKeyCurve25519(server,
            server->crypto->algoCtx.curve25519Private,
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id,
            packet->pkCurve25519Req.privateKeyId));
    }
    /* load the public key */
    if (ret == 0) {
        ret = hsmLoadKeyCurve25519(server,
            server->crypto->pubKey.curve25519Public,
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id,
            packet->pkCurve25519Req.publicKeyId));
    }
    /* make shared secret */
    if (ret == 0) {
        len = CURVE25519_KEYSIZE;
        ret = wc_curve25519_shared_secret_ex(
            server->crypto->algoCtx.curve25519Private,
            server->crypto->pubKey.curve25519Public, out, (word32*)&len,
            packet->pkCurve25519Req.endian);
    }
    wc_curve25519_free(server->crypto->algoCtx.curve25519Private);
    wc_curve25519_free(server->crypto->pubKey.curve25519Public);
    if (ret == 0) {
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Res) +
            len;
        packet->pkCurve25519Res.sz = len;
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
    whKeyId keyId = WH_KEYTYPE_CRYPTO;
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
    keyId |= WH_KEYTYPE_CRYPTO;
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
                keyId = WH_KEYTYPE_CRYPTO;
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[server] -PK type:%u\n", packet->pkAnyReq.type);
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
                    packet->pkRsaReq.opType,
                    packet->pkRsaReq.inLen,
                    packet->pkRsaReq.keyId,
                    packet->pkRsaReq.outLen,
                    packet->pkRsaReq.type);
#endif
            switch (packet->pkRsaReq.opType)
            {
            case RSA_PUBLIC_ENCRYPT:
            case RSA_PUBLIC_DECRYPT:
            case RSA_PRIVATE_ENCRYPT:
            case RSA_PRIVATE_DECRYPT:
                ret = hsmCryptoRsaFunction(server, (whPacket*)data, size);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[server] RSA req recv. ret:%d type:%d\n", ret, packet->pkRsaRes.outLen);
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
            ret = hsmCryptoCurve25519KeyGen(server, (whPacket*)data, size);
            break;
        case WC_PK_TYPE_CURVE25519:
            ret = hsmCryptoCurve25519(server, (whPacket*)data, size);
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
