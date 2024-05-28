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
/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#ifndef WOLFHSM_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_server_crypto.h"

#ifndef NO_RSA
static int hsmCacheKeyRsa(whServerContext* server, RsaKey* key, whKeyId* outId)
{
    int ret = 0;
    int slotIdx = 0;
    whKeyId keyId = WOLFHSM_KEYTYPE_CRYPTO;
    /* get a free slot */
    ret = slotIdx = hsmCacheFindSlot(server);
    if (ret >= 0) {
        ret = hsmGetUniqueId(server, &keyId);
    }
    if (ret == 0) {
        /* export key */
        /* TODO: Fix wolfCrypto to allow KeyToDer when KEY_GEN is NOT set */
        XMEMSET((uint8_t*)&server->cache[slotIdx], 0, sizeof(CacheSlot));
        ret = wc_RsaKeyToDer(key, server->cache[slotIdx].buffer,
            WOLFHSM_KEYCACHE_BUFSIZE);
    }
    if (ret > 0) {
        /* set meta */
        server->cache[slotIdx].meta->id = keyId;
        server->cache[slotIdx].meta->len = ret;
        /* export keyId */
        *outId = keyId;
        ret = 0;
    }
    return ret;
}

static int hsmLoadKeyRsa(whServerContext* server, RsaKey* key, whKeyId keyId)
{
    int ret = 0;
    int slotIdx = 0;
    uint32_t idx = 0;
    uint32_t size;
    keyId |= (WOLFHSM_KEYTYPE_CRYPTO | (server->comm->client_id << 8));
    /* freshen the key */
    ret = slotIdx = hsmFreshenKey(server, keyId);
    /* decode the key */
    if (ret >= 0) {
        size = WOLFHSM_KEYCACHE_BUFSIZE;
        ret = wc_RsaPrivateKeyDecode(server->cache[slotIdx].buffer, (word32*)&idx, key,
            size);
    }
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_CURVE25519
static int hsmCacheKeyCurve25519(whServerContext* server, curve25519_key* key,
    whKeyId* outId)
{
    int ret;
    int slotIdx = 0;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_KEYSIZE;
    whKeyId keyId = WOLFHSM_KEYTYPE_CRYPTO;
    /* get a free slot */
    ret = slotIdx = hsmCacheFindSlot(server);
    if (ret >= 0) {
        ret = hsmGetUniqueId(server, &keyId);
    }
    if (ret == 0) {
        XMEMSET((uint8_t*)&server->cache[slotIdx], 0, sizeof(CacheSlot));
        /* export key */
        ret = wc_curve25519_export_key_raw(key,
            server->cache[slotIdx].buffer + CURVE25519_KEYSIZE, &privSz,
            server->cache[slotIdx].buffer, &pubSz);
    }
    if (ret == 0) {
        /* set meta */
        server->cache[slotIdx].meta->id = keyId;
        server->cache[slotIdx].meta->len = CURVE25519_KEYSIZE * 2;
        /* export keyId */
        *outId = keyId;
    }
    return ret;
}

static int hsmLoadKeyCurve25519(whServerContext* server, curve25519_key* key,
    whKeyId keyId)
{
    int ret = 0;
    int slotIdx = 0;
    uint32_t privSz = CURVE25519_KEYSIZE;
    uint32_t pubSz = CURVE25519_KEYSIZE;
    keyId |= WOLFHSM_KEYTYPE_CRYPTO;
    /* freshen the key */
    ret = slotIdx = hsmFreshenKey(server, keyId);
    /* decode the key */
    if (ret >= 0) {
        ret = wc_curve25519_import_public(server->cache[slotIdx].buffer, pubSz,
            key);
    }
    /* only import private if what we got back holds 2 keys */
    if (ret == 0 && server->cache[slotIdx].meta->len == CURVE25519_KEYSIZE * 2) {
        ret = wc_curve25519_import_private(
            server->cache[slotIdx].buffer + pubSz, privSz, key);
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
static int hsmCacheKeyEcc(whServerContext* server, ecc_key* key, whKeyId* outId)
{
    int ret;
    int slotIdx = 0;
    uint32_t qxLen;
    uint32_t qyLen;
    uint32_t qdLen;
    whKeyId keyId = WOLFHSM_KEYTYPE_CRYPTO;
    /* get a free slot */
    ret = slotIdx = hsmCacheFindSlot(server);
    if (ret >= 0) {
        ret = hsmGetUniqueId(server, &keyId);
    }
    /* export key */
    if (ret == 0) {
        XMEMSET((uint8_t*)&server->cache[slotIdx], 0, sizeof(CacheSlot));
        qxLen = qyLen = qdLen = key->dp->size;
        ret = wc_ecc_export_private_raw(key, server->cache[slotIdx].buffer,
            &qxLen, server->cache[slotIdx].buffer + qxLen,
            &qyLen, server->cache[slotIdx].buffer + qxLen + qyLen, &qdLen);
    }
    if (ret == 0) {
        /* set meta */
        server->cache[slotIdx].meta->id = keyId;
        server->cache[slotIdx].meta->len = qxLen + qyLen + qdLen;
        /* export keyId */
        *outId = keyId;
    }
    return ret;
}

static int hsmLoadKeyEcc(whServerContext* server, ecc_key* key, uint16_t keyId,
    int curveId)
{
    int ret;
    int slotIdx = 0;
    uint32_t keySz;
    keyId |= WOLFHSM_KEYTYPE_CRYPTO;
    /* freshen the key */
    ret = slotIdx = hsmFreshenKey(server, keyId);
    /* decode the key */
    if (ret >= 0) {
        keySz = server->cache[slotIdx].meta->len / 3;
        ret = wc_ecc_import_unsigned(key, server->cache[slotIdx].buffer,
            server->cache[slotIdx].buffer + keySz,
            server->cache[slotIdx].buffer + keySz * 2, curveId);
    }
    return ret;
}
#endif /* HAVE_ECC */

int wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    int res = 0;
    uint32_t field;
    uint8_t* in;
    whKeyId keyId = WOLFHSM_KEYID_ERASED;
    uint8_t* out;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* authIn;
    uint8_t* authTag;
    uint8_t* sig;
    uint8_t* hash;
    whPacket* packet = (whPacket*)data;
    whNvmMetadata meta[1];
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];

    if (server == NULL || server->crypto == NULL || data == NULL || size == NULL)
        return BAD_FUNC_ARG;

    switch (action)
    {
    case WC_ALGO_TYPE_CIPHER:
        switch (packet->cipherAnyReq.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            /* key, iv, in, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesCbcReq + 1);
            iv = key + packet->cipherAesCbcReq.keyLen;
            in = iv + AES_IV_SIZE;
            out = (uint8_t*)(&packet->cipherAesCbcRes + 1);
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* load the key from keystore */
            field = sizeof(tmpKey);
            ret = hsmReadKey(server, *(uint32_t*)key | WOLFHSM_KEYTYPE_CRYPTO,
                NULL, tmpKey, &field);
            if (ret == 0) {
                /* set key to use tmpKey data */
                key = tmpKey;
                /* overwrite keyLen with internal length */
                packet->cipherAesCbcReq.keyLen = field;
            }
#endif
            /* init key with possible hardware */
            if (ret == 0) {
                ret = wc_AesInit(server->crypto->aes, NULL,
                    server->crypto->devId);
            }
            /* load the key */
            if (ret == 0) {
                ret = wc_AesSetKey(server->crypto->aes, key,
                    packet->cipherAesCbcReq.keyLen, iv,
                    packet->cipherAesCbcReq.enc == 1 ?
                    AES_ENCRYPTION : AES_DECRYPTION);
            }
            /* do the crypto operation */
            if (ret == 0) {
                /* store this since it will be overwritten */
                field = packet->cipherAesCbcReq.sz;
                if (packet->cipherAesCbcReq.enc == 1)
                    ret = wc_AesCbcEncrypt(server->crypto->aes, out, in, field);
                else
                    ret = wc_AesCbcDecrypt(server->crypto->aes, out, in, field);
            }
            wc_AesFree(server->crypto->aes);
            /* encode the return sz */
            if (ret == 0) {
                /* set sz */
                packet->cipherAesCbcRes.sz = field;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->cipherAesCbcRes) + field;
            }
            break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            /* key, iv, in, authIn, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesGcmReq + 1);
            iv = key + packet->cipherAesGcmReq.keyLen;
            in = iv + packet->cipherAesGcmReq.ivSz;
            authIn = in + packet->cipherAesGcmReq.sz;
            out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* load the key from keystore */
            field = sizeof(tmpKey);
            ret = hsmReadKey(server, *(uint32_t*)key | WOLFHSM_KEYTYPE_CRYPTO,
                NULL, tmpKey, &field);
            if (ret == 0) {
                /* set key to use tmpKey data */
                key = tmpKey;
                /* overwrite keyLen with internal length */
                packet->cipherAesGcmReq.keyLen = field;
            }
#endif
            /* init key with possible hardware */
            if (ret == 0) {
                ret = wc_AesInit(server->crypto->aes, NULL,
                    server->crypto->devId);
            }
            /* load the key */
            if (ret == 0) {
                ret = wc_AesGcmSetKey(server->crypto->aes, key,
                    packet->cipherAesGcmReq.keyLen);
            }
            /* do the crypto operation */
            if (ret == 0) {
                /* store this since it will be overwritten */
                field = packet->cipherAesGcmReq.sz;
                *size = 0;
                if (packet->cipherAesGcmReq.enc == 1) {
                    /* set authTag as a packet output */
                    authTag = out + field;
                    *size += packet->cipherAesGcmReq.authTagSz;
                    /* copy authTagSz since it will be overwritten */
                    packet->cipherAesGcmRes.authTagSz =
                        packet->cipherAesGcmReq.authTagSz;
                    ret = wc_AesGcmEncrypt(server->crypto->aes, out, in, field,
                        iv, packet->cipherAesGcmReq.ivSz, authTag,
                        packet->cipherAesGcmReq.authTagSz, authIn,
                        packet->cipherAesGcmReq.authInSz);
                }
                else {
                    /* set authTag as a packet input */
                    authTag = authIn + packet->cipherAesGcmReq.authInSz;
                    ret = wc_AesGcmDecrypt(server->crypto->aes, out, in, field,
                        iv, packet->cipherAesGcmReq.ivSz, authTag,
                        packet->cipherAesGcmReq.authTagSz, authIn,
                        packet->cipherAesGcmReq.authInSz);
                }
            }
            wc_AesFree(server->crypto->aes);
            /* encode the return sz */
            if (ret == 0) {
                /* set sz */
                packet->cipherAesGcmRes.sz = field;
                *size += WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->cipherAesGcmRes) + field;
            }
            break;
#endif /* HAVE_AESGCM */
#endif /* HAVE_ECC */
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
    case WC_ALGO_TYPE_PK:
        switch (packet->pkAnyReq.type)
        {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
            /* init the rsa key */
            ret = wc_InitRsaKey_ex(server->crypto->rsa, NULL, INVALID_DEVID);
            /* make the rsa key with the given params */
            if (ret == 0) {
                ret = wc_MakeRsaKey(server->crypto->rsa,
                    packet->pkRsakgReq.size,
                    packet->pkRsakgReq.e,
                    server->crypto->rng);
            }
            /* cache the generated key, data will be blown away */
            if (ret == 0) {
                ret = hsmCacheKeyRsa(server, server->crypto->rsa, &keyId);
            }
            wc_FreeRsaKey(server->crypto->rsa);
            if (ret == 0) {
                /* set the assigned id */
                packet->pkRsakgRes.keyId =
                    (keyId & ~WOLFHSM_KEYUSER_MASK);
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkRsakgRes);
                ret = 0;
            }
            break;
#endif  /* WOLFSSL_KEY_GEN */
        case WC_PK_TYPE_RSA:
            switch (packet->pkRsaReq.opType)
            {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                    /* in and out are after the fixed size fields */
                    in = (uint8_t*)(&packet->pkRsaReq + 1);
                    out = (uint8_t*)(&packet->pkRsaRes + 1);
                    /* init rsa key */
                    ret = wc_InitRsaKey_ex(server->crypto->rsa, NULL,
                        INVALID_DEVID);
                    /* load the key from the keystore */
                    if (ret == 0) {
                        ret = hsmLoadKeyRsa(server, server->crypto->rsa,
                            packet->pkRsaReq.keyId);
                    }
                    /* do the rsa operation */
                    if (ret == 0) {
                        field = packet->pkRsaReq.outLen;
                        ret = wc_RsaFunction( in, packet->pkRsaReq.inLen,
                            out, (word32*)&field, packet->pkRsaReq.opType,
                            server->crypto->rsa, server->crypto->rng);
                    }
                    /* free the key */
                    wc_FreeRsaKey(server->crypto->rsa);
                    if (ret == 0) {
                        /*set outLen */
                        packet->pkRsaRes.outLen = field;
                        *size = WOLFHSM_PACKET_STUB_SIZE +
                            sizeof(packet->pkRsaRes) + field;
                    }
                    break;
            }
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            /* init rsa key */
            ret = wc_InitRsaKey_ex(server->crypto->rsa, NULL,
                server->crypto->devId);
            /* load the key from the keystore */
            if (ret == 0) {
                ret = hsmLoadKeyRsa(server, server->crypto->rsa,
                    packet->pkRsaGetSizeReq.keyId);
            }
            /* get the size */
            if (ret == 0)
                ret = wc_RsaEncryptSize(server->crypto->rsa);
            wc_FreeRsaKey(server->crypto->rsa);
            if (ret > 0) {
                /*set keySize */
                packet->pkRsaGetSizeRes.keySize = ret;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkRsaGetSizeRes);
                ret = 0;
            }
            break;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            /* init ecc key */
            ret = wc_ecc_init_ex(server->crypto->eccPrivate, NULL,
                server->crypto->devId);
            /* generate the key the key */
            if (ret == 0) {
                ret = wc_ecc_make_key_ex(server->crypto->rng,
                    packet->pkEckgReq.sz, server->crypto->eccPrivate,
                    packet->pkEckgReq.curveId);
            }
            /* cache the generated key */
            if (ret == 0)
                ret = hsmCacheKeyEcc(server, server->crypto->eccPrivate,&keyId);
            /* set the assigned id */
            wc_ecc_free(server->crypto->eccPrivate);
            if (ret == 0) {
                packet->pkEckgRes.keyId = keyId;
                *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEckgRes);
            }
            break;
        case WC_PK_TYPE_ECDH:
            /* out is after the fixed size fields */
            out = (uint8_t*)(&packet->pkEcdhRes + 1);
            /* init ecc key */
            ret = wc_ecc_init_ex(server->crypto->eccPrivate, NULL,
                server->crypto->devId);
            if (ret == 0)
                ret = wc_ecc_init_ex(server->crypto->eccPrivate, NULL,
                    server->crypto->devId);
            /* load the private key */
            if (ret == 0) {
                ret = hsmLoadKeyEcc(server, server->crypto->eccPrivate,
                    packet->pkEcdhReq.privateKeyId, packet->pkEcdhReq.curveId);
            }
            /* set rng */
            if (ret == 0) {
                ret = wc_ecc_set_rng(server->crypto->eccPrivate,
                    server->crypto->rng);
            }
            /* load the public key */
            if (ret == 0) {
                ret = hsmLoadKeyEcc(server, server->crypto->eccPublic,
                    packet->pkEcdhReq.publicKeyId, packet->pkEcdhReq.curveId);
            }
            /* make shared secret */
            if (ret == 0) {
                field = server->crypto->eccPrivate->dp->size;
                ret = wc_ecc_shared_secret(server->crypto->eccPrivate,
                    server->crypto->eccPublic, out, &field);
            }
            wc_ecc_free(server->crypto->eccPrivate);
            wc_ecc_free(server->crypto->eccPublic);
            if (ret == 0) {
                packet->pkEcdhRes.sz = field;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkEcdhRes) + field;
            }
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkEccSignReq + 1);
            out = (uint8_t*)(&packet->pkEccSignRes + 1);
            /* init pivate key */
            ret = wc_ecc_init_ex(server->crypto->eccPrivate, NULL,
                server->crypto->devId);
            /* load the private key */
            if (ret == 0) {
                ret = hsmLoadKeyEcc(server, server->crypto->eccPrivate,
                    packet->pkEccSignReq.keyId, packet->pkEccSignReq.curveId);
            }
            /* sign the input */
            if (ret == 0) {
                field = WH_COMM_MTU - sizeof(packet->pkEccSignRes);
                ret = wc_ecc_sign_hash(in, packet->pkEccSignReq.sz, out,
                    &field, server->crypto->rng, server->crypto->eccPrivate);
            }
            wc_ecc_free(server->crypto->eccPrivate);
            if (ret == 0) {
                packet->pkEccSignRes.sz = field;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkEccSignRes) + field;
            }
            break;
        case WC_PK_TYPE_ECDSA_VERIFY:
            /* sig and hash are after the fixed size fields */
            sig = (uint8_t*)(&packet->pkEccVerifyReq + 1);
            hash = (uint8_t*)(&packet->pkEccVerifyReq + 1) +
                packet->pkEccVerifyReq.sigSz;
            /* init public key */
            ret = wc_ecc_init_ex(server->crypto->eccPublic, NULL,
                server->crypto->devId);
            /* load the public key */
            if (ret == 0) {
                ret = hsmLoadKeyEcc(server, server->crypto->eccPublic,
                    packet->pkEccVerifyReq.keyId,
                    packet->pkEccVerifyReq.curveId);
            }
            /* verify the signature */
            if (ret == 0) {
                ret = wc_ecc_verify_hash(sig, packet->pkEccVerifyReq.sigSz,
                    hash, packet->pkEccVerifyReq.hashSz, &res,
                    server->crypto->eccPublic);
            }
            wc_ecc_free(server->crypto->eccPublic);
            if (ret == 0) {
                packet->pkEccVerifyRes.res = res;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkEccVerifyRes);
            }
            break;
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            /* init pivate key */
            ret = wc_ecc_init_ex(server->crypto->eccPrivate, NULL,
                server->crypto->devId);
            /* load the private key */
            if (ret == 0) {
                ret = hsmLoadKeyEcc(server, server->crypto->eccPrivate,
                    packet->pkEccCheckReq.keyId, packet->pkEccCheckReq.curveId);
            }
            /* check the key */
            if (ret == 0) {
                ret = wc_ecc_check_key(server->crypto->eccPrivate);
            }
            wc_ecc_free(server->crypto->eccPrivate);
            if (ret == 0) {
                packet->pkEccCheckRes.ok = 1;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkEccCheckRes);
            }
            break;
#endif /* HAVE_ECC */
#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
            /* init private key */
            ret = wc_curve25519_init_ex(server->crypto->curve25519Private, NULL,
                server->crypto->devId);
            /* make the key */
            if (ret == 0) {
                ret = wc_curve25519_make_key(server->crypto->rng,
                    packet->pkCurve25519kgReq.sz,
                    server->crypto->curve25519Private);
            }
            /* cache the generated key */
            if (ret == 0) {
                ret = hsmCacheKeyCurve25519(server,
                    server->crypto->curve25519Private, &keyId);
            }
            /* set the assigned id */
            wc_curve25519_free(server->crypto->curve25519Private);
            if (ret == 0) {
                /* strip client_id */
                packet->pkCurve25519kgRes.keyId =
                    (keyId & ~WOLFHSM_KEYUSER_MASK);
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkCurve25519kgRes);
            }
            else
                ret = BAD_FUNC_ARG;
            break;
        case WC_PK_TYPE_CURVE25519:
            /* out is after the fixed size fields */
            out = (uint8_t*)(&packet->pkCurve25519Res + 1);
            /* init ecc key */
            ret = wc_curve25519_init_ex(server->crypto->curve25519Private, NULL,
                server->crypto->devId);
            if (ret == 0) {
                ret = wc_curve25519_init_ex(server->crypto->curve25519Public,
                    NULL, server->crypto->devId);
            }
            /* load the private key */
            if (ret == 0) {
                ret = hsmLoadKeyCurve25519(server,
                    server->crypto->curve25519Private,
                    MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
                    server->comm->client_id,
                    packet->pkCurve25519Req.privateKeyId));
            }
            /* load the public key */
            if (ret == 0) {
                ret = hsmLoadKeyCurve25519(server,
                    server->crypto->curve25519Public,
                    MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
                    server->comm->client_id,
                    packet->pkCurve25519Req.publicKeyId));
            }
            /* make shared secret */
            if (ret == 0) {
                field = CURVE25519_KEYSIZE;
                ret = wc_curve25519_shared_secret_ex(
                    server->crypto->curve25519Private,
                    server->crypto->curve25519Public, out, (word32*)&field,
                    packet->pkCurve25519Req.endian);
            }
            wc_curve25519_free(server->crypto->curve25519Private);
            wc_curve25519_free(server->crypto->curve25519Public);
            if (ret == 0) {
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkCurve25519Res) + field;
                packet->pkCurve25519Res.sz = field;
            }
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
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->rngRes) +
                packet->rngRes.sz;
        }
        break;
#endif /* !WC_NO_RNG */
#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
        /* in, out and key are after the fixed size fields */
        in = (uint8_t*)(&packet->cmacReq + 1);
        key = in + packet->cmacReq.inSz;
        out = (uint8_t*)(&packet->cmacRes + 1);
        /* do oneshot if all fields are present */
        if (packet->cmacReq.inSz != 0 && packet->cmacReq.keySz != 0 &&
            packet->cmacReq.outSz != 0) {
            field = packet->cmacReq.outSz;
            ret = wc_AesCmacGenerate_ex(server->crypto->cmac, out, &field, in,
                packet->cmacReq.inSz, key, packet->cmacReq.keySz, NULL,
                server->crypto->devId);
            packet->cmacRes.outSz = field;
        }
        else {
            /* do each operation based on which fields are set */
            /* set key if present, otherwise load the struct from keyId */
            if (packet->cmacReq.keySz != 0) {
                /* initialize cmac with key and type */
                ret = wc_InitCmac_ex(server->crypto->cmac, key,
                    packet->cmacReq.keySz, packet->cmacReq.type, NULL, NULL,
                    server->crypto->devId);
            }
            else {
                field = sizeof(server->crypto->cmac);
                keyId = packet->cmacReq.keyId;
                ret = hsmReadKey(server,
                    MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
                    server->comm->client_id, keyId), NULL,
                    (uint8_t*)server->crypto->cmac, &field);
                /* if the key size is a multiple of aes, init the key and
                 * replace it with the cmac struct later */
                if (field == AES_128_KEY_SIZE || field == AES_192_KEY_SIZE ||
                    field == AES_256_KEY_SIZE) {
                    XMEMCPY(tmpKey, (uint8_t*)server->crypto->cmac, field);
                    /* type is not a part of the update call, assume AES */
                    ret = wc_InitCmac_ex(server->crypto->cmac, tmpKey,
                        field, WC_CMAC_AES, NULL, NULL,
                        server->crypto->devId);
                }
                else if (field != sizeof(server->crypto->cmac))
                    ret = BAD_FUNC_ARG;
            }
            if (ret == 0 && packet->cmacReq.inSz != 0) {
                ret = wc_CmacUpdate(server->crypto->cmac, in,
                    packet->cmacReq.inSz);
            }
            /* do final and evict the struct if outSz is set, otherwise cache
             * the struct for a future call */
            if (ret == 0 && packet->cmacReq.outSz != 0) {
                keyId = packet->cmacReq.keyId;
                field = packet->cmacReq.outSz;
                ret = wc_CmacFinal(server->crypto->cmac, out, &field);
                packet->cmacReq.outSz = field;
                /* evict the key */
                if (ret == 0) {
                    hsmEvictKey(server,
                        MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
                        server->comm->client_id, keyId));
                }
            }
            else if (ret == 0) {
                /* cache/re-cache updated struct */
                XMEMSET((uint8_t*)meta, 0, sizeof(meta));
                if (packet->cmacReq.keySz != 0) {
                    keyId = WOLFHSM_KEYTYPE_CRYPTO;
                    ret = hsmGetUniqueId(server, &keyId);
                }
                else {
                    keyId = MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
                        server->comm->client_id, packet->cmacReq.keyId);
                }
                meta->id = keyId;
                meta->len = sizeof(server->crypto->cmac);
                ret = hsmCacheKey(server, meta, (uint8_t*)server->crypto->cmac);
                packet->cmacRes.keyId = (keyId & WOLFHSM_KEYID_MASK);
                packet->cmacRes.outSz = 0;
            }
        }
        if (ret == 0) {
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->cmacRes) +
                packet->cmacRes.outSz;
        }
        break;
#endif
    case WC_ALGO_TYPE_NONE:
    default:
        ret = NOT_COMPILED_IN;
        break;
    }
    packet->rc = ret;
    if (ret != 0)
        *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->rc);
    return 0;
}

#endif  /* WOLFHSM_NO_CRYPTO */
