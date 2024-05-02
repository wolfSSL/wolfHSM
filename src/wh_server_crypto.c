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
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

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
        ret = wc_RsaKeyToDer(key, server->cache[slotIdx].buffer,
            WOLFHSM_KEYCACHE_BUFSIZE);
    }
    if (ret > 0) {
        /* set meta */
        XMEMSET((uint8_t*)server->cache[slotIdx].meta, 0,
            sizeof(server->cache[slotIdx].meta));
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
        ret = wc_RsaPrivateKeyDecode(server->cache[slotIdx].buffer, &idx, key,
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
        /* export key */
        ret = wc_curve25519_export_key_raw(key,
            server->cache[slotIdx].buffer + CURVE25519_KEYSIZE, &privSz,
            server->cache[slotIdx].buffer, &pubSz);
    }
    if (ret == 0) {
        /* set meta */
        XMEMSET((uint8_t*)server->cache[slotIdx].meta, 0,
            sizeof(server->cache[slotIdx].meta));
        server->cache[slotIdx].meta->id = keyId;
        server->cache[slotIdx].meta->len = CURVE25519_KEYSIZE * 2;
        /* export keyId */
        *outId = keyId;
        ret = 0;
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

int wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    uint32_t field;
    uint8_t* in;
    whKeyId keyId;
    uint8_t* out;
    whPacket* packet = (whPacket*)data;
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];
#endif

    if (server == NULL || server->crypto == NULL || data == NULL || size == NULL)
        return BAD_FUNC_ARG;

    switch (action)
    {
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
                            out, &field, packet->pkRsaReq.opType,
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
                    server->crypto->curve25519Public, out, &field,
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
