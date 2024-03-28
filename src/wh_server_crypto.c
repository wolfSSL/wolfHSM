/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_packet.h"

static int hsmGetUniqueId(whServerContext* server)
{
    int i;
    int ret = 0;
    uint16_t id;
    /* try every index, unless both cache and nvm are full one will work */
    for (id = 1; id < WOLFHSM_NUM_RAMKEYS + 1; id++) {
        /* check against chache keys */
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            if (id == server->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_NUM_RAMKEYS)
            continue;
#if 0
        /* check against nvm keys */
        for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
            if (ctx->nvmMetaCache[i].id == id) {
                break;
            }
        }
        /* try again if match */
        if (i < WOLFHSM_KEYSLOT_COUNT)
            continue;
#endif
        /* break if our id didn't match either cache or nvm */
        break;
    }
    /* if we've run out of space, return MEMORY_E */
    if (ret == 0 && id >= WOLFHSM_NUM_RAMKEYS + 1)
        ret = MEMORY_E;
    /* ultimately, return found id */
    if (ret == 0)
        ret = id;
    return ret;
}

static int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in)
{
    int i;
    int foundIndex = -1;
    /* make sure id is valid */
    if (meta->id == 0)
        return BAD_FUNC_ARG;
    /* make sure the key fits in a slot */
    if (meta->len > WOLFHSM_NVM_MAX_OBJECT_SIZE)
        return BUFFER_E;
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* check for empty slot or rewrite slot */
        if (foundIndex == -1 && (server->cache[i].meta->id == 0 ||
            server->cache[i].meta->id == meta->id)) {
            foundIndex = i;
        }
    }
#if 0
    /* if no empty slots, check for a commited key we can evict */
    if (foundIndex == -1) {
        for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
            if (ctx->cache[i].commited == 1) {
                foundIndex = i;
                break;
            }
        }
    }
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return MEMORY_E;
    ctx->cache[foundIndex].commited = 0;
    /* check if the key is in nvm, mark as commited */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT; i++) {
        /* check for duplicate id, shouldn't cache a key in nvm */
        if (ctx->nvmMetaCache[i].id == meta->id)
            ctx->cache[foundIndex].commited = 1;
    }
#endif
    /* write key if slot found */
    XMEMCPY((uint8_t*)server->cache[foundIndex].buffer, in, meta->len);
    XMEMCPY((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
        sizeof(whNvmMetadata));
#ifdef WOLFHSM_SHE_EXTENSION
    /* if this was RAM_KEY, set the global so we can export */
    if (meta->id == WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_RAM_KEY_ID))
        hsmSheRamKeyPlain = 1;
#endif
    return 0;
}

static int hsmReadKey(whServerContext* server, whNvmMetadata* meta, uint8_t* out)
{
    int i;
    uint16_t searchId = meta->id;
    uint16_t outLen = meta->len;
    /* make sure id is valid */
    if (meta->id == 0)
        return BAD_FUNC_ARG;
    /* check the cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* copy the meta and key before returning */
        if (server->cache[i].meta->id == searchId) {
            /* check outLen */
            if (server->cache[i].meta->len > outLen)
                return BUFFER_E;
            XMEMCPY((uint8_t*)meta, (uint8_t*)server->cache[i].meta,
                sizeof(whNvmMetadata));
            XMEMCPY(out, server->cache[i].buffer, meta->len);
            return 0;
        }
    }
    return BAD_FUNC_ARG;
#if 0
    /* setup address */
    if (ctx->partition == 1)
        addr = WOLFHSM_PART_1;
    /* find id in list */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT; i++) {
        /* check id */
        if (ctx->nvmMetaCache[i].id == searchId)
            break;
        /* keep track of length used by previous keys */
        keyOffset += ctx->nvmMetaCache[i].len;
    }
    /* if we looped to the end, no match */
    if (i >= WOLFHSM_KEYSLOT_COUNT)
        ret = BAD_FUNC_ARG;
    /* check the length, meta->len is the return size */
    if (ret == 0 && ctx->nvmMetaCache[i].len > outLen)
        ret = BUFFER_E;
    /* read key */
    if (ret == 0) {
        ret = hal_flash_read(addr + WOLFHSM_HEADER_SIZE + keyOffset, out,
            ctx->nvmMetaCache[i].len);
    }
    /* calculate key digest */
    if (ret == 0)
        ret = wc_InitSha256_ex(sha, ctx->heap, ctx->devId);
    if (ret == 0)
        ret = wc_Sha256Update(sha, out, ctx->nvmMetaCache[i].len);
    if (ret == 0)
        ret = wc_Sha256Final(sha, digest);
    /* validate key */
    if (XMEMCMP(digest, ctx->nvmMetaCache[i].confDigest, WOLFHSM_DIGEST_STUB)
        != 0) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* cache key if free slot, will only kick out other commited keys */
        hsmCacheKey(ctx, &ctx->nvmMetaCache[i], out);
        /* update out meta with nvm cache contents */
        XMEMCPY(meta, &ctx->nvmMetaCache[i], sizeof(NvmMetaData));
    }
#ifdef WOLFHSM_SHE_EXTENSION
    /* use empty string if we couldn't find the master ecu key */
    if (ret != 0 && searchId == WOLFHSM_SHE_MASTER_ECU_KEY_ID) {
        XMEMSET(out, 0, WOLFHSM_SHE_KEY_SZ);
        meta->len = WOLFHSM_SHE_KEY_SZ;
        meta->id = searchId;
        ret = 0;
    }
#endif
    return ret;
#endif
}

static int hsmCacheKeyRsa(whServerContext* server, RsaKey* key)
{
    int ret = 0;
    whNvmMetadata meta[1] = {0};
    byte keyBuf[2048];
    /* export key */
    ret = wc_RsaKeyToDer(key, keyBuf, sizeof(keyBuf));
    /* write key, no flags */
    if (ret > 0) {
        meta->len = ret;
        ret = hsmGetUniqueId(server);
    }
    if (ret > 0 ) {
        meta->id = ret;
        ret = hsmCacheKey(server, meta, keyBuf);
    }
    if (ret == 0)
        ret = meta->id;
    return ret;
}

static int hsmLoadKeyRsa(whServerContext* server, RsaKey* key, uint16_t keyId)
{
    int ret;
    uint32_t idx = 0;
    whNvmMetadata meta[1] = {0};
    byte keyBuf[2048];
    /* retrieve the key */
    meta->id = keyId;
    meta->len = sizeof(keyBuf);
    ret = hsmReadKey(server, meta, keyBuf);
    /* decode the key */
    if (ret == 0)
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, key, meta->len);

    return ret;
}

static int hsmCacheKeyCurve25519(whServerContext* server, curve25519_key* key)
{
    int ret;
    uint32_t privSz = CURVE25519_KEYSIZE;
    uint32_t pubSz = CURVE25519_KEYSIZE;
    whNvmMetadata meta[1] = {0};
    byte keyBuf[CURVE25519_KEYSIZE * 2];
    /* store public, then private so that loading an external public only key
     * will work along with our keys */
    ret = wc_curve25519_export_key_raw(key, keyBuf + CURVE25519_KEYSIZE,
        &privSz, keyBuf, &pubSz);
    /* cache key */
    if (ret == 0) {
        ret = hsmGetUniqueId(server);
    }
    if (ret > 0) {
        meta->len = privSz + pubSz;
        meta->id = ret;
        ret = hsmCacheKey(server, meta, keyBuf);
    }
    if (ret == 0)
        ret = meta->id;
    return ret;
}

static int hsmLoadKeyCurve25519(whServerContext* server, curve25519_key* key, uint16_t keyId)
{
    int ret;
    uint32_t privSz = CURVE25519_KEYSIZE;
    uint32_t pubSz = CURVE25519_KEYSIZE;
    whNvmMetadata meta[1] = {0};
    byte keyBuf[CURVE25519_KEYSIZE * 2];
    /* retrieve the key */
    meta->id = keyId;
    meta->len = privSz + pubSz;
    ret = hsmReadKey(server, meta, keyBuf);
    /* decode the key */
    if (ret == 0)
        ret = wc_curve25519_import_public(keyBuf, pubSz, key);
    /* only import private if what we got back holds 2 keys */
    if (ret == 0 && meta->len == CURVE25519_KEYSIZE * 2)
        ret = wc_curve25519_import_private(keyBuf + pubSz, privSz, key);
    return ret;
}

static int hsmCacheKeyEcc(whServerContext* server, ecc_key* key)
{
    int ret;
    uint32_t qxLen;
    uint32_t qyLen;
    uint32_t qdLen;
    whNvmMetadata meta[1] = {0};
    byte keyBuf[ECC_MAXSIZE_GEN * 3];
    /* export key */
    qxLen = qyLen = qdLen = key->dp->size;
    ret = wc_ecc_export_private_raw(key, keyBuf, &qxLen,
        keyBuf + qxLen, &qyLen, keyBuf + qxLen + qyLen, &qdLen);
    /* cache key */
    if (ret == 0) {
        ret = hsmGetUniqueId(server);
    }
    if (ret > 0) {
        meta->len = qxLen + qyLen + qdLen;
        meta->id = ret;
        ret = hsmCacheKey(server, meta, keyBuf);
    }
    if (ret == 0)
        ret = meta->id;
    return ret;
}

static int hsmLoadKeyEcc(whServerContext* server, ecc_key* key, uint16_t keyId,
    int curveId)
{
    int ret;
    uint32_t keySz;
    whNvmMetadata meta[1] = {0};
    byte keyBuf[ECC_MAXSIZE_GEN * 3];
    /* retrieve the key */
    meta->id = keyId;
    meta->len = sizeof(keyBuf);
    ret = hsmReadKey(server, meta, keyBuf);
    /* decode the key */
    if (ret == 0) {
        keySz = meta->len / 3;
        ret = wc_ecc_import_unsigned(key, keyBuf, keyBuf + keySz,
            keyBuf + keySz * 2, curveId);
    }
    return ret;
}

int wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    int res = 0;
    uint32_t field;
    uint8_t* in;
    uint8_t* out;
    uint8_t* sig;
    uint8_t* hash;
    whPacket* packet = (whPacket*)data;
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];
#endif

    if (server == NULL || data == NULL || size == NULL)
        return BAD_FUNC_ARG;

    switch (action)
    {
    case WC_ALGO_TYPE_PK:
        switch (packet->pkAnyReq.type)
        {
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
            /* cache the generated key */
            if (ret == 0)
                ret = hsmCacheKeyRsa(server, server->crypto->rsa);
            wc_FreeRsaKey(server->crypto->rsa);
            if (ret > 0) {
                /* set the assigned id */
                packet->pkRsakgRes.keyId = ret;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkRsakgRes);
                ret = 0;
            }
            break;
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
                        ret = hsmLoadKeyRsa(server,
                            server->crypto->rsa,
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
            ret = wc_InitRsaKey_ex(server->crypto->rsa, NULL, INVALID_DEVID);
            /* load the key from the keystore */
            if (ret == 0) {
                ret = hsmLoadKeyRsa(server,
                    server->crypto->rsa,
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
                ret = hsmCacheKeyEcc(server, server->crypto->eccPrivate);
            /* set the assigned id */
            wc_ecc_free(server->crypto->eccPrivate);
            if (ret > 0) {
                packet->pkEckgRes.keyId = ret;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkEckgRes);
                ret = 0;
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
                ret = hsmCacheKeyCurve25519(server, server->crypto->curve25519Private);
            }
            /* set the assigned id */
            wc_curve25519_free(server->crypto->curve25519Private);
            if (ret > 0) {
                packet->pkCurve25519kgRes.keyId = ret;
                *size = WOLFHSM_PACKET_STUB_SIZE +
                    sizeof(packet->pkCurve25519kgRes);
                ret = 0;
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
                    packet->pkCurve25519Req.privateKeyId);
            }
            /* load the public key */
            if (ret == 0) {
                ret = hsmLoadKeyCurve25519(server,
                    server->crypto->curve25519Public,
                    packet->pkEcdhReq.publicKeyId);
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
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
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
    case WC_ALGO_TYPE_NONE:
    default:
        ret = NOT_COMPILED_IN;
        break;
    }
    packet->rc = ret;
    return 0;
}
