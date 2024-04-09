/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

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

static int hsmCacheKeyCurve25519(whServerContext* server, curve25519_key* key)
{
    int ret;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_KEYSIZE;
    whNvmMetadata meta[1] = {{0}};
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
        XMEMSET(meta, 0, sizeof(whNvmMetadata));
        meta->len = privSz + pubSz;
        meta->id = ret;
        ret = hsmCacheKey(server, meta, keyBuf);
    }
    if (ret == 0)
        ret = meta->id;
    return ret;
}

static int hsmLoadKeyCurve25519(whServerContext* server, curve25519_key* key, whKeyId keyId)
{
    int ret;
    uint32_t privSz = CURVE25519_KEYSIZE;
    uint32_t pubSz = CURVE25519_KEYSIZE;
    uint32_t size = privSz + pubSz;
    byte keyBuf[CURVE25519_KEYSIZE * 2];
    ret = hsmReadKey(server, keyId, NULL, keyBuf, &size);
    /* decode the key */
    if (ret == 0)
        ret = wc_curve25519_import_public(keyBuf, pubSz, key);
    /* only import private if what we got back holds 2 keys */
    if (ret == 0 && size == CURVE25519_KEYSIZE * 2)
        ret = wc_curve25519_import_private(keyBuf + pubSz, privSz, key);
    return ret;
}

int wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    word32 field;
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
