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
 * src/wh_client_crypto.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */


/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_utils.h"


/* Components */
#include "wolfhsm/wh_comm.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_packet.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

/** Forward declarations */
#ifdef HAVE_ECC
/* Server creates a key based on incoming flags */
static int _EccMakeKey(whClientContext* ctx,
        int size, int curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint16_t label_len, uint8_t* label,
        ecc_key* key);
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Server creates a key based on incoming flags */
static int _Curve25519MakeKey(whClientContext* ctx,
        uint16_t size,
        whKeyId *inout_key_id, whNvmFlags flags,
        const uint8_t* label, uint16_t label_len,
        curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifndef NO_RSA
/* Make an RSA key on the server based on the flags */
static int _RsaMakeKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whNvmFlags flags,  uint32_t label_len, uint8_t* label,
        whKeyId *inout_key_id, RsaKey* rsa);
#endif


/** Implementations */
int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size)
{
    int ret = WH_ERROR_OK;
    whPacket* packet;
    wh_Packet_rng_req* req;
    wh_Packet_rng_res* res;
    uint16_t max_size;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = &packet->rngReq;
    res = &packet->rngRes;
    uint8_t* res_out = (uint8_t*)(res + 1);

    /* Compute maximum response size */
    max_size = (uint16_t)(WOLFHSM_CFG_COMM_DATA_LEN -
            (res_out - (uint8_t*)packet));

    while ( (size > 0) &&
            (ret == WH_ERROR_OK) ) {
        /* Request Message */
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_RNG;
        uint16_t req_len = WH_PACKET_STUB_SIZE + sizeof(*req);
        uint16_t res_len;

        uint16_t req_size = size;
        if (req_size > max_size) {
            req_size = max_size;
        }
        req->sz = req_size;

        /* write request */
        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                (uint8_t*)packet);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == WH_ERROR_OK) {
            if (packet->rc != 0) {
                ret = packet->rc;
            } else {
                if (res->sz <= req_size) {
                    if(out != NULL) {
                        memcpy(out, res_out, res->sz);
                        out += res->sz;
                    }
                    size -= res->sz;
                }
            }
        }
    }
    return ret;
}

#ifndef NO_AES

#ifdef HAVE_AES_CBC
int wh_Client_AesCbc(whClientContext* ctx,
        Aes* aes, int enc,
        const uint8_t* in, uint32_t len,
        uint8_t* out)
{
    int ret = WH_ERROR_OK;
    uint16_t blocks = len / AES_BLOCK_SIZE;
    whPacket* packet;

    if (blocks == 0) {
        /* Nothing to do. */
        return WH_ERROR_OK;
    }

    if (    (ctx == NULL) ||
            (aes == NULL) ||
            ((len % AES_BLOCK_SIZE) != 0) ||
            (in == NULL) ||
            (out == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (ret == WH_ERROR_OK) {
        uint32_t last_offset = (blocks - 1) * AES_BLOCK_SIZE;

        uint32_t key_len    = aes->keylen;
        const uint8_t* key  = (const uint8_t*)(aes->devKey);
        whKeyId key_id      = WH_DEVCTX_TO_KEYID(aes->devCtx);
        uint8_t* iv         = (uint8_t*)aes->reg;
        uint32_t iv_len     = AES_IV_SIZE;

        uint16_t group      = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action     = WC_ALGO_TYPE_CIPHER;
        uint16_t type       = WC_CIPHER_AES_CBC;

        /* Request packet */
        wh_Packet_cipher_aescbc_req* req = &packet->cipherAesCbcReq;
        uint8_t* req_in     = (uint8_t*)(req + 1);
        uint8_t* req_key    = req_in + len;
        uint8_t* req_iv     = req_key + key_len;

        uint32_t req_len    = WH_PACKET_STUB_SIZE + sizeof(*req) + len +
                                key_len + iv_len;


    #ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] %s: enc:%d keylen:%d ivsz:%d insz:%d reqsz:%u "
                          "blocks:%u lastoffset:%u\n",
                    __func__,enc, key_len, iv_len, len,  req_len,
                    blocks, last_offset);
    #endif

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            /* if we're using an HSM key return BAD_FUNC_ARG */
            if (WH_KEYID_ISERASED(key_id)) {
                return CRYPTOCB_UNAVAILABLE;
            } else {
                return WH_ERROR_BADARGS;
            }
        }

        /* setup request packet */
        req->type       = type;
        req->enc        = enc;
        req->keyLen     = key_len;
        req->sz         = len;
        req->keyId      = key_id;
        if (    (in != NULL) &&
                (len > 0) ) {
            memcpy(req_in, in, len);
        }
        if (    (key != NULL) &&
                (key_len > 0) ) {
            memcpy(req_key, key, key_len);
        }
        if (    (iv != NULL) &&
                (iv_len > 0) ) {
            memcpy(req_iv, iv, iv_len);
        }

        /* Determine where ciphertext is for chaining */
        if(enc == 0) {
            /* Update the CBC state with the last cipher text black */
            /* III Must do this before the decrypt if in-place */
            XMEMCPY(iv, in + last_offset, iv_len);
        }

    #ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] in: \n", req_in, len);
        wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
        wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
    #endif

        /* write request */
    #ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] req packet: \n", (uint8_t*)packet, req_len);
    #endif
        ret = wh_Client_SendRequest(ctx, group, action, req_len, (uint8_t*)packet);
        /* read response */
        if (ret == WH_ERROR_OK) {
            /* Response packet */
            wh_Packet_cipher_aescbc_res* res = &packet->cipherAesCbcRes;
            uint8_t* res_out    = (uint8_t*)(res + 1);
            uint16_t res_len    = 0;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s Rcv Res ret:%d rc:%d res_len:%u\n",
                    __func__, ret, packet->rc, res_len);
            wh_Utils_Hexdump("[client] res packet: \n", (uint8_t*)packet, res_len);
#endif
            if (ret == WH_ERROR_OK) {
                if (packet->rc != 0) {
                    ret = packet->rc;
                } else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] out size:%d res_len:%d\n",
                            res->sz, res_len);
                    wh_Utils_Hexdump("[client] res_out: \n", out, res->sz);
#endif
                    /* copy the response res_out */
                    memcpy(out, res_out, res->sz);
                    if (enc != 0) {
                        /* Update the CBC state with the last cipher text black */
                        memcpy(iv, out + last_offset, AES_IV_SIZE);
                    }
                }
            }
        }
    }
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
int wh_Client_AesGcm(whClientContext* ctx,
        Aes* aes, int enc,
        const uint8_t* in, uint32_t len,
        const uint8_t* iv, uint32_t iv_len,
        const uint8_t* authin, uint32_t authin_len,
        const uint8_t* dec_tag, uint8_t* enc_tag, uint32_t tag_len,
        uint8_t* out)
{
    int ret = 0;

    if (    (ctx == NULL) ||
            (aes == NULL) ||
            ((in == NULL) && (len > 0))||
            ((iv == NULL) && (iv_len > 0)) ||
            ((authin == NULL) && (authin_len > 0)) ||
            ((enc == 0) && (dec_tag == NULL)) ||
            (out == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    uint16_t group      = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action     = WC_ALGO_TYPE_CIPHER;
    uint16_t type       = WC_CIPHER_AES_GCM;
    uint16_t dataSz     = 0;

    uint32_t key_len    = aes->keylen;
    const uint8_t* key  = (const uint8_t*)(aes->devKey);
    whKeyId key_id      = WH_DEVCTX_TO_KEYID(aes->devCtx);

    whPacket* packet    = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);

    /* Request packet */
    wh_Packet_cipher_aesgcm_req* req = &packet->cipherAesGcmReq;
    uint8_t* req_in     = (uint8_t*)(req + 1);
    uint8_t* req_key    = req_in + len;
    uint8_t* req_iv     = req_key + key_len;
    uint8_t* req_authin = req_iv + iv_len;
    uint8_t* req_dec_tag= req_authin + authin_len;

    uint32_t req_len    = WH_PACKET_STUB_SIZE + sizeof(*req) + len +
                            key_len + iv_len + authin_len +
                            ((enc == 0) ? tag_len : 0);

    /* Response packet */
    wh_Packet_cipher_aesgcm_res* res = &packet->cipherAesGcmRes;
    uint8_t* res_out    = (uint8_t*)(res + 1);
    uint8_t* res_enc_tag= res_out + len;

    uint32_t res_len    = WH_PACKET_STUB_SIZE+ sizeof(*res) + len +
                            ((enc == 0) ? 0: tag_len);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] AESGCM: enc:%d keylen:%d ivsz:%d insz:%d authinsz:%d authtagsz:%d reqsz:%u ressz:%u\n",
                enc, key_len, iv_len, len, authin_len, tag_len,
                req_len, res_len);
    printf("[client] AESGCM: req:%p in:%p key:%p iv:%p authin:%p dec_tag:%p res:%p out:%p res_enc_tag:%p\n",
            req, req_in, req_key, req_iv, req_authin, req_dec_tag, res, res_out, res_enc_tag);
#endif
    if (    (req_len > WOLFHSM_CFG_COMM_DATA_LEN) ||
            (res_len > WOLFHSM_CFG_COMM_DATA_LEN)) {
        /* if we're using an HSM key return BAD_FUNC_ARG */
        if (WH_KEYID_ISERASED(key_id)) {
            return CRYPTOCB_UNAVAILABLE;
        } else {
            return BAD_FUNC_ARG;
        }
    }

    /* setup request packet */
    req->type       = type;
    req->enc        = enc;
    req->keyLen     = key_len;
    req->sz         = len;
    req->ivSz       = iv_len;
    req->authInSz   = authin_len;
    req->authTagSz  = tag_len;
    req->keyId      = key_id;
    if (in != NULL) {
        memcpy(req_in, in, len);
    }
    memcpy(req_key, key, key_len);
    if (iv != NULL) {
        memcpy(req_iv, iv, iv_len);
    }
    if (authin != NULL) {
        memcpy(req_authin, authin, authin_len);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] in: \n", req_in, len);
    wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
    wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
    wh_Utils_Hexdump("[client] authin: \n", req_authin, authin_len);
#endif
    /* set auth tag by direction */
    if (enc == 0) {
        memcpy(req_dec_tag, dec_tag, tag_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] dec tag: \n", req_dec_tag, tag_len);
#endif
    }

    /* write request */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] AESGCM req packet: \n", (uint8_t*)packet, req_len);
#endif
    ret = wh_Client_SendRequest(ctx, group, action, req_len, (uint8_t*)packet);
    /* read response */
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] GCM Rcv Res ret:%d rc:%d size:%d res_len:%u\n",
            ret, packet->rc, dataSz, res_len);
    wh_Utils_Hexdump("[client] AESGCM res packet: \n", (uint8_t*)packet, res_len);
#endif
    if (ret == 0) {
        if (packet->rc != 0) {
            ret = packet->rc;
        } else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] out size:%d datasz:%d tag_len:%d\n",
                    res->sz, dataSz, res->authTagSz);
            wh_Utils_Hexdump("[client] res_out: \n", out, res->sz);
#endif
            /* copy the response res_out */
            if (    (out != NULL) &&
                    (res->sz == len) ) {
                memcpy(out, res_out, res->sz);
            }
            /* write the authTag if applicable */
            if (    (enc != 0) &&
                    (enc_tag != NULL) &&
                    (res->authTagSz == tag_len)) {
                memcpy(enc_tag, res_enc_tag, res->authTagSz);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] res tag_len:%d exp tag_len:%u",
                        res->authTagSz, tag_len);
                wh_Utils_Hexdump("[client] enc authtag: ",  res_enc_tag,
                        res->authTagSz);
#endif
            }
        }
    }
    return ret;
}
#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#ifdef HAVE_ECC
int wh_Client_EccSetKeyId(ecc_key* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_EccGetKeyId(ecc_key* key, whKeyId* outId)
{
    if (    (key == NULL) ||
            (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_EccImportKey(whClientContext* ctx, ecc_key* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint16_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    whKeyId key_id = WH_KEYID_ERASED;
    byte buffer[ECC_BUFSIZE] = {0};
    uint16_t buffer_len = 0;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if(inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    ret = wh_Crypto_EccSerializeKeyDer(key, sizeof(buffer),buffer, &buffer_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s serialize ret:%d, key:%p, max_size:%u, buffer:%p, outlen:%u\n",
            __func__, ret, key, (unsigned int)sizeof(buffer), buffer, buffer_len);
#endif
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx,
                flags, label, label_len,
                buffer, buffer_len, &key_id);
        if (    (ret == WH_ERROR_OK) &&
                (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s label:%.*s ret:%d keyid:%u\n",
            __func__, label_len, label, ret, key_id);
#endif
    return ret;
}

int wh_Client_EccExportKey(whClientContext* ctx, whKeyId keyId,
        ecc_key* key,
        uint16_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    /* buffer cannot be larger than MTU */
    byte buffer[ECC_BUFSIZE] = {0};
    uint16_t buffer_len = sizeof(buffer);

    if (    (ctx == NULL) ||
            WH_KEYID_ISERASED(keyId) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret = wh_Client_KeyExport(ctx, keyId,
            label, label_len,
            buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Update the key structure */
        ret = wh_Crypto_EccDeserializeKeyDer(buffer, buffer_len, key);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x key:%p ret:%d label:%.*s\n",
            __func__, keyId, key, ret, (int)label_len, label);
#endif
    return ret;
}

static int _EccMakeKey(whClientContext* ctx,
        int size, int curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint16_t label_len, uint8_t* label,
        ecc_key* key)
{
    int ret = WH_ERROR_OK;
    whPacket* packet = NULL;
    whKeyId key_id = WH_KEYID_ERASED;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* No other calls before here, so this is always true */
    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint32_t type = WC_PK_TYPE_EC_KEYGEN;

        wh_Packet_pk_eckg_req* req = &packet->pkEckgReq;
        uint16_t req_len = WH_PACKET_STUB_SIZE + sizeof(*req);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            memset(req, 0, sizeof(*req));
            req->type = type;
            req->sz = size;
            req->curveId = curveId;
            req->flags = flags;
            req->keyId = key_id;
            if (    (label != NULL) &&
                    (label_len > 0) ) {
                if (label_len > WH_NVM_LABEL_LEN) {
                    label_len = WH_NVM_LABEL_LEN;
                }
                memcpy(req->label, label, label_len);
            }

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                    (uint8_t*)packet);
        #ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s Req sent:size:%u, ret:%d\n",
                    __func__, req->sz, ret);
        #endif
            if (ret == 0) {
                /* Response Message */
                wh_Packet_pk_eckg_res* res = &packet->pkEckgRes;
                uint8_t* key_der = (uint8_t*)(res + 1);
                uint16_t res_len;

                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);

            #ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s Res recv:keyid:%u, len:%u, rc:%d, ret:%d\n",
                        __func__, res->keyId, res->len, packet->rc, ret);
            #endif

                if (ret == WH_ERROR_OK) {
                    if (packet->rc == WH_ERROR_OK) {
                        /* Key is cached on server or is ephemeral */
                        key_id = (whKeyId)(res->keyId);

                        /* Update output variable if requested */
                        if (inout_key_id != NULL) {
                            *inout_key_id = key_id;
                        }

                        /* Update the context if provided */
                        if (key != NULL) {
                            uint16_t der_size = (uint16_t)(res->len);
                            /* Set the key_id.  Should be ERASED if EPHEMERAL */
                            wh_Client_EccSetKeyId(key, key_id);

                            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                                /* Response has the exported key */
                                ret = wh_Crypto_EccDeserializeKeyDer(key_der,
                                        der_size, key);
            #ifdef DEBUG_CRYPTOCB_VERBOSE
                                wh_Utils_Hexdump("[client] KeyGen export:",
                                        key_der, der_size);
            #endif
                            }
                        }
                    } else {
                        /* Server detected a problem with generation */
                        ret = packet->rc;
                    }
                }
            }
        } else {
            ret = WH_ERROR_BADARGS;
        }
    }
    return ret;
}

int wh_Client_EccMakeCacheKey(whClientContext* ctx,
        int size, int curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint16_t label_len, uint8_t* label)
{
    /* Valid keyid ptr is required in this form */
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _EccMakeKey(ctx,
            size, curveId,
            inout_key_id, flags,
            label_len, label,
            NULL);
}

int wh_Client_EccMakeExportKey(whClientContext* ctx,
        int size, int curveId, ecc_key* key)
{
    /* Valid key is required for this form */
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _EccMakeKey(ctx,
            size, curveId,
            NULL, WH_NVM_FLAGS_EPHEMERAL,
            0, NULL,
            key);
}

int wh_Client_EccSharedSecret(whClientContext* ctx,
                                ecc_key* priv_key, ecc_key* pub_key,
                                uint8_t* out, uint16_t *out_size)
{
    int ret = WH_ERROR_OK;
    whPacket* packet;

    /* Transaction state */
    whKeyId prv_key_id;
    int prv_evict = 0;
    whKeyId pub_key_id;
    int pub_evict = 0;

    if (    (ctx == NULL) ||
            (pub_key == NULL) ||
            (priv_key == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    pub_key_id = WH_DEVCTX_TO_KEYID(pub_key->devCtx);
    if (    (ret == WH_ERROR_OK) &&
            WH_KEYID_ISERASED(pub_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempEccDh-pub";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx,
                pub_key, &pub_key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            pub_evict = 1;
        }
    }

    prv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if (    (ret == WH_ERROR_OK) &&
            WH_KEYID_ISERASED(prv_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempEccDh-prv";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx,
                priv_key, &prv_key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message*/
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint32_t type = WC_PK_TYPE_ECDH;

        wh_Packet_pk_ecdh_req* req = &packet->pkEcdhReq;
        uint16_t req_len =  WH_PACKET_STUB_SIZE + sizeof(*req);
        uint32_t options = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (pub_evict != 0) {
                options |= WH_PACKET_PK_ECDH_OPTIONS_EVICTPUB;
            }
            if (prv_evict != 0) {
                options |= WH_PACKET_PK_ECDH_OPTIONS_EVICTPRV;
            }

            memset(req, 0, sizeof(*req));
            req->type           = type;
            req->options        = options;
            req->privateKeyId   = prv_key_id;
            req->publicKeyId    = pub_key_id;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                (uint8_t*)packet);
    #ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s req sent. priv:%u pub:%u\n",
                    __func__, req->privateKeyId, req->publicKeyId);
    #endif
            if (ret == WH_ERROR_OK) {
                /* Server will evict.  Reset our flags */
                pub_evict = prv_evict = 0;

                /* Response Message */
                wh_Packet_pk_ecdh_res* res = &packet->pkEcdhRes;
                uint8_t* res_out = (uint8_t*)(res + 1);
                uint16_t res_len;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
    #ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s resp packet recv. ret:%d rc:%d\n",
                        __func__, ret, packet->rc);
    #endif
                if (ret == WH_ERROR_OK) {
                    if (packet->rc != 0)
                        ret = packet->rc;
                    else {
                        if (out_size != NULL) {
                            *out_size = res->sz;
                        }
                        if (out != NULL) {
                            memcpy(out, res_out, res->sz);
                        }
        #ifdef DEBUG_CRYPTOCB_VERBOSE
                        wh_Utils_Hexdump("[client] Eccdh:", res_out, res->sz);
        #endif
                    }
                }
            }
        } else {
            ret = WH_ERROR_BADARGS;
        }
    }

    /* Evict the keys manually on error */
    if(pub_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if(prv_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, prv_key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}


int wh_Client_EccSign(whClientContext* ctx,
        ecc_key* key,
        const uint8_t* hash, uint16_t hash_len,
        uint8_t* sig, uint16_t *inout_sig_len)
{
    int ret = 0;
    whPacket* packet;

    /* Transaction state */
    whKeyId key_id;
    int evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
        __func__, ctx, key, hash, (unsigned)hash_len, sig, inout_sig_len);
#endif

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((hash == NULL) && (hash_len > 0)) ||
            ((sig != NULL) && (inout_sig_len == NULL)) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    #ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x, in_len:%u, inout_len:%p\n",
            __func__, key_id, hash_len, inout_sig_len);
    #endif

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempEccSign";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx,
                key, &key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group      = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action     = WC_ALGO_TYPE_PK;
        uint32_t type       = WC_PK_TYPE_ECDSA_SIGN;

        wh_Packet_pk_ecc_sign_req* req = &packet->pkEccSignReq;
        uint8_t* req_hash   = (uint8_t*)(req + 1);
        uint16_t req_len    = WH_PACKET_STUB_SIZE + sizeof(*req) + hash_len;
        uint32_t options    = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_PACKET_PK_ECCSIGN_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->type = type;
            req->options = options;
            req->keyId = key_id;
            req->sz = hash_len;
            if( (hash != NULL) && (hash_len > 0)) {
                memcpy(req_hash, hash, hash_len);
            }

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                    (uint8_t*)packet);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Response Message */
                wh_Packet_pk_ecc_sign_res* res = &packet->pkEccSignRes;
                uint8_t* res_sig = (uint8_t*)(res + 1);
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    if (packet->rc == 0) {
                        uint16_t sig_len = res->sz;
                        /* check inoutlen and read out */
                        if (inout_sig_len != NULL) {
                            if (sig_len > *inout_sig_len) {
                                /* Silently truncate the signature */
                                sig_len = *inout_sig_len;
                            }
                            *inout_sig_len = sig_len;
                            if (    (sig != NULL) &&
                                    (sig_len > 0)) {
                                memcpy(sig, res_sig, sig_len);
                            }
                        }
                    } else {
                        ret = packet->rc;
                    }
                }
            }
        } else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if(evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

int wh_Client_EccVerify(whClientContext* ctx, ecc_key* key,
        const uint8_t* sig, uint16_t sig_len,
        const uint8_t* hash, uint16_t hash_len,
        int *out_res)
{
    int ret = 0;
    whPacket* packet;

    /* Transaction state */
    whKeyId key_id;
    int evict = 0;
    int export_pub_key = 0;


#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s ctx:%p key:%p, sig:%p sig_len:%u, hash:%p hash_len:%u out_res:%p\n",
        __func__, ctx, key, sig, sig_len, hash, hash_len, out_res);
#endif

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((sig == NULL) && (sig_len > 0)) ||
            ((hash == NULL) && (hash_len > 0)) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (key->type == ECC_PRIVATEKEY_ONLY) {
        export_pub_key = 1;
    }
    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempEccVerify";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx,
                key, &key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == 0) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t type = WC_PK_TYPE_ECDSA_VERIFY;

        wh_Packet_pk_ecc_verify_req* req = &packet->pkEccVerifyReq;
        uint32_t options = 0;
        /* sig and hash are after the fixed size fields */
        uint8_t* req_sig = (uint8_t*)(req + 1);
        uint8_t* req_hash = req_sig + sig_len;
        uint16_t req_len = WH_PACKET_STUB_SIZE + sizeof(*req) +
                sig_len + hash_len;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            /* Set request packet members */
            if (evict != 0) {
                options |= WH_PACKET_PK_ECCVERIFY_OPTIONS_EVICT;
            }
            if (export_pub_key != 0) {
                options |= WH_PACKET_PK_ECCVERIFY_OPTIONS_EXPORTPUB;
            }

            memset(req, 0, sizeof(*req));
            req->type = type;
            req->options = options;
            req->keyId = key_id;
            req->sigSz = sig_len;
            if( (sig != NULL) && (sig_len > 0)) {
                XMEMCPY(req_sig, sig, sig_len);
            }
            req->hashSz = hash_len;
            if( (hash != NULL) && (hash_len > 0)) {
                XMEMCPY(req_hash, hash, hash_len);
            }

            /* write request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                (uint8_t*)packet);

            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;
                /* Response Message */
                wh_Packet_pk_ecc_verify_res* res = &packet->pkEccVerifyRes;
                uint8_t* res_pub_der = (uint8_t*)(res + 1);
                uint32_t res_der_size = 0;
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret == 0) {
                    if (packet->rc == 0) {
                        *out_res = res->res;
                        res_der_size = res->pubSz;
                        if (res_der_size > 0) {
                            /* Update the key with the generated public key */
                            ret = wh_Crypto_EccUpdatePrivateOnlyKeyDer(key,
                                    res_der_size, res_pub_der);
                        }
                    } else {
                        ret = packet->rc;
                    }
                }
            }
        } else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if(evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

#if 0
int wh_Client_EccCheckPubKey(whClientContext* ctx, ecc_key* key,
        const uint8_t* pub_key, uint16_t pub_key_len)
{
/* TODO: Check if keyid is set on incoming key.
 *      if not, import private key to server
 *      send request with pub key der
 *      server creates new key with private and public.  check
 *      evict temp key
 */
    int ret;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            (pub_key == NULL) ||
            (pub_key_len == 0) ) {
        return WH_ERROR_BADARGS;
    }
    int curve_id = wc_ecc_get_curve_id(key->idx);
    whKeyId key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Request packet */
    wh_Packet_pk_ecc_check_req* req = &packet->pkEccCheckReq;
    uint8_t* req_pub_key = (uint8_t*)(req + 1);

    req->type = WC_PK_TYPE_EC_CHECK_PRIV_KEY;
    req->keyId = key_id;
    req->curveId = curve_id;

    /* Response packet */
    wh_Packet_pk_ecc_check_res* res = &packet->pkEccCheckRes;


    /* write request */
    ret = wh_Client_SendRequest(ctx, group,
        WC_ALGO_TYPE_PK,
        WH_PACKET_STUB_SIZE + sizeof(packet->pkEccCheckReq),
        (uint8_t*)packet);
    /* read response */
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        if (packet->rc != 0)
            ret = packet->rc;
    }
}
#endif /* 0 */

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
int wh_Client_Curve25519SetKeyId(curve25519_key* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    /* TODO: Eliminate this and handle remote keys cleaner */
    key->pubSet = 1;
    key->privSet = 1;
    return WH_ERROR_OK;
}

int wh_Client_Curve25519GetKeyId(curve25519_key* key, whKeyId* outId)
{
    if (    (key == NULL) ||
            (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_Curve25519ImportKey(whClientContext* ctx, curve25519_key* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint16_t label_len, uint8_t* label)

{
    int ret = 0;
    whKeyId key_id = WH_KEYID_ERASED;
    byte buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t buffer_len = 0;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if(inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    buffer_len = sizeof(buffer);
    ret        = wh_Crypto_Curve25519SerializeKey(key, buffer, &buffer_len);
    if (ret == 0) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx,
                flags, label, label_len,
                buffer, buffer_len, &key_id);
        if (inout_keyId != NULL) {
            *inout_keyId = key_id;
        }
#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_CRYPTOCB_VERBOSE)
        printf("[client] importKey: cached keyid=%u\n", key_id);
        wh_Utils_Hexdump("[client] importKey: key=", buffer, buffer_len);
#endif
    }
    return ret;
}

int wh_Client_Curve25519ExportKey(whClientContext* ctx, whKeyId keyId,
        curve25519_key* key,
        uint16_t label_len, uint8_t* label)
{
    int ret = 0;
    /* buffer cannot be larger than MTU */
    byte buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t buffer_len = sizeof(buffer);

    if (    (ctx == NULL) ||
            WH_KEYID_ISERASED(keyId) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret = wh_Client_KeyExport(ctx, keyId,
            label, label_len,
            buffer, &buffer_len);
    if (ret == 0) {
        /* Update the key structure */
        ret = wh_Crypto_Curve25519DeserializeKey(buffer, buffer_len, key);
    }

    return ret;
}

static int _Curve25519MakeKey(whClientContext* ctx,
        uint16_t size,
        whKeyId *inout_key_id, whNvmFlags flags,
        const uint8_t* label, uint16_t label_len,
        curve25519_key* key)
{
    int ret = 0;
    whPacket* packet = NULL;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t data_len = 0;
    wh_Packet_pk_curve25519kg_req* req = NULL;
    wh_Packet_pk_curve25519kg_res* res = NULL;
    uint32_t type = WC_PK_TYPE_CURVE25519_KEYGEN;
    whKeyId key_id = WH_KEYID_ERASED;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset((uint8_t*)packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    req = &packet->pkCurve25519kgReq;
    res = &packet->pkCurve25519kgRes;

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Set up the request packet */
    req->type = type;
    req->sz = size;
    req->flags = flags;
    req->keyId = key_id;
    if (    (label != NULL) &&
            (label_len > 0) ) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }
    data_len = WH_PACKET_STUB_SIZE + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, action, data_len, (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] Curve25519 KeyGen Req sent:size:%u, ret:%d\n",
            req->sz, ret);
#endif
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &data_len,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] Curve25519 KeyGen Res recv:keyid:%u, len:%u, rc:%d, ret:%d\n",
            res->keyId, res->len, packet->rc, ret);
#endif

    if (ret == 0) {
        if (packet->rc == 0) {
            /* Key is cached on server or is ephemeral */
            key_id = (whKeyId)(res->keyId);

            /* Update output variable if requested */
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }

            /* Update the context if provided */
            if (key != NULL) {
                uint16_t der_size = (uint16_t)(res->len);
                uint8_t* key_der = (uint8_t*)(res + 1);
                /* Set the key_id.  Should be ERASED if EPHEMERAL */
                wh_Client_Curve25519SetKeyId(key, key_id);

                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret = wh_Crypto_Curve25519DeserializeKey(key_der, der_size, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[client] KeyGen export:", key_der, der_size);
#endif
                }
            }
        } else {
            /* Server detected a problem with generation */
            ret = packet->rc;
        }
    }
    return ret;
}

int wh_Client_Curve25519MakeCacheKey(whClientContext* ctx,
        uint16_t size,
        whKeyId *inout_key_id, whNvmFlags flags,
        const uint8_t* label, uint16_t label_len)
{
    /* Valid keyid ptr is required in this form */
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519MakeKey(ctx,
            size,
            inout_key_id, flags,
            label, label_len,
            NULL);
}

int wh_Client_Curve25519MakeExportKey(whClientContext* ctx,
        uint16_t size, curve25519_key* key)
{
    /* Valid key is required for this form */
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519MakeKey(ctx,
            size,
            NULL, WH_NVM_FLAGS_EPHEMERAL,
            NULL, 0,
            key);
}

int wh_Client_Curve25519SharedSecret(whClientContext* ctx,
        curve25519_key* priv_key, curve25519_key* pub_key,
        int endian, uint8_t* out, uint16_t *out_size)
{
    int ret = WH_ERROR_OK;
    whPacket* packet;

    /* Transaction state */
    whKeyId prv_key_id;
    int prv_evict = 0;
    whKeyId pub_key_id;
    int pub_evict = 0;

    if (    (ctx == NULL) ||
            (pub_key == NULL) ||
            (priv_key == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    pub_key_id = WH_DEVCTX_TO_KEYID(pub_key->devCtx);
    if (    (ret == WH_ERROR_OK) &&
            WH_KEYID_ISERASED(pub_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempX25519-pub";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_Curve25519ImportKey(ctx,
                pub_key, &pub_key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            pub_evict = 1;
        }
    }

    prv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if (    (ret == WH_ERROR_OK) &&
            WH_KEYID_ISERASED(prv_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempX25519-prv";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_Curve25519ImportKey(ctx,
                priv_key, &prv_key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message*/
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint32_t type = WC_PK_TYPE_CURVE25519;

        wh_Packet_pk_curve25519_req* req = &packet->pkCurve25519Req;
        uint16_t req_len =  WH_PACKET_STUB_SIZE + sizeof(*req);
        uint32_t options = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (pub_evict != 0) {
                options |= WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPUB;
            }
            if (prv_evict != 0) {
                options |= WH_PACKET_PK_CURVE25519_OPTIONS_EVICTPRV;
            }

            memset(req, 0, sizeof(*req));
            req->type           = type;
            req->options        = options;
            req->privateKeyId   = prv_key_id;
            req->publicKeyId    = pub_key_id;
            req->endian         = endian;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                (uint8_t*)packet);
    #ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s req sent. priv:%u pub:%u\n",
                    __func__, req->privateKeyId, req->publicKeyId);
    #endif
            if (ret == WH_ERROR_OK) {
                /* Server will evict.  Reset our flags */
                pub_evict = prv_evict = 0;

                /* Response Message */
                wh_Packet_pk_curve25519_res* res = &packet->pkCurve25519Res;
                uint8_t* res_out = (uint8_t*)(res + 1);
                uint16_t res_len;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
    #ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s resp packet recv. ret:%d rc:%d\n",
                        __func__, ret, packet->rc);
    #endif
                if (ret == WH_ERROR_OK) {
                    if (packet->rc != 0)
                        ret = packet->rc;
                    else {
                        if (out_size != NULL) {
                            *out_size = res->sz;
                        }
                        if (out != NULL) {
                            memcpy(out, res_out, res->sz);
                        }
        #ifdef DEBUG_CRYPTOCB_VERBOSE
                        wh_Utils_Hexdump("[client] X25519:", res_out, res->sz);
        #endif
                    }
                }
            }
        } else {
            ret = WH_ERROR_BADARGS;
        }
    }

    /* Evict the keys manually on error */
    if(pub_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if(prv_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, prv_key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifndef NO_RSA
int wh_Client_RsaSetKeyId(RsaKey* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_RsaGetKeyId(RsaKey* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}


int wh_Client_RsaImportKey(whClientContext* ctx, const RsaKey* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    whKeyId key_id = WH_KEYID_ERASED;
    byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t derSize = 0;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }
    /* Convert RSA key to DER format */
    ret = wh_Crypto_RsaSerializeKeyDer(key, sizeof(keyDer), keyDer, &derSize);
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags,
                label, label_len,
                keyDer, derSize, &key_id);
        if (inout_keyId != NULL) {
            *inout_keyId = key_id;
        }
    }
    return ret;
}

int wh_Client_RsaExportKey(whClientContext* ctx, whKeyId keyId, RsaKey* key,
        uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    /* DER cannot be larger than MTU */
    byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t derSize = sizeof(keyDer);
    uint8_t keyLabel[WH_NVM_LABEL_LEN] = {0};

    if (    (ctx == NULL) ||
            (keyId == WH_KEYID_ERASED) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret = wh_Client_KeyExport(ctx, keyId,
            keyLabel, sizeof(keyLabel),
            keyDer, &derSize);
    if (ret == 0) {
        ret = wh_Crypto_RsaDeserializeKeyDer(derSize, keyDer, key);
        if (ret == 0) {
            /* Successful parsing of RSA key.  Update the label */
            if ((label_len > 0) && (label != NULL)) {
                if (label_len > WH_NVM_LABEL_LEN) {
                    label_len = WH_NVM_LABEL_LEN;
                }
                memcpy(label, keyLabel, label_len);
            }
        }
    }

    return ret;
}

static int _RsaMakeKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whNvmFlags flags,  uint32_t label_len, uint8_t* label,
        whKeyId *inout_key_id, RsaKey* rsa)
{
    int ret = 0;
    whPacket* packet = NULL;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t data_len = 0;
    wh_Packet_pk_rsakg_req* req = NULL;
    wh_Packet_pk_rsakg_res* res = NULL;
    uint32_t type = WC_PK_TYPE_RSA_KEYGEN;
    whKeyId key_id = WH_KEYID_ERASED;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset((uint8_t*)packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    req = &packet->pkRsakgReq;
    res = &packet->pkRsakgRes;

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Set up the request packet */
    req->type = type;
    req->size = size;
    req->e = e;
    req->flags = flags;
    req->keyId = key_id;
    if (    (label != NULL) &&
            (label_len > 0) ) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }
    data_len = WH_PACKET_STUB_SIZE + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, action, data_len, (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("RSA KeyGen Req sent:size:%u, e:%u, ret:%d\n",
            req->size, req->e, ret);
#endif
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &data_len,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("RSA KeyGen Res recv:keyid:%u, len:%u, rc:%d, ret:%d\n",
            res->keyId, res->len, packet->rc, ret);
#endif

    if (ret == 0) {
        if (packet->rc == 0) {
            /* Key is cached on server or is ephemeral */
            key_id = (whKeyId)(res->keyId);

            /* Update output variable if requested */
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }

            /* Update the RSA context if provided */
            if (rsa != NULL) {
                word32 der_size = (word32)(res->len);
                uint8_t* rsa_der = (uint8_t*)(res + 1);
                /* Set the rsa key_id.  Should be ERASED if EPHEMERAL */
                wh_Client_RsaSetKeyId(rsa, key_id);

#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s Set key_id:%x with flags:%x\n",
                        __func__, key_id, flags);
#endif
                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret = wh_Crypto_RsaDeserializeKeyDer(der_size, rsa_der, rsa);
                }
            }
        } else {
            /* Server detected a problem with generation */
            ret = packet->rc;
        }
    }
    return ret;
}

int wh_Client_RsaMakeCacheKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint32_t label_len, uint8_t* label)
{
    /* Valid keyid ptr is required in this form */
    if (    (ctx == NULL) ||
            (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _RsaMakeKey(ctx,
            size, e,
            flags, label_len, label,
            inout_key_id, NULL);
}

int wh_Client_RsaMakeExportKey(whClientContext* ctx,
        uint32_t size, uint32_t e, RsaKey* rsa)
{
    /* Valid ctx and rsa are required for this form */
    if (    (ctx == NULL) ||
            (rsa == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _RsaMakeKey(ctx,
            size, e,
            WH_NVM_FLAGS_EPHEMERAL,  0, NULL,
            NULL, rsa);
}

int wh_Client_RsaFunction(whClientContext* ctx,
        RsaKey* key, int rsa_type,
        const uint8_t* in, uint16_t in_len,
        uint8_t* out, uint16_t *inout_out_len)
{
    int ret = WH_ERROR_OK;
    whPacket* packet;

    /* Transaction state */
    whKeyId key_id;
    int evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s ctx:%p key:%p, rsa_type:%d in:%p in_len:%u, out:%p inout_out_len:%p\n",
        __func__, ctx, key, rsa_type, in, (unsigned)in_len, out, inout_out_len);
#endif

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((in == NULL) && (in_len > 0)) ||
            ((out != NULL) && (inout_out_len == NULL)) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s key_id:%x\n",
        __func__, key_id);
#endif


    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempRsaFunction";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_RsaImportKey(ctx,
                key, &key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group      = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action     = WC_ALGO_TYPE_PK;
        uint32_t type       = WC_PK_TYPE_RSA;

        wh_Packet_pk_rsa_req* req = &packet->pkRsaReq;
        uint8_t* req_in   = (uint8_t*)(req + 1);
        uint16_t req_len    = WH_PACKET_STUB_SIZE + sizeof(*req) + in_len;
        uint32_t options    = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_PACKET_PK_RSA_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->type = type;
            req->opType = rsa_type;
            req->options = options;
            req->keyId = key_id;
            req->inLen = in_len;
            if( (in != NULL) && (in_len > 0)) {
                memcpy(req_in, in, in_len);
            }
            req->outLen = *inout_out_len;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                    (uint8_t*)packet);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Response Message */
                wh_Packet_pk_rsa_res* res = &packet->pkRsaRes;
                uint8_t* res_out = (uint8_t*)(res + 1);
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    if (packet->rc == 0) {
                        uint16_t out_len = res->outLen;
                        /* check inoutlen and read out */
                        if (inout_out_len != NULL) {
                            if (out_len > *inout_out_len) {
                                /* Silently truncate the response */
                                out_len = *inout_out_len;
                            }
                            *inout_out_len = out_len;
                            if (    (out != NULL) &&
                                    (out_len > 0)) {
                                memcpy(out, res_out, out_len);
                            }
                        }
                    } else {
                        ret = packet->rc;
                    }
                }
            }
        } else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if(evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

int wh_Client_RsaGetSize(whClientContext* ctx,
        const RsaKey* key, int* out_size)
{
    int ret = WH_ERROR_OK;
    whPacket* packet;

    /* Transaction state */
    whKeyId key_id;
    int evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s ctx:%p key:%p, out_size:%p \n",
        __func__, ctx, key, out_size);
#endif

    if (    (ctx == NULL) ||
            (key == NULL) ||
            (out_size == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempRsaGetSize";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] %s Importing temp key\n", __func__);
#endif
        ret = wh_Client_RsaImportKey(ctx,
                key, &key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group      = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action     = WC_ALGO_TYPE_PK;
        uint32_t type       = WC_PK_TYPE_RSA_GET_SIZE;

        wh_Packet_pk_rsa_get_size_req* req = &packet->pkRsaGetSizeReq;
        uint16_t req_len    = WH_PACKET_STUB_SIZE + sizeof(*req);
        uint32_t options    = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_PACKET_PK_RSA_GET_SIZE_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->type = type;
            req->options = options;
            req->keyId = key_id;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                    (uint8_t*)packet);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Response Message */
                wh_Packet_pk_rsa_get_size_res* res = &packet->pkRsaGetSizeRes;
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    if (packet->rc == 0) {
                        *out_size = res->keySize;
                    } else {
                        ret = packet->rc;
                    }
                }
            }
        } else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if(evict != 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] %s Evicting temp key %x\n", __func__, key_id);
#endif
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}


#endif /* !NO_RSA */

#ifndef NO_AES
int wh_Client_AesSetKeyId(Aes* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_AesGetKeyId(Aes* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}
#endif

#ifdef WOLFSSL_CMAC
int wh_Client_CmacSetKeyId(Cmac* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_CmacGetKeyId(Cmac* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

#ifndef NO_AES
int wh_Client_CmacAesGenerate(Cmac* cmac, byte* out, word32* outSz,
    const byte* in, word32 inSz, whNvmId keyId, void* heap)
{
    int ret;
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, heap,
        WH_DEV_ID);
    /* set keyId */
    if (ret == 0)
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret == 0)
        ret = wc_CmacUpdate(cmac, in, inSz);
    if (ret == 0)
        ret = wc_CmacFinal(cmac, out, outSz);
    return ret;
}

int wh_Client_CmacAesVerify(Cmac* cmac, const byte* check, word32 checkSz,
    const byte* in, word32 inSz, whNvmId keyId, void* heap)
{
    int ret;
    word32 outSz = AES_BLOCK_SIZE;
    byte out[AES_BLOCK_SIZE];
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, heap,
        WH_DEV_ID);
    /* set keyId */
    if (ret == 0)
        ret = wh_Client_CmacSetKeyId(cmac, keyId);
    if (ret == 0)
        ret = wc_CmacUpdate(cmac, in, inSz);
    if (ret == 0)
        ret = wc_CmacFinal(cmac, out, &outSz);
    if (ret == 0)
        ret = memcmp(out, check, outSz) == 0 ? 0 : 1;
    return ret;
}
#endif /* !NO_AES */

int wh_Client_CmacCancelableResponse(whClientContext* c, Cmac* cmac,
    uint8_t* out, uint16_t* outSz)
{
    whPacket* packet;
    uint8_t* packOut;
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    if (c == NULL || cmac == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after the fixed size fields */
    packOut = (uint8_t*)(&packet->cmacRes + 1);
    do {
        ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
            (uint8_t*)packet);
    } while (ret == WH_ERROR_NOTREADY);
    /* check for out of sequence action */
    if (ret == 0 && (group != WH_MESSAGE_GROUP_CRYPTO ||
        action != WC_ALGO_TYPE_CMAC)) {
        ret = WH_ERROR_ABORTED;
    }
    if (ret == 0) {
        if (packet->rc != 0)
            ret = packet->rc;
        /* read keyId and out */
        else {
            cmac->devCtx = (void*)((intptr_t)packet->cmacRes.keyId);
            if (out != NULL) {
                if (packet->cmacRes.outSz > *outSz)
                    ret = WH_ERROR_BADARGS;
                else {
                    XMEMCPY(out, packOut, packet->cmacRes.outSz);
                    *outSz = packet->cmacRes.outSz;
                }
            }
        }
    }
    return ret;
}
#endif /* WOLFSSL_CMAC */
#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
