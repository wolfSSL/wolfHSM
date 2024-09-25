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
 * src/wh_client_cryptocb.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"


#ifndef NO_SHA256
static int _handleSha256(int devId, wc_CryptoInfo* info, void* inCtx,
                         whPacket* packet);
static int _xferSha256BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha256* sha256,
                                           whPacket* packet,
                                           uint32_t isLastBlock);
#ifdef WOLFHSM_CFG_DMA                                           
static int _handleSha256Dma(int devId, wc_CryptoInfo* info, void* inCtx,
                         whPacket* packet);
#endif /* WOLFHSM_CFG_DMA */
#endif /* ! NO_SHA256 */

#ifndef NO_AES
#ifdef HAVE_AES_CBC
#if 0
static int wh_Client_CryptoCbAesCbc(whClientContext* ctx, wc_CryptoInfo* info,
        whPacket* packet);

static int wh_Client_CryptoCbAesCbc(whClientContext* ctx, wc_CryptoInfo* info,
        whPacket* packet)
{
    int ret = 0;

    return ret;
}
#endif
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
static int wh_Client_CryptoCbAesGcm(whClientContext* ctx,
        uint32_t enc,
        Aes* aes,
        uint32_t len, const uint8_t* in,
        uint32_t iv_len, const uint8_t* iv,
        uint32_t authin_len, const uint8_t* authin,
        uint32_t tag_len, const uint8_t* dec_tag, uint8_t* enc_tag,
        uint8_t* out);

static int wh_Client_CryptoCbAesGcm(whClientContext* ctx,
        uint32_t enc, Aes* aes,
        uint32_t len, const uint8_t* in,
        uint32_t iv_len, const uint8_t* iv,
        uint32_t authin_len, const uint8_t* authin,
        uint32_t tag_len, const uint8_t* dec_tag, uint8_t* enc_tag,
        uint8_t* out)
{
    int ret = 0;
    uint16_t group      = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action     = WC_ALGO_TYPE_CIPHER;
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
    req->type       = WC_CIPHER_AES_GCM;
    req->enc        = enc;
    req->keyLen     = key_len;
    req->sz         = len;
    req->ivSz       = iv_len;
    req->authInSz   = authin_len;
    req->authTagSz  = tag_len;
    req->keyId      = key_id;
    XMEMCPY(req_in, in, len);
    XMEMCPY(req_key, key, key_len);
    XMEMCPY(req_iv, iv, iv_len);
    XMEMCPY(req_authin, authin, authin_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] in: \n", req_in, len);
    wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
    wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
    wh_Utils_Hexdump("[client] authin: \n", req_authin, authin_len);
#endif
    /* set auth tag by direction */
    if (enc == 0) {
        XMEMCPY(req_dec_tag, dec_tag, tag_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] dec tag: \n", req_dec_tag, tag_len);
#endif
    }

    /* write request */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] AESGCM req packet: \n", (uint8_t*)packet, req_len);
#endif
    ret = wh_Client_SendRequest(ctx, group, action,
        req_len,
        (uint8_t*)packet);
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
            XMEMCPY(out, res_out, res->sz);
            /* write the authTag if applicable */
            if (    (enc != 0) &&
                    (enc_tag != NULL) &&
                    (res->authTagSz == tag_len)) {
                XMEMCPY(enc_tag, res_enc_tag, res->authTagSz);
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

int wh_Client_CryptoCb(int devId, wc_CryptoInfo* info, void* inCtx)
{
    /* III When possible, return wolfCrypt-enumerated errors */
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    whPacket* packet = NULL;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WH_MESSAGE_ACTION_NONE;
    uint16_t dataSz = 0;

    if (    (devId == INVALID_DEVID) ||
            (info == NULL) ||
            (inCtx == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    printf("[client] %s info:%p algo_type:%d\n", __func__, info,
            (info!=NULL)?info->algo_type:-1);
    wc_CryptoCb_InfoString(info);
#endif
    /* Get data pointer from the context to use as request/response storage */
    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET((uint8_t*)packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    /* Based on the info type, process the request */
    switch (info->algo_type)
    {
#if !defined(NO_AES) || !defined(NO_DES3)
    case WC_ALGO_TYPE_CIPHER:
        /* Set shared cipher request members */
        packet->cipherAnyReq.type = info->cipher.type;
        packet->cipherAnyReq.enc = info->cipher.enc;

        switch (info->cipher.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
        {
            int enc = info->cipher.enc != 0;
            uint32_t len = info->cipher.aescbc.sz;
            uint32_t key_len = info->cipher.aescbc.aes->keylen;
            whKeyId key_id = WH_DEVCTX_TO_KEYID(info->cipher.aescbc.aes->devCtx);

            /* in, key, iv, and out are after fixed size fields */
            uint8_t* in = (uint8_t*)(&packet->cipherAesCbcReq + 1);
            uint8_t* key = in + len;
            uint8_t* iv = key + key_len;
            uint8_t* out = (uint8_t*)(&packet->cipherAesCbcRes + 1);

            uint16_t blocks = len / AES_BLOCK_SIZE;
            size_t last_offset = (blocks - 1) * AES_BLOCK_SIZE;

            dataSz = sizeof(packet->cipherAesCbcReq) +
                    len + key_len + AES_IV_SIZE;

            if (    key_len >  sizeof(info->cipher.aescbc.aes->devKey)) {
                return BAD_FUNC_ARG;
            }
            /* III 0 size check is done in wolfCrypt */
            if(     (blocks == 0) ||
                    ((len % AES_BLOCK_SIZE) != 0) ) {
                /* CBC requires only full blocks */
                ret = BAD_LENGTH_E;
                break;
            }
            /* Is the request larger than a single message? */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                /* if we're using an non-erased HSM key return BAD_FUNC_ARG */
                if (WH_KEYID_ISERASED(key_id)) {
                    ret = BAD_LENGTH_E;
                } else {
                    ret = BAD_FUNC_ARG;
                }
                break;
            }


            /* Set AESCBC request members */
            packet->cipherAesCbcReq.keyLen = key_len;
            packet->cipherAesCbcReq.sz = len;
            packet->cipherAesCbcReq.keyId = key_id;

            if (    (info->cipher.aescbc.in != NULL) &&
                    (len > 0)) {
                XMEMCPY(in, info->cipher.aescbc.in, len);
            }
            if (key_len > 0) {
                XMEMCPY(key, info->cipher.aescbc.aes->devKey, key_len);
            }
            XMEMCPY(iv, info->cipher.aescbc.aes->reg, AES_IV_SIZE);

            /* Determine where ciphertext is for chaining */
            if(enc == 0) {
                /* Update the CBC state with the last cipher text black */
                /* III Must do this before the decrypt if in-place */
                XMEMCPY(info->cipher.aescbc.aes->reg,
                        in + last_offset,
                        AES_BLOCK_SIZE);
            }

            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_CIPHER,
                WH_PACKET_STUB_SIZE + dataSz,
                (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] sent AESCBC request. key:%p %d, in:%p %d, out:%p, enc:%d, ret:%d\n",
                    info->cipher.aescbc.aes->devKey, key_len,
                    info->cipher.aescbc.in, len,
                    info->cipher.aescbc.out, info->cipher.enc, ret);
            wh_Utils_Hexdump("  In:", in, len);
            wh_Utils_Hexdump("  Key:", key, key_len);
            wh_Utils_Hexdump("  Iv:", iv, AES_IV_SIZE);

#endif /* DEBUG_CRYPTOCB */

            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }

            if (ret == 0) {
                if (packet->rc == 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("  Out:", out, packet->cipherAesCbcRes.sz);
#endif /* DEBUG_CRYPTOCB */
                    /* copy the response out */
                    XMEMCPY(info->cipher.aescbc.out, out,
                        packet->cipherAesCbcRes.sz);
                    if (enc != 0) {
                        /* Update the CBC state with the last cipher text black */
                        XMEMCPY(info->cipher.aescbc.aes->reg,
                            out + last_offset,
                            AES_BLOCK_SIZE);
                    }
                } else {
                    ret = packet->rc;
                }
            }
        } break;
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
        {
            /* Extract wc_cryptocb_info fields */
            uint32_t enc        = info->cipher.enc;
            Aes* aes            = (enc == 0) ?  info->cipher.aesgcm_dec.aes :
                                                info->cipher.aesgcm_enc.aes;
            uint32_t len        = (enc == 0) ?  info->cipher.aesgcm_dec.sz :
                                                info->cipher.aesgcm_enc.sz;
            uint32_t iv_len     = (enc == 0) ?  info->cipher.aesgcm_dec.ivSz:
                                                info->cipher.aesgcm_enc.ivSz;
            uint32_t authin_len = (enc == 0) ?  info->cipher.aesgcm_dec.authInSz:
                                                info->cipher.aesgcm_enc.authInSz;
            uint32_t tag_len    = (enc == 0) ?  info->cipher.aesgcm_dec.authTagSz:
                                                info->cipher.aesgcm_enc.authTagSz;

            const uint8_t* info_in    = (enc == 0) ? info->cipher.aesgcm_dec.in :
                                                info->cipher.aesgcm_enc.in;
            const uint8_t* info_iv    = (enc == 0) ? info->cipher.aesgcm_dec.iv :
                                                info->cipher.aesgcm_enc.iv;
            const uint8_t* info_authin = (enc == 0) ? info->cipher.aesgcm_dec.authIn :
                                                info->cipher.aesgcm_enc.authIn;
            const uint8_t* info_dec_tag = info->cipher.aesgcm_dec.authTag;
            uint8_t* info_enc_tag = info->cipher.aesgcm_enc.authTag;
            uint8_t* info_out    = (enc == 0) ?  info->cipher.aesgcm_dec.out :
                                                info->cipher.aesgcm_enc.out;

#ifdef DEBUG_CRYPTOCB_VERBOSE
            wh_Utils_Hexdump("[client] check dec_tag:\n", (uint8_t*)info_dec_tag, tag_len);
#endif
            ret = wh_Client_CryptoCbAesGcm(ctx, enc, aes,
                    len, info_in, iv_len, info_iv, authin_len, info_authin,
                    tag_len, info_dec_tag, info_enc_tag,
                    info_out);

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
#endif /* !NO_AES || !NO_DES */

    case WC_ALGO_TYPE_PK:
        /* set type */
        packet->pkAnyReq.type = info->pk.type;
        switch (info->pk.type)
        {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
        {
            ret = wh_Client_MakeExportRsaKey(ctx,
                    info->pk.rsakg.size, info->pk.rsakg.e,
                    info->pk.rsakg.key);
            /* Fix up error code to be wolfCrypt*/
            if (ret == WH_ERROR_BADARGS) {
                ret = BAD_FUNC_ARG;
            }
        } break;
#endif  /* WOLFSSL_KEY_GEN */

        case WC_PK_TYPE_RSA:
        {
            /* in and out are after the fixed size fields */
            uint8_t* in = (uint8_t*)(&packet->pkRsaReq + 1);
            uint8_t* out = (uint8_t*)(&packet->pkRsaRes + 1);
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaReq)
                + info->pk.rsa.inLen;
            whKeyId keyId = WH_DEVCTX_TO_KEYID(info->pk.rsa.key->devCtx);
            int evict = 0;

            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

            /* check to see if the keyId is erased */
            if (WH_KEYID_ISERASED(keyId)) {
                /* Must import the key to the server and evict it afterwards */
                uint8_t keyLabel[] = "ClientCbTempRSA";
                whNvmFlags flags = WH_NVM_FLAGS_NONE;

                ret = wh_Client_ImportRsaKey(ctx, info->pk.rsa.key,
                        flags, sizeof(keyLabel), keyLabel, &keyId);
                if (ret != 0) {
                    break;
                }
                evict = 1;
            }

            /* Set packet members. Reset anyreq.type just in case */
            packet->pkAnyReq.type = info->pk.type;
            packet->pkRsaReq.keyId = keyId;
            packet->pkRsaReq.opType = info->pk.rsa.type;
            packet->pkRsaReq.inLen = info->pk.rsa.inLen;
            packet->pkRsaReq.outLen = *info->pk.rsa.outLen;
            /* set in */
            XMEMCPY(in, info->pk.rsa.in, info->pk.rsa.inLen);

            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
                (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] RSA req sent. opType:%u inLen:%d keyId:%u outLen:%u type:%u\n",
                    packet->pkRsaReq.opType,
                    packet->pkRsaReq.inLen,
                    packet->pkRsaReq.keyId,
                    packet->pkRsaReq.outLen,
                    packet->pkRsaReq.type);
#endif
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] RSA resp packet recv. ret:%d rc:%d\n", ret, packet->rc);
#endif
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read outLen */
                    *info->pk.rsa.outLen = packet->pkRsaRes.outLen;
                    /* read out */
                    XMEMCPY(info->pk.rsa.out, out, packet->pkRsaRes.outLen);
                }
            }
            if (evict != 0) {
                /* Evict the imported key */
                ret = wh_Client_KeyEvict(ctx, keyId);
            }
        } break;

        case WC_PK_TYPE_RSA_GET_SIZE:
        {
            /* set keyId */
            packet->pkRsaGetSizeReq.keyId =
                (intptr_t)(info->pk.rsa_get_size.key->devCtx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeReq),
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
                else {
                    /* read outLen */
                    *info->pk.rsa_get_size.keySize =
                        packet->pkRsaGetSizeRes.keySize;
                }
            }
        } break;

#endif /* !NO_RSA */

#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
        {
            /* Extract info parameters */
            uint32_t size       = info->pk.eckg.size;
            uint32_t curve_id   = info->pk.eckg.curveId;
            ecc_key* key        = info->pk.eckg.key;

            ret = wh_Client_EccMakeExportKey(ctx, size, curve_id, key);
        } break;

        case WC_PK_TYPE_ECDH:
        {
            /* Extract info parameters */
            ecc_key* priv_key   = info->pk.ecdh.private_key;
            ecc_key* pub_key    = info->pk.ecdh.public_key;
            uint8_t* out        = info->pk.ecdh.out;
            word32* out_len     = info->pk.ecdh.outlen;
            uint16_t len = 0;
            if(out_len != NULL) {
                len = *out_len;
            }

            ret = wh_Client_EccSharedSecret(ctx,
                                            priv_key, pub_key,
                                            out, &len);
            if (    (ret == WH_ERROR_OK) &&
                    (out_len != NULL) ){
                *out_len = len;
            }
        } break;

        case WC_PK_TYPE_ECDSA_SIGN:
        {
            /* Extract info parameters */
            ecc_key* key        = info->pk.eccsign.key;
            const uint8_t* hash = (const uint8_t*)info->pk.eccsign.in;
            uint16_t hash_len   = (uint16_t)info->pk.eccsign.inlen;
            uint8_t* sig        = (uint8_t*)info->pk.eccsign.out;
            word32* out_sig_len = info->pk.eccsign.outlen;
            uint16_t sig_len = 0;

            if(out_sig_len != NULL) {
                sig_len = (uint16_t)(*out_sig_len);
            }

            ret = wh_Client_EccSign(ctx, key, hash, hash_len, sig, &sig_len);
            if (    (ret == WH_ERROR_OK) &&
                    (out_sig_len != NULL)) {
                *out_sig_len = sig_len;
            }
        } break;

        case WC_PK_TYPE_ECDSA_VERIFY:
        {
            /* Extract info parameters */
            ecc_key* key        = info->pk.eccverify.key;
            const uint8_t* sig  = (const uint8_t*)info->pk.eccverify.sig;
            uint16_t sig_len    = (uint16_t)info->pk.eccverify.siglen;
            const uint8_t* hash = (const uint8_t*)info->pk.eccverify.hash;
            uint16_t hash_len   = (uint16_t)info->pk.eccverify.hashlen;
            int* out_res        = info->pk.eccverify.res;

            ret = wh_Client_EccVerify(ctx, key, sig, sig_len, hash, hash_len, out_res);
        } break;

#if 0
        /* TODO: Check if keyid is set on incoming key.
         *      if not, import private key to server
         *      send request with pub key der
         *      server creates new key with private and public.  check
         *      evict temp key
         */
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
        {
            int ret;
            /* Extract info parameters */
            ecc_key* key = info->pk.ecc_check.key;
            const uint8_t* pub_key = info->pk.ecc_check.pubKey;
            uint32_t pub_key_len = info->pk.ecc_check.pubKeySz;

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
        } break;
#endif

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
        {
            ret = wh_Client_Curve25519MakeExportKey(ctx,
                    info->pk.curve25519kg.size,
                    info->pk.curve25519kg.key);
            /* Fix up error code to be wolfCrypt*/
            if (ret == WH_ERROR_BADARGS) {
                ret = BAD_FUNC_ARG;
            }
        } break;

        case WC_PK_TYPE_CURVE25519:
        {
            /* Extract info parameters */
            curve25519_key* pub_key = info->pk.curve25519.public_key;
            curve25519_key* priv_key = info->pk.curve25519.private_key;
            int endian = info->pk.curve25519.endian;
            uint8_t* out        = info->pk.curve25519.out;
            word32* out_len     = info->pk.curve25519.outlen;
            uint16_t len = 0;
            if(out_len != NULL) {
                len = *out_len;
            }

            ret = wh_Client_Curve25519SharedSecret(ctx,
                                            priv_key, pub_key,
                                            endian,
                                            out, &len);
            if (    (ret == WH_ERROR_OK) &&
                    (out_len != NULL) ){
                *out_len = len;
            }
        } break;
#endif /* HAVE_CURVE25519 */

        case WC_PK_TYPE_NONE:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;

#ifndef WC_NO_RNG
    case WC_ALGO_TYPE_RNG:
    {
        /* Extract info parameters */
        uint8_t* out = info->rng.out;
        uint32_t size = info->rng.sz;

        ret = wh_Client_RngGenerate(ctx, out, size);
    } break;
#endif /* !WC_NO_RNG */

#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
    {
        /* Extract info parameters */
        const uint8_t* in = info->cmac.in;
        uint32_t in_len = (in == NULL) ? 0 : info->cmac.inSz;
        const uint8_t* key = info->cmac.key;
        uint32_t key_len = (key == NULL) ? 0 : info->cmac.keySz;
        uint8_t* mac = info->cmac.out;
        word32 *out_mac_len = info->cmac.outSz;
        Cmac* cmac = info->cmac.cmac;
        int type = info->cmac.type;

        whKeyId key_id = WH_DEVCTX_TO_KEYID(cmac->devCtx);
        uint32_t mac_len = (    (mac == NULL) ||
                                (out_mac_len == NULL)) ? 0 : *out_mac_len;

        /* Return success for a call with NULL params, or 0 len's */
        if ((in_len == 0) && (key_len == 0) && (mac_len == 0) ) {
            /* Update the type */
            cmac->type = type;
            ret = 0;
            break;
        }

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] cmac key:%p key_len:%d in:%p in_len:%d out:%p out_len:%d keyId:%x\n",
                key, key_len, in, in_len, mac, mac_len, key_id);
#endif
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_CMAC;


        wh_Packet_cmac_req* req = &packet->cmacReq;
        uint8_t* req_in = (uint8_t*)(req + 1);
        uint8_t* req_key = req_in + in_len;
        uint16_t req_len = WH_PACKET_STUB_SIZE + sizeof(*req) +
                in_len + key_len;

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            /* if we're using an HSM req_key return BAD_FUNC_ARG */
            if (!WH_KEYID_ISERASED(key_id)) {
                ret = BAD_FUNC_ARG;
            } else {
                ret = CRYPTOCB_UNAVAILABLE;
            }
            break;
        }

        memset(req, 0 , sizeof(*req));
        req->type = type;
        req->keyId = key_id;
        /* multiple modes are possible so we need to set zero size if buffers
         * are NULL */
        req->inSz = in_len;
        if (in_len != 0) {
            memcpy(req_in, in, in_len);
        }
        req->keySz = key_len;
        if (key_len != 0) {
            memcpy(req_key, key, key_len);
        }
        req->outSz = mac_len;

        /* write request */
        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                (uint8_t*)packet);
        if (ret == 0) {
            /* Update the local type since call succeeded */
            cmac->type = type;
            /* if the client marked they may want to cancel, handle the
             * response req_in a seperate call */
            if (ctx->cancelable)
                break;

            wh_Packet_cmac_res* res = &packet->cmacRes;
            uint8_t* res_mac = (uint8_t*)(res + 1);
            uint16_t res_len = 0;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
            if (ret == 0) {
                if (packet->rc != 0) {
                    ret = packet->rc;
                } else {
                    /* read keyId and res_out */
                    if (key != NULL) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        printf("[client] got keyid %x\n", res->keyId);
#endif
                        cmac->devCtx = WH_KEYID_TO_DEVCTX(res->keyId);
                    }
                    if (mac != NULL) {
                        memcpy(mac, res_mac, res->outSz);
                        if (out_mac_len != NULL) {
                            *(out_mac_len) = res->outSz;
                        }
                    }
                }
            }
        }
    } break;

#endif /* WOLFSSL_CMAC */

    case WC_ALGO_TYPE_HASH: {
        packet->hashAnyReq.type = info->hash.type;
        switch (info->hash.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256:
                ret = _handleSha256(devId, info, inCtx, packet);
                break;
#endif /* !NO_SHA256 */

            default:
                ret = CRYPTOCB_UNAVAILABLE;
                break;
        }
    } break; /* case WC_ALGO_TYPE_HASH */

    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

    /* Fix up error code to be wolfCrypt */
    if (ret == WH_ERROR_BADARGS) {
        ret = BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    if (ret == CRYPTOCB_UNAVAILABLE) {
        printf("[client] %s X not implemented: algo->type:%d\n", __func__, info->algo_type);
    } else {
        printf("[client] %s - ret:%d algo->type:%d\n", __func__, ret, info->algo_type);
    }
#endif /* DEBUG_CRYPTOCB */
    return ret;
}

#ifndef NO_SHA256
static int _handleSha256(int devId, wc_CryptoInfo* info, void* inCtx,
                         whPacket* packet)
{
    int              ret               = 0;
    whClientContext* ctx               = inCtx;
    wc_Sha256*       sha256            = info->hash.sha256;
    uint8_t*         sha256BufferBytes = (uint8_t*)sha256->buffer;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha256Hash(sha256, data, len, NULL) */
    if (info->hash.in != NULL) {
        size_t i = 0;

        /* Process the partial blocks directly from the input data. If there is
         * enough input data to fill a full block, transfer it to the server */
        if (sha256->buffLen > 0) {
            while (i < info->hash.inSz &&
                   sha256->buffLen < WC_SHA256_BLOCK_SIZE) {
                sha256BufferBytes[sha256->buffLen++] = info->hash.in[i++];
            }
            if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
                ret = _xferSha256BlockAndUpdateDigest(ctx, sha256, packet, 0);
                sha256->buffLen = 0;
            }
        }

        /* Process as many full blocks from the input data as we can */
        while ((info->hash.inSz - i) >= WC_SHA256_BLOCK_SIZE) {
            XMEMCPY(sha256BufferBytes, info->hash.in + i, WC_SHA256_BLOCK_SIZE);
            ret = _xferSha256BlockAndUpdateDigest(ctx, sha256, packet, 0);
            i += WC_SHA256_BLOCK_SIZE;
        }

        /* Copy any remaining data into the buffer to be sent in a subsequent
         * call when we have enough input data to send a full block */
        while (i < info->hash.inSz) {
            sha256BufferBytes[sha256->buffLen++] = info->hash.in[i++];
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha256Hash(sha256, NULL, 0, * hash) */
    if (info->hash.digest != NULL) {
        ret = _xferSha256BlockAndUpdateDigest(ctx, sha256, packet, 1);

        /* Copy out the final hash value */
        if (ret == 0) {
            memcpy(info->hash.digest, sha256->digest, WC_SHA256_DIGEST_SIZE);
        }

        /* reset the state of the sha context (without blowing away devId) */
        sha256->buffLen = 0;
        sha256->flags   = 0;
        sha256->hiLen   = 0;
        sha256->loLen   = 0;
        memset(sha256->digest, 0, sizeof(sha256->digest));
    }

    return ret;
}

static int _xferSha256BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha256* sha256, whPacket* packet,
                                           uint32_t isLastBlock)
{
    uint16_t                   group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                   action = WH_MESSAGE_ACTION_NONE;
    int                        ret    = 0;
    uint16_t                   dataSz = 0;
    wh_Packet_hash_sha256_req* req    = &packet->hashSha256Req;

    /* Ensure we always set the packet type, as if this function is called after
     * a response, it will be overwritten*/
    req->type = WC_HASH_TYPE_SHA256;

    /* Send the full block to the server, along with the
     * current hash state if needed. Finalization/padding of last block is up to
     * the server, we just need to let it know we are done and sending an
     * incomplete last block */
    if (isLastBlock) {
        req->isLastBlock  = 1;
        req->lastBlockLen = sha256->buffLen;
    }
    else {
        req->isLastBlock = 0;
    }
    XMEMCPY(req->inBlock, sha256->buffer,
            (isLastBlock) ? sha256->buffLen : WC_SHA256_BLOCK_SIZE);

    /* Send the hash state - this will be 0 on the first block on a properly
     * initialized sha256 struct */
    XMEMCPY(req->resumeState.hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
    packet->hashSha256Req.resumeState.hiLen = sha256->hiLen;
    packet->hashSha256Req.resumeState.loLen = sha256->loLen;

    ret = wh_Client_SendRequest(
        ctx, group, WC_ALGO_TYPE_HASH,
        WH_PACKET_STUB_SIZE + sizeof(packet->hashSha256Req), (uint8_t*)packet);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] send SHA256 Req:\n");
    wh_Utils_Hexdump("[client] inBlock: ", req->inBlock, WC_SHA256_BLOCK_SIZE);
    if (req->resumeState.hiLen != 0 || req->resumeState.loLen != 0) {
        wh_Utils_Hexdump("  [client] resumeHash: ", req->resumeState.hash,
                 (isLastBlock) ? req->lastBlockLen : WC_SHA256_BLOCK_SIZE);
        printf("  [client] hiLen: %u, loLen: %u\n", req->resumeState.hiLen,
               req->resumeState.loLen);
    }
    printf("  [client] ret = %d\n", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                         (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        if (packet->rc != 0) {
            ret = packet->rc;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] ERROR Client SHA256 Res recv: ret=%d", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
        else {
            /* Store the received intermediate hash in the sha256
             * context and indicate the field is now valid and
             * should be passed back and forth to the server */
            XMEMCPY(sha256->digest, packet->hashSha256Res.hash,
                    WC_SHA256_DIGEST_SIZE);
            sha256->hiLen = packet->hashSha256Res.hiLen;
            sha256->loLen = packet->hashSha256Res.loLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA256 Res recv:\n");
            wh_Utils_Hexdump("[client] hash: ", (uint8_t*)sha256->digest,
                     WC_SHA256_DIGEST_SIZE);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA

static int _handleSha256Dma(int devId, wc_CryptoInfo* info, void* inCtx,
                            whPacket* packet)
{
    int              ret    = WH_ERROR_OK;
    whClientContext* ctx    = inCtx;
    wc_Sha256*       sha256 = info->hash.sha256;
    uint16_t         respSz = 0;
    uint16_t         group  = WH_MESSAGE_GROUP_CRYPTO_DMA;

#if WH_DMA_IS_32BIT
    wh_Packet_hash_sha256_Dma32_req* req   = &packet->hashSha256Dma32Req;
    wh_Packet_hash_sha256_Dma32_res* resp  = &packet->hashSha256Dma32Res;
#else
    wh_Packet_hash_sha256_Dma64_req* req   = &packet->hashSha256Dma64Req;
    wh_Packet_hash_sha256_Dma64_res* resp  = &packet->hashSha256Dma64Res;
#endif

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha256Hash(sha256, data, len, NULL) */
    if (info->hash.in != NULL) {
        req->type       = WC_HASH_TYPE_SHA256;
        req->finalize   = 0;
        req->state.addr = (uintptr_t)sha256;
        req->state.sz   = sizeof(*sha256);
        req->input.addr = (uintptr_t)info->hash.in;
        req->input.sz   = info->hash.inSz;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA256 DMA UPDATE: inAddr=%p, inSz=%u\n",
               info->hash.in, info->hash.inSz);
#endif
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HASH,
                                    WH_PACKET_STUB_SIZE + sizeof(*req),
                                    (uint8_t*)packet);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }

        if (ret == WH_ERROR_OK) {
            if (packet->rc != WH_ERROR_OK) {
                ret = packet->rc;
            }
            /* Nothing to do on success, as server will have updated the context
             * in client memory */
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha256Hash(sha256, NULL, 0, * hash) */
    if ((ret == WH_ERROR_OK) && (info->hash.digest != NULL)) {
        /* Packet will have been trashed, so re-populate all fields */
        req->type        = WC_HASH_TYPE_SHA256;
        req->finalize    = 1;
        req->state.addr  = (uintptr_t)sha256;
        req->state.sz    = sizeof(*sha256);
        req->output.addr = (uintptr_t)info->hash.digest;
        req->output.sz   = WC_SHA256_DIGEST_SIZE; /* not needed, but YOLO */

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA256 DMA FINAL: outAddr=%p\n", info->hash.digest);
#endif
        /* send the request to the server */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HASH,
                                    WH_PACKET_STUB_SIZE + sizeof(*req),
                                    (uint8_t*)packet);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* Copy out the final hash value */
        if (ret == WH_ERROR_OK) {
            if (packet->rc != WH_ERROR_OK) {
                ret = packet->rc;
                (void)resp;
            }
            /* Nothing to do on success, as server will have updated the output
             * hash in client memory */
        }
    }

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* ! NO_SHA256 */


#ifdef WOLFHSM_CFG_DMA
int wh_Client_CryptoCbDma(int devId, wc_CryptoInfo* info, void* inCtx)
{
    /* III When possible, return wolfCrypt-enumerated errors */
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    whPacket* packet = NULL;

    if (    (devId == INVALID_DEVID) ||
            (info == NULL) ||
            (inCtx == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    printf("[client] %s ", __func__);
    wc_CryptoCb_InfoString(info);
#endif
    /* Get data pointer from the context to use as request/response storage */
    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET((uint8_t*)packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    /* Based on the info type, process the request */
    switch (info->algo_type)
    {
    case WC_ALGO_TYPE_HASH: {
        packet->hashAnyReq.type = info->hash.type;
        switch (info->hash.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256:
                ret = _handleSha256Dma(devId, info, inCtx, packet);
                break;
#endif /* !NO_SHA256 */

            default:
                ret = CRYPTOCB_UNAVAILABLE;
                break;
        }
    } break; /* case WC_ALGO_TYPE_HASH */

    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

#ifdef DEBUG_CRYPTOCB
    if (ret == CRYPTOCB_UNAVAILABLE) {
        printf("[client] %s X not implemented: algo->type:%d\n", __func__, info->algo_type);
    } else {
        printf("[client] %s - ret:%d algo->type:%d\n", __func__, ret, info->algo_type);
    }
#endif /* DEBUG_CRYPTOCB */
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
