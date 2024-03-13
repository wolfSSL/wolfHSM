/* wh_cryptocb.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include <stdint.h>
#include <unistd.h>
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfhsm/wh_packet.h>
#include <wolfhsm/common.h>
#include <wolfhsm/wh_error.h>
#include <wolfhsm/wh_client.h>
#include <wolfhsm/wh_message.h>

int wolfHSM_CryptoCb(int devId, wc_CryptoInfo* info, void* inCtx)
{
#if 0
    uint32_t field;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* in;
    uint8_t* authIn;
    uint8_t* authTag;
    uint8_t* sig;
    uint8_t* hash;
#endif
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    uint8_t rawPacket[WH_COMM_MTU];
    whPacket* packet = (whPacket*)rawPacket;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* out;

    if (devId == INVALID_DEVID || info == NULL)
        return BAD_FUNC_ARG;

    switch (info->algo_type)
    {
#if 0
    case WC_ALGO_TYPE_HASH:
        break;
    case WC_ALGO_TYPE_CIPHER:
        /* set type */
        packet->cipherAnyReq.type = info->cipher.type;
        /* set enc */
        packet->cipherAnyReq.enc = info->cipher.enc;
        switch (info->cipher.type)
        {
        case WC_CIPHER_AES_CBC:
            /* key, iv, in, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesCbcReq + 1);
            out = (uint8_t*)(&packet->cipherAesCbcRes + 1);
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* set iv to be after key id */
            iv = key + sizeof(uint32_t);
            /* set len */
            packet->len = sizeof(packet->cipherAesCbcReq) + sizeof(uint32_t) +
                AES_IV_SIZE + info->cipher.aescbc.sz;
            /* set keyLen, sizeof key id */
            packet->cipherAesCbcReq.keyLen = sizeof(uint32_t);
#else
            iv = key + info->cipher.aescbc.aes->keylen;
            /* set len */
            packet->len = sizeof(packet->cipherAesCbcReq) +
                info->cipher.aescbc.aes->keylen + AES_IV_SIZE +
                info->cipher.aescbc.sz;
            /* set keyLen */
            packet->cipherAesCbcReq.keyLen =
                info->cipher.aescbc.aes->keylen;
#endif
            /* set in to be after iv */
            in = iv + AES_IV_SIZE;
            /* set sz */
            packet->cipherAesCbcReq.sz = info->cipher.aescbc.sz;
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* set keyId */
            XMEMCPY(key, (uint8_t*)&info->cipher.aescbc.aes->devCtx,
                sizeof(uint32_t));
#else
            /* set key */
            XMEMCPY(key, info->cipher.aescbc.aes->devKey,
                info->cipher.aescbc.aes->keylen);
#endif
            /* set iv */
            XMEMCPY(iv, info->cipher.aescbc.aes->reg, AES_IV_SIZE);
            /* set in */
            XMEMCPY(in, info->cipher.aescbc.in, info->cipher.aescbc.sz);
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                else {
                    /* copy the response out */
                    XMEMCPY(info->cipher.aescbc.out, out,
                        packet->cipherAesCbcRes.sz);
                }
            }
            break;
        case WC_CIPHER_AES_GCM:
            /* key, iv, in, authIn, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesGcmReq + 1);
            out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* set iv to be after key id */
            iv = key + sizeof(uint32_t);
            /* set len */
            packet->len = sizeof(packet->cipherAesGcmReq) + sizeof(uint32_t) +
                info->cipher.aesgcm_enc.ivSz + info->cipher.aesgcm_enc.sz +
                info->cipher.aesgcm_enc.authInSz +
                info->cipher.aesgcm_enc.authTagSz;
            /* set keyLen, sizeof key id */
            packet->cipherAesGcmReq.keyLen = sizeof(uint32_t);
#else
            iv = key + info->cipher.aesgcm_enc.aes->keylen;
            /* set len */
            packet->len = sizeof(packet->cipherAesGcmReq) +
                info->cipher.aesgcm_enc.aes->keylen +
                info->cipher.aesgcm_enc.ivSz + info->cipher.aesgcm_enc.sz +
                info->cipher.aesgcm_enc.authInSz +
                info->cipher.aesgcm_enc.authTagSz;
            /* set keyLen */
            packet->cipherAesGcmReq.keyLen =
                info->cipher.aesgcm_enc.aes->keylen;
#endif
            /* set the rest of the buffers */
            in = iv + info->cipher.aesgcm_enc.ivSz;
            authIn = in + info->cipher.aesgcm_enc.sz;
            if (info->cipher.enc == 0)
                authTag = authIn + info->cipher.aesgcm_enc.authInSz;
            else
                authTag = out + info->cipher.aesgcm_enc.sz;
            /* set metadata */
            packet->cipherAesGcmReq.sz = info->cipher.aesgcm_enc.sz;
            packet->cipherAesGcmReq.ivSz = info->cipher.aesgcm_enc.ivSz;
            packet->cipherAesGcmReq.authInSz = info->cipher.aesgcm_enc.authInSz;
            packet->cipherAesGcmReq.authTagSz =
                info->cipher.aesgcm_enc.authTagSz;
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* set keyId */
            XMEMCPY(key, (uint8_t*)&info->cipher.aesgcm_enc.aes->devCtx,
                sizeof(uint32_t));
#else
            /* set key */
            XMEMCPY(key, info->cipher.aesgcm_enc.aes->devKey,
                info->cipher.aesgcm_enc.aes->keylen);
#endif
            /* write the bulk data */
            XMEMCPY(iv, info->cipher.aesgcm_enc.iv,
                info->cipher.aesgcm_enc.ivSz);
            XMEMCPY(in, info->cipher.aesgcm_enc.in, info->cipher.aesgcm_enc.sz);
            XMEMCPY(authIn, info->cipher.aesgcm_enc.authIn,
                info->cipher.aesgcm_enc.authInSz);
            /* set auth tag by direction */
            if (info->cipher.enc == 0) {
                XMEMCPY(authTag, info->cipher.aesgcm_dec.authTag,
                    info->cipher.aesgcm_enc.authTagSz);
            }
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                else {
                    /* copy the response out */
                    XMEMCPY(info->cipher.aesgcm_enc.out, out,
                        packet->cipherAesGcmRes.sz);
                    /* write the authTag if applicable */
                    if (info->cipher.enc == 1) {
                        XMEMCPY(info->cipher.aesgcm_enc.authTag, authTag,
                            packet->cipherAesGcmRes.authTagSz);
                    }
                }
            }
            break;
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
    case WC_ALGO_TYPE_PK:
        /* set type */
        packet->pkAnyReq.type = info->pk.type;
        switch (info->pk.type)
        {
        case WC_PK_TYPE_RSA_KEYGEN:
            /* set len */
            packet->len = sizeof(packet->pkRsakgReq);
            /* set size */
            packet->pkRsakgReq.size = info->pk.rsakg.size;
            /* set e */
            packet->pkRsakgReq.e = info->pk.rsakg.e;
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                /* read keyId */
                else
                    info->pk.rsakg.key->devCtx = packet->pkRsakgRes.keyId;
            }
            break;
        case WC_PK_TYPE_RSA:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkRsaReq + 1);
            out = (uint8_t*)(&packet->pkRsaRes + 1);
            /* set len */
            packet->len = sizeof(packet->pkRsaReq) + info->pk.rsa.inLen;
            /* set type */
            packet->pkRsaReq.opType = info->pk.rsa.type;
            /* set keyId */
            packet->pkRsaReq.keyId = info->pk.rsa.key->devCtx;
            /* set inLen */
            packet->pkRsaReq.inLen = info->pk.rsa.inLen;
            /* set outLen */
            packet->pkRsaReq.outLen = *info->pk.rsa.outLen;
            /* set in */
            XMEMCPY(in, info->pk.rsa.in, info->pk.rsa.inLen);
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                else {
                    /* read outLen */
                    *info->pk.rsa.outLen = packet->pkRsaRes.outLen;
                    /* read out */
                    XMEMCPY(info->pk.rsa.out, out, packet->pkRsaRes.outLen);
                }
            }
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            /* set len */
            packet->len = sizeof(packet->pkRsaGetSizeReq);
            /* set keyId */
            packet->pkRsaGetSizeReq.keyId = info->pk.rsa_get_size.key->devCtx;
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                else {
                    /* read keySize */
                    *info->pk.rsa_get_size.keySize =
                        packet->pkRsaGetSizeRes.keySize;
                }
            }
            break;
        case WC_PK_TYPE_EC_KEYGEN:
            /* set len */
            packet->len = sizeof(packet->pkEckgReq);
            /* set key size */
            packet->pkEckgReq.sz = info->pk.eckg.size;
            /* set curveId */
            packet->pkEckgReq.curveId = info->pk.eckg.curveId;
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                /* read keyId */
                else
                    info->pk.eckg.key->devCtx = packet->pkEckgRes.keyId;
            }
            break;
        case WC_PK_TYPE_ECDH:
            /* out is after the fixed size fields */
            out = (uint8_t*)(&packet->pkEcdhRes + 1);
            /* set len */
            packet->len = sizeof(packet->pkEcdhReq);
            /* set ids */
            packet->pkEcdhReq.privateKeyId = info->pk.ecdh.private_key->devCtx;
            packet->pkEcdhReq.publicKeyId = info->pk.ecdh.public_key->devCtx;
            /* set curveId */
            packet->pkEcdhReq.curveId =
                wc_ecc_get_curve_id(info->pk.ecdh.private_key->idx);
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                /* read out */
                else {
                    XMEMCPY(info->pk.ecdh.out, out, packet->pkEcdhRes.sz);
                    *info->pk.ecdh.outlen = packet->pkEcdhRes.sz;
                }
            }
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkEccSignReq + 1);
            out = (uint8_t*)(&packet->pkEccSignRes + 1);
            /* set len */
            packet->len = sizeof(packet->pkEccSignReq) + info->pk.eccsign.inlen;
            /* set keyId */
            packet->pkEccSignReq.keyId = info->pk.eccsign.key->devCtx;
            /* set curveId */
            packet->pkEccSignReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccsign.key->idx);
            /* set sz */
            packet->pkEccSignReq.sz = info->pk.eccsign.inlen;
            /* set in */
            XMEMCPY(in, info->pk.eccsign.in, info->pk.eccsign.inlen);
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                /* read out */
                else {
                    XMEMCPY(info->pk.eccsign.out, out, packet->pkEccSignRes.sz);
                    *info->pk.eccsign.outlen = packet->pkEccSignRes.sz;
                }
            }
            break;
        case WC_PK_TYPE_ECDSA_VERIFY:
            /* sig and hash are after the fixed size fields */
            sig = (uint8_t*)(&packet->pkEccVerifyReq + 1);
            hash = (uint8_t*)(&packet->pkEccVerifyReq + 1) +
                info->pk.eccverify.siglen;
            /* set len */
            packet->len = sizeof(packet->pkEccVerifyReq) +
                info->pk.eccverify.siglen + info->pk.eccverify.hashlen;
            /* set keyId */
            packet->pkEccVerifyReq.keyId = info->pk.eccverify.key->devCtx;
            /* set curveId */
            packet->pkEccVerifyReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* set sig and hash sz */
            packet->pkEccVerifyReq.sigSz = info->pk.eccverify.siglen;
            packet->pkEccVerifyReq.hashSz = info->pk.eccverify.hashlen;
            /* copy sig and hash */
            XMEMCPY(sig, info->pk.eccverify.sig, info->pk.eccverify.siglen);
            XMEMCPY(hash, info->pk.eccverify.hash, info->pk.eccverify.hashlen);
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0) {
                if (packet->type == WOLFHSM_ERROR)
                    ret = packet->error;
                /* read res */
                else
                    *info->pk.eccverify.res = packet->pkEccVerifyRes.res;
            }
            break;
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            /* set len */
            packet->len = sizeof(packet->pkEccCheckReq);
            /* set keyId */
            packet->pkEccCheckReq.keyId = info->pk.ecc_check.key->devCtx;
            /* set curveId */
            packet->pkEccCheckReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* write request, read response on same memory */
            ret = hsmClientXferPacket(ctx);
            if (ret == 0 && packet->type == WOLFHSM_ERROR)
                ret = packet->error;
            break;
        case WC_PK_TYPE_NONE:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
#endif
    case WC_ALGO_TYPE_RNG:
        /* out is after the fixed size fields */
        out = (uint8_t*)(&packet->rngRes + 1);
        /* set sz */
        packet->rngReq.sz = info->rng.sz;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_RNG,
            sizeof(packet->rngReq), rawPacket);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                    rawPacket);
                sleep(1);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            if (group != WH_MESSAGE_GROUP_CRYPTO || action != WC_ALGO_TYPE_RNG)
                ret = packet->error;
            /* read out */
            else
                XMEMCPY(info->rng.out, out, packet->rngRes.sz);
        }
        break;
#if 0
    case WC_ALGO_TYPE_SEED:
        break;
    case WC_ALGO_TYPE_HMAC:
        break;
    case WC_ALGO_TYPE_CMAC:
        /* out, in and key are after the fixed size fields */
        out = (uint8_t*)(&packet->cmacRes + 1);
        in = (uint8_t*)(&packet->cmacReq + 1);
        key = in + info->cmac.inSz;
        packet->len = sizeof(packet->cmacReq);
        packet->cmacReq.keyId = info->cmac.cmac->devCtx;
        packet->cmacReq.outSz = 0;
        packet->cmacReq.inSz = info->cmac.inSz;
        packet->cmacReq.keySz = info->cmac.keySz;
        packet->cmacReq.type = info->cmac.type;
        /* handle different cases, oneshot, init, update and final */
        if (info->cmac.key != NULL && info->cmac.in != NULL
                && info->cmac.out != NULL) {
            field = WOLFHSM_CMAC_ONESHOT;
            XMEMCPY(in, info->cmac.in, info->cmac.inSz);
            XMEMCPY(key, info->cmac.key, info->cmac.keySz);
            packet->cmacReq.outSz = *(info->cmac.outSz);
        }
        else if (info->cmac.key != NULL) {
            field = WOLFHSM_CMAC_INIT;
            XMEMCPY(key, info->cmac.key, info->cmac.keySz);
        }
        else if (info->cmac.in != NULL) {
            field = WOLFHSM_CMAC_UPDATE;
            XMEMCPY(in, info->cmac.in, info->cmac.inSz);
        }
        else if (info->cmac.out != NULL) {
            field = WOLFHSM_CMAC_FINAL;
            packet->cmacReq.outSz = *(info->cmac.outSz);
        }
        packet->cmacReq.opType = field;
        /* send packet */
        ret = hsmClientXferPacket(ctx);
        if (ret == 0) {
            if (packet->type == WOLFHSM_ERROR)
                ret = packet->error;
            /* handle return and set keyId */
            else if (field == WOLFHSM_CMAC_INIT)
                info->cmac.cmac->devCtx = packet->cmacRes.keyId;
            else if (field == WOLFHSM_CMAC_ONESHOT ||
                field == WOLFHSM_CMAC_FINAL) {
                *(info->cmac.outSz) = packet->cmacRes.outSz;
                XMEMCPY(info->cmac.out, out,
                    packet->cmacRes.outSz);
            }
        }
        break;
#endif
    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

    return ret;
}
