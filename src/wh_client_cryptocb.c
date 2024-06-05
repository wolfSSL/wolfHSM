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
 * wh_cryptocb.c
 */
#include <stdint.h>
#include <unistd.h>

#ifndef WOLFHSM_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client_cryptocb.h"

/* wolfHSM crypto callback assumes wc_CryptoInfo struct is unionized */
#if !defined(HAVE_ANONYMOUS_INLINE_AGGREGATES) \
    || ( defined(HAVE_ANONYMOUS_INLINE_AGGREGATES) \
         && HAVE_ANONYMOUS_INLINE_AGGREGATES==0  )
#error "wolfHSM needs wolfCrypt built with HAVE_ANONYMOUS_INLINE_AGGREGATES=1"
#endif

int wolfHSM_CryptoCb(int devId, wc_CryptoInfo* info, void* inCtx)
{
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    whPacket* packet;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* in;
    uint8_t* out;
    uint8_t* authIn;
    uint8_t* authTag;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* sig;
    uint8_t* hash;

    if (devId == INVALID_DEVID || info == NULL || inCtx == NULL)
        return BAD_FUNC_ARG;

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);

    XMEMSET((uint8_t*)packet, 0, WH_COMM_DATA_LEN);

    switch (info->algo_type)
    {
    case WC_ALGO_TYPE_CIPHER:
        /* set type */
        packet->cipherAnyReq.type = info->cipher.type;
        /* set enc */
        packet->cipherAnyReq.enc = info->cipher.enc;
        switch (info->cipher.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            /* key, iv, in, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesCbcReq + 1);
            out = (uint8_t*)(&packet->cipherAesCbcRes + 1);
            iv = key + info->cipher.aescbc.aes->keylen;
            dataSz = sizeof(packet->cipherAesCbcReq) +
                info->cipher.aescbc.aes->keylen + AES_IV_SIZE +
                info->cipher.aescbc.sz;
            if (dataSz > WH_COMM_DATA_LEN) {
                /* if we're using an HSM key return BAD_FUNC_ARG */
                if ((intptr_t)info->cipher.aescbc.aes->devCtx != 0)
                    return BAD_FUNC_ARG;
                else
                    return CRYPTOCB_UNAVAILABLE;
            }
            /* set keyLen */
            packet->cipherAesCbcReq.keyLen =
                info->cipher.aescbc.aes->keylen;
            /* set in to be after iv */
            in = iv + AES_IV_SIZE;
            /* set sz */
            packet->cipherAesCbcReq.sz = info->cipher.aescbc.sz;
            /* set keyId */
            packet->cipherAesCbcReq.keyId =
                (intptr_t)(info->cipher.aescbc.aes->devCtx);
            /* set key */
            XMEMCPY(key, info->cipher.aescbc.aes->devKey,
                info->cipher.aescbc.aes->keylen);
            /* set iv */
            XMEMCPY(iv, info->cipher.aescbc.aes->reg, AES_IV_SIZE);
            /* set in */
            XMEMCPY(in, info->cipher.aescbc.in, info->cipher.aescbc.sz);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_CIPHER,
                WOLFHSM_PACKET_STUB_SIZE + dataSz,
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
                    /* copy the response out */
                    XMEMCPY(info->cipher.aescbc.out, out,
                        packet->cipherAesCbcRes.sz);
                }
            }
            break;
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            /* key, iv, in, authIn, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesGcmReq + 1);
            out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
            iv = key + info->cipher.aesgcm_enc.aes->keylen;
            dataSz = sizeof(packet->cipherAesGcmReq) +
                info->cipher.aesgcm_enc.aes->keylen +
                info->cipher.aesgcm_enc.ivSz + info->cipher.aesgcm_enc.sz +
                info->cipher.aesgcm_enc.authInSz +
                info->cipher.aesgcm_enc.authTagSz;
            if (dataSz > WH_COMM_DATA_LEN) {
                /* if we're using an HSM key return BAD_FUNC_ARG */
                if ((intptr_t)info->cipher.aesgcm_enc.aes->devCtx != 0)
                    return BAD_FUNC_ARG;
                else
                    return CRYPTOCB_UNAVAILABLE;
            }
            /* set keyLen */
            packet->cipherAesGcmReq.keyLen =
                info->cipher.aesgcm_enc.aes->keylen;
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
            packet->cipherAesGcmReq.keyId =
                (intptr_t)(info->cipher.aescbc.aes->devCtx);
            /* set key */
            XMEMCPY(key, info->cipher.aesgcm_enc.aes->devKey,
                info->cipher.aesgcm_enc.aes->keylen);
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
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_CIPHER,
                WOLFHSM_PACKET_STUB_SIZE + dataSz,
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
#endif /* HAVE_AESGCM */
#endif /* NO_AES */
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
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
            /* set size */
            packet->pkRsakgReq.size = info->pk.rsakg.size;
            /* set e */
            packet->pkRsakgReq.e = info->pk.rsakg.e;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkRsakgReq),
                (uint8_t*)packet);
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
                    info->pk.rsakg.key->devCtx =
                        (void*)((intptr_t)packet->pkRsakgRes.keyId);
                }
            }
            break;
#endif  /* WOLFSSL_KEY_GEN */
        case WC_PK_TYPE_RSA:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkRsaReq + 1);
            out = (uint8_t*)(&packet->pkRsaRes + 1);
            dataSz = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkRsaReq)
                + info->pk.rsa.inLen;
            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WH_COMM_DATA_LEN)
                return BAD_FUNC_ARG;
            /* set type */
            packet->pkRsaReq.opType = info->pk.rsa.type;
            /* set keyId */
            packet->pkRsaReq.keyId = (intptr_t)(info->pk.rsa.key->devCtx);
            /* set inLen */
            packet->pkRsaReq.inLen = info->pk.rsa.inLen;
            /* set outLen */
            packet->pkRsaReq.outLen = *info->pk.rsa.outLen;
            /* set in */
            XMEMCPY(in, info->pk.rsa.in, info->pk.rsa.inLen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
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
                    *info->pk.rsa.outLen = packet->pkRsaRes.outLen;
                    /* read out */
                    XMEMCPY(info->pk.rsa.out, out, packet->pkRsaRes.outLen);
                }
            }
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            /* set keyId */
            packet->pkRsaGetSizeReq.keyId =
                (intptr_t)(info->pk.rsa_get_size.key->devCtx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeReq),
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
            break;
#endif  /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
            /* set key size */
            packet->pkEckgReq.sz = info->pk.eckg.size;
            /* set curveId */
            packet->pkEckgReq.curveId = info->pk.eckg.curveId;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEckgReq),
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
                    /* read keyId */
                    info->pk.eckg.key->devCtx =
                        (void*)((intptr_t)packet->pkEckgRes.keyId);
                }
            }
            break;
        case WC_PK_TYPE_ECDH:
            /* out is after the fixed size fields */
            out = (uint8_t*)(&packet->pkEcdhRes + 1);
            /* set ids */
            packet->pkEcdhReq.privateKeyId =
                (intptr_t)info->pk.ecdh.private_key->devCtx;
            packet->pkEcdhReq.publicKeyId =
                (intptr_t)info->pk.ecdh.public_key->devCtx;
            /* set curveId */
            packet->pkEcdhReq.curveId =
                wc_ecc_get_curve_id(info->pk.ecdh.private_key->idx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEcdhReq),
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
                    /* read out */
                    XMEMCPY(info->pk.ecdh.out, out, packet->pkEcdhRes.sz);
                    *info->pk.ecdh.outlen = packet->pkEcdhRes.sz;
                }
            }
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkEccSignReq + 1);
            out = (uint8_t*)(&packet->pkEccSignRes + 1);
            dataSz = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEccSignReq) +
                info->pk.eccsign.inlen;
            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WH_COMM_DATA_LEN)
                return BAD_FUNC_ARG;
            /* set keyId */
            packet->pkEccSignReq.keyId = (intptr_t)info->pk.eccsign.key->devCtx;
            /* set curveId */
            packet->pkEccSignReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccsign.key->idx);
            /* set sz */
            packet->pkEccSignReq.sz = info->pk.eccsign.inlen;
            /* set in */
            XMEMCPY(in, info->pk.eccsign.in, info->pk.eccsign.inlen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
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
                    /* read out */
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
            dataSz = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEccVerifyReq) +
                info->pk.eccverify.siglen + info->pk.eccverify.hashlen;
            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WH_COMM_DATA_LEN)
                return BAD_FUNC_ARG;
            /* set keyId */
            packet->pkEccVerifyReq.keyId =
                (intptr_t)info->pk.eccverify.key->devCtx;
            /* set curveId */
            packet->pkEccVerifyReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* set sig and hash sz */
            packet->pkEccVerifyReq.sigSz = info->pk.eccverify.siglen;
            packet->pkEccVerifyReq.hashSz = info->pk.eccverify.hashlen;
            /* copy sig and hash */
            XMEMCPY(sig, info->pk.eccverify.sig, info->pk.eccverify.siglen);
            XMEMCPY(hash, info->pk.eccverify.hash, info->pk.eccverify.hashlen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
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
                    /* read out */
                    *info->pk.eccverify.res = packet->pkEccVerifyRes.res;
                }
            }
            break;
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            /* set keyId */
            packet->pkEccCheckReq.keyId =
                (intptr_t)(info->pk.ecc_check.key->devCtx);
            /* set curveId */
            packet->pkEccCheckReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEccCheckReq),
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
            break;
#endif /* HAVE_ECC */
#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
            packet->pkCurve25519kgReq.sz = info->pk.curve25519kg.size;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519kgReq),
                (uint8_t*)packet);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                /* read out */
                else {
                    info->pk.curve25519kg.key->devCtx =
                        (void*)((intptr_t)packet->pkCurve25519kgRes.keyId);
                    /* set metadata */
                    info->pk.curve25519kg.key->pubSet = 1;
                    info->pk.curve25519kg.key->privSet = 1;
                }
            }
            break;
        case WC_PK_TYPE_CURVE25519:
            out = (uint8_t*)(&packet->pkCurve25519Res + 1);
            packet->pkCurve25519Req.privateKeyId =
                (intptr_t)(info->pk.curve25519.private_key->devCtx);
            packet->pkCurve25519Req.publicKeyId =
                (intptr_t)(info->pk.curve25519.public_key->devCtx);
            packet->pkCurve25519Req.endian = info->pk.curve25519.endian;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Req),
                (uint8_t*)packet);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                /* read out */
                else {
                    XMEMCPY(info->pk.curve25519.out, out,
                        packet->pkCurve25519Res.sz);
                }
            }
            break;
#endif /* HAVE_CURVE25519 */
        case WC_PK_TYPE_NONE:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
#ifndef WC_NO_RNG
    case WC_ALGO_TYPE_RNG:
        /* out is after the fixed size fields */
        out = (uint8_t*)(&packet->rngRes + 1);
        /* set sz */
        packet->rngReq.sz = info->rng.sz;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_RNG,
            WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->rngReq),(uint8_t*)packet);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            if (packet->rc != 0)
                ret = packet->rc;
            /* read out */
            else
                XMEMCPY(info->rng.out, out, packet->rngRes.sz);
        }
        break;
#endif /* !WC_NO_RNG */
#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
        dataSz = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->cmacReq) +
            info->cmac.inSz + info->cmac.keySz;
        if (dataSz > WH_COMM_DATA_LEN) {
            /* if we're using an HSM key return BAD_FUNC_ARG */
            if ((intptr_t)info->cmac.cmac->devCtx != 0)
                return BAD_FUNC_ARG;
            else
                return CRYPTOCB_UNAVAILABLE;
        }
        /* ignore init call with NULL params */
        if (info->cmac.in == NULL && info->cmac.key == NULL &&
            info->cmac.out == NULL) {
            return 0;
        }
        /* in, key and out are after the fixed size fields */
        in = (uint8_t*)(&packet->cmacReq + 1);
        key = in + info->cmac.inSz;
        out = (uint8_t*)(&packet->cmacRes + 1);
        packet->cmacReq.type = info->cmac.type;
        packet->cmacReq.keyId = (intptr_t)info->cmac.cmac->devCtx;
        /* multiple modes are possible so we need to set zero size if buffers
         * are NULL */
        if (info->cmac.in != NULL) {
            packet->cmacReq.inSz = info->cmac.inSz;
            XMEMCPY(in, info->cmac.in, info->cmac.inSz);
        }
        else
            packet->cmacReq.inSz = 0;
        if (info->cmac.key != NULL) {
            packet->cmacReq.keySz = info->cmac.keySz;
            XMEMCPY(key, info->cmac.key, info->cmac.keySz);
        }
        else
            packet->cmacReq.keySz = 0;
        if (info->cmac.out != NULL)
            packet->cmacReq.outSz = *(info->cmac.outSz);
        else
            packet->cmacReq.outSz = 0;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_CMAC,
            WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->cmacReq) +
            packet->cmacReq.inSz + packet->cmacReq.keySz, (uint8_t*)packet);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            if (packet->rc != 0)
                ret = packet->rc;
            /* read keyId and out */
            else {
                if (info->cmac.key != NULL) {
                    info->cmac.cmac->devCtx =
                        (void*)((intptr_t)packet->cmacRes.keyId);
                }
                if (info->cmac.out != NULL) {
                    XMEMCPY(info->cmac.out, out, packet->cmacRes.outSz);
                    *(info->cmac.outSz) = packet->cmacRes.outSz;
                }
            }
        }
        break;
#endif /* WOLFSSL_CMAC */
    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

    return ret;
}
#endif  /* WOLFHSM_NO_CRYPTO */
