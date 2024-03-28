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

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_message.h"

int wolfHSM_CryptoCb(int devId, wc_CryptoInfo* info, void* inCtx)
{
#if 0
    uint32_t field;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* authIn;
    uint8_t* authTag;
    uint8_t* sig;
    uint8_t* hash;
#endif
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    uint8_t rawPacket[WH_COMM_DATA_LEN];
    whPacket* packet = (whPacket*)rawPacket;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* in;
    uint8_t* out;
    uint8_t* sig;
    uint8_t* hash;

    if (devId == INVALID_DEVID || info == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(rawPacket, 0, sizeof(rawPacket));

    switch (info->algo_type)
    {
    case WC_ALGO_TYPE_PK:
        /* set type */
        packet->pkAnyReq.type = info->pk.type;
        switch (info->pk.type)
        {
        case WC_PK_TYPE_RSA_KEYGEN:
            /* set size */
            packet->pkRsakgReq.size = info->pk.rsakg.size;
            /* set e */
            packet->pkRsakgReq.e = info->pk.rsakg.e;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkRsakgReq),
                rawPacket);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    info->pk.rsakg.key->devCtx =
                        (void*)0 + packet->pkRsakgRes.keyId;
                }
            }
            break;
        case WC_PK_TYPE_RSA:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkRsaReq + 1);
            out = (uint8_t*)(&packet->pkRsaRes + 1);
            /* set type */
            packet->pkRsaReq.opType = info->pk.rsa.type;
            /* set keyId */
            packet->pkRsaReq.keyId =
                *((uint32_t*)(&info->pk.rsa.key->devCtx));
            /* set inLen */
            packet->pkRsaReq.inLen = info->pk.rsa.inLen;
            /* set outLen */
            packet->pkRsaReq.outLen = *info->pk.rsa.outLen;
            /* set in */
            XMEMCPY(in, info->pk.rsa.in, info->pk.rsa.inLen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkRsaReq)
                    + info->pk.rsa.inLen,
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
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
                *((uint32_t*)(&info->pk.rsa_get_size.key->devCtx));
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeReq),
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
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
        case WC_PK_TYPE_EC_KEYGEN:
            /* set key size */
            packet->pkEckgReq.sz = info->pk.eckg.size;
            /* set curveId */
            packet->pkEckgReq.curveId = info->pk.eckg.curveId;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEckgReq),
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read keyId */
                    XMEMCPY((void*)&info->pk.eckg.key->devCtx,
                        (void*)&packet->pkEckgRes.keyId,
                        sizeof(packet->pkEckgRes.keyId));
                }
            }
            break;
        case WC_PK_TYPE_ECDH:
            /* out is after the fixed size fields */
            out = (uint8_t*)(&packet->pkEcdhRes + 1);
            /* set ids */
            XMEMCPY((void*)&packet->pkEcdhReq.privateKeyId,
                (void*)&info->pk.ecdh.private_key->devCtx,
                sizeof(packet->pkEcdhReq.privateKeyId));
            XMEMCPY((void*)&packet->pkEcdhReq.publicKeyId,
                (void*)&info->pk.ecdh.public_key->devCtx,
                sizeof(packet->pkEcdhReq.publicKeyId));
            /* set curveId */
            packet->pkEcdhReq.curveId =
                wc_ecc_get_curve_id(info->pk.ecdh.private_key->idx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEcdhReq),
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
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
            /* set keyId */
            XMEMCPY((void*)&packet->pkEccSignReq.keyId,
                (void*)&info->pk.eccsign.key->devCtx,
                sizeof(packet->pkEccSignReq.keyId));
            /* set curveId */
            packet->pkEccSignReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccsign.key->idx);
            /* set sz */
            packet->pkEccSignReq.sz = info->pk.eccsign.inlen;
            /* set in */
            XMEMCPY(in, info->pk.eccsign.in, info->pk.eccsign.inlen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEccSignReq) +
                    info->pk.eccsign.inlen,
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
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
            /* set keyId */
            XMEMCPY((void*)&packet->pkEccVerifyReq.keyId,
                (void*)&info->pk.eccverify.key->devCtx,
                sizeof(packet->pkEccVerifyReq.keyId));
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
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEccVerifyReq) +
                info->pk.eccverify.siglen + info->pk.eccverify.hashlen,
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
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
            XMEMCPY((void*)&packet->pkEccCheckReq.keyId,
                (void*)&info->pk.ecc_check.key->devCtx,
                sizeof(packet->pkEccCheckReq.keyId));
            /* set curveId */
            packet->pkEccCheckReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkEccCheckReq),
                rawPacket);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
            }
            break;
        case WC_PK_TYPE_CURVE25519_KEYGEN:
            packet->pkCurve25519kgReq.sz = info->pk.curve25519kg.size;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519kgReq),
                rawPacket);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                /* read out */
                else {
                    info->pk.curve25519kg.key->devCtx =
                        (void*)0 + packet->pkCurve25519kgRes.keyId;
                    /* set metadata */
                    info->pk.curve25519kg.key->pubSet = 1;
                    info->pk.curve25519kg.key->privSet = 1;
                }
            }
            break;
        case WC_PK_TYPE_CURVE25519:
            out = (uint8_t*)(&packet->pkCurve25519Res + 1);
            packet->pkCurve25519Req.privateKeyId =
                *((uint32_t*)(&info->pk.curve25519.private_key->devCtx));
            packet->pkCurve25519Req.publicKeyId =
                *((uint32_t*)(&info->pk.curve25519.public_key->devCtx));
            packet->pkCurve25519Req.endian = info->pk.curve25519.endian;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Req),
                rawPacket);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        rawPacket);
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
        case WC_PK_TYPE_NONE:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
    case WC_ALGO_TYPE_RNG:
        /* out is after the fixed size fields */
        out = (uint8_t*)(&packet->rngRes + 1);
        /* set sz */
        packet->rngReq.sz = info->rng.sz;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_RNG,
            WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->rngReq), rawPacket);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                    rawPacket);
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
    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

    return ret;
}
