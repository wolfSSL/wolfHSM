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
#include "wolfhsm/wh_cryptocb.h"

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
                        (void*)((intptr_t)packet->pkRsakgRes.keyId);
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
                (intptr_t)(info->pk.rsa.key->devCtx);
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
                (intptr_t)(info->pk.rsa_get_size.key->devCtx);
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
