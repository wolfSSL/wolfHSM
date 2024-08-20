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

#include <stdint.h>

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"

#if defined(DEBUG_CRYPTOCB) || defined(DEBUG_CRYPTOCB_VERBOSE)
#include <stdio.h>
#endif

#ifdef DEBUG_CRYPTOCB_VERBOSE
static void _hexdump(const char* initial,uint8_t* ptr, size_t size)
{
#define HEXDUMP_BYTES_PER_LINE 16
    int count = 0;
    if(initial != NULL)
        printf("%s",initial);
    while(size > 0) {
        printf ("%02X ", *ptr);
        ptr++;
        size --;
        count++;
        if (count % HEXDUMP_BYTES_PER_LINE == 0) {
            printf("\n");
        }
    }
    if((count % HEXDUMP_BYTES_PER_LINE) != 0) {
        printf("\n");
    }
}
#endif

#ifndef NO_SHA256
static int _handleSha256(int devId, wc_CryptoInfo* info, void* inCtx,
                         whPacket* packet);
static int _xferSha256BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha256* sha256,
                                           whPacket* packet,
                                           uint32_t isLastBlock);
#endif


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
    printf("[client] Client_CryptoCb: ");
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
#ifndef NO_AES
    case WC_ALGO_TYPE_CIPHER:
        /* Set shared cipher request members */
        packet->cipherAnyReq.type = info->cipher.type;
        packet->cipherAnyReq.enc = info->cipher.enc;

        switch (info->cipher.type)
        {
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
            printf("- Client sent AESCBC request. key:%p %d, in:%p %d, out:%p, enc:%d, ret:%d\n",
                    info->cipher.aescbc.aes->devKey, key_len,
                    info->cipher.aescbc.in, len,
                    info->cipher.aescbc.out, info->cipher.enc, ret);
            _hexdump("  In:", in, len);
            _hexdump("  Key:", key, key_len);
            _hexdump("  Iv:", iv, AES_IV_SIZE);

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
                    _hexdump("  Out:", out, packet->cipherAesCbcRes.sz);
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
            /* in, key, iv, authIn, and out are after fixed size fields */
            uint8_t* in = (uint8_t*)(&packet->cipherAesGcmReq + 1);
            uint8_t* key = in + info->cipher.aesgcm_enc.sz;
            uint8_t* iv = key + info->cipher.aesgcm_enc.aes->keylen;
            uint8_t* authIn = iv + info->cipher.aesgcm_enc.ivSz;
            uint8_t* out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
            uint8_t* authTag = (info->cipher.enc == 0) ?
                    authIn + info->cipher.aesgcm_enc.authInSz :
                    out + info->cipher.aesgcm_enc.sz;
            dataSz = sizeof(packet->cipherAesGcmReq) +
                info->cipher.aesgcm_enc.aes->keylen +
                info->cipher.aesgcm_enc.ivSz + info->cipher.aesgcm_enc.sz +
                info->cipher.aesgcm_enc.authInSz +
                info->cipher.aesgcm_enc.authTagSz;


#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] AESGCM: enc:%d keylen:%d ivsz:%d insz:%d authinsz:%d authtagsz:%d datasz:%d\n",
                        info->cipher.enc,
                        info->cipher.aesgcm_enc.aes->keylen,
                        info->cipher.aesgcm_enc.ivSz,
                        info->cipher.aesgcm_enc.sz,
                        info->cipher.aesgcm_enc.authInSz,
                        info->cipher.aesgcm_enc.authTagSz,
                        dataSz);
#endif
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                /* if we're using an HSM key return BAD_FUNC_ARG */
                if (info->cipher.aesgcm_enc.aes->devCtx != NULL) {
                    ret = BAD_FUNC_ARG;
                } else {
                    ret = CRYPTOCB_UNAVAILABLE;
                }
                break;
            }

            /* set keyLen */
            packet->cipherAesGcmReq.keyLen =
                info->cipher.aesgcm_enc.aes->keylen;
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
            _hexdump("[client] key: ", key, info->cipher.aesgcm_enc.aes->keylen);
            _hexdump("[client] iv: ", iv, info->cipher.aesgcm_enc.ivSz);
            _hexdump("[client] in: ", in, info->cipher.aesgcm_enc.sz);
#endif
            /* set auth tag by direction */
            if (info->cipher.enc == 0) {
                XMEMCPY(authTag, info->cipher.aesgcm_dec.authTag,
                    info->cipher.aesgcm_enc.authTagSz);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                _hexdump("[client] dec authTag: ", authTag, info->cipher.aesgcm_enc.authTagSz);
#endif
            }
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_CIPHER,
                WH_PACKET_STUB_SIZE + dataSz,
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] out size:%d datasz:%d\n",
                            packet->cipherAesGcmRes.sz, dataSz);
                    _hexdump("[client] out: ", out, packet->cipherAesGcmRes.sz);
#endif
                    /* copy the response out */
                    XMEMCPY(info->cipher.aesgcm_enc.out, out,
                        packet->cipherAesGcmRes.sz);
                    /* write the authTag if applicable */
                    if (info->cipher.enc != 0) {
                        XMEMCPY(info->cipher.aesgcm_enc.authTag, authTag,
                            packet->cipherAesGcmRes.authTagSz);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        _hexdump("[client] enc authtag: ", authTag, packet->cipherAesGcmRes.authTagSz);
#endif

                    }
                }
            }
        } break;
#endif /* HAVE_AESGCM */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
#endif /* !NO_AES */

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
            /* set key size */
            packet->pkEckgReq.sz = info->pk.eckg.size;
            /* set curveId */
            packet->pkEckgReq.curveId = info->pk.eckg.curveId;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkEckgReq),
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
        } break;

        case WC_PK_TYPE_ECDH:
        {
            /* out is after the fixed size fields */
            uint8_t* out = (uint8_t*)(&packet->pkEcdhRes + 1);

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
                WH_PACKET_STUB_SIZE + sizeof(packet->pkEcdhReq),
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
        } break;

        case WC_PK_TYPE_ECDSA_SIGN:
        {
            /* in and out are after the fixed size fields */
            uint8_t* in = (uint8_t*)(&packet->pkEccSignReq + 1);
            uint8_t* out = (uint8_t*)(&packet->pkEccSignRes + 1);
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccSignReq) +
                info->pk.eccsign.inlen;

            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

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
                    /* check outlen and read out */
                    if (*info->pk.eccsign.outlen < packet->pkEccSignRes.sz) {
                        ret = BUFFER_E;
                    }
                    else {
                        *info->pk.eccsign.outlen = packet->pkEccSignRes.sz;
                        XMEMCPY(info->pk.eccsign.out, out,
                            packet->pkEccSignRes.sz);
                    }
                }
            }
        } break;

        case WC_PK_TYPE_ECDSA_VERIFY:
        {
            /* sig and hash are after the fixed size fields */
            uint8_t* sig = (uint8_t*)(&packet->pkEccVerifyReq + 1);
            uint8_t* hash = (uint8_t*)(&packet->pkEccVerifyReq + 1) +
                info->pk.eccverify.siglen;
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccVerifyReq) +
                info->pk.eccverify.siglen + info->pk.eccverify.hashlen;

            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

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
        } break;

        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
        {
            /* set keyId */
            packet->pkEccCheckReq.keyId =
                (intptr_t)(info->pk.ecc_check.key->devCtx);
            /* set curveId */
            packet->pkEccCheckReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
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

        #endif /* HAVE_ECC */
#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
        {
            ret = wh_Client_MakeExportCurve25519Key(ctx,
                    info->pk.curve25519kg.size,
                    info->pk.curve25519kg.key);
            /* Fix up error code to be wolfCrypt*/
            if (ret == WH_ERROR_BADARGS) {
                ret = BAD_FUNC_ARG;
            }
#if 0
            packet->pkCurve25519kgReq.sz = info->pk.curve25519kg.size;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519kgReq),
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
#endif
        } break;

        case WC_PK_TYPE_CURVE25519:
        {
            /* out is after the fixed size fields */
            uint8_t* out = (uint8_t*)(&packet->pkCurve25519Res + 1);
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Res);
            whKeyId priv_key_id = WH_DEVCTX_TO_KEYID(
                    info->pk.curve25519.private_key->devCtx);
            whKeyId pub_key_id = WH_DEVCTX_TO_KEYID(
                    info->pk.curve25519.public_key->devCtx);
            int endian = info->pk.curve25519.endian;
            int priv_evict = 0;
            int pub_evict = 0;

            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

            /* check to see if the pub key id is erased */
            if (WH_KEYID_ISERASED(pub_key_id)) {
                /* Must import the key to the server and evict it afterwards */
                uint8_t keyLabel[] = "ClientCbTempC25519-pub";
                whNvmFlags flags = WH_NVM_FLAGS_NONE;

                ret = wh_Client_ImportCurve25519Key(ctx,
                        info->pk.curve25519.public_key,
                        flags, sizeof(keyLabel), keyLabel, &pub_key_id);
                if (ret == 0) {
                    pub_evict = 1;
                }
            }

            /* check to see if the priv key id is erased */
            if (    (ret == 0) &&
                    (WH_KEYID_ISERASED(priv_key_id))) {
                /* Must import the key to the server and evict it afterwards */
                uint8_t keyLabel[] = "ClientCbTempC25519-priv";
                whNvmFlags flags = WH_NVM_FLAGS_NONE;

                ret = wh_Client_ImportCurve25519Key(ctx,
                        info->pk.curve25519.private_key,
                        flags, sizeof(keyLabel), keyLabel, &priv_key_id);
                if (ret == 0) {
                    priv_evict = 1;
                }
            }

            if (ret == 0) {
                /* Set packet members. Reset anyreq.type just in case */
                packet->pkAnyReq.type = info->pk.type;
                packet->pkCurve25519Req.privateKeyId = priv_key_id;
                packet->pkCurve25519Req.publicKeyId = pub_key_id;
                packet->pkCurve25519Req.endian = endian;

                /* write request */
                ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
                    (uint8_t*)packet);
    #ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] Curve25519 req sent. priv:%u pub:%u endian:%d type:%u\n",
                        packet->pkCurve25519Req.privateKeyId,
                        packet->pkCurve25519Req.publicKeyId,
                        packet->pkCurve25519Req.endian,
                        packet->pkCurve25519Req.type);
    #endif
                /* read response */
                if (ret == 0) {
                    do {
                        ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                            (uint8_t*)packet);
                    } while (ret == WH_ERROR_NOTREADY);
                }
    #ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] Curve25519 resp packet recv. ret:%d rc:%d\n", ret, packet->rc);
    #endif
                if (ret == 0) {
                    if (packet->rc != 0)
                        ret = packet->rc;
                    else {
                        /* read outLen */
                        *info->pk.curve25519.outlen = packet->pkCurve25519Res.sz;
                        /* read out */
                        XMEMCPY(info->pk.curve25519.out, out, packet->pkCurve25519Res.sz);
                    }
                }
            }
            if (pub_evict != 0) {
                /* Evict the imported key */
                ret = wh_Client_KeyEvict(ctx, pub_key_id);
            }
            if (priv_evict != 0) {
                /* Evict the imported key */
                ret = wh_Client_KeyEvict(ctx, priv_key_id);
            }


#if 0

            uint8_t* out = (uint8_t*)(&packet->pkCurve25519Res + 1);

            packet->pkCurve25519Req.privateKeyId =
                (intptr_t)(info->pk.curve25519.private_key->devCtx);
            packet->pkCurve25519Req.publicKeyId =
                (intptr_t)(info->pk.curve25519.public_key->devCtx);
            packet->pkCurve25519Req.endian = info->pk.curve25519.endian;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Req),
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
#endif
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
        /* out is after the fixed size fields */
        uint8_t* out = (uint8_t*)(&packet->rngRes + 1);

        /* set sz */
        packet->rngReq.sz = info->rng.sz;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_RNG,
            WH_PACKET_STUB_SIZE + sizeof(packet->rngReq),(uint8_t*)packet);
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
    } break;
#endif /* !WC_NO_RNG */

#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
    {
        /* in, key and out are after the fixed size fields */
        uint8_t* in = (uint8_t*)(&packet->cmacReq + 1);
        uint8_t* key = in + info->cmac.inSz;
        uint8_t* out = (uint8_t*)(&packet->cmacRes + 1);
        dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->cmacReq) +
            info->cmac.inSz + info->cmac.keySz;

        if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
            /* if we're using an HSM key return BAD_FUNC_ARG */
            if (info->cmac.cmac->devCtx != NULL) {
                ret = BAD_FUNC_ARG;
            } else {
                ret = CRYPTOCB_UNAVAILABLE;
            }
            break;
        }
        /* Return success for init call with NULL params */
        if (    (info->cmac.in == NULL) &&
                (info->cmac.key == NULL) &&
                (info->cmac.out == NULL)) {
            ret = 0;
            break;
        }

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
            WH_PACKET_STUB_SIZE + sizeof(packet->cmacReq) +
            packet->cmacReq.inSz + packet->cmacReq.keySz, (uint8_t*)packet);
        if (ret == 0) {
            /* if the client marked they may want to cancel, handle the
             * response in a seperate call */
            if (ctx->cancelable)
                break;
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

#ifdef DEBUG_CRYPTOCB
    if (ret == CRYPTOCB_UNAVAILABLE) {
        printf("[client] Client_CryptoCb: X not implemented: algo->type:%d\n", info->algo_type);
    } else {
        printf("[client] Client_CryptoCb: - ret:%d algo->type:%d\n", ret, info->algo_type);
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
    _hexdump("[client] inBlock: ", req->inBlock, WC_SHA256_BLOCK_SIZE);
    if (req->resumeState.hiLen != 0 || req->resumeState.loLen != 0) {
        _hexdump("  [client] resumeHash: ", req->resumeState.hash,
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
            _hexdump("[client] hash: ", (uint8_t*)sha256->digest,
                     WC_SHA256_DIGEST_SIZE);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
    }

    return ret;
}

#endif /* !NO_SHA256 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
