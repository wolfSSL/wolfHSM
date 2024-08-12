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

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

/* Components */
#include "wolfhsm/wh_comm.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"

#endif

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_packet.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#ifdef HAVE_CURVE25519
int wh_Client_SetKeyIdCurve25519(curve25519_key* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    key->pubSet = 1;
    key->privSet = 1;
    return WH_ERROR_OK;
}

int wh_Client_GetKeyIdCurve25519(curve25519_key* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ECC
int wh_Client_SetKeyIdEcc(ecc_key* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_GetKeyIdEcc(ecc_key* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_ImportEccKey(whClientContext* ctx, ecc_key* key,
        uint32_t label_len, uint8_t* label, whKeyId *out_keyId)
{
    int ret = 0;
    whKeyId cacheKeyId = WH_KEYID_ERASED;
    byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    word32 derSize = 0;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    /* Convert RSA key to DER format */
    ret = derSize = wc_EccKeyToDer(key, keyDer, sizeof(keyDer));
    if( (ret == 0) &&
        (derSize >= 0)) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE,
                label, label_len,
                keyDer, derSize, &cacheKeyId);
        if (out_keyId != NULL) {
            *out_keyId = cacheKeyId;
        }
    }
    return ret;
}

int wh_Client_ExportEccKey(whClientContext* ctx, whKeyId keyId, ecc_key* key,
        uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    /* DER cannot be larger than MTU */
    byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint32_t derSize = sizeof(keyDer);
    uint8_t keyLabel[WH_NVM_LABEL_LEN] = {0};

    if (    (ctx == NULL) ||
            (keyId == WH_KEYID_ERASED) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret = wh_Client_KeyExport(ctx,keyId,
            keyLabel, sizeof(keyLabel),
            keyDer, &derSize);
    if (ret == 0) {
        word32 idx = 0;
        /* Update the RSA key structure */
        ret = wc_EccPrivateKeyDecode(
                keyDer, &idx,
                key,
                derSize);
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
#endif /* HAVE_ECC */

#ifndef NO_RSA
int wh_Client_SetKeyIdRsa(RsaKey* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_GetKeyIdRsa(RsaKey* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}


int wh_Client_ImportRsaKey(whClientContext* ctx, RsaKey* key,
        whNvmFlags flags, uint32_t label_len, uint8_t* label,
        whKeyId *out_keyId)
{
    int ret = 0;
    whKeyId cacheKeyId = WH_KEYID_ERASED;
    byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    int derSize = 0;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    /* Convert RSA key to DER format */
    ret = derSize = wc_RsaKeyToDer(key, keyDer, sizeof(keyDer));
    if(derSize >= 0) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags,
                label, label_len,
                keyDer, derSize, &cacheKeyId);
        if (out_keyId != NULL) {
            *out_keyId = cacheKeyId;
        }
    }
    return ret;
}

int wh_Client_ExportRsaKey(whClientContext* ctx, whKeyId keyId, RsaKey* key,
        uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    /* DER cannot be larger than MTU */
    byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint32_t derSize = sizeof(keyDer);
    uint8_t keyLabel[WH_NVM_LABEL_LEN] = {0};

    if (    (ctx == NULL) ||
            (keyId == WH_KEYID_ERASED) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret = wh_Client_KeyExport(ctx,keyId,
            keyLabel, sizeof(keyLabel),
            keyDer, &derSize);
    if (ret == 0) {
        word32 idx = 0;
        /* Update the RSA key structure */
        ret = wc_RsaPrivateKeyDecode(
                keyDer, &idx,
                key,
                derSize);
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

int wh_Client_MakeRsaKey(whClientContext* ctx,
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

    /* Set up the reqeust packet */
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
                word32 idx = 0;
                /* Set the rsa key_id.  Should be ERASED if EPHEMERAL */
                wh_Client_SetKeyIdRsa(rsa, key_id);

                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret = wc_RsaPrivateKeyDecode(rsa_der, &idx, rsa, der_size);
                }
            }
        } else {
            /* Server detected a problem with generation */
            ret = packet->rc;
        }
    }
    return ret;
}

int wh_Client_MakeCacheRsaKey(whClientContext* ctx,
        uint32_t size, uint32_t e,
        whNvmFlags flags,  uint32_t label_len, uint8_t* label,
        whKeyId *inout_key_id)
{
    /* Valid keyid ptr is required in this form */
    if (    (ctx == NULL) ||
            (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_MakeRsaKey(ctx,
            size, e,
            flags, label_len, label,
            inout_key_id, NULL);
}

int wh_Client_MakeExportRsaKey(whClientContext* ctx,
        uint32_t size, uint32_t e, RsaKey* rsa)
{
    /* Valid ctx and rsa are required for this form */
    if (    (ctx == NULL) ||
            (rsa == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_MakeRsaKey(ctx,
            size, e,
            WH_NVM_FLAGS_EPHEMERAL,  0, NULL,
            NULL, rsa);
}


#endif /* !NO_RSA */

#ifndef NO_AES
int wh_Client_SetKeyIdAes(Aes* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_GetKeyIdAes(Aes* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}
#endif

#ifdef WOLFSSL_CMAC
int wh_Client_SetKeyIdCmac(Cmac* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_GetKeyIdCmac(Cmac* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_AesCmacGenerate(Cmac* cmac, byte* out, word32* outSz,
    const byte* in, word32 inSz, whNvmId keyId, void* heap)
{
    int ret;
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, heap,
        WH_DEV_ID);
    /* set keyId */
    if (ret == 0)
        ret = wh_Client_SetKeyIdCmac(cmac, keyId);
    if (ret == 0)
        ret = wc_CmacUpdate(cmac, in, inSz);
    if (ret == 0)
        ret = wc_CmacFinal(cmac, out, outSz);
    return ret;
}

int wh_Client_AesCmacVerify(Cmac* cmac, const byte* check, word32 checkSz,
    const byte* in, word32 inSz, whNvmId keyId, void* heap)
{
    int ret;
    word32 outSz = AES_BLOCK_SIZE;
    byte out[AES_BLOCK_SIZE];
    ret = wc_InitCmac_ex(cmac, NULL, 0, WC_CMAC_AES, NULL, heap,
        WH_DEV_ID);
    /* set keyId */
    if (ret == 0)
        ret = wh_Client_SetKeyIdCmac(cmac, keyId);
    if (ret == 0)
        ret = wc_CmacUpdate(cmac, in, inSz);
    if (ret == 0)
        ret = wc_CmacFinal(cmac, out, &outSz);
    if (ret == 0)
        ret = memcmp(out, check, outSz) == 0 ? 0 : 1;
    return ret;
}

int wh_Client_CmacCancelableResponse(whClientContext* c, Cmac* cmac,
    uint8_t* out, uint32_t* outSz)
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
