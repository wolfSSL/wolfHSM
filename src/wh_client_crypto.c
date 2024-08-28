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
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_utils.h"


/* Components */
#include "wolfhsm/wh_comm.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
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

#ifdef HAVE_ECC
int wh_Client_SetEccKeyId(ecc_key* key, whNvmId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_GetEccKeyId(ecc_key* key, whNvmId* outId)
{
    if (    (key == NULL) ||
            (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_ImportEccKey(whClientContext* ctx, ecc_key* key,
        whKeyId *inout_keyId, whNvmFlags flags,
        uint32_t label_len, uint8_t* label)

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

    ret = wh_Crypto_SerializeEccKey(key, sizeof(buffer),buffer,
            &buffer_len);
    printf("[client] ImportEccKey serialize ret:%d, key:%p, max_size:%u, buffer:%p, outlen:%u\n",
            ret, key, (unsigned int)sizeof(buffer), buffer, buffer_len);
    if (ret == 0) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx,
                flags, label, label_len,
                buffer, buffer_len, &key_id);
        if (inout_keyId != NULL) {
            *inout_keyId = key_id;
        }
    }
    return ret;
}

int wh_Client_ExportEccKey(whClientContext* ctx, whKeyId keyId,
        ecc_key* key,
        uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    /* buffer cannot be larger than MTU */
    byte buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint32_t buffer_len = sizeof(buffer);

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
        ret = wh_Crypto_DeserializeEccKey(
                buffer_len, buffer, key);
    }

    return ret;
}

int wh_Client_MakeEccKey(whClientContext* ctx,
        uint32_t size, uint32_t curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint32_t label_len, uint8_t* label,
        ecc_key* key)
{
    int ret = 0;
    whPacket* packet = NULL;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t data_len = 0;
    wh_Packet_pk_eckg_req* req = NULL;
    wh_Packet_pk_eckg_res* res = NULL;
    uint32_t type = WC_PK_TYPE_EC_KEYGEN;
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

    req = &packet->pkEckgReq;
    res = &packet->pkEckgRes;

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Set up the request packet */
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
    data_len = WH_PACKET_STUB_SIZE + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, action, data_len, (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] Ecc KeyGen Req sent:size:%u, ret:%d\n",
            req->sz, ret);
#endif
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &data_len,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] Ecc KeyGen Res recv:keyid:%u, len:%u, rc:%d, ret:%d\n",
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
            if (key != NULL) {
                uint16_t der_size = (uint16_t)(res->len);
                uint8_t* key_der = (uint8_t*)(res + 1);
                /* Set the key_id.  Should be ERASED if EPHEMERAL */
                wh_Client_SetEccKeyId(key, key_id);

                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret = wh_Crypto_DeserializeEccKey(
                            der_size, key_der, key);
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

int wh_Client_MakeCacheEccKey(whClientContext* ctx,
        uint32_t size, uint32_t curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint32_t label_len, uint8_t* label)
{
    /* Valid keyid ptr is required in this form */
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_MakeEccKey(ctx,
            size, curveId,
            inout_key_id, flags,
            label_len, label,
            NULL);
}

int wh_Client_MakeExportEccKey(whClientContext* ctx,
        uint32_t size, uint32_t curveId, ecc_key* key)
{
    /* Valid key is required for this form */
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_MakeEccKey(ctx,
            size, curveId,
            NULL, WH_NVM_FLAGS_EPHEMERAL,
            0, NULL,
            key);
}

#endif /* HAVE_ECC */

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

#if 0
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
#endif

#endif /* HAVE_ECC */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
