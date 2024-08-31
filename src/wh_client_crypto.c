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
int wh_Client_EccSetKeyId(ecc_key* key, whNvmId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_EccGetKeyId(ecc_key* key, whNvmId* outId)
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
        uint32_t label_len, uint8_t* label)

{
    int ret = WH_ERROR_OK;
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

    ret = wh_Crypto_EccSerializeKey(key, sizeof(buffer),buffer, &buffer_len);
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
        uint32_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    /* buffer cannot be larger than MTU */
    byte buffer[ECC_BUFSIZE] = {0};
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
    if (ret == WH_ERROR_OK) {
        /* Update the key structure */
        ret = wh_Crypto_EccDeserializeKey(buffer, buffer_len, key);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x key:%p ret:%d label:%.*s\n",
            __func__, keyId, key, ret, label_len, label);
#endif
    return ret;
}

int wh_Client_EccMakeKey(whClientContext* ctx,
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
    printf("[client] %s Req sent:size:%u, ret:%d\n",
            __func__, req->sz, ret);
#endif
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &data_len,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s Res recv:keyid:%u, len:%u, rc:%d, ret:%d\n",
            __func__, res->keyId, res->len, packet->rc, ret);
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
                wh_Client_EccSetKeyId(key, key_id);

                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret = wh_Crypto_EccDeserializeKey(key_der, der_size, key);
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
    return ret;
}

int wh_Client_EccMakeCacheKey(whClientContext* ctx,
        uint32_t size, uint32_t curveId,
        whKeyId *inout_key_id, whNvmFlags flags,
        uint32_t label_len, uint8_t* label)
{
    /* Valid keyid ptr is required in this form */
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_EccMakeKey(ctx,
            size, curveId,
            inout_key_id, flags,
            label_len, label,
            NULL);
}

int wh_Client_EccMakeExportKey(whClientContext* ctx,
        uint32_t size, uint32_t curveId, ecc_key* key)
{
    /* Valid key is required for this form */
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Client_EccMakeKey(ctx,
            size, curveId,
            NULL, WH_NVM_FLAGS_EPHEMERAL,
            0, NULL,
            key);
}

int wh_Client_EccSharedSecret(whClientContext* ctx,
                                ecc_key* priv_key, ecc_key* pub_key,
                                uint8_t* out, word32 *out_size)
{
    int ret = 0;
    whPacket* packet;

    /* Transaction state */
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t type = WC_PK_TYPE_ECDH;
    int priv_evict;
    whKeyId priv_key_id;
    int pub_evict;
    whKeyId pub_key_id;

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
    if (    (ret == 0) &&
            WH_KEYID_ISERASED(pub_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "ClientCbTempEcc-pub";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx,
                pub_key, &pub_key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == 0) {
            pub_evict = 1;
        }
    } else {
        pub_evict = 0;
    }

    priv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if (    (ret == 0) &&
            WH_KEYID_ISERASED(priv_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "ClientCbTempEcc-priv";
        whNvmFlags flags = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx,
                priv_key, &priv_key_id, flags,
                sizeof(keyLabel), keyLabel);
        if (ret == 0) {
            priv_evict = 1;
        }
    } else {
        priv_evict = 0;
    }


    if (ret == 0) {
        /* Generate Request */
        wh_Packet_pk_ecdh_req* req = &packet->pkEcdhReq;
        uint16_t req_len =  WH_PACKET_STUB_SIZE + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        req->type = type;
        req->privateKeyId = priv_key_id;
        req->publicKeyId = pub_key_id;

        /* write request */
        ret = wh_Client_SendRequest(ctx, group, action, req_len,
            (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] EccDh req sent. priv:%u pub:%u type:%u\n",
                req->privateKeyId,
                req->publicKeyId,
                req->type);
#endif
        if (ret == 0) {
            wh_Packet_pk_ecdh_res* res = &packet->pkEcdhRes;
            uint16_t res_len;
            /* out is after the fixed size fields */
            uint8_t* res_out = (uint8_t*)(res + 1);

            /* read response */
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] EccDh resp packet recv. ret:%d rc:%d\n", ret, packet->rc);
#endif
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    if (out_size != NULL) {
                        *out_size = res->sz;
                    }
                    if (out != NULL) {
                        XMEMCPY(out, res_out, res->sz);
                    }
    #ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[client] Eccdh:", res_out, res->sz);
    #endif
                }
            }
        }
    }
    if (pub_evict != 0) {
        wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if (priv_evict != 0) {
        wh_Client_KeyEvict(ctx, priv_key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("client %s ret:%d\n", __func__, ret);
#endif
    return ret;

}

#endif /* HAVE_ECC */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
