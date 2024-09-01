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
#include "wolfssl/wolfcrypt/ecc.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_packet.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

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
    memset((uint8_t*)packet, 0, sizeof(*packet));

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
    memset((uint8_t*)packet, 0, sizeof(*packet));

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
        if (ret == 0) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message*/
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t type = WC_PK_TYPE_ECDH;

        wh_Packet_pk_ecdh_req* req = &packet->pkEcdhReq;
        uint16_t req_len =  WH_PACKET_STUB_SIZE + sizeof(*req);
        uint32_t options = 0;

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        if (pub_evict != 0) {
            options |= WH_PACKET_PK_ECDH_OPTIONS_EVICTPUB;
        }
        if (prv_evict != 0) {
            options |= WH_PACKET_PK_ECDH_OPTIONS_EVICTPRV;
        }

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


int wh_Client_EccDsaSign(whClientContext* ctx,
        ecc_key* key,
        const uint8_t* in, word32 in_len,
        uint8_t* out, word32 *inout_len)
{
    int ret = 0;
    whPacket* packet;

    /* Transaction state */
    whKeyId key_id;
    int evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
        __func__, ctx, key, in, in_len, out, inout_len);
#endif

    if (    (ctx == NULL) ||
            (key == NULL) ||
            ((in == NULL) && (in_len > 0)) ||
            ((out != NULL) && (inout_len == NULL)) ) {
        return WH_ERROR_BADARGS;
    }

    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset((uint8_t*)packet, 0, sizeof(*packet));


    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);


    #ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x, in_len:%u, inout_len:%p\n",
            __func__, key_id, in_len, inout_len);
    #endif

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempEccDsaSign";
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
        uint16_t type = WC_PK_TYPE_ECDSA_SIGN;

        wh_Packet_pk_ecc_sign_req* req;
        req = &packet->pkEccSignReq;
        uint8_t* req_in = (uint8_t*)(req + 1);
        uint16_t req_len = WH_PACKET_STUB_SIZE + sizeof(*req) + in_len;
        uint32_t options = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_PACKET_PK_ECSIGN_OPTIONS_EVICT;
            }
            req->type = type;
            req->options = options;
            req->keyId = key_id;
            req->sz = in_len;
            if( (in != NULL) && (in_len > 0)) {
                XMEMCPY(req_in, in, in_len);
            }

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                    (uint8_t*)packet);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Response Message */
                wh_Packet_pk_ecc_sign_res* res;
                res = &packet->pkEccSignRes;
                uint8_t* res_out = (uint8_t*)(res + 1);
                uint16_t res_len;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    if (packet->rc == 0) {
                        uint16_t out_len = res->sz;
                        /* check inoutlen and read out */
                        if (inout_len != NULL) {
                            if (out_len > *inout_len) {
                                /* Silently truncate the signature */
                                out_len = *inout_len;
                            }
                            *inout_len = out_len;
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

int wh_Client_EccDsaVerify(whClientContext* ctx, ecc_key* key,
        const uint8_t* sig, word32 sig_len,
        const uint8_t* hash, word32 hash_len,
        int *out_res)
{
    int ret = 0;
    whPacket* packet;

    /* Transaction state */
    whKeyId key_id;
    int evict = 0;
    int export_pub_key = 0;


#ifdef DEBUG_CRYPTOCB_VERBOSE
printf("[client] %s ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
        __func__, ctx, key, in, in_len, out, inout_len);
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
    memset((uint8_t*)packet, 0, sizeof(*packet));

    /* TODO: Check the request size to ensure it will fit before importing key*/
#if 0
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        ret = WH_ERROR_BADARGS;
        break;
    }
#endif

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (key->type == ECC_PRIVATEKEY_ONLY) {
            export_pub_key = 1;
        }
    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t keyLabel[] = "TempEccDsaVerify";
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
                            ret = wh_Crypto_UpdatePrivateOnlyEccKey(key,
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

#endif /* HAVE_ECC */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
