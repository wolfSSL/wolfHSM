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
 * src/wh_client_she.c
 *
 */


/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && defined(WOLFHSM_CFG_ENABLE_CLIENT)

#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_error.h"

/* Components */
#include "wolfhsm/wh_comm.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_she.h"

#include "wolfhsm/wh_client.h"

#include "wolfhsm/wh_client_she.h"

int wh_Client_ShePreProgramKey(whClientContext* c, whNvmId keyId,
    whNvmFlags flags, uint8_t* key, whNvmSize keySz)
{
    int ret;
    int32_t outRc;
    uint8_t label[WH_NVM_LABEL_LEN] = { 0 };

    /* Create a key with 0 counter */
    wh_She_Meta2Label(0, flags, label);
    ret = wh_Client_NvmAddObject(c,
            WH_MAKE_KEYID(WH_KEYTYPE_SHE, c->comm->client_id, keyId),
            0, 0, sizeof(label), label, keySz, key, (int32_t*)&outRc);
    if (ret == 0)
        ret = outRc;
    return ret;
}

int wh_Client_SheSetUidRequest(whClientContext* c, uint8_t* uid, uint32_t uidSz)
{
    int ret;
    whMessageShe_SetUidRequest *req = NULL;

    if (c == NULL || uid == NULL || uidSz < WH_SHE_UID_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_SetUidRequest*)wh_CommClient_GetDataPtr(c->comm);

    memcpy(req->uid, uid, sizeof(req->uid));

    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_SET_UID,
                                sizeof(*req), (uint8_t*)req);
    return ret;
}

int wh_Client_SheSetUidResponse(whClientContext* c)
{
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    int ret;
    whMessageShe_SetUidResponse *resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_SetUidResponse*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == WH_ERROR_OK) {
        ret = resp->rc;
    }
    return ret;
}

int wh_Client_SheSetUid(whClientContext* c, uint8_t* uid, uint32_t uidSz)
{
    int ret;
    ret = wh_Client_SheSetUidRequest(c, uid, uidSz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheSetUidResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheSecureBoot(whClientContext* c, uint8_t* bootloader,
                            uint32_t bootloaderLen)
{
    int      ret;
    uint32_t bootloaderSent = 0;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* in;
    uint8_t* respBuf;

    whMessageShe_SecureBootInitRequest*    initReq    = NULL;
    whMessageShe_SecureBootUpdateRequest*  updateReq  = NULL;
    whMessageShe_SecureBootInitResponse*   initResp   = NULL;
    whMessageShe_SecureBootFinishResponse* finishResp = NULL;

    if (c == NULL || bootloader == NULL || bootloaderLen == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Get request and response buffers from comm client */
    initReq =
        (whMessageShe_SecureBootInitRequest*)wh_CommClient_GetDataPtr(c->comm);
    respBuf = (uint8_t*)wh_CommClient_GetDataPtr(c->comm);

    /* send init sub command */
    initReq->sz = bootloaderLen;
    ret =
        wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_INIT,
                              sizeof(*initReq), (uint8_t*)initReq);

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, respBuf);
            initResp = (whMessageShe_SecureBootInitResponse*)respBuf;
        } while (ret == WH_ERROR_NOTREADY);
    }

    /* send update sub command until we've sent the entire bootloader */
    while (ret == 0 && bootloaderSent < bootloaderLen) {
        uint32_t justSent;

        if (initResp->rc != WH_SHE_ERC_NO_ERROR) {
            return initResp->rc;
        }

        /* Get fresh request buffer for update */
        updateReq =
            (whMessageShe_SecureBootUpdateRequest*)wh_CommClient_GetDataPtr(
                c->comm);
        in = (uint8_t*)(updateReq + 1);

        /* send what's left in the size available */
        updateReq->sz = ((bootloaderLen - bootloaderSent) %
                         (WOLFHSM_CFG_COMM_DATA_LEN - sizeof(*updateReq)));

        justSent = updateReq->sz;
        memcpy(in, bootloader + bootloaderSent, updateReq->sz);

        ret = wh_Client_SendRequest(
            c, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_UPDATE,
            sizeof(*updateReq) + updateReq->sz, (uint8_t*)updateReq);

        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
                                             respBuf);
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* increment sent  */
        if (ret == 0) {
            bootloaderSent += justSent;
        }
    }

    /* send finish sub command */
    if (ret == 0) {
        ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
                                    WH_SHE_SECURE_BOOT_FINISH, 0, NULL);
    }

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, respBuf);
            finishResp = (whMessageShe_SecureBootFinishResponse*)respBuf;
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == 0) {
        ret = finishResp->rc;
    }

    return ret;
}

int wh_Client_SheGetStatusRequest(whClientContext* c)
{
    int ret;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Status request is a zero-length message */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
        WH_SHE_GET_STATUS, 0, NULL);
    return ret;
}

int wh_Client_SheGetStatusResponse(whClientContext* c, uint8_t* sreg)
{
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    int ret;
    whMessageShe_GetStatusResponse *resp = NULL;

    if (c == NULL || sreg == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_GetStatusResponse*)wh_CommClient_GetDataPtr(c->comm);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);

    /* return error or set sreg */
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR)
            ret = resp->rc;
        else
            *sreg = resp->sreg;
    }
    return ret;
}

int wh_Client_SheGetStatus(whClientContext* c, uint8_t* sreg)
{
    int ret;
    ret = wh_Client_SheGetStatusRequest(c);
    if (ret == 0) {
        do {
            ret = wh_Client_SheGetStatusResponse(c, sreg);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheLoadKeyRequest(whClientContext* c, uint8_t* messageOne,
                                uint8_t* messageTwo, uint8_t* messageThree)
{
    int       ret;
    whMessageShe_LoadKeyRequest *req = NULL;

    if (c == NULL || messageOne == NULL || messageTwo == NULL ||
        messageThree == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_LoadKeyRequest*)wh_CommClient_GetDataPtr(c->comm);
    /* copy in messages 1-3 */
    memcpy(req->messageOne, messageOne,
           sizeof(req->messageOne));
    memcpy(req->messageTwo, messageTwo,
           sizeof(req->messageTwo));
    memcpy(req->messageThree, messageThree,
           sizeof(req->messageThree));
    /* send load key req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_LOAD_KEY,
                                sizeof(*req), (uint8_t*)req);
    return ret;
}

int wh_Client_SheLoadKeyResponse(whClientContext* c, uint8_t* messageFour,
                                 uint8_t* messageFive)
{
    int                           ret;
    uint16_t                      group;
    uint16_t                      action;
    uint16_t                      dataSz;
    whMessageShe_LoadKeyResponse* resp = NULL;

    if (c == NULL || messageFour == NULL || messageFive == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_LoadKeyResponse*)wh_CommClient_GetDataPtr(c->comm);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else {
            /* copy out message 4 and 5 */
            memcpy(messageFour, resp->messageFour, sizeof(resp->messageFour));
            memcpy(messageFive, resp->messageFive, sizeof(resp->messageFive));
        }
    }
    return ret;
}

int wh_Client_SheLoadKey(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive)
{
    int ret;
    ret = wh_Client_SheLoadKeyRequest(c, messageOne, messageTwo, messageThree);
    if (ret == 0) {
        do {
            ret = wh_Client_SheLoadKeyResponse(c, messageFour, messageFive);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheLoadPlainKeyRequest(whClientContext* c, uint8_t* key,
                                     uint32_t keySz)
{
    whMessageShe_LoadPlainKeyRequest* req = NULL;

    if (c == NULL || key == NULL || keySz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_LoadPlainKeyRequest*)wh_CommClient_GetDataPtr(c->comm);

    memcpy(req->key, key, WH_SHE_KEY_SZ);

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_LOAD_PLAIN_KEY,
                                 sizeof(*req), (uint8_t*)req);
}

int wh_Client_SheLoadPlainKeyResponse(whClientContext* c)
{
    int                                ret;
    uint16_t                           group;
    uint16_t                           action;
    uint16_t                           dataSz;
    whMessageShe_LoadPlainKeyResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp =
        (whMessageShe_LoadPlainKeyResponse*)wh_CommClient_GetDataPtr(c->comm);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        ret = resp->rc;
    }
    return ret;
}

int wh_Client_SheLoadPlainKey(whClientContext* c, uint8_t* key, uint32_t keySz)
{
    int ret;
    ret = wh_Client_SheLoadPlainKeyRequest(c, key, keySz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheLoadPlainKeyResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheExportRamKeyRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Export RAM Key is a zero-length message */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_EXPORT_RAM_KEY,
                                 0, NULL);
}

int wh_Client_SheExportRamKeyResponse(whClientContext* c, uint8_t* messageOne,
                                      uint8_t* messageTwo,
                                      uint8_t* messageThree,
                                      uint8_t* messageFour,
                                      uint8_t* messageFive)
{
    int                                ret;
    uint16_t                           group;
    uint16_t                           action;
    uint16_t                           dataSz;
    whMessageShe_ExportRamKeyResponse* resp = NULL;

    if (c == NULL || messageOne == NULL || messageTwo == NULL ||
        messageThree == NULL || messageFour == NULL || messageFive == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp =
        (whMessageShe_ExportRamKeyResponse*)wh_CommClient_GetDataPtr(c->comm);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else {
            memcpy(messageOne, resp->messageOne, sizeof(resp->messageOne));
            memcpy(messageTwo, resp->messageTwo, sizeof(resp->messageTwo));
            memcpy(messageThree, resp->messageThree,
                   sizeof(resp->messageThree));
            memcpy(messageFour, resp->messageFour, sizeof(resp->messageFour));
            memcpy(messageFive, resp->messageFive, sizeof(resp->messageFive));
        }
    }

    return ret;
}

int wh_Client_SheExportRamKey(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive)
{
    int ret;
    ret = wh_Client_SheExportRamKeyRequest(c);
    if (ret == 0) {
        do {
            ret = wh_Client_SheExportRamKeyResponse(c, messageOne, messageTwo,
                messageThree, messageFour, messageFive);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheInitRndRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Init RND is a zero-length message */    
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_INIT_RND, 0,
                                NULL);
}

int wh_Client_SheInitRndResponse(whClientContext* c)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whMessageShe_InitRngResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_InitRngResponse*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        ret = resp->rc;
    }
    return ret;
}

int wh_Client_SheInitRnd(whClientContext* c)
{
    int ret;
    ret = wh_Client_SheInitRndRequest(c);
    if (ret == 0) {
        do {
            ret = wh_Client_SheInitRndResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheRndRequest(whClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* RND is a zero-length message */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_RND, 0, NULL);
}

int wh_Client_SheRndResponse(whClientContext* c, uint8_t* out, uint32_t* outSz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whMessageShe_RndResponse* resp = NULL;

    if (c == NULL || out == NULL || outSz == NULL || *outSz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_RndResponse*)wh_CommClient_GetDataPtr(c->comm);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);

    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR)
            ret = resp->rc;
        else {
            memcpy(out, resp->rnd, sizeof(resp->rnd));
            *outSz = sizeof(resp->rnd);
        }
    }
    return ret;
}

int wh_Client_SheRnd(whClientContext* c, uint8_t* out, uint32_t* outSz)
{
    int ret;
    ret = wh_Client_SheRndRequest(c);
    if (ret == 0) {
        do {
            ret = wh_Client_SheRndResponse(c, out, outSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheExtendSeedRequest(whClientContext* c, uint8_t* entropy,
    uint32_t entropySz)
{
    int ret;
    whMessageShe_ExtendSeedRequest *req = NULL;

    if (c == NULL || entropy == NULL || entropySz != WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_ExtendSeedRequest*)wh_CommClient_GetDataPtr(c->comm);

    /* set entropy */
    memcpy(req->entropy, entropy, sizeof(req->entropy));

    /* send init rng req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_EXTEND_SEED,
                                sizeof(*req), (uint8_t*)req);

    return ret;
}

int wh_Client_SheExtendSeedResponse(whClientContext* c)
{
    int                              ret;
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         dataSz;
    whMessageShe_ExtendSeedResponse* resp = NULL;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_ExtendSeedResponse*)wh_CommClient_GetDataPtr(c->comm);
    ret  = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);

    if (ret == 0) {
        ret = resp->rc;
    }

    return ret;
}

int wh_Client_SheExtendSeed(whClientContext* c, uint8_t* entropy,
    uint32_t entropySz)
{
    int ret;
    ret = wh_Client_SheExtendSeedRequest(c, entropy, entropySz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheExtendSeedResponse(c);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheEncEcbRequest(whClientContext* c, uint8_t keyId, uint8_t* in,
                               uint32_t sz)
{
    uint8_t*                    packIn;
    whMessageShe_EncEcbRequest* req = NULL;

    if (c == NULL || in == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_EncEcbRequest*)wh_CommClient_GetDataPtr(c->comm);

    /* in is after fixed sized fields */
    packIn     = (uint8_t*)(req + 1);
    req->keyId = keyId;
    req->sz    = sz;
    memcpy(packIn, in, sz);

    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_ENC_ECB,
                                 sizeof(*req) + sz, (uint8_t*)req);
}

int wh_Client_SheEncEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     dataSz;
    uint8_t*                     packOut;
    whMessageShe_EncEcbResponse* resp = NULL;

    if (c == NULL || out == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_EncEcbResponse*)wh_CommClient_GetDataPtr(c->comm);

    /* out is after fixed sized fields */
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else if (sz < resp->sz) {
            ret = WH_ERROR_BADARGS;
        }
        else {
            memcpy(out, packOut, resp->sz);
        }
    }
    return ret;
}

int wh_Client_SheEncEcb(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint8_t* out, uint32_t sz)
{
    int ret;
    ret = wh_Client_SheEncEcbRequest(c, keyId, in, sz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheEncEcbResponse(c, out, sz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheEncCbcRequest(whClientContext* c, uint8_t keyId, uint8_t* iv,
                               uint32_t ivSz, uint8_t* in, uint32_t sz)
{
    uint8_t*                    packIn;
    whMessageShe_EncCbcRequest* req = NULL;

    if (c == NULL || in == NULL || sz < WH_SHE_KEY_SZ || iv == NULL ||
        ivSz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_EncCbcRequest*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn     = (uint8_t*)(req + 1);
    req->keyId = keyId;
    req->sz    = sz;
    /* set iv */
    memcpy(req->iv, iv, ivSz);
    /* set in */
    memcpy(packIn, in, sz);

    /* send enc ecb */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_ENC_CBC,
                                 sizeof(*req) + sz, (uint8_t*)req);
}

int wh_Client_SheEncCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     dataSz;
    uint8_t*                     packOut;
    whMessageShe_EncCbcResponse* resp = NULL;

    if (c == NULL || out == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_EncCbcResponse*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else if (sz < resp->sz) {
            ret = WH_ERROR_BADARGS;
        }
        else {
            memcpy(out, packOut, resp->sz);
        }
    }
    return ret;
}

int wh_Client_SheEncCbc(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint8_t* out, uint32_t sz)
{
    int ret;
    ret = wh_Client_SheEncCbcRequest(c, keyId, iv, ivSz, in, sz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheEncCbcResponse(c, out, sz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheDecEcbRequest(whClientContext* c, uint8_t keyId, uint8_t* in,
                               uint32_t sz)
{
    uint8_t*                    packIn;
    whMessageShe_DecEcbRequest* req = NULL;

    if (c == NULL || in == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_DecEcbRequest*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn     = (uint8_t*)(req + 1);
    req->keyId = keyId;
    req->sz    = sz;
    memcpy(packIn, in, sz);

    /* send enc ecb */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_DEC_ECB,
                                 sizeof(*req) + sz, (uint8_t*)req);
}

int wh_Client_SheDecEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     dataSz;
    uint8_t*                     packOut;
    whMessageShe_DecEcbResponse* resp = NULL;

    if (c == NULL || out == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_DecEcbResponse*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else if (sz < resp->sz) {
            ret = WH_ERROR_BADARGS;
        }
        else {
            memcpy(out, packOut, resp->sz);
        }
    }
    return ret;
}

int wh_Client_SheDecEcb(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint8_t* out, uint32_t sz)
{
    int ret;
    ret = wh_Client_SheDecEcbRequest(c, keyId, in, sz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheDecEcbResponse(c, out, sz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheDecCbcRequest(whClientContext* c, uint8_t keyId, uint8_t* iv,
                               uint32_t ivSz, uint8_t* in, uint32_t sz)
{
    uint8_t*                    packIn;
    whMessageShe_DecCbcRequest* req = NULL;

    if (c == NULL || in == NULL || sz < WH_SHE_KEY_SZ || iv == NULL ||
        ivSz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_DecCbcRequest*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn     = (uint8_t*)(req + 1);
    req->keyId = keyId;
    req->sz    = sz;
    /* set iv */
    memcpy(req->iv, iv, ivSz);
    /* set in */
    memcpy(packIn, in, sz);

    /* send enc ecb */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_DEC_CBC,
                                 sizeof(*req) + sz, (uint8_t*)req);
}

int wh_Client_SheDecCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     dataSz;
    uint8_t*                     packOut;
    whMessageShe_DecCbcResponse* resp = NULL;

    if (c == NULL || out == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_DecCbcResponse*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(resp + 1);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else if (sz < resp->sz) {
            ret = WH_ERROR_BADARGS;
        }
        else {
            memcpy(out, packOut, resp->sz);
        }
    }
    return ret;
}

int wh_Client_SheDecCbc(whClientContext* c, uint8_t keyId, uint8_t* iv,
    uint32_t ivSz, uint8_t* in, uint8_t* out, uint32_t sz)
{
    int ret;
    ret = wh_Client_SheDecCbcRequest(c, keyId, iv, ivSz, in, sz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheDecCbcResponse(c, out, sz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheGenerateMacRequest(whClientContext* c, uint8_t keyId,
                                    uint8_t* in, uint32_t sz)
{
    uint8_t*                    packIn;
    whMessageShe_GenMacRequest* req = NULL;

    if (c == NULL || in == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_GenMacRequest*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn     = (uint8_t*)(req + 1);
    req->keyId = keyId;
    req->sz    = sz;
    /* set in */
    memcpy(packIn, in, sz);

    /* send enc ecb */
    return wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_GEN_MAC,
                                 sizeof(*req) + sz, (uint8_t*)req);
}

int wh_Client_SheGenerateMacResponse(whClientContext* c, uint8_t* out,
                                     uint32_t sz)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     dataSz;
    whMessageShe_GenMacResponse* resp = NULL;

    if (c == NULL || out == NULL || sz < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_GenMacResponse*)wh_CommClient_GetDataPtr(c->comm);

    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else {
            memcpy(out, resp->mac, WH_SHE_KEY_SZ);
        }
    }
    return ret;
}

int wh_Client_SheGenerateMac(whClientContext* c, uint8_t keyId, uint8_t* in,
    uint32_t inSz, uint8_t* out, uint32_t outSz)
{
    int ret;
    ret = wh_Client_SheGenerateMacRequest(c, keyId, in, inSz);
    if (ret == 0) {
        do {
            ret = wh_Client_SheGenerateMacResponse(c, out, outSz);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_SheVerifyMacRequest(whClientContext* c, uint8_t keyId,
                                  uint8_t* message, uint32_t messageLen,
                                  uint8_t* mac, uint32_t macLen)
{
    int       ret;
    uint8_t*  messageIn;
    uint8_t*  macIn;
    whMessageShe_VerifyMacRequest* req = NULL;

    if (c == NULL || message == NULL || messageLen < WH_SHE_KEY_SZ ||
        mac == NULL || macLen < WH_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageShe_VerifyMacRequest*)wh_CommClient_GetDataPtr(c->comm);

    /* message and mac are after fixed sized fields */
    messageIn                     = (uint8_t*)(req + 1);
    macIn                         = messageIn + messageLen;
    req->keyId = keyId;
    req->messageLen = messageLen;
    req->macLen     = WH_SHE_KEY_SZ;
    /* set message */
    memcpy(messageIn, message, messageLen);
    memcpy(macIn, mac, WH_SHE_KEY_SZ);

    /* send verify mac */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_VERIFY_MAC,
                                sizeof(*req) + messageLen + WH_SHE_KEY_SZ,
                                (uint8_t*)req);
    return ret;
}

int wh_Client_SheVerifyMacResponse(whClientContext* c, uint8_t* outStatus)
{
    int                             ret;
    uint16_t                        group;
    uint16_t                        action;
    uint16_t                        dataSz;
    whMessageShe_VerifyMacResponse* resp = NULL;

    if (c == NULL || outStatus == NULL) {
        return WH_ERROR_BADARGS;
    }

    resp = (whMessageShe_VerifyMacResponse*)wh_CommClient_GetDataPtr(c->comm);
    ret  = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)resp);
    if (ret == 0) {
        if (resp->rc != WH_SHE_ERC_NO_ERROR) {
            ret = resp->rc;
        }
        else {
            *outStatus = resp->status;
        }
    }
    return ret;
}

int wh_Client_SheVerifyMac(whClientContext* c, uint8_t keyId, uint8_t* message,
    uint32_t messageLen, uint8_t* mac, uint32_t macLen, uint8_t* outStatus)
{
    int ret;
    ret = wh_Client_SheVerifyMacRequest(c, keyId, message, messageLen, mac,
        macLen);
    if (ret == 0) {
        do {
            ret = wh_Client_SheVerifyMacResponse(c, outStatus);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && WOLFHSM_CFG_ENABLE_CLIENT */
