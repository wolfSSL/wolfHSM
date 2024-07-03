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

#ifdef WOLFHSM_SHE_EXTENSION

#include <stdint.h>
#include <stdlib.h>  /* For NULL */
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

#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_client.h"

#include "wolfhsm/wh_client_she.h"

int wh_Client_ShePreProgramKey(whClientContext* c, whNvmId keyId,
    whNvmFlags flags, uint8_t* key, whNvmSize keySz)
{
    int ret;
    int32_t outRc;
    uint8_t label[WOLFHSM_NVM_LABEL_LEN] = { 0 };
    whSheMetadata* she_meta = (whSheMetadata*)label;

    she_meta->flags = flags;
    ret = wh_Client_NvmAddObject(c, MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_SHE,
        c->comm->client_id, keyId), 0, 0, sizeof(label), label, keySz, key, (int32_t*)&outRc);
    if (ret == 0)
        ret = outRc;
    return ret;
}

int wh_Client_SheSetUidRequest(whClientContext* c, uint8_t* uid, uint32_t uidSz)
{
    int ret;
    whPacket* packet;
    if (c == NULL || uid == NULL || uidSz < WOLFHSM_SHE_UID_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* set uid */
    memcpy(packet->sheSetUidReq.uid, uid, sizeof(packet->sheSetUidReq.uid));
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_SET_UID,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheSetUidReq),
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheSetUidResponse(whClientContext* c)
{
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    int ret;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0)
        ret = packet->rc;
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
    int ret;
    uint32_t bootloaderSent = 0;
    uint32_t justSent = 0;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* in;
    whPacket* packet;
    if (c == NULL || bootloader == NULL || bootloaderLen == 0)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after the size argument */
    in = (uint8_t*)(&packet->sheSecureBootUpdateReq + 1);
    /* send init sub command */
    packet->sheSecureBootInitReq.sz = bootloaderLen;
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
        WH_SHE_SECURE_BOOT_INIT, WOLFHSM_PACKET_STUB_SIZE +
        sizeof(packet->sheSecureBootInitReq), (uint8_t*)packet);
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
    /* send update sub command until we've sent the entire bootloader */
    while (ret == 0 && bootloaderSent < bootloaderLen) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            return packet->rc;
        /* send what's left in the size available */
        packet->sheSecureBootUpdateReq.sz = ((bootloaderLen - bootloaderSent)
            % (WH_COMM_DATA_LEN - sizeof(packet->sheSecureBootUpdateReq)));
        justSent = packet->sheSecureBootUpdateReq.sz;
        memcpy(in, bootloader + bootloaderSent,
            packet->sheSecureBootUpdateReq.sz);
        ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
            WH_SHE_SECURE_BOOT_UPDATE,
            WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheSecureBootUpdateReq) +
            packet->sheSecureBootUpdateReq.sz,
            (uint8_t*)packet);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }
        /* increment sent  */
        if (ret == 0)
            bootloaderSent += justSent;
    }
    /* send finish sub command */
    if (ret == 0) {
        ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
            WH_SHE_SECURE_BOOT_FINISH, WOLFHSM_PACKET_STUB_SIZE,
            (uint8_t*)packet);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
                (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0)
        ret = packet->rc;
    return ret;
}

int wh_Client_SheGetStatusRequest(whClientContext* c)
{
    int ret;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* send status request */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
        WH_SHE_GET_STATUS, WOLFHSM_PACKET_STUB_SIZE,
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheGetStatusResponse(whClientContext* c, uint8_t* sreg)
{
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    int ret;
    whPacket* packet;
    if (c == NULL || sreg == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    /* return error or set sreg */
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else
            *sreg = packet->sheGetStatusRes.sreg;
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
    int ret;
    whPacket* packet;
    if (c == NULL || messageOne == NULL || messageTwo == NULL ||
        messageThree == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* copy in messages 1-3 */
    memcpy(packet->sheLoadKeyReq.messageOne, messageOne,
        sizeof(packet->sheLoadKeyReq.messageOne));
    memcpy(packet->sheLoadKeyReq.messageTwo, messageTwo,
        sizeof(packet->sheLoadKeyReq.messageTwo));
    memcpy(packet->sheLoadKeyReq.messageThree, messageThree,
        sizeof(packet->sheLoadKeyReq.messageThree));
    /* send load key req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
        WH_SHE_LOAD_KEY, WOLFHSM_PACKET_STUB_SIZE +
        sizeof(packet->sheLoadKeyReq), (uint8_t*)packet);
    return ret;
}

int wh_Client_SheLoadKeyResponse(whClientContext* c, uint8_t* messageFour,
    uint8_t* messageFive)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL || messageFour == NULL || messageFive == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else {
            /* copy out message 4 and 5 */
            memcpy(messageFour, packet->sheLoadKeyRes.messageFour,
                sizeof(packet->sheLoadKeyRes.messageFour));
            memcpy(messageFive, packet->sheLoadKeyRes.messageFive,
                sizeof(packet->sheLoadKeyRes.messageFive));
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
    int ret;
    whPacket* packet;
    if (c == NULL || key == NULL || keySz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* copy the key */
    memcpy(packet->sheLoadPlainKeyReq.key, key, WOLFHSM_SHE_KEY_SZ);
    /* send load key req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE,
        WH_SHE_LOAD_PLAIN_KEY, WOLFHSM_PACKET_STUB_SIZE +
        sizeof(packet->sheLoadPlainKeyReq), (uint8_t*)packet);
    return ret;
}

int wh_Client_SheLoadPlainKeyResponse(whClientContext* c)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0)
        ret = packet->rc;
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
    int ret;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* send export ram key req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_EXPORT_RAM_KEY,
        WOLFHSM_PACKET_STUB_SIZE, (uint8_t*)packet);
    return ret;
}

int wh_Client_SheExportRamKeyResponse(whClientContext* c, uint8_t* messageOne,
    uint8_t* messageTwo, uint8_t* messageThree, uint8_t* messageFour,
    uint8_t* messageFive)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL || messageOne == NULL || messageTwo == NULL ||
        messageThree == NULL || messageFour == NULL || messageFive == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else {
            memcpy(messageOne, packet->sheExportRamKeyRes.messageOne,
                sizeof(packet->sheExportRamKeyRes.messageOne));
            memcpy(messageTwo, packet->sheExportRamKeyRes.messageTwo,
                sizeof(packet->sheExportRamKeyRes.messageTwo));
            memcpy(messageThree, packet->sheExportRamKeyRes.messageThree,
                sizeof(packet->sheExportRamKeyRes.messageThree));
            memcpy(messageFour, packet->sheExportRamKeyRes.messageFour,
                sizeof(packet->sheExportRamKeyRes.messageFour));
            memcpy(messageFive, packet->sheExportRamKeyRes.messageFive,
                sizeof(packet->sheExportRamKeyRes.messageFive));
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
    int ret;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* send init rnd req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_INIT_RND,
        WOLFHSM_PACKET_STUB_SIZE, (uint8_t*)packet);
    return ret;
}

int wh_Client_SheInitRndResponse(whClientContext* c)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        ret = packet->rc;
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
    int ret;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* send rnd req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_RND,
        WOLFHSM_PACKET_STUB_SIZE, (uint8_t*)packet);
    return ret;
}

int wh_Client_SheRndResponse(whClientContext* c, uint8_t* out, uint32_t* outSz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL || out == NULL || outSz == NULL ||*outSz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else {
            memcpy(out, packet->sheRndRes.rnd, sizeof(packet->sheRndRes.rnd));
            *outSz = sizeof(packet->sheRndRes.rnd);
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
    whPacket* packet;
    if (c == NULL || entropy == NULL || entropySz != WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* set entropy */
    memcpy(packet->sheExtendSeedReq.entropy, entropy,
        sizeof(packet->sheExtendSeedReq.entropy));
    /* send init rng req */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_EXTEND_SEED,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheExtendSeedReq),
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheExtendSeedResponse(whClientContext* c)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0)
        ret = packet->rc;
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
    int ret;
    uint8_t* packIn;
    whPacket* packet;
    if (c == NULL || in == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn = (uint8_t*)(&packet->sheEncEcbReq + 1);
    packet->sheEncEcbReq.keyId = keyId;
    packet->sheEncEcbReq.sz = sz;
    /* set in */
    memcpy(packIn, in, sz);
    /* send enc ecb */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_ENC_ECB,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheEncEcbReq) + sz,
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheEncEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* packOut;
    whPacket* packet;
    if (c == NULL || out == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(&packet->sheEncEcbRes + 1);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else if (sz < packet->sheEncEcbRes.sz)
            ret = WH_ERROR_BADARGS;
        else
            memcpy(out, packOut, packet->sheEncEcbRes.sz);
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
    int ret;
    uint8_t* packIn;
    whPacket* packet;
    if (c == NULL || in == NULL || sz < WOLFHSM_SHE_KEY_SZ || iv == NULL ||
        ivSz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn = (uint8_t*)(&packet->sheEncCbcReq + 1);
    packet->sheEncCbcReq.keyId = keyId;
    packet->sheEncCbcReq.sz = sz;
    /* set iv */
    memcpy(packet->sheEncCbcReq.iv, iv, ivSz);
    /* set in */
    memcpy(packIn, in, sz);
    /* send enc ecb */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_ENC_CBC,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheEncCbcReq) + sz,
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheEncCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* packOut;
    whPacket* packet;
    if (c == NULL || out == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(&packet->sheEncCbcRes + 1);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else if (sz < packet->sheEncCbcRes.sz)
            ret = WH_ERROR_BADARGS;
        else
            memcpy(out, packOut, packet->sheEncCbcRes.sz);
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
    int ret;
    uint8_t* packIn;
    whPacket* packet;
    if (c == NULL || in == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn = (uint8_t*)(&packet->sheDecEcbReq + 1);
    packet->sheDecEcbReq.keyId = keyId;
    packet->sheDecEcbReq.sz = sz;
    /* set in */
    memcpy(packIn, in, sz);
    /* send enc ecb */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_DEC_ECB,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheDecEcbReq) + sz,
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheDecEcbResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* packOut;
    whPacket* packet;
    if (c == NULL || out == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(&packet->sheDecEcbRes + 1);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else if (sz < packet->sheDecEcbRes.sz)
            ret = WH_ERROR_BADARGS;
        else
            memcpy(out, packOut, packet->sheDecEcbRes.sz);
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
    int ret;
    uint8_t* packIn;
    whPacket* packet;
    if (c == NULL || in == NULL || sz < WOLFHSM_SHE_KEY_SZ || iv == NULL ||
        ivSz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn = (uint8_t*)(&packet->sheDecCbcReq + 1);
    packet->sheDecCbcReq.keyId = keyId;
    packet->sheDecCbcReq.sz = sz;
    /* set iv */
    memcpy(packet->sheDecCbcReq.iv, iv, ivSz);
    /* set in */
    memcpy(packIn, in, sz);
    /* send enc ecb */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_DEC_CBC,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheDecCbcReq) + sz,
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheDecCbcResponse(whClientContext* c, uint8_t* out, uint32_t sz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* packOut;
    whPacket* packet;
    if (c == NULL || out == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* out is after fixed sized fields */
    packOut = (uint8_t*)(&packet->sheDecCbcRes + 1);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else if (sz < packet->sheDecCbcRes.sz)
            ret = WH_ERROR_BADARGS;
        else
            memcpy(out, packOut, packet->sheDecCbcRes.sz);
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
    int ret;
    uint8_t* packIn;
    whPacket* packet;
    if (c == NULL || in == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* in is after fixed sized fields */
    packIn = (uint8_t*)(&packet->sheGenMacReq + 1);
    packet->sheGenMacReq.keyId = keyId;
    packet->sheGenMacReq.sz = sz;
    /* set in */
    memcpy(packIn, in, sz);
    /* send enc ecb */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_GEN_MAC,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheGenMacReq) + sz,
        (uint8_t*)packet);
    return ret;
}

int wh_Client_SheGenerateMacResponse(whClientContext* c, uint8_t* out,
    uint32_t sz)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL || out == NULL || sz < WOLFHSM_SHE_KEY_SZ)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else
            memcpy(out, packet->sheGenMacRes.mac, WOLFHSM_SHE_KEY_SZ);
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
    uint8_t* message, uint32_t messageLen, uint8_t* mac, uint32_t macLen)
{
    int ret;
    uint8_t* messageIn;
    uint8_t* macIn;
    whPacket* packet;
    if (c == NULL || message == NULL || messageLen < WOLFHSM_SHE_KEY_SZ ||
        mac == NULL || macLen < WOLFHSM_SHE_KEY_SZ) {
        return WH_ERROR_BADARGS;
    }
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    /* message and mac are after fixed sized fields */
    messageIn = (uint8_t*)(&packet->sheVerifyMacReq + 1);
    macIn = messageIn + messageLen;
    packet->sheVerifyMacReq.keyId = keyId;
    packet->sheVerifyMacReq.messageLen = messageLen;
    packet->sheVerifyMacReq.macLen = WOLFHSM_SHE_KEY_SZ;
    /* set message */
    memcpy(messageIn, message, messageLen);
    memcpy(macIn, mac, WOLFHSM_SHE_KEY_SZ);
    /* send verify mac */
    ret = wh_Client_SendRequest(c, WH_MESSAGE_GROUP_SHE, WH_SHE_VERIFY_MAC,
        WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->sheVerifyMacReq) + messageLen
        + WOLFHSM_SHE_KEY_SZ, (uint8_t*)packet);
    return ret;
}

int wh_Client_SheVerifyMacResponse(whClientContext* c, uint8_t* outStatus)
{
    int ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    whPacket* packet;
    if (c == NULL || outStatus == NULL)
        return WH_ERROR_BADARGS;
    packet = (whPacket*)wh_CommClient_GetDataPtr(c->comm);
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz, (uint8_t*)packet);
    if (ret == 0) {
        if (packet->rc != WOLFHSM_SHE_ERC_NO_ERROR)
            ret = packet->rc;
        else
            *outStatus = packet->sheVerifyMacRes.status;
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

#endif /* WOLFHSM_SHE_EXTENSION */
