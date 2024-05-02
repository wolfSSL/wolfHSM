#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

/* Components */
#include "wolfhsm/wh_comm.h"

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"

#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_client.h"

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
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
        (uint8_t*)packet);
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
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
        (uint8_t*)packet);
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
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
        (uint8_t*)packet);
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
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
        (uint8_t*)packet);
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
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
        (uint8_t*)packet);
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
        WOLFHSM_PACKET_STUB_SIZE, (uint8_t*)packet);
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
    ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
        (uint8_t*)packet);
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
