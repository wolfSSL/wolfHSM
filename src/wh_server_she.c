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
 * src/wh_server_she.c
 *
 */



/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */


#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfhsm/wh_server_keystore.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_she_crypto.h"
#include "wolfhsm/wh_server_she.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/** SHE defined constants */
static const uint8_t _SHE_KEY_UPDATE_ENC_C[] = WH_SHE_KEY_UPDATE_ENC_C;
static const uint8_t _SHE_KEY_UPDATE_MAC_C[] = WH_SHE_KEY_UPDATE_MAC_C;
static const uint8_t _SHE_PRNG_KEY_C[]       = WH_SHE_PRNG_KEY_C;
static const uint8_t _SHE_PRNG_SEED_KEY_C[]  = WH_SHE_PRNG_SEED_KEY_C;

enum WH_SHE_SB_STATE {
    WH_SHE_SB_INIT,
    WH_SHE_SB_UPDATE,
    WH_SHE_SB_FINISH,
    WH_SHE_SB_SUCCESS,
    WH_SHE_SB_FAILURE,
};

/** Local Declarations */
static int wh_AesMp16(whServerContext* server, uint8_t* in, word32 inSz,
        uint8_t* out);
static uint16_t hsmShePopAuthId(uint8_t* messageOne);
static uint32_t hsmShePopFlags(uint8_t* messageTwo);
static int hsmSheSetUid(whServerContext* server, whPacket* packet);
static int hsmSheSecureBootInit(whServerContext* server, whPacket* packet,
        uint16_t* size);
static int hsmSheSecureBootUpdate(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheSecureBootFinish(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheGetStatus(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheLoadKey(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheLoadPlainKey(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheExportRamKey(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheRnd(whServerContext* server, whPacket* packet, uint16_t* size);
static int hsmSheExtendSeed(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheEncEcb(whServerContext* server, whPacket* packet,
        uint16_t* size);
static int hsmSheEncCbc(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheDecEcb(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheDecCbc(whServerContext* server, whPacket* packet,
    uint16_t* size);
static int hsmSheGenerateMac(whServerContext* server, whPacket* packet,
    uint16_t* size);


/** Local Implementations */

/* kdf function based on the Miyaguchi-Preneel one-way compression function */
static int wh_AesMp16(whServerContext* server, uint8_t* in, word32 inSz,
        uint8_t* out)
{
    /* check valid inputs */
    if (server == NULL || server->she == NULL)
        return WH_ERROR_BADARGS;
    return wh_She_AesMp16_ex(server->she->sheAes, NULL, server->crypto->devId,
            in, inSz, out);
}

/* AuthID is the 4 rightmost bits of messageOne */
static uint16_t hsmShePopAuthId(uint8_t* messageOne)
{
    return (*(messageOne + WH_SHE_M1_SZ - 1) & 0x0f);
}

/* ID is the second to last 4 bits of messageOne */
static uint16_t hsmShePopId(uint8_t* messageOne)
{
    return ((*(messageOne + WH_SHE_M1_SZ - 1) & 0xf0) >> 4);
}

/* flags are the rightmost 4 bits of byte 3 as it's leftmost bits
 * and leftmost bit of byte 4 as it's rightmost bit */
static uint32_t hsmShePopFlags(uint8_t* messageTwo)
{
    return (((messageTwo[3] & 0x0f) << 4) | ((messageTwo[4] & 0x80) >> 7));
}

static int hsmSheSetUid(whServerContext* server, whPacket* packet)
{
    int ret = 0;
    if (server->she->uidSet == 1)
        ret = WH_SHE_ERC_SEQUENCE_ERROR;
    if (ret == 0) {
        XMEMCPY(server->she->uid, packet->sheSetUidReq.uid,
            sizeof(packet->sheSetUidReq.uid));
        server->she->uidSet = 1;
    }
    return ret;
}

static int hsmSheSecureBootInit(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    uint32_t keySz;
    uint8_t macKey[WH_SHE_KEY_SZ];
    /* if we aren't looking for init return error */
    if (server->she->sbState != WH_SHE_SB_INIT)
        ret = WH_SHE_ERC_SEQUENCE_ERROR;
    if (ret == 0) {
        /* set the expected size */
        server->she->blSize = packet->sheSecureBootInitReq.sz;
        /* check if the boot mac key is empty */
        keySz = sizeof(macKey);
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_BOOT_MAC_KEY_ID), NULL,
            macKey, &keySz);
        /* if the key wasn't found */
        if (ret != 0) {
            /* return ERC_NO_SECURE_BOOT */
            ret = WH_SHE_ERC_NO_SECURE_BOOT;
            /* skip SB process since we have no key */
            server->she->sbState = WH_SHE_SB_SUCCESS;
            server->she->cmacKeyFound = 0;
        }
        else
            server->she->cmacKeyFound = 1;
    }
    /* init the cmac, use const length since the nvm key holds both key and
     * expected digest so meta->len will be too long */
    if (ret == 0) {
        ret = wc_InitCmac_ex(server->she->sheCmac, macKey, WH_SHE_KEY_SZ,
            WC_CMAC_AES, NULL, NULL, server->crypto->devId);
    }
    /* hash 12 zeros */
    if (ret == 0) {
        XMEMSET(macKey, 0, WH_SHE_BOOT_MAC_PREFIX_LEN);
        ret = wc_CmacUpdate(server->she->sheCmac, macKey, WH_SHE_BOOT_MAC_PREFIX_LEN);
    }
    /* TODO is size big or little endian? spec says it is 32 bit */
    /* hash size */
    if (ret == 0) {
        ret = wc_CmacUpdate(server->she->sheCmac, (uint8_t*)&server->she->blSize,
            sizeof(server->she->blSize));
    }
    if (ret == 0) {
        /* advance to the next state */
        server->she->sbState = WH_SHE_SB_UPDATE;
        /* set ERC_NO_ERROR */
        packet->sheSecureBootInitRes.status = WH_SHE_ERC_NO_ERROR;
        *size = WH_PACKET_STUB_SIZE +
            sizeof(packet->sheSecureBootInitRes);
    }
    return ret;
}

static int hsmSheSecureBootUpdate(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    uint8_t* in;
    /* if we aren't looking for update return error */
    if (server->she->sbState != WH_SHE_SB_UPDATE)
        ret = WH_SHE_ERC_SEQUENCE_ERROR;
    if (ret == 0) {
        /* the bootloader chunk is after the fixed fields */
        in = (uint8_t*)(&packet->sheSecureBootUpdateReq + 1);
        /* increment blSizeReceived */
        server->she->blSizeReceived += packet->sheSecureBootUpdateReq.sz;
        /* check that we didn't exceed the expected bootloader size */
        if (server->she->blSizeReceived > server->she->blSize)
            ret = WH_SHE_ERC_SEQUENCE_ERROR;
    }
    /* update with the new input */
    if (ret == 0)
        ret = wc_CmacUpdate(server->she->sheCmac, in, packet->sheSecureBootUpdateReq.sz);
    if (ret == 0) {
        /* advance to the next state if we've cmaced the entire image */
        if (server->she->blSizeReceived == server->she->blSize)
            server->she->sbState = WH_SHE_SB_FINISH;
        /* set ERC_NO_ERROR */
        packet->sheSecureBootUpdateRes.status = WH_SHE_ERC_NO_ERROR;
        *size = WH_PACKET_STUB_SIZE +
            sizeof(packet->sheSecureBootUpdateRes);
    }
    return ret;
}

static int hsmSheSecureBootFinish(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    uint32_t keySz;
    uint32_t field;
    uint8_t cmacOutput[AES_BLOCK_SIZE];
    uint8_t macDigest[WH_SHE_KEY_SZ];
    /* if we aren't looking for finish return error */
    if (server->she->sbState != WH_SHE_SB_FINISH)
        ret = WH_SHE_ERC_SEQUENCE_ERROR;
    /* call final */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_CmacFinal(server->she->sheCmac, cmacOutput, (word32*)&field);
    }
    /* load the cmac to check */
    if (ret == 0) {
        keySz = sizeof(macDigest);
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_BOOT_MAC), NULL, macDigest,
            &keySz);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    }
    if (ret == 0) {
        /* compare and set either success or failure */
        ret = XMEMCMP(cmacOutput, macDigest, field);
        if (ret == 0) {
            server->she->sbState = WH_SHE_SB_SUCCESS;
            packet->sheSecureBootFinishRes.status = WH_SHE_ERC_NO_ERROR;
            *size = WH_PACKET_STUB_SIZE +
                sizeof(packet->sheSecureBootFinishRes);
        }
        else {
            server->she->sbState = WH_SHE_SB_FAILURE;
            ret = WH_SHE_ERC_GENERAL_ERROR;
        }
    }
    return ret;
}

static int hsmSheGetStatus(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    /* TODO do we care about all the sreg fields? */
    packet->sheGetStatusRes.sreg = 0;
    /* SECURE_BOOT */
    if (server->she->cmacKeyFound)
        packet->sheGetStatusRes.sreg |= WH_SHE_SREG_SECURE_BOOT;
    /* BOOT_FINISHED */
    if (server->she->sbState == WH_SHE_SB_SUCCESS ||
        server->she->sbState == WH_SHE_SB_FAILURE) {
        packet->sheGetStatusRes.sreg |= WH_SHE_SREG_BOOT_FINISHED;
    }
    /* BOOT_OK */
    if (server->she->sbState == WH_SHE_SB_SUCCESS)
        packet->sheGetStatusRes.sreg |= WH_SHE_SREG_BOOT_OK;
    /* RND_INIT */
    if (server->she->rndInited == 1)
        packet->sheGetStatusRes.sreg |= WH_SHE_SREG_RND_INIT;
    *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheGetStatusRes);
    return 0;
}

static int hsmSheLoadKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    int keyRet = 0;
    uint32_t keySz;
    uint32_t field;
    uint8_t kdfInput[WH_SHE_KEY_SZ * 2];
    uint8_t cmacOutput[AES_BLOCK_SIZE];
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    whNvmMetadata meta[1];
    uint32_t she_meta_count = 0;
    uint32_t she_meta_flags = 0;
    uint32_t* msg_counter_BE;

    /* read the auth key by AuthID */
    keySz = sizeof(kdfInput);
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id,
        hsmShePopAuthId(packet->sheLoadKeyReq.messageOne)), NULL, kdfInput,
        &keySz);
    /* make K2 using AES-MP(authKey | WH_SHE_KEY_UPDATE_MAC_C) */
    if (ret == 0) {
        /* add WH_SHE_KEY_UPDATE_MAC_C to the input */
        XMEMCPY(kdfInput + keySz, _SHE_KEY_UPDATE_MAC_C,
            sizeof(_SHE_KEY_UPDATE_MAC_C));
        /* do kdf */
        ret = wh_AesMp16(server, kdfInput,
            keySz + sizeof(_SHE_KEY_UPDATE_MAC_C), tmpKey);
    }
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    /* cmac messageOne and messageTwo using K2 as the cmac key */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(server->she->sheCmac, cmacOutput, (word32*)&field,
            (uint8_t*)&packet->sheLoadKeyReq,
            sizeof(packet->sheLoadKeyReq.messageOne) +
            sizeof(packet->sheLoadKeyReq.messageTwo), tmpKey,
            WH_SHE_KEY_SZ, NULL, server->crypto->devId);
    }
    /* compare digest to M3 */
    if (ret == 0 && XMEMCMP(packet->sheLoadKeyReq.messageThree,
        cmacOutput, field) != 0) {
        ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
    }
    /* make K1 using AES-MP(authKey | WH_SHE_KEY_UPDATE_ENC_C) */
    if (ret == 0) {
        /* add WH_SHE_KEY_UPDATE_ENC_C to the input */
        XMEMCPY(kdfInput + keySz, _SHE_KEY_UPDATE_ENC_C,
            sizeof(_SHE_KEY_UPDATE_ENC_C));
        /* do kdf */
        ret = wh_AesMp16(server, kdfInput,
            keySz + sizeof(_SHE_KEY_UPDATE_ENC_C), tmpKey);
    }
    /* decrypt messageTwo */
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, WH_SHE_KEY_SZ,
            NULL, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcDecrypt(server->she->sheAes,
            packet->sheLoadKeyReq.messageTwo,
            packet->sheLoadKeyReq.messageTwo,
            sizeof(packet->sheLoadKeyReq.messageTwo));
    }
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    /* load the target key */
    if (ret == 0) {
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id,
            hsmShePopId(packet->sheLoadKeyReq.messageOne)), meta, kdfInput,
            &keySz);
        /* Extract count and flags from the label, even if it failed */
        wh_She_Label2Meta(meta->label, &she_meta_count, &she_meta_flags);
        /* if the keyslot is empty or write protection is not on continue */
        if (ret == WH_ERROR_NOTFOUND ||
            (she_meta_flags & WH_SHE_FLAG_WRITE_PROTECT) == 0) {
            keyRet = ret;
            ret = 0;
        }
        else
            ret = WH_SHE_ERC_WRITE_PROTECTED;
    }
    /* check UID == 0 */
    if (ret == 0 && wh_Utils_memeqzero(packet->sheLoadKeyReq.messageOne,
        WH_SHE_UID_SZ) == 1) {
        /* check wildcard */
        if ((she_meta_flags & WH_SHE_FLAG_WILDCARD) == 0) {
            ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
        }
    }
    /* compare to UID */
    else if (ret == 0 && XMEMCMP(packet->sheLoadKeyReq.messageOne,
        server->she->uid, sizeof(server->she->uid)) != 0) {
        ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
    }
    /* verify msg_counter_BE is greater than stored value */
    msg_counter_BE = (uint32_t*)packet->sheLoadKeyReq.messageTwo;
    if (ret == 0 &&
        keyRet != WH_ERROR_NOTFOUND &&
        wh_Utils_ntohl(*msg_counter_BE) >> 4 <= she_meta_count) {
        ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
    }
    /* write key with msg_counter_BE */
    if (ret == 0) {
        meta->id = WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id,
            hsmShePopId(packet->sheLoadKeyReq.messageOne));
        she_meta_flags =
            hsmShePopFlags(packet->sheLoadKeyReq.messageTwo);
        she_meta_count = wh_Utils_ntohl(*msg_counter_BE) >> 4;
        /* Update the meta label with new values */
        wh_She_Meta2Label(she_meta_count, she_meta_flags, meta->label);
        meta->len = WH_SHE_KEY_SZ;
        /* cache if ram key, overwrite otherwise */
        if ((meta->id & WH_KEYID_MASK) == WH_SHE_RAM_KEY_ID) {
            ret = hsmCacheKey(server, meta, packet->sheLoadKeyReq.messageTwo
                + WH_SHE_KEY_SZ);
        }
        else {
            ret = wh_Nvm_AddObject(server->nvm, meta, meta->len,
                packet->sheLoadKeyReq.messageTwo + WH_SHE_KEY_SZ);
            /* read the evicted back from nvm */
            if (ret == 0) {
                keySz = WH_SHE_KEY_SZ;
                ret = hsmReadKey(server, meta->id, meta,
                    packet->sheLoadKeyReq.messageTwo + WH_SHE_KEY_SZ,
                    &keySz);
                /* Extract count and flags from the label, even if it failed */
                wh_She_Label2Meta(meta->label, &she_meta_count, &she_meta_flags);
            }
        }
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
    }
    /* generate K3 using the updated key */
    if (ret == 0) {
        /* copy new key to kdfInput */
        XMEMCPY(kdfInput, packet->sheLoadKeyReq.messageTwo +
            WH_SHE_KEY_SZ, WH_SHE_KEY_SZ);
        /* add WH_SHE_KEY_UPDATE_ENC_C to the input */
        XMEMCPY(kdfInput + meta->len, _SHE_KEY_UPDATE_ENC_C,
            sizeof(_SHE_KEY_UPDATE_ENC_C));
        /* do kdf */
        ret = wh_AesMp16(server, kdfInput,
            meta->len + sizeof(_SHE_KEY_UPDATE_ENC_C), tmpKey);
    }
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, WH_SHE_KEY_SZ,
            NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        /* reset messageTwo with the nvm read msg_counter_BE, pad with a 1 bit */
        *msg_counter_BE = wh_Utils_htonl(she_meta_count << 4);
        packet->sheLoadKeyReq.messageTwo[3] |= 0x08;
        /* encrypt the new msg_counter_BE */
        ret = wc_AesEncryptDirect(server->she->sheAes,
            packet->sheLoadKeyRes.messageFour + WH_SHE_KEY_SZ,
            packet->sheLoadKeyReq.messageTwo);
    }
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    /* generate K4 using the updated key */
    if (ret == 0) {
        /* set our UID, ID and AUTHID are already set from messageOne */
        XMEMCPY(packet->sheLoadKeyRes.messageFour, server->she->uid,
            sizeof(server->she->uid));
        /* add WH_SHE_KEY_UPDATE_MAC_C to the input */
        XMEMCPY(kdfInput + meta->len, _SHE_KEY_UPDATE_MAC_C,
            sizeof(_SHE_KEY_UPDATE_MAC_C));
        /* do kdf */
        ret = wh_AesMp16(server, kdfInput,
            meta->len + sizeof(_SHE_KEY_UPDATE_MAC_C), tmpKey);
    }
    /* cmac messageFour using K4 as the cmac key */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(server->she->sheCmac, packet->sheLoadKeyRes.messageFive,
            (word32*)&field, packet->sheLoadKeyRes.messageFour,
            sizeof(packet->sheLoadKeyRes.messageFour), tmpKey,
            WH_SHE_KEY_SZ, NULL, server->crypto->devId);
    }
    if (ret == 0) {
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheLoadKeyRes);
        /* mark if the ram key was loaded */
        if ((meta->id & WH_KEYID_MASK) == WH_SHE_RAM_KEY_ID)
            server->she->ramKeyPlain = 1;
    }
    return ret;
}

static int hsmSheLoadPlainKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    whNvmMetadata meta[1] = {{0}};
    meta->id = WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, WH_SHE_RAM_KEY_ID);
    meta->len = WH_SHE_KEY_SZ;
    /* cache if ram key, overwrite otherwise */
    ret = hsmCacheKey(server, meta, packet->sheLoadPlainKeyReq.key);
    if (ret == 0) {
        *size = WH_PACKET_STUB_SIZE;
        server->she->ramKeyPlain = 1;
    }
    return ret;
}


static int hsmSheExportRamKey(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    uint32_t keySz;
    uint32_t field;
    uint8_t kdfInput[WH_SHE_KEY_SZ * 2];
    uint8_t cmacOutput[AES_BLOCK_SIZE];
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    whNvmMetadata meta[1];
    uint32_t* counter;

    /* check if ram key was loaded by CMD_LOAD_PLAIN_KEY */
    if (server->she->ramKeyPlain == 0)
        ret = WH_SHE_ERC_KEY_INVALID;
    /* read the auth key by AuthID */
    if (ret == 0) {
        keySz = WH_SHE_KEY_SZ;
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_SECRET_KEY_ID), meta,
            kdfInput, &keySz);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    }
    if (ret == 0) {
        /* set UID, key id and authId */
        XMEMCPY(packet->sheExportRamKeyRes.messageOne, server->she->uid,
            sizeof(server->she->uid));
        packet->sheExportRamKeyRes.messageOne[15] =
            ((WH_SHE_RAM_KEY_ID << 4) | (WH_SHE_SECRET_KEY_ID));
        /* add WH_SHE_KEY_UPDATE_ENC_C to the input */
        XMEMCPY(kdfInput + meta->len, _SHE_KEY_UPDATE_ENC_C,
            sizeof(_SHE_KEY_UPDATE_ENC_C));
        /* generate K1 */
        ret = wh_AesMp16(server, kdfInput,
            meta->len + sizeof(_SHE_KEY_UPDATE_ENC_C), tmpKey);
    }
    /* build cleartext M2 */
    if (ret == 0) {
        /* set the counter, flags and ram key */
        XMEMSET(packet->sheExportRamKeyRes.messageTwo, 0,
            sizeof(packet->sheExportRamKeyRes.messageTwo));
        /* set count to 1 */
        counter = (uint32_t*)packet->sheExportRamKeyRes.messageTwo;
        *counter = (wh_Utils_htonl(1) << 4);
        keySz = WH_SHE_KEY_SZ;
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_RAM_KEY_ID), meta,
            packet->sheExportRamKeyRes.messageTwo + WH_SHE_KEY_SZ,
            &keySz);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    }
    /* encrypt M2 with K1 */
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, WH_SHE_KEY_SZ, NULL,
            AES_ENCRYPTION);
    }
    if (ret == 0) {
        /* copy the ram key to cmacOutput before it gets encrypted */
        XMEMCPY(cmacOutput,
            packet->sheExportRamKeyRes.messageTwo + WH_SHE_KEY_SZ,
            WH_SHE_KEY_SZ);
        ret = wc_AesCbcEncrypt(server->she->sheAes,
            packet->sheExportRamKeyRes.messageTwo,
            packet->sheExportRamKeyRes.messageTwo,
            sizeof(packet->sheExportRamKeyRes.messageTwo));
    }
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        /* add WH_SHE_KEY_UPDATE_MAC_C to the input */
        XMEMCPY(kdfInput + meta->len, _SHE_KEY_UPDATE_MAC_C,
            sizeof(_SHE_KEY_UPDATE_MAC_C));
        /* generate K2 */
        ret = wh_AesMp16(server, kdfInput,
            meta->len + sizeof(_SHE_KEY_UPDATE_MAC_C), tmpKey);
    }
    /* cmac messageOne and messageTwo using K2 as the cmac key */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(server->she->sheCmac,
            packet->sheExportRamKeyRes.messageThree, (word32*)&field,
            (uint8_t*)&packet->sheExportRamKeyRes,
            sizeof(packet->sheExportRamKeyRes.messageOne) +
            sizeof(packet->sheExportRamKeyRes.messageTwo), tmpKey,
            WH_SHE_KEY_SZ, NULL, server->crypto->devId);
    }
    if (ret == 0) {
        /* copy the ram key to kdfInput */
        XMEMCPY(kdfInput, cmacOutput, WH_SHE_KEY_SZ);
        /* add WH_SHE_KEY_UPDATE_ENC_C to the input */
        XMEMCPY(kdfInput + WH_SHE_KEY_SZ, _SHE_KEY_UPDATE_ENC_C,
            sizeof(_SHE_KEY_UPDATE_ENC_C));
        /* generate K3 */
        ret = wh_AesMp16(server, kdfInput,
            WH_SHE_KEY_SZ + sizeof(_SHE_KEY_UPDATE_ENC_C), tmpKey);
    }
    /* set K3 as encryption key */
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, WH_SHE_KEY_SZ,
            NULL, AES_ENCRYPTION);
    }
    if (ret == 0) {
        XMEMSET(packet->sheExportRamKeyRes.messageFour, 0,
            sizeof(packet->sheExportRamKeyRes.messageFour));
        /* set counter to 1, pad with 1 bit */
        counter = (uint32_t*)(packet->sheExportRamKeyRes.messageFour +
                WH_SHE_KEY_SZ);
        *counter = (wh_Utils_htonl(1) << 4);
        packet->sheExportRamKeyRes.messageFour[WH_SHE_KEY_SZ + 3] |=
            0x08;
        /* encrypt the new counter */
        ret = wc_AesEncryptDirect(server->she->sheAes,
            packet->sheExportRamKeyRes.messageFour + WH_SHE_KEY_SZ,
            packet->sheExportRamKeyRes.messageFour + WH_SHE_KEY_SZ);
    }
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        /* set UID, key id and authId */
        XMEMCPY(packet->sheExportRamKeyRes.messageFour, server->she->uid,
            sizeof(server->she->uid));
        packet->sheExportRamKeyRes.messageFour[15] =
            ((WH_SHE_RAM_KEY_ID << 4) | (WH_SHE_SECRET_KEY_ID));
        /* add WH_SHE_KEY_UPDATE_MAC_C to the input */
        XMEMCPY(kdfInput + WH_SHE_KEY_SZ, _SHE_KEY_UPDATE_MAC_C,
            sizeof(_SHE_KEY_UPDATE_MAC_C));
        /* generate K4 */
        ret = wh_AesMp16(server, kdfInput,
            WH_SHE_KEY_SZ + sizeof(_SHE_KEY_UPDATE_MAC_C), tmpKey);
    }
    /* cmac messageFour using K4 as the cmac key */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(server->she->sheCmac,
            packet->sheExportRamKeyRes.messageFive, (word32*)&field,
            packet->sheExportRamKeyRes.messageFour,
            sizeof(packet->sheExportRamKeyRes.messageFour), tmpKey,
            WH_SHE_KEY_SZ, NULL, server->crypto->devId);
    }
    if (ret == 0)
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheExportRamKeyRes);
    return ret;
}

static int hsmSheInitRnd(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    uint32_t keySz;
    uint8_t kdfInput[WH_SHE_KEY_SZ * 2];
    uint8_t cmacOutput[AES_BLOCK_SIZE];
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    whNvmMetadata meta[1];
    /* check that init hasn't already been called since startup */
    if (server->she->rndInited == 1)
        ret = WH_SHE_ERC_SEQUENCE_ERROR;
    /* read secret key */
    if (ret == 0) {
        keySz = WH_SHE_KEY_SZ;
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_SECRET_KEY_ID), meta,
            kdfInput, &keySz);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    }
    if (ret == 0) {
        /* add PRNG_SEED_KEY_C */
        XMEMCPY(kdfInput + WH_SHE_KEY_SZ, _SHE_PRNG_SEED_KEY_C,
            sizeof(_SHE_PRNG_SEED_KEY_C));
        /* generate PRNG_SEED_KEY */
        ret = wh_AesMp16(server, kdfInput,
            WH_SHE_KEY_SZ + sizeof(_SHE_PRNG_SEED_KEY_C), tmpKey);
    }
    /* read the current PRNG_SEED, i - 1, to cmacOutput */
    if (ret == 0) {
        keySz = WH_SHE_KEY_SZ;
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_PRNG_SEED_ID), meta,
            cmacOutput, &keySz);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    }
    /* set up aes */
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, WH_SHE_KEY_SZ,
            NULL, AES_ENCRYPTION);
    }
    /* encrypt to the PRNG_SEED, i */
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(server->she->sheAes, cmacOutput, cmacOutput,
            WH_SHE_KEY_SZ);
    }
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    /* save PRNG_SEED, i */
    if (ret == 0) {
        meta->id = WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_PRNG_SEED_ID);
        meta->len = WH_SHE_KEY_SZ;
        ret = wh_Nvm_AddObject(server->nvm, meta, meta->len, cmacOutput);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
    }
    if (ret == 0) {
        /* set PRNG_STATE */
        XMEMCPY(server->she->prngState, cmacOutput, WH_SHE_KEY_SZ);
        /* add PRNG_KEY_C to the kdf input */
        XMEMCPY(kdfInput + WH_SHE_KEY_SZ, _SHE_PRNG_KEY_C,
            sizeof(_SHE_PRNG_KEY_C));
        /* generate PRNG_KEY */
        ret = wh_AesMp16(server, kdfInput,
            WH_SHE_KEY_SZ + sizeof(_SHE_PRNG_KEY_C),
            server->she->prngKey);
    }
    if (ret == 0) {
        /* set init rng to 1 */
        server->she->rndInited = 1;
        /* set ERC_NO_ERROR */
        packet->sheInitRngRes.status = WH_SHE_ERC_NO_ERROR;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheInitRngRes);
    }
    return ret;
}


static int hsmSheRnd(whServerContext* server, whPacket* packet, uint16_t* size)
{
    int ret = 0;
    /* check that rng has been inited */
    if (server->she->rndInited == 0)
        ret = WH_SHE_ERC_RNG_SEED;
    /* set up aes */
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    /* use PRNG_KEY as the encryption key */
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, server->she->prngKey,
            WH_SHE_KEY_SZ, NULL, AES_ENCRYPTION);
    }
    /* encrypt the PRNG_STATE, i - 1 to i */
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(server->she->sheAes, server->she->prngState,
            server->she->prngState, WH_SHE_KEY_SZ);
    }
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        /* copy PRNG_STATE */
        XMEMCPY(packet->sheRndRes.rnd, server->she->prngState,
            WH_SHE_KEY_SZ);
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheRndRes);
    }
    return ret;
}

static int hsmSheExtendSeed(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret = 0;
    uint32_t keySz;
    uint8_t kdfInput[WH_SHE_KEY_SZ * 2];
    whNvmMetadata meta[1];
    /* check that rng has been inited */
    if (server->she->rndInited == 0)
        ret = WH_SHE_ERC_RNG_SEED;
    if (ret == 0) {
        /* set kdfInput to PRNG_STATE */
        XMEMCPY(kdfInput, server->she->prngState, WH_SHE_KEY_SZ);
        /* add the user supplied entropy to kdfInput */
        XMEMCPY(kdfInput + WH_SHE_KEY_SZ,
            packet->sheExtendSeedReq.entropy,
            sizeof(packet->sheExtendSeedReq.entropy));
        /* extend PRNG_STATE */
        ret = wh_AesMp16(server, kdfInput,
            WH_SHE_KEY_SZ + sizeof(packet->sheExtendSeedReq.entropy),
            server->she->prngState);
    }
    /* read the PRNG_SEED into kdfInput */
    if (ret == 0) {
        keySz = WH_SHE_KEY_SZ;
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_PRNG_SEED_ID), meta,
            kdfInput, &keySz);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    }
    if (ret == 0) {
        /* extend PRNG_STATE */
        ret = wh_AesMp16(server, kdfInput,
            WH_SHE_KEY_SZ + sizeof(packet->sheExtendSeedReq.entropy),
            kdfInput);
    }
    /* save PRNG_SEED */
    if (ret == 0) {
        meta->id = WH_MAKE_KEYID(WH_KEYTYPE_SHE,
            server->comm->client_id, WH_SHE_PRNG_SEED_ID);
        meta->len = WH_SHE_KEY_SZ;
        ret = wh_Nvm_AddObject(server->nvm, meta, meta->len, kdfInput);
        if (ret != 0)
            ret = WH_SHE_ERC_KEY_UPDATE_ERROR;
    }
    if (ret == 0) {
        /* set ERC_NO_ERROR */
        packet->sheExtendSeedRes.status = WH_SHE_ERC_NO_ERROR;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheExtendSeedRes);
    }
    return ret;
}

static int hsmSheEncEcb(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    uint32_t field;
    uint32_t keySz;
    uint8_t* in;
    uint8_t* out;
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    /* in and out are after the fixed sized fields */
    in = (uint8_t*)(&packet->sheEncEcbReq + 1);
    out = (uint8_t*)(&packet->sheEncEcbRes + 1);
    /* load the key */
    keySz = WH_SHE_KEY_SZ;
    field = packet->sheEncEcbReq.sz;
    /* only process a multiple of block size */
    field -= (field % AES_BLOCK_SIZE);
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, packet->sheEncEcbReq.keyId), NULL,
        tmpKey, &keySz);
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    if (ret == 0)
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, keySz, NULL, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesEcbEncrypt(server->she->sheAes, out, in, field);
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        packet->sheEncEcbRes.sz = field;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheEncEcbRes) + field;
    }
    return ret;
}

static int hsmSheEncCbc(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    uint32_t field;
    uint32_t keySz;
    uint8_t* in;
    uint8_t* out;
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    /* in and out are after the fixed sized fields */
    in = (uint8_t*)(&packet->sheEncCbcReq + 1);
    out = (uint8_t*)(&packet->sheEncCbcRes + 1);
    /* load the key */
    keySz = WH_SHE_KEY_SZ;
    field = packet->sheEncCbcReq.sz;
    /* only process a multiple of block size */
    field -= (field % AES_BLOCK_SIZE);
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, packet->sheEncCbcReq.keyId), NULL,
        tmpKey, &keySz);
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, keySz, packet->sheEncCbcReq.iv,
            AES_ENCRYPTION);
    }
    if (ret == 0)
        ret = wc_AesCbcEncrypt(server->she->sheAes, out, in, field);
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        packet->sheEncEcbRes.sz = field;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheEncCbcRes) + field;
    }
    return ret;
}

static int hsmSheDecEcb(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    uint32_t field;
    uint32_t keySz;
    uint8_t* in;
    uint8_t* out;
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    /* in and out are after the fixed sized fields */
    in = (uint8_t*)(&packet->sheDecEcbReq + 1);
    out = (uint8_t*)(&packet->sheDecEcbRes + 1);
    /* load the key */
    keySz = WH_SHE_KEY_SZ;
    field = packet->sheDecEcbReq.sz;
    /* only process a multiple of block size */
    field -= (field % AES_BLOCK_SIZE);
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, packet->sheDecEcbReq.keyId), NULL,
        tmpKey, &keySz);
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    if (ret == 0)
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, keySz, NULL, AES_DECRYPTION);
    if (ret == 0)
        ret = wc_AesEcbDecrypt(server->she->sheAes, out, in, field);
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        packet->sheDecEcbRes.sz = field;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheDecEcbRes) + field;
    }
    return ret;
}

static int hsmSheDecCbc(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    uint32_t field;
    uint32_t keySz;
    uint8_t* in;
    uint8_t* out;
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    /* in and out are after the fixed sized fields */
    in = (uint8_t*)(&packet->sheDecCbcReq + 1);
    out = (uint8_t*)(&packet->sheDecCbcRes + 1);
    /* load the key */
    keySz = WH_SHE_KEY_SZ;
    field = packet->sheDecCbcReq.sz;
    /* only process a multiple of block size */
    field -= (field % AES_BLOCK_SIZE);
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, packet->sheDecCbcReq.keyId), NULL,
        tmpKey, &keySz);
    if (ret == 0)
        ret = wc_AesInit(server->she->sheAes, NULL, server->crypto->devId);
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    if (ret == 0) {
        ret = wc_AesSetKey(server->she->sheAes, tmpKey, keySz, packet->sheDecCbcReq.iv,
            AES_DECRYPTION);
    }
    if (ret == 0)
        ret = wc_AesCbcDecrypt(server->she->sheAes, out, in, field);
    /* free aes for protection */
    wc_AesFree(server->she->sheAes);
    if (ret == 0) {
        packet->sheDecCbcRes.sz = field;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheDecCbcRes) + field;
    }
    return ret;
}

static int hsmSheGenerateMac(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    uint32_t field = AES_BLOCK_SIZE;
    uint32_t keySz;
    uint8_t* in;
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    /* in and out are after the fixed sized fields */
    in = (uint8_t*)(&packet->sheGenMacReq + 1);
    /* load the key */
    keySz = WH_SHE_KEY_SZ;
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, packet->sheGenMacReq.keyId), NULL, tmpKey,
        &keySz);
    /* hash the message */
    if (ret == 0) {
        ret = wc_AesCmacGenerate_ex(server->she->sheCmac, packet->sheGenMacRes.mac, (word32*)&field,
            in, packet->sheGenMacReq.sz, tmpKey, WH_SHE_KEY_SZ, NULL,
            server->crypto->devId);
    }
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    if (ret == 0)
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheGenMacRes);
    return ret;
}

static int hsmSheVerifyMac(whServerContext* server, whPacket* packet,
    uint16_t* size)
{
    int ret;
    uint32_t keySz;
    uint8_t* message;
    uint8_t* mac;
    uint8_t tmpKey[WH_SHE_KEY_SZ];
    /* in and mac are after the fixed sized fields */
    message = (uint8_t*)(&packet->sheVerifyMacReq + 1);
    mac = message + packet->sheVerifyMacReq.messageLen;
    /* load the key */
    keySz = WH_SHE_KEY_SZ;
    ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_SHE,
        server->comm->client_id, packet->sheVerifyMacReq.keyId), NULL, tmpKey,
        &keySz);
    /* verify the mac */
    if (ret == 0) {
        ret = wc_AesCmacVerify_ex(server->she->sheCmac, mac, packet->sheVerifyMacReq.macLen,
            message, packet->sheVerifyMacReq.messageLen, tmpKey, keySz, NULL,
            server->crypto->devId);
        /* only evaluate if key was found */
        if (ret == 0)
            packet->sheVerifyMacRes.status = 0;
        else
            packet->sheVerifyMacRes.status = 1;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->sheVerifyMacRes);
    }
    else
        ret = WH_SHE_ERC_KEY_NOT_AVAILABLE;
    return ret;
}

int wh_Server_HandleSheRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    whPacket* packet = (whPacket*)data;

    if (server == NULL || data == NULL || size == NULL)
        return WH_ERROR_BADARGS;

    /* TODO does SHE specify what this error should be? */
    /* if we haven't secure booted, only allow secure boot requests */
    if ((server->she->sbState != WH_SHE_SB_SUCCESS &&
        (action != WH_SHE_SECURE_BOOT_INIT &&
        action != WH_SHE_SECURE_BOOT_UPDATE &&
        action != WH_SHE_SECURE_BOOT_FINISH &&
        action != WH_SHE_GET_STATUS &&
        action != WH_SHE_SET_UID)) ||
        (action != WH_SHE_SET_UID && server->she->uidSet == 0)) {
        packet->rc = WH_SHE_ERC_SEQUENCE_ERROR;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->rc);
        return 0;
    }

    switch (action)
    {
    case WH_SHE_SET_UID:
        ret = hsmSheSetUid(server, packet);
        break;
    case WH_SHE_SECURE_BOOT_INIT:
        ret = hsmSheSecureBootInit(server, packet, size);
        break;
    case WH_SHE_SECURE_BOOT_UPDATE:
        ret = hsmSheSecureBootUpdate(server, packet, size);
        break;
    case WH_SHE_SECURE_BOOT_FINISH:
        ret = hsmSheSecureBootFinish(server, packet, size);
        break;
    case WH_SHE_GET_STATUS:
        ret = hsmSheGetStatus(server, packet, size);
        break;
    case WH_SHE_LOAD_KEY:
        ret = hsmSheLoadKey(server, packet, size);
        break;
    case WH_SHE_LOAD_PLAIN_KEY:
        ret = hsmSheLoadPlainKey(server, packet, size);
        break;
    case WH_SHE_EXPORT_RAM_KEY:
        ret = hsmSheExportRamKey(server, packet, size);
        break;
    case WH_SHE_INIT_RND:
        ret = hsmSheInitRnd(server, packet, size);
        break;
    case WH_SHE_RND:
        ret = hsmSheRnd(server, packet, size);
        break;
    case WH_SHE_EXTEND_SEED:
        ret = hsmSheExtendSeed(server, packet, size);
        break;
    case WH_SHE_ENC_ECB:
        ret = hsmSheEncEcb(server, packet, size);
        break;
    case WH_SHE_ENC_CBC:
        ret = hsmSheEncCbc(server, packet, size);
        break;
    case WH_SHE_DEC_ECB:
        ret = hsmSheDecEcb(server, packet, size);
        break;
    case WH_SHE_DEC_CBC:
        ret = hsmSheDecCbc(server, packet, size);
        break;
    case WH_SHE_GEN_MAC:
        ret = hsmSheGenerateMac(server, packet, size);
        break;
    case WH_SHE_VERIFY_MAC:
        ret = hsmSheVerifyMac(server, packet, size);
        break;
    default:
        ret = WH_ERROR_BADARGS;
        break;
    }
    /* if a handler didn't set a specific error, set general error */
    if (ret != 0) {
        if (ret != WH_SHE_ERC_SEQUENCE_ERROR &&
        ret != WH_SHE_ERC_KEY_NOT_AVAILABLE && ret != WH_SHE_ERC_KEY_INVALID &&
        ret != WH_SHE_ERC_KEY_EMPTY && ret != WH_SHE_ERC_NO_SECURE_BOOT &&
        ret != WH_SHE_ERC_WRITE_PROTECTED && ret != WH_SHE_ERC_KEY_UPDATE_ERROR
        && ret != WH_SHE_ERC_RNG_SEED && ret != WH_SHE_ERC_NO_DEBUGGING &&
        ret != WH_SHE_ERC_BUSY && ret != WH_SHE_ERC_MEMORY_FAILURE) {
            ret = WH_SHE_ERC_GENERAL_ERROR;
        }
        packet->rc = ret;
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->rc);
    }
    /* reset our SHE state */
    /* TODO is it safe to call wc_InitCmac over and over or do we need to call final first? */
    if ((action == WH_SHE_SECURE_BOOT_INIT ||
        action == WH_SHE_SECURE_BOOT_UPDATE ||
        action == WH_SHE_SECURE_BOOT_FINISH) && ret != 0 &&
        ret != WH_SHE_ERC_NO_SECURE_BOOT) {
        server->she->sbState = WH_SHE_SB_INIT;
        server->she->blSize = 0;
        server->she->blSizeReceived = 0;
        server->she->cmacKeyFound = 0;
    }
    packet->rc = ret;
    return 0;
}

#else /* WOLFHSM_CFG_NO_CRYPTO */
int wh_Server_HandleSheRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    /* No crypto build, so always return bad args */
    (void)server;
    (void)action;
    (void)data;
    (void)size;
    return WH_ERROR_BADARGS;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_CFG_SHE_EXTENSION*/
