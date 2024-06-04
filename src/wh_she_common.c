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
 * src/wh_she_common.c
 *
 */
/* System libraries */

#ifdef WOLFHSM_SHE_EXTENSION

#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

static const uint8_t WOLFHSM_SHE_KEY_UPDATE_ENC_C[] = {0x01, 0x01, 0x53, 0x48, 0x45,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
static const uint8_t WOLFHSM_SHE_KEY_UPDATE_MAC_C[] = {0x01, 0x02, 0x53, 0x48, 0x45,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};



static int wh_AesMp16(uint8_t* in, word32 inSz, uint8_t* out)
{
    int ret;
    int i = 0;
    int j;
    Aes aes[1];
    uint8_t paddedInput[AES_BLOCK_SIZE];
    uint8_t messageZero[WOLFHSM_SHE_KEY_SZ] = {0};
    /* check valid inputs */
    if (in == NULL || inSz == 0 || out == NULL)
        return WH_ERROR_BADARGS;
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    /* do the first block with messageZero as the key */
    if (ret == 0) {
        ret = wc_AesSetKeyDirect(aes, messageZero, AES_BLOCK_SIZE, NULL,
            AES_ENCRYPTION);
    }
    while (ret == 0 && i < (int)inSz) {
        /* copy a block and pad it if we're short */
        if ((int)inSz - i < (int)AES_BLOCK_SIZE) {
            XMEMCPY(paddedInput, in + i, inSz - i);
            XMEMSET(paddedInput + inSz - i, 0, AES_BLOCK_SIZE - (inSz - i));
        }
        else
            XMEMCPY(paddedInput, in + i, AES_BLOCK_SIZE);
        /* encrypt this block */
        ret = wc_AesEncryptDirect(aes, out, paddedInput);
        /* xor with the original message and then the previous block */
        for (j = 0; j < (int)AES_BLOCK_SIZE; j++) {
            out[j] ^= paddedInput[j];
            /* use messageZero as our previous output buffer */
            out[j] ^= messageZero[j];
        }
        /* set the key for the next block */
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, out, AES_BLOCK_SIZE,
                NULL, AES_ENCRYPTION);
        }
        if (ret == 0) {
            /* store previous output in messageZero */
            XMEMCPY(messageZero, out, AES_BLOCK_SIZE);
            /* increment to next block */
            i += AES_BLOCK_SIZE;
        }
    }
    /* free aes for protection */
    wc_AesFree(aes);
    return ret;
}

int wh_SheGenerateLoadableKey(uint8_t keyId,
    uint8_t authKeyId, uint32_t count, uint32_t flags, uint8_t* uid,
    uint8_t* key, uint8_t* authKey, uint8_t* messageOne, uint8_t* messageTwo,
    uint8_t* messageThree, uint8_t* messageFour, uint8_t* messageFive)
{
    int ret = 0;
    uint32_t field;
    uint8_t tmpKey[WOLFHSM_SHE_KEY_SZ];
    uint8_t cmacOutput[AES_BLOCK_SIZE];
    uint8_t kdfInput[WOLFHSM_SHE_KEY_SZ * 2];
    Cmac cmac[1];
    Aes aes[1];
    if (uid == NULL || key == NULL || authKey == NULL || messageOne == NULL ||
        messageTwo == NULL || messageThree == NULL || messageFour == NULL ||
        messageFive == NULL || keyId > WOLFHSM_SHE_PRNG_SEED_ID ||
        authKeyId > WOLFHSM_SHE_PRNG_SEED_ID) {
        return WH_ERROR_BADARGS;
    }
    /* add authKey to kdfInput */
    XMEMCPY(kdfInput, authKey, WOLFHSM_SHE_KEY_SZ);
    /* set UID, key id and authId */
    XMEMCPY(messageOne, uid, WOLFHSM_SHE_UID_SZ);
    messageOne[15] = ((keyId << 4) | (authKeyId));
    /* add WOLFHSM_SHE_KEY_UPDATE_ENC_C to the input */
    XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_UPDATE_ENC_C,
        sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C));
    /* generate K1 */
    ret = wh_AesMp16(kdfInput,
        WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C), tmpKey);
    /* build cleartext M2 */
    if (ret == 0) {
        /* set the counter, flags and key */
        XMEMSET(messageTwo, 0, WOLFHSM_SHE_M2_SZ);
        XMEMCPY(messageTwo + WOLFHSM_SHE_KEY_SZ, key, WOLFHSM_SHE_KEY_SZ);
        *((uint32_t*)messageTwo) = (wh_Utils_htonl(count) << 4);
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    }
    /* encrypt M2 with K1 */
    if (ret == 0) {
        ret = wc_AesSetKey(aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
            AES_ENCRYPTION);
    }
    if (ret == 0) {
        /* copy the key to cmacOutput before it gets encrypted */
        XMEMCPY(cmacOutput, messageTwo + WOLFHSM_SHE_KEY_SZ,
            WOLFHSM_SHE_KEY_SZ);
        ret = wc_AesCbcEncrypt(aes, messageTwo, messageTwo, WOLFHSM_SHE_M2_SZ);
    }
    /* free aes for protection */
    wc_AesFree(aes);
    if (ret == 0) {
        /* add WOLFHSM_SHE_KEY_UPDATE_MAC_C to the input */
        XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_UPDATE_MAC_C,
            sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C));
        /* generate K2 */
        ret = wh_AesMp16(kdfInput,
            WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C), tmpKey);
    }
    /* cmac messageOne and messageTwo using K2 as the cmac key */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, tmpKey, WOLFHSM_SHE_KEY_SZ,
            WC_CMAC_AES, NULL, NULL, INVALID_DEVID);
    }
    /* hash M1 | M2 */
    if (ret == 0)
        ret = wc_CmacUpdate(cmac, messageOne, WOLFHSM_SHE_M1_SZ);
    if (ret == 0)
        ret = wc_CmacUpdate(cmac, messageTwo, WOLFHSM_SHE_M2_SZ);
    /* get the digest */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_CmacFinal(cmac, messageThree, (word32*)&field);
    }
    if (ret == 0) {
        /* copy the ram key to kdfInput */
        XMEMCPY(kdfInput, cmacOutput, WOLFHSM_SHE_KEY_SZ);
        /* add WOLFHSM_SHE_KEY_UPDATE_ENC_C to the input */
        XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_UPDATE_ENC_C,
            sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C));
        /* generate K3 */
        ret = wh_AesMp16(kdfInput,
            WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C), tmpKey);
    }
    /* set K3 as encryption key */
    if (ret == 0)
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
            AES_ENCRYPTION);
    }
    if (ret == 0) {
        XMEMSET(messageFour, 0, WOLFHSM_SHE_M4_SZ);
        /* set counter, pad with 1 bit */
        *((uint32_t*)(messageFour + WOLFHSM_SHE_KEY_SZ)) = (wh_Utils_htonl(count) << 4);
        messageFour[WOLFHSM_SHE_KEY_SZ + 3] |= 0x08;
        /* encrypt the new counter */
        ret = wc_AesEncryptDirect(aes, messageFour + WOLFHSM_SHE_KEY_SZ,
            messageFour + WOLFHSM_SHE_KEY_SZ);
    }
    /* free aes for protection */
    wc_AesFree(aes);
    if (ret == 0) {
        /* set UID, key id and authId */
        XMEMCPY(messageFour, uid, WOLFHSM_SHE_UID_SZ);
        messageFour[15] = ((keyId << 4) | (authKeyId));
        /* add WOLFHSM_SHE_KEY_UPDATE_MAC_C to the input */
        XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_UPDATE_MAC_C,
            sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C));
        /* generate K4 */
        ret = wh_AesMp16(kdfInput,
            WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C), tmpKey);
    }
    /* cmac messageFour using K4 as the cmac key */
    if (ret == 0) {
        field = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(cmac, messageFive, (word32*)&field, messageFour,
            WOLFHSM_SHE_M4_SZ, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL, INVALID_DEVID);
    }
    return ret;
}

#endif /* WOLFHSM_SHE_EXTENSION */

