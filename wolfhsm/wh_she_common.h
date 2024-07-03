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
 * wolfhsm/wh_she_common.h
 *
 */

#ifndef WOLFHSM_WH_SHE_COMMON_H_
#define WOLFHSM_WH_SHE_COMMON_H_

#include <stdint.h>

#define WOLFHSM_SHE_SECRET_KEY_ID 0
#define WOLFHSM_SHE_MASTER_ECU_KEY_ID 1
#define WOLFHSM_SHE_BOOT_MAC_KEY_ID 2
#define WOLFHSM_SHE_BOOT_MAC 3
#define WOLFHSM_SHE_RAM_KEY_ID 14
#define WOLFHSM_SHE_PRNG_SEED_ID 15

#define WOLFHSM_SHE_KEY_SZ 16
#define WOLFHSM_SHE_UID_SZ 15

#define WOLFHSM_SHE_BOOT_MAC_PREFIX_LEN 12

#define WOLFHSM_SHE_M1_SZ 16
#define WOLFHSM_SHE_M2_SZ 32
#define WOLFHSM_SHE_M3_SZ WOLFHSM_SHE_M1_SZ
#define WOLFHSM_SHE_M4_SZ WOLFHSM_SHE_M2_SZ
#define WOLFHSM_SHE_M5_SZ WOLFHSM_SHE_M1_SZ

/* M1 is 15 bytes of UID, 4 bits of KID, 4 bits of AID */
#define WH_SHE_M1_UID_OFFSET 0
#define WH_SHE_M1_KID_OFFSET 15
#define WH_SHE_M1_KID_SHIFT 4
#define WH_SHE_M1_AID_SHIFT 0

/* M2 is 28 bits of BE counter, 4 bits of flags, 96 bits of 0's, 16 bytes Key */
#define WH_SHE_M2_COUNT_SHIFT 4
#define WH_SHE_M2_FLAGS_SHIFT 0
#define WH_SHE_M2_KEY_OFFSET 16

/* M4 is 15 bytes of UID, 4 bits of KID, 4 bits of AID, like M1.
 * Followed by 16 bytes of the counter encrypted with K3
 */
#define WH_SHE_M4_UID_OFFSET 0
#define WH_SHE_M4_KID_OFFSET 15
#define WH_SHE_M4_KID_SHIFT 4
#define WH_SHE_M4_AID_SHIFT 0
#define WH_SHE_M4_COUNT_OFFSET 16
#define WH_SHE_M4_COUNT_SHIFT 4
#define WH_SHE_M4_COUNT_PAD 0x8

/* sreg flags */
#define WOLFHSM_SHE_SREG_BUSY (1 << 0)
#define WOLFHSM_SHE_SREG_SECURE_BOOT (1 << 1)
#define WOLFHSM_SHE_SREG_BOOT_INIT (1 << 2)
#define WOLFHSM_SHE_SREG_BOOT_FINISHED (1 << 3)
#define WOLFHSM_SHE_SREG_BOOT_OK (1 << 4)
#define WOLFHSM_SHE_SREG_RND_INIT (1 << 5)
#define WOLFHSM_SHE_SREG_EXT_DEBUGGER (1 << 6)
#define WOLFHSM_SHE_SREG_INT_DEBUGGER (1 << 7)
/* key flags */
#define WOLFHSM_SHE_FLAG_WRITE_PROTECT (1 << 0)
#define WOLFHSM_SHE_FLAG_BOOT_PROTECT (1 << 1)
#define WOLFHSM_SHE_FLAG_DEBUGGER_PROTECTION (1 << 2)
#define WOLFHSM_SHE_FLAG_USAGE (1 << 3)
#define WOLFHSM_SHE_FLAG_WILDCARD (1 << 4)
#define WOLFHSM_SHE_M1_SZ 16
#define WOLFHSM_SHE_M2_SZ 32
#define WOLFHSM_SHE_M3_SZ WOLFHSM_SHE_M1_SZ
#define WOLFHSM_SHE_M4_SZ WOLFHSM_SHE_M2_SZ
#define WOLFHSM_SHE_M5_SZ WOLFHSM_SHE_M1_SZ

#ifdef WOLFHSM_SHE_EXTENSION
#ifndef WOLFHSM_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"

typedef struct {
    uint32_t count;
    uint32_t flags;
} whSheMetadata;

int wh_AesMp16_ex(Aes* aes, void* heap, int devid,
        uint8_t* in, word32 inSz, uint8_t* out);

int wh_SheGenerateLoadableKey(uint8_t keyId,
    uint8_t authKeyId, uint32_t count, uint32_t flags, uint8_t* uid,
    uint8_t* key, uint8_t* authKey, uint8_t* messageOne, uint8_t* messageTwo,
    uint8_t* messageThree, uint8_t* messageFour, uint8_t* messageFive);

#endif /* !WOLFHSM_NO_CRYPTO*/
#endif /* WOLFHSM_SHE_EXTENSION */

#endif /* WOLFHSM_WH_SHE_COMMON_H_ */
