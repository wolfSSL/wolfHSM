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
 * wolfhsm/wh_common.h
 *
 */

#ifndef WOLFHSM_WH_COMMON_H_
#define WOLFHSM_WH_COMMON_H_

/* TODO: consider using the version without _t */
#include <stdint.h>

/* Device Id to be registered and passed to wolfCrypt functions */
#define WOLFHSM_DEV_ID 0x5748534D  /* "WHSM" */

#define WOLFHSM_DIGEST_STUB 8

/** Resource allocations */
enum WOLFHSM_NUM_ENUM {
    WOLFHSM_NUM_COUNTERS = 8,       /* Number of non-volatile 32-bit counters */
    WOLFHSM_NUM_RAMKEYS = 16,        /* Number of RAM keys */
    WOLFHSM_NUM_NVMOBJECTS = 32,    /* Number of NVM objects in the directory */
    WOLFHSM_NUM_MANIFESTS = 8,      /* Number of compiletime manifests */
    WOLFHSM_KEYCACHE_BUFSIZE = 1200, /* Size in bytes of key cache buffer  */
};


/** Non-volatile counters */

/* HSM Counter identifier type. */
typedef uint16_t whCounterId;


/** Key Management */

/* HSM key identifier type.  Top nibble identifies key type/location */
typedef uint16_t whKeyId;

/* Id Constants */
#define WOLFHSM_KEYID_ERASED 0x0000

/* Key Masks */
#define WOLFHSM_KEYID_MASK   0x00FF
#define WOLFHSM_KEYUSER_MASK 0x0F00
#define WOLFHSM_KEYTYPE_MASK 0xF000

/* Key Flags */
#define WOLFHSM_KEYFLAG_RSA         0x1000
#define WOLFHSM_KEYFLAG_ECC         0x2000
#define WOLFHSM_KEYFLAG_CURVE25519  0x3000
#define WOLFHSM_KEYFLAG_ED25519     0x4000
#define WOLFHSM_KEYFLAG_AES         0x5000
#define WOLFHSM_KEYFLAG_HMAC        0x6000
#define WOLFHSM_KEYFLAG_CMAC        0x7000

/* Key Types */
#define WOLFHSM_KEYTYPE_CRYPTO    0x1000
/* She keys are technically raw keys but a SHE keyId needs */
#define WOLFHSM_KEYTYPE_SHE       0x2000
#define WOLFHSM_KEYTYPE_COUNTER   0x3000

#define MAKE_WOLFHSM_KEYID(_type, _user, _id) \
    (whKeyId)(((_type) & WOLFHSM_KEYTYPE_MASK) | (((_user) & 0xF) << 8) | ((_id) & WOLFHSM_KEYID_MASK))


/** NVM Management */

/* HSM NVM object identifier type. */
typedef uint16_t whNvmId;

/* HSM NVM Size type */
typedef uint16_t whNvmSize;

/* HSM NVM Access type */
typedef uint16_t whNvmAccess;

/* HSM NVM Flags type */
typedef uint16_t whNvmFlags;

/* HSM NVM metadata structure */
enum WOLFHSM_NVM_ENUM {
    WOLFHSM_NVM_LABEL_LEN = 24,
    WOLFHSM_NVM_METADATA_LEN = 32,
    WOLFHSM_NVM_MAX_OBJECT_SIZE = 65535,
};

/* List flags */
#define WOLFHSM_NVM_ACCESS_ANY (0xFFFF)
#define WOLFHSM_NVM_FLAGS_ANY (0xFFFF)

/* User-specified metadata for an NVM object, MUST be a multiple of
 * WHFU_BYTES_PER_UNIT */
typedef struct {
    whNvmId id;             /* Unique identifier */
    whNvmAccess access;     /* Growth */
    whNvmFlags flags;       /* Growth */
    whNvmSize len;          /* Length of data in bytes */
    uint8_t label[WOLFHSM_NVM_LABEL_LEN];
} whNvmMetadata;
/* static_assert(sizeof(whNvmMetadata) == WOLFHSM_NVM_METADATA_LEN) */


/* Custom request shared defs */
#define WH_CUSTOM_CB_NUM_CALLBACKS 8

#ifdef WOLFHSM_SHE_EXTENSION
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
int wh_SheGenerateLoadableKey(uint8_t keyId,
    uint8_t authKeyId, uint32_t count, uint32_t flags, uint8_t* uid,
    uint8_t* key, uint8_t* authKey, uint8_t* messageOne, uint8_t* messageTwo,
    uint8_t* messageThree, uint8_t* messageFour, uint8_t* messageFive);
#endif

#endif /* WOLFHSM_WH_COMMON_H_ */
