
/* common.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifndef WOLFHSM_COMMON_H
#define WOLFHSM_COMMON_H
#include <stdint.h>
#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfhsm/wh_common.h"

#if (defined(__IAR_SYSTEMS_ICC__) && (__IAR_SYSTEMS_ICC__ > 8)) || \
                                                    defined(__GNUC__)
    #define WOLFHSM_PACK __attribute__ ((packed))
#else
    #define WOLFSSL_PACK
#endif

#ifdef __cplusplus
    extern "C" {
#endif
#define WOLFHSM_MAGIC       0x574F4C46 /* WOLF */
#define WOLFHSM_MAGIC_TRAIL 0x48534D5F /* HSM_ */
#define WOLFHSM_DIGEST_STUB 8
#ifndef WOLFHSM_SHE_EXTENSION
/* 2 for id, 4 for flags, 2 for len, 24 for label and 8 for confDigest */
#define WOLFHSM_NVM_METADATA_LEN 40
#else
/* + 4 for count */
#define WOLFHSM_NVM_METADATA_LEN 44
#endif
/* TODO should this be overwritable by hal? */
#ifndef WOLFHSM_HWIF_SLOT_COUNT
    #define WOLFHSM_HWIF_SLOT_COUNT 1
#endif
#define WOLFHSM_KEYSIZE 4096
#define WOLFHSM_KEYSLOT_COUNT 11
#define WOLFHSM_CACHE_COUNT 3
#define WOLFHSM_PART_COUNTER_SZ 4
#define WOLFHSM_COUNTER_MAX 0xFFFFFFFF
#define WOLFHSM_HEADER_SIZE (WOLFHSM_PART_COUNTER_SZ + WOLFHSM_NVM_METADATA_LEN * WOLFHSM_KEYSLOT_COUNT)
#define WOLFHSM_PARTITION_SIZE (WOLFHSM_KEYSIZE * WOLFHSM_KEYSLOT_COUNT + WOLFHSM_HEADER_SIZE)
/* TODO should this be overwritable by hal? */
#define WOLFHSM_PART_0 0
#define WOLFHSM_PART_1 WOLFHSM_PARTITION_SIZE
/* TODO should this be overwritable by hal? */
#define WOLFHSM_ID_ERASED 0

enum WOLFHSM_TYPE {
    WOLFHSM_ERROR,
    WOLFHSM_CRYPTOCB,
    WOLFHSM_MANAGE,
#ifdef WOLFHSM_SHE_EXTENSION
    WOLFHSM_SHE,
#endif
};

enum WOLFHSM_MANAGE_SUBTYPE {
    WOLFHSM_KEY_CACHE,
    WOLFHSM_KEY_EVICT,
    WOLFHSM_KEY_COMMIT,
    WOLFHSM_KEY_ERASE,
    WOLFHSM_KEY_EXPORT,
    WOLFHSM_VERSION_EXCHANGE,
};

enum WOLFHSM_CMAC_FINAL {
    WOLFHSM_CMAC_ONESHOT,
    WOLFHSM_CMAC_INIT,
    WOLFHSM_CMAC_UPDATE,
    WOLFHSM_CMAC_FINAL,
};

#ifdef WOLFHSM_SHE_EXTENSION
#define WOLFHSM_SHE_SECRET_KEY_ID 0
#define WOLFHSM_SHE_MASTER_ECU_KEY_ID 1
#define WOLFHSM_SHE_BOOT_MAC_KEY_ID 2
#define WOLFHSM_SHE_RAM_KEY_ID 14
#define WOLFHSM_SHE_PRNG_SEED_ID 15
#define WOLFHSM_SHE_KEY_SZ 16
#define WOLFHSM_SHE_BOOT_MAC_PREFIX_LEN 12
enum WOLFHSM_SHE_SUBTYPE {
    WOLFHSM_SHE_SECURE_BOOT_INIT,
    WOLFHSM_SHE_SECURE_BOOT_UPDATE,
    WOLFHSM_SHE_SECURE_BOOT_FINISH,
    WOLFHSM_SHE_GET_STATUS,
    WOLFHSM_SHE_LOAD_KEY,
    WOLFHSM_SHE_EXPORT_RAM_KEY,
    WOLFHSM_SHE_INIT_RNG,
    WOLFHSM_SHE_RND,
    WOLFHSM_SHE_EXTEND_SEED,
};
enum WOLFHSM_SHE_ERROR {
    /* TODO I couldn't find their actual values in the documentation I had */
    WOLFHSM_SHE_ERC_NO_ERROR = 0,
    WOLFHSM_SHE_ERC_NO_SECURE_BOOT = -1,
    WOLFHSM_SHE_ERC_KEY_UPDATE_ERROR = -2,
    WOLFHSM_SHE_ERC_WRITE_PROTECTED = -3,
    WOLFHSM_SHE_ERC_KEY_INVALID = -4,
    WOLFHSM_SHE_ERC_SEQUENCE_ERROR = -5,
    WOLFHSM_SHE_ERC_RNG_SEED = -6,
};
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
/* she keyIds are 0-11, must add 1 to make nonzero */
#define WOLFHSM_SHE_TRANSLATE_KEY_ID(id) (id | 0xF000 )
#endif /* WOLFHSM_SHE_EXTENSION */

#define WOLFHSM_COMM_HEADER_LEN 10
#define WOLFHSM_COMM_DATA_LEN 1280
#define WOLFHSM_COMM_MTU (WOLFHSM_COMM_HEADER_LEN + WOLFHSM_COMM_DATA_LEN)

struct WOLFHSM_CTX;
typedef struct wh_Packet wh_Packet;

typedef int (*WOLFHSMHwIf_Read)(struct WOLFHSM_CTX* ctx, uint8_t* buf,
    uint16_t bufSz);
typedef int (*WOLFHSMHwIf_Write)(struct WOLFHSM_CTX* ctx, uint8_t* buf,
    uint16_t bufSz);
typedef int (*WOLFHSMHwIf_Readable)(struct WOLFHSM_CTX* ctx);

typedef struct WOLFHSM_HWIF {
    WOLFHSMHwIf_Read read;
    WOLFHSMHwIf_Write write;
    WOLFHSMHwIf_Readable readable;
    void* ifCtx;
#ifdef WOLFHSM_DYNAMIC_PACKET
    uint8_t* dynamicPacket;
#endif
} WOLFHSM_HWIF;

#if 0
typedef struct WOLFHSM_PACK NvmMetaData {
    uint16_t id;
    uint32_t flags;
    uint16_t len;
    uint8_t label[WOLFHSM_NVM_LABEL_LEN];
    uint8_t confDigest[WOLFHSM_DIGEST_STUB];
#ifdef WOLFHSM_SHE_EXTENSION
    uint32_t count;
#endif
} NvmMetaData;

typedef struct CacheSlot {
    uint8_t commited;
    NvmMetaData meta[1];
    uint8_t buffer[WOLFHSM_KEYSIZE];
} CacheSlot;

typedef struct WOLFHSM_CTX {
    /*WOLFHSM_HalIoCb ioCb;*/
    uint32_t version;
    int hwifCount;
    int hwifIdx;
    WOLFHSM_HWIF hwifs[WOLFHSM_HWIF_SLOT_COUNT];
#ifdef WOLFHSM_DYNAMIC_PACKET
    uint8_t* packet;
#else
    uint8_t packet[WOLFHSM_COMM_MTU];
#endif
#ifdef WOLFHSM_SERVER
    uint8_t partition;
    WC_RNG rng[1];
    NvmMetaData nvmMetaCache[WOLFHSM_KEYSLOT_COUNT];
    CacheSlot cache[WOLFHSM_CACHE_COUNT];
    void* heap;
    int devId;
#endif
} WOLFHSM_CTX;

int wolfHSM_Init(WOLFHSM_CTX* ctx);
int wolfHSM_Cleanup(WOLFHSM_CTX* ctx);
int hal_init(WOLFHSM_CTX* ctx);
int hal_cleanup(WOLFHSM_CTX* ctx);
int hal_flash_write(uint32_t address, uint8_t* data, uint16_t size);
int hal_flash_read(uint32_t address, uint8_t* data, uint16_t size);
int hal_flash_erase(uint32_t address, uint16_t size);
void networkizePacket(wh_Packet* packet);
void hostizePacketHeader(wh_Packet* packet);
void hostizePacket(wh_Packet* packet);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* !WOLFHSM_COMMON_H */
