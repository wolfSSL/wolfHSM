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

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

/** Non-volatile counters */
/* HSM Counter identifier type. */
typedef uint16_t whCounterId;
#define WH_COUNTER_ID_INVALID ((whCounterId)0)


/** Key Management */
/* HSM key identifier type.  Top nibble identifies key type/location */
typedef uint16_t whKeyId;

/* KeyId Constants */
#define WH_KEYID_ERASED 0x0000

/* Key Masks */
#define WH_KEYID_MASK   0x00FF
#define WH_KEYUSER_MASK 0x0F00
#define WH_KEYTYPE_MASK 0xF000

/* Macro to construct a keyid */
#define WH_MAKE_KEYID(_type, _user, _id)        \
    ((whKeyId)(((_type) & WH_KEYTYPE_MASK) |    \
    (((_user) << 8) & WH_KEYUSER_MASK) |        \
    ((_id) & WH_KEYID_MASK)))

/* Key Types */
#define WH_KEYTYPE_CRYPTO    0x1000
/* She keys are technically raw keys but a SHE keyId needs */
#define WH_KEYTYPE_SHE       0x2000
#define WH_KEYTYPE_COUNTER   0x3000


/** NVM Management */
/* HSM NVM object identifier type. */
typedef uint16_t whNvmId;
#define WH_NVM_ID_INVALID ((whNvmId)0)

/* HSM NVM Size type */
typedef uint16_t whNvmSize;

/* HSM NVM Access type */
typedef uint16_t whNvmAccess;
#define WH_NVM_ACCESS_NONE ((whNvmAccess)0)
#define WH_NVM_ACCESS_ANY  ((whNvmAccess)-1)

/* HSM NVM Flags type */
typedef uint16_t whNvmFlags;
#define WH_NVM_FLAGS_NONE  ((whNvmFlags)0)
#define WH_NVM_FLAGS_ANY   ((whNvmFlags)-1)

/* HSM NVM metadata structure */
enum WH_NVM_ENUM {
    WH_NVM_LABEL_LEN = 24,
};

/* User-specified metadata for an NVM object, MUST be a multiple of
 * WHFU_BYTES_PER_UNIT */
typedef struct {
    whNvmId id;             /* Unique identifier */
    whNvmAccess access;     /* Growth */
    whNvmFlags flags;       /* Growth */
    whNvmSize len;          /* Length of data in bytes */
    uint8_t label[WH_NVM_LABEL_LEN];
} whNvmMetadata;

#endif /* !WOLFHSM_WH_COMMON_H_ */
