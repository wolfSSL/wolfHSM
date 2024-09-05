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
#define WH_KEYID_IDMAX 0xFF

/* Key Masks */
#define WH_KEYID_MASK   0x00FF
#define WH_KEYID_SHIFT  0
#define WH_KEYUSER_MASK 0x0F00
#define WH_KEYUSER_SHIFT 8
#define WH_KEYTYPE_MASK 0xF000
#define WH_KEYTYPE_SHIFT 12

/* Macro to construct a keyid */
#define WH_MAKE_KEYID(_type, _user, _id)                    \
    ((whKeyId)(                                             \
     (((_type) << WH_KEYTYPE_SHIFT) & WH_KEYTYPE_MASK) |    \
     (((_user) << WH_KEYUSER_SHIFT) & WH_KEYUSER_MASK) |    \
     (((_id) << WH_KEYID_SHIFT) & WH_KEYID_MASK)))
#define WH_KEYID_TYPE(_kid) (((_kid) & WH_KEYTYPE_MASK) >> WH_KEYTYPE_SHIFT)
#define WH_KEYID_USER(_kid) (((_kid) & WH_KEYUSER_MASK) >> WH_KEYUSER_SHIFT)
#define WH_KEYID_ID(_kid)   (((_kid) & WH_KEYID_MASK) >> WH_KEYID_SHIFT)

#define WH_KEYID_ISERASED(_kid) (WH_KEYID_ID(_kid) == WH_KEYID_ERASED)

/* Key Types */
#define WH_KEYTYPE_NVM      0x0     /* Ordinary NvmId.  Not a key */
#define WH_KEYTYPE_CRYPTO   0x1     /* Key for Crypto operations */
#define WH_KEYTYPE_SHE      0x2     /* SKE keys are AES or CMAC binary arrays */
#define WH_KEYTYPE_COUNTER  0x3     /* Monotonic counter */

/* Convert a keyId to a pointer to be stored in wolfcrypt devctx */
#define WH_KEYID_TO_DEVCTX(_k) ((void*)((intptr_t)(_k)))
#define WH_DEVCTX_TO_KEYID(_d) ((whKeyId)((intptr_t)(_d)))

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

/* Growth */
#define WH_ACCESS_OWN_MASK     0x000F
#define WH_ACCESS_OWN_SHIFT    0
#define WH_ACCESS_OTH_MASK     0x00F0
#define WH_ACCESS_OTH_SHIFT    4
#define WH_ACCESS_USER_MASK     0xFF00
#define WH_ACCESS_USER_SHIFT    8

#define WH_ACCESS_READ      ((whNvmAccess)1 << 0)
#define WH_ACCESS_WRITE     ((whNvmAccess)1 << 1)
#define WH_ACCESS_EXEC      ((whNvmAccess)1 << 2)
#define WH_ACCESS_SPECIAL   ((whNvmAccess)1 << 3)

#define WH_NVM_MAKE_ACCESS(_user, _oth, _own)                       \
    ((whAccess)(                                                    \
     (((_user) << WH_ACCESS_USER_SHIFT) & WH_ACCESS_USER_MASK) |    \
     (((_oth)  << WH_ACCESS_OTH_SHIFT)  & WH_ACCESS_OTH_MASK)  |    \
     (((_own)  << WH_ACCESS_OWN_SHIFT)  & WH_ACCESS_OWN_MASK)))

/* HSM NVM Flags type */
typedef uint16_t whNvmFlags;
#define WH_NVM_FLAGS_NONE  ((whNvmFlags)0)
#define WH_NVM_FLAGS_ANY   ((whNvmFlags)-1)

#define WH_NVM_FLAGS_IMMUTABLE      ((whNvmFlags)1 << 0) /* Cannot be overwritten */
#define WH_NVM_FLAGS_SENSITIVE      ((whNvmFlags)1 << 1) /* Holds private/secret data */
#define WH_NVM_FLAGS_NONEXPORTABLE  ((whNvmFlags)1 << 2) /* Cannot be exported */
#define WH_NVM_FLAGS_LOCAL          ((whNvmFlags)1 << 3) /* Was generated locally */
#define WH_NVM_FLAGS_EPHEMERAL      ((whNvmFlags)1 << 4) /* Cannot be cached nor committed */



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
