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

/* Key management types and helpers */
#include "wolfhsm/wh_keyid.h"

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

/* Generic NVM flags */
/* Cannot be modified */
#define WH_NVM_FLAGS_NONMODIFIABLE ((whNvmFlags)1 << 0)
/* Holds private/secret data */
#define WH_NVM_FLAGS_SENSITIVE      ((whNvmFlags)1 << 1)
/* Cannot be exported */
#define WH_NVM_FLAGS_NONEXPORTABLE  ((whNvmFlags)1 << 2)
/* Was generated locally */
#define WH_NVM_FLAGS_LOCAL          ((whNvmFlags)1 << 3)
/* Cannot be cached nor committed */
#define WH_NVM_FLAGS_EPHEMERAL      ((whNvmFlags)1 << 4)
/* Cannot be destroyed (but can be modified) */
#define WH_NVM_FLAGS_NONDESTROYABLE ((whNvmFlags)1 << 11)

/* Key usage policy flags
 *
 * Key usage flags control which cryptographic operations are permitted.
 * Multiple usage flags can be combined. If no usage flags are set, the key
 * cannot be used for any operation. Use WH_NVM_FLAGS_USAGE_ANY to allow all
 * operations.
 */
/* Key can be used for encryption */
#define WH_NVM_FLAGS_USAGE_ENCRYPT ((whNvmFlags)1 << 5)
/* Key can be used for decryption */
#define WH_NVM_FLAGS_USAGE_DECRYPT ((whNvmFlags)1 << 6)
/* Key can be used for signing */
#define WH_NVM_FLAGS_USAGE_SIGN    ((whNvmFlags)1 << 7)
/* Key can be used for verification */
#define WH_NVM_FLAGS_USAGE_VERIFY  ((whNvmFlags)1 << 8)
/* Key can be used for key wrapping */
#define WH_NVM_FLAGS_USAGE_WRAP    ((whNvmFlags)1 << 9)
/* Key can be used for key derivation */
#define WH_NVM_FLAGS_USAGE_DERIVE  ((whNvmFlags)1 << 10)

/* No flags set */
#define WH_NVM_FLAGS_NONE ((whNvmFlags)0)
/* All flags set */
#define WH_NVM_FLAGS_ANY ((whNvmFlags)-1)
/* All usage flags set */
#define WH_NVM_FLAGS_USAGE_ANY                                              \
    ((whNvmFlags)(WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT | \
                  WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |     \
                  WH_NVM_FLAGS_USAGE_WRAP |                                 \
                  WH_NVM_FLAGS_USAGE_DERIVE))

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

/* Certificate management flags */
typedef uint16_t whCertFlags;
#define WH_CERT_FLAGS_NONE ((whCertFlags)0)
#define WH_CERT_FLAGS_ANY ((whCertFlags)-1)

/* Cache public key belonging to the leaf certificate */
#define WH_CERT_FLAGS_CACHE_LEAF_PUBKEY ((whCertFlags)1 << 0)

#define WH_KEYWRAP_AES_GCM_TAG_SIZE 16
#define WH_KEYWRAP_AES_GCM_IV_SIZE 12
#define WH_KEYWRAP_AES_GCM_HEADER_SIZE \
    (WH_KEYWRAP_AES_GCM_IV_SIZE + WH_KEYWRAP_AES_GCM_TAG_SIZE)

#endif /* !WOLFHSM_WH_COMMON_H_ */
