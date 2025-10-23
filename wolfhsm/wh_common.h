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

/* Certificate management flags */
typedef uint16_t whCertFlags;
#define WH_CERT_FLAGS_NONE ((whCertFlags)0)
#define WH_CERT_FLAGS_ANY ((whCertFlags)-1)

/* Cache public key belonging to the leaf certificate */
#define WH_CERT_FLAGS_CACHE_LEAF_PUBKEY ((whCertFlags)1 << 0)

#define WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE 16
#define WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE 12

#endif /* !WOLFHSM_WH_COMMON_H_ */
