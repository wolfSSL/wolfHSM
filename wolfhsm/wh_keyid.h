/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 * wolfhsm/wh_keyid.h
 *
 * KeyId type definitions, constants, and helper functions for wolfHSM
 */

#ifndef WOLFHSM_WH_KEYID_H_
#define WOLFHSM_WH_KEYID_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

/** Key Management */
/* HSM key identifier type.  Top nibble identifies key type/location */
typedef uint16_t whKeyId;

/* KeyId Constants */
#define WH_KEYID_ERASED 0x0000
#define WH_KEYID_IDMAX 0xFF

/* Key Masks */
#define WH_KEYID_MASK 0x00FF
#define WH_KEYID_SHIFT 0
#define WH_KEYUSER_MASK 0x0F00
#define WH_KEYUSER_SHIFT 8
#define WH_KEYTYPE_MASK 0xF000
#define WH_KEYTYPE_SHIFT 12

/* Client-facing key flags are defined in wh_client.h:
 * - WH_CLIENT_KEYID_GLOBAL_FLAG
 * - WH_CLIENT_KEYID_WRAPPED_FLAG
 */

/* Macro to construct a server-unique keyid */
#define WH_MAKE_KEYID(_type, _user, _id)                           \
    ((whKeyId)((((_type) << WH_KEYTYPE_SHIFT) & WH_KEYTYPE_MASK) | \
               (((_user) << WH_KEYUSER_SHIFT) & WH_KEYUSER_MASK) | \
               (((_id) << WH_KEYID_SHIFT) & WH_KEYID_MASK)))
#define WH_KEYID_TYPE(_kid) (((_kid)&WH_KEYTYPE_MASK) >> WH_KEYTYPE_SHIFT)
#define WH_KEYID_USER(_kid) (((_kid)&WH_KEYUSER_MASK) >> WH_KEYUSER_SHIFT)
#define WH_KEYID_ID(_kid) (((_kid)&WH_KEYID_MASK) >> WH_KEYID_SHIFT)

#define WH_KEYID_ISERASED(_kid) (WH_KEYID_ID(_kid) == WH_KEYID_ERASED)
#define WH_KEYID_ISWRAPPED(_kid) (WH_KEYID_TYPE(_kid) == WH_KEYTYPE_WRAPPED)

/* Reserve USER=0 for global keys in the internal keyId encoding.
 * This is server-internal; clients use WH_CLIENT_KEYID_GLOBAL_FLAG from
 * wh_client.h */
#define WH_KEYUSER_GLOBAL 0

/* Key Types */
#define WH_KEYTYPE_NVM 0x0     /* Ordinary NvmId.  Not a key */
#define WH_KEYTYPE_CRYPTO 0x1  /* Key for Crypto operations */
#define WH_KEYTYPE_SHE 0x2     /* SKE keys are AES or CMAC binary arrays */
#define WH_KEYTYPE_COUNTER 0x3 /* Monotonic counter */
#define WH_KEYTYPE_WRAPPED 0x4 /* Wrapped key metadata */

/* Convert a keyId to a pointer to be stored in wolfcrypt devctx */
#define WH_KEYID_TO_DEVCTX(_k) ((void*)((intptr_t)(_k)))
#define WH_DEVCTX_TO_KEYID(_d) ((whKeyId)((intptr_t)(_d)))

/**
 * @brief Translate client keyId (with flags) to server keyId encoding
 *
 * Translates client-facing keyId format (ID + flags) to server-internal format
 * (TYPE + USER + ID). Client flags are:
 * - 0x0100 (bit 8): WH_CLIENT_KEYID_GLOBAL_FLAG  → USER = 0
 * - 0x0200 (bit 9): WH_CLIENT_KEYID_WRAPPED_FLAG → TYPE = WH_KEYTYPE_WRAPPED
 *
 * @param type Key type to use as the TYPE field. Input value is ignored and
 *  WH_KEYTYPE_WRAPPED is used if the input clientId has the
 *  WH_CLIENT_KEYID_WRAPPED flag set.
 * @param clientId Client identifier to use as USER field
 * @param reqId Requested keyId from client (may include flags)
 * @return Server-internal keyId with TYPE, USER, and ID fields properly set.
 */
whKeyId wh_KeyId_TranslateClient(uint16_t type, uint16_t clientId,
                                 whKeyId reqId);

#endif /* !WOLFHSM_WH_KEYID_H_ */
