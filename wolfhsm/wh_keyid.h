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

/* Maximum valid client_id. The USER field of whKeyId is 4 bits, so client_id
 * must fit in [1, WH_CLIENT_ID_MAX]: value 0 is reserved for the global-keys
 * namespace (WH_KEYUSER_GLOBAL), and larger values would be silently
 * truncated by WH_MAKE_KEYID, breaking per-client key isolation.
 * wh_Client_Init() rejects out-of-range ids (including 0) before any
 * communication; the server rejects ids above the maximum at
 * WH_MESSAGE_COMM_ACTION_INIT and, with WOLFHSM_CFG_GLOBAL_KEYS, also rejects
 * 0. Derived from WH_KEYUSER_MASK so the bound stays in sync if the USER
 * field is ever widened. */
#define WH_CLIENT_ID_MAX (WH_KEYUSER_MASK >> WH_KEYUSER_SHIFT)

/*
 * Client-facing key flags (temporary, stripped by server during translation)
 *
 * Clients use simple numeric IDs (0-255) with optional flags to indicate
 * global or wrapped keys. The server translates these to full internal
 * representations with TYPE/USER/ID fields.

 * Client keyId usage:
 * - Regular keys: Simple numeric ID (e.g., 5)
 * - Global keys: ID with WH_KEYID_CLIENT_GLOBAL_FLAG set
 * - Wrapped keys: ID with WH_KEYID_CLIENT_WRAPPED_FLAG set
 * - Hardware-only keys: ID with WH_KEYID_CLIENT_HW_FLAG set
 * - Wrapped metadata: Must use full WH_MAKE_KEYID() construction including type
 *    and metadata when populating the ID field in metadata to be wrapped
 *
 */
/* Bit 8: Client-to-server signal for global key (shared across all clients) */
#define WH_KEYID_CLIENT_GLOBAL_FLAG ((whKeyId)0x0100)

/* Bit 9: Client-to-server signal for wrapped key */
#define WH_KEYID_CLIENT_WRAPPED_FLAG ((whKeyId)0x0200)

/* Bit 10: Client-to-server signal for a hardware-only key. The key material
 * lives exclusively in a hardware keystore (see wolfhsm/wh_hwkeystore.h) and
 * is fetched on demand by the server. It never enters the key cache or NVM
 * and is never returned to a client. Such keys are only usable as KEKs in
 * the keywrap API */
#define WH_KEYID_CLIENT_HW_FLAG ((whKeyId)0x0400)

/* Combined mask of all client-facing flags */
#define WH_CLIENT_KEYID_FLAGS_MASK                                \
    (WH_KEYID_CLIENT_GLOBAL_FLAG | WH_KEYID_CLIENT_WRAPPED_FLAG | \
     WH_KEYID_CLIENT_HW_FLAG)

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
#define WH_KEYID_ISHW(_kid) (WH_KEYID_TYPE(_kid) == WH_KEYTYPE_HW)

/* Reserve USER=0 for global keys in the internal keyId encoding.
 * This is server-internal; clients use WH_KEYID_CLIENT_GLOBAL_FLAG from
 * wh_client.h */
#define WH_KEYUSER_GLOBAL 0

/* Key Types */
#define WH_KEYTYPE_NVM 0x0     /* Ordinary NvmId.  Not a key */
#define WH_KEYTYPE_CRYPTO 0x1  /* Key for Crypto operations */
#define WH_KEYTYPE_SHE 0x2     /* SKE keys are AES or CMAC binary arrays */
#define WH_KEYTYPE_COUNTER 0x3 /* Monotonic counter */
#define WH_KEYTYPE_WRAPPED 0x4 /* Wrapped key metadata */
#define WH_KEYTYPE_HW 0x5 /* HW-only key. Port-specific */

/* True when a key id carries no explicit identifier (ID field == 0) and so must
 * not be accepted as one - it would collide with the "assign me one" sentinel
 * used for dynamic id assignment. SHE keys are exempt: their ids are fixed by
 * the SHE slot map, where slot 0 (SECRET_KEY) is a legitimate explicit id, not
 * a request for dynamic assignment. */
#define WH_KEYID_IS_UNASSIGNED(_kid) \
    (WH_KEYID_ISERASED(_kid) && (WH_KEYID_TYPE(_kid) != WH_KEYTYPE_SHE))

/* Convert a keyId to a pointer to be stored in wolfcrypt devctx */
#define WH_KEYID_TO_DEVCTX(_k) ((void*)((intptr_t)(_k)))
#define WH_DEVCTX_TO_KEYID(_d) ((whKeyId)((intptr_t)(_d)))

/**
 * @brief Translate client keyId (with flags) to server keyId encoding
 *
 * Translates client-facing keyId format (ID + flags) to server-internal format
 * (TYPE + USER + ID). Client flags are:
 * - 0x0100 (bit 8): WH_KEYID_CLIENT_GLOBAL_FLAG  → USER = 0
 * - 0x0200 (bit 9): WH_KEYID_CLIENT_WRAPPED_FLAG → TYPE = WH_KEYTYPE_WRAPPED
 * - 0x0400 (bit 10): WH_KEYID_CLIENT_HW_FLAG → TYPE = WH_KEYTYPE_HW
 *
 * @param type Key type to use as the TYPE field. Input value is ignored and
 *  WH_KEYTYPE_WRAPPED or WH_KEYTYPE_HW is used if the input clientId has
 *  the corresponding flag set. If both flags are set, HW takes
 *  precedence.
 * @param clientId Client identifier to use as USER field. Must be in
 *  [1, WH_CLIENT_ID_MAX] (0 is reserved for WH_KEYUSER_GLOBAL);
 *  wh_Client_Init() and the server's INIT handling enforce this so callers
 *  may assume the value fits in the 4-bit USER field.
 * @param reqId Requested keyId from client (may include flags)
 * @return Server-internal keyId with TYPE, USER, and ID fields properly set.
 */
whKeyId wh_KeyId_TranslateFromClient(uint16_t type, uint16_t clientId,
                                     whKeyId reqId);

/**
 * @brief Translate server keyId to client keyId format (with flags)
 *
 * Translates server-internal keyId format (TYPE + USER + ID) back to
 * client-facing format (ID + flags). Server encoding is converted to flags:
 * - USER = 0 (WH_KEYUSER_GLOBAL)  → 0x0100 (WH_KEYID_CLIENT_GLOBAL_FLAG)
 * - TYPE = WH_KEYTYPE_WRAPPED     → 0x0200 (WH_KEYID_CLIENT_WRAPPED_FLAG)
 * - TYPE = WH_KEYTYPE_HW          → 0x0400 (WH_KEYID_CLIENT_HW_FLAG)
 *
 * This ensures clients can identify global and wrapped keys after they are
 * returned from server operations (cache, key generation, etc.).
 *
 * @param serverId Server-internal keyId with TYPE, USER, and ID fields
 * @return Client-facing keyId with ID portion and appropriate flag bits set
 */
whKeyId wh_KeyId_TranslateToClient(whKeyId serverId);

#endif /* !WOLFHSM_WH_KEYID_H_ */
