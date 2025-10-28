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
 * src/wh_keyid.c
 *
 * KeyId helper function implementations for wolfHSM
 */

#include "wolfhsm/wh_keyid.h"

whKeyId wh_KeyId_TranslateClient(uint16_t type, uint16_t clientId,
                                 whKeyId reqId)
{
    uint16_t user = clientId;
    whKeyId  id   = reqId & WH_KEYID_MASK;

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Check for global flag (bit 8: 0x0100) */
    if ((reqId & 0x0100) != 0) {
        user = WH_KEYUSER_GLOBAL;
    }
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    /* Check for wrapped flag (bit 9: 0x0200) */
    if ((reqId & 0x0200) != 0) {
        type = WH_KEYTYPE_WRAPPED;
    }
#endif

    return WH_MAKE_KEYID(type, user, id);
}

whKeyId wh_KeyId_ToClient(whKeyId serverId)
{
    whKeyId clientId = WH_KEYID_ID(serverId);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Convert USER=0 to global flag (bit 8: 0x0100) */
    if (WH_KEYID_USER(serverId) == WH_KEYUSER_GLOBAL) {
        clientId |= 0x0100; /* WH_CLIENT_KEYID_GLOBAL_FLAG */
    }
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    /* Convert TYPE=WRAPPED to wrapped flag (bit 9: 0x0200) */
    if (WH_KEYID_TYPE(serverId) == WH_KEYTYPE_WRAPPED) {
        clientId |= 0x0200; /* WH_CLIENT_KEYID_WRAPPED_FLAG */
    }
#endif

    return clientId;
}
