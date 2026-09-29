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
#include "wolfhsm/wh_error.h"

whKeyId wh_KeyId_TranslateFromClient(uint16_t type, uint16_t clientId,
                                     whKeyId reqId)
{
    uint16_t user = clientId;
    whKeyId  id   = reqId & WH_KEYID_MASK;

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Convert global flag to USER=0 */
    if ((reqId & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0) {
        user = WH_KEYUSER_GLOBAL;
    }
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    /* Convert wrapped flag to TYPE=WH_KETYPE_WRAPPED */
    if ((reqId & WH_KEYID_CLIENT_WRAPPED_FLAG) != 0) {
        type = WH_KEYTYPE_WRAPPED;
    }
#endif

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Convert hardware-only flag to TYPE=WH_KEYTYPE_HW. Checked after
     * the wrapped flag so HW wins if a client sets both */
    if ((reqId & WH_KEYID_CLIENT_HW_FLAG) != 0) {
        type = WH_KEYTYPE_HW;
    }
#endif

    return WH_MAKE_KEYID(type, user, id);
}

whKeyId wh_KeyId_TranslateObjectIdFromClient(uint16_t type, uint16_t clientId,
                                             whKeyId reqId)
{
    /* Strip wrapped and hardware flags so fixed types are preserved. */
    reqId &=
        (whKeyId) ~(WH_KEYID_CLIENT_WRAPPED_FLAG | WH_KEYID_CLIENT_HW_FLAG);
    return wh_KeyId_TranslateFromClient(type, clientId, reqId);
}

int wh_KeyId_CheckClientObjectId(whKeyId reqId)
{
    /* Reject bits outside valid ID and flag ranges */
    if ((reqId & (whKeyId) ~(WH_KEYID_MASK | WH_CLIENT_KEYID_FLAGS_MASK)) !=
        0) {
        return WH_ERROR_BADARGS;
    }
    /* Wrapped and hardware flags are not valid for fixed-type objects */
    if ((reqId & (WH_KEYID_CLIENT_WRAPPED_FLAG | WH_KEYID_CLIENT_HW_FLAG)) !=
        0) {
        return WH_ERROR_BADARGS;
    }
#ifndef WOLFHSM_CFG_GLOBAL_KEYS
    /* Reject global flag when global keys are disabled */
    if ((reqId & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0) {
        return WH_ERROR_BADARGS;
    }
#endif
    return WH_ERROR_OK;
}

int wh_KeyId_CheckClientObjectIdForCreate(whKeyId reqId)
{
    /* ID 0 is invalid for object creation */
    if (WH_KEYID_ISERASED(reqId)) {
        return WH_ERROR_BADARGS;
    }
    return wh_KeyId_CheckClientObjectId(reqId);
}

whKeyId wh_KeyId_TranslateToClient(whKeyId serverId)
{
    whKeyId clientId = WH_KEYID_ID(serverId);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Convert USER=0 to global flag */
    if (WH_KEYID_USER(serverId) == WH_KEYUSER_GLOBAL) {
        clientId |= WH_KEYID_CLIENT_GLOBAL_FLAG;
    }
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    /* Convert TYPE=WRAPPED to wrapped flag */
    if (WH_KEYID_TYPE(serverId) == WH_KEYTYPE_WRAPPED) {
        clientId |= WH_KEYID_CLIENT_WRAPPED_FLAG;
    }
#endif

#ifdef WOLFHSM_CFG_HWKEYSTORE
    /* Convert TYPE=HW to hardware-only flag */
    if (WH_KEYID_TYPE(serverId) == WH_KEYTYPE_HW) {
        clientId |= WH_KEYID_CLIENT_HW_FLAG;
    }
#endif

    return clientId;
}
