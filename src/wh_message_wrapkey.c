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

#include "wolfhsm/wh_settings.h"
#ifdef WOLFHSM_CFG_WRAPKEY
#include "wolfhsm/wh_message_wrapkey.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include <string.h>


/* Key Wrap Request translation */
int wh_MessageWrapKey_TranslateWrapRequest(
    uint16_t magic, const whMessageWrapKey_WrapRequest* src,
    whMessageWrapKey_WrapRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, keySz);
    WH_T16(magic, dest, src, serverKeyId);
    WH_T16(magic, dest, src, cipherType);
    return 0;
}

/* Key Wrap Response translation */
int wh_MessageWrapKey_TranslateWrapResponse(
    uint16_t magic, const whMessageWrapKey_WrapResponse* src,
    whMessageWrapKey_WrapResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, wrappedKeySz);
    WH_T16(magic, dest, src, cipherType);
    return 0;
}

/* Key Unwrap Request translation */
int wh_MessageWrapKey_TranslateUnwrapRequest(
    uint16_t magic, const whMessageWrapKey_UnwrapRequest* src,
    whMessageWrapKey_UnwrapRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, wrappedKeySz);
    WH_T16(magic, dest, src, serverKeyId);
    WH_T16(magic, dest, src, cipherType);
    return 0;
}

/* Key Unwrap Response translation */
int wh_MessageWrapKey_TranslateUnwrapResponse(
    uint16_t magic, const whMessageWrapKey_UnwrapResponse* src,
    whMessageWrapKey_UnwrapResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, keySz);
    WH_T16(magic, dest, src, cipherType);
    return 0;
}

/* Wrapped Key Cache Request translation */
int wh_MessageWrapKey_TranslateCacheRequest(
    uint16_t magic, const whMessageWrapKey_CacheRequest* src,
    whMessageWrapKey_CacheRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, wrappedKeySz);
    WH_T16(magic, dest, src, serverKeyId);
    WH_T16(magic, dest, src, cipherType);
    return 0;
}

/* Key Cache Response translation */
int wh_MessageWrapKey_TranslateCacheResponse(
    uint16_t magic, const whMessageWrapKey_CacheResponse* src,
    whMessageWrapKey_CacheResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, keyId);
    WH_T16(magic, dest, src, cipherType);
    return 0;
}

#endif /* WOLFHSM_CFG_WRAPKEY */
