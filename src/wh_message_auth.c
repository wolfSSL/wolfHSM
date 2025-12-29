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
 * src/wh_message_auth.c
 *
 * Message translation functions for Auth Manager messages
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"

#include "wolfhsm/wh_message_auth.h"


int wh_MessageAuth_TranslateSimpleResponse(uint16_t magic,
        const whMessageAuth_SimpleResponse* src,
        whMessageAuth_SimpleResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

int wh_MessageAuth_TranslateLoginRequest(uint16_t magic,
        const whMessageAuth_LoginRequest* src,
        whMessageAuth_LoginRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T16(magic, dest, src, method);
    if (src != dest) {
        memcpy(dest->username, src->username, sizeof(dest->username));
        memcpy(dest->auth_data, src->auth_data, src->auth_data_len);
    }
    WH_T16(magic, dest, src, auth_data_len);
    return 0;
}

int wh_MessageAuth_TranslateLoginResponse(uint16_t magic,
        const whMessageAuth_LoginResponse* src,
        whMessageAuth_LoginResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, user_id);
    WH_T32(magic, dest, src, permissions);
    return 0;
}

int wh_MessageAuth_TranslateLogoutRequest(uint16_t magic,
        const whMessageAuth_LogoutRequest* src,
        whMessageAuth_LogoutRequest* dest)
{
    /* TODO: Translate logout request message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}


int wh_MessageAuth_TranslateUserAddRequest(uint16_t magic,
        const whMessageAuth_UserAddRequest* src,
        whMessageAuth_UserAddRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (src != dest) {
        memcpy(dest->username, src->username, sizeof(dest->username));
    }
    WH_T32(magic, dest, src, permissions);
    return 0;
}

int wh_MessageAuth_TranslateUserAddResponse(uint16_t magic,
        const whMessageAuth_UserAddResponse* src,
        whMessageAuth_UserAddResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, user_id);
    return 0;
}

int wh_MessageAuth_TranslateUserDeleteRequest(uint16_t magic,
        const whMessageAuth_UserDeleteRequest* src,
        whMessageAuth_UserDeleteRequest* dest)
{
    /* TODO: Translate user delete request message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}

int wh_MessageAuth_TranslateUserGetRequest(uint16_t magic,
        const whMessageAuth_UserGetRequest* src,
        whMessageAuth_UserGetRequest* dest)
{
    /* TODO: Translate user get request message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}

int wh_MessageAuth_TranslateUserGetResponse(uint16_t magic,
        const whMessageAuth_UserGetResponse* src,
        whMessageAuth_UserGetResponse* dest)
{
    /* TODO: Translate user get response message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}

int wh_MessageAuth_TranslateUserSetPermissionsRequest(uint16_t magic,
        const whMessageAuth_UserSetPermissionsRequest* src,
        whMessageAuth_UserSetPermissionsRequest* dest)
{
    /* TODO: Translate user set permissions request message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}

int wh_MessageAuth_TranslateUserSetCredentialsRequest(uint16_t magic,
        const whMessageAuth_UserSetCredentialsRequest* src,
        whMessageAuth_UserSetCredentialsRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T16(magic, dest, src, user_id);
    WH_T16(magic, dest, src, method);
    WH_T16(magic, dest, src, credentials_len);
    if (src != dest) {
        memcpy(dest->credentials, src->credentials, src->credentials_len);
    }
    return 0;
}


int wh_MessageAuth_TranslateCheckAuthorizationRequest(uint16_t magic,
        const whMessageAuth_CheckAuthorizationRequest* src,
        whMessageAuth_CheckAuthorizationRequest* dest)
{
    /* TODO: Translate check authorization request message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}

int wh_MessageAuth_TranslateCheckAuthorizationResponse(uint16_t magic,
        const whMessageAuth_CheckAuthorizationResponse* src,
        whMessageAuth_CheckAuthorizationResponse* dest)
{
    /* TODO: Translate check authorization response message */
    (void)magic;
    (void)src;
    (void)dest;
    return 0;
}
