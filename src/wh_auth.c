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
 * src/wh_auth.c
 *
 * Core Auth Manager implementation. Provides wrapper functions that delegate
 * to the configured auth backend callbacks.
 *
 * - Verifies PINs/credentials
 * - Manages sessions
 * - Authorization decisions
 * - Session state tracking and logging
 *
 * The Auth Manager is agnostic to the transport used and manages authentication
 * of a session. It can take a PIN or certificate for verification and logs
 * all login attempts along with actions done by logged in users. An
 * authenticated session is separate from a comm connection and sits on top of
 * a comm connection. Allowing for multiple authenticated sessions opened and
 * closed multiple times through out the span of a single comm connection
 * established.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>     /* For NULL */
#include <string.h>     /* For memset, memcpy */

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_auth.h"


int wh_Auth_Init(whAuthContext* context, const whAuthConfig *config)
{
    /* TODO: Initialize auth manager context */
    (void)context;
    (void)config;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_Cleanup(whAuthContext* context)
{
    /* TODO: Cleanup auth manager context */
    (void)context;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_Authenticate(whAuthContext* context, uint8_t client_id,
                          whAuthMethod method, const void* auth_data,
                          uint16_t auth_data_len,
                          whUserId* out_user_id, whSessionId* out_session_id,
                          whAuthPermissions* out_permissions)
{
    /* TODO: Authenticate user using specified method */
    (void)context;
    (void)client_id;
    (void)method;
    (void)auth_data;
    (void)auth_data_len;
    (void)out_user_id;
    (void)out_session_id;
    (void)out_permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_SessionCreate(whAuthContext* context, whUserId user_id,
                           uint8_t client_id, whAuthPermissions permissions,
                           whSessionId* out_session_id)
{
    /* TODO: Create new session for authenticated user */
    (void)context;
    (void)user_id;
    (void)client_id;
    (void)permissions;
    (void)out_session_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_SessionDestroy(whAuthContext* context, whSessionId session_id)
{
    /* TODO: Destroy session */
    (void)context;
    (void)session_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_SessionGet(whAuthContext* context, whSessionId session_id,
                        whAuthSession* out_session)
{
    /* TODO: Get session information */
    (void)context;
    (void)session_id;
    (void)out_session;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_CheckAuthorization(whAuthContext* context, whSessionId session_id,
                                whAuthAction action, uint32_t object_id)
{
    /* TODO: Check if action is authorized for session */
    (void)context;
    (void)session_id;
    (void)action;
    (void)object_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_UserAdd(whAuthContext* context, const char* username,
                     whUserId* out_user_id, whAuthPermissions permissions)
{
    /* TODO: Add new user */
    (void)context;
    (void)username;
    (void)out_user_id;
    (void)permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_UserDelete(whAuthContext* context, whUserId user_id)
{
    /* TODO: Delete user */
    (void)context;
    (void)user_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_UserSetPermissions(whAuthContext* context, whUserId user_id,
                                 whAuthPermissions permissions)
{
    /* TODO: Set user permissions */
    (void)context;
    (void)user_id;
    (void)permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_UserGet(whAuthContext* context, whUserId user_id,
                     whAuthUser* out_user)
{
    /* TODO: Get user information */
    (void)context;
    (void)user_id;
    (void)out_user;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_UserSetCredentials(whAuthContext* context, whUserId user_id,
                                 whAuthMethod method, const void* credentials,
                                 uint16_t credentials_len)
{
    /* TODO: Set user credentials */
    (void)context;
    (void)user_id;
    (void)method;
    (void)credentials;
    (void)credentials_len;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_SessionStatus(whAuthContext* context, uint8_t client_id,
                           uint32_t* out_active_sessions,
                           whSessionId* out_session_list, uint16_t max_sessions)
{
    /* TODO: Get session status for client */
    (void)context;
    (void)client_id;
    (void)out_active_sessions;
    (void)out_session_list;
    (void)max_sessions;
    return WH_ERROR_NOTIMPL;
}

int wh_Auth_CommonCallback(void* auth_context, whSessionId session_id,
                           whAuthAction action, uint32_t object_id)
{
    /* TODO: Common callback for authorization checks throughout wolfHSM */
    (void)auth_context;
    (void)session_id;
    (void)action;
    (void)object_id;
    return WH_ERROR_NOTIMPL;
}
