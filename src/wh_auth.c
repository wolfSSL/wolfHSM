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
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_auth.h"


int wh_Auth_Init(whAuthContext* context, const whAuthConfig *config)
{
    int rc = 0;

    if (    (context == NULL) ||
            (config == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    context->cb = config->cb;
    context->context = config->context;
    memset(&context->user, 0, sizeof(whAuthUser));

    if (context->cb != NULL && context->cb->Init != NULL) {
        rc = context->cb->Init(context->context, config->config);
        if (rc != 0) {
            context->cb = NULL;
            context->context = NULL;
        }
    }

    return rc;
}


int wh_Auth_Cleanup(whAuthContext* context)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if (context->cb->Cleanup == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->Cleanup(context->context);
}


/* return value is if the login attempt happened or if a fatal error occurred.
 * The result of the login attempt is stored in loggedIn -- 1 for success,
 * 0 for failure */
int wh_Auth_Login(whAuthContext* context, uint8_t client_id,
                          whAuthMethod method, const char* username,
                          const void* auth_data,
                          uint16_t auth_data_len,
                          int* loggedIn)
{
    int rc;
    whUserId out_user_id;
    whAuthPermissions out_permissions;

    if (loggedIn == NULL) {
        return WH_ERROR_BADARGS;
    }
    *loggedIn = 0;

    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (context->cb->Login == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* allowing only one user logged in to an open connection at a time */
    if (context->user.user_id != WH_USER_ID_INVALID) {
        *loggedIn = 0;
        rc = WH_ERROR_OK; /* login attempt happened but failed */
    }
    else {
        rc = context->cb->Login(context->context, client_id, method,
                              username, auth_data, auth_data_len, &out_user_id,
                              &out_permissions, loggedIn);
        if (rc == WH_ERROR_OK && *loggedIn) {
            context->user.user_id = out_user_id;
            context->user.permissions = out_permissions;
            context->user.is_active = true;
        }
    }

    return rc;
}


int wh_Auth_Logout(whAuthContext* context, whUserId user_id)
{
    int rc;

    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (context->cb->Logout == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    rc = context->cb->Logout(context->context, context->user.user_id, user_id);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Clear the user context */
    memset(&context->user, 0, sizeof(whAuthUser));
    return WH_ERROR_OK;
}


/* Check on request authorization and action permissions for current user
 * logged in */
int wh_Auth_CheckRequestAuthorization(whAuthContext* context, uint16_t group,
    uint16_t action)
{
    uint16_t user_id = context->user.user_id;

    printf("In authorization check: User ID: %d, Group: %d, Action: %d\n",
        user_id, group, action);

    return context->cb->CheckRequestAuthorization(context->context, user_id,
        group, action);
}


/* Check on key ID use after request has been parsed */
int wh_Auth_CheckKeyAuthorization(whAuthContext* context, uint32_t key_id,
    uint16_t action)
{
    uint16_t user_id = context->user.user_id;

    printf("In key authorization check: User ID: %d, Key ID: %d, Action: %d\n",
        user_id, key_id, action);

    return context->cb->CheckKeyAuthorization(context->context, user_id, key_id,
        action);
}

/********** API That Interact With User Database *******************************/

int wh_Auth_UserAdd(whAuthContext* context, const char* username,
                     whUserId* out_user_id, whAuthPermissions permissions,
                     whAuthMethod method, const void* credentials,
                     uint16_t credentials_len)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (context->cb->UserAdd == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    return context->cb->UserAdd(context->context, username, out_user_id, permissions,
            method, credentials, credentials_len);
}


int wh_Auth_UserDelete(whAuthContext* context, whUserId user_id)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (context->cb->UserDelete == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    return context->cb->UserDelete(context->context, user_id);
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

int wh_Auth_UserGet(whAuthContext* context, const char* username, whUserId* out_user_id,
    whAuthPermissions* out_permissions)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (context->cb->UserGet == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    return context->cb->UserGet(context->context, username, out_user_id, out_permissions);
}

int wh_Auth_UserSetCredentials(whAuthContext* context, whUserId user_id,
                                 whAuthMethod method,
                                 const void* current_credentials, uint16_t current_credentials_len,
                                 const void* new_credentials, uint16_t new_credentials_len)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ||
            (context->cb->UserSetCredentials == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    return context->cb->UserSetCredentials(context->context, user_id, method,
            current_credentials, current_credentials_len,
            new_credentials, new_credentials_len);
}

