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
 * - Calls to implemented callbacks for managing users and permissions
 * - Authorization decisions are routed through the implemented callbacks
 *
 * The Auth Manager is agnostic to the transport used and manages authentication
 * of a session. It can take a PIN or certificate for verification. An
 * authenticated session is separate from a comm connection and sits on top of
 * a comm connection. Allowing for multiple authenticated sessions opened and
 * closed multiple times through out the span of a single comm connection
 * established. Currently there is a restriction of one user logged in at a time
 * per comm connection.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_auth.h"
#include "wolfhsm/wh_message_auth.h"


int wh_Auth_Init(whAuthContext* context, const whAuthConfig* config)
{
    int rc = WH_ERROR_OK;

    if ((context == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    context->cb      = config->cb;
    context->context = config->context;
    memset(&context->user, 0, sizeof(whAuthUser));

#ifdef WOLFHSM_CFG_THREADSAFE
    /* Initialize the lock for thread-safe auth operations */
    rc = wh_Lock_Init(&context->lock, config->lockConfig);
    if (rc != WH_ERROR_OK) {
        context->cb      = NULL;
        context->context = NULL;
        return rc;
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    if (context->cb != NULL && context->cb->Init != NULL) {
        rc = context->cb->Init(context->context, config->config);
        if (rc != WH_ERROR_OK) {
#ifdef WOLFHSM_CFG_THREADSAFE
            (void)wh_Lock_Cleanup(&context->lock);
#endif
            context->cb      = NULL;
            context->context = NULL;
        }
    }

    return rc;
}


int wh_Auth_Cleanup(whAuthContext* context)
{
    int rc = WH_ERROR_OK;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if (context->cb->Cleanup == NULL) {
        return WH_ERROR_ABORTED;
    }

    rc = context->cb->Cleanup(context->context);

#ifdef WOLFHSM_CFG_THREADSAFE
    /* Cleanup the lock for thread-safe auth operations */
    (void)wh_Lock_Cleanup(&context->lock);
#endif /* WOLFHSM_CFG_THREADSAFE */

    return rc;
}


/* Returns a wolfHSM error code: WH_ERROR_OK (0) if the call completed
 * successfully (regardless of authentication result), or a negative error code
 * if a fatal error occurred. The result of the login attempt is stored in
 * loggedIn: 1 for successful authentication, 0 for failed authentication. */
int wh_Auth_Login(whAuthContext* context, uint8_t client_id,
                  whAuthMethod method, const char* username,
                  const void* auth_data, uint16_t auth_data_len, int* loggedIn)
{
    int               rc;
    whUserId          out_user_id;
    whAuthPermissions out_permissions;

    if (loggedIn == NULL) {
        return WH_ERROR_BADARGS;
    }
    *loggedIn = 0;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->Login == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        /* allowing only one user logged in to an open connection at a time */
        if (context->user.user_id != WH_USER_ID_INVALID) {
            *loggedIn = 0;
            rc        = WH_ERROR_OK; /* login attempt happened but failed */
        }
        else {
            rc = context->cb->Login(context->context, client_id, method,
                                    username, auth_data, auth_data_len,
                                    &out_user_id, &out_permissions, loggedIn);
            if (rc == WH_ERROR_OK && *loggedIn) {
                context->user.user_id     = out_user_id;
                context->user.permissions = out_permissions;
                context->user.is_active   = true;
            }
        }

        (void)WH_AUTH_UNLOCK(context);
    } /* LOCK() */
    return rc;
}


int wh_Auth_Logout(whAuthContext* context, whUserId user_id)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->Logout == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        rc = context->cb->Logout(context->context, context->user.user_id,
            user_id);
        if (rc == WH_ERROR_OK) {
            /* Clear the user context */
            memset(&context->user, 0, sizeof(whAuthUser));
        }

        (void)WH_AUTH_UNLOCK(context);
    } /* LOCK() */
    return rc;
}


/* Check on request authorization and action permissions for current user
 * logged in */
int wh_Auth_CheckRequestAuthorization(whAuthContext* context, uint16_t group,
                                      uint16_t action)
{
    uint16_t    user_id;
    int         rc;
    whAuthUser* user;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        user    = &context->user;
        user_id = user->user_id;
        /* @TODO add logging call here and with resulting return value  */

        if (user_id == WH_USER_ID_INVALID) {
            /* allow user login request attempt and comm */
            if (group == WH_MESSAGE_GROUP_COMM ||
                (group == WH_MESSAGE_GROUP_AUTH &&
                 action == WH_MESSAGE_AUTH_ACTION_LOGIN)) {
                rc = WH_ERROR_OK;
            }
            else {
                rc = WH_ERROR_ACCESS;
            }
        }
        else {
            int groupIndex = (group >> 8) & 0xFF;

            /* A user logged in should by default have access to logging out */
            if (group == WH_MESSAGE_GROUP_AUTH &&
                action == WH_MESSAGE_AUTH_ACTION_LOGOUT) {
                rc = WH_ERROR_OK;
            }
            else {
                /* Validate groupIndex is within bounds */
                if (groupIndex >= WH_NUMBER_OF_GROUPS || groupIndex < 0) {
                    rc = WH_ERROR_ACCESS;
                }
                else if (user->permissions.groupPermissions[groupIndex]) {
                    /* Check if action is within supported range */
                    if (action < WH_AUTH_ACTIONS_PER_GROUP) {
                        /* Get word index and bitmask for this action */
                        uint32_t wordIndex;
                        uint32_t bitmask;

                        WH_AUTH_ACTION_TO_WORD_AND_BITMASK(action, wordIndex,
                                                           bitmask);

                        if (wordIndex < WH_AUTH_ACTION_WORDS &&
                            (user->permissions
                                 .actionPermissions[groupIndex][wordIndex] &
                             bitmask)) {
                            rc = WH_ERROR_OK;
                        }
                        else {
                            rc = WH_ERROR_ACCESS;
                        }
                    }
                    else {
                        rc = WH_ERROR_ACCESS;
                    }
                }
                else {
                    rc = WH_ERROR_ACCESS;
                }
            }
        }

        /* allow authorization override if callback is set */
        if (context->cb->CheckRequestAuthorization != NULL) {
            rc = context->cb->CheckRequestAuthorization(context->context, rc,
                                                        user_id, group, action);
        }
        (void)WH_AUTH_UNLOCK(context);
    } /* LOCK() */
    return rc;
}


/* Check on key ID use after request has been parsed */
int wh_Auth_CheckKeyAuthorization(whAuthContext* context, uint32_t key_id,
                                  uint16_t action)
{
    uint16_t    user_id;
    int         rc = WH_ERROR_ACCESS;
    int         i;
    whAuthUser* user;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        /* Reset rc to default access denied after successful lock */
        rc = WH_ERROR_ACCESS;

        user_id = context->user.user_id;
        user    = &context->user;
        if (user->user_id == WH_USER_ID_INVALID) {
            (void)WH_AUTH_UNLOCK(context);
            return WH_ERROR_ACCESS;
        }

        /* Check if the requested key_id is in the user's keyIds array */
        for (i = 0; i < user->permissions.keyIdCount && i < WH_AUTH_MAX_KEY_IDS;
             i++) {
            if (user->permissions.keyIds[i] == key_id) {
                rc = WH_ERROR_OK;
                break;
            }
        }

        if (context->cb->CheckKeyAuthorization != NULL) {
            rc = context->cb->CheckKeyAuthorization(context->context, rc,
                user_id, key_id, action);
        }
        (void)WH_AUTH_UNLOCK(context);
    } /* LOCK() */
    return rc;
}

/********** API That Manages User Database ******************************/

int wh_Auth_UserAdd(whAuthContext* context, const char* username,
                    whUserId* out_user_id, whAuthPermissions permissions,
                    whAuthMethod method, const void* credentials,
                    uint16_t credentials_len)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->UserAdd == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        /* only an admin level user can add another admin level user */
        if (WH_AUTH_IS_ADMIN(permissions) &&
            !WH_AUTH_IS_ADMIN(context->user.permissions)) {
            rc = WH_AUTH_PERMISSION_ERROR;
        }
        else {
            rc =
                context->cb->UserAdd(context->context, username, out_user_id,
                             permissions, method, credentials, credentials_len);
        }
        (void)WH_AUTH_UNLOCK(context);
    } /* LOCK() */
    return rc;
}


int wh_Auth_UserDelete(whAuthContext* context, whUserId user_id)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->UserDelete == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        rc = context->cb->UserDelete(context->context, context->user.user_id,
                                     user_id);

        (void)WH_AUTH_UNLOCK(context);
    }  /* LOCK() */
    return rc;
}


int wh_Auth_UserSetPermissions(whAuthContext* context, whUserId user_id,
                               whAuthPermissions permissions)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->UserSetPermissions == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = context->cb->UserSetPermissions(
        context->context, context->user.user_id, user_id, permissions);

    (void)WH_AUTH_UNLOCK(context);
    return rc;
}

int wh_Auth_UserGet(whAuthContext* context, const char* username,
                    whUserId* out_user_id, whAuthPermissions* out_permissions)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->UserGet == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        rc = context->cb->UserGet(context->context, username, out_user_id,
                                  out_permissions);

        (void)WH_AUTH_UNLOCK(context);
    }  /* LOCK() */
    return rc;
}

int wh_Auth_UserSetCredentials(whAuthContext* context, whUserId user_id,
                               whAuthMethod method,
                               const void*  current_credentials,
                               uint16_t     current_credentials_len,
                               const void*  new_credentials,
                               uint16_t     new_credentials_len)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL) ||
        (context->cb->UserSetCredentials == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = WH_AUTH_LOCK(context);
    if (rc == WH_ERROR_OK) {
        rc = context->cb->UserSetCredentials(
            context->context, user_id, method, current_credentials,
            current_credentials_len, new_credentials, new_credentials_len);

        (void)WH_AUTH_UNLOCK(context);
    }  /* LOCK() */
    return rc;
}


/********** Lock/Unlock Functions for Thread Safety *************************/

#ifdef WOLFHSM_CFG_THREADSAFE
int wh_Auth_Lock(whAuthContext* auth)
{
    if (auth == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Lock_Acquire(&auth->lock);
}


int wh_Auth_Unlock(whAuthContext* auth)
{
    if (auth == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Lock_Release(&auth->lock);
}
#endif /* WOLFHSM_CFG_THREADSAFE */
