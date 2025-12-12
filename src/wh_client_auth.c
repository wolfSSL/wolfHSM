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
 * src/wh_client_auth.c
 *
 * Client-side Auth Manager API
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT

/* System libraries */
#include <string.h>  /* For memcpy, strncpy */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_auth.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_auth.h"

/** Authenticate */
int wh_Client_AuthAuthenticateRequest(whClientContext* c,
        whAuthMethod method, const void* auth_data, uint16_t auth_data_len)
{
    /* TODO: Send authenticate request (non-blocking).
     * Builds and sends the authentication request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)method;
    (void)auth_data;
    (void)auth_data_len;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthAuthenticateResponse(whClientContext* c, int32_t *out_rc,
        whUserId* out_user_id, whSessionId* out_session_id,
        whAuthPermissions* out_permissions)
{
    /* TODO: Receive authenticate response (non-blocking).
     * Polls for and processes the authentication response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_user_id;
    (void)out_session_id;
    (void)out_permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthAuthenticate(whClientContext* c, whAuthMethod method,
        const void* auth_data, uint16_t auth_data_len,
        int32_t* out_rc, whUserId* out_user_id, whSessionId* out_session_id,
        whAuthPermissions* out_permissions)
{
    /* TODO: Authenticate (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * authentication succeeds or fails. */
    (void)c;
    (void)method;
    (void)auth_data;
    (void)auth_data_len;
    (void)out_rc;
    (void)out_user_id;
    (void)out_session_id;
    (void)out_permissions;
    return WH_ERROR_NOTIMPL;
}

/** Session Create */
int wh_Client_AuthSessionCreateRequest(whClientContext* c,
        whUserId user_id, whAuthPermissions permissions)
{
    /* TODO: Send session create request (non-blocking).
     * Builds and sends the session create request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)user_id;
    (void)permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionCreateResponse(whClientContext* c, int32_t *out_rc,
        whSessionId* out_session_id)
{
    /* TODO: Receive session create response (non-blocking).
     * Polls for and processes the session create response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_session_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionCreate(whClientContext* c, whUserId user_id,
        whAuthPermissions permissions, int32_t* out_rc,
        whSessionId* out_session_id)
{
    /* TODO: Create session (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * session is created or operation fails. */
    (void)c;
    (void)user_id;
    (void)permissions;
    (void)out_rc;
    (void)out_session_id;
    return WH_ERROR_NOTIMPL;
}

/** Session Destroy */
int wh_Client_AuthSessionDestroyRequest(whClientContext* c,
        whSessionId session_id)
{
    /* TODO: Send session destroy request (non-blocking).
     * Builds and sends the session destroy request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)session_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionDestroyResponse(whClientContext* c, int32_t *out_rc)
{
    /* TODO: Receive session destroy response (non-blocking).
     * Polls for and processes the session destroy response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionDestroy(whClientContext* c, whSessionId session_id,
        int32_t* out_rc)
{
    /* TODO: Destroy session (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * session is destroyed or operation fails. */
    (void)c;
    (void)session_id;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

/** Session Get */
int wh_Client_AuthSessionGetRequest(whClientContext* c, whSessionId session_id)
{
    /* TODO: Send session get request (non-blocking).
     * Builds and sends the session get request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)session_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionGetResponse(whClientContext* c, int32_t *out_rc,
        whAuthSession* out_session)
{
    /* TODO: Receive session get response (non-blocking).
     * Polls for and processes the session get response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_session;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionGet(whClientContext* c, whSessionId session_id,
        int32_t* out_rc, whAuthSession* out_session)
{
    /* TODO: Get session (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * session information is retrieved or operation fails. */
    (void)c;
    (void)session_id;
    (void)out_rc;
    (void)out_session;
    return WH_ERROR_NOTIMPL;
}

/** Session Status */
int wh_Client_AuthSessionStatusRequest(whClientContext* c)
{
    /* TODO: Send session status request (non-blocking).
     * Builds and sends the session status request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionStatusResponse(whClientContext* c, int32_t *out_rc,
        uint32_t* out_active_sessions,
        whSessionId* out_session_list, uint16_t max_sessions)
{
    /* TODO: Receive session status response (non-blocking).
     * Polls for and processes the session status response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_active_sessions;
    (void)out_session_list;
    (void)max_sessions;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthSessionStatus(whClientContext* c, int32_t* out_rc,
        uint32_t* out_active_sessions,
        whSessionId* out_session_list, uint16_t max_sessions)
{
    /* TODO: Get session status (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * session status is retrieved or operation fails. */
    (void)c;
    (void)out_rc;
    (void)out_active_sessions;
    (void)out_session_list;
    (void)max_sessions;
    return WH_ERROR_NOTIMPL;
}

/** User Add */
int wh_Client_AuthUserAddRequest(whClientContext* c, const char* username,
        whAuthPermissions permissions)
{
    /* TODO: Send user add request (non-blocking).
     * Builds and sends the user add request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)username;
    (void)permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserAddResponse(whClientContext* c, int32_t *out_rc,
        whUserId* out_user_id)
{
    /* TODO: Receive user add response (non-blocking).
     * Polls for and processes the user add response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_user_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserAdd(whClientContext* c, const char* username,
        whAuthPermissions permissions, int32_t* out_rc, whUserId* out_user_id)
{
    /* TODO: Add user (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * user is added or operation fails. */
    (void)c;
    (void)username;
    (void)permissions;
    (void)out_rc;
    (void)out_user_id;
    return WH_ERROR_NOTIMPL;
}

/** User Delete */
int wh_Client_AuthUserDeleteRequest(whClientContext* c, whUserId user_id)
{
    /* TODO: Send user delete request (non-blocking).
     * Builds and sends the user delete request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)user_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserDeleteResponse(whClientContext* c, int32_t *out_rc)
{
    /* TODO: Receive user delete response (non-blocking).
     * Polls for and processes the user delete response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserDelete(whClientContext* c, whUserId user_id,
        int32_t* out_rc)
{
    /* TODO: Delete user (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * user is deleted or operation fails. */
    (void)c;
    (void)user_id;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

/** User Get */
int wh_Client_AuthUserGetRequest(whClientContext* c, whUserId user_id)
{
    /* TODO: Send user get request (non-blocking).
     * Builds and sends the user get request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)user_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserGetResponse(whClientContext* c, int32_t *out_rc,
        whAuthUser* out_user)
{
    /* TODO: Receive user get response (non-blocking).
     * Polls for and processes the user get response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_user;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserGet(whClientContext* c, whUserId user_id,
        int32_t* out_rc, whAuthUser* out_user)
{
    /* TODO: Get user (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * user information is retrieved or operation fails. */
    (void)c;
    (void)user_id;
    (void)out_rc;
    (void)out_user;
    return WH_ERROR_NOTIMPL;
}

/** User Set Permissions */
int wh_Client_AuthUserSetPermissionsRequest(whClientContext* c,
        whUserId user_id, whAuthPermissions permissions)
{
    /* TODO: Send user set permissions request (non-blocking).
     * Builds and sends the user set permissions request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)user_id;
    (void)permissions;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserSetPermissionsResponse(whClientContext* c, int32_t *out_rc)
{
    /* TODO: Receive user set permissions response (non-blocking).
     * Polls for and processes the user set permissions response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserSetPermissions(whClientContext* c, whUserId user_id,
        whAuthPermissions permissions, int32_t* out_rc)
{
    /* TODO: Set user permissions (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * permissions are set or operation fails. */
    (void)c;
    (void)user_id;
    (void)permissions;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

/** User Set Credentials */
int wh_Client_AuthUserSetCredentialsRequest(whClientContext* c,
        whUserId user_id, whAuthMethod method, const void* credentials,
        uint16_t credentials_len)
{
    /* TODO: Send user set credentials request (non-blocking).
     * Builds and sends the user set credentials request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)user_id;
    (void)method;
    (void)credentials;
    (void)credentials_len;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserSetCredentialsResponse(whClientContext* c, int32_t *out_rc)
{
    /* TODO: Receive user set credentials response (non-blocking).
     * Polls for and processes the user set credentials response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthUserSetCredentials(whClientContext* c, whUserId user_id,
        whAuthMethod method, const void* credentials, uint16_t credentials_len,
        int32_t* out_rc)
{
    /* TODO: Set user credentials (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * credentials are set or operation fails. */
    (void)c;
    (void)user_id;
    (void)method;
    (void)credentials;
    (void)credentials_len;
    (void)out_rc;
    return WH_ERROR_NOTIMPL;
}

/** Check Authorization */
int wh_Client_AuthCheckAuthorizationRequest(whClientContext* c,
        whSessionId session_id, whAuthAction action, uint32_t object_id)
{
    /* TODO: Send check authorization request (non-blocking).
     * Builds and sends the check authorization request message. Returns immediately.
     * May return WH_ERROR_NOTREADY if send buffer is busy. */
    (void)c;
    (void)session_id;
    (void)action;
    (void)object_id;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthCheckAuthorizationResponse(whClientContext* c, int32_t *out_rc,
        bool* out_authorized)
{
    /* TODO: Receive check authorization response (non-blocking).
     * Polls for and processes the check authorization response. Returns immediately.
     * Returns WH_ERROR_NOTREADY if response not yet available. */
    (void)c;
    (void)out_rc;
    (void)out_authorized;
    return WH_ERROR_NOTIMPL;
}

int wh_Client_AuthCheckAuthorization(whClientContext* c,
        whSessionId session_id, whAuthAction action, uint32_t object_id,
        int32_t* out_rc, bool* out_authorized)
{
    /* TODO: Check authorization (blocking convenience wrapper).
     * Calls Request, then loops on Response until complete. Blocks until
     * authorization check completes or operation fails. */
    (void)c;
    (void)session_id;
    (void)action;
    (void)object_id;
    (void)out_rc;
    (void)out_authorized;
    return WH_ERROR_NOTIMPL;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
