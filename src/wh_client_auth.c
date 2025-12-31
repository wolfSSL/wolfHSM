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
int wh_Client_AuthLoginRequest(whClientContext* c,
        whAuthMethod method, const char* username, const void* auth_data,
        uint16_t auth_data_len)
{
    whMessageAuth_LoginRequest msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    strncpy(msg.username, username, sizeof(msg.username));
    msg.method = method;
    msg.auth_data_len = auth_data_len;
    memcpy(msg.auth_data, auth_data, auth_data_len);
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_AUTH, WH_MESSAGE_AUTH_ACTION_LOGIN,
            sizeof(msg), &msg);
}

int wh_Client_AuthLoginResponse(whClientContext* c, int32_t *out_rc,
        whUserId* out_user_id,
        whAuthPermissions* out_permissions)
{
    uint8_t                    buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageAuth_LoginResponse* msg = (whMessageAuth_LoginResponse*)buffer;

    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, buffer);
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_AUTH) ||
            (resp_action != WH_MESSAGE_AUTH_ACTION_LOGIN) ||
            (resp_size != sizeof(whMessageAuth_LoginResponse))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg->rc;
            }
            if (out_user_id != NULL) {
                *out_user_id = msg->user_id;
            }
            /* @TODO: Set permissions */
            (void)out_permissions;
        }
    }
    return rc;
}

int wh_Client_AuthLogin(whClientContext* c, whAuthMethod method,
        const char* username, const void* auth_data, uint16_t auth_data_len,
        int32_t* out_rc, whUserId* out_user_id,
        whAuthPermissions* out_permissions)
{
    int rc;

    do {
        rc = wh_Client_AuthLoginRequest(c, method, username, auth_data, auth_data_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != 0) {
        return rc;
    }

    do {
        rc = wh_Client_AuthLoginResponse(c, out_rc, out_user_id, out_permissions);
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

int wh_Client_AuthLogoutRequest(whClientContext* c, whUserId user_id)
{
    whMessageAuth_LogoutRequest msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    msg.user_id = user_id;
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_AUTH, WH_MESSAGE_AUTH_ACTION_LOGOUT,
            sizeof(msg), &msg);
}


int wh_Client_AuthLogoutResponse(whClientContext* c, int32_t *out_rc)
{
    uint8_t                    buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageAuth_SimpleResponse* msg = (whMessageAuth_SimpleResponse*)buffer;

    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, buffer);
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_AUTH) ||
            (resp_action != WH_MESSAGE_AUTH_ACTION_LOGOUT) ||
            (resp_size != sizeof(whMessageAuth_SimpleResponse))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg->rc;
            }
        }
    }
    return rc;
}

int wh_Client_AuthLogout(whClientContext* c, whUserId user_id,
        int32_t* out_rc)
{
    int rc;

    do {
        rc = wh_Client_AuthLogoutRequest(c, user_id);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != 0) {
        return rc;
    }

    do {
        rc = wh_Client_AuthLogoutResponse(c, out_rc);
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

/** User Add */
int wh_Client_AuthUserAddRequest(whClientContext* c, const char* username,
        whAuthPermissions permissions, whAuthMethod method,
        const void* credentials, uint16_t credentials_len)
{
    whMessageAuth_UserAddRequest msg = {0};

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    strncpy(msg.username, username, sizeof(msg.username));
    (void)permissions;
    msg.permissions = 10; /* @TODO: Set permissions */
    msg.method = method;
    msg.credentials_len = credentials_len;
    if (credentials != NULL && credentials_len > 0) {
        if (credentials_len > WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN) {
            return WH_ERROR_BUFFER_SIZE;
        }
        memcpy(msg.credentials, credentials, credentials_len);
    }
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_AUTH, WH_MESSAGE_AUTH_ACTION_USER_ADD,
            sizeof(msg), &msg);
}

int wh_Client_AuthUserAddResponse(whClientContext* c, int32_t *out_rc,
        whUserId* out_user_id)
{
    uint8_t                    buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageAuth_UserAddResponse* msg = (whMessageAuth_UserAddResponse*)buffer;
    uint16_t hdr_len = sizeof(*msg);

    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, buffer);
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_AUTH) ||
            (resp_action != WH_MESSAGE_AUTH_ACTION_USER_ADD) ||
            (resp_size < hdr_len) || (resp_size > sizeof(buffer)) ||
            (resp_size - hdr_len > sizeof(whMessageAuth_UserAddResponse))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg->rc;
            }
            if (out_user_id != NULL) {
                *out_user_id = msg->user_id;
            }
        }
    }
    return rc;
}

int wh_Client_AuthUserAdd(whClientContext* c, const char* username,
        whAuthPermissions permissions, whAuthMethod method,
        const void* credentials, uint16_t credentials_len,
        int32_t* out_rc, whUserId* out_user_id)
{
    int rc;

    do {
        rc = wh_Client_AuthUserAddRequest(c, username, permissions, method,
                credentials, credentials_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != 0) {
        return rc;
    }

    do {
        rc = wh_Client_AuthUserAddResponse(c, out_rc, out_user_id);
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
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
        whUserId user_id, whAuthMethod method,
        const void* current_credentials, uint16_t current_credentials_len,
        const void* new_credentials, uint16_t new_credentials_len)
{
    uint8_t buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageAuth_UserSetCredentialsRequest* msg = (whMessageAuth_UserSetCredentialsRequest*)buffer;
    uint8_t* msg_current_creds = buffer + sizeof(*msg);
    uint8_t* msg_new_creds = msg_current_creds + current_credentials_len;
    uint16_t total_size;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    /* Validate lengths */
    if (current_credentials_len > WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }
    if (new_credentials_len > WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Calculate total message size */
    total_size = sizeof(*msg) + current_credentials_len + new_credentials_len;
    if (total_size > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Build message header */
    msg->user_id = user_id;
    msg->method = method;
    msg->WH_PAD[0] = 0;
    msg->current_credentials_len = current_credentials_len;
    msg->new_credentials_len = new_credentials_len;

    /* Copy variable-length credential data */
    if (current_credentials != NULL && current_credentials_len > 0) {
        memcpy(msg_current_creds, current_credentials, current_credentials_len);
    }
    if (new_credentials != NULL && new_credentials_len > 0) {
        memcpy(msg_new_creds, new_credentials, new_credentials_len);
    }
    
    return wh_Client_SendRequest(c,
            WH_MESSAGE_GROUP_AUTH, WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS,
            total_size, buffer);
}

int wh_Client_AuthUserSetCredentialsResponse(whClientContext* c, int32_t *out_rc)
{
    uint8_t                    buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    whMessageAuth_SimpleResponse* msg = (whMessageAuth_SimpleResponse*)buffer;

    int rc = 0;
    uint16_t resp_group = 0;
    uint16_t resp_action = 0;
    uint16_t resp_size = 0;

    if (c == NULL){
        return WH_ERROR_BADARGS;
    }

    rc = wh_Client_RecvResponse(c,
            &resp_group, &resp_action,
            &resp_size, buffer);
    if (rc == 0) {
        /* Validate response */
        if ((resp_group != WH_MESSAGE_GROUP_AUTH) ||
            (resp_action != WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS) ||
            (resp_size != sizeof(whMessageAuth_SimpleResponse))) {
            /* Invalid message */
            rc = WH_ERROR_ABORTED;
        }
        else {
            /* Valid message */
            if (out_rc != NULL) {
                *out_rc = msg->rc;
            }
        }
    }
    return rc;
}

int wh_Client_AuthUserSetCredentials(whClientContext* c, whUserId user_id,
        whAuthMethod method,
        const void* current_credentials, uint16_t current_credentials_len,
        const void* new_credentials, uint16_t new_credentials_len,
        int32_t* out_rc)
{
    int rc;

    do {
        rc = wh_Client_AuthUserSetCredentialsRequest(c, user_id, method,
            current_credentials, current_credentials_len,
            new_credentials, new_credentials_len);
    } while (rc == WH_ERROR_NOTREADY);

    if (rc != 0) {
        return rc;
    }

    do {
        rc = wh_Client_AuthUserSetCredentialsResponse(c, out_rc);
    } while (rc == WH_ERROR_NOTREADY);

    return rc;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
