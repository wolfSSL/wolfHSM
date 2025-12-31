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

 /* This contains a basic authentication implementation. */


/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_auth_base.h"

/* simple base user list */
#define WH_AUTH_BASE_MAX_USERS 5
#define WH_AUTH_BASE_MAX_CREDENTIALS_LEN 2048
typedef struct whAuthBase_User {
    whAuthUser user;
    whAuthMethod method;
    unsigned char credentials[WH_AUTH_BASE_MAX_CREDENTIALS_LEN];
    uint16_t credentials_len;
} whAuthBase_User;
static whAuthBase_User users[WH_AUTH_BASE_MAX_USERS];

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

int wh_AuthBase_Init(void* context, const void *config)
{
    /* TODO: Initialize auth manager context */
    (void)context;
    (void)config;
    return WH_ERROR_OK;
}

int wh_AuthBase_Cleanup(void* context)
{
    /* TODO: Cleanup auth manager context */
    (void)context;
    return WH_ERROR_NOTIMPL;
}

static whAuthBase_User* FindUser(const char* username)
{
    int i;
    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        if (strcmp(users[i].user.username, username) == 0) {
            return &users[i];
        }
    }
    return NULL;
}

static whAuthBase_User* CheckPin(const char* username, const void* auth_data, uint16_t auth_data_len)
{
    whAuthBase_User* found_user;
    found_user = FindUser(username);
    if (found_user != NULL &&
        found_user->credentials_len == auth_data_len &&
        memcmp(found_user->credentials, auth_data, auth_data_len) == 0) {
        return found_user;
    }
    return NULL;
}


static int VerifyCertificate(whAuthBase_User* found_user, const uint8_t* certificate, uint16_t certificate_len)
{
    int rc = WH_ERROR_OK;
    int err;
    WOLFSSL_CERT_MANAGER* cm = NULL;
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        return WH_ERROR_ABORTED;
    }
    err = wolfSSL_CertManagerLoadCABuffer(cm, found_user->credentials,
        found_user->credentials_len, WOLFSSL_FILETYPE_ASN1);
    if (err != WOLFSSL_SUCCESS) {
        rc = WH_ERROR_ABORTED;
    }
    err = wolfSSL_CertManagerVerifyBuffer(cm, certificate, certificate_len,
                                         WOLFSSL_FILETYPE_ASN1);
    if (err != WOLFSSL_SUCCESS) {
        rc = WH_ERROR_ABORTED;
    }
    wolfSSL_CertManagerFree(cm);
    return rc;
}

static whAuthBase_User* CheckCertificate(const char* username, const void* auth_data, uint16_t auth_data_len)
{
    whAuthBase_User* found_user;
    found_user = FindUser(username);
    if (found_user != NULL &&
        found_user->method == WH_AUTH_METHOD_CERTIFICATE &&
        found_user->credentials_len > 0) {
        if (VerifyCertificate(found_user, auth_data, auth_data_len) == WH_ERROR_OK) {
            return found_user;
        }
    }
    return NULL;
}

int wh_AuthBase_Login(void* context, uint8_t client_id,
                          whAuthMethod method, const char* username,
                          const void* auth_data,
                          uint16_t auth_data_len,
                          uint16_t* out_user_id,
                          whAuthPermissions* out_permissions,
                          int* loggedIn)
{
    whAuthBase_User* current_user = NULL;

    if ((out_user_id == NULL) ||
        (out_permissions == NULL) ||
        (loggedIn == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    *loggedIn = 0;

    (void)client_id;
    switch (method) {
        case WH_AUTH_METHOD_PIN:
            current_user = CheckPin(username, auth_data, auth_data_len);
            break;
        case WH_AUTH_METHOD_CERTIFICATE:
            current_user = CheckCertificate(username, auth_data, auth_data_len);
            break;
        default:
            return WH_ERROR_BADARGS;
    }

    if (current_user != NULL) {
        if (current_user->user.is_active) {
            /* Can not be logged in if already logged in */
            *loggedIn = 0;
        }
        else {
            *loggedIn = 1;
            *out_user_id = current_user->user.user_id;
            current_user->user.is_active = true;
        }
    }

    (void)context;
    return WH_ERROR_OK;
}

int wh_AuthBase_Logout(void* context, uint16_t user_id)
{
    whAuthBase_User* user;

    if (user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_BADARGS;
    }

    if (user_id - 1 >= WH_AUTH_BASE_MAX_USERS) {
        return WH_ERROR_NOTFOUND;
    }

    /* @TODO there likely should be restrictions here on who can logout who */

    user = &users[user_id - 1];
    user->user.is_active = false;
    (void)context;
    return WH_ERROR_OK;
}


int wh_AuthBase_CheckRequestAuthorization(void* context,
    uint8_t client_id, uint16_t group, uint16_t action)
{
    int rc;
    whAuthContext* auth_context = (whAuthContext*)context;


    printf("In authorization check: Client ID: %d, Group: %d, Action: %d\n",
        client_id, group, action);

    if (auth_context == NULL) {
        printf("This likely should be fail case when no authorization context is set\n");
        return WH_ERROR_OK;
    }

    if (auth_context->user.user_id == WH_USER_ID_INVALID) {
        /* allow user login request attempt */
        if (group == WH_MESSAGE_GROUP_AUTH &&
            action == WH_AUTH_ACTION_LOGIN) {
            rc = WH_ERROR_OK;
        }
        else {
            printf("No user associated with session");
            rc = WH_ERROR_ACCESS;
        }
    }
    else {
        int groupIndex = (group >> 8) & 0xFF;

        /* check if user has permissions for the group and action */
        if (auth_context->user.permissions.groupPermissions & group) {
            if (auth_context->user.permissions.actionPermissions[groupIndex] & action) {
                rc = WH_ERROR_OK;
            }
            else {
                printf("User does not have permissions for the action");
                rc = WH_ERROR_ACCESS;
            }
        }
        else {
            printf("User does not have permissions for the group");
            rc = WH_ERROR_ACCESS;
        }
    }

    return rc;
}

/* authorization check on key usage after the request has been parsed and before
 * the action is done */
int wh_AuthBase_CheckKeyAuthorization(void* context, uint8_t client_id,
    uint32_t key_id, uint16_t action)
{
    int rc;
    whAuthContext* auth_context = (whAuthContext*)context;

    printf("In key authorization check: Client ID: %d, Key ID: %d, Action: %d\n",
        client_id, key_id, action);

    if (auth_context->user.user_id == WH_USER_ID_INVALID) {
        rc = WH_ERROR_ACCESS;
    }
    else {
        if (auth_context->user.permissions.keyId == key_id) {
            rc = WH_ERROR_OK;
        }
        else {
            printf("User does not have access to the key");
            rc = WH_ERROR_ACCESS;
        }
    }

    return rc;
}


int wh_AuthBase_UserAdd(void* context, const char* username,
    uint16_t* out_user_id, whAuthPermissions permissions,
    whAuthMethod method, const void* credentials, uint16_t credentials_len)
{
    whAuthContext* auth_context = (whAuthContext*)context;
    whAuthBase_User* new_user;
    int i;
    int userId = WH_USER_ID_INVALID;

    /* Validate method is supported if credentials are provided */
    if (credentials != NULL && credentials_len > 0) {
        if (method != WH_AUTH_METHOD_PIN && method != WH_AUTH_METHOD_CERTIFICATE) {
            return WH_ERROR_BADARGS;
        }
    }

    for (i = 0; i < WH_AUTH_BASE_MAX_USERS; i++) {
        if (users[i].user.user_id == WH_USER_ID_INVALID) {
            break;
        }
    }

    if (i >= WH_AUTH_BASE_MAX_USERS) {
        printf("User list is full");
        return WH_ERROR_BUFFER_SIZE;
    }
    userId = i + 1; /* save 0 fron WH_USER_ID_INVALID */
    new_user = &users[i];
    
    memset(new_user, 0, sizeof(whAuthBase_User));
    new_user->user.user_id = userId;
    *out_user_id = userId;
    new_user->user.permissions = permissions;
    strcpy(new_user->user.username, username);
    new_user->user.is_active = false;
    new_user->user.failed_attempts = 0;
    new_user->user.lockout_until = 0;

    /* Set credentials if provided */
    if (credentials != NULL && credentials_len > 0) {
        if (credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
            return WH_ERROR_BUFFER_SIZE;
        }
        new_user->method = method;
        memcpy(new_user->credentials, credentials, credentials_len);
        new_user->credentials_len = credentials_len;
    }

    (void)auth_context;
    return WH_ERROR_OK;
}

int wh_AuthBase_UserDelete(void* context, uint16_t user_id)
{
    whAuthContext* auth_context = (whAuthContext*)context;
    whAuthBase_User* user = &users[user_id];
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }
    memset(user, 0, sizeof(whAuthBase_User));
    (void)auth_context;
    return WH_ERROR_OK;
}

int wh_AuthBase_UserSetPermissions(void* context, uint16_t user_id,
    whAuthPermissions permissions)
{
    whAuthContext* auth_context = (whAuthContext*)context;
    whAuthBase_User* user = &users[user_id];
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }
    user->user.permissions = permissions;
    (void)auth_context;
    return WH_ERROR_OK;
}

int wh_AuthBase_UserGet(void* context, uint16_t user_id,
    whAuthUser* out_user)
{
    whAuthContext* auth_context = (whAuthContext*)context;
    whAuthBase_User* user = &users[user_id];
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }
    memcpy(out_user, &user->user, sizeof(whAuthUser));
    (void)auth_context;
    return WH_ERROR_OK;
}

int wh_AuthBase_UserSetCredentials(void* context, uint16_t user_id,
    whAuthMethod method,
    const void* current_credentials, uint16_t current_credentials_len,
    const void* new_credentials, uint16_t new_credentials_len)
{
    whAuthContext* auth_context = (whAuthContext*)context;
    whAuthBase_User* user;
    int rc = WH_ERROR_OK;

    if (user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_BADARGS;
    }

    /* Validate method is supported */
    if (method != WH_AUTH_METHOD_PIN && method != WH_AUTH_METHOD_CERTIFICATE) {
        return WH_ERROR_BADARGS;
    }

    user = &users[user_id - 1]; /* subtract 1 to get the index */
    
    if (user->user.user_id == WH_USER_ID_INVALID) {
        return WH_ERROR_NOTFOUND;
    }

    /* Verify current credentials if user has existing credentials */
    if (user->credentials_len > 0) {
        /* User has existing credentials, so current_credentials must be provided and match */
        if (current_credentials == NULL || current_credentials_len == 0) {
            return WH_ERROR_ACCESS;
        }
        if (user->credentials_len != current_credentials_len ||
            memcmp(user->credentials, current_credentials, current_credentials_len) != 0) {
            return WH_ERROR_ACCESS;
        }
    } else {
        /* User has no existing credentials, current_credentials should be NULL */
        if (current_credentials != NULL && current_credentials_len > 0) {
            return WH_ERROR_BADARGS;
        }
    }

    /* Set new credentials */
    if (new_credentials_len > WH_AUTH_BASE_MAX_CREDENTIALS_LEN) {
        return WH_ERROR_BUFFER_SIZE;
    }
    user->method = method;
    if (new_credentials_len > 0) {
        memcpy(user->credentials, new_credentials, new_credentials_len);
        user->credentials_len = new_credentials_len;
    } else {
        /* Allow clearing credentials by setting length to 0 */
        user->credentials_len = 0;
    }

    (void)auth_context;
    return rc;
}