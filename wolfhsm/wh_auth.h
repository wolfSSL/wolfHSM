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
 * wolfhsm/wh_auth.h
 *
 * Abstract library to provide authentication and authorization management.
 * The Auth Manager is transport-agnostic and protocol-agnostic, providing
 * core security services for all wolfHSM operations.
 *
 * The Auth Manager:
 * - Verifies PINs/credentials
 * - Manages sessions
 * - Makes authorization decisions
 * - Tracks session state and logs authentication attempts
 */

#ifndef WOLFHSM_WH_AUTH_H_
#define WOLFHSM_WH_AUTH_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stdbool.h>

#include "wolfhsm/wh_common.h"

/** Auth Manager Types */

/* User identifier type */
typedef uint16_t whUserId;
#define WH_USER_ID_INVALID ((whUserId)0)

/* Authentication method enumeration */
typedef enum {
    WH_AUTH_METHOD_NONE = 0,
    WH_AUTH_METHOD_PIN,
    WH_AUTH_METHOD_CERTIFICATE,
    WH_AUTH_METHOD_CHALLENGE_RESPONSE,
    WH_AUTH_METHOD_PSK,
} whAuthMethod;


typedef struct {
    uint16_t groupPermissions; /* bit mask of if allowed for use in group */
    uint16_t actionPermissions[14]; /* array of action permissions for each group */
    uint32_t keyId; /* key ID that user has access to */
} whAuthPermissions;

/* User information */
typedef struct {
    whUserId user_id;
    char username[32];  /* Max username length */
    whAuthPermissions permissions;
    bool is_active;
    uint32_t failed_attempts;
    uint32_t lockout_until;  /* Timestamp when lockout expires */
} whAuthUser;

/** Auth Manager Callback Structure */

typedef struct {
    /* Initialize the auth backend */
    int (*Init)(void* context, const void *config);

    /* Cleanup the auth backend */
    int (*Cleanup)(void* context);

    /* Authenticate a user using the specified method */
    int (*Login)(void* context, uint8_t client_id,
                        whAuthMethod method, const char* username,
                        const void* auth_data,
                        uint16_t auth_data_len,
                        whUserId* out_user_id,
                        whAuthPermissions* out_permissions,
                        int* loggedIn);

    /* Logout a user */
    int (*Logout)(void* context, whUserId user_id);
    

    /* Check if an action is authorized for a session */
    int (*CheckRequestAuthorization)(void* context, uint8_t client_id,
                              uint16_t group, uint16_t action);

    /* Check if a key is authorized for use */
    int (*CheckKeyAuthorization)(void* context, uint8_t client_id,
                                 uint32_t key_id, uint16_t action);

    /* Add a new user */
    int (*UserAdd)(void* context, const char* username, whUserId* out_user_id,
                   whAuthPermissions permissions);

    /* Delete a user */
    int (*UserDelete)(void* context, whUserId user_id);

    /* Set user permissions */
    int (*UserSetPermissions)(void* context, whUserId user_id,
                               whAuthPermissions permissions);

    /* Get user information */
    int (*UserGet)(void* context, whUserId user_id, whAuthUser* out_user);

    /* Set user credentials (PIN, etc.) */
    int (*UserSetCredentials)(void* context, whUserId user_id,
                              whAuthMethod method, const void* credentials,
                              uint16_t credentials_len);
} whAuthCb;

/** Auth Manager Context and Config */

/* Simple helper context structure associated with an Auth Manager instance */
typedef struct whAuthContext_t {
    whAuthCb *cb;
    whAuthUser user;
    void* context;
} whAuthContext;

/* Simple helper configuration structure associated with an Auth Manager instance */
typedef struct whAuthConfig_t {
    whAuthCb *cb;
    void* context;
    void* config;
} whAuthConfig;

/** Public Auth Manager API Functions */

/* Initialize the auth manager */
int wh_Auth_Init(whAuthContext* context, const whAuthConfig *config);

/* Cleanup the auth manager */
int wh_Auth_Cleanup(whAuthContext* context);

/* Authenticate and login a user */
int wh_Auth_Login(whAuthContext* context, uint8_t client_id,
    whAuthMethod method, const char* username, const void* auth_data,
    uint16_t auth_data_len, int* loggedIn);

/* Logout a user */
int wh_Auth_Logout(whAuthContext* context, whUserId user_id);

/* Check authorization for an action */
int wh_Auth_CheckRequestAuthorization(whAuthContext* context, uint8_t client_id,
    uint16_t group, uint16_t action);

int wh_Auth_CheckKeyAuthorization(whAuthContext* context, uint8_t client_id,
    uint32_t key_id, uint16_t action);

/* Add a new user */
int wh_Auth_UserAdd(whAuthContext* context, const char* username,
                     whUserId* out_user_id, whAuthPermissions permissions);

/* Delete a user */
int wh_Auth_UserDelete(whAuthContext* context, whUserId user_id);

/* Set user permissions */
int wh_Auth_UserSetPermissions(whAuthContext* context, whUserId user_id,
                                 whAuthPermissions permissions);

/* Get user information */
int wh_Auth_UserGet(whAuthContext* context, whUserId user_id,
                     whAuthUser* out_user);

/* Set user credentials */
int wh_Auth_UserSetCredentials(whAuthContext* context, whUserId user_id,
                                 whAuthMethod method, const void* credentials,
                                 uint16_t credentials_len);
#endif /* !WOLFHSM_WH_AUTH_H_ */
