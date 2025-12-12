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
#include "wolfhsm/wh_comm.h"  /* For whClientId */

/** Auth Manager Types */

/* User identifier type */
typedef uint16_t whUserId;
#define WH_USER_ID_INVALID ((whUserId)0)
#define WH_USER_ID_ADMIN   ((whUserId)1)

/* Session identifier type */
typedef uint32_t whSessionId;
#define WH_SESSION_ID_INVALID ((whSessionId)0)

/* Authentication method enumeration */
typedef enum {
    WH_AUTH_METHOD_NONE = 0,
    WH_AUTH_METHOD_PIN,
    WH_AUTH_METHOD_CERTIFICATE,
    WH_AUTH_METHOD_CHALLENGE_RESPONSE,
    WH_AUTH_METHOD_PSK,
} whAuthMethod;

/* Permission flags */
typedef uint32_t whAuthPermissions;
#define WH_AUTH_PERM_NONE          ((whAuthPermissions)0x00000000)
#define WH_AUTH_PERM_READ          ((whAuthPermissions)0x00000001)
#define WH_AUTH_PERM_WRITE         ((whAuthPermissions)0x00000002)
#define WH_AUTH_PERM_EXEC          ((whAuthPermissions)0x00000004)
#define WH_AUTH_PERM_ADMIN         ((whAuthPermissions)0x00000008)
#define WH_AUTH_PERM_USER_MGMT     ((whAuthPermissions)0x00000010)
#define WH_AUTH_PERM_KEY_MGMT      ((whAuthPermissions)0x00000020)
#define WH_AUTH_PERM_NVM_MGMT      ((whAuthPermissions)0x00000040)
#define WH_AUTH_PERM_ALL           ((whAuthPermissions)0xFFFFFFFF)

/* Action types for authorization checks */
typedef enum {
    WH_ACTION_NONE = 0,
    WH_ACTION_OBJECT_READ,
    WH_ACTION_OBJECT_WRITE,
    WH_ACTION_OBJECT_DELETE,
    WH_ACTION_KEY_USE,
    WH_ACTION_KEY_EXPORT,
    WH_ACTION_USER_ADD,
    WH_ACTION_USER_DELETE,
    WH_ACTION_USER_MODIFY,
    WH_ACTION_PERMISSION_SET,
} whAuthAction;

/* Session state */
typedef struct {
    whSessionId session_id;
    whUserId user_id;
    uint8_t client_id;
    whAuthPermissions permissions;
    uint32_t created_time;
    uint32_t last_access_time;
    uint32_t timeout;
    bool is_valid;
} whAuthSession;

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
    int (*Authenticate)(void* context, uint8_t client_id,
                        whAuthMethod method, const void* auth_data,
                        uint16_t auth_data_len,
                        whUserId* out_user_id, whSessionId* out_session_id,
                        whAuthPermissions* out_permissions);

    /* Create a new session for an authenticated user */
    int (*SessionCreate)(void* context, whUserId user_id, uint8_t client_id,
                         whAuthPermissions permissions,
                         whSessionId* out_session_id);

    /* Destroy a session */
    int (*SessionDestroy)(void* context, whSessionId session_id);

    /* Get session information */
    int (*SessionGet)(void* context, whSessionId session_id,
                      whAuthSession* out_session);

    /* Check if an action is authorized for a session */
    int (*CheckAuthorization)(void* context, whSessionId session_id,
                              whAuthAction action, uint32_t object_id);

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

    /* Get session status/count */
    int (*SessionStatus)(void* context, uint8_t client_id,
                         uint32_t* out_active_sessions,
                         whSessionId* out_session_list, uint16_t max_sessions);
} whAuthCb;

/** Auth Manager Context and Config */

/* Simple helper context structure associated with an Auth Manager instance */
typedef struct whAuthContext_t {
    whAuthCb *cb;
    void* context;
} whAuthContext;

/* Simple helper configuration structure associated with an Auth Manager instance */
typedef struct whAuthConfig_t {
    whAuthCb *cb;
    void* context;
    void* config;
} whAuthConfig;

/** Common Auth Callback Function Type
 *
 * This callback can be used throughout wolfHSM when consulting the auth manager.
 * It provides a simple interface for authorization checks that can be called from
 * any component (NVM, Key Management, PKCS#11 handler, etc.)
 */
typedef int (*whAuthCommonCb)(void* auth_context, whSessionId session_id,
                                whAuthAction action, uint32_t object_id);

/** Public Auth Manager API Functions */

/* Initialize the auth manager */
int wh_Auth_Init(whAuthContext* context, const whAuthConfig *config);

/* Cleanup the auth manager */
int wh_Auth_Cleanup(whAuthContext* context);

/* Authenticate a user */
int wh_Auth_Authenticate(whAuthContext* context, uint8_t client_id,
                          whAuthMethod method, const void* auth_data,
                          uint16_t auth_data_len,
                          whUserId* out_user_id, whSessionId* out_session_id,
                          whAuthPermissions* out_permissions);

/* Create a new session */
int wh_Auth_SessionCreate(whAuthContext* context, whUserId user_id,
                           uint8_t client_id, whAuthPermissions permissions,
                           whSessionId* out_session_id);

/* Destroy a session */
int wh_Auth_SessionDestroy(whAuthContext* context, whSessionId session_id);

/* Get session information */
int wh_Auth_SessionGet(whAuthContext* context, whSessionId session_id,
                        whAuthSession* out_session);

/* Check authorization for an action */
int wh_Auth_CheckAuthorization(whAuthContext* context, whSessionId session_id,
                                whAuthAction action, uint32_t object_id);

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

/* Get session status */
int wh_Auth_SessionStatus(whAuthContext* context, uint8_t client_id,
                           uint32_t* out_active_sessions,
                           whSessionId* out_session_list, uint16_t max_sessions);

/** Common Auth Callback Helper
 *
 * This function provides a simple way to check authorization from any component
 * in wolfHSM. It can be used as a callback function pointer or called directly.
 *
 * @param[in] auth_context Pointer to the auth context (cast from void*)
 * @param[in] session_id The session ID to check authorization for
 * @param[in] action The action being requested
 * @param[in] object_id The object ID (if applicable, 0 for general actions)
 * @return int Returns 0 if authorized, WH_ERROR_ACCESS if denied, or other error codes
 */
int wh_Auth_CommonCallback(void* auth_context, whSessionId session_id,
                           whAuthAction action, uint32_t object_id);

#endif /* !WOLFHSM_WH_AUTH_H_ */
