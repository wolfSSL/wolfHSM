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
} whAuthMethod;

#define WH_NUMBER_OF_GROUPS 14
#define WH_AUTH_MAX_KEY_IDS \
    2 /* Maximum number of key IDs a user can have access to */
#define WH_AUTH_ACTIONS_PER_GROUP 256 /* Support up to 256 actions (0-255) */
#define WH_AUTH_ACTION_WORDS \
    ((WH_AUTH_ACTIONS_PER_GROUP + 31) / 32) /* 8 uint32_t words for 256 bits */

/* Convert action enum value (0-255) to bitmask and word index.
 * Returns the word index in the upper 16 bits and bitmask in lower 32 bits.
 * Use WH_AUTH_ACTION_WORD() and WH_AUTH_ACTION_BIT() to extract. */
#define WH_AUTH_ACTION_TO_WORD_AND_BIT(_action) \
    ((((_action) / 32) << 16) | (1UL << ((_action) % 32)))
#define WH_AUTH_ACTION_WORD(_word_and_bit) (((_word_and_bit) >> 16) & 0xFF)
#define WH_AUTH_ACTION_BIT(_word_and_bit) ((_word_and_bit) & 0xFFFFFFFFUL)

/* Legacy macro for backward compatibility - only works for actions < 32 */
#define WH_AUTH_ACTION_TO_BITMASK(_action) \
    (((_action) < 32) ? (1UL << (_action)) : 0)

typedef struct {
    uint16_t groupPermissions; /* bit mask of if allowed for use in group */
    uint32_t actionPermissions[WH_NUMBER_OF_GROUPS]
                              [WH_AUTH_ACTION_WORDS]; /* multi-word bit array
                                                          for action permissions
                                                          (256 bits per group) */
    uint16_t keyIdCount; /* Number of key IDs in the keyIds array (0 to
                            WH_AUTH_MAX_KEY_IDS) */
    uint32_t keyIds[WH_AUTH_MAX_KEY_IDS]; /* Array of key IDs that user has
                                             access to */
} whAuthPermissions;

/* User information */
typedef struct {
    whUserId          user_id;
    char              username[32]; /* Max username length */
    whAuthPermissions permissions;
    bool              is_active;
    uint32_t          failed_attempts;
    uint32_t          lockout_until; /* Timestamp when lockout expires */
} whAuthUser;

/** Auth Manager Callback Structure */

typedef struct {
    /* Initialize the auth backend */
    int (*Init)(void* context, const void* config);

    /* Cleanup the auth backend */
    int (*Cleanup)(void* context);

    /* Authenticate a user using the specified method */
    int (*Login)(void* context, uint8_t client_id, whAuthMethod method,
                 const char* username, const void* auth_data,
                 uint16_t auth_data_len, whUserId* out_user_id,
                 whAuthPermissions* out_permissions, int* loggedIn);

    /* Logout a user */
    int (*Logout)(void* context, whUserId current_user_id, whUserId user_id);


    /* Check if an action is authorized for a session */
    int (*CheckRequestAuthorization)(void* context, uint16_t user_id,
                                     uint16_t group, uint16_t action);

    /* Check if a key is authorized for use */
    int (*CheckKeyAuthorization)(void* context, uint16_t user_id,
                                 uint32_t key_id, uint16_t action);

    /* Add a new user */
    int (*UserAdd)(void* context, const char* username, whUserId* out_user_id,
                   whAuthPermissions permissions, whAuthMethod method,
                   const void* credentials, uint16_t credentials_len);

    /* Delete a user */
    int (*UserDelete)(void* context, whUserId current_user_id,
                      whUserId user_id);

    /* Set user permissions */
    int (*UserSetPermissions)(void* context, whUserId current_user_id,
                              whUserId user_id, whAuthPermissions permissions);

    /* Get user information by username */
    int (*UserGet)(void* context, const char* username, whUserId* out_user_id,
                   whAuthPermissions* out_permissions);

    /* Set user credentials (PIN, etc.) */
    int (*UserSetCredentials)(void* context, whUserId user_id,
                              whAuthMethod method,
                              const void*  current_credentials,
                              uint16_t     current_credentials_len,
                              const void*  new_credentials,
                              uint16_t     new_credentials_len);
} whAuthCb;

/** Auth Manager Context and Config */

/* Simple helper context structure associated with an Auth Manager instance */
typedef struct whAuthContext_t {
    whAuthCb*  cb;
    whAuthUser user;
    void*      context;
} whAuthContext;

#define WOLFHSM_MAX_CERTIFICATE_LEN 2048

/* Simple helper configuration structure associated with an Auth Manager
 * instance */
typedef struct whAuthConfig_t {
    whAuthCb* cb;
    void*     context;
    void*     config;
} whAuthConfig;

/** Public Auth Manager API Functions */

/**
 * @brief Initialize the auth manager.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] config Pointer to the auth configuration.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_Init(whAuthContext* context, const whAuthConfig* config);

/**
 * @brief Cleanup the auth manager.
 *
 * @param[in] context Pointer to the auth context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_Cleanup(whAuthContext* context);

/**
 * @brief Authenticate and login a user.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] client_id The client ID making the request.
 * @param[in] method The authentication method to use.
 * @param[in] username The username to authenticate.
 * @param[in] auth_data Pointer to the authentication data.
 * @param[in] auth_data_len Length of the authentication data.
 * @param[out] loggedIn Pointer to store the login status.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_Login(whAuthContext* context, uint8_t client_id,
                  whAuthMethod method, const char* username,
                  const void* auth_data, uint16_t auth_data_len, int* loggedIn);

/**
 * @brief Logout a user.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] user_id The user ID to logout.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_Logout(whAuthContext* context, whUserId user_id);

/**
 * @brief Check authorization for an action.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] group The group to check authorization for.
 * @param[in] action The action to check authorization for.
 * @return int Returns 0 if authorized, or a negative error code on failure.
 */
int wh_Auth_CheckRequestAuthorization(whAuthContext* context, uint16_t group,
                                      uint16_t action);

/**
 * @brief Check if a key is authorized for use. @TODO, this is a place holder
 * for calls to check key use but wolfHSM currently does not call it before key
 * use.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] key_id The key ID to check authorization for.
 * @param[in] action The action to check authorization for.
 * @return int Returns 0 if authorized, or a negative error code on failure.
 */
int wh_Auth_CheckKeyAuthorization(whAuthContext* context, uint32_t key_id,
                                  uint16_t action);

/**
 * @brief Add a new user.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] username The username for the new user.
 * @param[out] out_user_id Pointer to store the new user ID.
 * @param[in] permissions The permissions for the new user.
 * @param[in] method The authentication method for the new user.
 * @param[in] credentials Pointer to the credentials data.
 * @param[in] credentials_len Length of the credentials data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_UserAdd(whAuthContext* context, const char* username,
                    whUserId* out_user_id, whAuthPermissions permissions,
                    whAuthMethod method, const void* credentials,
                    uint16_t credentials_len);

/**
 * @brief Delete a user.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] user_id The user ID to delete.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_UserDelete(whAuthContext* context, whUserId user_id);

/**
 * @brief Set user permissions.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] user_id The user ID to set permissions for.
 * @param[in] permissions The new permissions to set.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_UserSetPermissions(whAuthContext* context, whUserId user_id,
                               whAuthPermissions permissions);

/**
 * @brief Get user information.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] username The username to look up.
 * @param[out] out_user_id Pointer to store the user ID.
 * @param[out] out_permissions Pointer to store the user permissions.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_UserGet(whAuthContext* context, const char* username,
                    whUserId* out_user_id, whAuthPermissions* out_permissions);

/**
 * @brief Set user credentials.
 *
 * @param[in] context Pointer to the auth context.
 * @param[in] user_id The user ID to set credentials for.
 * @param[in] method The authentication method.
 * @param[in] current_credentials Pointer to the current credentials data.
 * @param[in] current_credentials_len Length of the current credentials data.
 * @param[in] new_credentials Pointer to the new credentials data.
 * @param[in] new_credentials_len Length of the new credentials data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_UserSetCredentials(whAuthContext* context, whUserId user_id,
                               whAuthMethod method,
                               const void*  current_credentials,
                               uint16_t     current_credentials_len,
                               const void*  new_credentials,
                               uint16_t     new_credentials_len);
#endif /* !WOLFHSM_WH_AUTH_H_ */
