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
 * wh_auth_base.h
 *
 * Basic authentication and authorization implementation.
 */

#ifndef WOLFHSM_WH_AUTH_BASE_H_
#define WOLFHSM_WH_AUTH_BASE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_auth.h"

/**
 * @brief Initialize the auth base implementation.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] config Pointer to the configuration data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseInit(void* context, const void* config);

/**
 * @brief Cleanup the auth base implementation.
 *
 * @param[in] context Pointer to the auth base context.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseCleanup(void* context);

/**
 * @brief Authenticate a user using the specified method.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] client_id The client ID making the request.
 * @param[in] method The authentication method to use.
 * @param[in] username The username to authenticate.
 * @param[in] auth_data Pointer to the authentication data.
 * @param[in] auth_data_len Length of the authentication data.
 * @param[out] out_user_id Pointer to store the authenticated user ID.
 * @param[out] out_permissions Pointer to store the user permissions.
 * @param[out] loggedIn Pointer to store the login status.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseLogin(void* context, uint8_t client_id, whAuthMethod method,
                      const char* username, const void* auth_data,
                      uint16_t auth_data_len, whUserId* out_user_id,
                      whAuthPermissions* out_permissions, int* loggedIn);

/**
 * @brief Logout a user.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] current_user_id The user ID of the current user performing the
 * logout.
 * @param[in] user_id The user ID to logout.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseLogout(void* context, uint16_t current_user_id,
                       uint16_t user_id);

/**
 * @brief Add a new user.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] username The username for the new user.
 * @param[out] out_user_id Pointer to store the new user ID.
 * @param[in] permissions The permissions for the new user.
 * @param[in] method The authentication method for the new user.
 * @param[in] credentials Pointer to the credentials data.
 * @param[in] credentials_len Length of the credentials data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseUserAdd(void* context, const char* username,
                        whUserId* out_user_id, whAuthPermissions permissions,
                        whAuthMethod method, const void* credentials,
                        uint16_t credentials_len);

/**
 * @brief Delete a user.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] current_user_id The user ID of the current user performing the
 * deletion.
 * @param[in] user_id The user ID to delete.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseUserDelete(void* context, uint16_t current_user_id,
                           uint16_t user_id);

/**
 * @brief Set user permissions.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] current_user_id The user ID of the current user performing the
 * operation.
 * @param[in] user_id The user ID to set permissions for.
 * @param[in] permissions The new permissions to set.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseUserSetPermissions(void* context, uint16_t current_user_id,
                                   uint16_t          user_id,
                                   whAuthPermissions permissions);

/**
 * @brief Get user information by username.
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] username The username to look up.
 * @param[out] out_user_id Pointer to store the user ID.
 * @param[out] out_permissions Pointer to store the user permissions.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseUserGet(void* context, const char* username,
                        whUserId*          out_user_id,
                        whAuthPermissions* out_permissions);

/**
 * @brief Set user credentials (PIN, etc.).
 *
 * @param[in] context Pointer to the auth base context.
 * @param[in] user_id The user ID to set credentials for.
 * @param[in] method The authentication method.
 * @param[in] current_credentials Pointer to the current credentials data.
 * @param[in] current_credentials_len Length of the current credentials data.
 * @param[in] new_credentials Pointer to the new credentials data.
 * @param[in] new_credentials_len Length of the new credentials data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Auth_BaseUserSetCredentials(void* context, uint16_t user_id,
                                   whAuthMethod method,
                                   const void*  current_credentials,
                                   uint16_t     current_credentials_len,
                                   const void*  new_credentials,
                                   uint16_t     new_credentials_len);

#endif /* WOLFHSM_WH_AUTH_BASE_H_ */
