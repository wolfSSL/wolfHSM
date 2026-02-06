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
 * wolfhsm/wh_message_auth.h
 *
 * Message definitions for Auth Manager operations
 */

#ifndef WOLFHSM_WH_MESSAGE_AUTH_H_
#define WOLFHSM_WH_MESSAGE_AUTH_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_auth.h"

#define WH_MESSAGE_AUTH_MAX_USERNAME_LEN 32
#define WH_MESSAGE_AUTH_MAX_SESSIONS 16

/* Simple reusable response message */
typedef struct {
    int32_t rc;
} whMessageAuth_SimpleResponse;

/**
 * @brief Translate a simple response message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source simple response message.
 * @param[out] dest Pointer to the destination simple response message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateSimpleResponse(
    uint16_t magic, const whMessageAuth_SimpleResponse* src,
    whMessageAuth_SimpleResponse* dest);

/** Login Request */
typedef struct {
    uint16_t method;
    char     username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint16_t auth_data_len;
    /* auth_data follows */
} whMessageAuth_LoginRequest;

/**
 * @brief Translate a login request message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src_packet Pointer to the source packet data.
 * @param[in] src_size Size of the source packet.
 * @param[out] dest_header Pointer to the destination login request header.
 * @param[out] dest_auth_data Pointer to the destination buffer for auth data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateLoginRequest(
    uint16_t magic, const void* src_packet, uint16_t src_size,
    whMessageAuth_LoginRequest* dest_header, uint8_t* dest_auth_data);

/** Login Response */
typedef struct {
    int32_t  rc;
    uint16_t user_id;
} whMessageAuth_LoginResponse;

/**
 * @brief Translate a login response message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source login response message.
 * @param[out] dest Pointer to the destination login response message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateLoginResponse(
    uint16_t magic, const whMessageAuth_LoginResponse* src,
    whMessageAuth_LoginResponse* dest);

/** Logout Request */
typedef struct {
    uint16_t user_id;
    uint8_t  WH_PAD[2];
} whMessageAuth_LogoutRequest;

/**
 * @brief Translate a logout request message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source logout request message.
 * @param[out] dest Pointer to the destination logout request message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateLogoutRequest(
    uint16_t magic, const whMessageAuth_LogoutRequest* src,
    whMessageAuth_LogoutRequest* dest);

/** Logout Response (SimpleResponse) */

/* whAuthPermissions struct
 * uint8_t[WH_NUMBER_OF_GROUPS + 1] (groupPermissions, last byte is admin flag) +
 * uint32_t[WH_NUMBER_OF_GROUPS][WH_AUTH_ACTION_WORDS] (actionPermissions) +
 * uint16_t (keyIdCount) + uint32_t[WH_AUTH_MAX_KEY_IDS] (keyIds) */
#define WH_FLAT_PERMISSIONS_LEN                                                  \
    ((WH_NUMBER_OF_GROUPS + 1) + (4 * WH_NUMBER_OF_GROUPS * WH_AUTH_ACTION_WORDS) + \
     2 + (4 * WH_AUTH_MAX_KEY_IDS))

/**
 * @brief Flatten permissions structure into a byte buffer.
 *
 * @param[in] permissions Pointer to the permissions structure to flatten.
 * @param[out] buffer Pointer to the destination buffer.
 * @param[in] buffer_len Length of the destination buffer.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_FlattenPermissions(whAuthPermissions* permissions,
                                      uint8_t* buffer, uint16_t buffer_len);

/**
 * @brief Unflatten a byte buffer into a permissions structure.
 *
 * @param[in] buffer Pointer to the source buffer.
 * @param[in] buffer_len Length of the source buffer.
 * @param[out] permissions Pointer to the destination permissions structure.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_UnflattenPermissions(uint8_t* buffer, uint16_t buffer_len,
                                        whAuthPermissions* permissions);


/** User Add Request */
typedef struct {
    char     username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint8_t  permissions[WH_FLAT_PERMISSIONS_LEN];
    uint16_t method;
    uint16_t credentials_len;
    /* credentials follow */
} whMessageAuth_UserAddRequest;

/**
 * @brief Translate a user add request message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src_packet Pointer to the source packet data.
 * @param[in] src_size Size of the source packet.
 * @param[out] dest_header Pointer to the destination user add request header.
 * @param[out] dest_credentials Pointer to the destination buffer for
 * credentials.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserAddRequest(
    uint16_t magic, const void* src_packet, uint16_t src_size,
    whMessageAuth_UserAddRequest* dest_header, uint8_t* dest_credentials);

/** User Add Response */
typedef struct {
    int32_t  rc;
    uint16_t user_id;
    uint8_t  WH_PAD[2];
} whMessageAuth_UserAddResponse;

/**
 * @brief Translate a user add response message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source user add response message.
 * @param[out] dest Pointer to the destination user add response message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserAddResponse(
    uint16_t magic, const whMessageAuth_UserAddResponse* src,
    whMessageAuth_UserAddResponse* dest);

/** User Delete Request */
typedef struct {
    uint16_t user_id;
    uint8_t  WH_PAD[2];
} whMessageAuth_UserDeleteRequest;

/**
 * @brief Translate a user delete request message between different magic
 * numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source user delete request message.
 * @param[out] dest Pointer to the destination user delete request message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserDeleteRequest(
    uint16_t magic, const whMessageAuth_UserDeleteRequest* src,
    whMessageAuth_UserDeleteRequest* dest);

/** User Delete Response */
/* Use SimpleResponse */

/** User Get Request */
typedef struct {
    char    username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint8_t WH_PAD[2];
} whMessageAuth_UserGetRequest;

/**
 * @brief Translate a user get request message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source user get request message.
 * @param[out] dest Pointer to the destination user get request message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserGetRequest(
    uint16_t magic, const whMessageAuth_UserGetRequest* src,
    whMessageAuth_UserGetRequest* dest);

/** User Get Response */
typedef struct {
    int32_t  rc;
    uint16_t user_id;
    uint8_t  permissions[WH_FLAT_PERMISSIONS_LEN];
} whMessageAuth_UserGetResponse;

/**
 * @brief Translate a user get response message between different magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source user get response message.
 * @param[out] dest Pointer to the destination user get response message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserGetResponse(
    uint16_t magic, const whMessageAuth_UserGetResponse* src,
    whMessageAuth_UserGetResponse* dest);

/** User Set Permissions Request */
typedef struct {
    uint16_t user_id;
    uint8_t  permissions[WH_FLAT_PERMISSIONS_LEN];
} whMessageAuth_UserSetPermissionsRequest;

/**
 * @brief Translate a user set permissions request message between different
 * magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src Pointer to the source user set permissions request message.
 * @param[out] dest Pointer to the destination user set permissions request
 * message.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserSetPermissionsRequest(
    uint16_t magic, const whMessageAuth_UserSetPermissionsRequest* src,
    whMessageAuth_UserSetPermissionsRequest* dest);

/** User Set Permissions Response */
/* Use SimpleResponse */

/** User Set Credentials Request */
/* Header structure - credentials follow as variable-length data */
typedef struct {
    uint16_t user_id;
    uint16_t method;
    uint16_t current_credentials_len;
    uint16_t new_credentials_len;
    /* Variable-length data follows:
     *   current_credentials[current_credentials_len]
     *   new_credentials[new_credentials_len]
     */
} whMessageAuth_UserSetCredentialsRequest;

/**
 * @brief Translate a user set credentials request message between different
 * magic numbers.
 *
 * @param[in] magic The magic number for translation.
 * @param[in] src_packet Pointer to the source packet data.
 * @param[in] src_size Size of the source packet.
 * @param[out] dest_header Pointer to the destination user set credentials
 * request header.
 * @param[out] dest_current_creds Pointer to the destination buffer for current
 * credentials.
 * @param[out] dest_new_creds Pointer to the destination buffer for new
 * credentials.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_MessageAuth_TranslateUserSetCredentialsRequest(
    uint16_t magic, const void* src_packet, uint16_t src_size,
    whMessageAuth_UserSetCredentialsRequest* dest_header,
    uint8_t* dest_current_creds, uint8_t* dest_new_creds);

/** User Set Credentials Response */
/* Use SimpleResponse */

/*
 * Per-message maximum credential lengths based on actual header sizes.
 * These ensure each message type can use the maximum available space
 * in WOLFHSM_CFG_COMM_DATA_LEN for its variable-length credential data.
 */

/* Login: auth_data follows the LoginRequest header */
#define WH_MESSAGE_AUTH_LOGIN_MAX_AUTH_DATA_LEN \
    (WOLFHSM_CFG_COMM_DATA_LEN - sizeof(whMessageAuth_LoginRequest))

/* UserAdd: credentials follow the UserAddRequest header */
#define WH_MESSAGE_AUTH_USERADD_MAX_CREDENTIALS_LEN \
    (WOLFHSM_CFG_COMM_DATA_LEN - sizeof(whMessageAuth_UserAddRequest))

/* UserSetCredentials: both current and new credentials follow the header.
 * Each credential buffer can use up to half of the remaining space. */
#define WH_MESSAGE_AUTH_SETCREDS_MAX_CREDENTIALS_LEN \
    ((WOLFHSM_CFG_COMM_DATA_LEN - sizeof(whMessageAuth_UserSetCredentialsRequest)) / 2)

#endif /* !WOLFHSM_WH_MESSAGE_AUTH_H_ */
