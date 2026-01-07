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

enum WH_MESSAGE_AUTH_ACTION_ENUM {
    WH_MESSAGE_AUTH_ACTION_AUTHENTICATE      = 0x01,
    WH_MESSAGE_AUTH_ACTION_LOGIN             = 0x02,
    WH_MESSAGE_AUTH_ACTION_LOGOUT            = 0x03,
    WH_MESSAGE_AUTH_ACTION_USER_ADD          = 0x04,
    WH_MESSAGE_AUTH_ACTION_USER_DELETE       = 0x05,
    WH_MESSAGE_AUTH_ACTION_USER_GET          = 0x06,
    WH_MESSAGE_AUTH_ACTION_USER_SET_PERMISSIONS = 0x07,
    WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS = 0x08,
};

enum WH_MESSAGE_AUTH_MAX_ENUM {
    WH_MESSAGE_AUTH_MAX_USERNAME_LEN = 32,
    /* Reserve space for UserAddRequest fixed fields (username + permissions + method + credentials_len = 70 bytes) */
    WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN = WOLFHSM_CFG_COMM_DATA_LEN - 86,
    WH_MESSAGE_AUTH_MAX_SESSIONS = 16,
};

/* Simple reusable response message */
typedef struct {
    int32_t rc;
} whMessageAuth_SimpleResponse;

int wh_MessageAuth_TranslateSimpleResponse(uint16_t magic,
        const whMessageAuth_SimpleResponse* src,
        whMessageAuth_SimpleResponse* dest);

/** Login Request */
typedef struct {
    uint16_t method;
    char username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint16_t auth_data_len;
    uint8_t auth_data[WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN];
} whMessageAuth_LoginRequest;

int wh_MessageAuth_TranslateLoginRequest(uint16_t magic,
        const whMessageAuth_LoginRequest* src,
        whMessageAuth_LoginRequest* dest);

/** Login Response */
typedef struct {
    int32_t rc;
    uint16_t user_id;
    uint32_t permissions;
} whMessageAuth_LoginResponse;

int wh_MessageAuth_TranslateLoginResponse(uint16_t magic,
        const whMessageAuth_LoginResponse* src,
        whMessageAuth_LoginResponse* dest);

/** Logout Request */
typedef struct {
    uint16_t user_id;
    uint8_t WH_PAD[2];
} whMessageAuth_LogoutRequest;

int wh_MessageAuth_TranslateLogoutRequest(uint16_t magic,
        const whMessageAuth_LogoutRequest* src,
        whMessageAuth_LogoutRequest* dest);

/** Logout Response (SimpleResponse) */

/* whAuthPermissions struct
 * uint16_t + uint16_t[WH_NUMBER_OF_GROUPS] + uint32_t */
#define WH_FLAT_PERRMISIONS_LEN 2 + (2*WH_NUMBER_OF_GROUPS) + 4

int wh_MessageAuth_FlattenPermissions(whAuthPermissions* permissions,
    uint8_t* buffer, uint16_t buffer_len);
int wh_MessageAuth_UnflattenPermissions(uint8_t* buffer, uint16_t buffer_len,
    whAuthPermissions* permissions);


/** User Add Request */
typedef struct {
    char username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint8_t permissions[WH_FLAT_PERRMISIONS_LEN];
    uint16_t method;
    uint16_t credentials_len;
    uint8_t credentials[WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN];
} whMessageAuth_UserAddRequest;

int wh_MessageAuth_TranslateUserAddRequest(uint16_t magic,
        const whMessageAuth_UserAddRequest* src,
        whMessageAuth_UserAddRequest* dest);

/** User Add Response */
typedef struct {
    int32_t rc;
    uint16_t user_id;
    uint8_t WH_PAD[2];
} whMessageAuth_UserAddResponse;

int wh_MessageAuth_TranslateUserAddResponse(uint16_t magic,
        const whMessageAuth_UserAddResponse* src,
        whMessageAuth_UserAddResponse* dest);

/** User Delete Request */
typedef struct {
    uint16_t user_id;
    uint8_t WH_PAD[2];
} whMessageAuth_UserDeleteRequest;

int wh_MessageAuth_TranslateUserDeleteRequest(uint16_t magic,
        const whMessageAuth_UserDeleteRequest* src,
        whMessageAuth_UserDeleteRequest* dest);

/** User Delete Response */
/* Use SimpleResponse */

/** User Get Request */
typedef struct {
    char username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint8_t WH_PAD[2];
} whMessageAuth_UserGetRequest;

int wh_MessageAuth_TranslateUserGetRequest(uint16_t magic,
        const whMessageAuth_UserGetRequest* src,
        whMessageAuth_UserGetRequest* dest);

/** User Get Response */
typedef struct {
    int32_t rc;
    uint16_t user_id;
    uint8_t permissions[WH_FLAT_PERRMISIONS_LEN];
} whMessageAuth_UserGetResponse;

int wh_MessageAuth_TranslateUserGetResponse(uint16_t magic,
        const whMessageAuth_UserGetResponse* src,
        whMessageAuth_UserGetResponse* dest);

/** User Set Permissions Request */
typedef struct {
    uint16_t user_id;
    uint8_t WH_PAD[2];
    uint32_t permissions;
} whMessageAuth_UserSetPermissionsRequest;

int wh_MessageAuth_TranslateUserSetPermissionsRequest(uint16_t magic,
        const whMessageAuth_UserSetPermissionsRequest* src,
        whMessageAuth_UserSetPermissionsRequest* dest);

/** User Set Permissions Response */
/* Use SimpleResponse */

/** User Set Credentials Request */
/* Header structure - credentials follow as variable-length data */
typedef struct {
    uint16_t user_id;
    uint8_t method;
    uint8_t WH_PAD[1];  /* Padding for alignment */
    uint16_t current_credentials_len;
    uint16_t new_credentials_len;
    /* Variable-length data follows:
     *   current_credentials[current_credentials_len]
     *   new_credentials[new_credentials_len]
     */
} whMessageAuth_UserSetCredentialsRequest;

int wh_MessageAuth_TranslateUserSetCredentialsRequest(uint16_t magic,
        const void* src_packet, uint16_t src_size,
        whMessageAuth_UserSetCredentialsRequest* dest_header,
        uint8_t* dest_current_creds, uint8_t* dest_new_creds);

/** User Set Credentials Response */
/* Use SimpleResponse */

/** Check Authorization Request */
typedef struct {
    uint32_t session_id;
    uint8_t action;  /* whAuthAction */
    uint8_t WH_PAD[3];
    uint32_t object_id;
} whMessageAuth_CheckAuthorizationRequest;

int wh_MessageAuth_TranslateCheckAuthorizationRequest(uint16_t magic,
        const whMessageAuth_CheckAuthorizationRequest* src,
        whMessageAuth_CheckAuthorizationRequest* dest);

/** Check Authorization Response */
typedef struct {
    int32_t rc;
    uint8_t authorized;
    uint8_t WH_PAD[3];
} whMessageAuth_CheckAuthorizationResponse;

int wh_MessageAuth_TranslateCheckAuthorizationResponse(uint16_t magic,
        const whMessageAuth_CheckAuthorizationResponse* src,
        whMessageAuth_CheckAuthorizationResponse* dest);

#endif /* !WOLFHSM_WH_MESSAGE_AUTH_H_ */
