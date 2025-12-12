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
    WH_MESSAGE_AUTH_ACTION_SESSION_CREATE    = 0x02,
    WH_MESSAGE_AUTH_ACTION_SESSION_DESTROY   = 0x03,
    WH_MESSAGE_AUTH_ACTION_SESSION_GET       = 0x04,
    WH_MESSAGE_AUTH_ACTION_SESSION_STATUS    = 0x05,
    WH_MESSAGE_AUTH_ACTION_USER_ADD          = 0x06,
    WH_MESSAGE_AUTH_ACTION_USER_DELETE       = 0x07,
    WH_MESSAGE_AUTH_ACTION_USER_GET          = 0x08,
    WH_MESSAGE_AUTH_ACTION_USER_SET_PERMISSIONS = 0x09,
    WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS = 0x0A,
    WH_MESSAGE_AUTH_ACTION_CHECK_AUTHORIZATION  = 0x0B,
};

enum WH_MESSAGE_AUTH_MAX_ENUM {
    WH_MESSAGE_AUTH_MAX_USERNAME_LEN = 32,
    WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN = WOLFHSM_CFG_COMM_DATA_LEN - 64,
    WH_MESSAGE_AUTH_MAX_SESSIONS = 16,
};

/* Simple reusable response message */
typedef struct {
    int32_t rc;
} whMessageAuth_SimpleResponse;

int wh_MessageAuth_TranslateSimpleResponse(uint16_t magic,
        const whMessageAuth_SimpleResponse* src,
        whMessageAuth_SimpleResponse* dest);

/** Authenticate Request */
typedef struct {
    uint8_t method;  /* whAuthMethod */
    uint16_t auth_data_len;
    uint8_t WH_PAD[1];
    /* Auth data up to WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN follows */
} whMessageAuth_AuthenticateRequest;

int wh_MessageAuth_TranslateAuthenticateRequest(uint16_t magic,
        const whMessageAuth_AuthenticateRequest* src,
        whMessageAuth_AuthenticateRequest* dest);

/** Authenticate Response */
typedef struct {
    int32_t rc;
    uint16_t user_id;
    uint32_t session_id;
    uint32_t permissions;
} whMessageAuth_AuthenticateResponse;

int wh_MessageAuth_TranslateAuthenticateResponse(uint16_t magic,
        const whMessageAuth_AuthenticateResponse* src,
        whMessageAuth_AuthenticateResponse* dest);

/** Session Create Request */
typedef struct {
    uint16_t user_id;
    uint32_t permissions;
} whMessageAuth_SessionCreateRequest;

int wh_MessageAuth_TranslateSessionCreateRequest(uint16_t magic,
        const whMessageAuth_SessionCreateRequest* src,
        whMessageAuth_SessionCreateRequest* dest);

/** Session Create Response */
typedef struct {
    int32_t rc;
    uint32_t session_id;
} whMessageAuth_SessionCreateResponse;

int wh_MessageAuth_TranslateSessionCreateResponse(uint16_t magic,
        const whMessageAuth_SessionCreateResponse* src,
        whMessageAuth_SessionCreateResponse* dest);

/** Session Destroy Request */
typedef struct {
    uint32_t session_id;
} whMessageAuth_SessionDestroyRequest;

int wh_MessageAuth_TranslateSessionDestroyRequest(uint16_t magic,
        const whMessageAuth_SessionDestroyRequest* src,
        whMessageAuth_SessionDestroyRequest* dest);

/** Session Destroy Response */
/* Use SimpleResponse */

/** Session Get Request */
typedef struct {
    uint32_t session_id;
} whMessageAuth_SessionGetRequest;

int wh_MessageAuth_TranslateSessionGetRequest(uint16_t magic,
        const whMessageAuth_SessionGetRequest* src,
        whMessageAuth_SessionGetRequest* dest);

/** Session Get Response */
typedef struct {
    int32_t rc;
    uint32_t session_id;
    uint16_t user_id;
    uint16_t client_id;
    uint32_t permissions;
    uint32_t created_time;
    uint32_t last_access_time;
    uint32_t timeout;
    uint8_t is_valid;
    uint8_t WH_PAD[3];
} whMessageAuth_SessionGetResponse;

int wh_MessageAuth_TranslateSessionGetResponse(uint16_t magic,
        const whMessageAuth_SessionGetResponse* src,
        whMessageAuth_SessionGetResponse* dest);

/** Session Status Request */
/* Empty message */

/** Session Status Response */
typedef struct {
    int32_t rc;
    uint32_t active_sessions;
    uint32_t session_list[WH_MESSAGE_AUTH_MAX_SESSIONS];
} whMessageAuth_SessionStatusResponse;

int wh_MessageAuth_TranslateSessionStatusResponse(uint16_t magic,
        const whMessageAuth_SessionStatusResponse* src,
        whMessageAuth_SessionStatusResponse* dest);

/** User Add Request */
typedef struct {
    char username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint32_t permissions;
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
    uint16_t user_id;
    uint8_t WH_PAD[2];
} whMessageAuth_UserGetRequest;

int wh_MessageAuth_TranslateUserGetRequest(uint16_t magic,
        const whMessageAuth_UserGetRequest* src,
        whMessageAuth_UserGetRequest* dest);

/** User Get Response */
typedef struct {
    int32_t rc;
    uint16_t user_id;
    uint8_t WH_PAD[2];
    char username[WH_MESSAGE_AUTH_MAX_USERNAME_LEN];
    uint32_t permissions;
    uint8_t is_active;
    uint8_t WH_PAD2[3];
    uint32_t failed_attempts;
    uint32_t lockout_until;
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
typedef struct {
    uint16_t user_id;
    uint8_t method;  /* whAuthMethod */
    uint16_t credentials_len;
    /* Credentials data up to WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN follows */
} whMessageAuth_UserSetCredentialsRequest;

int wh_MessageAuth_TranslateUserSetCredentialsRequest(uint16_t magic,
        const whMessageAuth_UserSetCredentialsRequest* src,
        whMessageAuth_UserSetCredentialsRequest* dest);

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
