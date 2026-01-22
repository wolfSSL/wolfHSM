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
 * src/wh_server_auth.c
 *
 * Server-side Auth Manager request handler
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER

/* System libraries */
#include <stdint.h>
#include <stddef.h> /* For NULL */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_auth.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_auth.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_auth.h"

/* This function is responsible for handling all authentication and
 * authorization requests from the client.
 */
int wh_Server_HandleAuthRequest(whServerContext* server, uint16_t magic,
                                uint16_t action, uint16_t seq,
                                uint16_t req_size, const void* req_packet,
                                uint16_t* out_resp_size, void* resp_packet)
{
    int rc = 0;

    if ((server == NULL) || (req_packet == NULL) || (resp_packet == NULL) ||
        (out_resp_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* III: Translate function returns do not need to be checked since args
     * are not NULL */

    switch (action) {

        case WH_MESSAGE_AUTH_ACTION_LOGIN: {
            whMessageAuth_LoginRequest  req                        = {0};
            whMessageAuth_LoginResponse resp                       = {0};
            int                         loggedIn                   = 0;
            uint8_t auth_data[WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN] = {0};

            rc = wh_MessageAuth_TranslateLoginRequest(
                magic, req_packet, req_size, &req, auth_data);
            if (rc != WH_ERROR_OK) {
                resp.rc = rc;
            }

            if (resp.rc == WH_ERROR_OK) {
                rc      = wh_Auth_Login(server->auth, server->comm->client_id,
                                        req.method, req.username, auth_data,
                                        req.auth_data_len, &loggedIn);
                resp.rc = rc;
                if (rc == WH_ERROR_OK) {
                    if (loggedIn == 0) {
                        resp.rc      = WH_AUTH_LOGIN_FAILED;
                        resp.user_id = WH_USER_ID_INVALID;
                    }
                    else {
                        resp.user_id = server->auth->user.user_id;
                    }
                }
            }
            wh_MessageAuth_TranslateLoginResponse(
                magic, &resp, (whMessageAuth_LoginResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_MESSAGE_AUTH_ACTION_LOGOUT: {
            whMessageAuth_LogoutRequest  req  = {0};
            whMessageAuth_SimpleResponse resp = {0};

            if (req_size != sizeof(req)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                wh_MessageAuth_TranslateLogoutRequest(magic, req_packet, &req);

                rc      = wh_Auth_Logout(server->auth, req.user_id);
                resp.rc = rc;
            }
            wh_MessageAuth_TranslateSimpleResponse(
                magic, &resp, (whMessageAuth_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_MESSAGE_AUTH_ACTION_USER_ADD: {
            whMessageAuth_UserAddRequest  req                        = {0};
            whMessageAuth_UserAddResponse resp                       = {0};
            whAuthPermissions             permissions                = {0};
            uint8_t credentials[WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN] = {0};

            rc = wh_MessageAuth_TranslateUserAddRequest(
                magic, req_packet, req_size, &req, credentials);
            if (rc != WH_ERROR_OK) {
                resp.rc = rc;
            }
            else {
                if (wh_MessageAuth_UnflattenPermissions(req.permissions,
                                                        sizeof(req.permissions),
                                                        &permissions) != 0) {
                    resp.rc = WH_ERROR_BADARGS;
                }
                else {
                    rc      = wh_Auth_UserAdd(server->auth, req.username,
                                              &resp.user_id, permissions,
                                              req.method, credentials,
                                              req.credentials_len);
                    resp.rc = rc;
                }
            }
            wh_MessageAuth_TranslateUserAddResponse(
                magic, &resp, (whMessageAuth_UserAddResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_MESSAGE_AUTH_ACTION_USER_DELETE: {
            whMessageAuth_UserDeleteRequest req  = {0};
            whMessageAuth_SimpleResponse    resp = {0};

            if (req_size != sizeof(req)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                wh_MessageAuth_TranslateUserDeleteRequest(magic, req_packet,
                    &req);
                rc      = wh_Auth_UserDelete(server->auth, req.user_id);
                resp.rc = rc;
            }
            wh_MessageAuth_TranslateSimpleResponse(
                magic, &resp, (whMessageAuth_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_MESSAGE_AUTH_ACTION_USER_GET: {
            whMessageAuth_UserGetRequest  req             = {0};
            whMessageAuth_UserGetResponse resp            = {0};

            if (req_size != sizeof(req)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                whUserId          out_user_id     = WH_USER_ID_INVALID;
                whAuthPermissions out_permissions = {0};

                wh_MessageAuth_TranslateUserGetRequest(magic, req_packet, &req);

                rc      = wh_Auth_UserGet(server->auth, req.username,
                    &out_user_id, &out_permissions);
                resp.rc = rc;
                if (rc == WH_ERROR_OK) {
                    resp.user_id = out_user_id;
                    wh_MessageAuth_FlattenPermissions(&out_permissions,
                                                    resp.permissions,
                                                    sizeof(resp.permissions));
                }
            }
            wh_MessageAuth_TranslateUserGetResponse(
                magic, &resp, (whMessageAuth_UserGetResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_MESSAGE_AUTH_ACTION_USER_SET_PERMISSIONS: {
            whMessageAuth_UserSetPermissionsRequest req         = {0};
            whMessageAuth_SimpleResponse            resp        = {0};
            whAuthPermissions                       permissions = {0};

            if (req_size != sizeof(req)) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                wh_MessageAuth_TranslateUserSetPermissionsRequest(
                    magic, req_packet, &req);
                if (wh_MessageAuth_UnflattenPermissions(req.permissions,
                                                        sizeof(req.permissions),
                                                        &permissions) != 0) {
                    resp.rc = WH_ERROR_BADARGS;
                }
                else {
                    rc = wh_Auth_UserSetPermissions(server->auth, req.user_id,
                                                    permissions);
                    resp.rc = rc;
                }
            }
            wh_MessageAuth_TranslateSimpleResponse(
                magic, &resp, (whMessageAuth_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_MESSAGE_AUTH_ACTION_USER_SET_CREDENTIALS: {
            whMessageAuth_UserSetCredentialsRequest req_header         = {0};
            uint8_t current_creds[WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN] = {0};
            uint8_t new_creds[WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN]     = {0};
            whMessageAuth_SimpleResponse resp                          = {0};
            uint16_t min_size = sizeof(whMessageAuth_UserSetCredentialsRequest);

            if (req_size < min_size) {
                resp.rc = WH_ERROR_BADARGS;
            }
            else {
                rc = wh_MessageAuth_TranslateUserSetCredentialsRequest(
                    magic, req_packet, req_size, &req_header, current_creds,
                    new_creds);
                if (rc != 0) {
                    resp.rc = rc;
                }
                else {
                    rc = wh_Auth_UserSetCredentials(
                        server->auth, req_header.user_id, req_header.method,
                        (req_header.current_credentials_len > 0) ? current_creds
                                                                 : NULL,
                        req_header.current_credentials_len,
                        (req_header.new_credentials_len > 0) ? new_creds : NULL,
                        req_header.new_credentials_len);
                    resp.rc = rc;
                }
            }
            wh_MessageAuth_TranslateSimpleResponse(
                magic, &resp, (whMessageAuth_SimpleResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        default:
            /* Unknown request. Respond with empty packet */
            /* TODO: Use ErrorResponse packet instead */
            *out_resp_size = 0;
            rc             = WH_ERROR_NOTIMPL;
    }

    (void)seq;
    return rc;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
