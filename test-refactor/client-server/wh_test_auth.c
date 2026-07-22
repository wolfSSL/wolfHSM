/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test-refactor/client-server/wh_test_auth.c
 *
 * Client-side authentication tests. The POSIX server is configured
 * with an auth context plus an admin user, and the client logs in as
 * admin at connect (see posix/wh_test_posix_server.c and
 * wh_test_posix_client.c). Each test here changes the login session to
 * exercise a behavior, then restores the admin baseline so the next
 * client test stays authorized (the auth gate denies un-logged-in
 * requests). The bracketing is done once in _whTest_Auth_RunBracketed.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_AUTHENTICATION) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_auth.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_auth.h"

#include "wh_test_common.h"

#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif


/* ============================================================================
 * Client op helpers (blocking request/response against the running server)
 * ============================================================================
 */

static int _whTest_Auth_LoginOp(whClientContext* client, whAuthMethod method,
                                const char* username, const void* auth_data,
                                uint16_t auth_data_len, int32_t* out_rc,
                                whUserId* out_user_id)
{
    return wh_Client_AuthLogin(client, method, username, auth_data,
                               auth_data_len, out_rc, out_user_id);
}

static int _whTest_Auth_LogoutOp(whClientContext* client, whUserId user_id,
                                 int32_t* out_rc)
{
    return wh_Client_AuthLogout(client, user_id, out_rc);
}

static int _whTest_Auth_UserAddOp(whClientContext* client, const char* username,
                                  whAuthPermissions permissions,
                                  whAuthMethod method, const void* credentials,
                                  uint16_t credentials_len, int32_t* out_rc,
                                  whUserId* out_user_id)
{
    return wh_Client_AuthUserAdd(client, username, permissions, method,
                                 credentials, credentials_len, out_rc,
                                 out_user_id);
}

static int _whTest_Auth_UserDeleteOp(whClientContext* client, whUserId user_id,
                                     int32_t* out_rc)
{
    return wh_Client_AuthUserDelete(client, user_id, out_rc);
}

static int _whTest_Auth_UserSetPermsOp(whClientContext*  client,
                                       whUserId          user_id,
                                       whAuthPermissions permissions,
                                       int32_t*          out_rc)
{
    return wh_Client_AuthUserSetPermissions(client, user_id, permissions,
                                            out_rc);
}

static int _whTest_Auth_UserSetCredsOp(
    whClientContext* client, whUserId user_id, whAuthMethod method,
    const void* current_credentials, uint16_t current_credentials_len,
    const void* new_credentials, uint16_t new_credentials_len, int32_t* out_rc)
{
    return wh_Client_AuthUserSetCredentials(
        client, user_id, method, current_credentials, current_credentials_len,
        new_credentials, new_credentials_len, out_rc);
}

static int _whTest_Auth_UserGetOp(whClientContext* client, const char* username,
                                  int32_t* out_rc, whUserId* out_user_id,
                                  whAuthPermissions* out_permissions)
{
    return wh_Client_AuthUserGet(client, username, out_rc, out_user_id,
                                 out_permissions);
}

static void _whTest_Auth_DeleteUserByName(whClientContext* client,
                                          const char*      username)
{
    int32_t           server_rc = 0;
    whUserId          user_id   = WH_USER_ID_INVALID;
    whAuthPermissions perms;

    memset(&perms, 0, sizeof(perms));
    _whTest_Auth_UserGetOp(client, username, &server_rc, &user_id, &perms);
    if (server_rc == WH_ERROR_OK && user_id != WH_USER_ID_INVALID) {
        _whTest_Auth_UserDeleteOp(client, user_id, &server_rc);
    }
}


/* ============================================================================
 * Session bracketing
 * ============================================================================
 */

typedef int (*whTestAuthImplFn)(whClientContext*);

/* Admin's server-assigned user id, needed to log the baseline session
 * out (logout requires the real id, not WH_USER_ID_INVALID). Discovered
 * once from the live admin session, which is the baseline at bracket
 * entry. */
static whUserId _adminUserId = WH_USER_ID_INVALID;

/*
 * Run an auth test body with the session bracketed: start from a clean
 * logged-out state (the bodies assume logged-out, but the connect-time
 * baseline is the admin session), and on return restore the admin
 * baseline so the following client tests stay authorized.
 */
static int _whTest_Auth_RunBracketed(whClientContext* client,
                                     whTestAuthImplFn fn)
{
    int      ret;
    int32_t  rc  = 0;
    whUserId uid = WH_USER_ID_INVALID;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Discover admin's id once (admin is logged in at entry). */
    if (_adminUserId == WH_USER_ID_INVALID) {
        whAuthPermissions perms;
        memset(&perms, 0, sizeof(perms));
        (void)wh_Client_AuthUserGet(client, TEST_ADMIN_USERNAME, &rc,
                                    &_adminUserId, &perms);
    }
    /* Drop the admin baseline so the body starts logged-out. */
    if (_adminUserId != WH_USER_ID_INVALID) {
        (void)wh_Client_AuthLogout(client, _adminUserId, &rc);
    }

    ret = fn(client);

    /* Restore the admin baseline for the next test. */
    (void)wh_Client_AuthLogin(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                              TEST_ADMIN_PIN, (uint16_t)strlen(TEST_ADMIN_PIN),
                              &rc, &uid);
    if (rc == WH_ERROR_OK && uid != WH_USER_ID_INVALID) {
        _adminUserId = uid;
    }
    return ret;
}


/* ============================================================================
 * Test bodies (assume a logged-out start; bracketed by the wrappers below)
 * ============================================================================
 */

/* Logout Tests */
static int _whTest_AuthLogout_impl(whClientContext* client)
{
    int32_t           server_rc;
    whUserId          user_id;
    int32_t           login_rc;
    whAuthPermissions out_perms;

    /* Test 2: Logout after login */
    WH_TEST_PRINT("  Test: Logout after login\n");
    /* First login */
    memset(&out_perms, 0, sizeof(out_perms));
    login_rc = 0;
    user_id  = WH_USER_ID_INVALID;
    WH_TEST_ASSERT_RETURN(client->comm != NULL);
    WH_TEST_ASSERT_RETURN(client->comm->initialized == 1);
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &login_rc, &user_id));
    WH_TEST_ASSERT_RETURN(login_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Then logout */
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LogoutOp(client, user_id, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_PRINT("  Test: Logout before login\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LogoutOp(client, user_id, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 3: Logout with invalid user id */
    WH_TEST_PRINT(
        "  Test: Logout attempt with invalid user ID (should fail)\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LogoutOp(client, WH_USER_ID_INVALID, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    return WH_TEST_SUCCESS;
}

/* Login Tests */
static int _whTest_AuthLogin_impl(whClientContext* client)
{
    int32_t  server_rc;
    whUserId user_id;

    /* Test 1: Login with invalid credentials */
    WH_TEST_PRINT("  Test: Login with invalid credentials\n");
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, "wrong", 5,
                                                &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_LOGIN_FAILED ||
                          server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id == WH_USER_ID_INVALID);

    /* Test 2: Login with valid credentials */
    WH_TEST_PRINT("  Test: Login with valid credentials\n");
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Logout for next test */
    _whTest_Auth_LogoutOp(client, user_id, &server_rc);

    /* Test 3: Login with invalid username */
    WH_TEST_PRINT("  Test: Login with invalid username\n");
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "nonexistent", TEST_ADMIN_PIN,
                                                4, &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_LOGIN_FAILED ||
                          server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id == WH_USER_ID_INVALID);

    /* Test 4: Login if already logged in */
    WH_TEST_PRINT("  Test: Login if already logged in\n");
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Try to login again without logout */
    server_rc         = 0;
    whUserId user_id2 = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &server_rc, &user_id2));
    WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_LOGIN_FAILED ||
                          server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id2 == WH_USER_ID_INVALID);

    /* Cleanup */
    _whTest_Auth_LogoutOp(client, user_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Add User Tests */
static int _whTest_AuthAddUser_impl(whClientContext* client)
{
    int32_t           server_rc;
    whUserId          user_id;
    whAuthPermissions perms;
    char              long_username[34]; /* 33 chars + null terminator */
    int               rc;

    /* Login as admin first */
    whAuthPermissions admin_perms;
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc         = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Test 1: Add user with invalid username (too long) */
    WH_TEST_PRINT("  Test: Add user with invalid username (too long)\n");
    memset(long_username, 'a', 33);
    long_username[33] = '\0';
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;

    /* Expect client-side rejection due to username length */
    rc = wh_Client_AuthUserAddRequest(client, long_username, perms,
                                      WH_AUTH_METHOD_PIN, "test", 4);
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK || server_rc != WH_ERROR_OK ||
                          user_id == WH_USER_ID_INVALID);

    /* Test 2: Add user with invalid permissions (keyIdCount > max) */
    WH_TEST_PRINT("  Test: Add user with invalid permissions\n");
    memset(&perms, 0, sizeof(perms));
    perms.keyIdCount = WH_AUTH_MAX_KEY_IDS + 1; /* Invalid: exceeds max */
    server_rc        = 0;
    user_id          = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser1", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &user_id);
    /* Should clamp or reject invalid keyIdCount */
    if (server_rc == WH_ERROR_OK) {
        /* If it succeeds, keyIdCount should be clamped */
        WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);
    }

    /* Test 3: Add user if already exists */
    WH_TEST_PRINT("  Test: Add user if already exists\n");
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser2", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &user_id);
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Try to add same user again - should fail duplicate username */
    whUserId user_id2 = WH_USER_ID_INVALID;
    server_rc         = 0;
    _whTest_Auth_UserAddOp(client, "testuser2", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &user_id2);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id2 == WH_USER_ID_INVALID);

    /* Test 4: Non-admin cannot add admin user */
    WH_TEST_PRINT("  Test: Non-admin cannot add admin user\n");
    {
        whAuthPermissions nonadmin_add_perms;

        memset(&nonadmin_add_perms, 0, sizeof(nonadmin_add_perms));
        WH_AUTH_SET_ALLOWED_ACTION(nonadmin_add_perms, WH_MESSAGE_GROUP_AUTH,
                                   WH_MESSAGE_AUTH_ACTION_USER_ADD);
        WH_AUTH_SET_IS_ADMIN(nonadmin_add_perms, 0);

        server_rc = 0;
        user_id   = WH_USER_ID_INVALID;
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(
            client, "addadmin_testuser", nonadmin_add_perms, WH_AUTH_METHOD_PIN,
            "pass", 4, &server_rc, &user_id));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

        _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                    "addadmin_testuser", "pass",
                                                    4, &server_rc, &user_id));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        /* Non-admin can add other non-admin users */
        memset(&perms, 0, sizeof(perms));
        server_rc = 0;
        user_id2  = WH_USER_ID_INVALID;
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(
            client, "other_nonadmin", perms, WH_AUTH_METHOD_PIN, "test", 4,
            &server_rc, &user_id2));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(user_id2 != WH_USER_ID_INVALID);

        /* Non-admin cannot add admin user */
        memset(&perms, 0xFF, sizeof(perms));
        perms.keyIdCount = 0;
        server_rc        = 0;
        user_id2         = WH_USER_ID_INVALID;
        _whTest_Auth_UserAddOp(client, "wouldbe_admin", perms,
                               WH_AUTH_METHOD_PIN, "test", 4, &server_rc,
                               &user_id2);
        WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_PERMISSION_ERROR);
        WH_TEST_ASSERT_RETURN(user_id2 == WH_USER_ID_INVALID);
    }

    _whTest_Auth_LogoutOp(client, user_id, &server_rc);
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &server_rc, &admin_id));

    /* Cleanup */
    server_rc = 0;
    _whTest_Auth_DeleteUserByName(client, "testuser1");
    _whTest_Auth_DeleteUserByName(client, "testuser2");
    _whTest_Auth_DeleteUserByName(client, "addadmin_testuser");
    _whTest_Auth_DeleteUserByName(client, "other_nonadmin");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Delete User Tests */
static int _whTest_AuthDeleteUser_impl(whClientContext* client)
{
    int32_t           server_rc;
    whAuthPermissions admin_perms;
    whUserId          admin_id = WH_USER_ID_INVALID;
    whAuthPermissions perms;
    whAuthPermissions out_perms;
    whUserId          delete_user_id = WH_USER_ID_INVALID;

    /* Login as admin to perform delete operations */
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Test 1: Delete user with invalid user id */
    WH_TEST_PRINT("  Test: Delete user with invalid user ID\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserDeleteOp(client, WH_USER_ID_INVALID, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Delete user that does not exist */
    WH_TEST_PRINT("  Test: Delete user that does not exist\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserDeleteOp(client, 999, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND ||
                          server_rc != WH_ERROR_OK);

    /* Test 2b: Delete existing user (success path)  */
    WH_TEST_PRINT("  Test: Delete existing user\n");
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "deleteuser", perms,
                                                  WH_AUTH_METHOD_PIN, "pass", 4,
                                                  &server_rc, &delete_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(delete_user_id != WH_USER_ID_INVALID);

    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "deleteuser", &server_rc, &delete_user_id, &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserDeleteOp(client, delete_user_id, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc      = 0;
    delete_user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "deleteuser", &server_rc, &delete_user_id, &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK ||
                          delete_user_id == WH_USER_ID_INVALID);

    /* Test 3: Non-admin user trying to delete another user */
    WH_TEST_PRINT("  Test: Non-admin user trying to delete another user\n");
    {
        whUserId          nonadmin_id = WH_USER_ID_INVALID;
        whUserId          target_id   = WH_USER_ID_INVALID;
        whAuthPermissions nonadmin_perms;

        /* non-admin user with all auth group actions (includes delete) */
        memset(&nonadmin_perms, 0, sizeof(nonadmin_perms));
        WH_AUTH_SET_ALLOWED_GROUP(nonadmin_perms, WH_MESSAGE_GROUP_AUTH);
        WH_AUTH_SET_IS_ADMIN(nonadmin_perms, 0);

        server_rc = 0;
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(
            client, "nonadmin", nonadmin_perms, WH_AUTH_METHOD_PIN, "pass", 4,
            &server_rc, &nonadmin_id));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(nonadmin_id != WH_USER_ID_INVALID);

        /* Create a target user to try to delete */
        memset(&perms, 0, sizeof(perms));
        server_rc = 0;
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(
            client, "targetuser", perms, WH_AUTH_METHOD_PIN, "pass", 4,
            &server_rc, &target_id));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(target_id != WH_USER_ID_INVALID);

        /* Logout admin and login as non-admin user */
        server_rc = 0;
        _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

        server_rc = 0;
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                    "nonadmin", "pass", 4,
                                                    &server_rc, &nonadmin_id));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        /* Try to delete the target user as non-admin - should fail */
        server_rc = 0;
        WH_TEST_RETURN_ON_FAIL(
            _whTest_Auth_UserDeleteOp(client, target_id, &server_rc));
        WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);
        WH_TEST_PRINT("    Non-admin delete attempt correctly denied\n");

        /* Logout non-admin and login as admin to cleanup */
        server_rc = 0;
        _whTest_Auth_LogoutOp(client, nonadmin_id, &server_rc);

        server_rc = 0;
        WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                    "admin", "1234", 4,
                                                    &server_rc, &admin_id));
        WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

        /* Cleanup - delete both test users */
        _whTest_Auth_UserDeleteOp(client, nonadmin_id, &server_rc);
        _whTest_Auth_UserDeleteOp(client, target_id, &server_rc);
    }

    /* Test 4: Delete user when not logged in */
    WH_TEST_PRINT("  Test: Delete user when not logged in\n");
    /* Ensure we're logged out */
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    /* Try to delete without being logged in */
    server_rc = 0;
    _whTest_Auth_UserDeleteOp(client, 1, &server_rc);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    return WH_TEST_SUCCESS;
}

/* Get User Tests */
static int _whTest_AuthUserGet_impl(whClientContext* client)
{
    int32_t           server_rc;
    whUserId          admin_id   = WH_USER_ID_INVALID;
    whUserId          getuser_id = WH_USER_ID_INVALID;
    whUserId          target_id  = WH_USER_ID_INVALID;
    whUserId          fetched_id = WH_USER_ID_INVALID;
    whAuthPermissions perms;
    whAuthPermissions fetched_perms;
    int               groupIndex = (WH_MESSAGE_GROUP_AUTH >> 8) & 0xFF;
    uint32_t          actionWord, actionBit;

    WH_AUTH_ACTION_TO_WORD_AND_BITMASK(WH_MESSAGE_AUTH_ACTION_USER_GET,
                                       actionWord, actionBit);

    /* Login as admin to create the test users */
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, (uint16_t)strlen(TEST_ADMIN_PIN),
                             &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Non-admin user holding only the AUTH group USER_GET action */
    memset(&perms, 0, sizeof(perms));
    WH_AUTH_SET_ALLOWED_ACTION(perms, WH_MESSAGE_GROUP_AUTH,
                               WH_MESSAGE_AUTH_ACTION_USER_GET);
    WH_AUTH_SET_IS_ADMIN(perms, 0);
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "getuser", perms,
                                                  WH_AUTH_METHOD_PIN, "pass", 4,
                                                  &server_rc, &getuser_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(getuser_id != WH_USER_ID_INVALID);

    /* Second user, whose profile the non-admin must not be able to read */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "gettarget", perms,
                                                  WH_AUTH_METHOD_PIN, "pass", 4,
                                                  &server_rc, &target_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(target_id != WH_USER_ID_INVALID);

    /* Switch to the non-admin session */
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "getuser", "pass", 4, &server_rc,
                                                &getuser_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Test 1: Non-admin getting another user's profile */
    WH_TEST_PRINT("  Test: Non-admin get of another user\n");
    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_id = WH_USER_ID_INVALID;
    server_rc  = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "gettarget", &server_rc, &fetched_id, &fetched_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);
    /* No target identity may leak on the denied path */
    WH_TEST_ASSERT_RETURN(fetched_id == WH_USER_ID_INVALID);

    /* Test 2: Non-admin getting its own profile */
    WH_TEST_PRINT("  Test: Non-admin get of own user\n");
    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_id = WH_USER_ID_INVALID;
    server_rc  = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "getuser", &server_rc, &fetched_id, &fetched_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(fetched_id == getuser_id);
    /* The granted USER_GET action must survive the round trip; not admin */
    WH_TEST_ASSERT_RETURN(fetched_perms.groupPermissions[groupIndex] != 0);
    WH_TEST_ASSERT_RETURN(
        (fetched_perms.actionPermissions[groupIndex][actionWord] & actionBit) !=
        0);
    WH_TEST_ASSERT_RETURN(WH_AUTH_IS_ADMIN(fetched_perms) == 0);

    /* Test 3: Non-admin getting a name that does not exist. The error must
     * match the denied case so the response is not an existence oracle. */
    WH_TEST_PRINT("  Test: Non-admin get of unknown user\n");
    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_id = WH_USER_ID_INVALID;
    server_rc  = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "nosuchuser", &server_rc, &fetched_id, &fetched_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(fetched_id == WH_USER_ID_INVALID);

    /* Test 4: Admin getting another user's profile */
    WH_TEST_PRINT("  Test: Admin get of another user\n");
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, getuser_id, &server_rc);
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, (uint16_t)strlen(TEST_ADMIN_PIN),
                             &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_id = WH_USER_ID_INVALID;
    server_rc  = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "gettarget", &server_rc, &fetched_id, &fetched_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(fetched_id == target_id);
    /* gettarget was created with empty permissions and is not admin */
    WH_TEST_ASSERT_RETURN(fetched_perms.groupPermissions[groupIndex] == 0);
    WH_TEST_ASSERT_RETURN(WH_AUTH_IS_ADMIN(fetched_perms) == 0);

    /* Test 5: Admin getting a name that does not exist. Unlike a non-admin,
     * an admin is allowed to learn that the account is absent. */
    WH_TEST_PRINT("  Test: Admin get of unknown user\n");
    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_id = WH_USER_ID_INVALID;
    server_rc  = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "nosuchuser", &server_rc, &fetched_id, &fetched_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND);
    WH_TEST_ASSERT_RETURN(fetched_id == WH_USER_ID_INVALID);

    /* Cleanup */
    _whTest_Auth_DeleteUserByName(client, "getuser");
    _whTest_Auth_DeleteUserByName(client, "gettarget");
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Set User Permissions Tests */
static int _whTest_AuthSetPermissions_impl(whClientContext* client)
{
    int32_t           server_rc;
    whUserId          user_id;
    whAuthPermissions perms, new_perms;
    whAuthPermissions fetched_perms;
    whUserId          fetched_user_id = WH_USER_ID_INVALID;
    int32_t           get_rc          = 0;

    /* Login as admin first */
    whAuthPermissions admin_perms;
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc         = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Create a test user first */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "testuser3", perms,
                                                  WH_AUTH_METHOD_PIN, "test", 4,
                                                  &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Test 1: Set user permissions with invalid user id */
    WH_TEST_PRINT("  Test: Set user permissions with invalid user ID\n");
    memset(&new_perms, 0xFF, sizeof(new_perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetPermsOp(
        client, WH_USER_ID_INVALID, new_perms, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Set user permissions with invalid permissions */
    WH_TEST_PRINT("  Test: Set user permissions with invalid permissions\n");
    memset(&new_perms, 0, sizeof(new_perms));
    new_perms.keyIdCount = WH_AUTH_MAX_KEY_IDS + 1; /* Invalid */
    server_rc            = 0;
    _whTest_Auth_UserSetPermsOp(client, user_id, new_perms, &server_rc);
    /* Should clamp or reject invalid keyIdCount */
    if (server_rc == WH_ERROR_OK) {
        /* If it succeeds, keyIdCount should be clamped */
    }

    /* Test 2b: Set user permissions success path  */
    WH_TEST_PRINT("  Test: Set user permissions success\n");
    memset(&new_perms, 0, sizeof(new_perms));
    WH_AUTH_SET_ALLOWED_ACTION(new_perms, WH_MESSAGE_GROUP_AUTH,
                               WH_MESSAGE_AUTH_ACTION_USER_ADD);
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserSetPermsOp(client, user_id, new_perms, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_user_id = WH_USER_ID_INVALID;
    get_rc          = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(
        client, "testuser3", &get_rc, &fetched_user_id, &fetched_perms));
    WH_TEST_ASSERT_RETURN(get_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(fetched_user_id == user_id);
    {
        /* Compare group permission and all action permission words */
        int groupIndex        = (WH_MESSAGE_GROUP_AUTH >> 8) & 0xFF;
        int j;
        int permissions_match = 1;
        WH_TEST_ASSERT_RETURN(fetched_perms.groupPermissions[groupIndex] ==
                              new_perms.groupPermissions[groupIndex]);
        for (j = 0; j < WH_AUTH_ACTION_WORDS; j++) {
            if (fetched_perms.actionPermissions[groupIndex][j] !=
                new_perms.actionPermissions[groupIndex][j]) {
                permissions_match = 0;
                break;
            }
        }
        WH_TEST_ASSERT_RETURN(permissions_match);
    }

    /* Test 3: Set user permissions for non-existent user */
    WH_TEST_PRINT("  Test: Set user permissions for non-existent user\n");
    memset(&new_perms, 0, sizeof(new_perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserSetPermsOp(client, 999, new_perms, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND ||
                          server_rc != WH_ERROR_OK);

    /* Test 4: Set user permissions when not logged in */
    WH_TEST_PRINT("  Test: Set user permissions when not logged in\n");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    memset(&new_perms, 0, sizeof(new_perms));
    server_rc = 0;
    _whTest_Auth_UserSetPermsOp(client, user_id, new_perms, &server_rc);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Cleanup */
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    _whTest_Auth_DeleteUserByName(client, "testuser3");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Set User Credentials Tests */
static int _whTest_AuthSetCredentials_impl(whClientContext* client)
{
    int32_t           server_rc;
    whUserId          user_id;
    whAuthPermissions perms;

    /* Login as admin first */
    whAuthPermissions admin_perms;
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc         = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Create a test user first */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "testuser4", perms,
                                                  WH_AUTH_METHOD_PIN, "test", 4,
                                                  &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Test 1: Set user credentials with invalid user id */
    WH_TEST_PRINT("  Test: Set user credentials with invalid user ID\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetCredsOp(
        client, WH_USER_ID_INVALID, WH_AUTH_METHOD_PIN, "test", 4, "newpass", 7,
        &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Set user credentials with invalid method */
    WH_TEST_PRINT("  Test: Set user credentials with invalid method\n");
    server_rc = 0;
    _whTest_Auth_UserSetCredsOp(client, user_id, WH_AUTH_METHOD_NONE, "test", 4,
                                "newpass", 7, &server_rc);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 3: Set user credentials for non-existent user */
    WH_TEST_PRINT("  Test: Set user credentials for non-existent user\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetCredsOp(
        client, 999, WH_AUTH_METHOD_PIN, NULL, 0, "newpass", 7, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND ||
                          server_rc != WH_ERROR_OK);

    WH_TEST_PRINT("  Test: Admin setting credentials for non-admin user\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserSetCredsOp(client, user_id, WH_AUTH_METHOD_PIN, "test",
                                    4, "newpass", 7, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Verify new credentials work */
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc             = 0;
    whUserId test_user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "testuser4", "newpass", 7,
                                                &server_rc, &test_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(test_user_id == user_id);

    /* Cleanup: remove the test user (logged in as admin so the delete
     * is authorized). */
    _whTest_Auth_LogoutOp(client, test_user_id, &server_rc);
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    _whTest_Auth_DeleteUserByName(client, "testuser4");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Authorization Checks Tests */
static int _whTest_AuthRequestAuthorization_impl(whClientContext* client)
{
    int32_t           server_rc;
    whUserId          user_id;
    whUserId          temp_id3 = WH_USER_ID_INVALID;
    whAuthPermissions perms;

    /* Test 1: Operation when not logged in and not allowed */
    WH_TEST_PRINT("  Test: Operation when not logged in and not allowed\n");
    /* Ensure logged out */
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, WH_USER_ID_INVALID, &server_rc);

    /* Try an operation that requires auth (e.g., add user) */
    memset(&perms, 0, sizeof(perms));
    server_rc        = 0;
    whUserId temp_id = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser5", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Operation when logged in and allowed */
    WH_TEST_PRINT("  Test: Operation when logged in and allowed\n");
    /* Login as admin */
    memset(&perms, 0, sizeof(perms));
    server_rc         = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Retry operation after login (admin should be allowed) */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id   = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "testuser6", perms,
                                                  WH_AUTH_METHOD_PIN, "test", 4,
                                                  &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Test 3: Operation when logged in and not allowed */
    WH_TEST_PRINT("  Test: Operation when logged in and not allowed\n");
    /* Create a user with auth group but not USER_ADD action */
    memset(&perms, 0, sizeof(perms));
    WH_AUTH_SET_ALLOWED_GROUP(perms, WH_MESSAGE_GROUP_AUTH);
    WH_AUTH_CLEAR_ALLOWED_ACTION(perms, WH_MESSAGE_GROUP_AUTH,
                                 WH_MESSAGE_AUTH_ACTION_USER_ADD);
    server_rc                = 0;
    whUserId limited_user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserAddOp(client, "limiteduser", perms, WH_AUTH_METHOD_PIN,
                               "pass", 4, &server_rc, &limited_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Logout admin and login as limited user */
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
    memset(&perms, 0, sizeof(perms));
    server_rc             = 0;
    whUserId logged_in_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "limiteduser", "pass", 4,
                                                &server_rc, &logged_in_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Try an operation that requires permissions */
    memset(&perms, 0, sizeof(perms));
    server_rc         = 0;
    whUserId temp_id2 = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser7", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id2);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 3b: User with auth group cleared cannot add
     * (WH_AUTH_CLEAR_ALLOWED_GROUP) */
    WH_TEST_PRINT("  Test: User with no auth group cannot add\n");
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    memset(&perms, 0xFF, sizeof(perms));
    perms.keyIdCount = 0;
    WH_AUTH_CLEAR_ALLOWED_GROUP(perms, WH_MESSAGE_GROUP_AUTH);
    WH_AUTH_SET_IS_ADMIN(perms, 0);
    server_rc          = 0;
    whUserId noauth_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "noauthuser", perms,
                                                  WH_AUTH_METHOD_PIN, "pass", 4,
                                                  &server_rc, &noauth_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "noauthuser", "pass", 4,
                                                &server_rc, &logged_in_id));
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    temp_id2  = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser7b", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id2);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);

    /* Test 4: Logged in as different user and allowed */
    WH_TEST_PRINT("  Test: Logged in as different user and allowed\n");
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);

    server_rc                = 0;
    whUserId allowed_user_id = WH_USER_ID_INVALID;
    /* Login as admin to create allowed user */
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(
        client, WH_AUTH_METHOD_PIN, "admin", "1234", 4, &server_rc, &admin_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    memset(&perms, 0, sizeof(perms));
    WH_AUTH_SET_ALLOWED_ACTION(perms, WH_MESSAGE_GROUP_AUTH,
                               WH_MESSAGE_AUTH_ACTION_USER_ADD);
    /* Free a slot so the adds below stay within WH_AUTH_BASE_MAX_USERS (5) */
    _whTest_Auth_DeleteUserByName(client, "noauthuser");
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_UserAddOp(client, "alloweduser", perms, WH_AUTH_METHOD_PIN,
                               "pass", 4, &server_rc, &allowed_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    memset(&perms, 0, sizeof(perms));
    server_rc    = 0;
    logged_in_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "alloweduser", "pass", 4,
                                                &server_rc, &logged_in_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    temp_id3  = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser8", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id3);
    /* alloweduser holds the USER_ADD action, so the add is authorized */
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(temp_id3 != WH_USER_ID_INVALID);

    /* Test 5: Logged in as different user and not allowed */
    WH_TEST_PRINT("  Test: Logged in as different user and not allowed\n");
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);

    memset(&perms, 0, sizeof(perms));
    server_rc    = 0;
    logged_in_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "limiteduser", "pass", 4,
                                                &server_rc, &logged_in_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    temp_id3  = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser9", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id3);
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Cleanup */
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(
        _whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME,
                             TEST_ADMIN_PIN, 4, &server_rc, &admin_id));
    _whTest_Auth_DeleteUserByName(client, "limiteduser");
    _whTest_Auth_DeleteUserByName(client, "alloweduser");
    _whTest_Auth_DeleteUserByName(client, "testuser5");
    _whTest_Auth_DeleteUserByName(client, "testuser6");
    _whTest_Auth_DeleteUserByName(client, "testuser7");
    _whTest_Auth_DeleteUserByName(client, "testuser8");
    _whTest_Auth_DeleteUserByName(client, "testuser9");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}


/* ============================================================================
 * Bad-args tests (no live session needed; do not disturb the baseline)
 * ============================================================================
 */

static int _whTest_Auth_BadArgs(void)
{
    int               rc       = 0;
    int               loggedIn = 1;
    whAuthContext     ctx;
    whAuthConfig      config;
    whAuthPermissions perms;
    whUserId          user_id   = WH_USER_ID_INVALID;
    int32_t           server_rc = 0;

    memset(&ctx, 0, sizeof(ctx));
    memset(&config, 0, sizeof(config));
    memset(&perms, 0, sizeof(perms));

    WH_TEST_PRINT("  Test: Auth core bad args\n");
    rc = wh_Auth_Init(NULL, &config);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_Init(&ctx, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_Auth_Cleanup(NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_Cleanup(&ctx);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc =
        wh_Auth_Login(NULL, 0, WH_AUTH_METHOD_PIN, "user", "pin", 3, &loggedIn);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_Login(&ctx, 0, WH_AUTH_METHOD_PIN, "user", "pin", 3, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthLoginRequest(NULL, WH_AUTH_METHOD_PIN, "user", "pin", 3);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthLoginResponse(NULL, &server_rc, &user_id);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_Auth_Logout(NULL, 1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_Logout(&ctx, 1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_Auth_UserAdd(&ctx, "user", &user_id, perms, WH_AUTH_METHOD_PIN,
                         "pin", 3);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_UserDelete(&ctx, 1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_UserSetPermissions(&ctx, 1, perms);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_UserGet(&ctx, "user", &user_id, &perms);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_UserSetCredentials(&ctx, 1, WH_AUTH_METHOD_PIN, "pin", 3,
                                    "new", 3);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_Logout(NULL, 999); /* port may not support 999 users */
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    WH_TEST_PRINT("  Test: Auth client bad args\n");
    rc = wh_Client_AuthLoginRequest(NULL, WH_AUTH_METHOD_PIN,
                                    TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
                                    (uint16_t)strlen(TEST_ADMIN_PIN));
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthLogoutRequest(NULL, WH_USER_ID_INVALID);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_Auth_CheckRequestAuthorization(NULL, WH_MESSAGE_GROUP_AUTH,
                                           WH_MESSAGE_AUTH_ACTION_LOGIN);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_Client_AuthUserAddRequest(NULL, "baduser", perms,
                                      WH_AUTH_METHOD_NONE, "x", 1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthUserDeleteRequest(NULL, WH_USER_ID_INVALID);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthUserSetPermissionsRequest(NULL, WH_USER_ID_INVALID,
                                                 perms);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthUserSetCredentialsRequest(
        NULL, WH_USER_ID_INVALID, WH_AUTH_METHOD_PIN, NULL, 0, "new", 3);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Client_AuthUserGetRequest(NULL, "missing");
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    return WH_TEST_SUCCESS;
}

static int _whTest_Auth_MessageBadArgs(void)
{
    int                                     rc        = 0;
    whMessageAuth_SimpleResponse            simple    = {0};
    whMessageAuth_LoginRequest              login_hdr = {0};
    whMessageAuth_LoginRequest              login_out = {0};
    whMessageAuth_UserAddRequest            add_hdr   = {0};
    whMessageAuth_UserAddRequest            add_out   = {0};
    whMessageAuth_UserSetCredentialsRequest set_hdr   = {0};

    WH_TEST_PRINT("  Test: Auth message bad args\n");
    rc = wh_MessageAuth_TranslateSimpleResponse(0, NULL, &simple);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_MessageAuth_TranslateSimpleResponse(0, &simple, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_MessageAuth_TranslateLoginRequest(0, NULL, 0, &login_out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_MessageAuth_TranslateLoginRequest(0, &login_hdr, 0, &login_out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BUFFER_SIZE);

    memset(&login_hdr, 0, sizeof(login_hdr));
    login_hdr.auth_data_len =
        (uint16_t)(WH_MESSAGE_AUTH_LOGIN_MAX_AUTH_DATA_LEN + 1);
    rc = wh_MessageAuth_TranslateLoginRequest(0, &login_hdr, sizeof(login_hdr),
                                              &login_out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BUFFER_SIZE);

    rc = wh_MessageAuth_TranslateUserAddRequest(0, NULL, 0, &add_out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    memset(&add_hdr, 0, sizeof(add_hdr));
    add_hdr.credentials_len =
        (uint16_t)(WH_MESSAGE_AUTH_USERADD_MAX_CREDENTIALS_LEN + 1);
    rc = wh_MessageAuth_TranslateUserAddRequest(0, &add_hdr, sizeof(add_hdr),
                                                &add_out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BUFFER_SIZE);

    rc =
        wh_MessageAuth_TranslateUserSetCredentialsRequest(0, NULL, 0, &set_hdr);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    memset(&set_hdr, 0, sizeof(set_hdr));
    set_hdr.current_credentials_len = 4;
    set_hdr.new_credentials_len     = 4;
    rc = wh_MessageAuth_TranslateUserSetCredentialsRequest(
        0, &set_hdr, sizeof(set_hdr), &set_hdr);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BUFFER_SIZE);

    return WH_TEST_SUCCESS;
}


/* ============================================================================
 * Registered entry points
 * ============================================================================
 */

int whTest_AuthBadArgs(whClientContext* client)
{
    (void)client;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_BadArgs());
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_MessageBadArgs());
    return WH_TEST_SUCCESS;
}

int whTest_AuthLogin(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthLogin_impl);
}

int whTest_AuthLogout(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthLogout_impl);
}

int whTest_AuthAddUser(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthAddUser_impl);
}

int whTest_AuthDeleteUser(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthDeleteUser_impl);
}

int whTest_AuthUserGet(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthUserGet_impl);
}

int whTest_AuthSetPermissions(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthSetPermissions_impl);
}

int whTest_AuthSetCredentials(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client, _whTest_AuthSetCredentials_impl);
}

int whTest_AuthRequestAuthorization(whClientContext* client)
{
    return _whTest_Auth_RunBracketed(client,
                                     _whTest_AuthRequestAuthorization_impl);
}

#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */
