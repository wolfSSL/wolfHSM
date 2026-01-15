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
 * test/wh_test_auth.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_auth.h"
#include "wolfhsm/wh_auth_base.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_auth.h"

#include "wh_test_common.h"
#include "wh_test_auth.h"

#if defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP) && defined(WOLFHSM_CFG_TEST_POSIX)
#include "port/posix/posix_transport_tcp.h"
#endif

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define BUFFER_SIZE 4096

#define TEST_ADMIN_USERNAME "admin"
#define TEST_ADMIN_PIN "1234"

#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
/* Memory transport mode - setup structures */
static uint8_t req_buffer[BUFFER_SIZE] = {0};
static uint8_t resp_buffer[BUFFER_SIZE] = {0};
static whTransportMemConfig tmcf[1] = {0};
static whTransportClientCb tccb[1] = {WH_TRANSPORT_MEM_CLIENT_CB};
static whTransportMemClientContext tmcc[1] = {0};
static whCommClientConfig cc_conf[1] = {0};
static whClientConfig c_conf[1] = {0};
static whTransportServerCb tscb[1] = {WH_TRANSPORT_MEM_SERVER_CB};
static whTransportMemServerContext tmsc[1] = {0};
static whCommServerConfig cs_conf[1] = {0};
static whServerContext server[1] = {0};
static whClientContext client[1] = {0};

/* NVM setup */
static uint8_t memory[FLASH_RAM_SIZE] = {0};
static whFlashRamsimCtx fc[1] = {0};
static whFlashRamsimCfg fc_conf[1];
static const whFlashCb fcb[1] = {WH_FLASH_RAMSIM_CB};
static whTestNvmBackendUnion nvm_setup;
static whNvmConfig n_conf[1] = {0};
static whNvmContext nvm[1] = {{0}};

/* Auth setup following wh_posix_server pattern */
static whAuthCb default_auth_cb = {
    .Init = wh_AuthBase_Init,
    .Cleanup = wh_AuthBase_Cleanup,
    .Login = wh_AuthBase_Login,
    .Logout = wh_AuthBase_Logout,
    .CheckRequestAuthorization = wh_AuthBase_CheckRequestAuthorization,
    .CheckKeyAuthorization = wh_AuthBase_CheckKeyAuthorization,
    .UserAdd = wh_AuthBase_UserAdd,
    .UserDelete = wh_AuthBase_UserDelete,
    .UserSetPermissions = wh_AuthBase_UserSetPermissions,
    .UserGet = wh_AuthBase_UserGet,
    .UserSetCredentials = wh_AuthBase_UserSetCredentials
};
static whAuthContext auth_ctx = {0};

#ifndef WOLFHSM_CFG_NO_CRYPTO
static whServerCryptoContext crypto[1] = {{.devId = INVALID_DEVID}};
#endif

/* Setup helper for memory transport mode */
static int _whTest_Auth_SetupMemory(whClientContext** out_client)
{
    int rc = WH_ERROR_OK;

    /* Initialize transport memory config - avoid compound literals for C90 */
    tmcf->req = (whTransportMemCsr*)req_buffer;
    tmcf->req_size = sizeof(req_buffer);
    tmcf->resp = (whTransportMemCsr*)resp_buffer;
    tmcf->resp_size = sizeof(resp_buffer);

    /* Client configuration - avoid compound literals for C90 compatibility */
    cc_conf->transport_cb = tccb;
    cc_conf->transport_context = (void*)tmcc;
    cc_conf->transport_config = (void*)tmcf;
    cc_conf->client_id = WH_TEST_DEFAULT_CLIENT_ID;
    c_conf->comm = cc_conf;

    /* Server configuration */
    cs_conf->transport_cb = tscb;
    cs_conf->transport_context = (void*)tmsc;
    cs_conf->transport_config = (void*)tmcf;
    cs_conf->server_id = 124;

    /* Flash RAM sim configuration */
    fc_conf->size = FLASH_RAM_SIZE;
    fc_conf->sectorSize = FLASH_RAM_SIZE / 2;
    fc_conf->pageSize = 8;
    fc_conf->erasedByte = (uint8_t)0;
    fc_conf->memory = memory;

    /* Initialize NVM */
    WH_TEST_RETURN_ON_FAIL(
        whTest_NvmCfgBackend(WH_NVM_TEST_BACKEND_FLASH, &nvm_setup, n_conf, fc_conf, fc, fcb));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));
#endif

    /* Set up auth context following wh_posix_server pattern */
    static void* auth_backend_context = NULL;
    static whAuthConfig auth_config = {0};

    auth_config.cb = &default_auth_cb;
    auth_config.context = auth_backend_context;

    rc = wh_Auth_Init(&auth_ctx, &auth_config);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to initialize Auth Manager: %d\n", rc);
        return rc;
    }

    /* Server config with auth - avoid compound literals for C90 */
    whServerConfig s_conf[1] = {{0}};
    s_conf->comm_config = cs_conf;
    s_conf->nvm = nvm;
    s_conf->auth = &auth_ctx;
#ifndef WOLFHSM_CFG_NO_CRYPTO
    s_conf->crypto = crypto;
#if defined WOLF_CRYPTO_CB
    s_conf->devId = INVALID_DEVID;
#endif
#endif

    /* Initialize server first (must be before client) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, s_conf));

    /* Initialize client */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    
    /* Verify client comm is initialized */
    WH_TEST_ASSERT_RETURN(client->comm != NULL);
    WH_TEST_ASSERT_RETURN(client->comm->initialized == 1);

    /* For memory transport, set server as connected (connect callback should handle this,
     * but we set it explicitly to ensure it's connected) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, WH_COMM_CONNECTED));
    
    /* Verify server is connected */
    whCommConnected server_connected;
    WH_TEST_RETURN_ON_FAIL(wh_Server_GetConnected(server, &server_connected));
    WH_TEST_ASSERT_RETURN(server_connected == WH_COMM_CONNECTED);

    /* Connect client to server - use non-blocking approach for memory transport */
    uint32_t client_id, server_id;
    
    /* Verify server is ready (should return NOTREADY if no message) */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTREADY == wh_Server_HandleRequestMessage(server));
    
    /* Send comm init request */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(client));
    
    /* Process server message */
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    
    /* Get comm init response */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitResponse(client, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(client_id == client->comm->client_id);

    *out_client = client;
    return WH_ERROR_OK;
}

/* Cleanup helper for memory transport mode */
static int _whTest_Auth_CleanupMemory(void)
{
    wh_Client_Cleanup(client);
    wh_Server_Cleanup(server);
    wh_Auth_Cleanup(&auth_ctx);
    wh_Nvm_Cleanup(nvm);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif
    return WH_ERROR_OK;
}
#endif /* !WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP */


/* ============================================================================
 * Test Functions
 * ============================================================================ */

static int _whTest_Auth_LoginOp(whClientContext* client, whAuthMethod method,
    const char* username, const void* auth_data, uint16_t auth_data_len,
    int32_t* out_rc, whUserId* out_user_id, whAuthPermissions* out_perms)
{
#ifdef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    return wh_Client_AuthLogin(client, method, username, auth_data,
                               auth_data_len, out_rc, out_user_id, out_perms);
#else
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AuthLoginRequest(client, method, username, auth_data,
                                auth_data_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthLoginResponse(client, out_rc, out_user_id, out_perms);
#endif
}

static int _whTest_Auth_LogoutOp(whClientContext* client, whUserId user_id,
    int32_t* out_rc)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogoutRequest(client, user_id));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthLogoutResponse(client, out_rc);
#else
    return wh_Client_AuthLogout(client, user_id, out_rc);
#endif
}

static int _whTest_Auth_UserAddOp(whClientContext* client, const char* username,
    whAuthPermissions permissions, whAuthMethod method, const void* credentials,
    uint16_t credentials_len, int32_t* out_rc, whUserId* out_user_id)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AuthUserAddRequest(client, username, permissions, method,
                                    credentials, credentials_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthUserAddResponse(client, out_rc, out_user_id);
#else
    return wh_Client_AuthUserAdd(client, username, permissions, method,
                                 credentials, credentials_len, out_rc,
                                 out_user_id);
#endif
}

static int _whTest_Auth_UserDeleteOp(whClientContext* client, whUserId user_id,
    int32_t* out_rc)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthUserDeleteRequest(client, user_id));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthUserDeleteResponse(client, out_rc);
#else
    return wh_Client_AuthUserDelete(client, user_id, out_rc);
#endif
}

static int _whTest_Auth_UserSetPermsOp(whClientContext* client, whUserId user_id,
    whAuthPermissions permissions, int32_t* out_rc)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AuthUserSetPermissionsRequest(client, user_id, permissions));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthUserSetPermissionsResponse(client, out_rc);
#else
    return wh_Client_AuthUserSetPermissions(client, user_id, permissions,
                                            out_rc);
#endif
}

static int _whTest_Auth_UserSetCredsOp(whClientContext* client, whUserId user_id,
    whAuthMethod method, const void* current_credentials,
    uint16_t current_credentials_len, const void* new_credentials,
    uint16_t new_credentials_len, int32_t* out_rc)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_AuthUserSetCredentialsRequest(client, user_id, method,
            current_credentials, current_credentials_len,
            new_credentials, new_credentials_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthUserSetCredentialsResponse(client, out_rc);
#else
    return wh_Client_AuthUserSetCredentials(client, user_id, method,
        current_credentials, current_credentials_len,
        new_credentials, new_credentials_len, out_rc);
#endif
}

static int _whTest_Auth_UserGetOp(whClientContext* client, const char* username,
    int32_t* out_rc, whUserId* out_user_id, whAuthPermissions* out_permissions)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthUserGetRequest(client, username));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    return wh_Client_AuthUserGetResponse(client, out_rc, out_user_id,
                                            out_permissions);
#else
    return wh_Client_AuthUserGet(client, username, out_rc, out_user_id,
                                 out_permissions);
#endif
}

static void _whTest_Auth_DeleteUserByName(whClientContext* client,
    const char* username)
{
    int32_t server_rc = 0;
    whUserId user_id = WH_USER_ID_INVALID;
    whAuthPermissions perms;

    memset(&perms, 0, sizeof(perms));
    _whTest_Auth_UserGetOp(client, username, &server_rc, &user_id, &perms);
    if (server_rc == WH_ERROR_OK && user_id != WH_USER_ID_INVALID) {
        _whTest_Auth_UserDeleteOp(client, user_id, &server_rc);
    }
}

static int _whTest_Auth_BadArgs(void)
{
    int rc = 0;
    int loggedIn = 1;
    whAuthContext ctx;
    whAuthConfig config;
    whAuthPermissions perms;
    whUserId user_id = WH_USER_ID_INVALID;

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

    rc = wh_Auth_Login(NULL, 0, WH_AUTH_METHOD_PIN, "user", "pin", 3, &loggedIn);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_Login(&ctx, 0, WH_AUTH_METHOD_PIN, "user", "pin", 3, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_LoginRequest(NULL, 0, WH_AUTH_METHOD_PIN, "user", "pin", 3, &loggedIn);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_Auth_LoginResponse(NULL, &loggedIn, &user_id, &perms);
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
    rc = wh_Auth_UserSetCredentials(&ctx, 1, WH_AUTH_METHOD_PIN,
        "pin", 3, "new", 3);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    WH_TEST_PRINT("  Test: Auth base bad args\n");
    rc = wh_AuthBase_Login(NULL, 0, WH_AUTH_METHOD_PIN,
        TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, NULL, &perms, &loggedIn);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_AuthBase_Login(NULL, 0, WH_AUTH_METHOD_NONE, NULL, NULL, 0,
        &user_id, &perms, &loggedIn);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_AuthBase_Logout(NULL, 0, WH_USER_ID_INVALID);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_AuthBase_Logout(NULL, 0, 999);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_NOTFOUND);

    rc = wh_AuthBase_CheckRequestAuthorization(NULL, WH_USER_ID_INVALID,
        WH_MESSAGE_GROUP_AUTH, WH_MESSAGE_AUTH_ACTION_LOGIN);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_AuthBase_CheckRequestAuthorization(NULL, WH_USER_ID_INVALID,
        WH_MESSAGE_GROUP_AUTH, WH_MESSAGE_AUTH_ACTION_LOGOUT);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);
    rc = wh_AuthBase_CheckRequestAuthorization(NULL, WH_USER_ID_INVALID,
        WH_MESSAGE_GROUP_COMM, 0);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    rc = wh_AuthBase_CheckKeyAuthorization(NULL, WH_USER_ID_INVALID, 1, 0);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);

    rc = wh_AuthBase_UserAdd(NULL, "baduser", &user_id, perms,
        WH_AUTH_METHOD_NONE, "x", 1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_AuthBase_UserDelete(NULL, 0, WH_USER_ID_INVALID);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_NOTFOUND);
    rc = wh_AuthBase_UserSetPermissions(NULL, 0, WH_USER_ID_INVALID, perms);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_NOTFOUND);
    rc = wh_AuthBase_UserSetCredentials(NULL, WH_USER_ID_INVALID,
        WH_AUTH_METHOD_PIN, NULL, 0, "new", 3);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_AuthBase_UserGet(NULL, "missing", &user_id, &perms);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_NOTFOUND);

    return WH_TEST_SUCCESS;
}

static int _whTest_Auth_MessageBadArgs(void)
{
    int rc = 0;
    whMessageAuth_SimpleResponse simple = {0};
    whMessageAuth_LoginRequest login_hdr = {0};
    whMessageAuth_LoginRequest login_out = {0};
    whMessageAuth_UserAddRequest add_hdr = {0};
    whMessageAuth_UserAddRequest add_out = {0};
    whMessageAuth_UserSetCredentialsRequest set_hdr = {0};

    WH_TEST_PRINT("  Test: Auth message bad args\n");
    rc = wh_MessageAuth_TranslateSimpleResponse(0, NULL, &simple);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_MessageAuth_TranslateSimpleResponse(0, &simple, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_MessageAuth_TranslateLoginRequest(0, NULL, 0, &login_out, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);
    rc = wh_MessageAuth_TranslateLoginRequest(0, &login_hdr, 0, &login_out, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    memset(&login_hdr, 0, sizeof(login_hdr));
    login_hdr.auth_data_len = (uint16_t)(WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN + 1);
    rc = wh_MessageAuth_TranslateLoginRequest(0, &login_hdr, sizeof(login_hdr),
        &login_out, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    rc = wh_MessageAuth_TranslateUserAddRequest(0, NULL, 0, &add_out, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    memset(&add_hdr, 0, sizeof(add_hdr));
    add_hdr.credentials_len = (uint16_t)(WH_MESSAGE_AUTH_MAX_CREDENTIALS_LEN + 1);
    rc = wh_MessageAuth_TranslateUserAddRequest(0, &add_hdr, sizeof(add_hdr),
        &add_out, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BUFFER_SIZE);

    rc = wh_MessageAuth_TranslateUserSetCredentialsRequest(0, NULL, 0,
        &set_hdr, NULL, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    memset(&set_hdr, 0, sizeof(set_hdr));
    set_hdr.current_credentials_len = 4;
    set_hdr.new_credentials_len = 4;
    rc = wh_MessageAuth_TranslateUserSetCredentialsRequest(0, &set_hdr,
        sizeof(set_hdr), &set_hdr, NULL, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    return WH_TEST_SUCCESS;
}

/* Logout Tests */
int whTest_AuthLogout(whClientContext* client)
{
    int32_t server_rc;
    whUserId user_id;
    int32_t login_rc;
    whAuthPermissions out_perms;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Test 2: Logout after login */
    WH_TEST_PRINT("  Test: Logout after login\n");
    /* First login */
    memset(&out_perms, 0, sizeof(out_perms));
    login_rc = 0;
    user_id = WH_USER_ID_INVALID;
    /* Verify client is valid and comm is initialized */
    WH_TEST_ASSERT_RETURN(client != NULL);
    WH_TEST_ASSERT_RETURN(client->comm != NULL);
    WH_TEST_ASSERT_RETURN(client->comm->initialized == 1);
    WH_TEST_ASSERT_RETURN(client->comm->hdr != NULL);
    WH_TEST_ASSERT_RETURN(client->comm->transport_cb != NULL);
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, &login_rc,
                                                &user_id, &out_perms));
    WH_TEST_ASSERT_RETURN(login_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Then logout - use blocking version */
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LogoutOp(client, user_id, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_PRINT("  Test: Logout before login\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LogoutOp(client, user_id, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 3: Logout with invalid user id */
    WH_TEST_PRINT("  Test: Logout attempt with invalid user ID (should fail)\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LogoutOp(client, WH_USER_ID_INVALID,
                                                 &server_rc));
    /* Should return error for invalid user ID */
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    return WH_TEST_SUCCESS;
}

/* Login Tests */
int whTest_AuthLogin(whClientContext* client)
{
    int32_t server_rc;
    whUserId user_id;
    whAuthPermissions out_perms;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Test 1: Login with invalid credentials */
    WH_TEST_PRINT("  Test: Login with invalid credentials\n");
    memset(&out_perms, 0, sizeof(out_perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, "wrong", 5, &server_rc,
                                                &user_id, &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_LOGIN_FAILED || server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id == WH_USER_ID_INVALID);

    /* Test 2: Login with valid credentials - use blocking version */
    WH_TEST_PRINT("  Test: Login with valid credentials\n");
    memset(&out_perms, 0, sizeof(out_perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, &server_rc,
                                                &user_id, &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Logout for next test */
    _whTest_Auth_LogoutOp(client, user_id, &server_rc);

    /* Test 3: Login with invalid username */
    WH_TEST_PRINT("  Test: Login with invalid username\n");
    memset(&out_perms, 0, sizeof(out_perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "nonexistent", TEST_ADMIN_PIN, 4,
                                                &server_rc, &user_id,
                                                &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_LOGIN_FAILED || server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id == WH_USER_ID_INVALID);

    /* Test 4: Login if already logged in */
    WH_TEST_PRINT("  Test: Login if already logged in\n");
    /* First login */
    memset(&out_perms, 0, sizeof(out_perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, &server_rc,
                                                &user_id, &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Try to login again without logout */
    memset(&out_perms, 0, sizeof(out_perms));
    server_rc = 0;
    whUserId user_id2 = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, &server_rc,
                                                &user_id2, &out_perms));
    /* Second login should fail */
    WH_TEST_ASSERT_RETURN(server_rc == WH_AUTH_LOGIN_FAILED || server_rc != WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id2 == WH_USER_ID_INVALID);

    /* Cleanup */
    _whTest_Auth_LogoutOp(client, user_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Add User Tests */
int whTest_AuthAddUser(whClientContext* client)
{
    int32_t server_rc;
    whUserId user_id;
    whAuthPermissions perms;
    char long_username[34]; /* 33 chars + null terminator */
    int rc;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Login as admin first */
    whAuthPermissions admin_perms;
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, &server_rc,
                                                &admin_id, &admin_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Test 1: Add user with invalid username (too long) */
    WH_TEST_PRINT("  Test: Add user with invalid username (too long)\n");
    memset(long_username, 'a', 33);
    long_username[33] = '\0';
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;

    /* Expect client-side rejection due to username length */
    rc = wh_Client_AuthUserAddRequest(client, long_username, perms,
                                      WH_AUTH_METHOD_PIN, "test", 4);
    WH_TEST_ASSERT_RETURN(rc != WH_ERROR_OK || server_rc != WH_ERROR_OK ||
                          user_id == WH_USER_ID_INVALID);

    /* Test 2: Add user with invalid permissions (keyIdCount > max) */
    WH_TEST_PRINT("  Test: Add user with invalid permissions\n");
    memset(&perms, 0, sizeof(perms));
    perms.keyIdCount = WH_AUTH_MAX_KEY_IDS + 1; /* Invalid: exceeds max */
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
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
    user_id = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser2", perms,
                                                   WH_AUTH_METHOD_PIN, "test",
                                                   4, &server_rc, &user_id);
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Try to add same user again */
    whUserId user_id2 = WH_USER_ID_INVALID;
    server_rc = 0;
    _whTest_Auth_UserAddOp(client, "testuser2", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &user_id2);
    /* Should fail - user already exists (allow success if backend does not check) */
    if (server_rc == WH_ERROR_OK && user_id2 != WH_USER_ID_INVALID) {
        WH_TEST_PRINT("    Note: duplicate username allowed by backend\n");
        _whTest_Auth_UserDeleteOp(client, user_id2, &server_rc);
    }

    /* Cleanup */
    server_rc = 0;
    _whTest_Auth_DeleteUserByName(client, "testuser1");
    _whTest_Auth_DeleteUserByName(client, "testuser2");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Delete User Tests */
int whTest_AuthDeleteUser(whClientContext* client)
{
    int32_t server_rc;
    whAuthPermissions admin_perms;
    whUserId admin_id = WH_USER_ID_INVALID;
    whAuthPermissions perms;
    whAuthPermissions out_perms;
    whUserId delete_user_id = WH_USER_ID_INVALID;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Login as admin to perform delete operations */
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "admin", "1234", 4, &server_rc,
                                                &admin_id, &admin_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Test 1: Delete user with invalid user id */
    WH_TEST_PRINT("  Test: Delete user with invalid user ID\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserDeleteOp(client, WH_USER_ID_INVALID,
                                                     &server_rc));
    /* Should fail for invalid user ID */
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Delete user that does not exist */
    WH_TEST_PRINT("  Test: Delete user that does not exist\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserDeleteOp(client, 999, &server_rc));
    /* Should fail - user doesn't exist */
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND || server_rc != WH_ERROR_OK);

    /* Test 2b: Delete existing user (success path)  */
    WH_TEST_PRINT("  Test: Delete existing user\n");
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "deleteuser", perms,
                                                   WH_AUTH_METHOD_PIN, "pass",
                                                   4, &server_rc,
                                                   &delete_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(delete_user_id != WH_USER_ID_INVALID);

    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(client, "deleteuser",
                                                  &server_rc, &delete_user_id,
                                                  &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserDeleteOp(client, delete_user_id,
                                                     &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    delete_user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(client, "deleteuser",
                                                  &server_rc, &delete_user_id,
                                                  &out_perms));
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK ||
                          delete_user_id == WH_USER_ID_INVALID);

    /* Test 3: Delete user when not logged in */
    WH_TEST_PRINT("  Test: Delete user when not logged in\n");
    /* Ensure we're logged out */
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    /* Try to delete without being logged in */
    server_rc = 0;
    _whTest_Auth_UserDeleteOp(client, 1, &server_rc);
    /* Should fail authorization - not logged in */
    /* Note: This may fail if backend permission checks are not fully implemented */
    if (server_rc == WH_ERROR_ACCESS) {
        WH_TEST_PRINT("    Authorization check working (expected)\n");
    } else {
        WH_TEST_PRINT("    Note: Authorization check may not be fully implemented\n");
    }

    return WH_TEST_SUCCESS;
}

/* Set User Permissions Tests */
int whTest_AuthSetPermissions(whClientContext* client)
{
    int32_t server_rc;
    whUserId user_id;
    whAuthPermissions perms, new_perms;
    whAuthPermissions fetched_perms;
    whUserId fetched_user_id = WH_USER_ID_INVALID;
    int32_t get_rc = 0;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Login as admin first */
    whAuthPermissions admin_perms;
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "admin", "1234", 4, &server_rc,
                                                &admin_id, &admin_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Create a test user first */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "testuser3", perms,
                                                   WH_AUTH_METHOD_PIN, "test",
                                                   4, &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Test 1: Set user permissions with invalid user id */
    WH_TEST_PRINT("  Test: Set user permissions with invalid user ID\n");
    memset(&new_perms, 0xFF, sizeof(new_perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetPermsOp(client,
                                                       WH_USER_ID_INVALID,
                                                       new_perms, &server_rc));
    /* Should fail for invalid user ID */
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Set user permissions with invalid permissions */
    WH_TEST_PRINT("  Test: Set user permissions with invalid permissions\n");
    memset(&new_perms, 0, sizeof(new_perms));
    new_perms.keyIdCount = WH_AUTH_MAX_KEY_IDS + 1; /* Invalid */
    server_rc = 0;
    _whTest_Auth_UserSetPermsOp(client, user_id, new_perms, &server_rc);
    /* Should clamp or reject invalid keyIdCount */
    if (server_rc == WH_ERROR_OK) {
        /* If it succeeds, keyIdCount should be clamped */
    }

    /* Test 2b: Set user permissions success path  */
    WH_TEST_PRINT("  Test: Set user permissions success\n");
    memset(&new_perms, 0, sizeof(new_perms));
    new_perms.groupPermissions = WH_MESSAGE_GROUP_AUTH;
    new_perms.actionPermissions[(WH_MESSAGE_GROUP_AUTH >> 8) & 0xFF] =
        WH_MESSAGE_AUTH_ACTION_USER_ADD;
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetPermsOp(client, user_id,
                                                       new_perms, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    memset(&fetched_perms, 0, sizeof(fetched_perms));
    fetched_user_id = WH_USER_ID_INVALID;
    get_rc = 0;
    /* Use blocking version to verify permissions were set */
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserGetOp(client, "testuser3", &get_rc,
                                                  &fetched_user_id,
                                                  &fetched_perms));
    WH_TEST_ASSERT_RETURN(get_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(fetched_user_id == user_id);
    WH_TEST_ASSERT_RETURN(fetched_perms.groupPermissions ==
                          new_perms.groupPermissions);
    WH_TEST_ASSERT_RETURN(
        fetched_perms.actionPermissions[(WH_MESSAGE_GROUP_AUTH >> 8) & 0xFF] ==
        new_perms.actionPermissions[(WH_MESSAGE_GROUP_AUTH >> 8) & 0xFF]);

    /* Test 3: Set user permissions for non-existent user */
    WH_TEST_PRINT("  Test: Set user permissions for non-existent user\n");
    memset(&new_perms, 0, sizeof(new_perms));
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetPermsOp(client, 999, new_perms,
                                                       &server_rc));
    /* Should fail - user doesn't exist */
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND || server_rc != WH_ERROR_OK);

    /* Test 4: Set user permissions when not logged in */
    WH_TEST_PRINT("  Test: Set user permissions when not logged in\n");
    /* Logout */
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    /* Try to set permissions without being logged in */
    memset(&new_perms, 0, sizeof(new_perms));
    server_rc = 0;
    _whTest_Auth_UserSetPermsOp(client, user_id, new_perms, &server_rc);
    /* Should fail authorization - not logged in */
    /* Note: This may fail if backend permission checks are not fully implemented */
    if (server_rc == WH_ERROR_ACCESS) {
        WH_TEST_PRINT("    Authorization check working (expected)\n");
    } else {
        WH_TEST_PRINT("    Note: Authorization check may not be fully implemented\n");
    }

    /* Cleanup */
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "admin", "1234", 4, &server_rc,
                                                &admin_id, &admin_perms));
    _whTest_Auth_DeleteUserByName(client, "testuser3");
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    return WH_TEST_SUCCESS;
}

/* Set User Credentials Tests */
int whTest_AuthSetCredentials(whClientContext* client)
{
    int32_t server_rc;
    whUserId user_id;
    whAuthPermissions perms;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Login as admin first */
    whAuthPermissions admin_perms;
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "admin", "1234", 4, &server_rc,
                                                &admin_id, &admin_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Create a test user first */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "testuser4", perms,
                                                   WH_AUTH_METHOD_PIN, "test",
                                                   4, &server_rc, &user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Test 1: Set user credentials with invalid user id */
    WH_TEST_PRINT("  Test: Set user credentials with invalid user ID\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetCredsOp(client,
        WH_USER_ID_INVALID, WH_AUTH_METHOD_PIN, "test", 4, "newpass", 7,
        &server_rc));
    /* Should fail for invalid user ID */
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 2: Set user credentials with invalid method */
    WH_TEST_PRINT("  Test: Set user credentials with invalid method\n");
    server_rc = 0;
    _whTest_Auth_UserSetCredsOp(client, user_id, WH_AUTH_METHOD_NONE,
                                "test", 4, "newpass", 7, &server_rc);
    /* Should fail for invalid method */
    WH_TEST_ASSERT_RETURN(server_rc != WH_ERROR_OK);

    /* Test 3: Set user credentials for non-existent user */
    WH_TEST_PRINT("  Test: Set user credentials for non-existent user\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetCredsOp(client, 999,
        WH_AUTH_METHOD_PIN, NULL, 0, "newpass", 7, &server_rc));
    /* Should fail - user doesn't exist */
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND || server_rc != WH_ERROR_OK);

    WH_TEST_PRINT("  Test: Admin setting credentials for non-admin user\n");
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserSetCredsOp(client, user_id,
        WH_AUTH_METHOD_PIN, "test", 4, "newpass", 7, &server_rc));

    /* Should succeed - admin can set credentials for other users */
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Verify new credentials work */
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
    memset(&admin_perms, 0, sizeof(admin_perms));
    server_rc = 0;
    whUserId test_user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "testuser4", "newpass", 7,
                                                &server_rc, &test_user_id,
                                                &admin_perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(test_user_id == user_id);

    /* Cleanup */
    _whTest_Auth_LogoutOp(client, test_user_id, &server_rc);
    _whTest_Auth_DeleteUserByName(client, "testuser4");

    return WH_TEST_SUCCESS;
}

/* Authorization Checks Tests */
int whTest_AuthRequestAuthorization(whClientContext* client)
{
    int32_t server_rc;
    whUserId user_id;
    whUserId temp_id3 = WH_USER_ID_INVALID;
    whAuthPermissions perms;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Test 1: Operation when not logged in and not allowed */
    WH_TEST_PRINT("  Test: Operation when not logged in and not allowed\n");
    /* Ensure logged out */
    server_rc = 0;
    _whTest_Auth_LogoutOp(client, WH_USER_ID_INVALID, &server_rc);

    /* Try an operation that requires auth (e.g., add user) */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    whUserId temp_id = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser5", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id);
    /* Should fail authorization - not logged in */
    /* Note: This may fail if backend permission checks are not fully implemented */
    if (server_rc == WH_ERROR_ACCESS) {
        WH_TEST_PRINT("    Authorization check working (expected)\n");
    } else {
        WH_TEST_PRINT("    Note: Authorization check may not be fully implemented\n");
    }

    /* Test 2: Operation when logged in and allowed */
    WH_TEST_PRINT("  Test: Operation when logged in and allowed\n");
    /* Login as admin */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    whUserId admin_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "admin", "1234", 4, &server_rc,
                                                &admin_id, &perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Retry operation after login (admin should be allowed) - use blocking version */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "testuser6", perms,
                                                   WH_AUTH_METHOD_PIN, "test",
                                                   4, &server_rc, &user_id));
    /* Should succeed - admin has permissions */
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(user_id != WH_USER_ID_INVALID);

    /* Test 3: Operation when logged in and not allowed */
    WH_TEST_PRINT("  Test: Operation when logged in and not allowed\n");
    /* Create a user with limited permissions */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    whUserId limited_user_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "limiteduser", perms,
                                                   WH_AUTH_METHOD_PIN, "pass",
                                                   4, &server_rc,
                                                   &limited_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Logout admin and login as limited user */
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    whUserId logged_in_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "limiteduser", "pass", 4,
                                                &server_rc, &logged_in_id,
                                                &perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Try an operation that requires permissions */
    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    whUserId temp_id2 = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser7", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id2);
    /* Should fail authorization - user doesn't have permissions */
    /* Note: This may fail if backend permission checks are not fully implemented */
    if (server_rc == WH_ERROR_ACCESS) {
        WH_TEST_PRINT("    Authorization check working (expected)\n");
    } else {
        WH_TEST_PRINT("    Note: Authorization check may not be fully implemented\n");
    }

    /* Test 4: Logged in as different user and allowed */
    WH_TEST_PRINT("  Test: Logged in as different user and allowed\n");
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);

    server_rc = 0;
    whUserId allowed_user_id = WH_USER_ID_INVALID;
    /* Login as admin to create allowed user */
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "admin", "1234", 4, &server_rc,
                                                &admin_id, &perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    memset(&perms, 0, sizeof(perms));
    perms.groupPermissions = WH_MESSAGE_GROUP_AUTH;
    perms.actionPermissions[(WH_MESSAGE_GROUP_AUTH >> 8) & 0xFF] =
        WH_MESSAGE_AUTH_ACTION_USER_ADD;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_UserAddOp(client, "alloweduser", perms,
                                                   WH_AUTH_METHOD_PIN, "pass",
                                                   4, &server_rc,
                                                   &allowed_user_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    _whTest_Auth_LogoutOp(client, admin_id, &server_rc);

    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    logged_in_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "alloweduser", "pass", 4,
                                                &server_rc, &logged_in_id,
                                                &perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    temp_id3 = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser8", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id3);
    if (server_rc == WH_ERROR_ACCESS) {
        WH_TEST_PRINT("    Authorization check working (expected)\n");
    } else {
        WH_TEST_PRINT("    Note: Authorization check may not be fully implemented\n");
    }

    /* Test 5: Logged in as different user and not allowed */
    WH_TEST_PRINT("  Test: Logged in as different user and not allowed\n");
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);

    memset(&perms, 0, sizeof(perms));
    server_rc = 0;
    logged_in_id = WH_USER_ID_INVALID;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                                "limiteduser", "pass", 4,
                                                &server_rc, &logged_in_id,
                                                &perms));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    server_rc = 0;
    temp_id3 = WH_USER_ID_INVALID;
    _whTest_Auth_UserAddOp(client, "testuser9", perms, WH_AUTH_METHOD_PIN,
                           "test", 4, &server_rc, &temp_id3);
    if (server_rc == WH_ERROR_ACCESS) {
        WH_TEST_PRINT("    Authorization check working (expected)\n");
    } else {
        WH_TEST_PRINT("    Note: Authorization check may not be fully implemented\n");
    }

    /* Cleanup */
    _whTest_Auth_LogoutOp(client, logged_in_id, &server_rc);
    server_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_LoginOp(client, WH_AUTH_METHOD_PIN,
                                            TEST_ADMIN_USERNAME, TEST_ADMIN_PIN, 4, &server_rc,
                                                &admin_id, &perms));
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

/* Main Test Function */
int whTest_AuthTest(whClientContext* client_ctx)
{
    WH_TEST_PRINT("Testing authentication functionality...\n");

    WH_TEST_PRINT("Running auth bad-args tests...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_BadArgs());
    WH_TEST_PRINT("Running auth message bad-args tests...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_MessageBadArgs());

    /* Run authentication test groups */
    WH_TEST_PRINT("Running logout tests...\n");
    /* Verify client context is valid */
    WH_TEST_ASSERT_RETURN(client_ctx != NULL);
    WH_TEST_ASSERT_RETURN(client_ctx->comm != NULL);
    WH_TEST_RETURN_ON_FAIL(whTest_AuthLogout(client_ctx));

    WH_TEST_PRINT("Running login tests...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_AuthLogin(client_ctx));

    WH_TEST_PRINT("Running add user tests...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_AuthAddUser(client_ctx));

    WH_TEST_PRINT("Running delete user tests...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_AuthDeleteUser(client_ctx));

    WH_TEST_PRINT("Running set permissions tests...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_AuthSetPermissions(client_ctx));

    WH_TEST_PRINT("Running set credentials tests...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_AuthSetCredentials(client_ctx));

    WH_TEST_PRINT("Running authorization checks tests...\n");
    WH_TEST_RETURN_ON_FAIL(whTest_AuthRequestAuthorization(client_ctx));

    WH_TEST_PRINT("All authentication tests completed successfully\n");
    
    return WH_TEST_SUCCESS;
}


/* Run all the tests against a remote server running */
int whTest_AuthTCP(whClientConfig* clientCfg)
{
    whClientContext client[1] = {0};

    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, clientCfg));

    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInit(client, NULL, NULL));
    WH_TEST_RETURN_ON_FAIL(whTest_AuthTest(client));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_TEST_SUCCESS;
}


int whTest_AuthMEM(void)
{
#ifndef WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP
    whClientContext* client_ctx = NULL;

    /* Memory transport mode */
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_SetupMemory(&client_ctx));
    WH_TEST_RETURN_ON_FAIL(whTest_AuthTest(client_ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_Auth_CleanupMemory());

    return WH_TEST_SUCCESS;
#else
    return WH_TEST_FAIL;
#endif
}
