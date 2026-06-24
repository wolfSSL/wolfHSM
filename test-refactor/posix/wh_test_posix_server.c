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
 * test-refactor/wh_test_posix_server.c
 *
 * POSIX server-side init. Stand-in for what a real firmware's
 * boot flow would do: configure flash/NVM, init crypto, wire
 * up a transport, and bring up a server context.
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
#include "wolfhsm/wh_auth.h"
#include "wolfhsm/wh_auth_base.h"
#endif
#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#endif

#include "wh_test_common.h"
#include "wh_test_list.h"
#include "wh_test_posix_server.h"

#define POSIX_FLASH_SIZE       (1024 * 1024)
#define POSIX_FLASH_SECTOR_SZ  (128 * 1024)
#define POSIX_FLASH_PAGE_SZ    (8)
/* Sized to hold the mem-transport CSR plus a full WH_COMM_MTU
 * comm packet -- the wolfCrypt test (TESTWOLFCRYPT=1) needs the
 * full window for ML-DSA/Dilithium keys and signatures. */
#define POSIX_TRANSPORT_BUF_SZ (sizeof(whTransportMemCsr) + WH_COMM_MTU)


/* Flash (ramsim backing) */
static uint8_t          _flashMem[POSIX_FLASH_SIZE];
static whFlashRamsimCtx _flashCtx;
static whFlashRamsimCfg _flashCfg;
static const whFlashCb  _flashCb = WH_FLASH_RAMSIM_CB;

/* NVM wrapping the flash */
static whNvmFlashContext _nvmFlashCtx;
static whNvmFlashConfig  _nvmFlashCfg;
static whNvmCb           _nvmCb = WH_NVM_FLASH_CB;
static whNvmContext      _nvm;

#ifndef WOLFHSM_CFG_NO_CRYPTO
static whServerCryptoContext _crypto;
#endif

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif

/* Counter for checking CheckRequestAuthorization callback */
static int _checkReqAuthCount = 0;

static int _countCheckRequestAuth(void* context, int err, uint16_t user_id,
                                  uint16_t group, uint16_t action)
{
    (void)context;
    (void)user_id;
    (void)group;
    (void)action;
    _checkReqAuthCount++;
    return err;
}

/* Hook into CheckRequestAuthorization callback to ensure it fires.
 * Note that CheckKeyAuthorization is not implemented, so it is not checked. */
static whAuthCb _authCb = {
    .Init                      = wh_Auth_BaseInit,
    .Cleanup                   = wh_Auth_BaseCleanup,
    .Login                     = wh_Auth_BaseLogin,
    .Logout                    = wh_Auth_BaseLogout,
    .CheckRequestAuthorization = _countCheckRequestAuth,
    .UserAdd                   = wh_Auth_BaseUserAdd,
    .UserDelete                = wh_Auth_BaseUserDelete,
    .UserSetPermissions        = wh_Auth_BaseUserSetPermissions,
    .UserGet                   = wh_Auth_BaseUserGet,
    .UserSetCredentials        = wh_Auth_BaseUserSetCredentials,
};
static whAuthContext _auth;
#endif
#ifdef WOLFHSM_CFG_SHE_EXTENSION
/* SHE keystore/crypto state for the shared server (uidSet, sbState) */
static whServerSheContext _she;
#endif

/* Mem transport -- buffers and server-side state.
 * The client side re-uses these buffers via
 * whTestPosix_Server_GetTransportConfig. */
static uint8_t                     _req[POSIX_TRANSPORT_BUF_SZ];
static uint8_t                     _resp[POSIX_TRANSPORT_BUF_SZ];
static whTransportMemConfig        _tmCfg;
static whTransportMemServerContext _tmServerCtx;
static const whTransportServerCb   _tsCb = WH_TRANSPORT_MEM_SERVER_CB;
static whCommServerConfig          _commCfg;


int whTestPosix_Server_Init(whServerContext* server)
{
    whNvmConfig    nvmCfg;
    whServerConfig sCfg;

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Flash backend */
    memset(&_flashCtx, 0, sizeof(_flashCtx));
    memset(&_flashCfg, 0, sizeof(_flashCfg));
    _flashCfg.size       = POSIX_FLASH_SIZE;
    _flashCfg.sectorSize = POSIX_FLASH_SECTOR_SZ;
    _flashCfg.pageSize   = POSIX_FLASH_PAGE_SZ;
    _flashCfg.erasedByte = 0xFF;
    _flashCfg.memory     = _flashMem;

    /* Transport */
    memset(&_tmCfg, 0, sizeof(_tmCfg));
    _tmCfg.req       = (whTransportMemCsr*)_req;
    _tmCfg.req_size  = sizeof(_req);
    _tmCfg.resp      = (whTransportMemCsr*)_resp;
    _tmCfg.resp_size = sizeof(_resp);

    memset(&_commCfg, 0, sizeof(_commCfg));
    _commCfg.transport_cb      = &_tsCb;
    _commCfg.transport_context = (void*)&_tmServerCtx;
    _commCfg.transport_config  = (void*)&_tmCfg;
    _commCfg.server_id         = 1;

    /* NVM -- flash ctx/cfg/cb wired by pointer */
    memset(&_nvmFlashCfg, 0, sizeof(_nvmFlashCfg));
    _nvmFlashCfg.cb      = &_flashCb;
    _nvmFlashCfg.context = &_flashCtx;
    _nvmFlashCfg.config  = &_flashCfg;

    memset(&nvmCfg, 0, sizeof(nvmCfg));
    nvmCfg.cb      = &_nvmCb;
    nvmCfg.context = &_nvmFlashCtx;
    nvmCfg.config  = &_nvmFlashCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(&_nvm, &nvmCfg));

#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(
        wc_InitRng_ex(_crypto.rng, NULL, INVALID_DEVID));
#endif

    memset(&sCfg, 0, sizeof(sCfg));
    sCfg.comm_config = &_commCfg;
    sCfg.nvm         = &_nvm;
#ifndef WOLFHSM_CFG_NO_CRYPTO
    sCfg.crypto     = &_crypto;
    sCfg.devId      = INVALID_DEVID;
#endif

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    {
        whAuthConfig      authCfg = {0};
        whAuthPermissions perms;
        whUserId          adminId = WH_USER_ID_INVALID;
        int               i;

        authCfg.cb = &_authCb;
        WH_TEST_RETURN_ON_FAIL(wh_Auth_Init(&_auth, &authCfg));

        /* Admin user: full permissions, no key-id restrictions. */
        memset(&perms, 0xFF, sizeof(perms));
        perms.keyIdCount = 0;
        for (i = 0; i < WH_AUTH_MAX_KEY_IDS; i++) {
            perms.keyIds[i] = 0;
        }
        WH_TEST_RETURN_ON_FAIL(wh_Auth_BaseUserAdd(
            &_auth, TEST_ADMIN_USERNAME, &adminId, perms, WH_AUTH_METHOD_PIN,
            TEST_ADMIN_PIN, (uint16_t)strlen(TEST_ADMIN_PIN)));

        sCfg.auth = &_auth;
    }
#endif
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    memset(&_she, 0, sizeof(_she));
    sCfg.she = &_she;
#endif

    return wh_Server_Init(server, &sCfg);
}


int whTestPosix_Server_Cleanup(whServerContext* server)
{
    if (server == NULL) {
        return 0;
    }

    wh_Server_Cleanup(server);
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    wh_Auth_Cleanup(&_auth);
#endif
    wh_Nvm_Cleanup(&_nvm);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(_crypto.rng);
    wolfCrypt_Cleanup();
#endif

    return 0;
}


whTransportMemConfig* whTestPosix_Server_GetTransportConfig(void)
{
    return &_tmCfg;
}


int whTestPosix_Server_VerifyAuthCallbacks(void)
{
#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    /* The request-auth hook fires on every gated request, so expect non-0.
     * Note that the key-auth hook is an unwired placeholder, and is not
     * checked. */
    WH_TEST_ASSERT_RETURN(_checkReqAuthCount > 0);
    return WH_TEST_SUCCESS;
#else
    /* Nothing to verify without authentication compiled in. */
    return WH_TEST_SKIPPED;
#endif
}
