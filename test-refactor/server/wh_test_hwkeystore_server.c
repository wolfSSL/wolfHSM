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
 * test-refactor/server/wh_test_hwkeystore_server.c
 *
 * Server-side hardware keystore coverage that needs no client:
 *
 *   _whTest_HwKeystoreModule     - wh_HwKeystore_Init/Register/CheckUse/
 *                                  KeyRef/Cleanup: argument validation, the
 *                                  records, and the owner, usage and trust
 *                                  checks, using a local context (the shared
 *                                  server context is not touched)
 *   _whTest_HwKeystoreLifecycle  - optional backend Init/Cleanup hook dispatch
 *                                  and the Init-failure return path, using a
 *                                  backend that records its calls
 *   _whTest_KeystoreHwOnlyReject - every public keystore entry point must
 *                                  reject a hardware keyId with
 *                                  WH_ERROR_ACCESS before reaching the cache
 *                                  or NVM
 *
 * End-to-end use of hardware keys is covered by the misc group tests
 * misc/wh_test_hwkeystore.c (key wrap KEKs) and
 * misc/wh_test_hwkeystore_crypto.c (AES, CMAC and client loading), which bind
 * a hardware keystore to their own client/server pairs.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && defined(WOLFHSM_CFG_HWKEYSTORE)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_hwkeystore.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* ID and size of the hardware key the module tests register first */
#define WH_TEST_HWKEK_ID 3
#define WH_TEST_HWKEK_SIZE 32

/* USER field value for constructing server-internal hardware keyIds */
#define WH_TEST_HW_USER 1

/* Backend context recording optional Init/Cleanup hook dispatch. initRet and
 * cleanupRet let a test force the Init/Cleanup failure paths; initConfig
 * captures the config pointer forwarded to Init to prove it is plumbed
 * through */
typedef struct {
    int         initCalls;
    int         cleanupCalls;
    int         initRet;
    int         cleanupRet;
    const void* initConfig;
} HwKeystoreLifecycle;

static int _HwKeystoreInit(void* context, const void* config)
{
    HwKeystoreLifecycle* lc = (HwKeystoreLifecycle*)context;
    if (lc != NULL) {
        lc->initCalls++;
        lc->initConfig = config;
        return lc->initRet;
    }
    return WH_ERROR_OK;
}

static int _HwKeystoreCleanup(void* context)
{
    HwKeystoreLifecycle* lc = (HwKeystoreLifecycle*)context;
    if (lc != NULL) {
        lc->cleanupCalls++;
        return lc->cleanupRet;
    }
    return WH_ERROR_OK;
}

/* clang-format off */
static const whHwKeystoreCb _hwKeystoreLifecycleCb = {
    .Init    = _HwKeystoreInit,
    .Cleanup = _HwKeystoreCleanup,
};
/* clang-format on */

/* wh_HwKeystore front end in isolation: argument validation, the records, and
 * the checks the server makes on every use of a hardware key */
static int _whTest_HwKeystoreModule(void)
{
    whHwKeystoreContext hwks[1] = {{0}};
    whHwKeystoreConfig  conf[1] = {{0}};
    /* A shared port key, and a port key for one client */
    whKeyId shared =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYUSER_GLOBAL, WH_TEST_HWKEK_ID);
    whKeyId owned =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, WH_TEST_HWKEK_ID + 1);
    /* The same keys as the client and another client name them */
    whKeyId sharedByUser =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, WH_TEST_HWKEK_ID);
    whKeyId ownedByOther =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER + 1, WH_TEST_HWKEK_ID + 1);
    whKeyId out = WH_KEYID_ERASED;
    uint8_t ref[WH_HWKEYSTORE_REF_SIZE];
    int     i;

    /* Init needs a context and a config; the hook table is optional */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_HwKeystore_Init(NULL, conf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_HwKeystore_Init(hwks, NULL));

    /* An uninitialized context is refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_Register(hwks, shared,
                                                 WH_NVM_FLAGS_USAGE_WRAP,
                                                 WH_TEST_HWKEK_SIZE));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_CheckUse(hwks, sharedByUser,
                                                 WH_NVM_FLAGS_USAGE_WRAP,
                                                 &out));

    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwks, conf));

    /* The key reference is the server keyId, big-endian */
    wh_HwKeystore_KeyRef(shared, ref);
    WH_TEST_ASSERT_RETURN((ref[0] == (uint8_t)(shared >> 8)) &&
                          (ref[1] == (uint8_t)shared));

    /* Only hardware keyIds with a nonzero ID can be registered */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_HwKeystore_Register(hwks,
                               WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                             WH_KEYUSER_GLOBAL,
                                             WH_TEST_HWKEK_ID),
                               WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_HWKEK_SIZE));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_HwKeystore_Register(
            hwks, WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYUSER_GLOBAL, 0),
            WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_HWKEK_SIZE));

    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Register(
        hwks, shared, WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_HWKEK_SIZE));
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Register(
        hwks, owned, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        16));

    /* One record per hardware key number, whoever owns it */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_HwKeystore_Register(hwks, sharedByUser,
                                                 WH_NVM_FLAGS_USAGE_WRAP,
                                                 WH_TEST_HWKEK_SIZE));

    /* A shared key: any client can use it, and the recorded keyId comes back
     * for the key reference */
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_CheckUse(
        hwks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP, &out));
    WH_TEST_ASSERT_RETURN(out == shared);

    /* Port keys are trusted */
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_CheckUse(
        hwks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP | WH_NVM_FLAGS_TRUSTED,
        &out));

    /* The usage must match, and some usage is needed */
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                          wh_HwKeystore_CheckUse(hwks, sharedByUser,
                                                 WH_NVM_FLAGS_USAGE_ENCRYPT,
                                                 &out));
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                          wh_HwKeystore_CheckUse(hwks, sharedByUser, 0, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_USAGE ==
        wh_HwKeystore_CheckUse(hwks, sharedByUser, WH_NVM_FLAGS_TRUSTED, &out));

    /* A key for one client: only that client can use it */
    WH_TEST_RETURN_ON_FAIL(
        wh_HwKeystore_CheckUse(hwks, owned, WH_NVM_FLAGS_USAGE_ENCRYPT, &out));
    WH_TEST_ASSERT_RETURN(out == owned);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_HwKeystore_CheckUse(hwks, ownedByOther,
                                                 WH_NVM_FLAGS_USAGE_ENCRYPT,
                                                 &out));

    /* No record, a non-hardware keyId, ID 0, and no output */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_HwKeystore_CheckUse(hwks,
                               WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, 9),
                               WH_NVM_FLAGS_USAGE_ENCRYPT, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_HwKeystore_CheckUse(
            hwks,
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_HW_USER, WH_TEST_HWKEK_ID),
            WH_NVM_FLAGS_USAGE_WRAP, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_HwKeystore_CheckUse(hwks,
                               WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, 0),
                               WH_NVM_FLAGS_USAGE_WRAP, &out));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_CheckUse(hwks, sharedByUser,
                                                 WH_NVM_FLAGS_USAGE_WRAP,
                                                 NULL));

    /* The records run out */
    for (i = 2; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
        WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Register(
            hwks, WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYUSER_GLOBAL, 10 + i),
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16));
    }
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOSPACE ==
        wh_HwKeystore_Register(
            hwks, WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYUSER_GLOBAL, 9),
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16));

    /* Cleanup zeroizes the context, after which it is refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_HwKeystore_Cleanup(NULL));
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Cleanup(hwks));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_CheckUse(hwks, sharedByUser,
                                                 WH_NVM_FLAGS_USAGE_WRAP,
                                                 &out));

    return WH_ERROR_OK;
}

/* Optional backend Init/Cleanup hook dispatch and the Init-failure return
 * path, using a backend that records its hook calls */
static int _whTest_HwKeystoreLifecycle(void)
{
    HwKeystoreLifecycle lc            = {0};
    whHwKeystoreContext hwks[1]       = {{0}};
    whHwKeystoreConfig  conf[1]       = {{0}};
    const int           backendConfig = 0; /* sentinel forwarded to Init */
    whKeyId             keyId =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYUSER_GLOBAL, WH_TEST_HWKEK_ID);
    whKeyId out = WH_KEYID_ERASED;

    conf->cb      = &_hwKeystoreLifecycleCb;
    conf->context = &lc;
    conf->config  = &backendConfig;

    /* Init-failure path: the backend Init rc is propagated, the config pointer
     * was forwarded, and the context is left uninitialized (Register refuses
     * it). Cleanup must NOT have run for a backend whose Init never
     * succeeded */
    lc.initRet = WH_ERROR_ABORTED;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED == wh_HwKeystore_Init(hwks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);
    WH_TEST_ASSERT_RETURN(lc.initConfig == &backendConfig);
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 0);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_Register(hwks, keyId,
                                                 WH_NVM_FLAGS_USAGE_WRAP,
                                                 WH_TEST_HWKEK_SIZE));

    /* Init-success path: the backend Init is dispatched exactly once and the
     * context becomes usable */
    lc.initRet   = WH_ERROR_OK;
    lc.initCalls = 0;
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Register(
        hwks, keyId, WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_HWKEK_SIZE));

    /* Cleanup dispatches the backend Cleanup exactly once */
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Cleanup(hwks));
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 1);

    /* Cleanup-failure path: a backend Cleanup error is surfaced to the caller,
     * yet the context is still torn down (it is refused afterwards) */
    lc.initRet      = WH_ERROR_OK;
    lc.initCalls    = 0;
    lc.cleanupCalls = 0;
    lc.cleanupRet   = WH_ERROR_ABORTED;
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwks, conf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED == wh_HwKeystore_Cleanup(hwks));
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 1);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_HwKeystore_CheckUse(hwks, keyId, WH_NVM_FLAGS_USAGE_WRAP, &out));

    return WH_ERROR_OK;
}

/* Hardware keyIds must be rejected by every public keystore entry point
 * with WH_ERROR_ACCESS (or WH_ERROR_BADARGS for id generation). These checks
 * are pure keyId-type checks: they fire whether or not a hardware keystore
 * is bound to the server, and before the cache or NVM is consulted */
static int _whTest_KeystoreHwOnlyReject(whServerContext* server)
{
    whKeyId hwId =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, WH_TEST_HWKEK_ID);
    uint8_t        keyBuf[WH_TEST_HWKEK_SIZE] = {0};
    uint8_t*       outBuf                     = NULL;
    whNvmMetadata* outMeta                    = NULL;
    whNvmMetadata  meta                       = {0};
    uint32_t       outSz                      = sizeof(keyBuf);
    whNvmId        uniqueId;

    /* Id generation: the port defines hardware key ids, so the keystore never
     * assigns one */
    uniqueId = WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, 0);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_Server_KeystoreGetUniqueId(server, &uniqueId));

    /* Cache slot allocation (also the sole guard on the DMA cache path) */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreGetCacheSlot(
                              server, hwId, sizeof(keyBuf), &outBuf, &outMeta));

    /* Caching key material under a hardware key id */
    meta.id  = hwId;
    meta.len = sizeof(keyBuf);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreCacheKey(server, &meta, keyBuf));

    /* Freshen: how crypto handlers resolve keystore keys. A hardware key never
     * resolves here; the handlers use it by reference instead */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == wh_Server_KeystoreFreshenKey(
                                                 server, hwId, NULL, NULL));

    /* Reading hardware key material out of the keystore */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_Server_KeystoreReadKey(server, hwId, NULL, keyBuf, &outSz));

    /* Lifecycle operations */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEvictKey(server, hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreCommitKey(server, hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEraseKey(server, hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEraseKeyChecked(server, hwId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreRevokeKey(server, hwId));

    return WH_ERROR_OK;
}

int whTest_HwKeystoreServer(whServerContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_HwKeystoreModule());
    WH_TEST_RETURN_ON_FAIL(_whTest_HwKeystoreLifecycle());
    WH_TEST_RETURN_ON_FAIL(_whTest_KeystoreHwOnlyReject(ctx));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && WOLFHSM_CFG_HWKEYSTORE */
