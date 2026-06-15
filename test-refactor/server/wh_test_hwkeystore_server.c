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
 *   _whTest_HwKeystoreModule     - wh_HwKeystore_Init/GetKey/Cleanup argument
 *                                  validation and GetKey dispatch, using a
 *                                  local context (the shared server context
 *                                  is not touched)
 *   _whTest_HwKeystoreLifecycle  - optional backend Init/Cleanup callback
 *                                  dispatch and the Init-failure return path,
 *                                  using a backend that records its calls
 *   _whTest_KeystoreHwOnlyReject - every public keystore entry point must
 *                                  reject a hardware-only keyId with
 *                                  WH_ERROR_ACCESS before reaching the cache,
 *                                  NVM, or any hardware backend (none is
 *                                  bound to the shared server). FreshenKey is
 *                                  also the choke point through which all
 *                                  crypto handlers resolve keys, so this
 *                                  covers crypto key use of hardware-only ids
 *
 * End-to-end keywrap use of hardware-only KEKs is covered by the misc group
 * test misc/wh_test_hwkeystore.c, which binds a hardware keystore to its own
 * private client/server pair.
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

/* Id and material of the only key served by the local test backend */
#define WH_TEST_HWKEK_ID 3
#define WH_TEST_HWKEK_SIZE 32

/* USER field value for constructing server-internal hardware-only keyIds */
#define WH_TEST_HW_USER 1

static const uint8_t _hwKekMaterial[WH_TEST_HWKEK_SIZE] = {
    0x9a, 0x4e, 0x21, 0xc7, 0x5d, 0x10, 0xfb, 0x33, 0x6f, 0x82, 0xd4,
    0x59, 0xee, 0x07, 0xb1, 0x2c, 0x48, 0x95, 0x3a, 0xc6, 0x71, 0x0d,
    0xb8, 0xe5, 0x12, 0x6a, 0xf9, 0x84, 0x2f, 0xd0, 0x5b, 0xa7};

static int _HwKeystoreGetKey(void* context, whKeyId keyId, uint8_t* out,
                             uint16_t* inout_len)
{
    (void)context;

    /* Only hardware-only keyIds should ever reach a hardware keystore */
    if (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_HW) {
        return WH_ERROR_ACCESS;
    }

    /* Serve only the known test KEK id, refuse everything else */
    if (WH_KEYID_ID(keyId) != WH_TEST_HWKEK_ID) {
        return WH_ERROR_NOTFOUND;
    }

    if ((out == NULL) || (inout_len == NULL) ||
        (*inout_len < sizeof(_hwKekMaterial))) {
        return WH_ERROR_BUFFER_SIZE;
    }

    memcpy(out, _hwKekMaterial, sizeof(_hwKekMaterial));
    *inout_len = sizeof(_hwKekMaterial);
    return WH_ERROR_OK;
}

/* clang-format off */
static const whHwKeystoreCb _hwKeystoreCb = {
    .Init    = NULL,
    .Cleanup = NULL,
    .GetKey  = _HwKeystoreGetKey,
};
/* clang-format on */

/* Backend context recording optional Init/Cleanup callback dispatch. initRet
 * and cleanupRet let a test force the Init/Cleanup failure paths; initConfig
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
    .GetKey  = _HwKeystoreGetKey,
};
/* clang-format on */

/* wh_HwKeystore module front-end in isolation: argument validation, callback
 * dispatch, and lifecycle */
static int _whTest_HwKeystoreModule(void)
{
    int                 ret;
    whHwKeystoreContext hwks[1]    = {{0}};
    whHwKeystoreConfig  conf[1]    = {{0}};
    whHwKeystoreConfig  badConf[1] = {{0}};
    whKeyId             servedId =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, WH_TEST_HWKEK_ID);
    uint8_t  out[WH_TEST_HWKEK_SIZE] = {0};
    uint16_t outLen                  = sizeof(out);

    conf->cb = &_hwKeystoreCb;

    /* Init argument validation: NULL context/config/getKey are rejected */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_HwKeystore_Init(NULL, conf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_HwKeystore_Init(hwks, NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_Init(hwks, badConf));

    /* GetKey must reject NULL and uninitialized contexts */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(NULL, servedId, out, &outLen));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(hwks, servedId, out, &outLen));

    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwks, conf));

    /* GetKey argument validation on an initialized context */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(hwks, servedId, NULL, &outLen));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(hwks, servedId, out, NULL));

    /* Served id: material and reported length must match the backend's */
    ret = wh_HwKeystore_GetKey(hwks, servedId, out, &outLen);
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == ret);
    WH_TEST_ASSERT_RETURN(outLen == sizeof(_hwKekMaterial));
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(out, _hwKekMaterial, sizeof(_hwKekMaterial)));

    /* Backend policy: unserved id, undersized buffer, non-HW type */
    outLen = sizeof(out);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_HwKeystore_GetKey(
            hwks,
            WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, WH_TEST_HWKEK_ID + 1),
            out, &outLen));
    outLen = WH_TEST_HWKEK_SIZE - 1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BUFFER_SIZE ==
                          wh_HwKeystore_GetKey(hwks, servedId, out, &outLen));
    outLen = sizeof(out);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_HwKeystore_GetKey(
            hwks,
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_HW_USER, WH_TEST_HWKEK_ID),
            out, &outLen));

    /* Cleanup zeroizes the context, after which GetKey must reject it */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_HwKeystore_Cleanup(NULL));
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Cleanup(hwks));
    outLen = sizeof(out);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(hwks, servedId, out, &outLen));

    return WH_ERROR_OK;
}

/* Optional backend Init/Cleanup dispatch and the Init-failure return path,
 * using a backend that records its callback invocations */
static int _whTest_HwKeystoreLifecycle(void)
{
    HwKeystoreLifecycle lc            = {0};
    whHwKeystoreContext hwks[1]       = {{0}};
    whHwKeystoreConfig  conf[1]       = {{0}};
    const int           backendConfig = 0; /* sentinel forwarded to Init */
    whKeyId             servedId =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, WH_TEST_HWKEK_ID);
    uint8_t  out[WH_TEST_HWKEK_SIZE] = {0};
    uint16_t outLen                  = sizeof(out);

    conf->cb      = &_hwKeystoreLifecycleCb;
    conf->context = &lc;
    conf->config  = &backendConfig;

    /* Init-failure path: the backend Init rc is propagated, the config pointer
     * was forwarded, and the context is left uninitialized (GetKey rejects it).
     * Cleanup must NOT have run for a backend whose Init never succeeded */
    lc.initRet = WH_ERROR_ABORTED;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED == wh_HwKeystore_Init(hwks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);
    WH_TEST_ASSERT_RETURN(lc.initConfig == &backendConfig);
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 0);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(hwks, servedId, out, &outLen));

    /* Init-success path: the backend Init is dispatched exactly once and the
     * context becomes usable */
    lc.initRet   = WH_ERROR_OK;
    lc.initCalls = 0;
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);

    outLen = sizeof(out);
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_GetKey(hwks, servedId, out, &outLen));
    WH_TEST_ASSERT_RETURN(outLen == sizeof(_hwKekMaterial));

    /* Cleanup dispatches the backend Cleanup exactly once */
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Cleanup(hwks));
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 1);

    /* Cleanup-failure path: a backend Cleanup error is surfaced to the caller,
     * yet the context is still torn down (a subsequent GetKey rejects it) */
    lc.initRet      = WH_ERROR_OK;
    lc.initCalls    = 0;
    lc.cleanupCalls = 0;
    lc.cleanupRet   = WH_ERROR_ABORTED;
    WH_TEST_RETURN_ON_FAIL(wh_HwKeystore_Init(hwks, conf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED == wh_HwKeystore_Cleanup(hwks));
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 1);
    outLen = sizeof(out);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_HwKeystore_GetKey(hwks, servedId, out, &outLen));

    return WH_ERROR_OK;
}

/* Hardware-only keyIds must be rejected by every public keystore entry point
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

    /* Id generation: hardware-only ids are assigned by the backend, never by
     * the keystore */
    uniqueId = WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_TEST_HW_USER, 0);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_Server_KeystoreGetUniqueId(server, &uniqueId));

    /* Cache slot allocation (also the sole guard on the DMA cache path) */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreGetCacheSlot(
                              server, hwId, sizeof(keyBuf), &outBuf, &outMeta));

    /* Caching key material under a hardware-only id */
    meta.id  = hwId;
    meta.len = sizeof(keyBuf);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreCacheKey(server, &meta, keyBuf));

    /* Freshen: the resolution path used by all crypto handlers, so this also
     * proves crypto operations cannot use hardware-only keys */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS == wh_Server_KeystoreFreshenKey(
                                                 server, hwId, NULL, NULL));

    /* Reading hardware-only key material out of the keystore */
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
