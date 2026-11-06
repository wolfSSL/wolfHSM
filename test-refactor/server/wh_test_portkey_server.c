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
 * test-refactor/server/wh_test_portkey_server.c
 *
 * Server-side port key coverage that needs no client:
 *
 *   _whTest_PortKeyModule         - wh_PortKey_Init/RegisterFixed/CheckUse/
 *                                   KeyIdToRef/KeyRefToId/Cleanup: argument
 *                                   validation, the records, and the owner,
 *                                   usage and trust checks, using a local
 *                                   context (the shared server context is
 *                                   not touched)
 *   _whTest_PortKeyLoadable       - wh_PortKey_RegisterLoadable, and what
 *                                   the front end does with an empty key
 *                                   before it would call the port
 *   _whTest_PortKeyLifecycle      - optional backend Init/Cleanup hook
 *                                   dispatch and the Init-failure return
 *                                   path, using a backend that records its
 *                                   calls
 *   _whTest_KeystorePortKeyReject - every public keystore entry point must
 *                                   reject a port keyId with WH_ERROR_ACCESS
 *                                   before reaching the cache or NVM
 *
 * End-to-end use of port keys is covered by the misc group tests
 * misc/wh_test_portkey.c (key wrap KEKs) and
 * misc/wh_test_portkey_crypto.c (AES, CMAC and client loading), which bind
 * port keys to their own client/server pairs.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && defined(WOLFHSM_CFG_PORTKEY)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_portkey.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"

#ifdef WOLFHSM_CFG_PORTKEY_LOAD
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#endif

#include "wh_test_common.h"
#include "wh_test_list.h"

/* ID and size of the port key the module tests register first */
#define WH_TEST_PORTKEK_ID 3
#define WH_TEST_PORTKEK_SIZE 32

/* USER field value for constructing server-internal port keyIds */
#define WH_TEST_PORT_USER 1

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
} PortKeyLifecycle;

static int _PortKeyInit(void* context, const void* config)
{
    PortKeyLifecycle* lc = (PortKeyLifecycle*)context;
    if (lc != NULL) {
        lc->initCalls++;
        lc->initConfig = config;
        return lc->initRet;
    }
    return WH_ERROR_OK;
}

static int _PortKeyCleanup(void* context)
{
    PortKeyLifecycle* lc = (PortKeyLifecycle*)context;
    if (lc != NULL) {
        lc->cleanupCalls++;
        return lc->cleanupRet;
    }
    return WH_ERROR_OK;
}

/* clang-format off */
static const whPortKeyCb _portKeyLifecycleCb = {
    .Init    = _PortKeyInit,
    .Cleanup = _PortKeyCleanup,
};
/* clang-format on */

/* wh_PortKey front end in isolation: argument validation, the records, and
 * the checks the server makes on every use of a port key */
static int _whTest_PortKeyModule(void)
{
    whPortKeyContext pks[1]  = {{0}};
    whPortKeyConfig  conf[1] = {{0}};
    /* A shared fixed key, and a fixed key for one client */
    whKeyId shared =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, WH_TEST_PORTKEK_ID);
    whKeyId owned = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER,
                                  WH_TEST_PORTKEK_ID + 1);
    /* The same keys as the client and another client name them */
    whKeyId sharedByUser =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, WH_TEST_PORTKEK_ID);
    whKeyId ownedByOther = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER + 1,
                                         WH_TEST_PORTKEK_ID + 1);
    whKeyId out          = WH_KEYID_ERASED;
    uint8_t ref[WH_PORTKEY_REF_SIZE];
    int     i;

    /* Init needs a context and a config; the hook table is optional */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_PortKey_Init(NULL, conf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_PortKey_Init(pks, NULL));

    /* An uninitialized context is refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_RegisterFixed(pks, shared,
                                                   WH_NVM_FLAGS_USAGE_WRAP,
                                                   WH_TEST_PORTKEK_SIZE));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP, &out));

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));

    /* The key reference is the server keyId, big-endian */
    wh_PortKey_KeyIdToRef(shared, ref);
    WH_TEST_ASSERT_RETURN((ref[0] == (uint8_t)(shared >> 8)) &&
                          (ref[1] == (uint8_t)shared));

    /* The port reads the port key number from it, whoever owns the key */
    WH_TEST_ASSERT_RETURN(wh_PortKey_KeyRefToId(ref, sizeof(ref)) ==
                          WH_TEST_PORTKEK_ID);
    wh_PortKey_KeyIdToRef(owned, ref);
    WH_TEST_ASSERT_RETURN(wh_PortKey_KeyRefToId(ref, sizeof(ref)) ==
                          WH_TEST_PORTKEK_ID + 1);

    /* Not a port key reference: the wrong size, no reference, or another
     * key type */
    WH_TEST_ASSERT_RETURN(wh_PortKey_KeyRefToId(ref, sizeof(ref) - 1) == 0);
    WH_TEST_ASSERT_RETURN(wh_PortKey_KeyRefToId(NULL, sizeof(ref)) == 0);
    wh_PortKey_KeyIdToRef(
        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_KEYUSER_GLOBAL, WH_TEST_PORTKEK_ID),
        ref);
    WH_TEST_ASSERT_RETURN(wh_PortKey_KeyRefToId(ref, sizeof(ref)) == 0);

    /* Only port keyIds with a nonzero ID can be registered */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(
            pks,
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_KEYUSER_GLOBAL,
                          WH_TEST_PORTKEK_ID),
            WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, 0),
            WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE));

    /* A fixed key needs a size */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(pks, shared, WH_NVM_FLAGS_USAGE_WRAP, 0));

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, shared, WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, owned, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        16));

    /* One record per port key number, whoever owns it */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterFixed(pks, sharedByUser,
                                                   WH_NVM_FLAGS_USAGE_WRAP,
                                                   WH_TEST_PORTKEK_SIZE));

    /* A shared key: any client can use it, and the recorded keyId comes back
     * for the key reference */
    WH_TEST_RETURN_ON_FAIL(
        wh_PortKey_CheckUse(pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP, &out));
    WH_TEST_ASSERT_RETURN(out == shared);

    /* Fixed keys are trusted */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_CheckUse(
        pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP | WH_NVM_FLAGS_TRUSTED,
        &out));

    /* The usage must match, and some usage is needed */
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                          wh_PortKey_CheckUse(pks, sharedByUser,
                                              WH_NVM_FLAGS_USAGE_ENCRYPT,
                                              &out));
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                          wh_PortKey_CheckUse(pks, sharedByUser, 0, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_USAGE ==
        wh_PortKey_CheckUse(pks, sharedByUser, WH_NVM_FLAGS_TRUSTED, &out));

    /* A key for one client: only that client can use it */
    WH_TEST_RETURN_ON_FAIL(
        wh_PortKey_CheckUse(pks, owned, WH_NVM_FLAGS_USAGE_ENCRYPT, &out));
    WH_TEST_ASSERT_RETURN(out == owned);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_CheckUse(pks, ownedByOther,
                                              WH_NVM_FLAGS_USAGE_ENCRYPT,
                                              &out));

    /* No record, a non-port keyId, ID 0, and no output */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_PortKey_CheckUse(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 9),
            WH_NVM_FLAGS_USAGE_ENCRYPT, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(pks,
                            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_PORT_USER,
                                          WH_TEST_PORTKEK_ID),
                            WH_NVM_FLAGS_USAGE_WRAP, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 0),
            WH_NVM_FLAGS_USAGE_WRAP, &out));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP, NULL));

    /* The records run out */
    for (i = 2; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
        WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, 10 + i),
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16));
    }
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOSPACE ==
        wh_PortKey_RegisterFixed(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, 9),
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16));

    /* Cleanup zeroizes the context, after which it is refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_PortKey_Cleanup(NULL));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Cleanup(pks));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP, &out));

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_PORTKEY_LOAD
/* Registering loadable keys, and the requests on an empty one that the front
 * end answers without calling the port. No device is registered for devId,
 * so a call into the port would fail */
static int _whTest_PortKeyLoadable(void)
{
    whPortKeyContext pks[1]  = {{0}};
    whPortKeyConfig  conf[1] = {{0}};
    whKeyId          fixedKey =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, WH_TEST_PORTKEK_ID);
    whKeyId loadable     = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER,
                                         WH_TEST_PORTKEK_ID + 1);
    whKeyId unregistered = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 9);
    whKeyId keyId;
    whKeyId out = WH_KEYID_ERASED;
    whPortKeyInfo info;
    uint8_t       key[16] = {0};
    int           devId   = INVALID_DEVID;
    int           i;

    /* An uninitialized context is refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_RegisterLoadable(pks, loadable));

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));

    /* Only port keyIds with a nonzero ID can be registered */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterLoadable(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_PORT_USER,
                               WH_TEST_PORTKEK_ID + 1)));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterLoadable(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 0)));

    /* One record per port key number, whichever kind it is */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, fixedKey, WH_NVM_FLAGS_USAGE_ENCRYPT, 16));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterLoadable(pks, loadable));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterLoadable(pks, fixedKey));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterLoadable(pks, loadable));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterFixed(
                              pks, loadable, WH_NVM_FLAGS_USAGE_ENCRYPT, 16));

    /* An empty key can't be used or cleared, and describes as all zeros */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_PortKey_CheckUse(pks, loadable, WH_NVM_FLAGS_USAGE_ENCRYPT, &out));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_Clear(pks, devId, loadable));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_ClearAll(pks, devId, WH_TEST_PORT_USER));
    memset(&info, 0xFF, sizeof(info));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_GetInfo(pks, loadable, &info));
    WH_TEST_ASSERT_RETURN((info.keyType == 0) && (info.keyBits == 0) &&
                          (info.flags == 0) && (info.owner == 0));

    /* A fixed key describes from its record */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_GetInfo(pks, fixedKey, &info));
    WH_TEST_ASSERT_RETURN((info.keyType == WC_KEYSTORE_KEY_AES) &&
                          (info.keyBits == 128) &&
                          (info.flags == WH_NVM_FLAGS_USAGE_ENCRYPT) &&
                          (info.owner == WH_KEYUSER_GLOBAL));

    /* A key the port didn't register can't be described or loaded, and a
     * fixed key can't be loaded */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_GetInfo(pks, unregistered, &info));
    keyId = unregistered;
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_Load(pks, devId, &keyId, WH_KEYID_ERASED,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          sizeof(key)));
    keyId = fixedKey;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_Load(pks, devId, &keyId, WH_KEYID_ERASED,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          sizeof(key)));

    /* Both kinds share the records */
    for (i = 2; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
        WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterLoadable(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, 10 + i)));
    }
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE ==
                          wh_PortKey_RegisterLoadable(pks, unregistered));

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Cleanup(pks));
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_PORTKEY_LOAD */

/* Optional backend Init/Cleanup hook dispatch and the Init-failure return
 * path, using a backend that records its hook calls */
static int _whTest_PortKeyLifecycle(void)
{
    PortKeyLifecycle lc            = {0};
    whPortKeyContext pks[1]        = {{0}};
    whPortKeyConfig  conf[1]       = {{0}};
    const int        backendConfig = 0; /* sentinel forwarded to Init */
    whKeyId          keyId =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, WH_TEST_PORTKEK_ID);
    whKeyId out = WH_KEYID_ERASED;

    conf->cb      = &_portKeyLifecycleCb;
    conf->context = &lc;
    conf->config  = &backendConfig;

    /* Init-failure path: the backend Init rc is propagated, the config pointer
     * was forwarded, and the context is left uninitialized (Register refuses
     * it). Cleanup must NOT have run for a backend whose Init never
     * succeeded */
    lc.initRet = WH_ERROR_ABORTED;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED == wh_PortKey_Init(pks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);
    WH_TEST_ASSERT_RETURN(lc.initConfig == &backendConfig);
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 0);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_RegisterFixed(pks, keyId,
                                                   WH_NVM_FLAGS_USAGE_WRAP,
                                                   WH_TEST_PORTKEK_SIZE));

    /* Init-success path: the backend Init is dispatched exactly once and the
     * context becomes usable */
    lc.initRet   = WH_ERROR_OK;
    lc.initCalls = 0;
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, keyId, WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE));

    /* Cleanup dispatches the backend Cleanup exactly once */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Cleanup(pks));
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 1);

    /* Cleanup-failure path: a backend Cleanup error is surfaced to the caller,
     * yet the context is still torn down (it is refused afterwards) */
    lc.initRet      = WH_ERROR_OK;
    lc.initCalls    = 0;
    lc.cleanupCalls = 0;
    lc.cleanupRet   = WH_ERROR_ABORTED;
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED == wh_PortKey_Cleanup(pks));
    WH_TEST_ASSERT_RETURN(lc.cleanupCalls == 1);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(pks, keyId, WH_NVM_FLAGS_USAGE_WRAP, &out));

    return WH_ERROR_OK;
}

/* Port keyIds must be rejected by every public keystore entry point
 * with WH_ERROR_ACCESS (or WH_ERROR_BADARGS for id generation). These checks
 * are pure keyId-type checks: they fire whether or not port keys
 * are bound to the server, and before the cache or NVM is consulted */
static int _whTest_KeystorePortKeyReject(whServerContext* server)
{
    whKeyId portKeyId =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, WH_TEST_PORTKEK_ID);
    uint8_t        keyBuf[WH_TEST_PORTKEK_SIZE] = {0};
    uint8_t*       outBuf                       = NULL;
    whNvmMetadata* outMeta                      = NULL;
    whNvmMetadata  meta                         = {0};
    uint32_t       outSz                        = sizeof(keyBuf);
    whNvmId        uniqueId;

    /* Id generation: the port defines port key ids, so the keystore never
     * assigns one */
    uniqueId = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 0);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_Server_KeystoreGetUniqueId(server, &uniqueId));

    /* Cache slot allocation (also the sole guard on the DMA cache path) */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreGetCacheSlot(server, portKeyId,
                                                         sizeof(keyBuf),
                                                         &outBuf, &outMeta));

    /* Caching key material under a port key id */
    meta.id  = portKeyId;
    meta.len = sizeof(keyBuf);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreCacheKey(server, &meta, keyBuf));

    /* Freshen: how crypto handlers resolve keystore keys. A port key never
     * resolves here; the handlers use it by reference instead */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_Server_KeystoreFreshenKey(server, portKeyId, NULL, NULL));

    /* Reading port key material out of the keystore */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_Server_KeystoreReadKey(server, portKeyId, NULL, keyBuf, &outSz));

    /* Lifecycle operations */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEvictKey(server, portKeyId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreCommitKey(server, portKeyId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEraseKey(server, portKeyId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEraseKeyChecked(server, portKeyId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreRevokeKey(server, portKeyId));

    return WH_ERROR_OK;
}

int whTest_PortKeyServer(whServerContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyModule());
#ifdef WOLFHSM_CFG_PORTKEY_LOAD
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyLoadable());
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyLifecycle());
    WH_TEST_RETURN_ON_FAIL(_whTest_KeystorePortKeyReject(ctx));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && WOLFHSM_CFG_PORTKEY */
