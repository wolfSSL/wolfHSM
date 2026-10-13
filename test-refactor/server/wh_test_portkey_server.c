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
 *   _whTest_PortKeyByValue        - by-value fixed keys and wh_PortKey_Resolve/
 *                                   Read: an unknown access mode is refused,
 *                                   and the port's export runs only after the
 *                                   usual checks and leaves no key bytes
 *                                   behind when it fails
 *   _whTest_PortKeyLoadable       - wh_PortKey_RegisterLoadable, and what
 *                                   the front end does with an empty key
 *                                   before it would call the port
 *   _whTest_PortKeyNotReady       - a port's WH_ERROR_NOTREADY from a load or
 *                                   clear comes back as WH_ERROR_ABORTED,
 *                                   using a port that answers only keystore
 *                                   requests
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

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* ID and size of the port key the module tests register first */
#define WH_TEST_PORTKEK_ID 3
#define WH_TEST_PORTKEK_SIZE 32

/* USER field value for constructing server-internal port keyIds */
#define WH_TEST_PORT_USER 1

/* A port's own error code, for the export to fail with */
#define WH_TEST_PORT_ERROR (-30001)

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

/* devId of the port in _whTest_PortKeyByValue ("PKBV") */
#define WH_TEST_BYVALUE_DEVID 0x504B4256

/* Export state for _whTest_PortKeyByValue. ret makes the export fail, and
 * extra makes it report the wrong key size */
typedef struct {
    int     calls;
    whKeyId lastKeyId;
    int     ret;
    int     extra;
} PortKeyByValue;

static const uint8_t _byValueKey[16] = {
    0x3c, 0x81, 0x5e, 0x09, 0xd2, 0x47, 0xa8, 0x6b,
    0x10, 0xf5, 0x92, 0x2d, 0xc4, 0x7e, 0x33, 0xb9,
};

/* A port that only exports by-value keys */
static int _PortKeyExportCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    PortKeyByValue* rd = (PortKeyByValue*)ctx;
    const byte*     ref;
    byte*           out;
    word32*         outSz;

    (void)devId;
    if ((info->algo_type != WC_ALGO_TYPE_KEYSTORE) ||
        (info->keystore.type != WC_KEYSTORE_EXPORT_PLAIN) ||
        (info->keystore.op.exportPlain.keyRefSz != WH_PORTKEY_REF_SIZE)) {
        return CRYPTOCB_UNAVAILABLE;
    }
    ref   = info->keystore.op.exportPlain.keyRef;
    out   = info->keystore.op.exportPlain.key;
    outSz = info->keystore.op.exportPlain.keySz;

    rd->calls++;
    /* The reference is the registered keyId, big-endian */
    rd->lastKeyId = (whKeyId)(((whKeyId)ref[0] << 8) | ref[1]);
    if (rd->ret != 0) {
        /* Write part of a key, which must not be left behind */
        if (out != NULL) {
            out[0] = 0xA5;
        }
        return rd->ret;
    }
    if (out == NULL) {
        /* Size query */
        *outSz = sizeof(_byValueKey);
        return 0;
    }
    if (*outSz < sizeof(_byValueKey)) {
        return BUFFER_E;
    }
    memcpy(out, _byValueKey, sizeof(_byValueKey));
    *outSz = (word32)(sizeof(_byValueKey) + rd->extra);
    return 0;
}

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
                          wh_PortKey_RegisterFixed(
                              pks, shared, WH_NVM_FLAGS_USAGE_WRAP,
                              WH_TEST_PORTKEK_SIZE, WH_PORTKEY_ACCESS_BY_REF));
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
        wh_PortKey_RegisterFixed(pks,
                                 WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                               WH_KEYUSER_GLOBAL,
                                               WH_TEST_PORTKEK_ID),
                                 WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
                                 WH_PORTKEY_ACCESS_BY_REF));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, 0),
            WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
            WH_PORTKEY_ACCESS_BY_REF));

    /* A fixed key needs a size */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_RegisterFixed(pks, shared,
                                                   WH_NVM_FLAGS_USAGE_WRAP, 0,
                                                   WH_PORTKEY_ACCESS_BY_REF));

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, shared, WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
        WH_PORTKEY_ACCESS_BY_REF));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, owned, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, 16,
        WH_PORTKEY_ACCESS_BY_REF));

    /* One record per port key number, whoever owns it */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterFixed(
                              pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP,
                              WH_TEST_PORTKEK_SIZE, WH_PORTKEY_ACCESS_BY_REF));

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
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16, WH_PORTKEY_ACCESS_BY_REF));
    }
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOSPACE ==
        wh_PortKey_RegisterFixed(
            pks, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, 9),
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16, WH_PORTKEY_ACCESS_BY_REF));

    /* Cleanup zeroizes the context, after which it is refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_PortKey_Cleanup(NULL));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Cleanup(pks));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_CheckUse(pks, sharedByUser, WH_NVM_FLAGS_USAGE_WRAP, &out));

    return WH_ERROR_OK;
}

/* By-value keys: the front end gets their bytes from the port's export, but
 * only after the same checks as wh_PortKey_CheckUse() */
static int _whTest_PortKeyByValue(void)
{
    PortKeyByValue   rd      = {0};
    whPortKeyContext pks[1]  = {{0}};
    whPortKeyConfig  conf[1] = {{0}};
    int              devId   = WH_TEST_BYVALUE_DEVID;
    /* A shared by-value key, one for one client, and a key used by reference */
    whKeyId byValue =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL, WH_TEST_PORTKEK_ID);
    whKeyId owned = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER,
                                  WH_TEST_PORTKEK_ID + 1);
    whKeyId byRef = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL,
                                  WH_TEST_PORTKEK_ID + 2);
    /* The same keys as the client and another client name them */
    whKeyId byValueByUser =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, WH_TEST_PORTKEK_ID);
    whKeyId ownedByOther = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER + 1,
                                         WH_TEST_PORTKEK_ID + 1);
    whKeyId byRefByUser  = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER,
                                         WH_TEST_PORTKEK_ID + 2);
    whKeyId out          = WH_KEYID_ERASED;
    uint8_t key[32];
    uint16_t keySz;
    int      i;

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));

    /* An unknown access mode is refused, also one that is 0 in a byte */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(pks, byValue, WH_NVM_FLAGS_USAGE_ENCRYPT, 16,
                                 WH_PORTKEY_ACCESS_BY_VALUE + 1));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_RegisterFixed(pks, byValue,
                                                   WH_NVM_FLAGS_USAGE_ENCRYPT,
                                                   16, 0x100));

    /* A by-value key needs a size, and shares the records with other keys */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(pks, byValue, WH_NVM_FLAGS_USAGE_ENCRYPT, 0,
                                 WH_PORTKEY_ACCESS_BY_VALUE));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_RegisterFixed(
            pks,
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_KEYUSER_GLOBAL,
                          WH_TEST_PORTKEK_ID),
            WH_NVM_FLAGS_USAGE_ENCRYPT, 16, WH_PORTKEY_ACCESS_BY_VALUE));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, byValue, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DERIVE,
        16, WH_PORTKEY_ACCESS_BY_VALUE));
    WH_TEST_RETURN_ON_FAIL(
        wh_PortKey_RegisterFixed(pks, owned, WH_NVM_FLAGS_USAGE_ENCRYPT, 16,
                                 WH_PORTKEY_ACCESS_BY_VALUE));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, byRef, WH_NVM_FLAGS_USAGE_ENCRYPT, 16, WH_PORTKEY_ACCESS_BY_REF));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_PortKey_RegisterFixed(pks, byValueByUser, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                 16, WH_PORTKEY_ACCESS_BY_VALUE));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_PortKey_RegisterFixed(pks, byValueByUser, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                 16, WH_PORTKEY_ACCESS_BY_REF));

    /* With no device to export it, a by-value key can't be read */
    keySz = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_Read(pks, INVALID_DEVID, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    WH_TEST_RETURN_ON_FAIL(
        wc_CryptoCb_RegisterDevice(devId, _PortKeyExportCb, &rd));
    WH_TEST_ASSERT_RETURN(rd.calls == 0);

    /* The bytes come from the port, which gets the registered keyId */
    keySz = sizeof(key);
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Read(
        pks, devId, byValueByUser, WH_NVM_FLAGS_USAGE_DERIVE, key, &keySz));
    WH_TEST_ASSERT_RETURN((keySz == sizeof(_byValueKey)) &&
                          (memcmp(key, _byValueKey, keySz) == 0));
    WH_TEST_ASSERT_RETURN((rd.calls == 1) && (rd.lastKeyId == byValue));

    /* Resolve returns a by-value key's bytes, with no key reference */
    memset(key, 0, sizeof(key));
    keySz = sizeof(key);
    out   = byRef;
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Resolve(pks, devId, byValueByUser,
                                              WH_NVM_FLAGS_USAGE_ENCRYPT, &out,
                                              key, &keySz));
    WH_TEST_ASSERT_RETURN((out == WH_KEYID_ERASED) &&
                          (keySz == sizeof(_byValueKey)) &&
                          (memcmp(key, _byValueKey, keySz) == 0));
    /* and the recorded keyId, with no bytes, for a key used by reference */
    keySz = sizeof(key);
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Resolve(pks, devId, byRefByUser,
                                              WH_NVM_FLAGS_USAGE_ENCRYPT, &out,
                                              key, &keySz));
    WH_TEST_ASSERT_RETURN((out == byRef) && (keySz == 0));
    WH_TEST_ASSERT_RETURN(rd.calls == 2);

    /* Read refuses a key used by reference */
    keySz = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_Read(pks, devId, byRefByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));

    /* CheckUse accepts a by-value key without reading it. It is trusted */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_CheckUse(
        pks, byValueByUser, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_TRUSTED,
        &out));
    WH_TEST_ASSERT_RETURN(out == byValue);
    WH_TEST_ASSERT_RETURN(rd.calls == 2);

    /* Refused requests never reach the port */
    keySz = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_ERROR_USAGE ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_DECRYPT, key,
                                          &keySz));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_Read(pks, devId, ownedByOther,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_PortKey_Read(pks, devId,
                        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 9),
                        WH_NVM_FLAGS_USAGE_ENCRYPT, key, &keySz));
    keySz = sizeof(_byValueKey) - 1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BUFFER_SIZE ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    WH_TEST_ASSERT_RETURN(rd.calls == 2);

    /* Only its client can read the key it owns */
    keySz = sizeof(key);
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Read(
        pks, devId, owned, WH_NVM_FLAGS_USAGE_ENCRYPT, key, &keySz));
    WH_TEST_ASSERT_RETURN((rd.calls == 3) && (rd.lastKeyId == owned));

    /* A failed export leaves no key bytes behind, and its error comes back */
    rd.ret = WH_TEST_PORT_ERROR;
    memset(key, 0x5A, sizeof(key));
    keySz = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_TEST_PORT_ERROR ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    for (i = 0; i < (int)sizeof(key); i++) {
        WH_TEST_ASSERT_RETURN(key[i] == 0);
    }

    /* except NOTREADY, which a blocking client would wait on forever */
    rd.ret = WH_ERROR_NOTREADY;
    keySz  = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    rd.ret = WH_ERROR_OK;

    /* Nor does a key of the wrong size */
    rd.extra = 1;
    memset(key, 0x5A, sizeof(key));
    keySz = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    for (i = 0; i < (int)sizeof(key); i++) {
        WH_TEST_ASSERT_RETURN(key[i] == 0);
    }
    rd.extra = 0;

    /* Bad arguments */
    keySz = sizeof(key);
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_Read(NULL, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          &keySz));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, NULL,
                                          &keySz));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_Read(pks, devId, byValueByUser,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_PortKey_Resolve(pks, devId, byValueByUser,
                                             WH_NVM_FLAGS_USAGE_ENCRYPT, NULL,
                                             key, &keySz));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_Read(pks, devId,
                        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_PORT_USER,
                                      WH_TEST_PORTKEK_ID),
                        WH_NVM_FLAGS_USAGE_ENCRYPT, key, &keySz));
    WH_TEST_ASSERT_RETURN(rd.calls == 6);

#ifdef WOLFHSM_CFG_PORTKEY_LOAD
    /* Like any fixed key, clients can't clear or replace it, and it describes
     * from its record */
    {
        whPortKeyInfo info;

        WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                              wh_PortKey_Clear(pks, INVALID_DEVID, byValue));
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_ACCESS ==
            wh_PortKey_Load(pks, INVALID_DEVID, byValueByUser, WH_KEYID_ERASED,
                            WH_NVM_FLAGS_USAGE_ENCRYPT, _byValueKey,
                            sizeof(_byValueKey)));
        WH_TEST_RETURN_ON_FAIL(
            wh_PortKey_ClearAll(pks, INVALID_DEVID, WH_TEST_PORT_USER));
        WH_TEST_RETURN_ON_FAIL(wh_PortKey_GetInfo(pks, byValue, &info));
        WH_TEST_ASSERT_RETURN((info.keyBits == 128) &&
                              (info.flags == (WH_NVM_FLAGS_USAGE_ENCRYPT |
                                              WH_NVM_FLAGS_USAGE_DERIVE)) &&
                              (info.owner == WH_KEYUSER_GLOBAL));
        keySz = sizeof(key);
        WH_TEST_RETURN_ON_FAIL(wh_PortKey_Read(
            pks, devId, owned, WH_NVM_FLAGS_USAGE_ENCRYPT, key, &keySz));
    }
#endif /* WOLFHSM_CFG_PORTKEY_LOAD */

    wc_CryptoCb_UnRegisterDevice(devId);
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Cleanup(pks));
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
    whKeyId out          = WH_KEYID_ERASED;
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
    WH_TEST_RETURN_ON_FAIL(
        wh_PortKey_RegisterFixed(pks, fixedKey, WH_NVM_FLAGS_USAGE_ENCRYPT, 16,
                                 WH_PORTKEY_ACCESS_BY_REF));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterLoadable(pks, loadable));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterLoadable(pks, fixedKey));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_RegisterLoadable(pks, loadable));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_ACCESS ==
        wh_PortKey_RegisterFixed(pks, loadable, WH_NVM_FLAGS_USAGE_ENCRYPT, 16,
                                 WH_PORTKEY_ACCESS_BY_REF));

    /* An empty key can't be used or cleared, and describes as all zeros */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_PortKey_CheckUse(pks, loadable, WH_NVM_FLAGS_USAGE_ENCRYPT, &out));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_Clear(pks, devId, loadable));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_ClearAll(pks, devId, WH_TEST_PORT_USER));
    memset(&info, 0xFF, sizeof(info));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_GetInfo(pks, loadable, &info));
    WH_TEST_ASSERT_RETURN((info.keyBits == 0) && (info.flags == 0) &&
                          (info.owner == 0));

    /* A fixed key describes from its record */
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_GetInfo(pks, fixedKey, &info));
    WH_TEST_ASSERT_RETURN((info.keyBits == 128) &&
                          (info.flags == WH_NVM_FLAGS_USAGE_ENCRYPT) &&
                          (info.owner == WH_KEYUSER_GLOBAL));

    /* A key the port didn't register can't be described or loaded, a fixed
     * key can't be loaded, and ID 0 names no key */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_PortKey_GetInfo(pks, unregistered, &info));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_PortKey_Load(pks, devId, unregistered, WH_KEYID_ERASED,
                        WH_NVM_FLAGS_USAGE_ENCRYPT, key, sizeof(key)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_PortKey_Load(pks, devId, fixedKey, WH_KEYID_ERASED,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          sizeof(key)));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_BADARGS ==
        wh_PortKey_Load(
            pks, devId, WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, 0),
            WH_KEYID_ERASED, WH_NVM_FLAGS_USAGE_ENCRYPT, key, sizeof(key)));

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

/* devId of the port in _whTest_PortKeyNotReady ("PKNR") */
#define WH_TEST_PORT_DEVID 0x504B4E52

/* Errors for the port's keystore requests to return */
typedef struct {
    int importRet;
    int deleteRet;
} PortKeyKeystore;

/* A port that answers only keystore requests */
static int _PortKeyKeystoreCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    PortKeyKeystore* ks = (PortKeyKeystore*)ctx;

    (void)devId;
    if (info->algo_type == WC_ALGO_TYPE_KEYSTORE) {
        if (info->keystore.type == WC_KEYSTORE_IMPORT_PLAIN) {
            return ks->importRet;
        }
        if (info->keystore.type == WC_KEYSTORE_DELETE) {
            return ks->deleteRet;
        }
    }
    return CRYPTOCB_UNAVAILABLE;
}

/* A port's NOTREADY from a load or clear comes back as ABORTED, since a
 * blocking client would wait for a response forever */
static int _whTest_PortKeyNotReady(void)
{
    PortKeyKeystore  ks      = {0};
    whPortKeyContext pks[1]  = {{0}};
    whPortKeyConfig  conf[1] = {{0}};
    whKeyId          loadable =
        WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_TEST_PORT_USER, WH_TEST_PORTKEK_ID);
    whKeyId src     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_PORT_USER, 1);
    uint8_t key[16] = {0};
    int     devId   = WH_TEST_PORT_DEVID;

    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterLoadable(pks, loadable));
    WH_TEST_RETURN_ON_FAIL(
        wc_CryptoCb_RegisterDevice(devId, _PortKeyKeystoreCb, &ks));

    /* Loading */
    ks.importRet = WH_ERROR_NOTREADY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_PortKey_Load(pks, devId, loadable, src,
                                          WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                          sizeof(key)));
    ks.importRet = 0;

    /* Each clear function, on a freshly loaded key */
    ks.deleteRet = WH_ERROR_NOTREADY;
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Load(pks, devId, loadable, src,
                                           WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                           sizeof(key)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_PortKey_Clear(pks, devId, loadable));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Load(pks, devId, loadable, src,
                                           WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                           sizeof(key)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_PortKey_ClearAll(pks, devId, WH_TEST_PORT_USER));
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Load(pks, devId, loadable, src,
                                           WH_NVM_FLAGS_USAGE_ENCRYPT, key,
                                           sizeof(key)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          wh_PortKey_ClearSource(pks, devId, src));

    wc_CryptoCb_UnRegisterDevice(devId);
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
                          wh_PortKey_RegisterFixed(
                              pks, keyId, WH_NVM_FLAGS_USAGE_WRAP,
                              WH_TEST_PORTKEK_SIZE, WH_PORTKEY_ACCESS_BY_REF));

    /* Init-success path: the backend Init is dispatched exactly once and the
     * context becomes usable */
    lc.initRet   = WH_ERROR_OK;
    lc.initCalls = 0;
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_Init(pks, conf));
    WH_TEST_ASSERT_RETURN(lc.initCalls == 1);
    WH_TEST_RETURN_ON_FAIL(wh_PortKey_RegisterFixed(
        pks, keyId, WH_NVM_FLAGS_USAGE_WRAP, WH_TEST_PORTKEK_SIZE,
        WH_PORTKEY_ACCESS_BY_REF));

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
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyByValue());
#ifdef WOLFHSM_CFG_PORTKEY_LOAD
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyLoadable());
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyNotReady());
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_PortKeyLifecycle());
    WH_TEST_RETURN_ON_FAIL(_whTest_KeystorePortKeyReject(ctx));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && WOLFHSM_CFG_PORTKEY */
