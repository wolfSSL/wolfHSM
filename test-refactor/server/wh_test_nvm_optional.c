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
 * test-refactor/server/wh_test_nvm_optional.c
 *
 * Server-side test that the keystore treats NVM as optional. The shared
 * server context arrives fully initialized (with a real NVM); this test
 * temporarily detaches the NVM (server->nvm = NULL) to exercise the no-NVM
 * paths, then restores it. Mirrors test/wh_test_nvm_optional.c.
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_counter.h"
#include "wolfhsm/wh_server_counter.h"
#include "wolfhsm/wh_message_nvm.h"
#include "wolfhsm/wh_server_nvm.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#endif

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#define WH_TEST_NVMOPT_AES_BLOCK (16)
#define WH_TEST_NVMOPT_KEYLEN (32)

/* Use a key (as retrieved from the cache) for an AES-CBC round trip, proving a
 * primed key is usable for crypto without any NVM. */
static int _AesCbcRoundTrip(const uint8_t* key, uint32_t keyLen)
{
    Aes     aes[1];
    uint8_t iv[WH_TEST_NVMOPT_AES_BLOCK];
    uint8_t pt[WH_TEST_NVMOPT_AES_BLOCK * 2];
    uint8_t ct[sizeof(pt)];
    uint8_t dec[sizeof(pt)];
    int     ret;

    if ((keyLen != 16) && (keyLen != 24) && (keyLen != 32)) {
        WH_ERROR_PRINT("unexpected cached key length: %u\n", (unsigned)keyLen);
        return WH_TEST_FAIL;
    }

    memset(iv, 0x24, sizeof(iv));
    memset(pt, 0xA5, sizeof(pt));

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keyLen, iv, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, ct, pt, sizeof(pt));
        }
        wc_AesFree(aes);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("AES-CBC encrypt failed: %d\n", ret);
        return ret;
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, keyLen, iv, AES_DECRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(aes, dec, ct, sizeof(ct));
        }
        wc_AesFree(aes);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("AES-CBC decrypt failed: %d\n", ret);
        return ret;
    }

    if (memcmp(pt, dec, sizeof(pt)) != 0) {
        WH_ERROR_PRINT("NVM-optional AES-CBC round-trip mismatch\n");
        return WH_TEST_FAIL;
    }
    return 0;
}

#ifdef WOLFHSM_CFG_SHE_EXTENSION
static int _SheKeystoreChecks(whServerContext* server)
{
    whNvmMetadata meta[1];
    whNvmMetadata outMeta[1];
    uint8_t       sheKey[WH_SHE_KEY_SZ];
    uint8_t       outKey[WH_SHE_KEY_SZ];
    uint32_t      outSz;
    whKeyId       sheId;
    int           i;
    int           allZero;

    /* Init key to arbitrary value */
    for (i = 0; i < (int)sizeof(sheKey); i++) {
        sheKey[i] = (uint8_t)(0xF0 ^ i);
    }

    sheId = WH_MAKE_KEYID(WH_KEYTYPE_SHE, WH_TEST_DEFAULT_CLIENT_ID, 0x05);
    memset(meta, 0, sizeof(meta));
    meta->id     = sheId;
    meta->len    = (whNvmSize)WH_SHE_KEY_SZ;
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreCacheKey(server, meta, sheKey));

    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_KeystoreReadKey(server, sheId, outMeta, outKey, &outSz));
    WH_TEST_ASSERT_RETURN(outSz == (uint32_t)WH_SHE_KEY_SZ);
    WH_TEST_ASSERT_RETURN(0 == memcmp(outKey, sheKey, WH_SHE_KEY_SZ));

    /* SHE master-ecu key falls back to an all-zero key when not present. */
    memset(outKey, 0xFF, sizeof(outKey));
    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_KeystoreReadKey(server,
                                  WH_MAKE_KEYID(WH_KEYTYPE_SHE,
                                                WH_TEST_DEFAULT_CLIENT_ID,
                                                WH_SHE_MASTER_ECU_KEY_ID),
                                  outMeta, outKey, &outSz));
    WH_TEST_ASSERT_RETURN(outSz == (uint32_t)WH_SHE_KEY_SZ);
    allZero = 1;
    for (i = 0; i < (int)WH_SHE_KEY_SZ; i++) {
        if (outKey[i] != 0) {
            allZero = 0;
        }
    }
    WH_TEST_ASSERT_RETURN(allZero == 1);

    (void)wh_Server_KeystoreEvictKey(server, sheId);
    return 0;
}
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

/* Runs with server->nvm already detached (NULL) by the caller. */
static int _RunNvmOptionalChecks(whServerContext* server)
{
    whNvmMetadata  meta[1];
    whNvmMetadata  outMeta[1];
    uint8_t        keyData[WH_TEST_NVMOPT_KEYLEN];
    uint8_t        outKey[WH_TEST_NVMOPT_KEYLEN];
    uint32_t       outSz;
    uint8_t*       cacheBuf  = NULL;
    whNvmMetadata* cacheMeta = NULL;
    whKeyId        localId;
    whKeyId        globalId;
    whKeyId        missingId;
    whKeyId        eraseCheckedId;
    whKeyId        revokeId;
    int            i;

    for (i = 0; i < (int)sizeof(keyData); i++) {
        keyData[i] = (uint8_t)i;
    }

    localId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID, 0x10);
    globalId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_KEYUSER_GLOBAL, 0x11);
    missingId =
        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID, 0x77);
    eraseCheckedId =
        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID, 0x20);
    revokeId =
        WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID, 0x21);

    /* A cache miss with no NVM reports NOTFOUND (not BADARGS). */
    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_Server_KeystoreReadKey(server, missingId, outMeta, outKey, &outSz));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_Server_KeystoreFreshenKey(server, missingId, &cacheBuf, &cacheMeta));

#ifdef WOLFHSM_CFG_THREADSAFE
    /* The NVM lock is a successful no-op when there is no NVM to serialize. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_Server_NvmLock(server));
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_Server_NvmUnlock(server));
#endif

    /* Prime a local key and read it back. */
    memset(meta, 0, sizeof(meta));
    meta->id     = localId;
    meta->len    = (whNvmSize)sizeof(keyData);
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreCacheKey(server, meta, keyData));

    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_KeystoreReadKey(server, localId, outMeta, outKey, &outSz));
    WH_TEST_ASSERT_RETURN(outSz == (uint32_t)sizeof(keyData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outKey, keyData, sizeof(keyData)));

    /* Prime a GLOBAL key (USER==0): regression for the _GetCacheContext crash
     * (dereferenced server->nvm->globalCache when nvm==NULL). */
    memset(meta, 0, sizeof(meta));
    meta->id     = globalId;
    meta->len    = (whNvmSize)sizeof(keyData);
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreCacheKey(server, meta, keyData));
    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_KeystoreReadKey(server, globalId, outMeta, outKey, &outSz));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outKey, keyData, sizeof(keyData)));

    /* The primed key is retrievable via the crypto path (FreshenKey) and
     * usable for an AES-CBC round trip -- crypto works with no NVM. */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_KeystoreFreshenKey(server, localId, &cacheBuf, &cacheMeta));
    WH_TEST_ASSERT_RETURN(cacheBuf != NULL);
    WH_TEST_ASSERT_RETURN(cacheMeta != NULL);
    WH_TEST_RETURN_ON_FAIL(_AesCbcRoundTrip(cacheBuf, cacheMeta->len));

    /* Commit requires NVM to persist; with none it fails gracefully. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK !=
                          wh_Server_KeystoreCommitKey(server, localId));

    /* Erase is cache-only without NVM and succeeds; the key is then gone. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreEraseKey(server, localId));
    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_Server_KeystoreReadKey(server, localId, outMeta, outKey, &outSz));

    /* EraseKeyChecked enforces policy but, like the non-checked EraseKey
     * above, treats "nothing to erase" as OK. This holds whether or not NVM
     * is attached. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreEraseKeyChecked(server, missingId));

    /* On a primed, policy-permissive key, EraseKeyChecked succeeds cache-only
     * and the key is then gone. */
    memset(meta, 0, sizeof(meta));
    meta->id     = eraseCheckedId;
    meta->len    = (whNvmSize)sizeof(keyData);
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreCacheKey(server, meta, keyData));
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK == wh_Server_KeystoreEraseKeyChecked(
                                             server, eraseCheckedId));
    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          wh_Server_KeystoreReadKey(server, eraseCheckedId,
                                                    outMeta, outKey, &outSz));

    /* RevokeKey with no NVM revokes the cached copy (the NVM probe/commit is
     * skipped). The key becomes NONMODIFIABLE, so a subsequent policy-checked
     * erase is denied with ACCESS -- proving the revoke took effect and that
     * EraseKeyChecked surfaces policy errors with no NVM. */
    memset(meta, 0, sizeof(meta));
    meta->id     = revokeId;
    meta->len    = (whNvmSize)sizeof(keyData);
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreCacheKey(server, meta, keyData));
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreRevokeKey(server, revokeId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEraseKeyChecked(server, revokeId));
    /* Force-remove the revoked key (EraseKeyChecked could not). */
    (void)wh_Server_KeystoreEvictKey(server, revokeId);

    /* Drop the global key we cached so the shared context is clean. */
    (void)wh_Server_KeystoreEraseKey(server, globalId);

#ifdef WOLFHSM_CFG_SHE_EXTENSION
    WH_TEST_RETURN_ON_FAIL(_SheKeystoreChecks(server));
#endif

    return 0;
}

int whTest_NvmOptional(whServerContext* ctx)
{
    whServerContext* server = (whServerContext*)ctx;
    whNvmContext*    savedNvm;
    int              ret;

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Detach NVM to exercise the optional-NVM paths, then always restore so
     * later tests in the shared context still see their NVM backing. */
    savedNvm    = server->nvm;
    server->nvm = NULL;

    ret = _RunNvmOptionalChecks(server);

    server->nvm = savedNvm;
    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO */
