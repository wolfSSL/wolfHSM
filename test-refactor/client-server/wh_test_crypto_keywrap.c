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
 * test-refactor/client-server/wh_test_crypto_keywrap.c
 *
 * Single-client key wrap tests over AES-GCM:
 *   _whTest_CryptoKeyWrapSameOwner    - wrap a local key, then unwrap and
 *                                       export it as the owner and confirm the
 *                                       recovered key matches the original
 *   _whTest_CryptoKeyWrapNoNvmPersist - an unwrapped key is cache-only, so
 *                                       commit and erase must reject a wrapped
 *                                       key id while eviction still succeeds
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_KEYWRAP) && \
    !defined(NO_AES) && defined(HAVE_AESGCM)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define KEYWRAP_TEST_AESGCM_IV_SIZE 12
#define KEYWRAP_TEST_AESGCM_TAG_SIZE 16
#define KEYWRAP_TEST_WRAPPED_KEY_SIZE                            \
    (KEYWRAP_TEST_AESGCM_IV_SIZE + KEYWRAP_TEST_AESGCM_TAG_SIZE + \
     AES_256_KEY_SIZE + sizeof(whNvmMetadata))

#define KEYWRAP_TEST_WRAPKEY_ID 1
#define KEYWRAP_TEST_PLAINKEY_ID 2

/*
 * Wrap a local key, then unwrap and export it as the owning client.
 * The recovered key must match the original plaintext.
 */
static int _whTest_CryptoKeyWrapSameOwner(whClientContext* client)
{
    whKeyId  wrapKeyId = KEYWRAP_TEST_WRAPKEY_ID;
    uint8_t  wrapKey[AES_256_KEY_SIZE]  = "LocalWrapKey2Test9aXXXXXXXXXX!";
    uint8_t  plainKey[AES_256_KEY_SIZE] = "LocalPlainKey2Test9aXXXXXXXXX!";
    uint8_t  wrappedKey[KEYWRAP_TEST_WRAPPED_KEY_SIZE] = {0};
    uint16_t wrappedKeySz                = sizeof(wrappedKey);
    uint8_t  unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t unwrappedKeySz              = sizeof(unwrappedKey);
    whNvmMetadata meta                   = {0};
    whNvmMetadata exportMeta             = {0};

    WH_TEST_DEBUG_PRINT("Test: local wrap key, local key, same owner\n");

    /* Cache a local wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(
        client, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKeySameOwner",
        sizeof("WrapKeySameOwner"), wrapKey, sizeof(wrapKey), &wrapKeyId));

    /* Wrap a local key owned by this client */
    meta.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                 KEYWRAP_TEST_PLAINKEY_ID);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM,
                                             wrapKeyId, plainKey,
                                             sizeof(plainKey), &meta,
                                             wrappedKey, &wrappedKeySz));

    /* Owner unwraps and exports the local key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExport(
        client, WC_CIPHER_AES_GCM, wrapKeyId, wrappedKey, sizeof(wrappedKey),
        &exportMeta, unwrappedKey, &unwrappedKeySz));

    /* Recovered key matches the original */
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(unwrappedKey, plainKey, sizeof(plainKey)));

    /* Evict the wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, wrapKeyId));

    WH_TEST_PRINT("  PASS: local wrap key, local key, same owner\n");

    return WH_ERROR_OK;
}

/*
 * An unwrapped key is cache-only; the unwrapped key must never reach NVM.
 * This prevents an unwrapped key from shadowing a protected NVM entry, so
 * commit and erase must reject a wrapped key id while eviction succeeds.
 */
static int _whTest_CryptoKeyWrapNoNvmPersist(whClientContext* client)
{
    int      ret;
    whKeyId  wrapKeyId   = KEYWRAP_TEST_WRAPKEY_ID;
    whKeyId  cachedKeyId = 0;
    uint8_t  wrapKey[AES_256_KEY_SIZE]  = "NoNvmWrapKeyTest123456789aXX!";
    uint8_t  plainKey[AES_256_KEY_SIZE] = "NoNvmPlainKeyTest12345678aXX!";
    uint8_t  wrappedKey[KEYWRAP_TEST_WRAPPED_KEY_SIZE] = {0};
    uint16_t wrappedKeySz               = sizeof(wrappedKey);
    whNvmMetadata meta                  = {0};

    WH_TEST_DEBUG_PRINT("Test: unwrapped key cannot persist to NVM\n");

    /* Cache a local wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(
        client, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKeyNoNvm",
        sizeof("WrapKeyNoNvm"), wrapKey, sizeof(wrapKey), &wrapKeyId));

    /* Wrap a local key */
    meta.id  = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                 KEYWRAP_TEST_PLAINKEY_ID);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM,
                                             wrapKeyId, plainKey,
                                             sizeof(plainKey), &meta,
                                             wrappedKey, &wrappedKeySz));

    /* Unwrap and cache the key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCache(
        client, WC_CIPHER_AES_GCM, wrapKeyId, wrappedKey, sizeof(wrappedKey),
        &cachedKeyId));

    /* Commit must refuse to persist a wrapped key to NVM */
    ret = wh_Client_KeyCommit(client,
                              WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    /* Erase must likewise refuse a wrapped key */
    ret = wh_Client_KeyErase(client, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId));
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    /* Cache-only eviction must still succeed */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(
        client, WH_CLIENT_KEYID_MAKE_WRAPPED(cachedKeyId)));

    /* Evict the wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, wrapKeyId));

    WH_TEST_PRINT("  PASS: unwrapped key cannot persist to NVM\n");

    return WH_ERROR_OK;
}

int whTest_Crypto_KeyWrap(whClientContext* ctx)
{
    /* A preceding suite may leave the DMA-preferred dispatch mode set; reset
     * to the std path so this suite runs the same way in every config. */
    (void)wh_Client_SetDmaMode(ctx, 0);
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoKeyWrapSameOwner(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoKeyWrapNoNvmPersist(ctx));
    return WH_ERROR_OK;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_KEYWRAP && \
          !NO_AES && HAVE_AESGCM */
