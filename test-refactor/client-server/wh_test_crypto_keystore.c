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
 * test-refactor/client-server/wh_test_crypto_keystore.c
 *
 * Key cache lifecycle and non-exportable-flag enforcement:
 *   _whTest_KeyCache              - cache/export round-trip, evict,
 *                                   commit/erase, cross-cache eviction and
 *                                   replacement, and eviction with the cache
 *                                   full of NVM-backed keys (plus DMA variants
 *                                   when WOLFHSM_CFG_DMA)
 *   _whTest_NonExportableKeystore - confirm WH_NVM_FLAGS_NONEXPORTABLE keys
 *                                   cannot be exported while ordinary keys can
 *                                   (std and DMA export paths)
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define WH_TEST_KEYCACHE_KEYSIZE (16)
#define WH_TEST_KEYSTORE_TEST_SZ (32)

/* Cache a key, export it back, and verify the label and key round-trip. */
static int _whTest_CacheExportKey(whClientContext* ctx, whKeyId* inout_key_id,
                                  uint8_t* label_in, uint8_t* label_out,
                                  uint16_t label_len, uint8_t* key_in,
                                  uint8_t* key_out, uint16_t key_len)
{
    int      ret           = 0;
    uint16_t label_len_out = label_len;
    uint16_t key_len_out   = key_len;
    whKeyId  key_id_out    = *inout_key_id;

    ret = wh_Client_KeyCache(ctx, 0, label_in, label_len, key_in, key_len,
                             &key_id_out);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
    }
    else {
        ret = wh_Client_KeyExport(ctx, key_id_out, label_out, label_len_out,
                                  key_out, &key_len_out);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        }
        else {
            if ((key_len_out != key_len) ||
                (memcmp(key_in, key_out, key_len_out) != 0) ||
                (memcmp(label_in, label_out, label_len) != 0)) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
/* DMA variant of the cache/export round-trip helper. */
static int _whTest_CacheExportKeyDma(whClientContext* ctx,
                                     whKeyId* inout_key_id, uint8_t* label_in,
                                     uint8_t* label_out, uint16_t label_len,
                                     uint8_t* key_in, uint8_t* key_out,
                                     uint16_t key_len)
{
    int      ret           = 0;
    uint16_t label_len_out = label_len;
    uint16_t key_len_out   = key_len;
    whKeyId  key_id_out    = *inout_key_id;

    ret = wh_Client_KeyCacheDma(ctx, 0, label_in, label_len, key_in, key_len,
                                &key_id_out);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheDma %d\n", ret);
    }
    else {
        ret = wh_Client_KeyExportDma(ctx, key_id_out, key_out, key_len_out,
                                     label_out, label_len_out, &key_len_out);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExportDma %d\n", ret);
        }
        else {
            if ((key_len_out != key_len) ||
                (memcmp(key_in, key_out, key_len_out) != 0) ||
                (memcmp(label_in, label_out, label_len) != 0)) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

static int _whTest_KeyCache(whClientContext* ctx)
{
    int      devId = WH_CLIENT_DEVID(ctx);
    int      ret;
    int      i;
    uint16_t outLen;
    uint16_t keyId;
    WC_RNG   rng[1];
    uint8_t  key[WH_TEST_KEYCACHE_KEYSIZE];
    uint8_t  keyOut[WH_TEST_KEYCACHE_KEYSIZE]  = {0};
    uint8_t  labelIn[WH_NVM_LABEL_LEN]         = "KeyCache Test Label";
    uint8_t  labelOut[WH_NVM_LABEL_LEN]        = {0};

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    /* Randomize inputs */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
    }

    /* test regular cache/export */
    keyId = WH_KEYID_ERASED;
    if (ret == 0) {
        ret = _whTest_CacheExportKey(ctx, &keyId, labelIn, labelOut,
                                     sizeof(labelIn), key, keyOut, sizeof(key));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to Test CacheExportKey %d\n", ret);
        }
        else {
            WH_TEST_PRINT("KEY CACHE/EXPORT SUCCESS\n");
        }
    }

    if (ret == 0) {
        /* test evict for original client */
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        }
        else {
            outLen = sizeof(keyOut);
            ret = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                                      keyOut, &outLen);
            if (ret != WH_ERROR_NOTFOUND) {
                WH_ERROR_PRINT("Failed to not find evicted key %d\n", ret);
            }
            else {
                WH_TEST_PRINT("KEY CACHE EVICT SUCCESS\n");
                ret = 0;
            }
        }
    }

    if (ret == 0) {
        /* test commit/erase */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                 sizeof(key), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        }
        else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            }
            else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                }
                else {
                    outLen = sizeof(keyOut);
                    ret = wh_Client_KeyExport(ctx, keyId, labelOut,
                                              sizeof(labelOut), keyOut, &outLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n",
                                       ret);
                    }
                    else {
                        if ((outLen != sizeof(key) ||
                             (memcmp(key, keyOut, outLen) != 0) ||
                             (memcmp(labelIn, labelOut, sizeof(labelIn))) !=
                                 0)) {
                            WH_ERROR_PRINT("Failed to match committed key\n");
                            ret = -1;
                        }
                        else {
                            /* verify commit isn't using new nvm objects */
                            for (i = 0; i < WOLFHSM_CFG_NVM_OBJECT_COUNT; i++) {
                                ret = wh_Client_KeyCommit(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to over commit %d\n",
                                                   ret);
                                }
                            }
                            if (ret == 0) {
                                ret = wh_Client_KeyErase(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to erase key %d\n",
                                                   ret);
                                }
                                else {
                                    outLen = sizeof(keyOut);
                                    ret = wh_Client_KeyExport(ctx, keyId,
                                            labelOut, sizeof(labelOut), keyOut,
                                            &outLen);
                                    if (ret != WH_ERROR_NOTFOUND) {
                                        WH_ERROR_PRINT("Failed to not find "
                                                        "erased key\n");
                                        ret = -1;
                                    }
                                    else {
                                        ret = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (ret == 0) {
            WH_TEST_PRINT("KEY COMMIT/ERASE SUCCESS\n");
        }
    }

    /* Test cross-cache key eviction and replacement */
    if (ret == 0) {
        uint16_t crossKeyId;
        /* Key for regular cache (<= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const uint16_t smallKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2;
        uint8_t        smallKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2];
        /* Key for big cache (> WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const uint16_t bigKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100;
        uint8_t        bigKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100];

        uint8_t labelSmall[WH_NVM_LABEL_LEN] = "Small Key Label";
        uint8_t labelBig[WH_NVM_LABEL_LEN]   = "Big Key Label";

        /* Buffer for exported key and metadata */
        uint8_t  exportedKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100];
        uint8_t  exportedLabel[WH_NVM_LABEL_LEN];
        uint16_t exportedKeySize;

        /* Initialize test keys with different data */
        memset(smallKey, 0xAA, sizeof(smallKey));
        memset(bigKey, 0xBB, sizeof(bigKey));

        /* Test 1: Cache small key first, then cache same keyId with big key */
        crossKeyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelSmall, sizeof(labelSmall),
                                 smallKey, sizeof(smallKey), &crossKeyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache small key: %d\n", ret);
        }
        else {
            /* Now cache big key with same keyId - should succeed and evict the
             * small key */
            ret = wh_Client_KeyCache(ctx, 0, labelBig, sizeof(labelBig), bigKey,
                                     sizeof(bigKey), &crossKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to cache big key (expected success): %d\n", ret);
            }
            else {
                /* Verify the cached key is the big key by exporting it */
                exportedKeySize = sizeof(exportedKey);
                ret = wh_Client_KeyExport(ctx, crossKeyId, exportedLabel,
                                          sizeof(exportedLabel), exportedKey,
                                          &exportedKeySize);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to export key after cache: %d\n",
                                   ret);
                }
                else {
                    /* Verify exported key matches the big key */
                    if (exportedKeySize != bigKeySize ||
                        memcmp(exportedKey, bigKey, bigKeySize) != 0) {
                        WH_ERROR_PRINT(
                            "Exported key data doesn't match big key\n");
                        ret = -1;
                    }
                    /* Verify exported label matches the big key label */
                    else if (memcmp(exportedLabel, labelBig,
                                    sizeof(labelBig)) != 0) {
                        WH_ERROR_PRINT(
                            "Exported label doesn't match big key label\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                    }
                }
                /* Clean up */
                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, crossKeyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                    }
                }
                else {
                    /* On error, try our best to clean up */
                    (void)wh_Client_KeyEvict(ctx, crossKeyId);
                }

                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, crossKeyId);
                    if (ret != 0) {
                        /* double evict should fail */
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT("Double evict shouldn't succeed, "
                                       "cross-cache duplication test failed\n");
                        ret = -1;
                    }
                }
            }
        }

        /* Test 2: Cache big key first, then cache same keyId with small key */
        if (ret == 0) {
            crossKeyId = WH_KEYID_ERASED;
            ret = wh_Client_KeyCache(ctx, 0, labelBig, sizeof(labelBig), bigKey,
                                     sizeof(bigKey), &crossKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache big key: %d\n", ret);
            }
            else {
                /* Now cache small key with same keyId - should succeed and
                 * evict the big key */
                ret = wh_Client_KeyCache(ctx, 0, labelSmall, sizeof(labelSmall),
                                         smallKey, sizeof(smallKey),
                                         &crossKeyId);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed to cache small key (expected success): %d\n",
                        ret);
                }
                else {
                    /* Verify the cached key is the small key by exporting it */
                    exportedKeySize = sizeof(exportedKey);
                    ret = wh_Client_KeyExport(ctx, crossKeyId, exportedLabel,
                                              sizeof(exportedLabel),
                                              exportedKey, &exportedKeySize);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to export key after cache: %d\n", ret);
                    }
                    else {
                        /* Verify exported key matches the small key */
                        if (exportedKeySize != smallKeySize ||
                            memcmp(exportedKey, smallKey, smallKeySize) != 0) {
                            WH_ERROR_PRINT(
                                "Exported key data doesn't match small key\n");
                            ret = -1;
                        }
                        /* Verify exported label matches the small key label */
                        else if (memcmp(exportedLabel, labelSmall,
                                        sizeof(labelSmall)) != 0) {
                            WH_ERROR_PRINT("Exported label doesn't match small "
                                           "key label\n");
                            ret = -1;
                        }
                        else {
                            ret = 0;
                        }
                    }
                    /* Clean up */
                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, crossKeyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                        }
                    }
                    else {
                        /* On error, try our best to clean up */
                        (void)wh_Client_KeyEvict(ctx, crossKeyId);
                    }

                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, crossKeyId);
                        if (ret != 0) {
                            /* double evict should fail */
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "Double evict shouldn't succeed, "
                                "cross-cache duplication test failed\n");
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (ret == 0) {
            WH_TEST_PRINT("KEY CROSS-CACHE EVICTION AND REPLACEMENT SUCCESS\n");
        }
    }

#ifdef WOLFHSM_CFG_DMA
    /* test cache/export using DMA */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret = _whTest_CacheExportKeyDma(ctx, &keyId, labelIn, labelOut,
                                        sizeof(labelIn), key, keyOut,
                                        sizeof(key));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to Test CacheExportKeyDma %d\n", ret);
        }
        else {
            ret = wh_Client_KeyEvict(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
            }
            else {
                WH_TEST_PRINT("KEY CACHE/EXPORT DMA SUCCESS\n");
            }
        }
    }

    /* Test cross-cache key eviction and replacement with DMA */
    if (ret == 0) {
        uint16_t crossKeyId;
        /* Key for regular cache (<= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const uint16_t smallKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2;
        uint8_t        smallKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2];
        /* Key for big cache (> WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const uint16_t bigKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100;
        uint8_t        bigKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100];

        uint8_t labelSmall[WH_NVM_LABEL_LEN] = "Small DMA Key Label";
        uint8_t labelBig[WH_NVM_LABEL_LEN]   = "Big DMA Key Label";

        /* Buffer for exported key and metadata */
        uint8_t  exportedKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100];
        uint8_t  exportedLabel[WH_NVM_LABEL_LEN];
        uint16_t exportedKeySize;

        /* Initialize test keys with different data */
        memset(smallKey, 0xCC, sizeof(smallKey));
        memset(bigKey, 0xDD, sizeof(bigKey));

        /* Test 1: Cache small key with DMA first, then cache same keyId
         * with big key using DMA */
        crossKeyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCacheDma(ctx, 0, labelSmall, sizeof(labelSmall),
                                    smallKey, sizeof(smallKey), &crossKeyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache small key with DMA: %d\n", ret);
        }
        else {
            /* Now cache big key with same keyId using DMA - should succeed and
             * evict the small key */
            ret = wh_Client_KeyCacheDma(ctx, 0, labelBig, sizeof(labelBig),
                                        bigKey, sizeof(bigKey), &crossKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to cache big key with DMA (expected success): %d\n",
                    ret);
            }
            else {
                /* Verify the cached key is the big key by exporting it */
                exportedKeySize = bigKeySize;
                ret             = wh_Client_KeyExportDma(
                    ctx, crossKeyId, exportedKey, exportedKeySize, exportedLabel,
                    sizeof(exportedLabel), &exportedKeySize);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to export key after cache: %d\n",
                                   ret);
                }
                else {
                    /* Verify exported key matches the big key */
                    if (exportedKeySize != bigKeySize ||
                        memcmp(exportedKey, bigKey, bigKeySize) != 0) {
                        WH_ERROR_PRINT(
                            "Exported key data doesn't match big key\n");
                        ret = -1;
                    }
                    /* Verify exported label matches the big key label */
                    else if (memcmp(exportedLabel, labelBig,
                                    sizeof(labelBig)) != 0) {
                        WH_ERROR_PRINT(
                            "Exported label doesn't match big key label\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                    }
                }
                /* Clean up */
                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, crossKeyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                    }
                }
                else {
                    /* On error, try our best to clean up */
                    (void)wh_Client_KeyEvict(ctx, crossKeyId);
                }

                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, crossKeyId);
                    if (ret != 0) {
                        /* double evict should fail */
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT("Double evict shouldn't succeed, "
                                       "cross-cache duplication test failed\n");
                        ret = -1;
                    }
                }
            }
        }

        /* Test 2: Cache big key with DMA first, then cache
         * same keyId with small key using DMA */
        if (ret == 0) {
            crossKeyId = WH_KEYID_ERASED;
            ret = wh_Client_KeyCacheDma(ctx, 0, labelBig, sizeof(labelBig),
                                        bigKey, sizeof(bigKey), &crossKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache big key with DMA: %d\n", ret);
            }
            else {
                /* Now cache small key with same keyId using DMA - should
                 * succeed and evict the big key */
                ret = wh_Client_KeyCacheDma(ctx, 0, labelSmall,
                                            sizeof(labelSmall), smallKey,
                                            sizeof(smallKey), &crossKeyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to cache small key with DMA "
                                   "(expected success): %d\n",
                                   ret);
                }
                else {
                    /* Verify the cached key is the small key by exporting it */
                    exportedKeySize = smallKeySize;
                    ret             = wh_Client_KeyExportDma(
                        ctx, crossKeyId, exportedKey, exportedKeySize,
                        exportedLabel, sizeof(exportedLabel), &exportedKeySize);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to export key after cache: %d\n", ret);
                    }
                    else {
                        /* Verify exported key matches the small key */
                        if (exportedKeySize != smallKeySize ||
                            memcmp(exportedKey, smallKey, smallKeySize) != 0) {
                            WH_ERROR_PRINT(
                                "Exported key data doesn't match small key\n");
                            ret = -1;
                        }
                        /* Verify exported label matches the small key label */
                        else if (memcmp(exportedLabel, labelSmall,
                                        sizeof(labelSmall)) != 0) {
                            WH_ERROR_PRINT("Exported label doesn't match small "
                                           "key label\n");
                            ret = -1;
                        }
                        else {
                            ret = 0;
                        }
                    }
                    /* Clean up */
                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, crossKeyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                        }
                    }
                    else {
                        /* On error, try our best to clean up */
                        (void)wh_Client_KeyEvict(ctx, crossKeyId);
                    }

                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, crossKeyId);
                        if (ret != 0) {
                            /* double evict should fail */
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "Double evict shouldn't succeed, "
                                "cross-cache duplication test failed\n");
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (ret == 0) {
            WH_TEST_PRINT(
                "KEY CROSS-CACHE EVICTION AND REPLACEMENT DMA SUCCESS\n");
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    /* Ensure cache entries read from NVM are evictable.
     * Max out the cache with NVM-backed keys, then try caching a new key. */
    if (ret == 0) {
        const int nvmKeyCount = WOLFHSM_CFG_SERVER_KEYCACHE_COUNT;
        /* {0} == WH_KEYID_ERASED, so unused entries are skipped on cleanup
         * and each cache call requests a server-assigned id. */
        uint16_t  nvmKeyIds[WOLFHSM_CFG_SERVER_KEYCACHE_COUNT] = {0};
        uint16_t  extraKeyId = WH_KEYID_ERASED;

        /* Commit each key to NVM then evict it, so the keys live only in
         * the backing store and not in the cache. */
        for (i = 0; (i < nvmKeyCount) && (ret == 0); i++) {
            ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                     sizeof(key), &nvmKeyIds[i]);
            if (ret == 0) {
                ret = wh_Client_KeyCommit(ctx, nvmKeyIds[i]);
            }
            if (ret == 0) {
                ret = wh_Client_KeyEvict(ctx, nvmKeyIds[i]);
            }
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to stage NVM key %d: %d\n", i, ret);
            }
        }

        /* Read each key back, which caches it from NVM and fills the
         * cache with NVM-backed entries. */
        for (i = 0; (i < nvmKeyCount) && (ret == 0); i++) {
            outLen = sizeof(keyOut);
            ret = wh_Client_KeyExport(ctx, nvmKeyIds[i], labelOut,
                                      sizeof(labelOut), keyOut, &outLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to read back NVM key %d: %d\n", i, ret);
            }
        }

        /* With the cache full of NVM-backed keys, caching a new key must
         * still succeed by evicting one of them. */
        if (ret == 0) {
            ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                     sizeof(key), &extraKeyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache key with NVM-backed cache "
                               "full: %d\n", ret);
            }
        }

        /* Restore state regardless of the outcome above. */
        if (extraKeyId != WH_KEYID_ERASED) {
            (void)wh_Client_KeyEvict(ctx, extraKeyId);
        }
        for (i = 0; i < nvmKeyCount; i++) {
            if (nvmKeyIds[i] != WH_KEYID_ERASED) {
                (void)wh_Client_KeyErase(ctx, nvmKeyIds[i]);
            }
        }

        if (ret == 0) {
            WH_TEST_PRINT("KEY CACHE NVM-BACKED EVICTION SUCCESS\n");
        }
    }

    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_NonExportableKeystore(whClientContext* ctx)
{
    int     ret   = 0;
    whKeyId keyId = WH_KEYID_ERASED;
    uint8_t key[WH_TEST_KEYSTORE_TEST_SZ] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    uint8_t  exportedKey[WH_TEST_KEYSTORE_TEST_SZ] = {0};
    uint8_t  label[WH_NVM_LABEL_LEN]               = "NonExportableTestKey";
    uint8_t  exportedLabel[WH_NVM_LABEL_LEN]       = {0};
    uint16_t exportedKeySize;

    WH_TEST_PRINT("Testing non-exportable keystore enforcement...\n");

    /* Test 1: Cache a key with non-exportable flag and try to export it */
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONEXPORTABLE, label,
                             sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache non-exportable key: %d\n", ret);
        return ret;
    }

    /* Try to export the non-exportable key - should fail */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel, sizeof(exportedLabel),
                              exportedKey, &exportedKeySize);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("Non-exportable key was exported unexpectedly: %d\n",
                       ret);
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Non-exportable key export correctly denied\n");

    /* Clean up the key */
    wh_Client_KeyEvict(ctx, keyId);

    /* Test 2: Cache a key without non-exportable flag and verify it can be
     * exported */
    keyId = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache exportable key: %d\n", ret);
        return ret;
    }

    /* Try to export the exportable key - should succeed */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel, sizeof(exportedLabel),
                              exportedKey, &exportedKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export exportable key: %d\n", ret);
        return ret;
    }

    /* Verify exported data matches original */
    if (exportedKeySize != sizeof(key) ||
        memcmp(key, exportedKey, exportedKeySize) != 0 ||
        memcmp(label, exportedLabel, sizeof(label)) != 0) {
        WH_ERROR_PRINT("Exported key data doesn't match original\n");
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Exportable key export succeeded\n");

    /* Clean up */
    wh_Client_KeyEvict(ctx, keyId);

#ifdef WOLFHSM_CFG_DMA
    /* Test 3: Test DMA export with non-exportable key */
    WH_TEST_PRINT("Testing DMA key export protection...\n");

    /* Cache a key with non-exportable flag */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONEXPORTABLE, label,
                               sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache non-exportable key for DMA test: %d\n",
                       ret);
        return ret;
    }

    /* Try to export the non-exportable key via DMA - should fail */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExportDma(ctx, keyId, exportedKey, sizeof(exportedKey),
                                 exportedLabel, sizeof(exportedLabel),
                                 &exportedKeySize);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT(
            "Non-exportable key was exported via DMA unexpectedly: %d\n", ret);
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Non-exportable key DMA export correctly denied\n");

    /* Clean up the key */
    wh_Client_KeyEvict(ctx, keyId);

    /* Test 4: Test DMA export with exportable key */
    keyId = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache exportable key for DMA test: %d\n",
                       ret);
        return ret;
    }

    /* Try to export the exportable key via DMA - should succeed */
    memset(exportedKey, 0, sizeof(exportedKey));
    memset(exportedLabel, 0, sizeof(exportedLabel));
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExportDma(ctx, keyId, exportedKey, sizeof(exportedKey),
                                 exportedLabel, sizeof(exportedLabel),
                                 &exportedKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export exportable key via DMA: %d\n", ret);
        return ret;
    }

    /* Verify exported data matches original */
    if (exportedKeySize != sizeof(key) ||
        memcmp(key, exportedKey, exportedKeySize) != 0 ||
        memcmp(label, exportedLabel, sizeof(label)) != 0) {
        WH_ERROR_PRINT("DMA exported key data doesn't match original\n");
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Exportable key DMA export succeeded\n");

    /* Clean up */
    wh_Client_KeyEvict(ctx, keyId);
#endif /* WOLFHSM_CFG_DMA */

    WH_TEST_PRINT("NON-EXPORTABLE KEYSTORE TEST SUCCESS\n");
    return 0;
}

int whTest_Crypto_Keystore(whClientContext* ctx)
{
    /* A preceding suite may leave the DMA-preferred dispatch mode set; reset
     * to the std path so this suite runs the same way in every config. */
    (void)wh_Client_SetDmaMode(ctx, 0);
    WH_TEST_RETURN_ON_FAIL(_whTest_KeyCache(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_NonExportableKeystore(ctx));
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
