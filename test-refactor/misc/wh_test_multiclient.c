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
 * test-refactor/misc/wh_test_multiclient.c
 *
 * Multi-client test framework and test suites
 *
 * Provides reusable setup/teardown infrastructure for testing features that
 * require multiple clients. Each client connects to its own server instance,
 * but both servers share a common NVM context to enable testing of shared
 * resources (global keys, shared counters, etc.).
 */

#include "wolfhsm/wh_settings.h"

/* Legacy test/wh_test.c gates the whTest_MultiClient() call site on
 * !WOLFHSM_CFG_NO_CRYPTO. In test-refactor that gate has to live at the
 * file level so the test reports SKIPPED rather than running an empty
 * fixture under NOCRYPTO. */
#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_she_crypto.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_message_she.h"
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#include "wh_test_common.h"
#include "wh_test_keywrap_util.h"
#include "wh_test_list.h"

/* Test configuration */
#define FLASH_RAM_SIZE (1024 * 1024)   /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8)            /* 8B */
#define BUFFER_SIZE 4096

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/* Test key data */
static const uint8_t TEST_KEY_DATA_1[] = "TestGlobalKey1Data";
static const uint8_t TEST_KEY_DATA_2[] = "TestLocalKey2Data";
static const uint8_t TEST_KEY_DATA_3[] = "TestGlobalKey3DataLonger";
#endif

/* ============================================================================
 * DUMMY KEY ID DEFINITIONS
 *
 * Generic key ID values for use in tests. Actual keyIds are defined locally
 * within each test function and macros (WH_CLIENT_KEYID_MAKE_GLOBAL, etc.) are
 * applied at assignment time.
 * ========================================================================== */

#define DUMMY_KEYID_1 1
#define DUMMY_KEYID_2 2

#ifdef WOLFHSM_CFG_KEYWRAP
/* Trusted KEK for unwrap-and-cache (bytes: whTest_KeywrapKek). The test setup
 * provisions it in the shared NVM with WH_NVM_FLAGS_TRUSTED (the way whnvmtool
 * would), since unwrap-and-cache requires a trusted KEK a client can never
 * upload. Distinct global id, so it does not collide with the DUMMY_KEYID_*
 * keys the other tests use. */
#define WH_TEST_MC_WRAP_KEK_ID 0x30
#endif /* WOLFHSM_CFG_KEYWRAP */

/* ============================================================================
 * MULTI-CLIENT TEST FRAMEWORK INFRASTRUCTURE
 * ========================================================================== */

/* Server contexts for connect callbacks */
static whServerContext* testServer1 = NULL;
static whServerContext* testServer2 = NULL;

/* Connect callback for client 1 */
static int _connectCb1(void* context, whCommConnected connected)
{
    (void)context;
    if (testServer1 == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Server_SetConnected(testServer1, connected);
}

/* Connect callback for client 2 */
static int _connectCb2(void* context, whCommConnected connected)
{
    (void)context;
    if (testServer2 == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_Server_SetConnected(testServer2, connected);
}

/* ============================================================================
 * GLOBAL KEYS TEST SUITE
 * ========================================================================== */

#ifdef WOLFHSM_CFG_GLOBAL_KEYS

/*
 * Test 1: Basic global key operations
 * - Client 1 caches a global key
 * - Client 2 reads the same global key and verifies the data matches
 */
static int _testGlobalKeyBasic(whClientContext* client1,
                               whServerContext* server1,
                               whClientContext* client2,
                               whServerContext* server2)
{
    int      ret;
    whKeyId  keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz                         = sizeof(label);
    uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
    uint16_t outSz                           = sizeof(outBuf);

    WH_TEST_PRINT("Test: Global key basic operations\n");

    /* Client 1 caches a global key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"GlobalKey5", sizeof("GlobalKey5"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    /* Client 2 reads the same global key */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));

    /* Verify the key data matches */
    WH_TEST_ASSERT_RETURN(outSz == sizeof(TEST_KEY_DATA_1));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outBuf, TEST_KEY_DATA_1, outSz));

    WH_TEST_PRINT("  PASS: Basic global key operations\n");

    (void)ret;
    return 0;
}

/*
 * Test 2: Local key isolation
 * - Both clients cache local keys with the same ID but different data
 * - Each client verifies they can only read their own local key data, not the
 * other's
 */
static int _testLocalKeyIsolation(whClientContext* client1,
                                  whServerContext* server1,
                                  whClientContext* client2,
                                  whServerContext* server2)
{
    int      ret;
    whKeyId  keyId1 = DUMMY_KEYID_1; /* Local key for client 1 */
    whKeyId  keyId2 =
        DUMMY_KEYID_1; /* Same ID for client 2 - should be different key */
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz    = sizeof(label);
    uint8_t  outBuf[32] = {0};
    uint16_t outSz;

    WH_TEST_PRINT("Test: Local key isolation\n");

    /* Client 1 caches a local key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"LocalKey10_C1", sizeof("LocalKey10_C1"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId1));

    /* Client 2 caches a different local key with same ID */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client2, 0, (uint8_t*)"LocalKey10_C2", sizeof("LocalKey10_C2"),
        (uint8_t*)TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2), keyId2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client2, &keyId2));

    /* Client 1 reads its own key */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client1, keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client1, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    /* Client 2 reads its own key (different data) */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2)));

    WH_TEST_PRINT("  PASS: Local key isolation\n");

    (void)ret;
    return 0;
}

/*
 * Test 3: Mixed global and local keys with no cross-cache interference
 * - Client 1 caches both a global key and a local key with the same ID number
 * - Client 2 caches a local key with the same ID (different data)
 * - Client 1 can read both its global and local keys correctly
 * - Client 2 can access the global key
 * - Client 2 can read its own local key (different data than client 1's)
 * - Client 2 correctly fails to access Client 1's local key
 */
static int _testMixedGlobalLocal(whClientContext* client1,
                                 whServerContext* server1,
                                 whClientContext* client2,
                                 whServerContext* server2)
{
    int      ret;
    whKeyId  globalKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    whKeyId  localKeyId  = DUMMY_KEYID_1; /* Same ID number but local */
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz    = sizeof(label);
    uint8_t  outBuf[32] = {0};
    uint16_t outSz;

    WH_TEST_DEBUG_PRINT(
        "Test: Mixed global and local keys with no cross-cache interference\n");

    /* Client 1 caches global key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"Global15", sizeof("Global15"),
        (uint8_t*)TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3), globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &globalKeyId));

    /* Client 1 caches local key with same ID number */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"Local15_C1", sizeof("Local15_C1"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &localKeyId));

    /* Client 2 caches local key with same ID number (different data) */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client2, 0, (uint8_t*)"Local15_C2", sizeof("Local15_C2"),
        (uint8_t*)TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2), localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client2, &localKeyId));

    /* Client 1 reads its global key */
    globalKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    outSz       = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client1, globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client1, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3)));

    /* Client 1 reads its local key */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client1, localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client1, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    /* Client 2 accesses global key (should work) */
    globalKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    outSz       = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3)));

    /* Client 2 reads its own local key 15 (different data) */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2)));

    /* Client 1 tries to access Client 2's local key 15 - should fail */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client1, localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    ret = wh_Client_KeyExportResponse(client1, label, labelSz, outBuf, &outSz);
    /* Should get client 1's own local key, not client 2's */
    WH_TEST_ASSERT_RETURN(ret == 0);
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    WH_TEST_PRINT("  PASS: Mixed global and local keys with no cross-cache "
           "interference\n");

    (void)ret;
    return 0;
}

/*
 * Test 4: NVM persistence of global keys
 * - Client 1 caches a global key and commits it to NVM, then evicts it from
 * cache
 * - Client 2 successfully reloads the global key from NVM
 */
static int _testGlobalKeyNvmPersistence(whClientContext* client1,
                                        whServerContext* server1,
                                        whClientContext* client2,
                                        whServerContext* server2)
{
    int      ret;
    whKeyId  keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz                         = sizeof(label);
    uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
    uint16_t outSz;

    WH_TEST_PRINT("Test: NVM persistence of global keys\n");

    /* Client 1 caches and commits a global key to NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"GlobalNVM20", sizeof("GlobalNVM20"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    /* Commit to NVM */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommitRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommitResponse(client1));

    /* Evict from cache on server1 */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    /* Client 2 reads from NVM (will reload to cache) */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    /* Clean up - erase the key */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEraseRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEraseResponse(client1));

    WH_TEST_PRINT("  PASS: NVM persistence of global keys\n");

    (void)ret;
    return 0;
}

/*
 * Test 5: Export protection on global keys
 * - Client 1 caches a non-exportable global key
 * - Client 2 correctly fails when attempting to export the protected key
 */
static int _testGlobalKeyExportProtection(whClientContext* client1,
                                          whServerContext* server1,
                                          whClientContext* client2,
                                          whServerContext* server2)
{
    int      ret;
    whKeyId  keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz                         = sizeof(label);
    uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
    uint16_t outSz;

    WH_TEST_PRINT("Test: Export protection on global keys\n");

    /* Client 1 caches a non-exportable global key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_NONEXPORTABLE, (uint8_t*)"NoExport25",
        sizeof("NoExport25"), (uint8_t*)TEST_KEY_DATA_1,
        sizeof(TEST_KEY_DATA_1), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    /* Client 2 tries to export it - should fail */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    ret = wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz);
    /* Should fail due to non-exportable flag */
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Clean up */
    keyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Export protection on global keys\n");

    return 0;
}

#ifdef WOLFHSM_CFG_DMA
/*
 * Test 6: DMA operations with global keys
 * - Client 1 caches a global key using DMA transfer
 * - Client 2 reads the DMA-cached global key via regular export
 * - Client 1 caches another global key via regular method
 * - Client 2 exports that global key via DMA transfer
 */
static int _testGlobalKeyDma(whClientContext* client1, whServerContext* server1,
                             whClientContext* client2, whServerContext* server2)
{
    int      ret;
    whKeyId  keyId1       = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    whKeyId  keyId2       = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_2);
    uint8_t  keyData1[32] = "GlobalDmaCacheTestKey123456!";
    uint8_t  keyData2[32] = "GlobalDmaExportTestKey12345!";
    uint8_t  outBuf[32]  = {0};
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz = sizeof(label);
    uint16_t outSz;

    WH_TEST_PRINT("Test: DMA operations with global keys\n");

    /* Part 1: Cache via DMA, export via regular */
    /* Client 1 caches a global key using DMA */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheDmaRequest(
        client1, 0, (uint8_t*)"DmaGlobal35", sizeof("DmaGlobal35"), keyData1,
        sizeof(keyData1), keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheDmaResponse(client1, &keyId1));

    /* Client 2 reads the global key via regular export */
    keyId1 = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    outSz  = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));

    /* Verify the key data matches */
    WH_TEST_ASSERT_RETURN(outSz == sizeof(keyData1));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outBuf, keyData1, outSz));

    /* Part 2: Cache via regular, export via DMA */
    /* Client 1 caches a global key using regular method */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"DmaExport40", sizeof("DmaExport40"), keyData2,
        sizeof(keyData2), keyId2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId2));

    /* Client 2 exports the global key via DMA */
    keyId2 = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_2);
    outSz  = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportDmaRequest(client2, keyId2, outBuf, sizeof(outBuf)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportDmaResponse(client2, label, labelSz, &outSz));

    /* Verify the key data matches */
    WH_TEST_ASSERT_RETURN(outSz == sizeof(keyData2));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outBuf, keyData2, outSz));

    /* Clean up */
    keyId1 = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    keyId2 = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_2);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: DMA operations with global keys\n");

    (void)ret;
    return 0;
}
#endif /* WOLFHSM_CFG_DMA */

#ifdef WOLFHSM_CFG_KEYWRAP
/*
 * Test 7: Key wrap with global server key
 * - Client 1 caches a global wrapping key
 * - Client 2 wraps a key using that global server key
 * - Client 1 unwraps the key using the same global server key
 */
static int _testGlobalKeyWrapExport(whClientContext* client1,
                              whServerContext* server1,
                              whClientContext* client2,
                              whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "GlobalWrapKey123456789012345!";
    uint8_t plainKey[AES_256_KEY_SIZE] = "PlainKeyToWrap1234567890123!";
    /* Wrapped key size = IV(12) + TAG(16) + KEYSIZE(32) + metadata */
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_PRINT("Test: Key wrap with global server key\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey45",
        sizeof("WrapKey45"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 2 wraps a global key using the global server key */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len    = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client2, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client2, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 1 unwraps the key using the same global server key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportResponse(
        client1, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz));

    /* Verify the unwrapped key matches the original */
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(unwrappedKey, plainKey, sizeof(plainKey)));

    /* Clean up */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Key wrap with global server key\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 8: Key unwrap and cache with global server key
 * - Client 1 caches a global wrapping key and wraps a key (also global)
 * - Client 2 unwraps and caches the key using the global server key
 * - Client 2 exports and verifies the cached key matches the original
 */
static int _testGlobalKeyUnwrapCache(whClientContext* client1,
                                     whServerContext* server1,
                                     whClientContext* client2,
                                     whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID);
    whKeyId cachedKeyId = 0;
    uint8_t plainKey[AES_256_KEY_SIZE] = "KeyToCacheViaUnwrap123456!!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE] = {0};
    uint16_t      wrappedKeySz                 = sizeof(wrappedKey);
    uint8_t       verifyBuf[AES_256_KEY_SIZE]  = {0};
    uint8_t       label[WH_NVM_LABEL_LEN];
    uint16_t      labelSz  = sizeof(label);
    uint16_t      verifySz = sizeof(verifyBuf);
    whNvmMetadata meta     = {0};

    WH_TEST_PRINT("Test: Key unwrap and cache with global server key\n");

    /* The trusted KEK is provisioned in NVM by the test setup; client 1 wraps a
     * global key under it. */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID);
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len    = sizeof(plainKey);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 2 unwraps and caches the key using the trusted KEK */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID);
    ret         = wh_Client_KeyUnwrapAndCacheRequest(client2, WC_CIPHER_AES_GCM,
                                                     serverKeyId, wrappedKey,
                                                     sizeof(wrappedKey));
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Server_HandleRequestMessage(server2);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Client_KeyUnwrapAndCacheResponse(client2, WC_CIPHER_AES_GCM,
                                              &cachedKeyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Verify the cached key by exporting it */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(
        client2, WH_CLIENT_KEYID_MAKE_WRAPPED_GLOBAL(cachedKeyId)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportResponse(client2, label, labelSz,
                                                       verifyBuf, &verifySz));

    /* Verify the exported key matches the original */
    WH_TEST_ASSERT_RETURN(0 == memcmp(verifyBuf, plainKey, sizeof(plainKey)));

    /* Clean up */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(
        client2, WH_CLIENT_KEYID_MAKE_WRAPPED_GLOBAL(cachedKeyId)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client2));

    /* The KEK is server-owned in NVM (carries WH_NVM_FLAGS_TRUSTED) and is not
     * client-evictable, so there is nothing to clean up for it here. */

    WH_TEST_PRINT("  PASS: Key unwrap and cache with global server key\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 7a: Global wrapping key + Global wrapped key (Positive)
 * - Client 1 caches a global wrapping key
 * - Client 2 wraps a global key using it
 * - Client 1 unwraps and exports successfully
 */
static int _testWrappedKey_GlobalWrap_GlobalKey_Positive(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "GlobalWrapKey2Test7aXXXXXXXXX!";
    uint8_t plainKey[AES_256_KEY_SIZE] = "GlobalPlainKey2Test7aXXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_DEBUG_PRINT("Test 7a: Global wrap key + Global wrapped key (Positive)\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_7a",
        sizeof("WrapKey_7a"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 2 wraps a GLOBAL key using the global server key */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client2, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client2, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 1 unwraps and exports the global key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportResponse(
        client1, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz));

    /* Verify the unwrapped key matches the original */
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(unwrappedKey, plainKey, sizeof(plainKey)));

    /* Clean up */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Global wrap key + Global wrapped key (Positive)\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 7b: Global wrapping key + Global wrapped key (Negative - NONEXPORTABLE)
 * - Client 1 caches a global wrapping key
 * - Client 2 wraps a global key with NONEXPORTABLE flag
 * - Client 1 unwrap-and-export fails with WH_ERROR_ACCESS
 */
static int _testWrappedKey_GlobalWrap_GlobalKey_NonExportable(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "GlobalWrapKey2Test7bXXXXXXXXX!";
    uint8_t plainKey[AES_256_KEY_SIZE] = "GlobalPlainKey2Test7bXXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_DEBUG_PRINT("Test 7b: Global wrap key + Global wrapped key (Non-exportable)\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_7b",
        sizeof("WrapKey_7b"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 2 wraps a GLOBAL key with NONEXPORTABLE flag */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len   = sizeof(plainKey);
    meta.flags = WH_NVM_FLAGS_NONEXPORTABLE;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client2, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client2, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 1 tries to unwrap and export - should fail */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    ret = wh_Client_KeyUnwrapAndExportResponse(
        client1, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz);

    /* Should fail due to non-exportable flag */
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Clean up */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Global wrap key + Global wrapped key (Non-exportable)\n");

    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 8a: Global wrapping key + Local wrapped key (Positive - Owner)
 * - Client 1 caches a global wrapping key
 * - Client 2 wraps a LOCAL key (USER=client2_id) using global wrapping key
 * - Client 2 unwraps and exports successfully (owner)
 */
static int _testWrappedKey_GlobalWrap_LocalKey_OwnerExport(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int      ret;
    whKeyId  serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint16_t client2Id                  = WH_TEST_DEFAULT_CLIENT_ID + 1;
    uint8_t  wrapKey[AES_256_KEY_SIZE]  = "GlobalWrapKey2Test8aXXXXXXXXX!";
    uint8_t  plainKey[AES_256_KEY_SIZE] = "LocalPlainKey2Test8aXXXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_DEBUG_PRINT("Test 8a: Global wrap key + Local wrapped key (Owner export)\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_8a",
        sizeof("WrapKey_8a"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 2 wraps a LOCAL key (USER=client2_id) */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    meta.id     = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client2Id, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client2, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client2, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 2 (owner) unwraps and exports the local key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        client2, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportResponse(
        client2, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz));

    /* Verify the unwrapped key matches the original */
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(unwrappedKey, plainKey, sizeof(plainKey)));

    /* Clean up */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Global wrap key + Local wrapped key (Owner export)\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 8b: Global wrapping key + Local wrapped key (Negative - Non-owner)
 * - Client 1 caches a global wrapping key
 * - Client 2 wraps a LOCAL key (USER=client2_id)
 * - Client 1 unwrap-and-export fails with WH_ERROR_ACCESS (not owner)
 * - Client 1 unwrap-and-cache also fails with WH_ERROR_ACCESS
 */
static int _testWrappedKey_GlobalWrap_LocalKey_NonOwnerFails(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int      ret;
    whKeyId  serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    uint16_t client2Id                  = WH_TEST_DEFAULT_CLIENT_ID + 1;
    uint8_t  wrapKey[AES_256_KEY_SIZE]  = "GlobalWrapKey2Test8bXXXXXXXXX!";
    uint8_t  plainKey[AES_256_KEY_SIZE] = "LocalPlainKey2Test8bXXXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};
    whKeyId       cachedKeyId                    = 0;

    WH_TEST_DEBUG_PRINT("Test 8b: Global wrap key + Local wrapped key (Non-owner fails)\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_8b",
        sizeof("WrapKey_8b"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 2 wraps a LOCAL key (USER=client2_id) */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    meta.id     = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client2Id, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client2, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client2, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 1 (non-owner) tries to unwrap and export - should fail */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    ret = wh_Client_KeyUnwrapAndExportResponse(
        client1, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz);

    /* Should fail - Client 1 is not the owner */
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    /* Client 1 (non-owner) tries to unwrap and cache - should also fail */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    ret = wh_Client_KeyUnwrapAndCacheResponse(client1, WC_CIPHER_AES_GCM,
                                              &cachedKeyId);

    /* Should also fail - Client 1 is not the owner */
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    /* Clean up */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Global wrap key + Local wrapped key (Non-owner fails)\n");

    return WH_ERROR_OK;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 9b: Local wrapping key + Local wrapped key (Negative - No access without
 * wrap key)
 * - Client 1 caches a local wrapping key
 * - Client 1 wraps a local key
 * - Client 2 cannot unwrap (doesn't have wrapping key)
 */
static int _testWrappedKey_LocalWrap_LocalKey_NoAccessWithoutWrapKey(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int      ret;
    whKeyId  serverKeyId               = DUMMY_KEYID_1; /* Local wrapping key */
    uint16_t client1Id                 = WH_TEST_DEFAULT_CLIENT_ID;
    uint8_t  wrapKey[AES_256_KEY_SIZE] = "LocalWrapKey2Test9bXXXXXXXXXX!";
    uint8_t  plainKey[AES_256_KEY_SIZE] = "LocalPlainKey2Test9bXXXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_DEBUG_PRINT(
        "Test 9b: Local wrap key + Local wrapped key (No wrap key access)\n");

    /* Client 1 caches a LOCAL wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_9b",
        sizeof("WrapKey_9b"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 1 wraps a LOCAL key */
    serverKeyId = DUMMY_KEYID_1; /* Use local wrapping key */
    meta.id     = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client1Id, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 2 tries to unwrap - should fail (no wrapping key) */
    ret = wh_Client_KeyUnwrapAndExportRequest(client2, WC_CIPHER_AES_GCM,
                                              serverKeyId, wrappedKey,
                                              sizeof(wrappedKey));
    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
        ret = wh_Client_KeyUnwrapAndExportResponse(
            client2, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz);
    }

    /* Should fail - Client 2 doesn't have the wrapping key */
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Clean up */
    serverKeyId = DUMMY_KEYID_1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Local wrap key + Local wrapped key (No wrap key access)\n");

    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 10a: Local wrapping key + Global wrapped key (Positive - Any cache
 * global)
 * - Client 1 caches a local wrapping key
 * - Client 1 wraps a GLOBAL key (USER=0)
 * - Client 1 unwraps and caches to global cache
 * - Client 2 can read from global cache via KeyExport
 */
static int _testWrappedKey_LocalWrap_GlobalKey_AnyCacheGlobal(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID);
    uint8_t plainKey[AES_256_KEY_SIZE] = "GlobalPlainKey2Test10aXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]  = {0};
    uint16_t      wrappedKeySz                  = sizeof(wrappedKey);
    uint8_t       exportedKey[AES_256_KEY_SIZE] = {0};
    uint8_t       label[WH_NVM_LABEL_LEN];
    uint16_t      labelSz     = sizeof(label);
    uint16_t      exportedSz  = sizeof(exportedKey);
    whNvmMetadata meta        = {0};
    whKeyId       cachedKeyId = 0;

    WH_TEST_DEBUG_PRINT("Test 10a: Local wrap key + Global wrapped key (Cache global)\n");

    /* The trusted KEK is provisioned in NVM by the test setup; client 1 wraps a
     * GLOBAL key (USER=0) under it. */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID);
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 1 unwraps and caches to global cache */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheResponse(
        client1, WC_CIPHER_AES_GCM, &cachedKeyId));

    /* Client 2 reads from global cache via KeyExport */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(
        client2, WH_CLIENT_KEYID_MAKE_WRAPPED_GLOBAL(cachedKeyId)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportResponse(
        client2, label, labelSz, exportedKey, &exportedSz));

    /* Verify the exported key matches the original */
    WH_TEST_ASSERT_RETURN(0 == memcmp(exportedKey, plainKey, sizeof(plainKey)));

    /* Clean up */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(
        client2, WH_CLIENT_KEYID_MAKE_WRAPPED_GLOBAL(cachedKeyId)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client2));

    WH_TEST_PRINT("  PASS: Local wrap key + Global wrapped key (Cache global)\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}

/*
 * Test 10b: Local wrapping key + Global wrapped key (Negative - No wrap key)
 * - Client 1 caches a local wrapping key
 * - Client 1 wraps a global key
 * - Client 2 cannot unwrap (doesn't have wrapping key)
 */
static int _testWrappedKey_LocalWrap_GlobalKey_NonOwnerNoWrapKey(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId                = DUMMY_KEYID_1; /* Local wrapping key */
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "LocalWrapKey2Test10bXXXXXXXXX!";
    uint8_t plainKey[AES_256_KEY_SIZE] = "GlobalPlainKey2Test10bXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_DEBUG_PRINT("Test 10b: Local wrap key + Global wrapped key (No wrap key)\n");

    /* Client 1 caches a LOCAL wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_10b",
        sizeof("WrapKey_10b"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 1 wraps a GLOBAL key */
    serverKeyId = DUMMY_KEYID_1; /* Use local wrapping key */
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 2 tries to unwrap - should fail (no wrapping key) */
    ret = wh_Client_KeyUnwrapAndExportRequest(client2, WC_CIPHER_AES_GCM,
                                              serverKeyId, wrappedKey,
                                              sizeof(wrappedKey));
    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
        ret = wh_Client_KeyUnwrapAndExportResponse(
            client2, WC_CIPHER_AES_GCM, &meta, unwrappedKey, &unwrappedKeySz);
    }

    /* Should fail - Client 2 doesn't have the wrapping key */
    WH_TEST_ASSERT_RETURN(ret != 0);

    /* Clean up */
    serverKeyId = DUMMY_KEYID_1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Local wrap key + Global wrapped key (No wrap key)\n");

    return 0;
#undef WRAPPED_KEY_SIZE
}

#endif /* WOLFHSM_CFG_KEYWRAP */

/*
 * Test: KeyId flag preservation
 * - Tests that global and wrapped flags are preserved in server responses
 * - Verifies keyCache operations return correct flags
 */
static int _testKeyIdFlagPreservation(whClientContext* client1,
                                      whServerContext* server1,
                                      whClientContext* client2,
                                      whServerContext* server2)
{
    (void)client2;
    (void)server2;

    WH_TEST_PRINT("Test: KeyId flag preservation\n");

    /* Test 1: Global key cache preserves global flag */
    {
        whKeyId keyId         = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
        whKeyId returnedKeyId = 0;

        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
            client1, 0, (uint8_t*)"GlobalKeyFlags", sizeof("GlobalKeyFlags"),
            (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyCacheResponse(client1, &returnedKeyId));

        /* Verify global flag is preserved */
        WH_TEST_ASSERT_RETURN((returnedKeyId & WH_KEYID_CLIENT_GLOBAL_FLAG) !=
                              0);
        WH_TEST_ASSERT_RETURN((returnedKeyId & WH_KEYID_MASK) == DUMMY_KEYID_1);

        /* Clean up */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyEvictRequest(client1, returnedKeyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

        WH_TEST_PRINT("  PASS: Global key cache preserves global flag\n");
    }

    /* Test 2: Local key cache does not have global flag */
    {
        whKeyId keyId         = DUMMY_KEYID_2; /* Local key - no flags */
        whKeyId returnedKeyId = 0;

        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
            client1, 0, (uint8_t*)"LocalKeyFlags", sizeof("LocalKeyFlags"),
            (uint8_t*)TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2), keyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyCacheResponse(client1, &returnedKeyId));

        /* Verify no global flag */
        WH_TEST_ASSERT_RETURN((returnedKeyId & WH_KEYID_CLIENT_GLOBAL_FLAG) ==
                              0);
        WH_TEST_ASSERT_RETURN((returnedKeyId & WH_KEYID_MASK) == DUMMY_KEYID_2);

        /* Clean up */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyEvictRequest(client1, returnedKeyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

        WH_TEST_PRINT("  PASS: Local key cache has no global flag\n");
    }

    /* Test 3: Reusing returned keyId works correctly */
    {
        whKeyId  requestKeyId  = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
        whKeyId  returnedKeyId = 0;
        uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
        uint16_t outSz                           = sizeof(outBuf);
        uint8_t  label[WH_NVM_LABEL_LEN];
        uint16_t labelSz = sizeof(label);

        /* Cache a global key and get keyId back */
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
            client1, 0, (uint8_t*)"ReuseTest", sizeof("ReuseTest"),
            (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), requestKeyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyCacheResponse(client1, &returnedKeyId));

        /* Use the returned keyId to export the key (common pattern) */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyExportRequest(client1, returnedKeyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportResponse(
            client1, label, labelSz, outBuf, &outSz));

        /* Verify data matches */
        WH_TEST_ASSERT_RETURN(outSz == sizeof(TEST_KEY_DATA_1));
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

        /* Clean up using returned keyId */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_KeyEvictRequest(client1, returnedKeyId));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

        WH_TEST_PRINT("  PASS: Reusing returned keyId works correctly\n");
    }

    return 0;
}

/* Helper function to run all global keys tests */
static int _runGlobalKeysTests(whClientContext* client1,
                               whServerContext* server1,
                               whClientContext* client2,
                               whServerContext* server2)
{
    WH_TEST_RETURN_ON_FAIL(
        _testKeyIdFlagPreservation(client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyBasic(client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testLocalKeyIsolation(client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testMixedGlobalLocal(client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyNvmPersistence(client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyExportProtection(client1, server1, client2, server2));

#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyDma(client1, server1, client2, server2));
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyWrapExport(client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyUnwrapCache(client1, server1, client2, server2));

    /* Comprehensive wrapped key access control tests */
    WH_TEST_RETURN_ON_FAIL(_testWrappedKey_GlobalWrap_GlobalKey_Positive(
        client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(_testWrappedKey_GlobalWrap_GlobalKey_NonExportable(
        client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(_testWrappedKey_GlobalWrap_LocalKey_OwnerExport(
        client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(_testWrappedKey_GlobalWrap_LocalKey_NonOwnerFails(
        client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testWrappedKey_LocalWrap_LocalKey_NoAccessWithoutWrapKey(
            client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(_testWrappedKey_LocalWrap_GlobalKey_AnyCacheGlobal(
        client1, server1, client2, server2));

    WH_TEST_RETURN_ON_FAIL(
        _testWrappedKey_LocalWrap_GlobalKey_NonOwnerNoWrapKey(
            client1, server1, client2, server2));
#endif

    WH_TEST_PRINT("All Global Keys Tests PASSED ===\n");
    return 0;
}

#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/* ============================================================================
 * GLOBAL SHE KEYS TEST SUITE
 *
 * With WOLFHSM_CFG_SHE_GLOBAL_KEYS all SHE slots live in the global-keys
 * namespace, so the two servers (sharing one NVM and its global cache) act as
 * one SHE device seen by both clients. Uses the split request/response APIs
 * since there is no server thread to pump requests.
 * ========================================================================== */

#if defined(WOLFHSM_CFG_SHE_GLOBAL_KEYS) && !defined(WOLFHSM_CFG_NO_CRYPTO)

/* SHE slots used by this suite */
#define SHE_MC_USER_SLOT 4
#define SHE_MC_LOAD_SLOT 5
#define SHE_MC_PRIME_SLOT 8
#define SHE_MC_CTR_SLOT 9

/* Provision a SHE slot in the shared NVM, the way ShePreProgramKey does but
 * with the split API. Counter and SHE flags go in the object label. */
static int _sheGlobalAddNvmKey(whClientContext* client, whServerContext* server,
                               uint8_t sheSlot, uint32_t counter,
                               uint32_t sheFlags, const uint8_t* key)
{
    int     ret;
    int32_t rc                      = 0;
    uint8_t label[WH_NVM_LABEL_LEN] = {0};

    wh_She_Meta2Label(counter, sheFlags, label);
    ret = wh_Client_NvmAddObjectRequest(
        client, WH_SHE_MAKE_KEYID(client->comm->client_id, sheSlot), 0, 0,
        sizeof(label), label, WH_SHE_KEY_SZ, key);
    if (ret == 0) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    if (ret == 0) {
        ret = wh_Client_NvmAddObjectResponse(client, &rc);
    }
    if (ret == 0) {
        ret = (int)rc;
    }
    return ret;
}

/* One ECB encrypt through the given client/server pair */
static int _sheGlobalEncEcb(whClientContext* client, whServerContext* server,
                            uint8_t sheSlot, uint8_t* in, uint8_t* out)
{
    int ret = wh_Client_SheEncEcbRequest(client, sheSlot, in, WH_SHE_KEY_SZ);
    if (ret == 0) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    if (ret == 0) {
        ret = wh_Client_SheEncEcbResponse(client, out, WH_SHE_KEY_SZ);
    }
    return ret;
}

/* Software AES-ECB of one block, the expected value for the server results */
static int _sheGlobalSwEcb(const uint8_t* key, const uint8_t* in, uint8_t* out)
{
    Aes aes[1];
    int ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(aes, key, WH_SHE_KEY_SZ, NULL, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesEncryptDirect(aes, out, in);
        }
        wc_AesFree(aes);
    }
    return ret;
}

static int _sheGlobalSetUid(whClientContext* client, whServerContext* server,
                            uint8_t* uid, uint32_t uidSz)
{
    int ret = wh_Client_SheSetUidRequest(client, uid, uidSz);
    if (ret == 0) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    if (ret == 0) {
        ret = wh_Client_SheSetUidResponse(client);
    }
    return ret;
}

static int _sheGlobalLoadPlainKey(whClientContext* client,
                                  whServerContext* server, uint8_t* key)
{
    int ret = wh_Client_SheLoadPlainKeyRequest(client, key, WH_SHE_KEY_SZ);
    if (ret == 0) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    if (ret == 0) {
        ret = wh_Client_SheLoadPlainKeyResponse(client);
    }
    return ret;
}

/* boot MAC digest = CMAC_bootMacKey(zeros || size || bootloader) */
static int _sheGlobalComputeBootMac(const uint8_t* bootloader,
                                    uint32_t       bootloaderSz,
                                    const uint8_t* bootMacKey,
                                    uint8_t*       digestOut)
{
    int     ret;
    Cmac    cmac[1];
    uint8_t zeros[WH_SHE_BOOT_MAC_PREFIX_LEN] = {0};
    word32  digestSz                          = AES_BLOCK_SIZE;

    if ((ret = wc_InitCmac(cmac, bootMacKey, WH_SHE_KEY_SZ, WC_CMAC_AES,
                           NULL)) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, zeros, sizeof(zeros))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, (const uint8_t*)&bootloaderSz,
                             sizeof(bootloaderSz))) != 0) {
        return ret;
    }
    if ((ret = wc_CmacUpdate(cmac, bootloader, bootloaderSz)) != 0) {
        return ret;
    }
    return wc_CmacFinal(cmac, digestOut, &digestSz);
}

/* The secure-boot protocol (INIT / UPDATE / FINISH) only has a blocking
 * client API, so drive the messages directly and pump the server between
 * each step. The bootloader used here fits one UPDATE chunk. */
static int _sheGlobalSecureBoot(whClientContext* client,
                                whServerContext* server, uint8_t* bootloader,
                                uint32_t bootloaderLen)
{
    int      ret;
    uint16_t group;
    uint16_t action;
    uint16_t dataSz;
    uint8_t* respBuf;

    whMessageShe_SecureBootInitRequest*    initReq;
    whMessageShe_SecureBootUpdateRequest*  updateReq;
    whMessageShe_SecureBootInitResponse*   initResp;
    whMessageShe_SecureBootUpdateResponse* updateResp;
    whMessageShe_SecureBootFinishResponse* finishResp;

    if (bootloaderLen >
        (uint32_t)(WOLFHSM_CFG_COMM_DATA_LEN -
                   sizeof(whMessageShe_SecureBootUpdateRequest))) {
        return WH_ERROR_BADARGS;
    }

    respBuf = (uint8_t*)wh_CommClient_GetDataPtr(client->comm);

    /* INIT: announce the bootloader size */
    initReq = (whMessageShe_SecureBootInitRequest*)wh_CommClient_GetDataPtr(
        client->comm);
    initReq->sz = bootloaderLen;
    WH_TEST_RETURN_ON_FAIL(wh_Client_SendRequest(
        client, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_INIT, sizeof(*initReq),
        (uint8_t*)initReq));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    ret = wh_Client_RecvResponse(client, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, respBuf);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    initResp = (whMessageShe_SecureBootInitResponse*)respBuf;
    if (initResp->rc != WH_SHE_ERC_NO_ERROR) {
        return initResp->rc;
    }

    /* UPDATE: feed the bootloader (single chunk) */
    updateReq = (whMessageShe_SecureBootUpdateRequest*)wh_CommClient_GetDataPtr(
        client->comm);
    updateReq->sz = bootloaderLen;
    memcpy((uint8_t*)(updateReq + 1), bootloader, bootloaderLen);
    WH_TEST_RETURN_ON_FAIL(wh_Client_SendRequest(
        client, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_UPDATE,
        (uint16_t)(sizeof(*updateReq) + bootloaderLen), (uint8_t*)updateReq));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    ret = wh_Client_RecvResponse(client, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, respBuf);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    updateResp = (whMessageShe_SecureBootUpdateResponse*)respBuf;
    if (updateResp->rc != WH_SHE_ERC_NO_ERROR) {
        return updateResp->rc;
    }

    /* FINISH: verify the boot MAC */
    WH_TEST_RETURN_ON_FAIL(wh_Client_SendRequest(
        client, WH_MESSAGE_GROUP_SHE, WH_SHE_SECURE_BOOT_FINISH, 0, NULL));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    ret = wh_Client_RecvResponse(client, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, respBuf);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    finishResp = (whMessageShe_SecureBootFinishResponse*)respBuf;
    return finishResp->rc;
}

static int _sheGlobalGetStatus(whClientContext* client, whServerContext* server,
                               uint8_t* sreg)
{
    int ret = wh_Client_SheGetStatusRequest(client);
    if (ret == 0) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    if (ret == 0) {
        ret = wh_Client_SheGetStatusResponse(client, sreg);
    }
    return ret;
}

#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
static int _sheGlobalUnwrapAndCache(whClientContext* client,
                                    whServerContext* server, uint8_t* blob,
                                    uint16_t blobSz, uint16_t* outId)
{
    /* The KEK is a global CRYPTO key, so unlike SHE slot ids the client must
     * name it with the global flag */
    int ret = wh_Client_KeyUnwrapAndCacheRequest(
        client, WC_CIPHER_AES_GCM,
        WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID), blob, blobSz);
    if (ret == 0) {
        ret = wh_Server_HandleRequestMessage(server);
    }
    if (ret == 0) {
        ret = wh_Client_KeyUnwrapAndCacheResponse(client, WC_CIPHER_AES_GCM,
                                                  outId);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_KEYWRAP && HAVE_AESGCM */

static int _runSheGlobalTests(whClientContext* client1,
                              whServerContext* server1,
                              whClientContext* client2,
                              whServerContext* server2)
{
    int     ret;
    int     i;
    uint8_t sheUid[WH_SHE_UID_SZ];
    uint8_t secretKey[WH_SHE_KEY_SZ];
    uint8_t masterKey[WH_SHE_KEY_SZ];
    uint8_t bootMacKey[WH_SHE_KEY_SZ];
    uint8_t bootDigest[WH_SHE_KEY_SZ];
    uint8_t bootloader[64];
    uint8_t userKey[WH_SHE_KEY_SZ];
    uint8_t loadKey[WH_SHE_KEY_SZ];
    uint8_t ramKey[WH_SHE_KEY_SZ];
    uint8_t ptIn[WH_SHE_KEY_SZ];
    uint8_t ct1[WH_SHE_KEY_SZ];
    uint8_t ct2[WH_SHE_KEY_SZ];
    uint8_t ctSw[WH_SHE_KEY_SZ];
    uint8_t sreg;
    uint8_t m1[WH_SHE_M1_SZ];
    uint8_t m2[WH_SHE_M2_SZ];
    uint8_t m3[WH_SHE_M3_SZ];
    uint8_t m4[WH_SHE_M4_SZ];
    uint8_t m5[WH_SHE_M5_SZ];
    uint8_t m4Out[WH_SHE_M4_SZ];
    uint8_t m5Out[WH_SHE_M5_SZ];

    WH_TEST_PRINT("Testing Global SHE Keys...\n");

    for (i = 0; i < (int)sizeof(sheUid); i++) {
        sheUid[i] = (uint8_t)i;
    }
    memset(secretKey, 0xA1, sizeof(secretKey));
    memset(masterKey, 0xA2, sizeof(masterKey));
    memset(bootMacKey, 0xA8, sizeof(bootMacKey));
    memset(bootloader, 0xB7, sizeof(bootloader));
    memset(userKey, 0xA3, sizeof(userKey));
    memset(loadKey, 0xA4, sizeof(loadKey));
    memset(ramKey, 0xA5, sizeof(ramKey));
    memset(ptIn, 0x11, sizeof(ptIn));

    /* Client 1 provisions the shared SHE slots, including the boot MAC key
     * and the expected bootloader digest; same UID on both servers */
    WH_TEST_RETURN_ON_FAIL(_sheGlobalComputeBootMac(
        bootloader, sizeof(bootloader), bootMacKey, bootDigest));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalAddNvmKey(
        client1, server1, WH_SHE_SECRET_KEY_ID, 0, 0, secretKey));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalAddNvmKey(
        client1, server1, WH_SHE_MASTER_ECU_KEY_ID, 0, 0, masterKey));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalAddNvmKey(
        client1, server1, WH_SHE_BOOT_MAC_KEY_ID, 0, 0, bootMacKey));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalAddNvmKey(
        client1, server1, WH_SHE_BOOT_MAC, 0, 0, bootDigest));
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalAddNvmKey(client1, server1, SHE_MC_USER_SLOT, 0, 0, userKey));
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalSetUid(client1, server1, sheUid, sizeof(sheUid)));
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalSetUid(client2, server2, sheUid, sizeof(sheUid)));

    /* Both servers secure boot against the keys client 1 provisioned. The
     * boot state machine is per server, so each must boot on its own. */
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalSecureBoot(client1, server1, bootloader, sizeof(bootloader)));
    sreg = 0;
    WH_TEST_RETURN_ON_FAIL(_sheGlobalGetStatus(client1, server1, &sreg));
    WH_TEST_ASSERT_RETURN((sreg & WH_SHE_SREG_BOOT_OK) != 0);
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalSecureBoot(client2, server2, bootloader, sizeof(bootloader)));
    sreg = 0;
    WH_TEST_RETURN_ON_FAIL(_sheGlobalGetStatus(client2, server2, &sreg));
    WH_TEST_ASSERT_RETURN((sreg & WH_SHE_SREG_BOOT_OK) != 0);
    WH_TEST_PRINT("  PASS: Both servers secure boot on shared boot keys\n");

    /* Both clients encrypt with the slot client 1 provisioned */
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalEncEcb(client1, server1, SHE_MC_USER_SLOT, ptIn, ct1));
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalEncEcb(client2, server2, SHE_MC_USER_SLOT, ptIn, ct2));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalSwEcb(userKey, ptIn, ctSw));
    WH_TEST_ASSERT_RETURN(memcmp(ct1, ct2, sizeof(ct1)) == 0);
    WH_TEST_ASSERT_RETURN(memcmp(ct1, ctSw, sizeof(ct1)) == 0);
    WH_TEST_PRINT("  PASS: Both clients share a provisioned SHE slot\n");

    /* Client 1 installs a key with the LoadKey protocol; client 2 uses it */
    WH_TEST_RETURN_ON_FAIL(wh_She_GenerateLoadableKey(
        SHE_MC_LOAD_SLOT, WH_SHE_MASTER_ECU_KEY_ID, 1, 0, sheUid, loadKey,
        masterKey, m1, m2, m3, m4, m5));
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheLoadKeyRequest(client1, m1, m2, m3));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheLoadKeyResponse(client1, m4Out, m5Out));
    WH_TEST_ASSERT_RETURN(memcmp(m4Out, m4, sizeof(m4)) == 0);
    WH_TEST_ASSERT_RETURN(memcmp(m5Out, m5, sizeof(m5)) == 0);
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalEncEcb(client2, server2, SHE_MC_LOAD_SLOT, ptIn, ct2));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalSwEcb(loadKey, ptIn, ctSw));
    WH_TEST_ASSERT_RETURN(memcmp(ct2, ctSw, sizeof(ct2)) == 0);
    WH_TEST_PRINT("  PASS: LoadKey by client 1 visible to client 2\n");

#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
    {
        uint8_t  blob[128];
        uint16_t blobSz;
        uint16_t outId;
        uint16_t expSz = (uint16_t)(WH_KEYWRAP_AES_GCM_HEADER_SIZE +
                                    sizeof(whNvmMetadata) + WH_SHE_KEY_SZ);
        uint8_t  primeKey[WH_SHE_KEY_SZ];
        uint8_t  ctrKey[WH_SHE_KEY_SZ];

        memset(primeKey, 0xA6, sizeof(primeKey));
        memset(ctrKey, 0xA7, sizeof(ctrKey));

        /* Wrap-export a SHE slot naming it by raw slot number, no global
         * flag, under the shared trusted KEK */
        blobSz = sizeof(blob);
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapExportRequest(
            client1, WC_CIPHER_AES_GCM, SHE_MC_USER_SLOT, WH_KEYTYPE_SHE,
            WH_CLIENT_KEYID_MAKE_GLOBAL(WH_TEST_MC_WRAP_KEK_ID)));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapExportResponse(
            client1, WC_CIPHER_AES_GCM, blob, &blobSz));
        WH_TEST_ASSERT_RETURN(blobSz == expSz);
        WH_TEST_PRINT("  PASS: Wrap-export of a SHE slot by raw slot id\n");

        /* Client 1 builds a blob for an unused slot, client 2 primes it,
         * client 1 uses it through the shared global cache */
        blobSz = sizeof(blob);
        WH_TEST_RETURN_ON_FAIL(whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_SHE_MAKE_KEYID(client1->comm->client_id, SHE_MC_PRIME_SLOT), 1,
            0, primeKey, blob, &blobSz));
        WH_TEST_RETURN_ON_FAIL(
            _sheGlobalUnwrapAndCache(client2, server2, blob, blobSz, &outId));
        WH_TEST_ASSERT_RETURN((outId & WH_KEYID_MASK) == SHE_MC_PRIME_SLOT);
        WH_TEST_ASSERT_RETURN((outId & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0);
        WH_TEST_RETURN_ON_FAIL(
            _sheGlobalEncEcb(client1, server1, SHE_MC_PRIME_SLOT, ptIn, ct1));
        WH_TEST_RETURN_ON_FAIL(_sheGlobalSwEcb(primeKey, ptIn, ctSw));
        WH_TEST_ASSERT_RETURN(memcmp(ct1, ctSw, sizeof(ct1)) == 0);
        WH_TEST_PRINT("  PASS: Cross-client unwrap-and-cache prime\n");

        /* Counter guard runs against the globally committed slot */
        WH_TEST_RETURN_ON_FAIL(_sheGlobalAddNvmKey(
            client1, server1, SHE_MC_CTR_SLOT, 5, 0, ctrKey));
        blobSz = sizeof(blob);
        WH_TEST_RETURN_ON_FAIL(whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_SHE_MAKE_KEYID(client2->comm->client_id, SHE_MC_CTR_SLOT), 3, 0,
            ctrKey, blob, &blobSz));
        ret = _sheGlobalUnwrapAndCache(client2, server2, blob, blobSz, &outId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("SHE global counter rollback expected ACCESS, got "
                           "%d\n",
                           ret);
            return (ret == 0) ? WH_ERROR_ABORTED : ret;
        }
        blobSz = sizeof(blob);
        WH_TEST_RETURN_ON_FAIL(whTest_BuildSheKeyBlob(
            whTest_KeywrapKek, sizeof(whTest_KeywrapKek),
            WH_SHE_MAKE_KEYID(client2->comm->client_id, SHE_MC_CTR_SLOT), 5, 0,
            ctrKey, blob, &blobSz));
        WH_TEST_RETURN_ON_FAIL(
            _sheGlobalUnwrapAndCache(client2, server2, blob, blobSz, &outId));
        WH_TEST_PRINT("  PASS: Counter guard on a globally committed slot\n");
    }
#endif /* WOLFHSM_CFG_KEYWRAP && HAVE_AESGCM */

    /* The RAM key is one shared volatile slot, but the plain-loaded state
     * that allows exporting it is per server */
    WH_TEST_RETURN_ON_FAIL(_sheGlobalLoadPlainKey(client1, server1, ramKey));
    WH_TEST_RETURN_ON_FAIL(
        _sheGlobalEncEcb(client2, server2, WH_SHE_RAM_KEY_ID, ptIn, ct2));
    WH_TEST_RETURN_ON_FAIL(_sheGlobalSwEcb(ramKey, ptIn, ctSw));
    WH_TEST_ASSERT_RETURN(memcmp(ct2, ctSw, sizeof(ct2)) == 0);
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheExportRamKeyRequest(client2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    ret = wh_Client_SheExportRamKeyResponse(client2, m1, m2, m3, m4, m5);
    if (ret != WH_SHE_ERC_KEY_INVALID) {
        WH_ERROR_PRINT("SHE global RAM key export without plain load expected "
                       "KEY_INVALID, got %d\n",
                       ret);
        return (ret == 0) ? WH_ERROR_ABORTED : ret;
    }
    WH_TEST_RETURN_ON_FAIL(_sheGlobalLoadPlainKey(client2, server2, ramKey));
    WH_TEST_RETURN_ON_FAIL(wh_Client_SheExportRamKeyRequest(client2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheExportRamKeyResponse(client2, m1, m2, m3, m4, m5));
    WH_TEST_PRINT("  PASS: Shared RAM key, per-server export state\n");

    /* Cleanup: evict the cached SHE entries (shared global cache, so one
     * server suffices) and destroy the NVM objects so later suites and the
     * next fixture run start clean. Clients cannot evict SHE-typed cache
     * entries, so use the server API directly. */
    {
        static const uint8_t evictSlots[] = {
            WH_SHE_MASTER_ECU_KEY_ID, WH_SHE_BOOT_MAC_KEY_ID, WH_SHE_BOOT_MAC,
            SHE_MC_USER_SLOT,         SHE_MC_LOAD_SLOT,       SHE_MC_PRIME_SLOT,
            SHE_MC_CTR_SLOT,          WH_SHE_RAM_KEY_ID,
        };
        /* All SHE ids are global here, so the client id argument is moot */
        whNvmId destroyList[] = {
            WH_SHE_MAKE_KEYID(0, WH_SHE_SECRET_KEY_ID),
            WH_SHE_MAKE_KEYID(0, WH_SHE_MASTER_ECU_KEY_ID),
            WH_SHE_MAKE_KEYID(0, WH_SHE_BOOT_MAC_KEY_ID),
            WH_SHE_MAKE_KEYID(0, WH_SHE_BOOT_MAC),
            WH_SHE_MAKE_KEYID(0, SHE_MC_USER_SLOT),
            WH_SHE_MAKE_KEYID(0, SHE_MC_LOAD_SLOT),
#if defined(WOLFHSM_CFG_KEYWRAP) && defined(HAVE_AESGCM)
            /* Only created by the keywrap sub-tests above */
            WH_SHE_MAKE_KEYID(0, SHE_MC_CTR_SLOT),
#endif
        };
        int32_t rc = 0;

        for (i = 0; i < (int)sizeof(evictSlots); i++) {
            ret = wh_Server_KeystoreEvictKey(
                server1,
                WH_SHE_MAKE_KEYID(client1->comm->client_id, evictSlots[i]));
            if (ret != 0 && ret != WH_ERROR_NOTFOUND) {
                return ret;
            }
        }
        WH_TEST_RETURN_ON_FAIL(wh_Client_NvmDestroyObjectsRequest(
            client1, (whNvmId)(sizeof(destroyList) / sizeof(destroyList[0])),
            destroyList));
        WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_NvmDestroyObjectsResponse(client1, &rc));
        WH_TEST_ASSERT_RETURN(rc == 0);
    }

    WH_TEST_PRINT("All Global SHE Keys Tests PASSED ===\n");
    return 0;
}

#endif /* WOLFHSM_CFG_SHE_GLOBAL_KEYS && !WOLFHSM_CFG_NO_CRYPTO */

/* ============================================================================
 * MULTI-CLIENT SEQUENTIAL TEST FRAMEWORK
 * ========================================================================== */

/* Generic setup/teardown for multi-client sequential tests using shared memory
 */
static int _whTest_MultiClient(void)
{
    int ret = 0;

    /* Transport memory configurations for both clients */
    static uint8_t       req1[BUFFER_SIZE];
    static uint8_t       resp1[BUFFER_SIZE];
    whTransportMemConfig tmcf1[1] = {{
        .req       = (whTransportMemCsr*)req1,
        .req_size  = sizeof(req1),
        .resp      = (whTransportMemCsr*)resp1,
        .resp_size = sizeof(resp1),
    }};

    static uint8_t       req2[BUFFER_SIZE];
    static uint8_t       resp2[BUFFER_SIZE];
    whTransportMemConfig tmcf2[1] = {{
        .req       = (whTransportMemCsr*)req2,
        .req_size  = sizeof(req2),
        .resp      = (whTransportMemCsr*)resp2,
        .resp_size = sizeof(resp2),
    }};

    /* Client 1 configuration */
    whTransportClientCb         tccb1[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc1[1]    = {0};
    whCommClientConfig          cc_conf1[1] = {{
                 .transport_cb      = tccb1,
                 .transport_context = (void*)tmcc1,
                 .transport_config  = (void*)tmcf1,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
                 .connect_cb        = _connectCb1,
    }};
    whClientContext             client1[1]  = {0};
    whClientConfig              c_conf1[1]  = {{
                      .comm = cc_conf1,
    }};

    /* Client 2 configuration */
    whTransportClientCb         tccb2[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc2[1]    = {0};
    whCommClientConfig          cc_conf2[1] = {{
                 .transport_cb      = tccb2,
                 .transport_context = (void*)tmcc2,
                 .transport_config  = (void*)tmcf2,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID + 1,
                 .connect_cb        = _connectCb2,
    }};
    whClientContext             client2[1]  = {0};
    whClientConfig              c_conf2[1]  = {{
                      .comm = cc_conf2,
    }};

    /* Shared NVM configuration using RamSim Flash */
    static uint8_t   memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]                  = {0};
    whFlashRamsimCfg fc_conf[1]             = {{
                    .size       = FLASH_RAM_SIZE,
                    .sectorSize = FLASH_SECTOR_SIZE,
                    .pageSize   = FLASH_PAGE_SIZE,
                    .erasedByte = ~(uint8_t)0,
                    .memory     = memory,
    }};
    const whFlashCb  fcb[1]                 = {WH_FLASH_RAMSIM_CB};

    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {0}; /* Shared NVM */

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Crypto contexts for both servers */
    whServerCryptoContext crypto1[1] = {0};
    whServerCryptoContext crypto2[1] = {0};
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* SHE contexts for both servers */
    whServerSheContext she1[1];
    whServerSheContext she2[1];
#endif
#endif

    /* Server 1 configuration */
    whTransportServerCb         tscb1[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc1[1]    = {0};
    whCommServerConfig          cs_conf1[1] = {{
                 .transport_cb      = tscb1,
                 .transport_context = (void*)tmsc1,
                 .transport_config  = (void*)tmcf1,
                 .server_id         = 101,
    }};
    whServerConfig              s_conf1[1]  = {{
                      .comm_config = cs_conf1,
                      .nvm         = nvm, /* Shared NVM */
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
        .crypto = crypto1,
#ifdef WOLFHSM_CFG_SHE_EXTENSION
        .she = she1,
#endif
#endif
    }};
    whServerContext server1[1] = {0};

    /* Server 2 configuration */
    whTransportServerCb         tscb2[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc2[1]    = {0};
    whCommServerConfig          cs_conf2[1] = {{
                 .transport_cb      = tscb2,
                 .transport_context = (void*)tmsc2,
                 .transport_config  = (void*)tmcf2,
                 .server_id         = 102,
    }};
    whServerConfig              s_conf2[1]  = {{
                      .comm_config = cs_conf2,
                      .nvm         = nvm, /* Shared NVM */

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
        .crypto = crypto2,
#ifdef WOLFHSM_CFG_SHE_EXTENSION
        .she = she2,
#endif
#endif
    }};
    whServerContext server2[1] = {0};

    /* Expose server contexts to connect callbacks */
    testServer1 = server1;
    testServer2 = server2;

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_SHE_EXTENSION)
    memset(she1, 0, sizeof(she1));
    memset(she2, 0, sizeof(she2));
#endif

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Initialize wolfCrypt */
    ret = wolfCrypt_Init();
    if (ret != 0)
        return ret;
#endif

    /* Initialize NVM (shared) */
    ret = wh_Nvm_Init(nvm, n_conf);
    if (ret != 0)
        return ret;

#ifdef WOLFHSM_CFG_KEYWRAP
    /* Provision the trusted KEK into the shared NVM before any client runs, the
     * way whnvmtool would. WH_NVM_FLAGS_TRUSTED makes it the trusted KEK that
     * unwrap-and-cache requires; both servers freshen it from this NVM. */
    {
        whNvmMetadata kekMeta = {0};
        kekMeta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_KEYUSER_GLOBAL,
                                       WH_TEST_MC_WRAP_KEK_ID);
        kekMeta.access = WH_NVM_ACCESS_ANY;
        kekMeta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP |
                        WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_NONMODIFIABLE;
        kekMeta.len = (whNvmSize)sizeof(whTest_KeywrapKek);
        memcpy(kekMeta.label, "MC wrap KEK", sizeof("MC wrap KEK"));
        ret = wh_Nvm_AddObject(nvm, &kekMeta, kekMeta.len, whTest_KeywrapKek);
        if (ret != 0)
            return ret;
    }
#endif /* WOLFHSM_CFG_KEYWRAP */

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Initialize RNGs */
    ret = wc_InitRng_ex(crypto1->rng, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_InitRng_ex(crypto2->rng, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;
#endif

    /* Initialize servers */
    ret = wh_Server_Init(server1, s_conf1);
    if (ret != 0)
        return ret;

    ret = wh_Server_Init(server2, s_conf2);
    if (ret != 0)
        return ret;

    /* Initialize clients */
    ret = wh_Client_Init(client1, c_conf1);
    if (ret != 0)
        return ret;

    ret = wh_Client_Init(client2, c_conf2);
    if (ret != 0)
        return ret;

    /* Initialize communication for both clients */
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    ret = wh_Client_CommInitRequest(client1);
    if (ret != 0)
        return ret;
    ret = wh_Server_HandleRequestMessage(server1);
    if (ret != 0)
        return ret;
    ret = wh_Client_CommInitResponse(client1, &client_id, &server_id);
    if (ret != 0)
        return ret;

    ret = wh_Client_CommInitRequest(client2);
    if (ret != 0)
        return ret;
    ret = wh_Server_HandleRequestMessage(server2);
    if (ret != 0)
        return ret;
    ret = wh_Client_CommInitResponse(client2, &client_id, &server_id);
    if (ret != 0)
        return ret;

    WH_TEST_PRINT("=== Multi-Client Sequential Tests Begin ===\n");
    /* Run test suites that require multiple clients */
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    WH_TEST_RETURN_ON_FAIL(
        _runGlobalKeysTests(client1, server1, client2, server2));
#endif

#if defined(WOLFHSM_CFG_SHE_GLOBAL_KEYS) && !defined(WOLFHSM_CFG_NO_CRYPTO)
    WH_TEST_RETURN_ON_FAIL(
        _runSheGlobalTests(client1, server1, client2, server2));
#endif

    /* Future test suites here */

    /* Cleanup */
    wh_Client_Cleanup(client1);
    wh_Client_Cleanup(client2);
    wh_Server_Cleanup(server1);
    wh_Server_Cleanup(server2);
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    wc_FreeRng(crypto1->rng);
    wc_FreeRng(crypto2->rng);
    wolfCrypt_Cleanup();
#endif
    wh_Nvm_Cleanup(nvm);

    WH_TEST_PRINT("=== Multi-Client Sequential Tests Complete ===\n");

    return 0;
}

/* ============================================================================
 * PUBLIC API
 * ========================================================================== */

/* Main entry point for multi-client tests */
int whTest_MultiClient(void* ctx)
{
    (void)ctx;
    return _whTest_MultiClient();
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
