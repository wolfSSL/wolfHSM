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
 * test/wh_test_multiclient.c
 *
 * Multi-client test framework and test suites
 *
 * Provides reusable setup/teardown infrastructure for testing features that
 * require multiple clients. Each client connects to its own server instance,
 * but both servers share a common NVM context to enable testing of shared
 * resources (global keys, shared counters, etc.).
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

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

#include "wh_test_common.h"

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
    whKeyId serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    whKeyId cachedKeyId                = 0;
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "GlobalUnwrapKey123456789012!";
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

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"UnwrapKey50",
        sizeof("UnwrapKey50"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 1 wraps a global key */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    meta.id =
        WH_CLIENT_KEYID_MAKE_WRAPPED_META(WH_KEYUSER_GLOBAL, DUMMY_KEYID_2);
    meta.len    = sizeof(plainKey);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 2 unwraps and caches the key using the global server key */
    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
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

    serverKeyId = WH_CLIENT_KEYID_MAKE_GLOBAL(DUMMY_KEYID_1);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

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
 * Test 9a: Local wrapping key + Local wrapped key (Positive - Same owner)
 * - Client 1 caches a local wrapping key
 * - Client 1 wraps a LOCAL key (USER=client1_id)
 * - Client 1 unwraps and exports successfully
 */
static int _testWrappedKey_LocalWrap_LocalKey_SameOwner(
    whClientContext* client1, whServerContext* server1,
    whClientContext* client2, whServerContext* server2)
{
    int      ret;
    whKeyId  serverKeyId               = DUMMY_KEYID_1; /* Local wrapping key */
    uint16_t client1Id                 = WH_TEST_DEFAULT_CLIENT_ID;
    uint8_t  wrapKey[AES_256_KEY_SIZE] = "LocalWrapKey2Test9aXXXXXXXXXX!";
    uint8_t  plainKey[AES_256_KEY_SIZE] = "LocalPlainKey2Test9aXXXXXXXXX!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint16_t      wrappedKeySz                   = sizeof(wrappedKey);
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    uint16_t      unwrappedKeySz                 = sizeof(unwrappedKey);
    whNvmMetadata meta                           = {0};

    WH_TEST_DEBUG_PRINT("Test 9a: Local wrap key + Local wrapped key (Same owner)\n");

    /* Client 1 caches a LOCAL wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_9a",
        sizeof("WrapKey_9a"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 1 wraps a LOCAL key (USER=client1_id) */
    serverKeyId = DUMMY_KEYID_1; /* Use local wrapping key */
    meta.id     = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client1Id, DUMMY_KEYID_2);
    meta.len = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, &wrappedKeySz));

    /* Client 1 (owner) unwraps and exports the local key */
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
    serverKeyId = DUMMY_KEYID_1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    WH_TEST_PRINT("  PASS: Local wrap key + Local wrapped key (Same owner)\n");

    (void)ret;
    (void)client2;
    (void)server2;
    return 0;
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
    whKeyId serverKeyId                = DUMMY_KEYID_1; /* Local wrapping key */
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "LocalWrapKey2Test10aXXXXXXXXX!";
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

    /* Client 1 caches a LOCAL wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_USAGE_WRAP, (uint8_t*)"WrapKey_10a",
        sizeof("WrapKey_10a"), wrapKey, sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    /* Client 1 wraps a GLOBAL key (USER=0) */
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

    serverKeyId = DUMMY_KEYID_1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

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

    WH_TEST_RETURN_ON_FAIL(_testWrappedKey_LocalWrap_LocalKey_SameOwner(
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
 * MULTI-CLIENT SEQUENTIAL TEST FRAMEWORK
 * ========================================================================== */

/* Generic setup/teardown for multi-client sequential tests using shared memory
 */
static int whTest_MultiClientSequential(void)
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
#endif
    }};
    whServerContext server2[1] = {0};

    /* Expose server contexts to connect callbacks */
    testServer1 = server1;
    testServer2 = server2;

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
int whTest_MultiClient(void)
{
    return whTest_MultiClientSequential();
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
