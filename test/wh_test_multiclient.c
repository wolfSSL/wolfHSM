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

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wh_test_common.h"
#include "wh_test_keywrap_util.h"

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

    /* The KEK is server-owned in NVM (WH_NVM_FLAGS_TRUSTED) and not
     * client-evictable, so there is nothing to clean up for it here. */

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

#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
/* ============================================================================
 * CLIENT NVM ID-TRANSLATION TEST SUITE
 *
 * These tests assert the per-client NVM id namespace: each client sees its own
 * 1..255 id range plus a shared 1..255 global range. Cross-client raw access
 * via the NVM api is impossible.
 *
 * Only meaningful when client NVM id translation is enabled (default).
 * ========================================================================== */

static const uint8_t NVM_ISOLATION_PAYLOAD_A[] = "client-A-secret-NVM-payload";
static const uint8_t NVM_ISOLATION_PAYLOAD_B[] = "client-B-different-payload";

/*
 * Helper: add an NVM object via the explicit Request/Handle/Response
 * pattern so that the matching server can be driven manually (multiclient
 * sequential setup has no automatic dispatch).
 */
static int _nvmAddViaServer(whClientContext* client, whServerContext* server,
                            whNvmId id, whNvmSize len, const uint8_t* data,
                            int32_t* out_rc)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectRequest(
        client, id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, 0, NULL, len, data));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectResponse(client, out_rc));
    return WH_ERROR_OK;
}

static int _nvmReadViaServer(whClientContext* client, whServerContext* server,
                             whNvmId id, whNvmSize len, int32_t* out_rc,
                             whNvmSize* out_len, uint8_t* buf)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadRequest(client, id, 0, len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmReadResponse(client, out_rc, out_len, buf));
    return WH_ERROR_OK;
}

static int _nvmDestroyViaServer(whClientContext* client,
                                whServerContext* server, whNvmId id,
                                int32_t* out_rc)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmDestroyObjectsRequest(client, 1, &id));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmDestroyObjectsResponse(client, out_rc));
    return WH_ERROR_OK;
}

static int _nvmListViaServer(whClientContext* client, whServerContext* server,
                             whNvmId startId, int32_t* out_rc,
                             whNvmId* out_count, whNvmId* out_id)
{
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmListRequest(
        client, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, startId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmListResponse(client, out_rc, out_count, out_id));
    return WH_ERROR_OK;
}

static int _nvmGetMetadataViaServer(whClientContext* client,
                                    whServerContext* server, whNvmId id,
                                    int32_t* out_rc)
{
    whNvmId     got_id = 0;
    whNvmAccess access = 0;
    whNvmFlags  flags  = 0;
    whNvmSize   len    = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataRequest(client, id));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadataResponse(
        client, out_rc, &got_id, &access, &flags, &len, 0, NULL));
    return WH_ERROR_OK;
}

/*
 * Client A adds NVM id 5 with secret payload. Client B reading id 5 must NOT
 * see A's bytes (either NOTFOUND, or B's own value if B has one).
 */
static int _testNvmClientIsolation(whClientContext* client1,
                                   whServerContext* server1,
                                   whClientContext* client2,
                                   whServerContext* server2)
{
    const whNvmId shared_id = 5;
    int32_t       out_rc    = 0;
    uint8_t       buf[64]   = {0};
    whNvmSize     out_len   = 0;

    WH_TEST_PRINT("Testing NVM client isolation...\n");

    /* Client A adds a secret object at id=5 */
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(client1, server1, shared_id,
                                            sizeof(NVM_ISOLATION_PAYLOAD_A),
                                            NVM_ISOLATION_PAYLOAD_A, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Client A confirms it can read its own bytes back */
    out_len = 0;
    memset(buf, 0, sizeof(buf));
    WH_TEST_RETURN_ON_FAIL(_nvmReadViaServer(
        client1, server1, shared_id, sizeof(buf), &out_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == sizeof(NVM_ISOLATION_PAYLOAD_A));
    WH_TEST_ASSERT_RETURN(memcmp(buf, NVM_ISOLATION_PAYLOAD_A,
                                 sizeof(NVM_ISOLATION_PAYLOAD_A)) == 0);

    /* Client B reads id=5: must NOT find A's bytes */
    out_len = 0;
    memset(buf, 0, sizeof(buf));
    WH_TEST_RETURN_ON_FAIL(_nvmReadViaServer(
        client2, server2, shared_id, sizeof(buf), &out_rc, &out_len, buf));
    /* Either NOTFOUND or read returned different bytes; never A's plaintext. */
    if (out_rc == WH_ERROR_OK) {
        WH_TEST_ASSERT_RETURN(memcmp(buf, NVM_ISOLATION_PAYLOAD_A,
                                     sizeof(NVM_ISOLATION_PAYLOAD_A)) != 0);
    }

    /* Client B adds its own object at the same client-facing id=5 */
    out_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(client2, server2, shared_id,
                                            sizeof(NVM_ISOLATION_PAYLOAD_B),
                                            NVM_ISOLATION_PAYLOAD_B, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Client B reads id=5: gets ITS OWN value */
    out_len = 0;
    memset(buf, 0, sizeof(buf));
    WH_TEST_RETURN_ON_FAIL(_nvmReadViaServer(
        client2, server2, shared_id, sizeof(buf), &out_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == sizeof(NVM_ISOLATION_PAYLOAD_B));
    WH_TEST_ASSERT_RETURN(memcmp(buf, NVM_ISOLATION_PAYLOAD_B,
                                 sizeof(NVM_ISOLATION_PAYLOAD_B)) == 0);

    /* Client A still sees ITS OWN value, not B's */
    out_len = 0;
    memset(buf, 0, sizeof(buf));
    WH_TEST_RETURN_ON_FAIL(_nvmReadViaServer(
        client1, server1, shared_id, sizeof(buf), &out_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == sizeof(NVM_ISOLATION_PAYLOAD_A));
    WH_TEST_ASSERT_RETURN(memcmp(buf, NVM_ISOLATION_PAYLOAD_A,
                                 sizeof(NVM_ISOLATION_PAYLOAD_A)) == 0);

    /* Cleanup: each client destroys its own */
    WH_TEST_RETURN_ON_FAIL(
        _nvmDestroyViaServer(client1, server1, shared_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(
        _nvmDestroyViaServer(client2, server2, shared_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("  NVM client isolation: PASS\n");
    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/*
 * List has two namespaces:
 *  - own       : startId without GLOBAL flag
 *  - global    : startId with WH_KEYID_CLIENT_GLOBAL_FLAG set
 *
 * Client A populates 2 own ids and 2 global ids. Each scan must visit only
 * the corresponding namespace.
 */
static int _testNvmGlobalNamespaceList(whClientContext* client1,
                                       whServerContext* server1,
                                       whClientContext* client2,
                                       whServerContext* server2)
{
    int32_t       out_rc           = 0;
    whNvmId       count            = 0;
    whNvmId       cur              = 0;
    int           seen_own[256]    = {0};
    int           seen_global[256] = {0};
    int           i;
    int           iters;
    const whNvmId own_ids[2]    = {3, 7};
    const whNvmId global_ids[2] = {2, 4};
    (void)server2;
    (void)client2;

    WH_TEST_PRINT("Testing NVM list with global namespace...\n");

    /* Populate own ids */
    for (i = 0; i < 2; i++) {
        WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(
            client1, server1, own_ids[i], sizeof(NVM_ISOLATION_PAYLOAD_A),
            NVM_ISOLATION_PAYLOAD_A, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    }

    /* Populate global ids */
    for (i = 0; i < 2; i++) {
        WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(
            client1, server1, global_ids[i] | WH_KEYID_CLIENT_GLOBAL_FLAG,
            sizeof(NVM_ISOLATION_PAYLOAD_B), NVM_ISOLATION_PAYLOAD_B, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    }

    /* Iterate own namespace (no flag on startId). Expect ids in own_ids.
     * Cap iterations to defend against an unintentional infinite loop. */
    cur = 0;
    for (iters = 0; iters < 16; iters++) {
        WH_TEST_RETURN_ON_FAIL(
            _nvmListViaServer(client1, server1, cur, &out_rc, &count, &cur));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        if (count == 0) {
            break;
        }
        /* Must not carry the GLOBAL flag */
        WH_TEST_ASSERT_RETURN((cur & WH_KEYID_CLIENT_GLOBAL_FLAG) == 0);
        WH_TEST_ASSERT_RETURN((cur & WH_KEYID_MASK) <= WH_KEYID_IDMAX);
        seen_own[cur & WH_KEYID_MASK] = 1;
        if (count == 1) {
            break;
        }
    }
    WH_TEST_ASSERT_RETURN(iters < 16);

    /* Iterate global namespace (GLOBAL flag on startId). Expect ids in
     * global_ids, all returned with GLOBAL flag set. */
    cur = WH_KEYID_CLIENT_GLOBAL_FLAG;
    for (iters = 0; iters < 16; iters++) {
        WH_TEST_RETURN_ON_FAIL(
            _nvmListViaServer(client1, server1, cur, &out_rc, &count, &cur));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        if (count == 0) {
            break;
        }
        WH_TEST_ASSERT_RETURN((cur & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0);
        seen_global[cur & WH_KEYID_MASK] = 1;
        if (count == 1) {
            break;
        }
    }
    WH_TEST_ASSERT_RETURN(iters < 16);

    for (i = 0; i < 2; i++) {
        WH_TEST_ASSERT_RETURN(seen_own[own_ids[i]] == 1);
        WH_TEST_ASSERT_RETURN(seen_global[global_ids[i]] == 1);
    }
    /* Crosscheck: globals never appear in the own scan and vice-versa */
    WH_TEST_ASSERT_RETURN(seen_own[global_ids[0]] == 0);
    WH_TEST_ASSERT_RETURN(seen_own[global_ids[1]] == 0);
    WH_TEST_ASSERT_RETURN(seen_global[own_ids[0]] == 0);
    WH_TEST_ASSERT_RETURN(seen_global[own_ids[1]] == 0);

    /* Cleanup */
    for (i = 0; i < 2; i++) {
        WH_TEST_RETURN_ON_FAIL(
            _nvmDestroyViaServer(client1, server1, own_ids[i], &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(_nvmDestroyViaServer(
            client1, server1, global_ids[i] | WH_KEYID_CLIENT_GLOBAL_FLAG,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    }

    WH_TEST_PRINT("  NVM global namespace list: PASS\n");
    return WH_ERROR_OK;
}

#else  /* !WOLFHSM_CFG_GLOBAL_KEYS */

/*
 * Without global keys there is no global namespace: AddObject must reject
 * the GLOBAL flag and the other verbs must ignore it, resolving to the
 * caller's own namespace. USER=0 objects (e.g. provisioned by whnvmtool)
 * must stay unreachable, including via List.
 */
static int _testNvmGlobalFlagDisabled(whClientContext* client1,
                                      whServerContext* server1,
                                      whClientContext* client2,
                                      whServerContext* server2)
{
    const whNvmId own_id     = 3;
    const whNvmId planted_id = 6;
    whNvmId       planted_nvm_id;
    whNvmMetadata meta    = {0};
    int32_t       out_rc  = 0;
    whNvmId       count   = 0;
    whNvmId       cur     = 0;
    whNvmSize     out_len = 0;
    uint8_t       buf[64] = {0};

    (void)client2;
    (void)server2;

    WH_TEST_PRINT("Testing NVM GLOBAL flag with global keys disabled...\n");

    /* Plant a USER=0 object directly, as provisioning would */
    planted_nvm_id =
        WH_MAKE_KEYID(WH_KEYTYPE_NVM, WH_KEYUSER_GLOBAL, planted_id);
    meta.id     = planted_nvm_id;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONE;
    meta.len    = sizeof(NVM_ISOLATION_PAYLOAD_B);
    WH_TEST_ASSERT_RETURN(
        wh_Nvm_AddObject(server1->nvm, &meta, sizeof(NVM_ISOLATION_PAYLOAD_B),
                         NVM_ISOLATION_PAYLOAD_B) == WH_ERROR_OK);

    /* AddObject with the GLOBAL flag fails loudly */
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(
        client1, server1, 5 | WH_KEYID_CLIENT_GLOBAL_FLAG,
        sizeof(NVM_ISOLATION_PAYLOAD_A), NVM_ISOLATION_PAYLOAD_A, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_BADARGS);

    /* Add an own object without the flag */
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(client1, server1, own_id,
                                            sizeof(NVM_ISOLATION_PAYLOAD_A),
                                            NVM_ISOLATION_PAYLOAD_A, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* A GLOBAL-flagged List ignores the flag: it walks the caller's own
     * namespace and never surfaces the planted USER=0 object */
    cur = WH_KEYID_CLIENT_GLOBAL_FLAG;
    WH_TEST_RETURN_ON_FAIL(
        _nvmListViaServer(client1, server1, cur, &out_rc, &count, &cur));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(count == 1);
    WH_TEST_ASSERT_RETURN(cur == own_id);

    /* Read ignores the flag the same way: it resolves to the own object */
    WH_TEST_RETURN_ON_FAIL(_nvmReadViaServer(
        client1, server1, own_id | WH_KEYID_CLIENT_GLOBAL_FLAG, sizeof(buf),
        &out_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == sizeof(NVM_ISOLATION_PAYLOAD_A));
    WH_TEST_ASSERT_RETURN(memcmp(buf, NVM_ISOLATION_PAYLOAD_A, out_len) == 0);

    /* The planted USER=0 object is not reachable via the flag */
    WH_TEST_RETURN_ON_FAIL(_nvmGetMetadataViaServer(
        client1, server1, planted_id | WH_KEYID_CLIENT_GLOBAL_FLAG, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc != WH_ERROR_OK);

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(
        _nvmDestroyViaServer(client1, server1, own_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(
        wh_Nvm_DestroyObjects(server1->nvm, 1, &planted_nvm_id) == WH_ERROR_OK);

    WH_TEST_PRINT("  NVM GLOBAL flag disabled semantics: PASS\n");
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/*
 * Reject malformed AddObject requests:
 *  - id portion == 0 (erased sentinel)
 *  - wrapped flag set
 */
static int _testNvmAddObjectRejections(whClientContext* client1,
                                       whServerContext* server1,
                                       whClientContext* client2,
                                       whServerContext* server2)
{
    int32_t out_rc = 0;
    (void)server2;
    (void)client2;

    WH_TEST_PRINT("Testing NVM AddObject bad-id rejections...\n");

    /* id=0 with own scope */
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(client1, server1, 0, 4,
                                            (const uint8_t*)"data", &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc != WH_ERROR_OK);

    /* id=0 with global scope */
    out_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(client1, server1,
                                            WH_KEYID_CLIENT_GLOBAL_FLAG, 4,
                                            (const uint8_t*)"data", &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc != WH_ERROR_OK);

    /* wrapped flag set */
    out_rc = 0;
    WH_TEST_RETURN_ON_FAIL(_nvmAddViaServer(client1, server1,
                                            5 | WH_KEYID_CLIENT_WRAPPED_FLAG, 4,
                                            (const uint8_t*)"data", &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc != WH_ERROR_OK);

    WH_TEST_PRINT("  NVM AddObject rejections: PASS\n");
    return WH_ERROR_OK;
}

/*
 * The WRAPPED and HW client flags must not let the NVM API reach a
 * differently-typed object. Plant a WRAPPED-typed and an HW-typed object in
 * client1's own namespace at numeric id 9, then confirm the client NVM
 * read/getmetadata/destroy verbs cannot touch them via those flags.
 */
static int _testNvmWrappedHwFlagIsolation(whClientContext* client1,
                                          whServerContext* server1,
                                          whClientContext* client2,
                                          whServerContext* server2)
{
    const whNvmId   planted_id     = 9;
    const uint8_t   secret[]       = "planted-non-nvm-secret";
    const whNvmSize secretSz       = (whNvmSize)sizeof(secret);
    const whKeyId   clientFlags[2] = {WH_KEYID_CLIENT_WRAPPED_FLAG,
                                      WH_KEYID_CLIENT_HW_FLAG};
    int32_t         out_rc         = 0;
    whNvmSize       out_len        = 0;
    uint8_t         buf[64]        = {0};
    whNvmMetadata   meta           = {0};
    whKeyId         wrappedId;
    whKeyId         hwId;
    int             i;

    (void)client2;
    (void)server2;

    WH_TEST_PRINT("Testing NVM WRAPPED/HW flag type isolation...\n");

    wrappedId =
        WH_MAKE_KEYID(WH_KEYTYPE_WRAPPED, server1->comm->client_id, planted_id);
    hwId = WH_MAKE_KEYID(WH_KEYTYPE_HW, server1->comm->client_id, planted_id);

    /* Plant the two forbidden objects directly in the shared store. */
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONE;
    meta.len    = secretSz;
    meta.id     = wrappedId;
    WH_TEST_ASSERT_RETURN(
        wh_Nvm_AddObject(server1->nvm, &meta, secretSz, secret) == WH_ERROR_OK);
    meta.id = hwId;
    WH_TEST_ASSERT_RETURN(
        wh_Nvm_AddObject(server1->nvm, &meta, secretSz, secret) == WH_ERROR_OK);

    for (i = 0; i < 2; i++) {
        whNvmId flagged = (whNvmId)(planted_id | clientFlags[i]);

        /* Read: must not return the planted bytes. With the flag stripped this
         * resolves to a nonexistent NVM object 9 and fails. */
        memset(buf, 0, sizeof(buf));
        out_rc = 0;
        WH_TEST_RETURN_ON_FAIL(_nvmReadViaServer(
            client1, server1, flagged, secretSz, &out_rc, &out_len, buf));
        WH_TEST_ASSERT_RETURN(out_rc != WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(memcmp(buf, secret, secretSz) != 0);

        /* GetMetadata: must not surface the planted object. */
        out_rc = 0;
        WH_TEST_RETURN_ON_FAIL(
            _nvmGetMetadataViaServer(client1, server1, flagged, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc != WH_ERROR_OK);

        /* Destroy: must not reach the planted object. */
        out_rc = 0;
        WH_TEST_RETURN_ON_FAIL(
            _nvmDestroyViaServer(client1, server1, flagged, &out_rc));
    }

    /* Both planted objects must still exist after the flagged destroys. */
    WH_TEST_ASSERT_RETURN(wh_Nvm_GetMetadata(server1->nvm, wrappedId, &meta) ==
                          WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(wh_Nvm_GetMetadata(server1->nvm, hwId, &meta) ==
                          WH_ERROR_OK);

    /* Clean up the planted objects. */
    (void)wh_Nvm_DestroyObjects(server1->nvm, 1, &wrappedId);
    (void)wh_Nvm_DestroyObjects(server1->nvm, 1, &hwId);

    WH_TEST_PRINT("  NVM WRAPPED/HW flag isolation: PASS\n");
    return WH_ERROR_OK;
}

static int _runNvmIdTranslationTests(whClientContext* client1,
                                     whServerContext* server1,
                                     whClientContext* client2,
                                     whServerContext* server2)
{
    WH_TEST_PRINT("=== NVM Id Translation Tests Begin ===\n");
    WH_TEST_RETURN_ON_FAIL(
        _testNvmClientIsolation(client1, server1, client2, server2));
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    WH_TEST_RETURN_ON_FAIL(
        _testNvmGlobalNamespaceList(client1, server1, client2, server2));
#else
    WH_TEST_RETURN_ON_FAIL(
        _testNvmGlobalFlagDisabled(client1, server1, client2, server2));
#endif
    WH_TEST_RETURN_ON_FAIL(
        _testNvmAddObjectRejections(client1, server1, client2, server2));
    WH_TEST_RETURN_ON_FAIL(
        _testNvmWrappedHwFlagIsolation(client1, server1, client2, server2));
    WH_TEST_PRINT("All NVM Id Translation Tests PASSED ===\n");
    return WH_ERROR_OK;
}

#endif /* !WOLFHSM_CFG_LEGACY_CLIENT_NVM */

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

#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
    WH_TEST_RETURN_ON_FAIL(
        _runNvmIdTranslationTests(client1, server1, client2, server2));
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

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLF_CRYPTO_CB)

/* ============================================================================
 * CLIENT DEVID REGISTRATION LIFECYCLE
 *
 * wh_Client_Init registers the client's devIds in wolfCrypt's process-global,
 * fixed-size cryptoCb table and wh_Client_Cleanup must unregister them: the
 * table is only reset when the last wolfCrypt user in the process cleans up,
 * so a leaked entry both consumes a table slot and keeps dispatching into the
 * dead client context. Every Init rebinds the global WH_DEV_ID (and
 * WH_DEV_ID_DMA with DMA) to its own context and additionally registers the
 * configured devId when it differs from WH_DEV_ID; any client's Cleanup
 * unregisters the globals. These tests observe table occupancy through the
 * only public accessors (Register/UnRegister) by counting how many throwaway
 * registrations fit before the table is full.
 * ========================================================================== */

/* Throwaway devId base for probing free cryptoCb table slots ("WHT\0"+i).
 * Outside the global devIds (WH_DEV_ID / WH_DEV_ID_DMA), the custom test
 * devIds, and the fill range below. */
#define PROBE_DEV_ID_BASE 0x57485400
/* Upper bound on probed slots. Must be >= wolfCrypt's
 * MAX_CRYPTO_DEVID_CALLBACKS (internal to cryptocb.c; default 8). */
#define PROBE_MAX_SLOTS 128

/* Separate devId base ("WHU\0"+i) for table-fill entries that stay
 * registered while _countFreeCryptoCbSlots() runs: wolfCrypt re-registration
 * of an existing devId reuses its entry, so fill ids must never collide with
 * the probe ids or the count comes back wrong (and the counter's
 * unregistration pass would tear the fill entries down). */
#define FILL_DEV_ID_BASE 0x57485500

/* Global devIds rebound by every wh_Client_Init: WH_DEV_ID, plus
 * WH_DEV_ID_DMA when DMA support is compiled in. Their table slots are
 * shared by all clients in the process (each Init rebinds the same
 * entries). */
#ifdef WOLFHSM_CFG_DMA
#define GLOBAL_DEVID_COUNT 2
#else
#define GLOBAL_DEVID_COUNT 1
#endif

/* Slots consumed by one wh_Client_Init with a custom (non-default) devId on
 * an otherwise unoccupied table: the globals plus the configured devId */
#define DEVIDS_PER_INIT (GLOBAL_DEVID_COUNT + 1)

/* Custom per-client devIds for the two-client cases ("WH"+n). Distinct from
 * WH_DEV_ID, WH_DEV_ID_DMA, and the probe range. */
#define TEST_DEVID_1 0x57480001
#define TEST_DEVID_2 0x57480002

static int _probeCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)info;
    (void)ctx;
    return CRYPTOCB_UNAVAILABLE;
}

/* Count free slots in the cryptoCb table by registering throwaway devIds
 * until registration fails, then unregistering them all. */
static int _countFreeCryptoCbSlots(void)
{
    int count = 0;
    int i;

    for (i = 0; i < PROBE_MAX_SLOTS; i++) {
        if (wc_CryptoCb_RegisterDevice(PROBE_DEV_ID_BASE + i, _probeCryptoCb,
                                       NULL) != 0) {
            break;
        }
        count++;
    }
    for (i = 0; i < count; i++) {
        wc_CryptoCb_UnRegisterDevice(PROBE_DEV_ID_BASE + i);
    }
    return count;
}

static int whTest_MultiClientDevIdLifecycle(void)
{
    int slotsBase = 0;
    int slots     = 0;
    int rc        = 0;
    int i         = 0;

    /* Client transports: no servers needed, registration lifecycle only */
    static uint8_t       req1[BUFFER_SIZE];
    static uint8_t       resp1[BUFFER_SIZE];
    whTransportMemConfig tmcf1[1] = {{
        .req       = (whTransportMemCsr*)req1,
        .req_size  = sizeof(req1),
        .resp      = (whTransportMemCsr*)resp1,
        .resp_size = sizeof(resp1),
    }};

    whTransportClientCb         tccb1[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc1[1]    = {0};
    whCommClientConfig          cc_conf1[1] = {{
                 .transport_cb      = tccb1,
                 .transport_context = (void*)tmcc1,
                 .transport_config  = (void*)tmcf1,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientContext             client1[1]  = {0};
    whClientConfig              c_conf1[1]  = {{
                      .comm = cc_conf1,
    }};

    static uint8_t       req2[BUFFER_SIZE];
    static uint8_t       resp2[BUFFER_SIZE];
    whTransportMemConfig tmcf2[1] = {{
        .req       = (whTransportMemCsr*)req2,
        .req_size  = sizeof(req2),
        .resp      = (whTransportMemCsr*)resp2,
        .resp_size = sizeof(resp2),
    }};

    whTransportClientCb         tccb2[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc2[1]    = {0};
    whCommClientConfig          cc_conf2[1] = {{
                 .transport_cb      = tccb2,
                 .transport_context = (void*)tmcc2,
                 .transport_config  = (void*)tmcf2,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID + 1,
    }};
    whClientContext             client2[1]  = {0};
    whClientConfig              c_conf2[1]  = {{
                      .comm = cc_conf2,
    }};

    WH_TEST_PRINT("=== Multi-Client DevId Lifecycle Tests Begin ===\n");

    /* Client ids outside 1..WH_CLIENT_ID_MAX are rejected before any
     * initialization */
    cc_conf1[0].client_id = 0;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
    cc_conf1[0].client_id = WH_CLIENT_ID_MAX + 1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
    cc_conf1[0].client_id = WH_TEST_DEFAULT_CLIENT_ID;

    /* Negative devIds and (with DMA) the reserved WH_DEV_ID_DMA are
     * rejected before any initialization */
    c_conf1[0].devId = -1;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
#ifdef WOLFHSM_CFG_DMA
    c_conf1[0].devId = WH_DEV_ID_DMA;
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS == wh_Client_Init(client1, c_conf1));
#endif /* WOLFHSM_CFG_DMA */
    c_conf1[0].devId = 0;

    /* Hold an app-level wolfCrypt reference for the whole test so the
     * cryptoCb table is never reset by a final wolfCrypt_Cleanup: any entry
     * a client leaks stays visible, as it would in a process with other
     * active wolfCrypt users. */
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());

    slotsBase = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slotsBase >= GLOBAL_DEVID_COUNT + 2);

    /* A config that leaves devId 0 binds the default WH_DEV_ID; only the
     * global devIds occupy table slots */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client1) == WH_DEV_ID);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - GLOBAL_DEVID_COUNT);

    /* Cleanup must release every slot Init consumed even though wolfCrypt
     * stays initialized (the app still holds a reference) */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);

    /* Re-init with the same config must succeed and register again */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - GLOBAL_DEVID_COUNT);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);

    /* A custom configured devId is registered alongside the globals */
    c_conf1[0].devId = TEST_DEVID_1;
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client1) == TEST_DEVID_1);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - DEVIDS_PER_INIT);

    /* Two simultaneously active clients with distinct devIds: the second
     * Init rebinds the shared global entries (net zero new slots) and adds
     * only its own devId */
    c_conf2[0].devId = TEST_DEVID_2;
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client2, c_conf2));
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client2) == TEST_DEVID_2);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - DEVIDS_PER_INIT - 1);

    /* Cleaning up one client releases its own devId and the shared global
     * devIds -- the globals are yanked from the still-active sibling, which
     * is the documented single-client contract for WH_DEV_ID/WH_DEV_ID_DMA.
     * The sibling's own configured devId stays registered. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - 1);

    /* Re-init the first client while the second stays active: the globals
     * are rebound and both custom devIds are live again */
    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client1, c_conf1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - DEVIDS_PER_INIT - 1);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client2));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase - 1);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client1));
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);
    c_conf1[0].devId = 0;
    c_conf2[0].devId = 0;

    /* Init with a full cryptoCb table must fail cleanly (WH_ERROR_ABORTED)
     * and the failure-path cleanup must not disturb existing entries */
    for (i = 0; i < slotsBase; i++) {
        WH_TEST_RETURN_ON_FAIL(wc_CryptoCb_RegisterDevice(
            FILL_DEV_ID_BASE + i, _probeCryptoCb, NULL));
    }
    rc = wh_Client_Init(client1, c_conf1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(WH_CLIENT_DEVID(client1) == 0);
    for (i = 0; i < slotsBase; i++) {
        wc_CryptoCb_UnRegisterDevice(FILL_DEV_ID_BASE + i);
    }
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);

    /* Init that fails partway through its registrations (the custom devId
     * fits, but a later global rebind hits the full table) must unwind
     * exactly the entries it registered and leave the fill entries intact */
    for (i = 0; i < slotsBase - (DEVIDS_PER_INIT - 1); i++) {
        WH_TEST_RETURN_ON_FAIL(wc_CryptoCb_RegisterDevice(
            FILL_DEV_ID_BASE + i, _probeCryptoCb, NULL));
    }
    c_conf1[0].devId = TEST_DEVID_1;
    rc               = wh_Client_Init(client1, c_conf1);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == DEVIDS_PER_INIT - 1);
    for (i = 0; i < slotsBase - (DEVIDS_PER_INIT - 1); i++) {
        wc_CryptoCb_UnRegisterDevice(FILL_DEV_ID_BASE + i);
    }
    slots = _countFreeCryptoCbSlots();
    WH_TEST_ASSERT_RETURN(slots == slotsBase);
    c_conf1[0].devId = 0;

    (void)wolfCrypt_Cleanup();

    WH_TEST_PRINT("=== Multi-Client DevId Lifecycle Tests Complete ===\n");
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLF_CRYPTO_CB */

/* ============================================================================
 * PUBLIC API
 * ========================================================================== */

/* Main entry point for multi-client tests */
int whTest_MultiClient(void)
{
    WH_TEST_RETURN_ON_FAIL(whTest_MultiClientSequential());
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLF_CRYPTO_CB)
    WH_TEST_RETURN_ON_FAIL(whTest_MultiClientDevIdLifecycle());
#endif
    return 0;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
