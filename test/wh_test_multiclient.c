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

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wh_test_common.h"

/* Test configuration */
#define FLASH_RAM_SIZE (1024 * 1024)   /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8)            /* 8B */
#define BUFFER_SIZE 4096

/* Test key data */
static const uint8_t TEST_KEY_DATA_1[] = "TestGlobalKey1Data";
static const uint8_t TEST_KEY_DATA_2[] = "TestLocalKey2Data";
static const uint8_t TEST_KEY_DATA_3[] = "TestGlobalKey3DataLonger";

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

/* Test 1: Basic global key operations */
static int _testGlobalKeyBasic(whClientContext* client1,
                               whServerContext* server1,
                               whClientContext* client2,
                               whServerContext* server2)
{
    int      ret;
    whKeyId  keyId = WH_MAKE_KEYID_GLOBAL(5);
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz                         = sizeof(label);
    uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
    uint16_t outSz                           = sizeof(outBuf);

    printf("Test: Global key basic operations\n");

    /* Client 1 caches a global key */
    printf("About to cache global key with keyId=%u\n", keyId);
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"GlobalKey5", sizeof("GlobalKey5"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId));
    printf("Handling server request...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    printf("Getting cache response...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    printf("  Client 1 cached global key ID %d\n", keyId);

    /* Client 2 reads the same global key - recreate the global keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(5);
    printf("Client 2 exporting global key with keyId=%u\n", keyId);
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    printf("Server2 handling export request...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    printf("Client2 getting export response...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));

    /* Verify the key data matches */
    WH_TEST_ASSERT_RETURN(outSz == sizeof(TEST_KEY_DATA_1));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outBuf, TEST_KEY_DATA_1, outSz));

    printf("  Client 2 successfully read global key\n");
    printf("  PASS: Basic global key operations\n\n");

    (void)ret;
    return 0;
}

/* Test 2: Local key isolation */
static int _testLocalKeyIsolation(whClientContext* client1,
                                  whServerContext* server1,
                                  whClientContext* client2,
                                  whServerContext* server2)
{
    int      ret;
    whKeyId  keyId1 = 10; /* Local key for client 1 */
    whKeyId  keyId2 = 10; /* Same ID for client 2 - should be different key */
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz    = sizeof(label);
    uint8_t  outBuf[32] = {0};
    uint16_t outSz;

    printf("Test: Local key isolation\n");

    /* Client 1 caches a local key with ID 10 */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"LocalKey10_C1", sizeof("LocalKey10_C1"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId1));

    printf("  Client 1 cached local key ID %d\n", keyId1);

    /* Client 2 caches a different local key with same ID 10 */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client2, 0, (uint8_t*)"LocalKey10_C2", sizeof("LocalKey10_C2"),
        (uint8_t*)TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2), keyId2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client2, &keyId2));

    printf("  Client 2 cached local key ID %d\n", keyId2);

    /* Client 1 reads its own key */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client1, keyId1));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client1, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    printf("  Client 1 read its own local key successfully\n");

    /* Client 2 reads its own key (different data) */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId2));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_2, sizeof(TEST_KEY_DATA_2)));

    printf("  Client 2 read its own local key successfully (different data)\n");
    printf("  PASS: Local key isolation\n\n");

    (void)ret;
    return 0;
}

/* Test 3: Mixed global and local keys */
static int _testMixedGlobalLocal(whClientContext* client1,
                                 whServerContext* server1,
                                 whClientContext* client2,
                                 whServerContext* server2)
{
    int      ret;
    whKeyId  globalKeyId = WH_MAKE_KEYID_GLOBAL(15);
    whKeyId  localKeyId  = 15; /* Same ID number but local */
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz    = sizeof(label);
    uint8_t  outBuf[32] = {0};
    uint16_t outSz;

    printf("Test: Mixed global and local keys\n");

    /* Client 1 caches global key 15 */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"Global15", sizeof("Global15"),
        (uint8_t*)TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3), globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &globalKeyId));

    printf("  Client 1 cached global key 15\n");

    /* Client 1 caches local key 15 */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"Local15_C1", sizeof("Local15_C1"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &localKeyId));

    printf("  Client 1 cached local key 15\n");

    /* Client 2 accesses global key 15 (should work) - recreate the global keyId
     */
    globalKeyId = WH_MAKE_KEYID_GLOBAL(15);
    outSz       = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3)));

    printf("  Client 2 read global key 15 successfully\n");

    /* Client 2 tries to access client 1's local key 15 - should fail or get
     * empty */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    ret = wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz);
    /* Should fail because client 2 doesn't have local key 15 */
    WH_TEST_ASSERT_RETURN(ret != 0);

    printf("  Client 2 correctly cannot access Client 1's local key 15\n");
    printf("  PASS: Mixed global and local keys\n\n");

    return 0;
}

/* Test 4: NVM persistence of global keys */
static int _testGlobalKeyNvmPersistence(whClientContext* client1,
                                        whServerContext* server1,
                                        whClientContext* client2,
                                        whServerContext* server2)
{
    int      ret;
    whKeyId  keyId = WH_MAKE_KEYID_GLOBAL(20);
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz                         = sizeof(label);
    uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
    uint16_t outSz;

    printf("Test: NVM persistence of global keys\n");

    /* Client 1 caches and commits a global key to NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"GlobalNVM20", sizeof("GlobalNVM20"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    /* Commit to NVM - recreate the global keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(20);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommitRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommitResponse(client1));

    printf("  Client 1 cached and committed global key to NVM\n");

    /* Evict from cache on server1 - recreate the global keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(20);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    printf("  Evicted key from cache\n");

    /* Client 2 reads from NVM (will reload to cache) - recreate the global
     * keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(20);
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    printf("  Client 2 successfully loaded global key from NVM\n");

    /* Clean up - erase the key - recreate the global keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(20);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEraseRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEraseResponse(client1));

    printf("  PASS: NVM persistence of global keys\n\n");

    (void)ret;
    return 0;
}

/* Test 5: Export protection on global keys */
static int _testGlobalKeyExportProtection(whClientContext* client1,
                                          whServerContext* server1,
                                          whClientContext* client2,
                                          whServerContext* server2)
{
    int      ret;
    whKeyId  keyId = WH_MAKE_KEYID_GLOBAL(25);
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz                         = sizeof(label);
    uint8_t  outBuf[sizeof(TEST_KEY_DATA_1)] = {0};
    uint16_t outSz;

    printf("Test: Export protection on global keys\n");

    /* Client 1 caches a non-exportable global key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, WH_NVM_FLAGS_NONEXPORTABLE, (uint8_t*)"NoExport25",
        sizeof("NoExport25"), (uint8_t*)TEST_KEY_DATA_1,
        sizeof(TEST_KEY_DATA_1), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    printf("  Client 1 cached non-exportable global key\n");

    /* Client 2 tries to export it - should fail - recreate the global keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(25);
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    ret = wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz);
    /* Should fail due to non-exportable flag */
    WH_TEST_ASSERT_RETURN(ret != 0);

    printf("  Client 2 correctly blocked from exporting non-exportable key\n");

    /* Clean up - recreate the global keyId */
    keyId = WH_MAKE_KEYID_GLOBAL(25);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    printf("  PASS: Export protection on global keys\n\n");

    return 0;
}

/* Test 6: No cross-cache interference */
static int _testNoCrossCacheInterference(whClientContext* client1,
                                         whServerContext* server1,
                                         whClientContext* client2,
                                         whServerContext* server2)
{
    int      ret;
    whKeyId  globalKeyId = WH_MAKE_KEYID_GLOBAL(30);
    whKeyId  localKeyId  = 30;
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz    = sizeof(label);
    uint8_t  outBuf[32] = {0};
    uint16_t outSz;

    printf("Test: No cross-cache interference\n");

    /* Client 1 caches key 30 as global */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"Global30", sizeof("Global30"),
        (uint8_t*)TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3), globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &globalKeyId));

    printf("  Client 1 cached global key 30\n");

    /* Client 2 caches key 30 as local */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client2, 0, (uint8_t*)"Local30_C2", sizeof("Local30_C2"),
        (uint8_t*)TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1), localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client2, &localKeyId));

    printf("  Client 2 cached local key 30\n");

    /* Client 1 reads global key 30 - recreate the global keyId */
    globalKeyId = WH_MAKE_KEYID_GLOBAL(30);
    outSz       = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client1, globalKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client1, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_3, sizeof(TEST_KEY_DATA_3)));

    printf("  Client 1 correctly read global key 30\n");

    /* Client 2 reads local key 30 */
    outSz = sizeof(outBuf);
    memset(outBuf, 0, sizeof(outBuf));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, localKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(outBuf, TEST_KEY_DATA_1, sizeof(TEST_KEY_DATA_1)));

    printf("  Client 2 correctly read local key 30 (different data)\n");
    printf("  PASS: No cross-cache interference\n\n");

    (void)ret;
    return 0;
}

#ifdef WOLFHSM_CFG_DMA
/* Test 7: DMA cache with global keys */
static int _testGlobalKeyDmaCache(whClientContext* client1,
                                  whServerContext* server1,
                                  whClientContext* client2,
                                  whServerContext* server2)
{
    int      ret;
    whKeyId  keyId       = WH_MAKE_KEYID_GLOBAL(35);
    uint8_t  keyData[32] = "GlobalDmaCacheTestKey123456!";
    uint8_t  outBuf[32]  = {0};
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz = sizeof(label);
    uint16_t outSz   = sizeof(outBuf);

    printf("Test: DMA cache with global keys\n");

    /* Client 1 caches a global key using DMA */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheDmaRequest(
        client1, 0, (uint8_t*)"DmaGlobal35", sizeof("DmaGlobal35"), keyData,
        sizeof(keyData), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheDmaResponse(client1, &keyId));

    printf("  Client 1 cached global key via DMA\n");

    /* Client 2 reads the global key via regular export */
    keyId = WH_MAKE_KEYID_GLOBAL(35);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportResponse(client2, label, labelSz, outBuf, &outSz));

    /* Verify the key data matches */
    WH_TEST_ASSERT_RETURN(outSz == sizeof(keyData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outBuf, keyData, outSz));

    printf("  Client 2 successfully read DMA-cached global key\n");

    /* Clean up */
    keyId = WH_MAKE_KEYID_GLOBAL(35);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    printf("  PASS: DMA cache with global keys\n\n");

    (void)ret;
    return 0;
}

/* Test 8: DMA export with global keys */
static int _testGlobalKeyDmaExport(whClientContext* client1,
                                   whServerContext* server1,
                                   whClientContext* client2,
                                   whServerContext* server2)
{
    int      ret;
    whKeyId  keyId       = WH_MAKE_KEYID_GLOBAL(40);
    uint8_t  keyData[32] = "GlobalDmaExportTestKey12345!";
    uint8_t  outBuf[32]  = {0};
    uint8_t  label[WH_NVM_LABEL_LEN];
    uint16_t labelSz = sizeof(label);
    uint16_t outSz   = sizeof(outBuf);

    printf("Test: DMA export with global keys\n");

    /* Client 1 caches a global key using regular method */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"DmaExport40", sizeof("DmaExport40"), keyData,
        sizeof(keyData), keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &keyId));

    printf("  Client 1 cached global key\n");

    /* Client 2 exports the global key via DMA */
    keyId = WH_MAKE_KEYID_GLOBAL(40);
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportDmaRequest(client2, keyId, outBuf, sizeof(outBuf)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportDmaResponse(client2, label, labelSz, &outSz));

    /* Verify the key data matches */
    WH_TEST_ASSERT_RETURN(outSz == sizeof(keyData));
    WH_TEST_ASSERT_RETURN(0 == memcmp(outBuf, keyData, outSz));

    printf("  Client 2 successfully exported global key via DMA\n");

    /* Clean up */
    keyId = WH_MAKE_KEYID_GLOBAL(40);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, keyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    printf("  PASS: DMA export with global keys\n\n");

    (void)ret;
    return 0;
}
#endif /* WOLFHSM_CFG_DMA */

#ifdef WOLFHSM_CFG_KEYWRAP
/* Test 9: Key wrap with global server key */
static int _testGlobalKeyWrap(whClientContext* client1,
                              whServerContext* server1,
                              whClientContext* client2,
                              whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId                = WH_MAKE_KEYID_GLOBAL(45);
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "GlobalWrapKey123456789012345!";
    uint8_t plainKey[AES_256_KEY_SIZE] = "PlainKeyToWrap1234567890123!";
    /* Wrapped key size = IV(12) + TAG(16) + KEYSIZE(32) + metadata */
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE]   = {0};
    uint8_t       unwrappedKey[AES_256_KEY_SIZE] = {0};
    whNvmMetadata meta                           = {0};

    printf("Test: Key wrap with global server key\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"WrapKey45", sizeof("WrapKey45"), wrapKey,
        sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    printf("  Client 1 cached global wrapping key\n");

    /* Client 2 wraps a key using the global server key */
    serverKeyId = WH_MAKE_KEYID_GLOBAL(45);
    meta.id     = WH_KEYID_ERASED;
    meta.len    = sizeof(plainKey);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client2, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client2, WC_CIPHER_AES_GCM, wrappedKey, sizeof(wrappedKey)));

    printf("  Client 2 wrapped key using global server key\n");

    /* Client 1 unwraps the key using the same global server key */
    serverKeyId = WH_MAKE_KEYID_GLOBAL(45);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportRequest(
        client1, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndExportResponse(
        client1, WC_CIPHER_AES_GCM, &meta, unwrappedKey, sizeof(unwrappedKey)));

    /* Verify the unwrapped key matches the original */
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(unwrappedKey, plainKey, sizeof(plainKey)));

    printf("  Client 1 successfully unwrapped key using global server key\n");

    /* Clean up */
    serverKeyId = WH_MAKE_KEYID_GLOBAL(45);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    printf("  PASS: Key wrap with global server key\n\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}

/* Test 10: Key unwrap and cache with global server key */
static int _testGlobalKeyUnwrapCache(whClientContext* client1,
                                     whServerContext* server1,
                                     whClientContext* client2,
                                     whServerContext* server2)
{
    int     ret;
    whKeyId serverKeyId                = WH_MAKE_KEYID_GLOBAL(50);
    whKeyId cachedKeyId                = 0;
    uint8_t wrapKey[AES_256_KEY_SIZE]  = "GlobalUnwrapKey123456789012!";
    uint8_t plainKey[AES_256_KEY_SIZE] = "KeyToCacheViaUnwrap123456!!";
#define WRAPPED_KEY_SIZE (12 + 16 + AES_256_KEY_SIZE + sizeof(whNvmMetadata))
    uint8_t       wrappedKey[WRAPPED_KEY_SIZE] = {0};
    uint8_t       verifyBuf[AES_256_KEY_SIZE]  = {0};
    uint8_t       label[WH_NVM_LABEL_LEN];
    uint16_t      labelSz  = sizeof(label);
    uint16_t      verifySz = sizeof(verifyBuf);
    whNvmMetadata meta     = {0};

    printf("Test: Key unwrap and cache with global server key\n");

    /* Client 1 caches a global wrapping key */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheRequest_ex(
        client1, 0, (uint8_t*)"UnwrapKey50", sizeof("UnwrapKey50"), wrapKey,
        sizeof(wrapKey), serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCacheResponse(client1, &serverKeyId));

    printf("  Client 1 cached global wrapping key\n");

    /* Client 1 wraps a key */
    serverKeyId = WH_MAKE_KEYID_GLOBAL(50);
    meta.id     = WH_KEYID_ERASED;
    meta.len    = sizeof(plainKey);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapRequest(client1, WC_CIPHER_AES_GCM,
                                                    serverKeyId, plainKey,
                                                    sizeof(plainKey), &meta));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyWrapResponse(
        client1, WC_CIPHER_AES_GCM, wrappedKey, sizeof(wrappedKey)));

    printf("  Client 1 wrapped key\n");

    /* Client 2 unwraps and caches the key using the global server key */
    serverKeyId = WH_MAKE_KEYID_GLOBAL(50);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheRequest(
        client2, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
        sizeof(wrappedKey)));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyUnwrapAndCacheResponse(
        client2, WC_CIPHER_AES_GCM, &cachedKeyId));

    printf("  Client 2 unwrapped and cached key\n");

    /* Verify the cached key by exporting it */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportRequest(client2, cachedKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportResponse(client2, label, labelSz,
                                                       verifyBuf, &verifySz));

    /* Verify the exported key matches the original */
    WH_TEST_ASSERT_RETURN(0 == memcmp(verifyBuf, plainKey, sizeof(plainKey)));

    printf("  Client 2 verified cached key matches original\n");

    /* Clean up */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client2, cachedKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server2));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client2));

    serverKeyId = WH_MAKE_KEYID_GLOBAL(50);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictRequest(client1, serverKeyId));
    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleRequestMessage(server1));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(client1));

    printf("  PASS: Key unwrap and cache with global server key\n\n");

    (void)ret;
    return 0;
#undef WRAPPED_KEY_SIZE
}
#endif /* WOLFHSM_CFG_KEYWRAP */

/* Helper function to run all global keys tests */
static int _runGlobalKeysTests(whClientContext* client1,
                               whServerContext* server1,
                               whClientContext* client2,
                               whServerContext* server2)
{
    printf("=== Running Global Keys Test Suite ===\n\n");

    printf("Running test 1: Global key basic operations...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyBasic(client1, server1, client2, server2));

    printf("Running test 2: Local key isolation...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testLocalKeyIsolation(client1, server1, client2, server2));

    printf("Running test 3: Mixed global and local keys...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testMixedGlobalLocal(client1, server1, client2, server2));

    printf("Running test 4: NVM persistence...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyNvmPersistence(client1, server1, client2, server2));

    printf("Running test 5: Export protection...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyExportProtection(client1, server1, client2, server2));

    printf("Running test 6: No cross-cache interference...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testNoCrossCacheInterference(client1, server1, client2, server2));

#ifdef WOLFHSM_CFG_DMA
    printf("Running test 7: DMA cache with global keys...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyDmaCache(client1, server1, client2, server2));

    printf("Running test 8: DMA export with global keys...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyDmaExport(client1, server1, client2, server2));
#endif

#ifdef WOLFHSM_CFG_KEYWRAP
    printf("Running test 9: Key wrap with global server key...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyWrap(client1, server1, client2, server2));

    printf("Running test 10: Key unwrap and cache with global server key...\n");
    fflush(stdout);
    WH_TEST_RETURN_ON_FAIL(
        _testGlobalKeyUnwrapCache(client1, server1, client2, server2));
#endif

    printf("=== All Global Keys Tests PASSED ===\n\n");
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

    printf("=== Multi-Client Sequential Test Setup ===\n\n");

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
    whServerCryptoContext crypto1[1] = {{.devId = INVALID_DEVID}};
    whServerCryptoContext crypto2[1] = {{.devId = INVALID_DEVID}};
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
    printf("Initializing wolfCrypt...\n");
    fflush(stdout);
    ret = wolfCrypt_Init();
    printf("wolfCrypt_Init returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;
#endif

    /* Initialize NVM (shared) */
    printf("Initializing NVM...\n");
    fflush(stdout);
    ret = wh_Nvm_Init(nvm, n_conf);
    printf("wh_Nvm_Init returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Initialize RNGs */
    printf("Initializing RNG1...\n");
    fflush(stdout);
    ret = wc_InitRng_ex(crypto1->rng, NULL, crypto1->devId);
    printf("wc_InitRng_ex(crypto1) returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;

    printf("Initializing RNG2...\n");
    fflush(stdout);
    ret = wc_InitRng_ex(crypto2->rng, NULL, crypto2->devId);
    printf("wc_InitRng_ex(crypto2) returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;
#endif

    /* Initialize servers */
    printf("Initializing server1...\n");
    fflush(stdout);
    ret = wh_Server_Init(server1, s_conf1);
    printf("wh_Server_Init(server1) returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;

    printf("Initializing server2...\n");
    fflush(stdout);
    ret = wh_Server_Init(server2, s_conf2);
    printf("wh_Server_Init(server2) returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;

    /* Initialize clients */
    printf("Initializing client1...\n");
    fflush(stdout);
    ret = wh_Client_Init(client1, c_conf1);
    printf("wh_Client_Init(client1) returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;

    printf("Initializing client2...\n");
    fflush(stdout);
    ret = wh_Client_Init(client2, c_conf2);
    printf("wh_Client_Init(client2) returned: %d\n", ret);
    fflush(stdout);
    if (ret != 0)
        return ret;

    /* Initialize communication for both clients */
    uint32_t client_id = 0;
    uint32_t server_id = 0;

    printf("Initializing comm for client1...\n");
    fflush(stdout);
    ret = wh_Client_CommInitRequest(client1);
    if (ret != 0)
        return ret;
    ret = wh_Server_HandleRequestMessage(server1);
    if (ret != 0)
        return ret;
    ret = wh_Client_CommInitResponse(client1, &client_id, &server_id);
    printf("wh_Client_CommInit for client1 returned: %d (client_id=%u, "
           "server_id=%u)\n",
           ret, client_id, server_id);
    fflush(stdout);
    if (ret != 0)
        return ret;

    printf("Initializing comm for client2...\n");
    fflush(stdout);
    ret = wh_Client_CommInitRequest(client2);
    if (ret != 0)
        return ret;
    ret = wh_Server_HandleRequestMessage(server2);
    if (ret != 0)
        return ret;
    ret = wh_Client_CommInitResponse(client2, &client_id, &server_id);
    printf("wh_Client_CommInit for client2 returned: %d (client_id=%u, "
           "server_id=%u)\n",
           ret, client_id, server_id);
    fflush(stdout);
    if (ret != 0)
        return ret;

    printf("Multi-client setup complete. Ready to run test suites.\n\n");

    /* Run test suites that require multiple clients */
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    WH_TEST_RETURN_ON_FAIL(
        _runGlobalKeysTests(client1, server1, client2, server2));
#endif

    /* Future test suites can be added here:
     * - Access control tests
     * - Shared counter tests
     * - Cross-client operations tests
     */

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

    printf("=== Multi-Client Sequential Tests Complete ===\n\n");

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
