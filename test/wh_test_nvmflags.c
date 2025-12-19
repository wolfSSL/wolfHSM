/*
 * Copyright (C) 2024 wolfSSL Inc.
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

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
#include "wh_test_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"

#define TEST_NVM_ID_NONMOD 0x0001
#define TEST_NVM_ID_MODIFIABLE 0x0002
#define TEST_NVM_ID_NONDESTROYABLE 0x0003
#define TEST_NVM_ID_NONMOD_DMA 0x0004
#define TEST_NVM_ID_NONDESTROYABLE_DMA 0x0005
#define TEST_KEY_ID_NONMOD 0x0001
#define TEST_KEY_ID_MODIFIABLE 0x0002
#define TEST_KEY_ID_PROMOTE 0x0003
#define TEST_KEY_ID_NONDESTROYABLE 0x0004
#define TEST_KEY_ID_NONMOD_DMA 0x0005
#define TEST_KEY_ID_PROMOTE_DMA 0x0006
#define TEST_KEY_ID_NONDESTROYABLE_DMA 0x0007

static int _testNonExportableNvmAccess(whClientContext* client)
{
    int       ret       = 0;
    whNvmId   nvmId     = 2; /* Arbitrary NVM ID */
    uint8_t   nvmData[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t   exportedNvmData[sizeof(nvmData)] = {0};
    uint8_t   nvmLabel[WH_NVM_LABEL_LEN]       = "NonExportableNvmObj";
    int32_t   out_rc                           = 0;
    whNvmSize out_len                          = 0;

    WH_TEST_PRINT("Testing non-exportable NVM object access protection...\n");

    /* Test 1: Regular NVM Read Protection */
    /* Create NVM object with non-exportable flag */
    ret = wh_Client_NvmAddObject(client, nvmId, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_NONEXPORTABLE, sizeof(nvmLabel),
                                 nvmLabel, sizeof(nvmData), nvmData, &out_rc);
    if (ret != 0 || out_rc != 0) {
        WH_ERROR_PRINT(
            "Failed to add non-exportable NVM object: ret=%d, out_rc=%d\n", ret,
            (int)out_rc);
        return ret != 0 ? ret : out_rc;
    }

    /* Try to read the non-exportable NVM object - should fail */
    out_rc = 0;
    ret = wh_Client_NvmRead(client, nvmId, 0, sizeof(exportedNvmData), &out_rc,
                            &out_len, exportedNvmData);
    if (ret != 0 || out_rc != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("Non-exportable NVM object was read unexpectedly: "
                       "ret=%d, out_rc=%d\n",
                       ret, (int)out_rc);
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Non-exportable NVM object read correctly denied\n");

    /* Clean up NVM object */
    whNvmId destroyList[] = {nvmId};
    out_rc                = 0;
    wh_Client_NvmDestroyObjects(client, 1, destroyList, &out_rc);

    /* Test 2: Verify exportable NVM objects can still be read */
    memcpy(nvmLabel, "ExportableNvmObject", sizeof("ExportableNvmObject"));

    ret = wh_Client_NvmAddObject(client, nvmId, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_NONE, sizeof(nvmLabel), nvmLabel,
                                 sizeof(nvmData), nvmData, &out_rc);
    if (ret != 0 || out_rc != 0) {
        WH_ERROR_PRINT(
            "Failed to add exportable NVM object: ret=%d, out_rc=%d\n", ret,
            (int)out_rc);
        return ret != 0 ? ret : out_rc;
    }

    /* Try to read the exportable NVM object - should succeed */
    memset(exportedNvmData, 0, sizeof(exportedNvmData));
    out_rc  = 0;
    out_len = 0;
    ret = wh_Client_NvmRead(client, nvmId, 0, sizeof(exportedNvmData), &out_rc,
                            &out_len, exportedNvmData);
    if (ret != 0 || out_rc != 0) {
        WH_ERROR_PRINT(
            "Failed to read exportable NVM object: ret=%d, out_rc=%d\n", ret,
            (int)out_rc);
        return ret != 0 ? ret : out_rc;
    }

    /* Verify data matches */
    if (out_len != sizeof(nvmData) ||
        memcmp(nvmData, exportedNvmData, out_len) != 0) {
        WH_ERROR_PRINT("Exported NVM data doesn't match original\n");
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Exportable NVM object read succeeded\n");

    /* Clean up */
    out_rc = 0;
    wh_Client_NvmDestroyObjects(client, 1, &nvmId, &out_rc);

#ifdef WOLFHSM_CFG_DMA
    /* Test 3: DMA NVM Read Protection */
    WH_TEST_PRINT("Testing DMA NVM read protection...\n");

    /* Create NVM object with non-exportable flag */
    memcpy(nvmLabel, "NonExportDmaNvmObj", sizeof("NonExportDmaNvmObj"));

    ret = wh_Client_NvmAddObject(client, nvmId, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_NONEXPORTABLE, sizeof(nvmLabel),
                                 nvmLabel, sizeof(nvmData), nvmData, &out_rc);
    if (ret != 0 || out_rc != 0) {
        WH_ERROR_PRINT("Failed to add non-exportable NVM object for DMA: "
                       "ret=%d, out_rc=%d\n",
                       ret, (int)out_rc);
        return ret != 0 ? ret : out_rc;
    }

    /* Try to read the non-exportable NVM object via DMA - should fail */
    memset(exportedNvmData, 0, sizeof(exportedNvmData));
    out_rc = 0;
    ret    = wh_Client_NvmReadDma(client, nvmId, 0, sizeof(exportedNvmData),
                                  exportedNvmData, &out_rc);
    if (ret != 0 || out_rc != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("Non-exportable NVM object was read via DMA "
                       "unexpectedly: ret=%d, out_rc=%d\n",
                       ret, (int)out_rc);
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Non-exportable NVM object DMA read correctly denied\n");

    /* Clean up */
    out_rc = 0;
    wh_Client_NvmDestroyObjects(client, 1, &nvmId, &out_rc);

    /* Test 4: Verify exportable NVM objects can be read via DMA */
    memcpy(nvmLabel, "ExportableDmaNvmObj", sizeof("ExportableDmaNvmObj"));

    ret = wh_Client_NvmAddObject(client, nvmId, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_NONE, sizeof(nvmLabel), nvmLabel,
                                 sizeof(nvmData), nvmData, &out_rc);
    if (ret != 0 || out_rc != 0) {
        WH_ERROR_PRINT(
            "Failed to add exportable NVM object for DMA: ret=%d, out_rc=%d\n",
            ret, (int)out_rc);
        return ret != 0 ? ret : out_rc;
    }

    /* Try to read the exportable NVM object via DMA - should succeed */
    memset(exportedNvmData, 0, sizeof(exportedNvmData));
    out_rc = 0;
    ret    = wh_Client_NvmReadDma(client, nvmId, 0, sizeof(exportedNvmData),
                                  exportedNvmData, &out_rc);
    if (ret != 0 || out_rc != 0) {
        WH_ERROR_PRINT(
            "Failed to read exportable NVM object via DMA: ret=%d, out_rc=%d\n",
            ret, (int)out_rc);
        return ret != 0 ? ret : out_rc;
    }

    /* Verify data matches */
    if (memcmp(nvmData, exportedNvmData, sizeof(nvmData)) != 0) {
        WH_ERROR_PRINT("DMA exported NVM data doesn't match original\n");
        return -1;
    }

    WH_TEST_DEBUG_PRINT("Exportable NVM object DMA read succeeded\n");

    /* Clean up */
    out_rc = 0;
    wh_Client_NvmDestroyObjects(client, 1, &nvmId, &out_rc);
#endif /* WOLFHSM_CFG_DMA */

    WH_TEST_PRINT("NON-EXPORTABLE NVM ACCESS TEST SUCCESS\n");
    return 0;
}

#if defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
static int _testNvmNonmodifiableNoOverwrite(whClientContext* client)
{
    int32_t   server_rc;
    uint8_t   data1[]                 = {0x11, 0x22, 0x33, 0x44};
    uint8_t   data2[]                 = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t   readData[sizeof(data1)] = {0};
    whNvmSize readLen                 = sizeof(readData);
    uint8_t   label[]                 = "TST";
    uint8_t   labelLen                = (uint8_t)strlen((const char*)label);
    whNvmId   list[1]                 = {TEST_NVM_ID_NONMOD};

    WH_TEST_PRINT("Testing NVM NONMODIFIABLE: no overwrite...\n");

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmAddObject(client, TEST_NVM_ID_NONMOD, WH_NVM_ACCESS_ANY,
                               WH_NVM_FLAGS_NONMODIFIABLE, labelLen, label,
                               sizeof(data1), data1, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(client, TEST_NVM_ID_NONMOD, 0,
                                             sizeof(readData), &server_rc,
                                             &readLen, readData));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data1, sizeof(data1)) == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmAddObject(client, TEST_NVM_ID_NONMOD, WH_NVM_ACCESS_ANY,
                               WH_NVM_FLAGS_NONMODIFIABLE, labelLen, label,
                               sizeof(data2), data2, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);

    memset(readData, 0, sizeof(readData));
    readLen = sizeof(readData);
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(client, TEST_NVM_ID_NONMOD, 0,
                                             sizeof(readData), &server_rc,
                                             &readLen, readData));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data1, sizeof(data1)) == 0);

    WH_TEST_PRINT("  NVM NONMODIFIABLE no overwrite: PASS\n");


    WH_TEST_PRINT("Testing NVM NONMODIFIABLE: no destroy...\n");

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmDestroyObjects(client, 1, list, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(client, TEST_NVM_ID_NONMOD, 0,
                                             sizeof(readData), &server_rc,
                                             &readLen, readData));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_PRINT("  NVM NONMODIFIABLE no destroy: PASS\n");
    return WH_ERROR_OK;
}

static int _testNvmNondestroyableModifyNoDestroy(whClientContext* client)
{
    int32_t   server_rc;
    uint8_t   data1[]                 = {0x55, 0x66, 0x77, 0x88};
    uint8_t   data2[]                 = {0x99, 0xAA, 0xBB, 0xCC};
    uint8_t   readData[sizeof(data2)] = {0};
    whNvmSize readLen                 = sizeof(readData);
    whNvmId   list[1]                 = {TEST_NVM_ID_NONDESTROYABLE};
    uint8_t   label[]                 = "NDY";
    uint8_t   labelLen                = (uint8_t)strlen((const char*)label);

    WH_TEST_PRINT(
        "Testing NVM NONDESTROYABLE: modify allowed, destroy denied...\n");

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObject(
        client, TEST_NVM_ID_NONDESTROYABLE, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_NONDESTROYABLE, labelLen, label, sizeof(data1), data1,
        &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* modify the object */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObject(
        client, TEST_NVM_ID_NONDESTROYABLE, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_NONDESTROYABLE, labelLen, label, sizeof(data2), data2,
        &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(client, TEST_NVM_ID_NONDESTROYABLE,
                                             0, sizeof(readData), &server_rc,
                                             &readLen, readData));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data2, sizeof(data2)) == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmDestroyObjects(client, 1, list, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);

    memset(readData, 0, sizeof(readData));
    readLen = sizeof(readData);
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(client, TEST_NVM_ID_NONDESTROYABLE,
                                             0, sizeof(readData), &server_rc,
                                             &readLen, readData));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data2, sizeof(data2)) == 0);

    WH_TEST_PRINT(
        "  NVM NONDESTROYABLE modify allowed, destroy denied: PASS\n");
    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA
static int _testNvmNonmodifiableNoOverwriteDma(whClientContext* client)
{
    int32_t       server_rc;
    uint8_t       data1[]                 = {0x11, 0x22, 0x33, 0x44};
    uint8_t       data2[]                 = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t       readData[sizeof(data1)] = {0};
    whNvmSize     readLen                 = sizeof(readData);
    whNvmId       list[1]                 = {TEST_NVM_ID_NONMOD_DMA};
    whNvmMetadata meta                    = {0};

    WH_TEST_PRINT("Testing NVM DMA NONMODIFIABLE: no overwrite...\n");

    meta.id     = TEST_NVM_ID_NONMOD_DMA;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len    = sizeof(data1);
    memcpy(meta.label, "DMANONMOD", sizeof("DMANONMOD"));

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectDma(
        client, &meta, sizeof(data1), data1, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadDma(client, TEST_NVM_ID_NONMOD_DMA,
                                                0, sizeof(readData), readData,
                                                &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data1, sizeof(data1)) == 0);

    meta.len = sizeof(data2);
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectDma(
        client, &meta, sizeof(data2), data2, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);

    memset(readData, 0, sizeof(readData));
    readLen = sizeof(readData);
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadDma(
        client, TEST_NVM_ID_NONMOD_DMA, 0, readLen, readData, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data1, sizeof(data1)) == 0);

    WH_TEST_PRINT("  NVM DMA NONMODIFIABLE no overwrite: PASS\n");


    WH_TEST_PRINT("Testing NVM DMA NONMODIFIABLE: no destroy...\n");

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmDestroyObjects(client, 1, list, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmReadDma(client, TEST_NVM_ID_NONMOD_DMA,
                                                0, sizeof(readData), readData,
                                                &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_PRINT("  NVM DMA NONMODIFIABLE no destroy: PASS\n");
    return WH_ERROR_OK;
}

static int _testNvmNondestroyableModifyNoDestroyDma(whClientContext* client)
{
    int32_t       server_rc;
    uint8_t       data1[]                 = {0x55, 0x66, 0x77, 0x88};
    uint8_t       data2[]                 = {0x99, 0xAA, 0xBB, 0xCC};
    uint8_t       readData[sizeof(data2)] = {0};
    whNvmSize     readLen                 = sizeof(readData);
    whNvmId       list[1]                 = {TEST_NVM_ID_NONDESTROYABLE_DMA};
    whNvmMetadata meta                    = {0};

    WH_TEST_PRINT(
        "Testing NVM DMA NONDESTROYABLE: modify allowed, destroy denied...\n");

    meta.id     = TEST_NVM_ID_NONDESTROYABLE_DMA;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONDESTROYABLE;
    meta.len    = sizeof(data1);
    memcpy(meta.label, "DMANONDEST", sizeof("DMANONDEST"));

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectDma(
        client, &meta, sizeof(data1), data1, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* modify the object via DMA */
    meta.len = sizeof(data2);
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObjectDma(
        client, &meta, sizeof(data2), data2, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmReadDma(client, TEST_NVM_ID_NONDESTROYABLE_DMA, 0,
                             sizeof(readData), readData, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data2, sizeof(data2)) == 0);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmDestroyObjects(client, 1, list, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_ACCESS);

    memset(readData, 0, sizeof(readData));
    readLen = sizeof(readData);
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_NvmReadDma(client, TEST_NVM_ID_NONDESTROYABLE_DMA, 0, readLen,
                             readData, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(readData, data2, sizeof(data2)) == 0);

    WH_TEST_PRINT(
        "  NVM DMA NONDESTROYABLE modify allowed, destroy denied: PASS\n");
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
static int _testKeyNonmodifiableNoRecache(whClientContext* client)
{
    int      ret;
    uint16_t keyId   = TEST_KEY_ID_NONMOD;
    uint8_t  key1[]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t  key2[]  = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    uint8_t  label[] = "nonmod_key";

    WH_TEST_PRINT("Testing Key NONMODIFIABLE: no re-cache...\n");

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                             sizeof(label), key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                             sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                             sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                             sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Key NONMODIFIABLE no re-cache: PASS\n");

    WH_TEST_PRINT("Testing Key NONMODIFIABLE: no erase...\n");

    ret = wh_Client_KeyErase(client, TEST_KEY_ID_NONMOD);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Key NONMODIFIABLE no erase: PASS\n");

    return WH_ERROR_OK;
}

static int _testKeyNonmodifiableInNvm(whClientContext* client)
{
    uint16_t keyId   = TEST_KEY_ID_PROMOTE;
    uint8_t  key1[]  = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint8_t  key2[]  = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
    uint8_t  label[] = "promote_key";
    int      ret;

    WH_TEST_PRINT("Testing Key NONMODIFIABLE: commit then enforce...\n");

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE, label, sizeof(label),
                             key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                             sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE, label, sizeof(label),
                             key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Key NONMODIFIABLE commit then enforce: PASS\n");
    return WH_ERROR_OK;
}

static int _testKeyNondestroyableNoErase(whClientContext* client)
{
    int      ret;
    uint16_t keyId  = TEST_KEY_ID_NONDESTROYABLE;
    uint8_t  key1[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};
    uint8_t  key2[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                       0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    uint8_t  exported[sizeof(key2)] = {0};
    uint16_t exportedLen            = sizeof(exported);
    uint8_t  label[]                = "nondestroyable_key";

    WH_TEST_PRINT(
        "Testing Key NONDESTROYABLE: erase denied, modify allowed...\n");

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONDESTROYABLE, label,
                             sizeof(label), key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    ret = wh_Client_KeyErase(client, keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    exportedLen = sizeof(exported);
    ret = wh_Client_KeyExport(client, keyId, NULL, 0, exported, &exportedLen);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(exportedLen == sizeof(key1));
    WH_TEST_ASSERT_RETURN(memcmp(exported, key1, sizeof(key1)) == 0);

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONDESTROYABLE, label,
                             sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));

    exportedLen = sizeof(exported);
    ret = wh_Client_KeyExport(client, keyId, NULL, 0, exported, &exportedLen);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(exportedLen == sizeof(key2));
    WH_TEST_ASSERT_RETURN(memcmp(exported, key2, sizeof(key2)) == 0);

    WH_TEST_PRINT("  Key NONDESTROYABLE erase denied, modify allowed: PASS\n");
    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA
static int _testKeyNonmodifiableNoRecacheDma(whClientContext* client)
{
    int      ret;
    uint16_t keyId   = TEST_KEY_ID_NONMOD_DMA;
    uint8_t  key1[]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t  key2[]  = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    uint8_t  label[] = "nonmod_key_dma";

    WH_TEST_PRINT("Testing Key DMA NONMODIFIABLE: no re-cache...\n");

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                                sizeof(label), key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                                sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                                sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                                sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Key DMA NONMODIFIABLE no re-cache: PASS\n");

    WH_TEST_PRINT("Testing Key DMA NONMODIFIABLE: no erase...\n");

    ret = wh_Client_KeyErase(client, TEST_KEY_ID_NONMOD_DMA);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Key DMA NONMODIFIABLE no erase: PASS\n");

    return WH_ERROR_OK;
}

static int _testKeyNonmodifiableInNvmDma(whClientContext* client)
{
    uint16_t keyId   = TEST_KEY_ID_PROMOTE_DMA;
    uint8_t  key1[]  = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    uint8_t  key2[]  = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
    uint8_t  label[] = "promote_key_dma";
    int      ret;

    WH_TEST_PRINT("Testing Key DMA NONMODIFIABLE: commit then enforce...\n");

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONE, label, sizeof(label),
                                key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONMODIFIABLE, label,
                                sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONE, label, sizeof(label),
                                key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    WH_TEST_PRINT("  Key DMA NONMODIFIABLE commit then enforce: PASS\n");
    return WH_ERROR_OK;
}

static int _testKeyNondestroyableNoEraseDma(whClientContext* client)
{
    int      ret;
    uint16_t keyId  = TEST_KEY_ID_NONDESTROYABLE_DMA;
    uint8_t  key1[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                       0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};
    uint8_t  key2[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                       0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    uint8_t  exported[sizeof(key2)]  = {0};
    uint16_t exportedLen             = sizeof(exported);
    uint8_t  label[WH_NVM_LABEL_LEN] = "nondestroyable_dma";

    WH_TEST_PRINT(
        "Testing Key DMA NONDESTROYABLE: erase denied, modify allowed...\n");

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONDESTROYABLE, label,
                                sizeof(label), key1, sizeof(key1), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    ret = wh_Client_KeyErase(client, keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ACCESS);

    exportedLen = sizeof(exported);
    ret = wh_Client_KeyExportDma(client, keyId, exported, sizeof(exported),
                                 label, sizeof(label), &exportedLen);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(exportedLen == sizeof(key1));
    WH_TEST_ASSERT_RETURN(memcmp(exported, key1, sizeof(key1)) == 0);

    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONDESTROYABLE, label,
                                sizeof(label), key2, sizeof(key2), &keyId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCommit(client, keyId));

    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, keyId));

    exportedLen = sizeof(exported);
    ret = wh_Client_KeyExportDma(client, keyId, exported, sizeof(exported),
                                 label, sizeof(label), &exportedLen);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(exportedLen == sizeof(key2));
    WH_TEST_ASSERT_RETURN(memcmp(exported, key2, sizeof(key2)) == 0);

    WH_TEST_PRINT(
        "  Key DMA NONDESTROYABLE erase denied, modify allowed: PASS\n");
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#endif /* WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS */
int whTest_NvmFlags(whClientContext* client)
{
    int ret = 0;

    WH_TEST_PRINT("=== NVM Flags Enforcement Tests ===\n\n");

    WH_TEST_PRINT("=== NVM Object Tests (NONEXPORTABLE) ===\n");

    ret = _testNonExportableNvmAccess(client);
    if (ret != WH_ERROR_OK)
        return ret;


#if defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
    WH_TEST_PRINT("--- NVM Object Tests (NONMODIFIABLE/NODESTROYABLE) ---\n");

    ret = _testNvmNonmodifiableNoOverwrite(client);
    if (ret != WH_ERROR_OK)
        return ret;

    ret = _testNvmNondestroyableModifyNoDestroy(client);
    if (ret != WH_ERROR_OK)
        return ret;

#ifdef WOLFHSM_CFG_DMA
    WH_TEST_PRINT(
        "\n--- NVM Object DMA Tests (NONMODIFIABLE/NONDESTROYABLE) DMA ---\n");

    ret = _testNvmNonmodifiableNoOverwriteDma(client);
    if (ret != WH_ERROR_OK)
        return ret;

    ret = _testNvmNondestroyableModifyNoDestroyDma(client);
    if (ret != WH_ERROR_OK)
        return ret;
#endif /* WOLFHSM_CFG_DMA */

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    WH_TEST_PRINT("\n--- Key Object Tests (NONMODIFIABLE/NODESTROYABLE) ---\n");

    ret = _testKeyNonmodifiableNoRecache(client);
    if (ret != WH_ERROR_OK)
        return ret;

    ret = _testKeyNonmodifiableInNvm(client);
    if (ret != WH_ERROR_OK)
        return ret;

    ret = _testKeyNondestroyableNoErase(client);
    if (ret != WH_ERROR_OK)
        return ret;

#ifdef WOLFHSM_CFG_DMA
    WH_TEST_PRINT(
        "\n--- Key Object DMA Tests (NONMODIFIABLE/NONDESTROYABLE) DMA ---\n");

    ret = _testKeyNonmodifiableNoRecacheDma(client);
    if (ret != WH_ERROR_OK)
        return ret;

    ret = _testKeyNonmodifiableInNvmDma(client);
    if (ret != WH_ERROR_OK)
        return ret;

    ret = _testKeyNondestroyableNoEraseDma(client);
    if (ret != WH_ERROR_OK)
        return ret;
#endif /* WOLFHSM_CFG_DMA */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */
#else
    WH_TEST_PRINT("\n--- Skipping NVM Object Tests "
                  "(NONMODIFIABLE/NONDESTROYABLE) due to persistent "
                  "NVM artifacts not being allowed ---\n");
#endif /* WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS */

    WH_TEST_PRINT("\n=== All NVM Flags Tests Complete ===\n");
    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
