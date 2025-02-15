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

#include <stdio.h>
#include <string.h>

#include "wh_test_common.h"
#include "wh_test_nvm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

/* HAL Flash state and configuration */
static whFlashRamsimCtx flashCtx = {0};
static whFlashRamsimCfg flashCfg = {
    .size = 1024 * 1024,  /* 1MB Flash */
    .sectorSize = 4096,    /* 4KB Sector Size */
    .pageSize = 8,         /* 8B Page Size */
    .erasedByte = 0xFF,
};
static whNvmFlashContext nvmFlashCtx = {0};
static const whFlashCb flashCb = WH_FLASH_RAMSIM_CB;
static const whNvmCb nvmCb = WH_NVM_FLASH_CB;

static int whTest_NvmInit(whNvmContext* nvm)
{
    int ret;
    whNvmConfig cfg = {0};
    whNvmFlashConfig nvmFlashCfg = {
        .cb = &flashCb,
        .context = &flashCtx,
        .config = &flashCfg,
    };

    printf("Testing NVM initialization...\n");

    /* Test invalid parameters */
    ret = wh_Nvm_Init(NULL, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Initialize flash */
    ret = flashCb.Init(&flashCtx, &flashCfg);
    if (ret != 0) {
        WH_ERROR_PRINT("Flash init failed: %d\n", ret);
        return ret;
    }

    /* Initialize NVM flash */
    ret = nvmCb.Init(&nvmFlashCtx, &nvmFlashCfg);
    if (ret != 0) {
        WH_ERROR_PRINT("NVM flash init failed: %d\n", ret);
        flashCb.Cleanup(&flashCtx);
        return ret;
    }

    /* Setup NVM config */
    cfg.cb = (whNvmCb*)&nvmCb;
    cfg.context = &nvmFlashCtx;
    cfg.config = &nvmFlashCfg;

    /* Test valid init */
    ret = wh_Nvm_Init(nvm, &cfg);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    return WH_ERROR_OK;
}

static int whTest_NvmCleanup(whNvmContext* nvm)
{
    int ret;

    /* Test invalid cleanup */
    ret = wh_Nvm_Cleanup(NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);

    /* Test valid cleanup */
    ret = wh_Nvm_Cleanup(nvm);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Cleanup NVM flash */
    ret = nvmCb.Cleanup(&nvmFlashCtx);
    WH_TEST_ASSERT_RETURN(ret == 0);

    /* Cleanup flash */
    ret = flashCb.Cleanup(&flashCtx);
    WH_TEST_ASSERT_RETURN(ret == 0);

    return WH_ERROR_OK;
}

static int whTest_NvmObjectOps(whNvmContext* nvm)
{
    int ret;
    whNvmObjectId objId = WH_NVM_OBJID_INVALID;
    uint8_t testData[] = "Test NVM object data";
    uint8_t readBuffer[sizeof(testData)];
    uint32_t readSize;

    printf("Testing NVM object operations...\n");

    /* Test object creation */
    ret = wh_Nvm_CreateObject(nvm, &objId, sizeof(testData), WH_NVM_FLAGS_NONE);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(objId != WH_NVM_OBJID_INVALID);

    /* Test object write */
    ret = wh_Nvm_WriteObject(nvm, objId, testData, sizeof(testData));
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test object read */
    ret = wh_Nvm_ReadObject(nvm, objId, readBuffer, sizeof(readBuffer), &readSize);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(readSize == sizeof(testData));
    WH_TEST_ASSERT_RETURN(memcmp(testData, readBuffer, readSize) == 0);

    /* Test object deletion */
    ret = wh_Nvm_DeleteObject(nvm, objId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("NVM object operations tests passed\n");
    return WH_ERROR_OK;
}

static int whTest_NvmMetadata(whNvmContext* nvm)
{
    int ret;
    whNvmObjectId objId = WH_NVM_OBJID_INVALID;
    whNvmObjectInfo info = {0};

    printf("Testing NVM metadata operations...\n");

    /* Create test object */
    ret = wh_Nvm_CreateObject(nvm, &objId, 256, WH_NVM_FLAGS_NONE);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    /* Test get object info */
    ret = wh_Nvm_GetObjectInfo(nvm, objId, &info);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(info.size == 256);
    WH_TEST_ASSERT_RETURN(info.flags == WH_NVM_FLAGS_NONE);

    /* Test object deletion */
    ret = wh_Nvm_DeleteObject(nvm, objId);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);

    printf("NVM metadata tests passed\n");
    return WH_ERROR_OK;
}

int whTest_Nvm(void)
{
    int ret;
    whNvmContext nvm = {0};

    printf("Testing NVM...\n");

    /* Test initialization */
    ret = whTest_NvmInit(&nvm);
    if (ret != 0) {
        WH_ERROR_PRINT("NVM init failed: %d\n", ret);
        return ret;
    }

    /* Test object operations */
    ret = whTest_NvmObjectOps(&nvm);
    if (ret != 0) {
        WH_ERROR_PRINT("NVM object operations failed: %d\n", ret);
        goto cleanup;
    }

    /* Test metadata operations */
    ret = whTest_NvmMetadata(&nvm);
    if (ret != 0) {
        WH_ERROR_PRINT("NVM metadata operations failed: %d\n", ret);
        goto cleanup;
    }

cleanup:
    /* Test cleanup */
    if (whTest_NvmCleanup(&nvm) != 0) {
        WH_ERROR_PRINT("NVM cleanup failed\n");
        return WH_ERROR_CLEANUP;
    }

    printf("All NVM tests completed\n");
    return ret;
}
