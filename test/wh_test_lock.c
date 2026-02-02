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
 * test/wh_test_lock.c
 *
 * Super simple smoke tests to ensure a lock implementation has basic
 * functionality
 */

#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"

#include "wh_test_common.h"
#include "wh_test_lock.h"

#ifdef WOLFHSM_CFG_THREADSAFE

#include "wolfhsm/wh_lock.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#ifdef WOLFHSM_CFG_TEST_POSIX
#include "port/posix/posix_lock.h"
#define FLASH_RAM_SIZE (1024 * 1024)
#define FLASH_SECTOR_SIZE (4096)
#define FLASH_PAGE_SIZE (8)
#endif

/* Test: Lock init/cleanup lifecycle */
static int testLockLifecycle(whLockConfig* lockConfig)
{
    whLock lock;
    int    rc;

    memset(&lock, 0, sizeof(lock));

    WH_TEST_PRINT("Testing lock lifecycle...\n");

    if (lockConfig == NULL) {
        WH_TEST_PRINT("  Lock lifecycle: SKIPPED (no config provided)\n");
        return WH_ERROR_OK;
    }

    /* Init should succeed */
    rc = wh_Lock_Init(&lock, lockConfig);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Acquire and release should work */
    rc = wh_Lock_Acquire(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    rc = wh_Lock_Release(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Cleanup should succeed */
    rc = wh_Lock_Cleanup(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* After cleanup, acquire should fail */
    rc = wh_Lock_Acquire(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    /* After cleanup, release should fail */
    rc = wh_Lock_Release(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    /* Second cleanup should succeed (idempotent) */
    rc = wh_Lock_Cleanup(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    WH_TEST_PRINT("  Lock lifecycle: PASS\n");
    return WH_ERROR_OK;
}

/* Test: NULL config results in no-op locking */
static int testNullConfigNoOp(void)
{
    whLock lock;
    int    rc;

    memset(&lock, 0, sizeof(lock));

    WH_TEST_PRINT("Testing NULL config no-op...\n");

    /* Init with NULL config should succeed (no-op mode) */
    rc = wh_Lock_Init(&lock, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Acquire/release should be no-ops returning OK */
    rc = wh_Lock_Acquire(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    rc = wh_Lock_Release(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Cleanup should succeed */
    rc = wh_Lock_Cleanup(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    WH_TEST_PRINT("  NULL config no-op: PASS\n");
    return WH_ERROR_OK;
}

/* Test: Operations on uninitialized lock should fail appropriately */
static int testUninitializedLock(void)
{
    whLock lock;
    int    rc;

    WH_TEST_PRINT("Testing uninitialized lock...\n");

    /* Create zeroed lock structure (no init call) */
    memset(&lock, 0, sizeof(lock));

    /* Acquire on uninitialized lock should fail */
    rc = wh_Lock_Acquire(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    /* Release on uninitialized lock should fail */
    rc = wh_Lock_Release(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    /* Cleanup on uninitialized lock should succeed (idempotent) */
    rc = wh_Lock_Cleanup(&lock);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    WH_TEST_PRINT("  Uninitialized lock: PASS\n");
    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_TEST_POSIX
/* Test: NVM simulator with lock config. Restrict to POSIX port test due to
 * resource utilization */
static int testNvmRamSimWithLock(whLockConfig* lockConfig)
{
    /* Flash simulator */
    uint8_t          flashMemory[FLASH_RAM_SIZE];
    const whFlashCb  flashCb[1]  = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx flashCtx[1] = {0};
    whFlashRamsimCfg flashCfg[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_SECTOR_SIZE,
        .pageSize   = FLASH_PAGE_SIZE,
        .erasedByte = 0xFF,
        .memory     = flashMemory,
    }};

    /* NVM flash layer */
    whNvmCb           nvmFlashCb[1]  = {WH_NVM_FLASH_CB};
    whNvmFlashContext nvmFlashCtx[1] = {0};
    whNvmFlashConfig  nvmFlashCfg    = {
            .cb      = flashCb,
            .context = flashCtx,
            .config  = flashCfg,
    };

    /* NVM context with lock */
    whNvmContext nvm = {0};
    whNvmConfig  nvmCfg;

    whNvmMetadata meta;
    uint8_t       testData[] = "Hello, NVM with lock!";
    uint8_t       readBuf[32];
    int           rc;

    WH_TEST_PRINT("Testing NVM with lock...\n");

    memset(flashMemory, 0xFF, sizeof(flashMemory));

    /* Initialize NVM flash */
    rc = wh_NvmFlash_Init(nvmFlashCtx, &nvmFlashCfg);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Set up NVM config with user-supplied lock */
    nvmCfg.cb         = nvmFlashCb;
    nvmCfg.context    = nvmFlashCtx;
    nvmCfg.config     = &nvmFlashCfg;
    nvmCfg.lockConfig = lockConfig;

    rc = wh_Nvm_Init(&nvm, &nvmCfg);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Test basic NVM operations with locking */
    memset(&meta, 0, sizeof(meta));
    meta.id  = 1;
    meta.len = sizeof(testData);

    rc = wh_Nvm_AddObject(&nvm, &meta, sizeof(testData), testData);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    memset(readBuf, 0, sizeof(readBuf));
    rc = wh_Nvm_Read(&nvm, 1, 0, sizeof(testData), readBuf);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(memcmp(testData, readBuf, sizeof(testData)) == 0);

    /* Cleanup */
    rc = wh_Nvm_Cleanup(&nvm);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    rc = wh_NvmFlash_Cleanup(nvmFlashCtx);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    WH_TEST_PRINT("  NVM with lock: PASS\n");
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

int whTest_LockConfig(whLockConfig* lockConfig)
{
    WH_TEST_PRINT("Testing lock functionality...\n");

    WH_TEST_RETURN_ON_FAIL(testLockLifecycle(lockConfig));
    WH_TEST_RETURN_ON_FAIL(testNullConfigNoOp());
    WH_TEST_RETURN_ON_FAIL(testUninitializedLock());
#ifdef WOLFHSM_CFG_TEST_POSIX
    WH_TEST_RETURN_ON_FAIL(testNvmRamSimWithLock(lockConfig));
#endif

    WH_TEST_PRINT("Lock tests PASSED\n");
    return WH_ERROR_OK;
}


#if defined(WOLFHSM_CFG_TEST_POSIX)
int whTest_LockPosix(void)
{
    posixLockContext lockCtx = {0};
    whLockCb         lockCb  = POSIX_LOCK_CB;
    whLockConfig     lockConfig;

    lockConfig.cb      = &lockCb;
    lockConfig.context = &lockCtx;
    lockConfig.config  = NULL; /* Use default mutex attributes */

    return whTest_LockConfig(&lockConfig);
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

#endif /* WOLFHSM_CFG_THREADSAFE */
