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
 * test-refactor/wh_test_nvm_flash.c
 *
 * NVM flash test suite. The fixture (flash + NVM stack) is
 * owned by the caller; these tests just consume it. Exercises
 * flash unit ops and NVM add/read/overwrite/destroy/reclaim
 * through the callback interface.
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_flash_unit.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"

#include "wh_test_common.h"
#include "wh_test_list.h"
#include "wh_test_flash_fault_inject.h"

#define NVM_FLASH_SIZE       (1024 * 1024)
#define NVM_FLASH_SECTOR_SZ  (4096)
#define NVM_FLASH_PAGE_SZ    (8)


/*
 * Module-private fixture. A single file-static instance holds
 * all ramsim/NVM state the tests poke at; _setup populates it,
 * _cleanup is a placeholder for symmetry.
 */
typedef struct {
    uint8_t          memory[NVM_FLASH_SIZE];
    whFlashRamsimCtx flashCtx;
    whFlashRamsimCfg flashCfg;
    whFlashCb        flashCb;

    /* NVM backend selected per-test by whTest_NvmCfgBackend */
    whTestNvmBackendUnion nvmSetup;
    whNvmConfig           nvmCfg;
} whTestNvmFlashCtx;

static whTestNvmFlashCtx _ctx;


/*
 * Populate the module-private fixture. Called from the top
 * of each test so every test starts against a fresh state.
 */
static void _setup(void)
{
    whTestNvmFlashCtx* c              = &_ctx;
    const whFlashCb    initFlashCb[1] = {WH_FLASH_RAMSIM_CB};

    memset(c, 0, sizeof(*c));

    c->flashCb = initFlashCb[0];
    c->flashCfg.size       = NVM_FLASH_SIZE;
    c->flashCfg.sectorSize = NVM_FLASH_SECTOR_SZ;
    c->flashCfg.pageSize   = NVM_FLASH_PAGE_SZ;
    c->flashCfg.erasedByte = 0;
    c->flashCfg.memory     = c->memory;
}


/*
 * Wire the requested NVM backend over the ramsim flash configured
 * by _setup, leaving _ctx.nvmCfg ready to Init. Delegates to the
 * shared backend selector so flash and flash-log tests stay in
 * sync with the rest of the suite.
 */
static int _selectNvm(whTestNvmBackendType type)
{
    return whTest_NvmCfgBackend(type, &_ctx.nvmSetup, &_ctx.nvmCfg,
        &_ctx.flashCfg, &_ctx.flashCtx, &_ctx.flashCb);
}


/* ---- Flash unit operations ---- */

/*
 * Exercises flash unit program/read/erase/blank-check
 * and byte-level read/write including unaligned access.
 */
int whTest_FlashUnitOps(void* ctx)
{
    whTestNvmFlashCtx* c = &_ctx;
    uint8_t write_bytes[8] = {
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87
    };
    uint8_t      read_bytes[8]     = {0};
    whFlashUnit  write_buf[4]      = {0};
    whFlashUnit  read_buf[4]       = {0};
    uint32_t     partition_units   = 0;

    (void)ctx;
    _setup();

    WH_TEST_RETURN_ON_FAIL(
        c->flashCb.Init(&c->flashCtx, &c->flashCfg));

    partition_units = wh_FlashUnit_Bytes2Units(
        c->flashCb.PartitionSize(&c->flashCtx));

    /* Unlock + erase + blank check */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_WriteUnlock(
        &c->flashCb, &c->flashCtx, 0, partition_units));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Erase(
        &c->flashCb, &c->flashCtx, 0, partition_units));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_BlankCheck(
        &c->flashCb, &c->flashCtx, 0, partition_units));

    /* Program + read back at unit granularity */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(
        &c->flashCb, &c->flashCtx, 0, 1, write_buf));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(
        &c->flashCb, &c->flashCtx, 1, 2, write_buf));

    memset(read_buf, 0, sizeof(read_buf));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(
        &c->flashCb, &c->flashCtx, 0, 1, read_buf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(
        write_buf, read_buf, 1 * WHFU_BYTES_PER_UNIT));

    /* Program + read back at byte granularity */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(
        &c->flashCb, &c->flashCtx,
        10 * WHFU_BYTES_PER_UNIT, 8, write_bytes));

    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(
        &c->flashCb, &c->flashCtx,
        10 * WHFU_BYTES_PER_UNIT, 8, read_bytes));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(write_bytes, read_bytes, 8));

    /* Unaligned read (exercises offset_rem path) */
    {
        uint8_t  pattern[WHFU_BYTES_PER_UNIT * 4];
        uint8_t  readback[WHFU_BYTES_PER_UNIT * 4];
        uint32_t base = 20;
        uint32_t i;

        for (i = 0; i < sizeof(pattern); i++) {
            pattern[i] = (uint8_t)(0x10 + i);
        }

        WH_TEST_RETURN_ON_FAIL(
            wh_FlashUnit_ProgramBytes(
                &c->flashCb, &c->flashCtx,
                base * WHFU_BYTES_PER_UNIT,
                sizeof(pattern), pattern));

        memset(readback, 0, sizeof(readback));
        WH_TEST_RETURN_ON_FAIL(
            wh_FlashUnit_ReadBytes(
                &c->flashCb, &c->flashCtx,
                base * WHFU_BYTES_PER_UNIT + 3,
                5, readback));
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(readback, &pattern[3], 5));

        memset(readback, 0, sizeof(readback));
        WH_TEST_RETURN_ON_FAIL(
            wh_FlashUnit_ReadBytes(
                &c->flashCb, &c->flashCtx,
                base * WHFU_BYTES_PER_UNIT + 2,
                21, readback));
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(readback, &pattern[2], 21));
    }

    /* Erase + lock */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Erase(
        &c->flashCb, &c->flashCtx, 0, partition_units));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_BlankCheck(
        &c->flashCb, &c->flashCtx, 0, partition_units));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_WriteLock(
        &c->flashCb, &c->flashCtx, 0, partition_units));

    WH_TEST_RETURN_ON_FAIL(
        c->flashCb.Cleanup(&c->flashCtx));

    return 0;
}


/* ---- NVM operations ---- */

static int _addAndCheck(const whNvmCb* cb, void* context,
    whNvmMetadata* meta, whNvmSize len, const uint8_t* data)
{
    whNvmMetadata readMeta = {0};
    uint8_t       readBuf[256];

    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, meta, len, data));
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, meta->id, 0, len, readBuf));
    WH_TEST_RETURN_ON_FAIL(
        cb->GetMetadata(context, meta->id, &readMeta));
    WH_TEST_ASSERT_RETURN(meta->id == readMeta.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(data, readBuf, len));

    return 0;
}


/*
 * Backend-agnostic object lifecycle: init the NVM backend from
 * cfg, add three objects, overwrite, reclaim, destroy, and verify
 * data integrity throughout, then clean up. Shared by the plain
 * flash and flash-log backend tests.
 */
static int _addOverwriteDestroy(const whNvmCb* cb, void* context,
    const void* cfg)
{
    uint8_t data1[]   = "Data1";
    uint8_t data2[]   = "Data2";
    uint8_t data3[]   = "Data3";
    uint8_t update1[] = "Update1fdsafdasfdsafdsafdsafdsaf";
    uint8_t update2[] = "Update2fdafdafdafdsafdsafdasfd";
    whNvmId ids[]     = {100, 400, 300};

    whNvmMetadata meta1 = {.id = ids[0], .label = "L1"};
    whNvmMetadata meta2 = {.id = ids[1], .label = "L2"};
    whNvmMetadata meta3 = {.id = ids[2], .label = "L3"};

    whNvmMetadata readMeta = {0};
    uint8_t       readBuf[256];
    size_t        i;

    WH_TEST_RETURN_ON_FAIL(cb->Init(context, cfg));

    /* Add 3 objects */
    WH_TEST_RETURN_ON_FAIL(
        _addAndCheck(cb, context, &meta1, sizeof(data1), data1));
    WH_TEST_RETURN_ON_FAIL(
        _addAndCheck(cb, context, &meta2, sizeof(data2), data2));
    WH_TEST_RETURN_ON_FAIL(
        _addAndCheck(cb, context, &meta3, sizeof(data3), data3));

    /* Overwrite objects */
    WH_TEST_RETURN_ON_FAIL(
        _addAndCheck(cb, context, &meta1, sizeof(update1), update1));
    WH_TEST_RETURN_ON_FAIL(
        _addAndCheck(cb, context, &meta2, sizeof(update2), update2));

    /* Reclaim space */
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));

    /* Verify all objects survived reclaim */
    for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        memset(&readMeta, 0, sizeof(readMeta));
        WH_TEST_RETURN_ON_FAIL(
            cb->GetMetadata(context, ids[i], &readMeta));
        WH_TEST_RETURN_ON_FAIL(
            cb->Read(context, ids[i], 0, readMeta.len, readBuf));
    }

    /* Destroy first object, verify it's gone */
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 1, ids));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND == cb->Read(context, ids[0], 0,
            sizeof(readBuf), readBuf));

    /* Destroy remaining */
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context,
        sizeof(ids) / sizeof(ids[0]), ids));

    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

    return 0;
}


/*
 * Object lifecycle against the plain NVM flash backend.
 */
int whTest_NvmAddOverwriteDestroy(void* ctx)
{
    (void)ctx;
    _setup();
    WH_TEST_RETURN_ON_FAIL(_selectNvm(WH_NVM_TEST_BACKEND_FLASH));
    return _addOverwriteDestroy(_ctx.nvmCfg.cb, _ctx.nvmCfg.context,
        _ctx.nvmCfg.config);
}


/*
 * Same lifecycle against the NVM flash-log backend, which layers a
 * journaled log over the same ramsim flash. Skipped when the log
 * backend isn't built.
 */
int whTest_NvmFlashLog(void* ctx)
{
    (void)ctx;
#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    _setup();
    WH_TEST_RETURN_ON_FAIL(_selectNvm(WH_NVM_TEST_BACKEND_FLASH_LOG));
    return _addOverwriteDestroy(_ctx.nvmCfg.cb, _ctx.nvmCfg.context,
        _ctx.nvmCfg.config);
#else
    return WH_TEST_SKIPPED;
#endif
}


/* ---- NVM recovery ---- */

/*
 * Two flash images for the recovery test: one live backing store
 * and one snapshot replayed as init data to model a reboot over a
 * dirty flash. File-static to keep 2 MB off the stack.
 */
static uint8_t _recoveryMemory[NVM_FLASH_SIZE];
static uint8_t _recoveryBackup[NVM_FLASH_SIZE];


/*
 * Simulate a failure (eg power loss) during AddObject(), then reinit
 * and confirm the half-written object is not found.
 */
static int _simulateFailureAndRecover(
    int failAfter, int* dataSize, uint32_t* bytesAvalBefore,
    whNvmId* objsAvailBefore, uint32_t* bytesReclBefore, whNvmId* objsReclBefore,
    uint32_t* bytesAvalAfter, whNvmId* objsAvailAfter, uint32_t* bytesReclAfter,
    whNvmId* objsReclAfter)
{
    unsigned char         data[]      = "This is test data for recovery test";
    whNvmMetadata         meta        = {.id = 42, .label = "RecoveryTest"};
    const whFlashCb       flashCb[1]  = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx      flashCtx[1] = {0};
    whFlashRamsimCfg      flashCfg[1] = {{
              .size       = NVM_FLASH_SIZE,
              .sectorSize = NVM_FLASH_SECTOR_SZ,
              .pageSize   = NVM_FLASH_PAGE_SZ,
              .erasedByte = (uint8_t)0,
              .memory     = _recoveryMemory,
    }};
    const whFlashCb       flashFaultInjCb[1] = {WH_FLASH_FAULTINJECT_CB};
    whFlashFaultInjectCtx faultInjCtx[1]     = {0};
    whFlashFaultInjectCfg faultInjCfg[1]     = {{
            .realCb  = flashCb,
            .realCtx = flashCtx,
            .realCfg = flashCfg,
    }};
    const whNvmCb         cb[1]      = {WH_NVM_FLASH_CB};
    whNvmFlashContext     context[1] = {0};
    whNvmFlashConfig      cfg        = {
             .cb      = flashFaultInjCb,
             .context = faultInjCtx,
             .config  = faultInjCfg,
    };
    whNvmMetadata checkMeta = {0};
    int           ret       = 0;

    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, bytesAvalBefore,
                                            objsAvailBefore, bytesReclBefore,
                                            objsReclBefore));
    faultInjCtx->failAfterPrograms = failAfter;
    ret = cb->AddObject(context, (whNvmMetadata*)&meta, (whNvmSize)sizeof(data),
                        data);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    /* Save the memory state for recovery testing */
    memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);

    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    /* clean-up the memory */
    memset(_recoveryMemory, 0, NVM_FLASH_SIZE);

    /* Reinit the NVM stack with the backup data from the failure */
    flashCfg->initData = _recoveryBackup;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
    WH_TEST_ASSERT_RETURN(cb->GetMetadata(context, meta.id, &checkMeta) ==
                          WH_ERROR_NOTFOUND);

    /* Return available and reclaimable stats after recovery */
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, bytesAvalAfter,
                                            objsAvailAfter, bytesReclAfter,
                                            objsReclAfter));
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    *dataSize = sizeof(data);
    return 0;
}


/*
 * Recover from a program failure at two points: writing the object
 * start (the metadata/start record only) and writing the object
 * count (after the data is on flash). Each scenario checks the
 * partial object is reclaimed and the live counts are consistent.
 */
int whTest_NvmRecovery(void* ctx)
{
    int      test_data_len;
    uint32_t bytesBefore, bytesAfter;
    whNvmId  objsBefore, objsAfter;
    uint32_t bytesReclBefore, bytesReclAfter;
    whNvmId  objsReclBefore, objsReclAfter;

    (void)ctx;

    WH_TEST_PRINT("--simulate failure when writing object start\n");
    WH_TEST_RETURN_ON_FAIL(_simulateFailureAndRecover(
        2 /* program epoch, metadata and fail */, &test_data_len, &bytesBefore,
        &objsBefore, &bytesReclBefore, &objsReclBefore, &bytesAfter, &objsAfter,
        &bytesReclAfter, &objsReclAfter));
    /* object should be marked as reclaimable */
    WH_TEST_ASSERT_RETURN(objsReclAfter == objsReclBefore + 1);
    /* data should not be marked as reclaimable */
    WH_TEST_ASSERT_RETURN(bytesAfter == bytesBefore);
    WH_TEST_ASSERT_RETURN(bytesReclAfter == bytesReclBefore);
    /* available object should be decremented */
    WH_TEST_ASSERT_RETURN(objsAfter == objsBefore - 1);

    WH_TEST_PRINT("--simulate failure when writing object count\n");
    WH_TEST_RETURN_ON_FAIL(_simulateFailureAndRecover(
        4 /* program epoch, metadata, start, data and fail */, &test_data_len,
        &bytesBefore, &objsBefore, &bytesReclBefore, &objsReclBefore,
        &bytesAfter, &objsAfter, &bytesReclAfter, &objsReclAfter));
    /* object should be marked as reclaimable */
    WH_TEST_ASSERT_RETURN(objsReclAfter == objsReclBefore + 1);
    /* data should be marked as reclaimable by test_data_len rounded up to
     * WHFU_BYTES_PER_UNIT */
    WH_TEST_ASSERT_RETURN(bytesAfter <= bytesBefore - test_data_len);
    WH_TEST_ASSERT_RETURN(bytesReclAfter >= bytesReclBefore);
    WH_TEST_ASSERT_RETURN(bytesReclAfter == bytesBefore - bytesAfter);
    /* available object should be decremented */
    WH_TEST_ASSERT_RETURN(objsAfter == objsBefore - 1);

    return 0;
}
