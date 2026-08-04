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
#include "wolfhsm/wh_utils.h"

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
 * Two flash images shared by the recovery and CRC tests: one live
 * backing store and one snapshot replayed as init data to model a
 * reboot over a dirty flash. File-static to keep 2 MB off the stack.
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
 * Interrupt an add while a committed object is already in the partition,
 * then verify the reloaded directory accounts for both data regions and
 * places new objects after them.
 */
static int _simulateFailureWithPrecedingObject(void)
{
    const whFlashCb       flashCb[1]         = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx      flashCtx[1]        = {0};
    whFlashRamsimCfg      flashCfg[1]        = {{
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
    const whNvmCb         cb[1]              = {WH_NVM_FLASH_CB};
    whNvmFlashContext     context[1]         = {0};
    whNvmFlashConfig      cfg                = {
                            .cb      = flashFaultInjCb,
                            .context = faultInjCtx,
                            .config  = faultInjCfg,
    };
    whNvmMetadata firstMeta = {.id = 50, .label = "RecoveryFirst"};
    whNvmMetadata intrMeta  = {.id = 51, .label = "RecoveryIntr"};
    whNvmMetadata postMeta  = {.id = 52, .label = "RecoveryPost"};
    whNvmMetadata checkMeta = {0};
    uint8_t       firstData[64];
    uint8_t       intrData[40];
    uint8_t       postData[40];
    uint8_t       readBuf[64];
    uint32_t      availStart    = 0;
    uint32_t      availAfter    = 0;
    uint32_t      reclaimAfter  = 0;
    whNvmId       objsStart     = 0;
    whNvmId       objsAfter     = 0;
    whNvmId       objsReclAfter = 0;
    uint32_t      i             = 0;

    for (i = 0; i < sizeof(firstData); i++) {
        firstData[i] = (uint8_t)(0x11 ^ (i * 7));
    }
    for (i = 0; i < sizeof(intrData); i++) {
        intrData[i] = (uint8_t)(0x22 ^ (i * 3));
        postData[i] = (uint8_t)(0x33 ^ (i * 5));
    }

    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
    WH_TEST_RETURN_ON_FAIL(
        cb->GetAvailable(context, &availStart, &objsStart, NULL, NULL));

    /* Commit one object so the interrupted entry's data starts at a nonzero
     * offset */
    WH_TEST_RETURN_ON_FAIL(cb->AddObject(
        context, &firstMeta, (whNvmSize)sizeof(firstData), firstData));

    /* Interrupt the next add at the count-word program (5th program: epoch,
     * metadata, start, data, count) */
    faultInjCtx->failAfterPrograms = 5;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          cb->AddObject(context, &intrMeta,
                                        (whNvmSize)sizeof(intrData), intrData));

    /* Reboot onto the dirty flash */
    memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(_recoveryMemory, 0, NVM_FLASH_SIZE);
    flashCfg->initData = _recoveryBackup;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));

    /* Committed object is intact, interrupted one is hidden */
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, firstMeta.id, 0,
                                    (whNvmSize)sizeof(firstData), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(firstData, readBuf, sizeof(firstData)));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, intrMeta.id, &checkMeta));

    /* Both data regions are accounted: the committed object as used, the
     * interrupted one as reserved and reclaimable */
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availAfter, &objsAfter,
                                            &reclaimAfter, &objsReclAfter));
    WH_TEST_ASSERT_RETURN(availAfter ==
                          availStart - sizeof(firstData) - sizeof(intrData));
    WH_TEST_ASSERT_RETURN(objsAfter == objsStart - 2);
    WH_TEST_ASSERT_RETURN(reclaimAfter == sizeof(intrData));
    WH_TEST_ASSERT_RETURN(objsReclAfter == 1);

    /* A new add lands after both regions instead of on top of them */
    WH_TEST_RETURN_ON_FAIL(cb->AddObject(
        context, &postMeta, (whNvmSize)sizeof(postData), postData));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, postMeta.id, 0,
                                    (whNvmSize)sizeof(postData), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(postData, readBuf, sizeof(postData)));
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    return 0;
}


/*
 * Recover from a program failure at two points: writing the object
 * start (the metadata/start record only) and writing the object
 * count (after the data is on flash). Each scenario checks the
 * partial object is reclaimed and the live counts are consistent.
 * Also repeats the count-word interruption with a committed object
 * already in the partition, pinning the recovered start offset.
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

    WH_TEST_PRINT("--simulate failure after a committed object\n");
    WH_TEST_RETURN_ON_FAIL(_simulateFailureWithPrecedingObject());

    return 0;
}


/* ---- NVM CRC16 integrity ---- */

#if defined(WOLFHSM_CFG_NVM_FLASH_CRC16)

/* Find needle in haystack. Returns byte offset or -1 if not found */
static int _findFlashPattern(const uint8_t* haystack, uint32_t hay_len,
                             const uint8_t* needle, uint32_t needle_len)
{
    uint32_t i;

    if ((needle_len == 0) || (needle_len > hay_len)) {
        return -1;
    }
    for (i = 0; i <= hay_len - needle_len; i++) {
        if (memcmp(&haystack[i], needle, needle_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int _crc16Vectors(void)
{
    const char* check = "123456789";
    uint16_t    crc;
    uint16_t    crc_split;

    /* Known CRC-16/CCITT-FALSE check value */
    crc = wh_Utils_Crc16(WH_UTILS_CRC16_INIT, check, 9);
    WH_TEST_ASSERT_RETURN(crc == 0x29B1);

    /* Incremental computation matches one-shot */
    crc_split = wh_Utils_Crc16(WH_UTILS_CRC16_INIT, check, 4);
    crc_split = wh_Utils_Crc16(crc_split, check + 4, 5);
    WH_TEST_ASSERT_RETURN(crc_split == crc);

    /* Zero length returns the seed */
    WH_TEST_ASSERT_RETURN(wh_Utils_Crc16(WH_UTILS_CRC16_INIT, check, 0) ==
                          WH_UTILS_CRC16_INIT);
    WH_TEST_ASSERT_RETURN(wh_Utils_Crc16(WH_UTILS_CRC16_INIT, NULL, 0) ==
                          WH_UTILS_CRC16_INIT);
    /* NULL data is treated as zero length regardless of len */
    WH_TEST_ASSERT_RETURN(wh_Utils_Crc16(WH_UTILS_CRC16_INIT, NULL, 5) ==
                          WH_UTILS_CRC16_INIT);
    return 0;
}
#endif /* WOLFHSM_CFG_NVM_FLASH_CRC16 */


/*
 * CRC16 integrity checks in the NVM flash backend: corrupted object
 * data is caught on full reads and reclaim copies, corrupted metadata
 * is caught when the directory is loaded, and metadata-only objects
 * keep working. Also checks a failed destroy leaves the cached
 * directory matching flash, an interrupted write with corrupt
 * metadata blocks new writes until compaction reclaims it, and a
 * corrupt overwrite resurrects the previous version. Skipped unless
 * built with WOLFHSM_CFG_NVM_FLASH_CRC16.
 */
int whTest_NvmCrc16(void* ctx)
{
    (void)ctx;
#if defined(WOLFHSM_CFG_NVM_FLASH_CRC16)
    {
        const whFlashCb   flashCb[1]  = {WH_FLASH_RAMSIM_CB};
        whFlashRamsimCtx  flashCtx[1] = {0};
        whFlashRamsimCfg  flashCfg[1] = {{
             .size       = NVM_FLASH_SIZE,
             .sectorSize = NVM_FLASH_SECTOR_SZ,
             .pageSize   = NVM_FLASH_PAGE_SZ,
             .erasedByte = (uint8_t)0,
             .memory     = _recoveryMemory,
        }};
        const whNvmCb     cb[1]       = {WH_NVM_FLASH_CB};
        whNvmFlashContext context[1]  = {0};
        whNvmFlashConfig  cfg         = {
                     .cb      = flashCb,
                     .context = flashCtx,
                     .config  = flashCfg,
        };

        /* Fault-injecting flash wrapper for the interrupted-write scenario */
        const whFlashCb       flashFaultInjCb[1] = {WH_FLASH_FAULTINJECT_CB};
        whFlashFaultInjectCtx faultInjCtx[1]     = {0};
        whFlashFaultInjectCfg faultInjCfg[1]     = {{
                .realCb  = flashCb,
                .realCtx = flashCtx,
                .realCfg = flashCfg,
        }};
        whNvmFlashConfig      faultCfg           = {
                           .cb      = flashFaultInjCb,
                           .context = faultInjCtx,
                           .config  = faultInjCfg,
        };

        uint8_t       dataPattern[100];
        uint8_t       readBuf[100];
        whNvmMetadata dataMeta    = {.id = 200, .label = "CrcDataTest"};
        whNvmMetadata metaMeta    = {.id = 201, .label = "CrcMetaTest"};
        whNvmMetadata goodMeta    = {.id = 202, .label = "CrcGoodTest"};
        whNvmMetadata cntrMeta    = {.id = 203, .label = "CrcCounterTest"};
        whNvmMetadata keepMeta    = {.id = 210, .label = "CrcKeepTest"};
        whNvmMetadata badCopyMeta = {.id = 211, .label = "CrcBadCopyTest"};
        whNvmMetadata intrMeta    = {.id = 212, .label = "CrcIntrTest"};
        whNvmMetadata postMeta    = {.id = 213, .label = "CrcPostTest"};
        whNvmMetadata lenMeta     = {.id = 214, .label = "CrcLenTest"};
        whNvmMetadata v1Meta      = {.id = 220, .label = "CrcResurrectV1"};
        whNvmMetadata v2Meta      = {.id = 220, .label = "CrcResurrectV2"};
        whNvmMetadata metaBuf     = {0};
        unsigned char metaData[]  = "MetaTestData";
        unsigned char goodData[]  = "GoodObjectData";
        unsigned char keepData[]  = "KeepThisObject";
        unsigned char v1Data[]    = "ResurrectV1Data";
        unsigned char v2Data[]    = "ResurrectV2Data!";
        uint8_t       intrData[40];
        uint8_t       postData[40];
        whNvmId       destroyId      = 0;
        uint32_t      availBytes     = 0;
        uint32_t      reclaimBytes   = 0;
        whNvmId       availObjects   = 0;
        whNvmId       reclaimObjects = 0;
        int           offset         = -1;
        uint32_t      i              = 0;

        WH_TEST_RETURN_ON_FAIL(_crc16Vectors());

        for (i = 0; i < sizeof(dataPattern); i++) {
            dataPattern[i] = (uint8_t)(0x5A ^ (i * 7));
        }
        for (i = 0; i < sizeof(intrData); i++) {
            intrData[i] = (uint8_t)(0xA5 ^ (i * 3));
            postData[i] = (uint8_t)(0x3C ^ (i * 5));
        }

        WH_TEST_PRINT("--CRC16: data corruption detection\n");
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &dataMeta, (whNvmSize)sizeof(dataPattern), dataPattern));

        /* Full read is verified and passes */
        WH_TEST_RETURN_ON_FAIL(cb->Read(
            context, dataMeta.id, 0, (whNvmSize)sizeof(dataPattern), readBuf));
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(dataPattern, readBuf, sizeof(dataPattern)));

        /* Corrupt one data byte directly in the simulated flash */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE, dataPattern,
                                   (uint32_t)sizeof(dataPattern));
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset + 50] ^= 0xFF;

        /* Full read fails CRC. Partial reads are not verified */
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTVERIFIED ==
                              cb->Read(context, dataMeta.id, 0,
                                       (whNvmSize)sizeof(dataPattern),
                                       readBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, dataMeta.id, 0,
                                        (whNvmSize)sizeof(dataPattern) - 1,
                                        readBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, dataMeta.id, 1,
                                        (whNvmSize)sizeof(dataPattern) - 1,
                                        readBuf));
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, dataMeta.id, &metaBuf));

        /* Reclaim must abort when copying the corrupt object */
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTVERIFIED ==
                              cb->DestroyObjects(context, 0, NULL));
        /* Active partition is untouched: object still present */
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, dataMeta.id, &metaBuf));

        /* Restore the byte: read and reclaim work again */
        _recoveryMemory[offset + 50] ^= 0xFF;
        WH_TEST_RETURN_ON_FAIL(cb->Read(
            context, dataMeta.id, 0, (whNvmSize)sizeof(dataPattern), readBuf));
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));

        /* Read back from the new partition, re-verified after the copy */
        WH_TEST_RETURN_ON_FAIL(cb->Read(
            context, dataMeta.id, 0, (whNvmSize)sizeof(dataPattern), readBuf));
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(dataPattern, readBuf, sizeof(dataPattern)));
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        WH_TEST_PRINT("--CRC16: metadata corruption detection\n");
        flashCfg->initData = NULL;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &metaMeta, (whNvmSize)sizeof(metaData), metaData));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &goodMeta, (whNvmSize)sizeof(goodData), goodData));

        /* Corrupt one on-flash label byte of the first object */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE,
                                   (const uint8_t*)"CrcMetaTest", 11);
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset + 3] ^= 0xFF;

        /* Reload the directory from flash to force verification */
        memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
        memset(_recoveryMemory, 0, NVM_FLASH_SIZE);
        flashCfg->initData = _recoveryBackup;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        flashCfg->initData = NULL;

        /* Corrupt object is hidden, healthy object is intact */
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, metaMeta.id, &metaBuf));
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->Read(context, metaMeta.id, 0,
                                       (whNvmSize)sizeof(metaData), readBuf));
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, goodMeta.id, &metaBuf));

        /* Corrupt entry is accounted as reclaimable */
        WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes,
                                                &availObjects, &reclaimBytes,
                                                &reclaimObjects));
        WH_TEST_ASSERT_RETURN(reclaimObjects >= 1);
        WH_TEST_ASSERT_RETURN(reclaimBytes >= sizeof(metaData));

        /* Compaction drops the corrupt object and keeps the healthy one */
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, metaMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, goodMeta.id, 0,
                                        (whNvmSize)sizeof(goodData), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(goodData, readBuf, sizeof(goodData)));
        WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes,
                                                &availObjects, &reclaimBytes,
                                                &reclaimObjects));
        WH_TEST_ASSERT_RETURN(reclaimObjects == 0);

        /* Freed slot and data are reusable */
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &metaMeta, (whNvmSize)sizeof(metaData), metaData));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, metaMeta.id, 0,
                                        (whNvmSize)sizeof(metaData), readBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        WH_TEST_PRINT("--CRC16: metadata-only object\n");
        flashCfg->initData = NULL;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(context, &cntrMeta, 0, NULL));
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, cntrMeta.id, &metaBuf));
        WH_TEST_ASSERT_RETURN(metaBuf.len == 0);
        /* Zero-length objects have no readable data */
        WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                              cb->Read(context, cntrMeta.id, 0, 0, readBuf));
        /* Survives compaction with a vacuous data CRC */
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, cntrMeta.id, &metaBuf));

        /* Metadata CRC still protects it */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE,
                                   (const uint8_t*)"CrcCounterTest", 14);
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset + 3] ^= 0xFF;
        memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
        memset(_recoveryMemory, 0, NVM_FLASH_SIZE);
        flashCfg->initData = _recoveryBackup;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        flashCfg->initData = NULL;
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, cntrMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        WH_TEST_PRINT("--CRC16: failed destroy leaves directory intact\n");
        flashCfg->initData = NULL;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &keepMeta, (whNvmSize)sizeof(keepData), keepData));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(context, &badCopyMeta,
                                             (whNvmSize)sizeof(dataPattern),
                                             dataPattern));

        /* Corrupt one data byte of the object that is NOT being destroyed */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE, dataPattern,
                                   (uint32_t)sizeof(dataPattern));
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset + 10] ^= 0xFF;

        /* Destroy fails when the reclaim copies the corrupt object */
        destroyId = keepMeta.id;
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTVERIFIED ==
                              cb->DestroyObjects(context, 1, &destroyId));

        /* The requested object must still be present and readable */
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, keepMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, keepMeta.id, 0,
                                        (whNvmSize)sizeof(keepData), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(keepData, readBuf, sizeof(keepData)));
        /* The corrupt object is still visible too */
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTVERIFIED ==
                              cb->Read(context, badCopyMeta.id, 0,
                                       (whNvmSize)sizeof(dataPattern),
                                       readBuf));

        /* Destroying the corrupt object itself succeeds (it is not copied)
         * and must not drop the object whose destroy failed earlier */
        destroyId = badCopyMeta.id;
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 1, &destroyId));
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_NOTFOUND ==
            cb->GetMetadata(context, badCopyMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, keepMeta.id, 0,
                                        (whNvmSize)sizeof(keepData), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(keepData, readBuf, sizeof(keepData)));
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        WH_TEST_PRINT("--CRC16: interrupted write with corrupt metadata\n");
        flashCfg->initData = NULL;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));

        /* Interrupt an add at the count-word program (5th program: epoch,
         * metadata, start, data, count), leaving its data on flash */
        faultInjCtx->failAfterPrograms = 5;
        WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                              cb->AddObject(context, &intrMeta,
                                            (whNvmSize)sizeof(intrData),
                                            intrData));

        /* Also corrupt one on-flash label byte of the interrupted entry */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE,
                                   (const uint8_t*)"CrcIntrTest", 11);
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset + 3] ^= 0xFF;

        /* Reload the directory from flash */
        memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
        memset(_recoveryMemory, 0, NVM_FLASH_SIZE);
        flashCfg->initData = _recoveryBackup;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));
        flashCfg->initData = NULL;

        /* Entry is hidden. Without trusted metadata its extent is unknown,
         * so the rest of the data area is reserved and new writes are
         * refused */
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, intrMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes,
                                                &availObjects, &reclaimBytes,
                                                &reclaimObjects));
        WH_TEST_ASSERT_RETURN(availBytes == 0);
        WH_TEST_ASSERT_RETURN(reclaimObjects >= 1);
        WH_TEST_ASSERT_RETURN(reclaimBytes >= sizeof(intrData));
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE ==
                              cb->AddObject(context, &postMeta,
                                            (whNvmSize)sizeof(postData),
                                            postData));

        /* Compaction reclaims the interrupted entry and unblocks writes */
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, intrMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &postMeta, (whNvmSize)sizeof(postData), postData));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, postMeta.id, 0,
                                        (whNvmSize)sizeof(postData), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(postData, readBuf, sizeof(postData)));
        WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes,
                                                &availObjects, &reclaimBytes,
                                                &reclaimObjects));
        WH_TEST_ASSERT_RETURN(reclaimObjects == 0);
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        WH_TEST_PRINT("--CRC16: interrupted write with corrupt length\n");
        flashCfg->initData = NULL;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));

        /* Interrupt an add at the count-word program, as above */
        faultInjCtx->failAfterPrograms = 5;
        WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                              cb->AddObject(context, &lenMeta,
                                            (whNvmSize)sizeof(intrData),
                                            intrData));

        /* Under-report the entry's on-flash length: len is the two bytes
         * before the label, which starts at metadata byte 8 */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE,
                                   (const uint8_t*)"CrcLenTest", 10);
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset - 2] = 1;
        _recoveryMemory[offset - 1] = 0;

        /* Reload the directory from flash */
        memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
        memset(_recoveryMemory, 0, NVM_FLASH_SIZE);
        flashCfg->initData = _recoveryBackup;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));
        flashCfg->initData = NULL;

        /* The corrupt length is not trusted: a new add must not land on the
         * entry's partially written data, so writes are refused instead */
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, lenMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes,
                                                &availObjects, &reclaimBytes,
                                                &reclaimObjects));
        WH_TEST_ASSERT_RETURN(availBytes == 0);
        WH_TEST_ASSERT_RETURN(reclaimObjects >= 1);
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE ==
                              cb->AddObject(context, &postMeta,
                                            (whNvmSize)sizeof(postData),
                                            postData));

        /* Compaction reclaims the entry and unblocks writes */
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              cb->GetMetadata(context, lenMeta.id, &metaBuf));
        WH_TEST_RETURN_ON_FAIL(cb->AddObject(
            context, &postMeta, (whNvmSize)sizeof(postData), postData));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, postMeta.id, 0,
                                        (whNvmSize)sizeof(postData), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(postData, readBuf, sizeof(postData)));
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        WH_TEST_PRINT("--CRC16: corrupt overwrite resurrects previous "
                      "version\n");
        flashCfg->initData = NULL;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        WH_TEST_RETURN_ON_FAIL(
            cb->AddObject(context, &v1Meta, (whNvmSize)sizeof(v1Data), v1Data));
        WH_TEST_RETURN_ON_FAIL(
            cb->AddObject(context, &v2Meta, (whNvmSize)sizeof(v2Data), v2Data));

        /* In session the overwrite is authoritative */
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, v2Meta.id, 0,
                                        (whNvmSize)sizeof(v2Data), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(v2Data, readBuf, sizeof(v2Data)));

        /* Corrupt one on-flash label byte of the newest copy */
        offset = _findFlashPattern(_recoveryMemory, NVM_FLASH_SIZE,
                                   (const uint8_t*)"CrcResurrectV2", 14);
        WH_TEST_ASSERT_RETURN(offset >= 0);
        _recoveryMemory[offset + 3] ^= 0xFF;

        /* Reload the directory from flash */
        memcpy(_recoveryBackup, _recoveryMemory, NVM_FLASH_SIZE);
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
        memset(_recoveryMemory, 0, NVM_FLASH_SIZE);
        flashCfg->initData = _recoveryBackup;
        WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
        flashCfg->initData = NULL;

        /* Documented caveat: with the newest copy corrupt, the previous
         * version becomes visible again */
        WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, v1Meta.id, &metaBuf));
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(metaBuf.label, v1Meta.label, sizeof(metaBuf.label)));
        WH_TEST_ASSERT_RETURN(metaBuf.len == sizeof(v1Data));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, v1Meta.id, 0,
                                        (whNvmSize)sizeof(v1Data), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(v1Data, readBuf, sizeof(v1Data)));

        /* The corrupt newest copy is reclaimable; compaction drops it and
         * the previous version remains */
        WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes,
                                                &availObjects, &reclaimBytes,
                                                &reclaimObjects));
        WH_TEST_ASSERT_RETURN(reclaimObjects == 1);
        WH_TEST_ASSERT_RETURN(reclaimBytes >= sizeof(v2Data));
        WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
        WH_TEST_RETURN_ON_FAIL(cb->Read(context, v1Meta.id, 0,
                                        (whNvmSize)sizeof(v1Data), readBuf));
        WH_TEST_ASSERT_RETURN(0 == memcmp(v1Data, readBuf, sizeof(v1Data)));
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

        return 0;
    }
#else
    return WH_TEST_SKIPPED;
#endif /* WOLFHSM_CFG_NVM_FLASH_CRC16 */
}
