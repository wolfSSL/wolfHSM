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
#include <stddef.h>

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER)

/* core test includes */
#include "wh_test_common.h"

/* APIs to test */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_nvm_flash_log.h"
#include "wolfhsm/wh_flash_unit.h"

/* NVM simulator backends to use for testing NVM module */
#include "wolfhsm/wh_flash_ramsim.h"
/* Fault injection layer to simulate power failures */
#include "wh_test_flash_fault_inject.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <unistd.h>  /* For unlink */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define FLASH_SECTOR_SIZE (4096) /* 4KB */
#define FLASH_PAGE_SIZE (8) /* 8B */

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
static void _HexDump(const char* p, size_t data_len)
{
    const size_t         bytesPerLine = 16;
    const unsigned char  two_digits   = 0x10;
    const unsigned char* u            = (const unsigned char*)p;
    printf("    HD:%p for %lu bytes\n", p, data_len);
    if ((p == NULL) || (data_len == 0))
        return;
    size_t off = 0;
    for (off = 0; off < data_len; off++) {
        if ((off % bytesPerLine) == 0)
            printf("    ");
        if (u[off] < two_digits) {
            printf("0%X ", u[off]);
        }
        else {
            printf("%X ", u[off]);
        }
        if ((off % bytesPerLine) == (bytesPerLine - 1))
            printf("\n");
    }
    if ((off % bytesPerLine) != 0)
        printf("\n");
}

static void _ShowAvailable(const whNvmCb* cb, void* context)
{
    int       rc              = 0;
    uint32_t free_space      = 0;
    whNvmId   free_objects    = 0;
    uint32_t reclaim_space   = 0;
    whNvmId   reclaim_objects = 0;
    rc = cb->GetAvailable(context, &free_space, &free_objects, &reclaim_space,
                          &reclaim_objects);
    if (rc == 0) {
        printf("NVM %p has %u bytes, and %u objects available \n"
               "           %u bytes, and %u objects reclaimable \n",
               context, (unsigned int)free_space, (unsigned int)free_objects,
               (unsigned int)reclaim_space, (unsigned int)reclaim_objects);
    }
    else {
        printf("NVM %p failed to get available info: %d.\n", context, rc);
    }
}


static void _ShowList(const whNvmCb* cb, void* context)
{
    int rc = 0;
    /* Dump NVM contents */
    uint16_t listCount = 0;
    uint16_t id        = 0;
    do {
        listCount = 0;

        rc = cb->List(context, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_ANY,
                      id, &listCount, &id);

        if ((rc == 0) && (listCount > 0)) {
            printf("Found object id 0x%X (%d) with %d more objects\n", id, id,
                   listCount - 1);
            whNvmMetadata myMetadata;
            memset(&myMetadata, 0, sizeof(myMetadata));
            rc = cb->GetMetadata(context, id, &myMetadata);

            if (rc == 0) {

                uint8_t data[16] = {0};
                whNvmSize offset = 0;

                printf("-Id:%04hX\n-Label:%.*s\n"
                       "-Access:%04hX\n-Flags:%04hX\n-Len:%d\n",
                       myMetadata.id, (int)sizeof(myMetadata.label),
                       myMetadata.label, myMetadata.access, myMetadata.flags,
                       myMetadata.len);

                while ( (rc == 0) &&
                        ((myMetadata.len - offset) > sizeof(data))) {
                    /* Read the data from this object */
                    rc = cb->Read(context, id, offset, sizeof(data), data);

                    if (rc == 0) {
                        /* Show the data from this object */
                        _HexDump((const char*)data, (int)(sizeof(data)));
                        offset += sizeof(data);
                    }
                }
                if ((rc == 0) && (offset < myMetadata.len)) {
                    whNvmSize final = myMetadata.len - offset;
                    rc = cb->Read(context, id, offset, final, data);

                    if (rc == 0) {
                        /* Show the data from this object */
                        _HexDump((const char*)data, (int)(final));
                        offset += final;
                    }
                }
            }
        }
        else
            break;
    } while (listCount > 0);
}
#endif


static int addObjectWithReadBackCheck(const whNvmCb*     cb,
                                      void* context,
                                      whNvmMetadata* meta, whNvmSize data_len,
                                      const uint8_t* data)

{
    whNvmMetadata metaBuf = {0};
    unsigned char dataBuf[256];

    WH_TEST_RETURN_ON_FAIL(cb->AddObject(context, meta, data_len, data));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, meta->id, 0, data_len, dataBuf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta->id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta->id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(data, dataBuf, data_len));
    return 0;
}

static int destroyObjectWithReadBackCheck(const whNvmCb*     cb,
                                          whNvmFlashContext* context,
                                          whNvmId            list_count,
                                          const whNvmId*     id_list)
{
    whNvmMetadata metaBuf = {0};
    unsigned char dataBuf[256];

    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, list_count, id_list));
    /* Try to read an arbitrary ID - it should fail  */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND == cb->Read(context, id_list[0], 0,
                                                        sizeof(dataBuf),
                                                        dataBuf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, id_list[0], &metaBuf));
    return 0;
}

int whTest_Flash(const whFlashCb* fcb, void* fctx, const void* cfg)
{
    uint8_t write_bytes[8] = { 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87};
    uint8_t read_bytes[8] = {0};
    whFlashUnit write_buffer[4] = {0};
    whFlashUnit read_buffer[4] = {0};

    uint32_t partition_units = 0;

    WH_TEST_RETURN_ON_FAIL(fcb->Init(fctx, cfg));

    partition_units = wh_FlashUnit_Bytes2Units(fcb->PartitionSize(fctx)) ;

    /* Unlock the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_WriteUnlock(fcb, fctx,
            0, partition_units));

    /* Erase the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Erase(fcb, fctx,
            0, partition_units));

    /* Blank check the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_BlankCheck(fcb, fctx,
            0, partition_units));

    /* Program a few different unit sizes */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx,
            0, 1, write_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx,
            1, 2, write_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx,
            3, 3, write_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Program(fcb, fctx,
            6, 4, write_buffer));

    /* Read back and check */
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx,
            0, 1, read_buffer));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_buffer, read_buffer,
               1 * WHFU_BYTES_PER_UNIT));
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx,
            1, 2, read_buffer));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_buffer, read_buffer,
               2 * WHFU_BYTES_PER_UNIT));
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx,
            3, 3, read_buffer));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_buffer, read_buffer,
               3 * WHFU_BYTES_PER_UNIT));
    memset(read_buffer, 0, sizeof(read_buffer));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Read(fcb, fctx,
            6, 4, read_buffer));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_buffer, read_buffer,
               4 * WHFU_BYTES_PER_UNIT));

    /* Program a few different byte sizes */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                10 * WHFU_BYTES_PER_UNIT, 1, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                11 * WHFU_BYTES_PER_UNIT, 2, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                12 * WHFU_BYTES_PER_UNIT, 3, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                13 * WHFU_BYTES_PER_UNIT, 4, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                14 * WHFU_BYTES_PER_UNIT, 5, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                15 * WHFU_BYTES_PER_UNIT, 6, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                16 * WHFU_BYTES_PER_UNIT, 7, write_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                17 * WHFU_BYTES_PER_UNIT, 8, write_bytes));

    /* Read back and compare */
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                10 * WHFU_BYTES_PER_UNIT, 1, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 1));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                11 * WHFU_BYTES_PER_UNIT, 2, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 2));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                12 * WHFU_BYTES_PER_UNIT, 3, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 3));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                13 * WHFU_BYTES_PER_UNIT, 4, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 4));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                14 * WHFU_BYTES_PER_UNIT, 5, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 5));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                15 * WHFU_BYTES_PER_UNIT, 6, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 6));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                16 * WHFU_BYTES_PER_UNIT, 7, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 7));
    memset(read_bytes, 0, sizeof(read_bytes));
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                17 * WHFU_BYTES_PER_UNIT, 8, read_bytes));
    WH_TEST_RETURN_ON_FAIL(memcmp(write_bytes, read_bytes, 8));

    /* Erase the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_Erase(fcb, fctx,
            0, partition_units));

    /* Blank check the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_BlankCheck(fcb, fctx,
            0, partition_units));

    /* Lock the first partition */
    WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_WriteLock(fcb, fctx,
            0, partition_units));

    WH_TEST_RETURN_ON_FAIL(fcb->Cleanup(fctx));

    return 0;
}

int whTest_NvmFlashCfg(void* cfg, void* context, const whNvmCb *cb)
{
    int               ret        = 0;

    WH_TEST_RETURN_ON_FAIL(cb->Init(context, cfg));

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    printf("--Initial NVM contents\n");
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Add 3 new Objects */
    unsigned char data1[]   = "Data1";
    unsigned char data2[]   = "Data2";
    unsigned char data3[]   = "Data3";
    unsigned char update1[] = "Update1fdsafdasfdsafdsafdsafdsafdasfdasfd";
    unsigned char update2[] = "Update2fdafdafdafdsafdsafdasfd";
    unsigned char update3[] =
        "Update3fdsafdsafdafdafdafdafdafdafdafdsfadfdsfadsafdsafdasfdsa";
    whNvmId id1   = 100;
    whNvmId id2   = 400;
    whNvmId id3   = 300;
    whNvmId ids[] = {id1, id2, id3};

    whNvmMetadata meta1 = {.id = ids[0], .label = "Label1"};
    whNvmMetadata meta2 = {.id = ids[1], .label = "Label2"};
    whNvmMetadata meta3 = {.id = ids[2], .label = "Label3"};


    /* Add 3 objects, checking for each object that we can read back what was
     * written */
    printf("--Adding 3 new objects\n");
    ret = addObjectWithReadBackCheck(cb, context, &meta1, sizeof(data1), data1);
    if (ret != 0) {
        goto cleanup;
    }
    ret = addObjectWithReadBackCheck(cb, context, &meta2, sizeof(data2), data2);
    if (ret != 0) {
        goto cleanup;
    }
    ret = addObjectWithReadBackCheck(cb, context, &meta3, sizeof(data3), data3);
    if (ret != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Overwrite an existing Object */
    printf("--Overwrite an existing object\n");
    ret = addObjectWithReadBackCheck(cb, context, &meta1, sizeof(update1),
                                     update1);
    if (ret != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Overwrite an existing Object twice */
    printf("--Overwrite an existing object again \n");
    ret = addObjectWithReadBackCheck(cb, context, &meta2, sizeof(update2),
                                     update2);
    if (ret != 0) {
        goto cleanup;
    }

    printf("--Overwrite an existing object with new data\n");
    ret = addObjectWithReadBackCheck(cb, context, &meta2, sizeof(update3),
                                     update3);
    if (ret != 0) {
        goto cleanup;
    }


#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Regenerate */
    printf("--Reclaim space\n");
    if ((ret = cb->DestroyObjects(context, 0, NULL)) != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Ensure reclamation doesn't destroy active objects */
    {
        whNvmMetadata metaBuf = {0};
        unsigned char dataBuf[256];
        size_t i = 0;
        printf("--Read IDs after reclaim\n");
        for (i=0; i<sizeof(ids)/sizeof(ids[0]); i++) {
            if ((ret = cb->GetMetadata(context, ids[i], &metaBuf)) != 0) {
                WH_ERROR_PRINT("GetMetadata after reclaim returned %d\n", ret);
                goto cleanup;
            }

            if ((ret = cb->Read(context, ids[i], 0, metaBuf.len, dataBuf)) != 0) {
                WH_ERROR_PRINT("Read after reclaim returned %d\n", ret);
                goto cleanup;
            }
        }
    }

    /* Destroy 1 object */
    printf("--Destroy 1 object\n");

    if ((ret = destroyObjectWithReadBackCheck(cb, context, 1, ids)) != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Attempt to destroy 3 objects, of which one has been already destroyed.
     * This should not cause an error */
    printf("--Destroy 3 objects\n");
    if ((ret = destroyObjectWithReadBackCheck(
             cb, context, sizeof(ids) / sizeof(ids[0]), ids)) != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    printf("--Done\n");

cleanup:
    /* Don't overwrite an already failed return code? */
    if (ret == 0) {
        WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    }
    else {
        (void)cb->Cleanup(context);
    }

    return ret;
}


int whTest_NvmFlash_RamSim(void)
{
    /* HAL Flash state and configuration */
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    const whFlashCb  myCb[1]          = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx myHalFlashCtx[1] = {0};
    whFlashRamsimCfg myHalFlashCfg[1] = {{
        .size       = FLASH_RAM_SIZE,    /* 1MB  Flash */
        .sectorSize = FLASH_SECTOR_SIZE, /* 4KB  Sector Size */
        .pageSize   = FLASH_PAGE_SIZE,   /* 8B   Page Size */
        .erasedByte = (uint8_t)0,
        .memory     = memory,
    }};

    WH_TEST_RETURN_ON_FAIL(whTest_Flash(myCb, myHalFlashCtx, myHalFlashCfg));

    /* NVM Configuration using PosixSim HAL Flash */
    whNvmFlashConfig myNvmCfg = {
        .cb      = myCb,
        .context = myHalFlashCtx,
        .config  = myHalFlashCfg,
    };
    whNvmFlashContext nvmFlashCtx[1] = {0};
    const whNvmCb    nvmFlashCb[1]     = {WH_NVM_FLASH_CB};

    WH_TEST_RETURN_ON_FAIL(whTest_NvmFlashCfg(&myNvmCfg, nvmFlashCtx, nvmFlashCb));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    whNvmFlashLogConfig myLogCfg = {
        .flash_cb  = myCb,
        .flash_ctx = myHalFlashCtx,
        .flash_cfg = myHalFlashCfg,
    };
    whNvmFlashLogContext nvmLogCtx[1] = {0};
    const whNvmCb        nvmLogCb[1]     = {WH_NVM_FLASH_LOG_CB};
    WH_TEST_RETURN_ON_FAIL(whTest_NvmFlashCfg(&myLogCfg, nvmLogCtx, nvmLogCb));
#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */

    return 0;

}

static int
simulateFailureAndRecover(int failAfter, int* dataSize,
                          uint32_t* bytesAvalBefore, whNvmId* objsAvailBefore,
                          uint32_t* bytesReclBefore, whNvmId* objsReclBefore,
                          uint32_t* bytesAvalAfter, whNvmId* objsAvailAfter,
                          uint32_t* bytesReclAfter, whNvmId* objsReclAfter)
{
    uint8_t           memory[FLASH_RAM_SIZE]       = {0};
    uint8_t           backupMemory[FLASH_RAM_SIZE] = {0};
    unsigned char     data[]      = "This is test data for recovery test";
    whNvmMetadata     meta        = {.id = 42, .label = "RecoveryTest"};
    const whFlashCb   flashCb[1]  = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx  flashCtx[1] = {0};
    whFlashRamsimCfg  flashCfg[1] = {{
         .size       = FLASH_RAM_SIZE,    /* 1MB  Flash */
         .sectorSize = FLASH_SECTOR_SIZE, /* 4KB  Sector Size */
         .pageSize   = FLASH_PAGE_SIZE,   /* 8B   Page Size */
         .erasedByte = (uint8_t)0,
         .memory     = memory,
    }};
    const whFlashCb   flashFaultInjCb[1] = {WH_FLASH_FAULTINJECT_CB};
    whFlashFaultInjectCtx  faultInjCtx[1] = {0};
    whFlashFaultInjectCfg  faultInjCfg[1] = {{
        .realCb = flashCb,
        .realCtx = flashCtx,
        .realCfg = flashCfg,
    }};
    const whNvmCb     cb[1]       = {WH_NVM_FLASH_CB};
    whNvmFlashContext context[1]  = {0};
    whNvmFlashConfig  cfg         = {
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
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);

    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    /* clean-up the memory */
    memset(memory, 0, FLASH_RAM_SIZE);

    flashCfg->initData = backupMemory;
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

int whTest_NvmFlash_Recovery(void)
{
    int      test_data_len;
    uint32_t bytesBefore, bytesAfter;
    whNvmId  objsBefore, objsAfter;
    uint32_t bytesReclBefore, bytesReclAfter;
    whNvmId  objsReclBefore, objsReclAfter;

    printf("--simulate failure when writing object start\n");
    WH_TEST_RETURN_ON_FAIL(simulateFailureAndRecover(
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

    printf("--simulate failure when writing object count\n");
    WH_TEST_RETURN_ON_FAIL(simulateFailureAndRecover(
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

#if defined(WOLFHSM_CFG_TEST_POSIX)

int whTest_NvmFlash_PosixFileSim(void)
{
    /* HAL Flash state and configuration */
    const whFlashCb       myCb[1]              = {POSIX_FLASH_FILE_CB};
    posixFlashFileContext myHalFlashContext[1] = {0};
    posixFlashFileConfig  myHalFlashConfig[1]  = {{
          .filename       = "myNvm.bin",
          .partition_size = 16384,
          .erased_byte    = (~(uint8_t)0),
    }};

    WH_TEST_RETURN_ON_FAIL(whTest_Flash(myCb, myHalFlashContext,
            myHalFlashConfig));

    /* NVM Configuration using PosixSim HAL Flash */
    whNvmFlashConfig myNvmCfg = {
        .cb      = myCb,
        .context = myHalFlashContext,
        .config  = myHalFlashConfig,
    };
    whNvmFlashContext nvmFlashCtx[1] = {0};
    const whNvmCb    nvmFlashCb[1]     = {WH_NVM_FLASH_CB};

    WH_TEST_ASSERT(0 == whTest_NvmFlashCfg(&myNvmCfg, nvmFlashCtx, nvmFlashCb));


    unlink(myHalFlashConfig[0].filename);

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    WH_TEST_ASSERT(myHalFlashConfig[0].partition_size >=
                   WH_NVM_FLASH_LOG_PARTITION_SIZE);
    myHalFlashConfig[0].partition_size = WH_NVM_FLASH_LOG_PARTITION_SIZE;
    memset(myHalFlashContext, 0, sizeof(myHalFlashContext));
    whNvmFlashLogConfig myLogCfg = {
        .flash_cb  = myCb,
        .flash_ctx = myHalFlashContext,
        .flash_cfg = myHalFlashConfig,
    };
    whNvmFlashLogContext nvmLogCtx[1] = {0};
    const whNvmCb        nvmLogCb[1]     = {WH_NVM_FLASH_LOG_CB};
    WH_TEST_RETURN_ON_FAIL(whTest_NvmFlashCfg(&myLogCfg, nvmLogCtx, nvmLogCb));
#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */

    /* Remove the configured file on success*/
    unlink(myHalFlashConfig[0].filename);
    return 0;
}

#endif


int whTest_NvmFlash(void)
{
    printf("Testing NVM flash with RAM sim...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_RamSim());

    printf("Testing NVM flash recovery mechanism...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_Recovery());

#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing NVM flash with POSIX file sim...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_PosixFileSim());
#endif

    return 0;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
