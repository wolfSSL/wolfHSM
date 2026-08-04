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
#include "wolfhsm/wh_utils.h"

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

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
static void _HexDump(const char* p, size_t data_len)
{
    const size_t         bytesPerLine = 16;
    const unsigned char  two_digits   = 0x10;
    const unsigned char* u            = (const unsigned char*)p;

    WH_TEST_DEBUG_PRINT("    HD:%p for %lu bytes\n", p, data_len);
    if ((p == NULL) || (data_len == 0))
        return;

    size_t off = 0;
    for (off = 0; off < data_len; off++) {
        if ((off % bytesPerLine) == 0)
            WH_TEST_PRINT("    ");
        if (u[off] < two_digits) {
            WH_TEST_PRINT("0%X ", u[off]);
        }
        else {
            WH_TEST_PRINT("%X ", u[off]);
        }
        if ((off % bytesPerLine) == (bytesPerLine - 1))
            WH_TEST_PRINT("\n");
    }
    if ((off % bytesPerLine) != 0)
        WH_TEST_PRINT("\n");
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
        WH_TEST_DEBUG_PRINT("NVM %p has %u bytes, and %u objects available \n"
               "           %u bytes, and %u objects reclaimable \n",
               context, (unsigned int)free_space, (unsigned int)free_objects,
               (unsigned int)reclaim_space, (unsigned int)reclaim_objects);
    }
    else {
        WH_TEST_DEBUG_PRINT("NVM %p failed to get available info: %d.\n", context, rc);
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
            WH_TEST_DEBUG_PRINT("Found object id 0x%X (%d) with %d more objects\n", id, id,
                   listCount - 1);
            whNvmMetadata myMetadata;
            memset(&myMetadata, 0, sizeof(myMetadata));
            rc = cb->GetMetadata(context, id, &myMetadata);

            if (rc == 0) {

                uint8_t data[16] = {0};
                whNvmSize offset = 0;

                WH_TEST_DEBUG_PRINT("-Id:%04hX\n-Label:%.*s\n"
                       "-Access:%04hX\n-Flags:%04hX\n-Len:%d\n",
                       myMetadata.id, (int)sizeof(myMetadata.label),
                       myMetadata.label, myMetadata.access, myMetadata.flags,
                       myMetadata.len);

                while ((rc == 0) &&
                       ((myMetadata.len - offset) > (whNvmSize)sizeof(data))) {
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


static int addObjectWithReadBackCheck(const whNvmCb* cb, void* context,
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

    /* Test unaligned ReadBytes (exercises the offset_rem != 0 path) */
    {
        uint8_t pattern[WHFU_BYTES_PER_UNIT * 4];
        uint8_t readback[WHFU_BYTES_PER_UNIT * 4];
        uint32_t base_unit = 20;
        uint32_t i;

        for (i = 0; i < sizeof(pattern); i++) {
            pattern[i] = (uint8_t)(0x10 + i);
        }

        /* Program 4 full units at base_unit */
        WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ProgramBytes(fcb, fctx,
                    base_unit * WHFU_BYTES_PER_UNIT, sizeof(pattern), pattern));

        /* offset_rem = 3: should read pattern[3..7] */
        memset(readback, 0, sizeof(readback));
        WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                    base_unit * WHFU_BYTES_PER_UNIT + 3, 5, readback));
        WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[3], 5));

        /* offset_rem = 1: should read pattern[1..10] */
        memset(readback, 0, sizeof(readback));
        WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                    base_unit * WHFU_BYTES_PER_UNIT + 1, 10, readback));
        WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[1], 10));

        /* offset_rem = 5: should read pattern[5..7] */
        memset(readback, 0, sizeof(readback));
        WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                    base_unit * WHFU_BYTES_PER_UNIT + 5, 3, readback));
        WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[5], 3));

        /* Full 3-phase read: leading partial + aligned middle + trailing
         * offset_rem = 2, len = 21: 6 leading + 8 aligned + 7 trailing */
        memset(readback, 0, sizeof(readback));
        WH_TEST_RETURN_ON_FAIL(wh_FlashUnit_ReadBytes(fcb, fctx,
                    base_unit * WHFU_BYTES_PER_UNIT + 2, 21, readback));
        WH_TEST_ASSERT_RETURN(0 == memcmp(readback, &pattern[2], 21));
    }

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

int whTest_NvmFlashCfg(void* cfg, void* context, const whNvmCb* cb)
{
    int               ret        = 0;

    WH_TEST_RETURN_ON_FAIL(cb->Init(context, cfg));

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    WH_TEST_DEBUG_PRINT("--Initial NVM contents\n");
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
    WH_TEST_PRINT("--Adding 3 new objects\n");
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

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Overwrite an existing Object */
    WH_TEST_PRINT("--Overwrite an existing object\n");
    ret = addObjectWithReadBackCheck(cb, context, &meta1, sizeof(update1),
                                     update1);
    if (ret != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Overwrite an existing Object twice */
    WH_TEST_PRINT("--Overwrite an existing object again \n");
    ret = addObjectWithReadBackCheck(cb, context, &meta2, sizeof(update2),
                                     update2);
    if (ret != 0) {
        goto cleanup;
    }

    WH_TEST_PRINT("--Overwrite an existing object with new data\n");
    ret = addObjectWithReadBackCheck(cb, context, &meta2, sizeof(update3),
                                     update3);
    if (ret != 0) {
        goto cleanup;
    }


#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Regenerate */
    WH_TEST_PRINT("--Reclaim space\n");
    if ((ret = cb->DestroyObjects(context, 0, NULL)) != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Ensure reclamation doesn't destroy active objects */
    {
        whNvmMetadata metaBuf = {0};
        unsigned char dataBuf[256];
        size_t i = 0;
        WH_TEST_PRINT("--Read IDs after reclaim\n");
        for (i=0; i<sizeof(ids)/sizeof(ids[0]); i++) {
            if ((ret = cb->GetMetadata(context, ids[i], &metaBuf)) != 0) {
                WH_ERROR_PRINT("GetMetadata after reclaim returned %d\n", ret);
                goto cleanup;
            }

            if ((ret = cb->Read(context, ids[i], 0, metaBuf.len, dataBuf)) !=
                0) {
                WH_ERROR_PRINT("Read after reclaim returned %d\n", ret);
                goto cleanup;
            }
        }
    }

    /* Destroy 1 object */
    WH_TEST_PRINT("--Destroy 1 object\n");

    if ((ret = destroyObjectWithReadBackCheck(cb, context, 1, ids)) != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Attempt to destroy 3 objects, of which one has been already destroyed.
     * This should not cause an error */
    WH_TEST_PRINT("--Destroy 3 objects\n");
    if ((ret = destroyObjectWithReadBackCheck(
             cb, context, sizeof(ids) / sizeof(ids[0]), ids)) != 0) {
        goto cleanup;
    }

#if defined(WOLFHSM_CFG_DEBUG_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    WH_TEST_PRINT("--Done\n");

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
    const whNvmCb     nvmFlashCb[1]  = {WH_NVM_FLASH_CB};

    WH_TEST_RETURN_ON_FAIL(
        whTest_NvmFlashCfg(&myNvmCfg, nvmFlashCtx, nvmFlashCb));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    whNvmFlashLogConfig myLogCfg = {
        .flash_cb  = myCb,
        .flash_ctx = myHalFlashCtx,
        .flash_cfg = myHalFlashCfg,
    };
    whNvmFlashLogContext nvmLogCtx[1] = {0};
    const whNvmCb        nvmLogCb[1]  = {WH_NVM_FLASH_LOG_CB};
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

/* Interrupt an add while a committed object is already in the partition,
 * then verify the reloaded directory accounts for both data regions and
 * places new objects after them */
static int simulateFailureWithPrecedingObject(void)
{
    uint8_t               memory[FLASH_RAM_SIZE]       = {0};
    uint8_t               backupMemory[FLASH_RAM_SIZE] = {0};
    const whFlashCb       flashCb[1]                   = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx      flashCtx[1]                  = {0};
    whFlashRamsimCfg      flashCfg[1]                  = {{
                              .size       = FLASH_RAM_SIZE,
                              .sectorSize = FLASH_SECTOR_SIZE,
                              .pageSize   = FLASH_PAGE_SIZE,
                              .erasedByte = (uint8_t)0,
                              .memory     = memory,
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
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(memory, 0, FLASH_RAM_SIZE);
    flashCfg->initData = backupMemory;
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

int whTest_NvmFlash_Recovery(void)
{
    int      test_data_len;
    uint32_t bytesBefore, bytesAfter;
    whNvmId  objsBefore, objsAfter;
    uint32_t bytesReclBefore, bytesReclAfter;
    whNvmId  objsReclBefore, objsReclAfter;

    WH_TEST_PRINT("--simulate failure when writing object start\n");
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

    WH_TEST_PRINT("--simulate failure when writing object count\n");
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

    WH_TEST_PRINT("--simulate failure after a committed object\n");
    WH_TEST_RETURN_ON_FAIL(simulateFailureWithPrecedingObject());

    return 0;
}

#if defined(WOLFHSM_CFG_NVM_FLASH_CRC16)

/* Find needle in haystack. Returns byte offset or -1 if not found */
static int findFlashPattern(const uint8_t* haystack, uint32_t hay_len,
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

static int whTest_NvmFlash_Crc16Vectors(void)
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

int whTest_NvmFlash_Crc16(void)
{
    uint8_t          memory[FLASH_RAM_SIZE]       = {0};
    uint8_t          backupMemory[FLASH_RAM_SIZE] = {0};
    const whFlashCb  flashCb[1]                   = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx flashCtx[1]                  = {0};
    whFlashRamsimCfg flashCfg[1]                  = {{
                         .size       = FLASH_RAM_SIZE,
                         .sectorSize = FLASH_SECTOR_SIZE,
                         .pageSize   = FLASH_PAGE_SIZE,
                         .erasedByte = (uint8_t)0,
                         .memory     = memory,
    }};
    whNvmFlashConfig cfg                          = {
                                 .cb      = flashCb,
                                 .context = flashCtx,
                                 .config  = flashCfg,
    };
    whNvmFlashContext context[1] = {0};
    const whNvmCb     cb[1]      = {WH_NVM_FLASH_CB};

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

    WH_TEST_RETURN_ON_FAIL(whTest_NvmFlash_Crc16Vectors());

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
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, dataMeta.id, 0,
                                    (whNvmSize)sizeof(dataPattern), readBuf));
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(dataPattern, readBuf, sizeof(dataPattern)));

    /* Corrupt one data byte directly in the simulated flash */
    offset = findFlashPattern(memory, FLASH_RAM_SIZE, dataPattern,
                              (uint32_t)sizeof(dataPattern));
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset + 50] ^= 0xFF;

    /* Full read fails CRC. Partial reads are not verified */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTVERIFIED ==
                          cb->Read(context, dataMeta.id, 0,
                                   (whNvmSize)sizeof(dataPattern), readBuf));
    WH_TEST_RETURN_ON_FAIL(cb->Read(
        context, dataMeta.id, 0, (whNvmSize)sizeof(dataPattern) - 1, readBuf));
    WH_TEST_RETURN_ON_FAIL(cb->Read(
        context, dataMeta.id, 1, (whNvmSize)sizeof(dataPattern) - 1, readBuf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, dataMeta.id, &metaBuf));

    /* Reclaim must abort when copying the corrupt object */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTVERIFIED ==
                          cb->DestroyObjects(context, 0, NULL));
    /* Active partition is untouched: object still present */
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, dataMeta.id, &metaBuf));

    /* Restore the byte: read and reclaim work again */
    memory[offset + 50] ^= 0xFF;
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, dataMeta.id, 0,
                                    (whNvmSize)sizeof(dataPattern), readBuf));
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));

    /* Read back from the new partition, re-verified after the copy */
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, dataMeta.id, 0,
                                    (whNvmSize)sizeof(dataPattern), readBuf));
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(dataPattern, readBuf, sizeof(dataPattern)));
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

    WH_TEST_PRINT("--CRC16: metadata corruption detection\n");
    flashCfg->initData = NULL;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
    WH_TEST_RETURN_ON_FAIL(cb->AddObject(
        context, &metaMeta, (whNvmSize)sizeof(metaData), metaData));
    WH_TEST_RETURN_ON_FAIL(cb->AddObject(
        context, &goodMeta, (whNvmSize)sizeof(goodData), goodData));

    /* Corrupt one on-flash label byte of the first object */
    offset = findFlashPattern(memory, FLASH_RAM_SIZE,
                              (const uint8_t*)"CrcMetaTest", 11);
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset + 3] ^= 0xFF;

    /* Reload the directory from flash to force verification */
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(memory, 0, FLASH_RAM_SIZE);
    flashCfg->initData = backupMemory;
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
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes, &availObjects,
                                            &reclaimBytes, &reclaimObjects));
    WH_TEST_ASSERT_RETURN(reclaimObjects >= 1);
    WH_TEST_ASSERT_RETURN(reclaimBytes >= sizeof(metaData));

    /* Compaction drops the corrupt object and keeps the healthy one */
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, metaMeta.id, &metaBuf));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, goodMeta.id, 0,
                                    (whNvmSize)sizeof(goodData), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(goodData, readBuf, sizeof(goodData)));
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes, &availObjects,
                                            &reclaimBytes, &reclaimObjects));
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
    offset = findFlashPattern(memory, FLASH_RAM_SIZE,
                              (const uint8_t*)"CrcCounterTest", 14);
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset + 3] ^= 0xFF;
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(memory, 0, FLASH_RAM_SIZE);
    flashCfg->initData = backupMemory;
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
    WH_TEST_RETURN_ON_FAIL(cb->AddObject(
        context, &badCopyMeta, (whNvmSize)sizeof(dataPattern), dataPattern));

    /* Corrupt one data byte of the object that is NOT being destroyed */
    offset = findFlashPattern(memory, FLASH_RAM_SIZE, dataPattern,
                              (uint32_t)sizeof(dataPattern));
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset + 10] ^= 0xFF;

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
                                   (whNvmSize)sizeof(dataPattern), readBuf));

    /* Destroying the corrupt object itself succeeds (it is not copied) and
     * must not drop the object whose destroy failed earlier */
    destroyId = badCopyMeta.id;
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 1, &destroyId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
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
                                        (whNvmSize)sizeof(intrData), intrData));

    /* Also corrupt one on-flash label byte of the interrupted entry */
    offset = findFlashPattern(memory, FLASH_RAM_SIZE,
                              (const uint8_t*)"CrcIntrTest", 11);
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset + 3] ^= 0xFF;

    /* Reload the directory from flash */
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(memory, 0, FLASH_RAM_SIZE);
    flashCfg->initData = backupMemory;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));
    flashCfg->initData = NULL;

    /* Entry is hidden. Without trusted metadata its extent is unknown, so
     * the rest of the data area is reserved and new writes are refused */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, intrMeta.id, &metaBuf));
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes, &availObjects,
                                            &reclaimBytes, &reclaimObjects));
    WH_TEST_ASSERT_RETURN(availBytes == 0);
    WH_TEST_ASSERT_RETURN(reclaimObjects >= 1);
    WH_TEST_ASSERT_RETURN(reclaimBytes >= sizeof(intrData));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE ==
                          cb->AddObject(context, &postMeta,
                                        (whNvmSize)sizeof(postData), postData));

    /* Compaction reclaims the interrupted entry and unblocks writes */
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, intrMeta.id, &metaBuf));
    WH_TEST_RETURN_ON_FAIL(cb->AddObject(
        context, &postMeta, (whNvmSize)sizeof(postData), postData));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, postMeta.id, 0,
                                    (whNvmSize)sizeof(postData), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(postData, readBuf, sizeof(postData)));
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes, &availObjects,
                                            &reclaimBytes, &reclaimObjects));
    WH_TEST_ASSERT_RETURN(reclaimObjects == 0);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

    WH_TEST_PRINT("--CRC16: interrupted write with corrupt length\n");
    flashCfg->initData = NULL;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));

    /* Interrupt an add at the count-word program, as above */
    faultInjCtx->failAfterPrograms = 5;
    WH_TEST_ASSERT_RETURN(WH_ERROR_ABORTED ==
                          cb->AddObject(context, &lenMeta,
                                        (whNvmSize)sizeof(intrData), intrData));

    /* Under-report the entry's on-flash length: len is the two bytes before
     * the label, which starts at metadata byte 8 */
    offset = findFlashPattern(memory, FLASH_RAM_SIZE,
                              (const uint8_t*)"CrcLenTest", 10);
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset - 2] = 1;
    memory[offset - 1] = 0;

    /* Reload the directory from flash */
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(memory, 0, FLASH_RAM_SIZE);
    flashCfg->initData = backupMemory;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &faultCfg));
    flashCfg->initData = NULL;

    /* The corrupt length is not trusted: a new add must not land on the
     * entry's partially written data, so writes are refused instead */
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, lenMeta.id, &metaBuf));
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes, &availObjects,
                                            &reclaimBytes, &reclaimObjects));
    WH_TEST_ASSERT_RETURN(availBytes == 0);
    WH_TEST_ASSERT_RETURN(reclaimObjects >= 1);
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOSPACE ==
                          cb->AddObject(context, &postMeta,
                                        (whNvmSize)sizeof(postData), postData));

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

    WH_TEST_PRINT("--CRC16: corrupt overwrite resurrects previous version\n");
    flashCfg->initData = NULL;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &v1Meta, (whNvmSize)sizeof(v1Data), v1Data));
    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &v2Meta, (whNvmSize)sizeof(v2Data), v2Data));

    /* In session the overwrite is authoritative */
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, v2Meta.id, 0, (whNvmSize)sizeof(v2Data), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(v2Data, readBuf, sizeof(v2Data)));

    /* Corrupt one on-flash label byte of the newest copy */
    offset = findFlashPattern(memory, FLASH_RAM_SIZE,
                              (const uint8_t*)"CrcResurrectV2", 14);
    WH_TEST_ASSERT_RETURN(offset >= 0);
    memory[offset + 3] ^= 0xFF;

    /* Reload the directory from flash */
    memcpy(backupMemory, memory, FLASH_RAM_SIZE);
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));
    memset(memory, 0, FLASH_RAM_SIZE);
    flashCfg->initData = backupMemory;
    WH_TEST_RETURN_ON_FAIL(cb->Init(context, &cfg));
    flashCfg->initData = NULL;

    /* Documented caveat: with the newest copy corrupt, the previous version
     * becomes visible again */
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, v1Meta.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(metaBuf.label, v1Meta.label, sizeof(metaBuf.label)));
    WH_TEST_ASSERT_RETURN(metaBuf.len == sizeof(v1Data));
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, v1Meta.id, 0, (whNvmSize)sizeof(v1Data), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(v1Data, readBuf, sizeof(v1Data)));

    /* The corrupt newest copy is reclaimable; compaction drops it and the
     * previous version remains */
    WH_TEST_RETURN_ON_FAIL(cb->GetAvailable(context, &availBytes, &availObjects,
                                            &reclaimBytes, &reclaimObjects));
    WH_TEST_ASSERT_RETURN(reclaimObjects == 1);
    WH_TEST_ASSERT_RETURN(reclaimBytes >= sizeof(v2Data));
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, v1Meta.id, 0, (whNvmSize)sizeof(v1Data), readBuf));
    WH_TEST_ASSERT_RETURN(0 == memcmp(v1Data, readBuf, sizeof(v1Data)));
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

    return 0;
}
#endif /* WOLFHSM_CFG_NVM_FLASH_CRC16 */

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
    const whNvmCb     nvmFlashCb[1]  = {WH_NVM_FLASH_CB};

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
    const whNvmCb        nvmLogCb[1]  = {WH_NVM_FLASH_LOG_CB};

    WH_TEST_RETURN_ON_FAIL(whTest_NvmFlashCfg(&myLogCfg, nvmLogCtx, nvmLogCb));
#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */

    /* Remove the configured file on success*/
    unlink(myHalFlashConfig[0].filename);
    return 0;
}

/* Exercise the guard that rejects a partition whose doubled size cannot be
 * addressed by the uint32_t flash interface. MAX_OFFSET here is 0x100000000,
 * which exceeds UINT32_MAX on every platform, so the rejection is portable. */
static int whTest_NvmFlash_PosixOversizedPartition(void)
{
    const whFlashCb       myCb[1]              = {POSIX_FLASH_FILE_CB};
    posixFlashFileContext myHalFlashContext[1] = {0};
    posixFlashFileConfig  myHalFlashConfig[1]  = {{
          .filename       = "myNvmOversized.bin",
          .partition_size = 0x80000000u, /* doubled = 0x100000000 */
          .erased_byte    = (~(uint8_t)0),
    }};

    /* Init must reject the partition; nothing is left open to clean up */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
            myCb->Init(myHalFlashContext, myHalFlashConfig));

    unlink(myHalFlashConfig[0].filename);
    return 0;
}

#endif


int whTest_NvmFlash(void)
{
    WH_TEST_PRINT("Testing NVM flash with RAM sim...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_RamSim());

    WH_TEST_PRINT("Testing NVM flash recovery mechanism...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_Recovery());

#if defined(WOLFHSM_CFG_NVM_FLASH_CRC16)
    WH_TEST_PRINT("Testing NVM flash CRC16 integrity checks...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_Crc16());
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX)
    WH_TEST_PRINT("Testing NVM flash with POSIX file sim...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_PosixFileSim());

    WH_TEST_PRINT("Testing POSIX oversized-partition rejection...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_PosixOversizedPartition());
#endif

    return 0;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
