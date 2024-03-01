#include <stdio.h>
#include <string.h>

/* core test includes */
#include "wh_config.h"
#include "wh_test_common.h"

/* APIs to test */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"

/* NVM simulator backends to use for testing NVM module */
#include "wolfhsm/wh_flash_ramsim.h"
#if defined(WH_CFG_TEST_POSIX)
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

#if defined(WH_CFG_TEST_VERBOSE)
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
    whNvmSize free_space      = 0;
    whNvmId   free_objects    = 0;
    whNvmSize reclaim_space   = 0;
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

        rc = cb->List(context, WOLFHSM_NVM_ACCESS_ANY, WOLFHSM_NVM_FLAGS_ANY,
                      id, &listCount, &id);

        if ((rc == 0) && (listCount > 0)) {
            printf("Found object id 0x%X (%d) with %d more objects\n", id, id,
                   listCount - 1);
            whNvmMetadata myMetadata;
            memset(&myMetadata, 0, sizeof(myMetadata));
            rc = cb->GetMetadata(context, id, &myMetadata);

            if (rc == 0) {

                uint8_t data[WOLFHSM_NVM_MAX_OBJECT_SIZE];
                memset(&data, 0, sizeof(data));

                printf("-Id:%04hX\n-Label:%.*s\n"
                       "-Access:%04hX\n-Flags:%04hX\n-Len:%d\n",
                       myMetadata.id, (int)sizeof(myMetadata.label),
                       myMetadata.label, myMetadata.access, myMetadata.flags,
                       myMetadata.len);

                /* Read the data from this object */
                rc = cb->Read(context, id, 0, myMetadata.len, data);

                if (rc == 0) {
                    /* Show the data from this object */
                    _HexDump((const char*)data, (int)(myMetadata.len));
                }
            }
        }
        else
            break;
    } while (listCount > 0);
}
#endif


int whTest_NvmFlashCfg(whNvmFlashConfig* cfg)
{
    const whNvmCb     cb[1]      = {WH_NVM_FLASH_CB};
    whNvmFlashContext context[1] = {0};

    WH_TEST_RETURN_ON_FAIL(cb->Init(context, cfg));

#if defined(WH_CFG_TEST_VERBOSE)
    printf("--Initial NVM contents\n");
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Add 3 new Objects */
    unsigned char buf[256];
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

    whNvmMetadata meta1   = {.id = ids[0], .label = "Label1"};
    whNvmMetadata meta2   = {.id = ids[1], .label = "Label2"};
    whNvmMetadata meta3   = {.id = ids[2], .label = "Label3"};
    whNvmMetadata metaBuf = {0};


    /* Add 3 objects, checking for each object that we can read back what was
     * written */
    printf("--Adding 3 new objects\n");

    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &meta1, sizeof(data1), data1));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, meta1.id, 0, sizeof(data1), buf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta1.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta1.id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(data1, buf, sizeof(data1)));

    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &meta2, sizeof(data2), data2));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, meta2.id, 0, sizeof(data2), buf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta2.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta2.id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(data2, buf, sizeof(data2)));

    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &meta3, sizeof(data3), data3));
    WH_TEST_RETURN_ON_FAIL(cb->Read(context, meta3.id, 0, sizeof(data3), buf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta3.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta3.id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(data3, buf, sizeof(data3)));

#if defined(WH_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Overwrite an existing Object */
    printf("--Overwrite an existing object\n");
    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &meta1, sizeof(update1), update1));
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, meta1.id, 0, sizeof(update1), buf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta1.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta1.id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(update1, buf, sizeof(update1)));

#if defined(WH_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Overwrite an existing Object twice */
    printf("--Overwrite an existing object again \n");
    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &meta2, sizeof(update2), update2));
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, meta2.id, 0, sizeof(update2), buf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta2.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta2.id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(update2, buf, sizeof(update2)));

    printf("--Overwrite an existing object with new data\n");
    WH_TEST_RETURN_ON_FAIL(
        cb->AddObject(context, &meta2, sizeof(update3), update3));
    WH_TEST_RETURN_ON_FAIL(
        cb->Read(context, meta2.id, 0, sizeof(update3), buf));
    WH_TEST_RETURN_ON_FAIL(cb->GetMetadata(context, meta2.id, &metaBuf));
    WH_TEST_ASSERT_RETURN(meta2.id == metaBuf.id);
    WH_TEST_ASSERT_RETURN(0 == memcmp(update3, buf, sizeof(update3)));
#if defined(WH_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Regenerate */
    printf("--Reclaim space\n");
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 0, NULL));
#if defined(WH_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Destroy 1 object */
    printf("--Destroy 1 object\n");
    WH_TEST_RETURN_ON_FAIL(cb->DestroyObjects(context, 1, ids));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->Read(context, ids[0], 0, 0, buf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, ids[0], &metaBuf));
#if defined(WH_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    /* Attempt to destroy 3 objects, of which one has been already destroyed.
     * This should not cause an error */
    printf("--Destroy 3 objects\n");
    WH_TEST_RETURN_ON_FAIL(
        cb->DestroyObjects(context, sizeof(ids) / sizeof(ids[0]), ids));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->Read(context, meta2.id, 0, sizeof(update3), buf));
    WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                          cb->GetMetadata(context, meta2.id, &metaBuf));
#if defined(WH_CFG_TEST_VERBOSE)
    _ShowAvailable(cb, context);
    _ShowList(cb, context);
#endif

    printf("--Done\n");

    /* Clean up local data */
    WH_TEST_RETURN_ON_FAIL(cb->Cleanup(context));

    return 0;
}


int whTest_NvmFlash_RamSim(void)
{
    /* HAL Flash state and configuration */
    const whFlashCb  myCb[1]          = {WH_FLASH_RAMSIM_CB};
    whFlashRamsimCtx myHalFlashCtx[1] = {0};
    whFlashRamsimCfg myHalFlashCfg[1] = {{
        .size       = 1024 * 1024, /* 1MB  Flash */
        .sectorSize = 4096,        /* 4KB  Sector Size */
        .pageSize   = 8,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
    }};

    /* NVM Configuration using PosixSim HAL Flash */
    whNvmFlashConfig myNvmCfg = {
        .cb      = myCb,
        .context = myHalFlashCtx,
        .config  = myHalFlashCfg,
    };


    return whTest_NvmFlashCfg(&myNvmCfg);
}


#if defined(WH_CFG_TEST_POSIX)

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


    /* NVM Configuration using PosixSim HAL Flash */
    whNvmFlashConfig myNvmCfg = {
        .cb      = myCb,
        .context = myHalFlashContext,
        .config  = myHalFlashConfig,
    };


    WH_TEST_ASSERT(0 == whTest_NvmFlashCfg(&myNvmCfg));

    return 0;
}

#endif


int whTest_NvmFlash(void)
{
    printf("Testing NVM flash with RAM sim...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_RamSim());

#if defined(WH_CFG_TEST_POSIX)
    printf("Testing NVM flash with POSIX file sim...\n");
    WH_TEST_ASSERT(0 == whTest_NvmFlash_PosixFileSim());
#endif

    return 0;
}
