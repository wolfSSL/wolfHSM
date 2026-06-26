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
 * test-refactor/client-server/wh_test_nvm_ops.c
 *
 * NVM object lifecycle tests over both the blocking and DMA
 * client APIs. The Add/Update/List/Destroy body is shared via
 * a small dispatch struct (WhNvmTestObjectOps) so the same
 * coverage applies to both transports. The DMA entry point
 * only compiles when WOLFHSM_CFG_DMA is defined; otherwise the
 * weak stub in wh_test_list reports it as skipped.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define NVM_TEST_OBJECT_COUNT 5
#define NVM_TEST_OBJECT_ID_BASE      20
#define NVM_TEST_OOB_ID            30
#define NVM_TEST_DMA_ID_BASE       40


/*
 * Helpers to unify the DMA and non-DMA test functions.
 */
typedef int (*WhNvmTestObjectAddFn)(whClientContext* ctx, whNvmId id,
    whNvmAccess access, whNvmFlags flags,
    const uint8_t* label, whNvmSize label_len,
    const uint8_t* data, whNvmSize data_len,
    int32_t* server_rc);

typedef int (*WhNvmTestObjectReadFn)(whClientContext* ctx, whNvmId id,
    whNvmSize offset, whNvmSize len,
    uint8_t* buf, whNvmSize* out_len,
    int32_t* server_rc);

typedef struct {
    WhNvmTestObjectAddFn  add;
    WhNvmTestObjectReadFn read;
} WhNvmTestObjectOps;


static int _nvmIdInRange(whNvmId id, whNvmId base, whNvmId count)
{
    return (id >= base) && (id < (whNvmId)(base + count));
}


static int _destroyNvmId(whClientContext* ctx, whNvmId id)
{
    int32_t server_rc = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmDestroyObjects(
        ctx, 1, &id, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadata(
        ctx, id, &server_rc, NULL, NULL, NULL, NULL, 0, NULL));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_NOTFOUND);

    return WH_ERROR_OK;
}


/*
 * Add (or re-Add) one object via ops->add and verify:
 *   - avail_objects drops by 1 (a new slot is always consumed,
 *     even on re-Add, since the log is append-only)
 *   - reclaim_objects rises by reclaim_grow (0 for a fresh Add,
 *     1 for a re-Add that supersedes a prior version)
 *   - GetMetadata reports the just-written id/access/flags/len/label
 *   - ops->read returns the just-written payload
 */
static int _addAndVerifyOne(whClientContext* ctx,
    const WhNvmTestObjectOps* ops, whNvmId id,
    whNvmAccess access, whNvmFlags flags,
    const uint8_t* label, whNvmSize label_len,
    const uint8_t* data, whNvmSize data_len,
    int reclaim_grow)
{
    int32_t   server_rc       = 0;
    uint32_t  avail_size      = 0;
    uint32_t  reclaim_size    = 0;
    whNvmId   prev_avail      = 0;
    whNvmId   prev_reclaim    = 0;
    whNvmId   avail_objects   = 0;
    whNvmId   reclaim_objects = 0;

    whNvmId     gid     = 0;
    whNvmAccess gaccess = 0;
    whNvmFlags  gflags  = 0;
    whNvmSize   glen    = 0;
    char        glabel[WH_NVM_LABEL_LEN] = {0};
    uint8_t     buf[WOLFHSM_CFG_COMM_DATA_LEN];
    whNvmSize   rlen    = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &server_rc, &avail_size, &prev_avail,
        &reclaim_size, &prev_reclaim));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(ops->add(
        ctx, id, access, flags,
        label, label_len, data, data_len, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &server_rc, &avail_size, &avail_objects,
        &reclaim_size, &reclaim_objects));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(prev_avail - 1 == avail_objects);
    WH_TEST_ASSERT_RETURN(
        (whNvmId)(prev_reclaim + reclaim_grow) == reclaim_objects);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadata(
        ctx, id, &server_rc,
        &gid, &gaccess, &gflags, &glen,
        sizeof(glabel), (uint8_t*)glabel));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(gid == id);
    WH_TEST_ASSERT_RETURN(gaccess == access);
    WH_TEST_ASSERT_RETURN(gflags == flags);
    WH_TEST_ASSERT_RETURN(glen == data_len);
    WH_TEST_ASSERT_RETURN(memcmp(glabel, label, label_len) == 0);

    memset(buf, 0, sizeof(buf));
    WH_TEST_RETURN_ON_FAIL(ops->read(
        ctx, id, 0, glen,
        buf, &rlen, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(rlen == data_len);
    WH_TEST_ASSERT_RETURN(memcmp(buf, data, data_len) == 0);

    return WH_ERROR_OK;
}


/*
 * Create, Read, Update and Destroy test.
 */
static int _runNvmObjectTest(whClientContext* ctx,
    const WhNvmTestObjectOps* ops, whNvmId id_base)
{
    int32_t   server_rc       = 0;
    uint32_t  client_id       = 0;
    uint32_t  server_id       = 0;
    uint32_t  avail_size      = 0;
    uint32_t  reclaim_size    = 0;
    whNvmId   avail_objects   = 0;
    whNvmId   reclaim_objects = 0;
    whNvmId   baseline        = 0;
    char      label[WH_NVM_LABEL_LEN];
    char      data[WOLFHSM_CFG_COMM_DATA_LEN];
    whNvmSize label_len;
    whNvmSize data_len;
    int       i;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmInit(
        ctx, &server_rc, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Capture the starting available count so we don't assume
     * the suite is running on a virgin NVM. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &server_rc, &avail_size, &avail_objects,
        &reclaim_size, &reclaim_objects));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    /* Starting point for the test is available + reclaimable.
     * NVM activity may recycle stale entries from prior tests, so
     * `avail_objects` alone is not sufficient. */
    baseline = (whNvmId)(avail_objects + reclaim_objects);

    /* Add phase: fresh objects, no reclaim activity expected. */
    for (i = 0; i < NVM_TEST_OBJECT_COUNT; i++) {
        whNvmId id = (whNvmId)(id_base + i);
        memset(label, 0, sizeof(label));
        label_len = (whNvmSize)snprintf(label, sizeof(label),
            "Label:%d", id);
        data_len = (whNvmSize)snprintf(data, sizeof(data),
            "Data:%d Counter:%d", id, i);
        WH_TEST_RETURN_ON_FAIL(_addAndVerifyOne(
            ctx, ops, id,
            WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
            (const uint8_t*)label, label_len,
            (const uint8_t*)data, data_len,
            0));
    }

    /* Update phase: re-Add each id with new label and payload. */
    for (i = 0; i < NVM_TEST_OBJECT_COUNT; i++) {
        whNvmId id = (whNvmId)(id_base + i);
        memset(label, 0, sizeof(label));
        label_len = (whNvmSize)snprintf(label, sizeof(label),
            "Upd:%d", id);
        data_len = (whNvmSize)snprintf(data, sizeof(data),
            "Updated:%d Iter:%d", id, i);
        WH_TEST_RETURN_ON_FAIL(_addAndVerifyOne(
            ctx, ops, id,
            WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
            (const uint8_t*)label, label_len,
            (const uint8_t*)data, data_len,
            1));
    }

    /* Verify List enumerates the ids we own without assuming
     * the test owns unrelated objects that may already exist. */
    {
        whNvmAccess list_access = WH_NVM_ACCESS_ANY;
        whNvmFlags  list_flags  = WH_NVM_FLAGS_NONE;
        whNvmId     list_id     = 0;
        whNvmId     list_count  = 0;
        whNvmId     found       = 0;

        do {
            WH_TEST_RETURN_ON_FAIL(wh_Client_NvmList(
                ctx, list_access, list_flags, list_id,
                &server_rc, &list_count, &list_id));
            WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

            if ((list_count > 0) && _nvmIdInRange(
                    list_id, id_base, NVM_TEST_OBJECT_COUNT)) {
                found++;
            }
        } while (list_count > 0);

        WH_TEST_ASSERT_RETURN(found == NVM_TEST_OBJECT_COUNT);
    }

    for (i = 0; i < NVM_TEST_OBJECT_COUNT; i++) {
        WH_TEST_RETURN_ON_FAIL(_destroyNvmId(
            ctx, (whNvmId)(id_base + i)));
    }

    /* Cleanup -> Init round-trip leaves NVM in a usable state
     * with no leftovers. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmCleanup(ctx, &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmInit(
        ctx, &server_rc, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetAvailable(
        ctx, &server_rc, &avail_size, &avail_objects,
        &reclaim_size, &reclaim_objects));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    /* Live-object count must match the baseline; see note above. */
    WH_TEST_ASSERT_RETURN(
        (whNvmId)(avail_objects + reclaim_objects) == baseline);

    return WH_ERROR_OK;
}


/* Blocking-API adapters. */

static int _nvmTestObjectAddBlocking(whClientContext* ctx, whNvmId id,
    whNvmAccess access, whNvmFlags flags,
    const uint8_t* label, whNvmSize label_len,
    const uint8_t* data, whNvmSize data_len,
    int32_t* server_rc)
{
    return wh_Client_NvmAddObject(ctx, id, access, flags,
        label_len, (uint8_t*)label,
        data_len, data, server_rc);
}


static int _nvmTestObjectReadBlocking(whClientContext* ctx, whNvmId id,
    whNvmSize offset, whNvmSize len,
    uint8_t* buf, whNvmSize* out_len,
    int32_t* server_rc)
{
    return wh_Client_NvmRead(ctx, id, offset, len,
        server_rc, out_len, buf);
}


static const WhNvmTestObjectOps g_blockingTestOps = {
    _nvmTestObjectAddBlocking,
    _nvmTestObjectReadBlocking,
};


/*
 * Exercises NvmRead's offset/length clamping and overflow
 * safety. Adds a single object, runs the boundary cases, then
 * destroys it. Blocking-only -- the DMA read API has no
 * equivalent out_len reporting.
 */
static int _whTest_NvmOpsReadOob(whClientContext* ctx)
{
    const whNvmId id        = NVM_TEST_OOB_ID;
    int32_t       server_rc = 0;
    uint32_t      client_id = 0;
    uint32_t      server_id = 0;
    uint8_t       buf[WOLFHSM_CFG_COMM_DATA_LEN];
    char          label[WH_NVM_LABEL_LEN] = {0};
    char          data[]    = "OOB read clamping payload";
    whNvmSize     label_len;
    whNvmSize     data_len  = (whNvmSize)sizeof(data);
    whNvmSize     out_len;
    whNvmId       gid;
    whNvmAccess   gaccess;
    whNvmFlags    gflags;
    whNvmSize     meta_len;

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmInit(
        ctx, &server_rc, &client_id, &server_id));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    label_len = (whNvmSize)snprintf(label, sizeof(label), "OOB:%u", id);

    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmAddObject(
        ctx, id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE,
        label_len, (uint8_t*)label,
        data_len, (const uint8_t*)data,
        &server_rc));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);

    /* Confirm metadata length so we can phrase the rest of the
     * checks against meta_len rather than the raw write size. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmGetMetadata(
        ctx, id, &server_rc,
        &gid, &gaccess, &gflags, &meta_len,
        0, NULL));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(meta_len == data_len);

    /* len = meta_len + 1 -> clamp to meta_len */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(
        ctx, id, 0, (whNvmSize)(meta_len + 1),
        &server_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == meta_len);

    /* off=1, len=meta_len -> clamp to meta_len - 1 */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(
        ctx, id, 1, meta_len,
        &server_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == (whNvmSize)(meta_len - 1));

    /* off=meta_len-1, len=meta_len -> clamp to 1 */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(
        ctx, id, (whNvmSize)(meta_len - 1), meta_len,
        &server_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(out_len == 1);

    /* off == meta_len, len = 0 -> BADARGS (no readable bytes) */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(
        ctx, id, meta_len, 0,
        &server_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_BADARGS);

    /* off == UINT16_MAX -> BADARGS. Regression for integer
     * overflow in the offset+len bound check. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(
        ctx, id, (whNvmSize)UINT16_MAX, 1,
        &server_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_BADARGS);

    /* off=meta_len/2, len=meta_len -> clamp to meta_len - off.
     * Verifies the overflow-safe form of the bounds check. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_NvmRead(
        ctx, id, (whNvmSize)(meta_len / 2), meta_len,
        &server_rc, &out_len, buf));
    WH_TEST_ASSERT_RETURN(server_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(
        out_len == (whNvmSize)(meta_len - (meta_len / 2)));

    return _destroyNvmId(ctx, id);
}


int whTest_NvmOps(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_runNvmObjectTest(
        ctx, &g_blockingTestOps, NVM_TEST_OBJECT_ID_BASE));
    WH_TEST_RETURN_ON_FAIL(_whTest_NvmOpsReadOob(ctx));

    return WH_ERROR_OK;
}


#ifdef WOLFHSM_CFG_DMA

/* DMA-API adapters. */

static int _nvmTestObjectAddDma(whClientContext* ctx, whNvmId id,
    whNvmAccess access, whNvmFlags flags,
    const uint8_t* label, whNvmSize label_len,
    const uint8_t* data, whNvmSize data_len,
    int32_t* server_rc)
{
    whNvmMetadata meta = {
        .id     = id,
        .access = access,
        .flags  = flags,
        .len    = 0,
        .label  = {0},
    };
    if (label_len > sizeof(meta.label)) {
        label_len = sizeof(meta.label);
    }
    memcpy(meta.label, label, label_len);
    return wh_Client_NvmAddObjectDma(
        ctx, &meta, data_len, data, server_rc);
}


static int _nvmTestObjectReadDma(whClientContext* ctx, whNvmId id,
    whNvmSize offset, whNvmSize len,
    uint8_t* buf, whNvmSize* out_len,
    int32_t* server_rc)
{
    int ret = wh_Client_NvmReadDma(
        ctx, id, offset, len, buf, server_rc);
    /* DMA read returns exactly len bytes on success; mirror that
     * into out_len so the shared body's rlen check matches. */
    if (ret == 0 && *server_rc == WH_ERROR_OK) {
        *out_len = len;
    }
    return ret;
}


static const WhNvmTestObjectOps g_dmaTestOps = {
    _nvmTestObjectAddDma,
    _nvmTestObjectReadDma,
};


int whTest_NvmDma(whClientContext* ctx)
{
    return _runNvmObjectTest(ctx, &g_dmaTestOps, NVM_TEST_DMA_ID_BASE);
}

#endif /* WOLFHSM_CFG_DMA */
