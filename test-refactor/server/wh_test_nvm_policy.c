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
 * test-refactor/server/wh_test_nvm_policy.c
 *
 * Server-side test that the policy-checked keystore APIs report denials
 * correctly when NVM is attached. Complements wh_test_nvm_optional.c, which
 * covers the same APIs with the NVM detached.
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#define WH_TEST_NVMPOL_KEYLEN (32)

/* A destroy batch naming an absent id must still destroy the present ones */
static int _whTest_NvmPolicyDestroyBatchMissingId(whServerContext* server)
{
    whNvmMetadata meta[1];
    whNvmMetadata outMeta[1];
    uint8_t       data[]  = {0xA1, 0xB2, 0xC3, 0xD4};
    whNvmId       present = 0x0310;
    whNvmId       absent  = 0x0311;
    whNvmId       list[2];

    list[0] = absent;
    list[1] = present;

    memset(meta, 0, sizeof(meta));
    meta->id     = present;
    meta->len    = (whNvmSize)sizeof(data);
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Nvm_AddObjectChecked(server->nvm, meta, sizeof(data), data));

    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK == wh_Nvm_DestroyObjectsChecked(server->nvm, 2, list));

    WH_TEST_ASSERT_RETURN(
        WH_ERROR_NOTFOUND ==
        wh_Nvm_GetMetadata(server->nvm, present, outMeta));

    return WH_ERROR_OK;
}

/* Destroying a list whose ids are all absent must not replicate the partition.
 * Reclaimable space is the observable proof, since a replication compacts it
 * away. */
static int _whTest_NvmPolicyDestroyAllAbsentNoChurn(whServerContext* server)
{
    whNvmMetadata meta[1];
    uint8_t       data[] = {0x5A, 0x6B, 0x7C, 0x8D};
    whNvmId       id     = 0x0320;
    whNvmId       absent[2];
    uint32_t      availSize;
    uint32_t      reclaimBefore;
    uint32_t      reclaimAfter;
    whNvmId       availObjs;
    whNvmId       reclaimObjsBefore;
    whNvmId       reclaimObjsAfter;

    absent[0] = 0x0321;
    absent[1] = 0x0322;

    /* Overwrite the object so the old copy becomes reclaimable */
    memset(meta, 0, sizeof(meta));
    meta->id     = id;
    meta->len    = (whNvmSize)sizeof(data);
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Nvm_AddObjectChecked(server->nvm, meta, sizeof(data), data));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Nvm_AddObjectChecked(server->nvm, meta, sizeof(data), data));

    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Nvm_GetAvailable(server->nvm, &availSize, &availObjs,
                            &reclaimBefore, &reclaimObjsBefore));
    if (reclaimObjsBefore == 0) {
        /* Backend exposes no reclaimable space, so no-churn is not observable
         * here; pass without claiming it was verified. */
        (void)wh_Nvm_DestroyObjectsChecked(server->nvm, 1, &id);
        WH_TEST_PRINT("  no-churn NOT verified on this backend "
                      "(no reclaimable space to observe)\n");
        return WH_ERROR_OK;
    }

    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK == wh_Nvm_DestroyObjectsChecked(server->nvm, 2, absent));

    /* Untouched reclaimable space proves the backend was never called */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Nvm_GetAvailable(server->nvm, &availSize, &availObjs, &reclaimAfter,
                            &reclaimObjsAfter));
    WH_TEST_ASSERT_RETURN(reclaimObjsAfter == reclaimObjsBefore);
    WH_TEST_ASSERT_RETURN(reclaimAfter == reclaimBefore);

    /* Zero-count compaction, by contrast, does reach the backend and clears
     * reclaimable space, pinning the guard that lets it through */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK == wh_Nvm_DestroyObjectsChecked(server->nvm, 0, NULL));
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Nvm_GetAvailable(server->nvm, &availSize, &availObjs, &reclaimAfter,
                            &reclaimObjsAfter));
    WH_TEST_ASSERT_RETURN(reclaimObjsAfter == 0);

    /* Clean up the surviving object */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK == wh_Nvm_DestroyObjectsChecked(server->nvm, 1, &id));

    return WH_ERROR_OK;
}

/* Erasing a key that is absent from both cache and NVM is a successful erase,
 * matching the non-checked wh_Server_KeystoreEraseKey. */
static int _whTest_NvmPolicyMissingKeyEraseSucceeds(whServerContext* server)
{
    whKeyId missingId;

    missingId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID,
                              0x32);

    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreEraseKeyChecked(server, missingId));
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreEraseKey(server, missingId));

    return WH_ERROR_OK;
}

/* A revoked key that was never committed lives only in the cache, so the NVM
 * destroy step finds nothing. The erase must still report the cache eviction's
 * policy denial rather than the NVM layer's "nothing to destroy" success. */
static int _whTest_NvmPolicyRevokedCacheOnlyEraseDenied(whServerContext* server)
{
    whNvmMetadata meta[1];
    whNvmMetadata outMeta[1];
    uint8_t       keyData[WH_TEST_NVMPOL_KEYLEN];
    uint8_t       outKey[WH_TEST_NVMPOL_KEYLEN];
    uint32_t      outSz;
    whKeyId       revokeId;
    int           i;

    for (i = 0; i < (int)sizeof(keyData); i++) {
        keyData[i] = (uint8_t)(i + 1);
    }

    revokeId = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, WH_TEST_DEFAULT_CLIENT_ID,
                             0x31);

    /* Cache the key without committing it, so it never reaches NVM */
    memset(meta, 0, sizeof(meta));
    meta->id     = revokeId;
    meta->len    = (whNvmSize)sizeof(keyData);
    meta->flags  = WH_NVM_FLAGS_USAGE_ANY;
    meta->access = WH_NVM_ACCESS_ANY;
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreCacheKey(server, meta, keyData));

    /* Revoking marks the cached copy NONMODIFIABLE; with the key absent from
     * NVM there is nothing to commit. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_OK ==
                          wh_Server_KeystoreRevokeKey(server, revokeId));

    /* The denial must survive, even though the NVM destroy would succeed */
    WH_TEST_ASSERT_RETURN(WH_ERROR_ACCESS ==
                          wh_Server_KeystoreEraseKeyChecked(server, revokeId));

    /* Nothing was erased: the key is still readable */
    outSz = sizeof(outKey);
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_OK ==
        wh_Server_KeystoreReadKey(server, revokeId, outMeta, outKey, &outSz));
    WH_TEST_ASSERT_RETURN(outSz == (uint32_t)sizeof(keyData));

    /* Force-remove the revoked key (EraseKeyChecked could not) */
    (void)wh_Server_KeystoreEvictKey(server, revokeId);

    return WH_ERROR_OK;
}

int whTest_NvmPolicyChecked(whServerContext* ctx)
{
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(_whTest_NvmPolicyDestroyBatchMissingId(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_NvmPolicyDestroyAllAbsentNoChurn(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_NvmPolicyMissingKeyEraseSucceeds(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_NvmPolicyRevokedCacheOnlyEraseDenied(ctx));

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO */
