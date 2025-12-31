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
/*
 * src/wh_server_keystore.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_SERVER)

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_log.h"
#include "wolfhsm/wh_nvm_internal.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif

#include "wolfhsm/wh_server_keystore.h"


static int _FindInCacheUnlocked(whServerContext* server, whKeyId keyId,
                                int* out_index, int* out_big,
                                uint8_t** out_buffer, whNvmMetadata** out_meta);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/*
 * @brief Check if keyId represents a global key (USER == 0)
 */
static int _IsGlobalKey(whKeyId keyId)
{
    return (WH_KEYID_USER(keyId) == WH_KEYUSER_GLOBAL);
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/*
 * Thread-safe locking helpers for keystore operations.
 * Use the unified NVM lock to protect both NVM and cache access.
 * These are no-ops when WOLFHSM_CFG_THREADSAFE is not defined.
 */
#ifdef WOLFHSM_CFG_THREADSAFE
static int _LockKeystore(whServerContext* server)
{
    if (server->nvm != NULL) {
        return wh_Lock_Acquire(&server->nvm->lock);
    }
    return WH_ERROR_OK;
}

static int _UnlockKeystore(whServerContext* server)
{
    if (server->nvm != NULL) {
        return wh_Lock_Release(&server->nvm->lock);
    }
    return WH_ERROR_OK;
}
#else
#define _LockKeystore(server) (WH_ERROR_OK)
#define _UnlockKeystore(server) (WH_ERROR_OK)
#endif /* WOLFHSM_CFG_THREADSAFE */

/*
 * @brief Get the appropriate cache context based on keyId
 *
 * When WOLFHSM_CFG_GLOBAL_KEYS is enabled, routes to global cache if keyId
 * has USER == 0, otherwise routes to local cache. When disabled, always
 * routes to local cache.
 */
static whKeyCacheContext* _GetCacheContext(whServerContext* server,
                                           whKeyId          keyId)
{
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    if (_IsGlobalKey(keyId)) {
        return &server->nvm->globalCache;
    }
#else
    (void)keyId;
#endif
    return &server->localCache;
}

typedef enum {
    WH_KS_OP_CACHE = 0,
    WH_KS_OP_COMMIT,
    WH_KS_OP_EVICT,
    WH_KS_OP_EXPORT,
    WH_KS_OP_REVOKE,
} whKsOp;

static int _KeyIsCommittedUnlocked(whServerContext* server, whKeyId keyId)
{
    int ret;
    int big;
    int index;

    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    ret = _FindInCacheUnlocked(server, keyId, &index, &big, NULL, NULL);
    if (ret != WH_ERROR_OK) {
        return 0;
    }

    if (big == 0) {
        return ctx->cache[index].committed;
    }
    else {
        return ctx->bigCache[index].committed;
    }
}

/* Centralized cache/NVM policy: enforce NONMODIFIABLE/NONEXPORTABLE at the
 * keystore layer. Usage enforcement remains separate.
 *
 * This is an unlocked function - caller must hold the keystore lock. */
static int _KeystoreCheckPolicyUnlocked(whServerContext* server, whKsOp op,
                                        whKeyId keyId)
{
    whNvmMetadata* cacheMeta = NULL;
    whNvmMetadata  nvmMeta;
    whNvmFlags     flags;
    int            ret;
    int            foundInCache = 0;
    int            foundInNvm   = 0;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    /* Check cache first */
    ret = _FindInCacheUnlocked(server, keyId, NULL, NULL, NULL, &cacheMeta);
    if (ret == WH_ERROR_OK && cacheMeta != NULL) {
        foundInCache = 1;
    }
    else if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* Check NVM if not in cache */
    if (!foundInCache) {
        ret = wh_Nvm_GetMetadataUnlocked(server->nvm, keyId, &nvmMeta);
        if (ret == WH_ERROR_OK) {
            foundInNvm = 1;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            return ret;
        }
    }

    /* Key not found */
    if (!foundInCache && !foundInNvm) {
        return WH_ERROR_NOTFOUND;
    }

    /* Get flags from the appropriate source */
    flags = (foundInCache) ? cacheMeta->flags : nvmMeta.flags;

    switch (op) {
        case WH_KS_OP_CACHE:
            if (flags & WH_NVM_FLAGS_NONMODIFIABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_KS_OP_EVICT:
            if (_KeyIsCommittedUnlocked(server, keyId)) {
                /* Committed keys can always be evicted */
                break;
            }
            if (flags &
                (WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE)) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_KS_OP_EXPORT:
            if (flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_KS_OP_COMMIT:
        case WH_KS_OP_REVOKE:
            /* Always allowed */
            break;
        default:
            /* unknown operation */
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Find a key in the specified cache context
 */
static int _FindInKeyCacheUnlocked(whKeyCacheContext* ctx, whKeyId keyId,
                                   int* out_index, int* out_big,
                                   uint8_t**       out_buffer,
                                   whNvmMetadata** out_meta)
{
    int            ret = WH_ERROR_NOTFOUND;
    int            i;
    int            index  = -1;
    int            big    = -1;
    whNvmMetadata* meta   = NULL;
    uint8_t*       buffer = NULL;

    /* Search regular cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (ctx->cache[i].meta->id == keyId) {
            big    = 0;
            index  = i;
            meta   = ctx->cache[i].meta;
            buffer = ctx->cache[i].buffer;
            break;
        }
    }

    /* Search big cache if not found */
    if (index == -1) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == keyId) {
                big    = 1;
                index  = i;
                meta   = ctx->bigCache[i].meta;
                buffer = ctx->bigCache[i].buffer;
                break;
            }
        }
    }

    /* Set output parameters if found */
    if (index != -1) {
        if (out_index != NULL)
            *out_index = index;
        if (out_big != NULL)
            *out_big = big;
        if (out_meta != NULL)
            *out_meta = meta;
        if (out_buffer != NULL)
            *out_buffer = buffer;
        ret = WH_ERROR_OK;
    }

    return ret;
}

static int _EvictSlot(uint8_t* buf, whNvmMetadata* meta)
{
    meta->id = WH_KEYID_ERASED;
    memset(buf, 0, meta->len);
    return WH_ERROR_OK;
}

/**
 * @brief Get an available cache slot from the specified cache context
 */
static int _GetKeyCacheSlotUnlocked(whKeyCacheContext* ctx, uint16_t keySz,
                                    uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int foundIndex = -1;
    int i;
    int            evictRet = WH_ERROR_OK;
    uint8_t*       slotBuf  = NULL;
    whNvmMetadata* slotMeta = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Determine which cache to use based on key size */
    if (keySz <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* Search regular cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed key to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (ctx->cache[i].committed == 1) {
                    evictRet =
                        _EvictSlot(ctx->cache[i].buffer, ctx->cache[i].meta);
                    if (evictRet == WH_ERROR_OK) {
                        foundIndex = i;
                        break;
                    }
                }
            }
        }

        /* Zero slot and capture pointers */
        if (foundIndex >= 0) {
            memset(&ctx->cache[foundIndex], 0, sizeof(whCacheSlot));
            slotBuf  = ctx->cache[foundIndex].buffer;
            slotMeta = ctx->cache[foundIndex].meta;
        }
    }
    else {
        /* Search big cache for empty slot */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }

        /* If no empty slots, find committed key to evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (ctx->bigCache[i].committed == 1) {
                    evictRet = _EvictSlot(ctx->bigCache[i].buffer,
                                          ctx->bigCache[i].meta);
                    if (evictRet == WH_ERROR_OK) {
                        foundIndex = i;
                        break;
                    }
                }
            }
        }

        /* Zero slot and capture pointers */
        if (foundIndex >= 0) {
            memset(&ctx->bigCache[foundIndex], 0, sizeof(whBigCacheSlot));
            slotBuf  = ctx->bigCache[foundIndex].buffer;
            slotMeta = ctx->bigCache[foundIndex].meta;
        }
    }

    if (foundIndex == -1) {
        return WH_ERROR_NOSPACE;
    }

    /* Copy out pointers only if caller provided non-NULL output parameters */
    if (outBuf != NULL) {
        *outBuf = slotBuf;
    }
    if (outMeta != NULL) {
        *outMeta = slotMeta;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Evict a key from the specified cache context
 * zeroes the buffer
 */
static int _EvictKeyFromCacheUnlocked(whKeyCacheContext* ctx, whKeyId keyId)
{
    whNvmMetadata* meta      = NULL;
    uint8_t*       outBuffer = NULL;

    int ret =
        _FindInKeyCacheUnlocked(ctx, keyId, NULL, NULL, &outBuffer, &meta);

    if (ret == WH_ERROR_OK && meta != NULL) {
        return _EvictSlot(outBuffer, meta);
    }

    return ret;
}

/**
 * @brief Mark a cached key as committed
 */
static int _MarkKeyCommittedUnlocked(whKeyCacheContext* ctx, whKeyId keyId,
                                     int committed)
{
    int index = -1;
    int big   = -1;
    int ret   = _FindInKeyCacheUnlocked(ctx, keyId, &index, &big, NULL, NULL);

    if (ret == WH_ERROR_OK) {
        if (big == 0) {
            ctx->cache[index].committed = committed;
        }
        else {
            ctx->bigCache[index].committed = committed;
        }
    }

    return ret;
}

int wh_Server_KeystoreGetUniqueId(whServerContext* server, whNvmId* inout_id)
{
    int     ret   = WH_ERROR_OK;
    int     found = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whKeyId key_id = *inout_id;
    int     type   = WH_KEYID_TYPE(key_id);
    int     user   = WH_KEYID_USER(key_id);
    whNvmId buildId = WH_KEYID_ERASED;

    whKeyCacheContext* ctx = _GetCacheContext(server, key_id);

    /* Wrapped keys must be provisioned with explicit identifiers */
    if (type == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* try every index until we find a unique one, don't worry about capacity */
    for (id = WH_KEYID_IDMAX; id > WH_KEYID_ERASED; id--) {
        /* id loop var is not an input client ID so we don't need to handle the
         * global case */
        buildId = WH_MAKE_KEYID(type, user, id);

        /* Check against cache keys using unified cache functions */
        ret = _FindInKeyCacheUnlocked(ctx, buildId, NULL, NULL, NULL, NULL);
        if (ret == WH_ERROR_OK) {
            /* Found in cache, try next ID */
            continue;
        }
        else if (ret != WH_ERROR_NOTFOUND) {
            goto cleanup;
        }

        /* Check if keyId exists in NVM */
        ret = wh_Nvm_GetMetadataUnlocked(server->nvm, buildId, NULL);
        if (ret == WH_ERROR_NOTFOUND) {
            /* key doesn't exist in NVM, we found a candidate ID */
            found = 1;
            break;
        }

        if (ret != WH_ERROR_OK) {
            goto cleanup;
        }
    }

    if (!found) {
        ret = WH_ERROR_NOSPACE;
        goto cleanup;
    }

    /* Return found id */
    *inout_id = buildId;
    ret       = WH_ERROR_OK;

cleanup:
    (void)_UnlockKeystore(server);
    return ret;
}

/* Forward declarations for unlocked functions */
static int _GetCacheSlotUnlocked(whServerContext* server, whKeyId keyId,
                                 uint16_t keySz, uint8_t** outBuf,
                                 whNvmMetadata** outMeta);
static int _GetCacheSlotCheckedUnlocked(whServerContext* server, whKeyId keyId,
                                        uint16_t keySz, uint8_t** outBuf,
                                        whNvmMetadata** outMeta);

/* find a slot to cache a key. If key is already there, is evicted first */
int wh_Server_KeystoreGetCacheSlot(whServerContext* server, whKeyId keyId,
                                   uint16_t keySz, uint8_t** outBuf,
                                   whNvmMetadata** outMeta)
{
    int ret;

    if (server == NULL || (keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE &&
                           keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _GetCacheSlotUnlocked(server, keyId, keySz, outBuf, outMeta);

    (void)_UnlockKeystore(server);
    return ret;
}

int wh_Server_KeystoreGetCacheSlotChecked(whServerContext* server,
                                          whKeyId keyId, uint16_t keySz,
                                          uint8_t**       outBuf,
                                          whNvmMetadata** outMeta)
{
    int ret;

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_CACHE, keyId);
    if (ret == WH_ERROR_OK || ret == WH_ERROR_NOTFOUND) {
        ret = _GetCacheSlotUnlocked(server, keyId, keySz, outBuf, outMeta);
    }

    (void)_UnlockKeystore(server);
    return ret;
}

static int _KeystoreCacheKeyLocked(whServerContext* server, whNvmMetadata* meta,
                                   uint8_t* in, int checked)
{
    uint8_t*       slotBuf  = NULL;
    whNvmMetadata* slotMeta = NULL;
    int            ret;

    /* make sure id is valid */
    if ((server == NULL) || (meta == NULL) || (in == NULL) ||
        WH_KEYID_ISERASED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Use unlocked variants since we already hold the lock */
    if (checked) {
        ret = _GetCacheSlotCheckedUnlocked(server, meta->id, meta->len,
                                           &slotBuf, &slotMeta);
    }
    else {
        ret = _GetCacheSlotUnlocked(server, meta->id, meta->len, &slotBuf,
                                    &slotMeta);
    }
    if (ret == WH_ERROR_OK) {
        memcpy(slotBuf, in, meta->len);
        memcpy((uint8_t*)slotMeta, (uint8_t*)meta, sizeof(whNvmMetadata));

        _MarkKeyCommittedUnlocked(_GetCacheContext(server, meta->id), meta->id,
                                  0);

        WH_DEBUG_SERVER_VERBOSE("hsmCacheKey: cached keyid=0x%X, len=%u\n",
                                meta->id, meta->len);
        WH_DEBUG_VERBOSE_HEXDUMP("[server] cacheKey: key=", in, meta->len);
    }

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                               uint8_t* in)
{
    return _KeystoreCacheKeyLocked(server, meta, in, 0);
}
int wh_Server_KeystoreCacheKeyChecked(whServerContext* server,
                                      whNvmMetadata* meta, uint8_t* in)
{
    return _KeystoreCacheKeyLocked(server, meta, in, 1);
}

static int _FindInCacheUnlocked(whServerContext* server, whKeyId keyId,
                                int* out_index, int* out_big,
                                uint8_t** out_buffer, whNvmMetadata** out_meta)
{
    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    return _FindInKeyCacheUnlocked(ctx, keyId, out_index, out_big, out_buffer,
                                   out_meta);
}

/*
 * Internal unlocked keystore functions.
 * These assume the caller already holds server->nvm->lock for global keys.
 * For use when performing atomic multi-step operations.
 * When WOLFHSM_CFG_THREADSAFE is not defined, these use the regular NVM
 * functions via macros defined in wh_nvm.h.
 */

/* Unlocked version of wh_Server_KeystoreEvictKey.
 * Uses _EvictKeyFromCacheUnlocked which doesn't need the NVM lock. */
static int _EvictKeyUnlocked(whServerContext* server, whNvmId keyId)
{
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ctx = _GetCacheContext(server, keyId);
    return _EvictKeyFromCacheUnlocked(ctx, keyId);
}

/* Unlocked version of wh_Server_KeystoreGetCacheSlot.
 * Uses _EvictKeyUnlocked instead of the locked public version. */
static int _GetCacheSlotUnlocked(whServerContext* server, whKeyId keyId,
                                 uint16_t keySz, uint8_t** outBuf,
                                 whNvmMetadata** outMeta)
{
    whKeyCacheContext* ctx;
    int                ret;
    int                idx       = -1;
    int                isBig     = -1;
    uint8_t*           buf       = NULL;
    whNvmMetadata*     foundMeta = NULL;

    if (server == NULL || (keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE &&
                           keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE)) {
        return WH_ERROR_BADARGS;
    }

    ret = _FindInCacheUnlocked(server, keyId, &idx, &isBig, &buf, &foundMeta);
    if (ret == WH_ERROR_OK) {
        /* Key is already cached; evict it first */
        ret = _EvictKeyUnlocked(server, keyId);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }
    else if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    ctx = _GetCacheContext(server, keyId);
    return _GetKeyCacheSlotUnlocked(ctx, keySz, outBuf, outMeta);
}

/* Unlocked version of wh_Server_KeystoreGetCacheSlotChecked.
 * Uses _KeystoreCheckPolicyUnlocked and _GetCacheSlotUnlocked. */
static int _GetCacheSlotCheckedUnlocked(whServerContext* server, whKeyId keyId,
                                        uint16_t keySz, uint8_t** outBuf,
                                        whNvmMetadata** outMeta)
{
    int ret;
    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_CACHE, keyId);
    if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }
    return _GetCacheSlotUnlocked(server, keyId, keySz, outBuf, outMeta);
}

/* Unlocked version of wh_Server_KeystoreFreshenKey.
 * Uses wh_Nvm_*Unlocked functions for NVM access. */
static int _FreshenKeyUnlocked(whServerContext* server, whKeyId keyId,
                               uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int             ret            = 0;
    int             foundIndex     = -1;
    int             foundBigIndex  = -1;
    uint8_t*        cacheBufLocal  = NULL;
    whNvmMetadata*  cacheMetaLocal = NULL;
    uint8_t**       cacheBufOut;
    whNvmMetadata** cacheMetaOut;
    whNvmMetadata   tmpMeta[1];

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    /* Use local buffers to allow for optional (NULL) output parameters */
    cacheBufOut  = (outBuf != NULL) ? outBuf : (uint8_t**)&cacheBufLocal;
    cacheMetaOut = (outMeta != NULL) ? outMeta : &cacheMetaLocal;

    ret = _FindInCacheUnlocked(server, keyId, &foundIndex, &foundBigIndex,
                               cacheBufOut, cacheMetaOut);
    if (ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    /* Key not in the cache */

    /* For wrapped keys, just probe the cache and error if not found. We
     * don't support automatically unwrapping and caching outside of the
     * keywrap API */
    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_NOTFOUND;
    }

    /* Not in cache. Check if it is in NVM */
    ret = wh_Nvm_GetMetadataUnlocked(server->nvm, keyId, tmpMeta);
    if (ret == WH_ERROR_OK) {
        /* Key found in NVM, get a free cache slot */
        ret = _GetCacheSlotUnlocked(server, keyId, tmpMeta->len, cacheBufOut,
                                    cacheMetaOut);
        if (ret == WH_ERROR_OK) {
            /* Read the key from NVM into the cache slot */
            ret = wh_Nvm_ReadUnlocked(server->nvm, keyId, 0, tmpMeta->len,
                                      *cacheBufOut);
            if (ret == WH_ERROR_OK) {
                /* Copy the metadata to the cache slot if key read is
                 * successful */
                memcpy((uint8_t*)*cacheMetaOut, (uint8_t*)tmpMeta,
                       sizeof(whNvmMetadata));
                _MarkKeyCommittedUnlocked(_GetCacheContext(server, keyId),
                                          keyId, 1);
            }
        }
    }

    return ret;
}

/* Unlocked version of wh_Server_KeystoreCommitKey.
 * Uses wh_Nvm_AddObjectWithReclaimUnlocked for NVM access. */
static int _CommitKeyUnlocked(whServerContext* server, whNvmId keyId)
{
    uint8_t*           slotBuf;
    whNvmMetadata*     slotMeta;
    whNvmSize          size;
    int                ret;
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

    ctx = _GetCacheContext(server, keyId);

    /* Find the key in the appropriate cache context */
    ret = _FindInKeyCacheUnlocked(ctx, keyId, NULL, NULL, &slotBuf, &slotMeta);
    if (ret == WH_ERROR_OK) {
        size = slotMeta->len;
        ret  = wh_Nvm_AddObjectWithReclaimUnlocked(server->nvm, slotMeta, size,
                                                   slotBuf);
        if (ret == 0) {
            (void)_MarkKeyCommittedUnlocked(ctx, keyId, 1);
        }
    }

    return ret;
}

/* Unlocked version of _KeystoreCacheKeyLocked.
 * Uses _GetCacheSlotUnlocked to avoid re-acquiring the lock. */
static int _CacheKeyUnlocked(whServerContext* server, whNvmMetadata* meta,
                             uint8_t* in)
{
    uint8_t*       slotBuf;
    whNvmMetadata* slotMeta;
    int            ret;

    if ((server == NULL) || (meta == NULL) || (in == NULL) ||
        WH_KEYID_ISERASED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    ret =
        _GetCacheSlotUnlocked(server, meta->id, meta->len, &slotBuf, &slotMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    memcpy(slotBuf, in, meta->len);
    memcpy((uint8_t*)slotMeta, (uint8_t*)meta, sizeof(whNvmMetadata));
    _MarkKeyCommittedUnlocked(_GetCacheContext(server, meta->id), meta->id, 0);

    return WH_ERROR_OK;
}

/* Unlocked version of wh_Server_KeystoreReadKey.
 * Uses unlocked NVM functions and _CacheKeyUnlocked. */
static int _ReadKeyUnlocked(whServerContext* server, whKeyId keyId,
                            whNvmMetadata* outMeta, uint8_t* out,
                            uint32_t* outSz)
{
    int            ret = 0;
    whNvmMetadata  meta[1];
    whNvmMetadata* cacheMeta   = NULL;
    uint8_t*       cacheBuffer = NULL;

    if ((server == NULL) || (outSz == NULL) ||
        (WH_KEYID_ISERASED(keyId) &&
         (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_SHE))) {
        return WH_ERROR_BADARGS;
    }

    /* Check the cache using unified function */
    ret = _FindInCacheUnlocked(server, keyId, NULL, NULL, &cacheBuffer,
                               &cacheMeta);
    if (ret == WH_ERROR_OK) {
        /* Found in cache */
        if (cacheMeta->len > *outSz) {
            return WH_ERROR_NOSPACE;
        }
        if (outMeta != NULL) {
            memcpy((uint8_t*)outMeta, (uint8_t*)cacheMeta,
                   sizeof(whNvmMetadata));
        }
        if (out != NULL) {
            memcpy(out, cacheBuffer, cacheMeta->len);
        }
        *outSz = cacheMeta->len;
        return 0;
    }

    /* For wrapped keys, just probe the cache and error if not found. We
     * don't support automatically unwrapping and caching outside of the
     * keywrap API */
    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_NOTFOUND;
    }

    /* Not in cache, try to read the metadata from NVM */
    ret = wh_Nvm_GetMetadataUnlocked(server->nvm, keyId, meta);
    if (ret == 0) {
        /* set outSz */
        *outSz = meta->len;
        /* read meta */
        if (outMeta != NULL)
            memcpy((uint8_t*)outMeta, (uint8_t*)meta, sizeof(meta));
        /* read the object */
        if (out != NULL)
            ret = wh_Nvm_ReadUnlocked(server->nvm, keyId, 0, *outSz, out);
    }
    /* cache key if free slot, will only kick out other committed keys */
    if (ret == 0 && out != NULL) {
        (void)_CacheKeyUnlocked(server, meta, out);
    }
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* use empty key of zeros if we couldn't find the master ecu key */
    if ((ret == WH_ERROR_NOTFOUND) &&
        (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_SHE) &&
        (WH_KEYID_ID(keyId) == WH_SHE_MASTER_ECU_KEY_ID)) {
        memset(out, 0, WH_SHE_KEY_SZ);
        *outSz = WH_SHE_KEY_SZ;
        if (outMeta != NULL) {
            /* need empty flags and correct length and id */
            memset(outMeta, 0, sizeof(meta));
            meta->len = WH_SHE_KEY_SZ;
            meta->id  = keyId;
        }
        ret = 0;
    }
#endif
    return ret;
}

#ifdef WOLFHSM_CFG_KEYWRAP
static int _ExistsInCacheUnlocked(whServerContext* server, whKeyId keyId)
{
    int            ret           = 0;
    int            foundIndex    = -1;
    int            foundBigIndex = -1;
    whNvmMetadata* tmpMeta;
    uint8_t*       tmpBuf;

    ret = _FindInCacheUnlocked(server, keyId, &foundIndex, &foundBigIndex,
                               &tmpBuf, &tmpMeta);

    if (ret != WH_ERROR_OK) {
        /* Key doesn't exist in the cache */
        return 0;
    }

    /* Key exists in the cache */
    return 1;
}
#endif /* WOLFHSM_CFG_KEYWRAP */

/* try to put the specified key into cache if it isn't already, return pointers
 * to meta and the cached data*/
int wh_Server_KeystoreFreshenKey(whServerContext* server, whKeyId keyId,
                                 uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int ret;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _FreshenKeyUnlocked(server, keyId, outBuf, outMeta);

    (void)_UnlockKeystore(server);

    return ret;
}

/* Reads key from cache or NVM. If keyId is a wrapped key will attempt to read
 * from cache but NOT from NVM */
int wh_Server_KeystoreReadKey(whServerContext* server, whKeyId keyId,
                              whNvmMetadata* outMeta, uint8_t* out,
                              uint32_t* outSz)
{
    int ret;

    if ((server == NULL) || (outSz == NULL) ||
        (WH_KEYID_ISERASED(keyId) &&
         (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_SHE))) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _ReadKeyUnlocked(server, keyId, outMeta, out, outSz);

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreReadKeyChecked(whServerContext* server, whKeyId keyId,
                                     whNvmMetadata* outMeta, uint8_t* out,
                                     uint32_t* outSz)
{
    int ret;

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_EXPORT, keyId);
    if (ret == WH_ERROR_OK) {
        ret = _ReadKeyUnlocked(server, keyId, outMeta, out, outSz);
    }

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreEvictKey(whServerContext* server, whNvmId keyId)
{
    int                ret = 0;
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, keyId);

    /* Use the unified evict function */
    ret = _EvictKeyFromCacheUnlocked(ctx, keyId);

    if (ret == 0) {
        WH_DEBUG_SERVER_VERBOSE("wh_Server_KeystoreEvictKey: evicted keyid=0x%X\n",
               keyId);
    }

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreEvictKeyChecked(whServerContext* server, whNvmId keyId)
{
    int ret;

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_EVICT, keyId);
    if (ret == WH_ERROR_OK) {
        ret = _EvictKeyUnlocked(server, keyId);
    }

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreCommitKey(whServerContext* server, whNvmId keyId)
{
    int ret;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _CommitKeyUnlocked(server, keyId);

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreCommitKeyChecked(whServerContext* server, whNvmId keyId)
{
    int ret;

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_COMMIT, keyId);
    if (ret == WH_ERROR_OK) {
        ret = _CommitKeyUnlocked(server, keyId);
    }

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreEraseKey(whServerContext* server, whNvmId keyId)
{
    int ret;

    if ((server == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Remove the key from the cache if present */
    (void)_EvictKeyUnlocked(server, keyId);

    /* Destroy the object */
    ret = wh_Nvm_DestroyObjectsUnlocked(server->nvm, 1, &keyId);

    (void)_UnlockKeystore(server);

    return ret;
}

int wh_Server_KeystoreEraseKeyChecked(whServerContext* server, whNvmId keyId)
{
    int           ret;
    whNvmMetadata meta;

    if ((server == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Check eviction policy first */
    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_EVICT, keyId);
    if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        goto cleanup;
    }

    /* Check NVM destroy policy (NONMODIFIABLE/NONDESTROYABLE enforcement) */
    ret = wh_Nvm_GetMetadataUnlocked(server->nvm, keyId, &meta);
    if (ret == WH_ERROR_OK) {
        if (meta.flags &
            (WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE)) {
            ret = WH_ERROR_ACCESS;
            goto cleanup;
        }
    }
    else if (ret != WH_ERROR_NOTFOUND) {
        goto cleanup;
    }

    /* Remove the key from the cache if present */
    (void)_EvictKeyUnlocked(server, keyId);

    /* Destroy the object */
    ret = wh_Nvm_DestroyObjectsUnlocked(server->nvm, 1, &keyId);

cleanup:
    (void)_UnlockKeystore(server);
    return ret;
}

static void _revokeKey(whNvmMetadata* meta)
{

    /* Set NONMODIFIABLE flag and clear all usage flags */
    meta->flags |= WH_NVM_FLAGS_NONMODIFIABLE;
    meta->flags &= ~WH_NVM_FLAGS_USAGE_ANY;
}

static int _isKeyRevoked(whNvmMetadata* meta)
{
    if ((meta->flags & WH_NVM_FLAGS_NONMODIFIABLE) &&
        ((meta->flags & WH_NVM_FLAGS_USAGE_ANY) == 0)) {
        return 1;
    }

    return 0;
}

int wh_Server_KeystoreRevokeKey(whServerContext* server, whNvmId keyId)
{
    int            ret;
    int            isInNvm   = 0;
    uint8_t*       cacheBuf  = NULL;
    whNvmMetadata* cacheMeta = NULL;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_REVOKE, keyId);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* Check if key is in NVM */
    ret = wh_Nvm_GetMetadataUnlocked(server->nvm, keyId, NULL);
    if (ret == WH_ERROR_OK) {
        isInNvm = 1;
    }
    else if (ret != WH_ERROR_NOTFOUND) {
        goto cleanup;
    }

    /* Freshen key into cache */
    ret = _FreshenKeyUnlocked(server, keyId, &cacheBuf, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* If already revoked and committed, nothing to do */
    if (_isKeyRevoked(cacheMeta) && _KeyIsCommittedUnlocked(server, keyId)) {
        ret = WH_ERROR_OK;
        goto cleanup;
    }

    /* Revoke the key by updating its metadata */
    _revokeKey(cacheMeta);

    /* Commit the changes */
    if (isInNvm) {
        ret = wh_Nvm_AddObjectWithReclaimUnlocked(server->nvm, cacheMeta,
                                                  cacheMeta->len, cacheBuf);
        if (ret == WH_ERROR_OK) {
            _MarkKeyCommittedUnlocked(_GetCacheContext(server, keyId), keyId,
                                      1);
        }
    }

cleanup:
    (void)_UnlockKeystore(server);
    return ret;
}

#ifdef WOLFHSM_CFG_KEYWRAP

#ifndef NO_AES
#ifdef HAVE_AESGCM

static int _AesGcmKeyWrap(whServerContext* server, whKeyId serverKeyId,
                          uint8_t* keyIn, uint16_t keySz,
                          whNvmMetadata* metadataIn, uint8_t* wrappedKeyOut,
                          uint16_t wrappedKeySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t* serverKey;
    uint32_t serverKeySz;
    whNvmMetadata* serverKeyMetadata;
    uint8_t  plainBlob[sizeof(*metadataIn) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    uint32_t plainBlobSz = sizeof(*metadataIn) + keySz;
    uint8_t* encBlob;

    if (server == NULL || keyIn == NULL || metadataIn == NULL ||
        wrappedKeyOut == NULL || plainBlobSz > sizeof(plainBlob)) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the buffer is big enough to hold the wrapped key */
    if (wrappedKeySz <
        sizeof(iv) + sizeof(authTag) + sizeof(*metadataIn) + keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Get the server side key */
    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId,
                                       &serverKey, &serverKeyMetadata);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    serverKeySz = serverKeyMetadata->len;

    /* Validate key usage policy for wrapping (KEK) */
    ret = wh_Server_KeystoreEnforceKeyUsage(serverKeyMetadata,
                                            WH_NVM_FLAGS_USAGE_WRAP);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Generate the IV */
    ret = wc_RNG_GenerateBlock(server->crypto->rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Combine key and metadata into one blob */
    memcpy(plainBlob, metadataIn, sizeof(*metadataIn));
    memcpy(plainBlob + sizeof(*metadataIn), keyIn, keySz);

    /* Place the encrypted blob after the IV and Auth Tag */
    encBlob = (uint8_t*)wrappedKeyOut + sizeof(iv) + sizeof(authTag);

    /* Encrypt the blob */
    ret = wc_AesGcmEncrypt(aes, encBlob, plainBlob, plainBlobSz, iv,
                           sizeof(iv), authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Prepend IV + authTag to encrypted blob */
    memcpy(wrappedKeyOut, iv, sizeof(iv));
    memcpy(wrappedKeyOut + sizeof(iv), authTag, sizeof(authTag));

    wc_AesFree(aes);

    return WH_ERROR_OK;
}

static int _AesGcmKeyUnwrap(whServerContext* server, uint16_t serverKeyId,
                            void* wrappedKeyIn, uint16_t wrappedKeySz,
                            whNvmMetadata* metadataOut, void* keyOut,
                            uint16_t keySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t* serverKey;
    uint32_t serverKeySz;
    whNvmMetadata* serverKeyMetadata;
    uint8_t* encBlob   = (uint8_t*)wrappedKeyIn + sizeof(iv) + sizeof(authTag);
    uint16_t encBlobSz = wrappedKeySz - sizeof(iv) - sizeof(authTag);
    uint8_t  plainBlob[sizeof(*metadataOut) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];

    if (server == NULL || wrappedKeyIn == NULL || metadataOut == NULL ||
        keyOut == NULL || keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }


    /* Get the server side key */
    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId,
                                       &serverKey, &serverKeyMetadata);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    serverKeySz = serverKeyMetadata->len;

    /* Validate key usage policy for unwrapping (KEK) */
    ret = wh_Server_KeystoreEnforceKeyUsage(serverKeyMetadata,
                                            WH_NVM_FLAGS_USAGE_WRAP);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        return ret;
    }

    /* Extract IV and authTag from wrappedKeyIn */
    memcpy(iv, wrappedKeyIn, sizeof(iv));
    memcpy(authTag, wrappedKeyIn + sizeof(iv), sizeof(authTag));

    /* Decrypt the encrypted blob */
    ret = wc_AesGcmDecrypt(aes, plainBlob, encBlob, encBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Extract metadata and key from the decrypted blob */
    memcpy(metadataOut, plainBlob, sizeof(*metadataOut));
    memcpy(keyOut, plainBlob + sizeof(*metadataOut), keySz);

    wc_AesFree(aes);
    return WH_ERROR_OK;
}

static int _AesGcmDataWrap(whServerContext* server, whKeyId serverKeyId,
                           uint8_t* dataIn, uint16_t dataSz,
                           uint8_t* wrappedDataOut, uint16_t wrappedDataSz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t* serverKey;
    uint32_t serverKeySz;
    whNvmMetadata* serverKeyMetadata;
    uint8_t* encBlob;

    if (server == NULL || dataIn == NULL || wrappedDataOut == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the buffer is big enough to hold the wrapped data */
    if (wrappedDataSz < sizeof(iv) + sizeof(authTag) + dataSz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Get the server side key */
    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId,
                                       &serverKey, &serverKeyMetadata);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    serverKeySz = serverKeyMetadata->len;

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Generate the IV */
    ret = wc_RNG_GenerateBlock(server->crypto->rng, iv, sizeof(iv));
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Place the encrypted blob after the IV and Auth Tag */
    encBlob = (uint8_t*)wrappedDataOut + sizeof(iv) + sizeof(authTag);

    /* Encrypt the blob */
    ret = wc_AesGcmEncrypt(aes, encBlob, dataIn, dataSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    /* Prepend IV + authTag to encrypted blob */
    memcpy(wrappedDataOut, iv, sizeof(iv));
    memcpy(wrappedDataOut + sizeof(iv), authTag, sizeof(authTag));

    wc_AesFree(aes);

    return WH_ERROR_OK;
}

static int _AesGcmDataUnwrap(whServerContext* server, uint16_t serverKeyId,
                             void* wrappedDataIn, uint16_t wrappedDataSz,
                             void* dataOut, uint16_t dataSz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t*  serverKey;
    uint32_t serverKeySz;
    whNvmMetadata* serverKeyMetadata;
    uint8_t* encBlob   = (uint8_t*)wrappedDataIn + sizeof(iv) + sizeof(authTag);
    uint16_t encBlobSz = wrappedDataSz - sizeof(iv) - sizeof(authTag);

    if (server == NULL || wrappedDataIn == NULL || dataOut == NULL ||
        dataSz > WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key */
    ret = wh_Server_KeystoreFreshenKey(server, serverKeyId,
                                       &serverKey, &serverKeyMetadata);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    serverKeySz = serverKeyMetadata->len;

    /* Initialize AES context and set it to use the server side key */
    ret = wc_AesInit(aes, NULL, server->crypto->devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_AesGcmSetKey(aes, serverKey, serverKeySz);
    if (ret != 0) {
        return ret;
    }

    /* Extract IV and authTag from wrappedDataIn */
    memcpy(iv, wrappedDataIn, sizeof(iv));
    memcpy(authTag, wrappedDataIn + sizeof(iv), sizeof(authTag));

    /* Decrypt the encrypted blob */
    ret = wc_AesGcmDecrypt(aes, dataOut, encBlob, encBlobSz, iv, sizeof(iv),
                           authTag, sizeof(authTag), NULL, 0);
    if (ret != 0) {
        wc_AesFree(aes);
        return ret;
    }

    wc_AesFree(aes);
    return WH_ERROR_OK;
}

#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

static int _HandleKeyWrapRequest(whServerContext*                  server,
                                 whMessageKeystore_KeyWrapRequest* req,
                                 uint8_t* reqData, uint32_t reqDataSz,
                                 whMessageKeystore_KeyWrapResponse* resp,
                                 uint8_t* respData, uint32_t respDataSz)
{

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata;
    uint8_t       key[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    whKeyId       serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL ||
        resp == NULL || respData == NULL ||
        req->keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE)
    {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the metadata and key */
    if (reqDataSz < sizeof(metadata) + req->keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Extract the metadata and key from reqData */
    memcpy(&metadata, reqData, sizeof(metadata));
    memcpy(key, reqData + sizeof(metadata), req->keySz);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Wrapped key size is only passed back to the client on success */
    resp->wrappedKeySz = 0;

    /* Ensure the keyId in the wrapped metadata has the wrapped flag set */
    if (!WH_KEYID_ISWRAPPED(metadata.id)) {
        WH_LOG_F(&server->log, WH_LOG_LEVEL_ERROR,
                 "KeyWrapRequest: keyId:0x%08X is not wrapped", metadata.id);
        return WH_ERROR_BADARGS;
    }

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, 
                                               server->comm->client_id, 
                                               req->serverKeyId);

    /* Store the wrapped key in the response data */
    wrappedKey = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedKeySz =
                WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(metadata) + req->keySz;

            /* Check if the response data can fit the wrapped key */
            if (respDataSz < wrappedKeySz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Wrap the key */
            ret = _AesGcmKeyWrap(server, serverKeyId, key, req->keySz,
                                 &metadata, wrappedKey, wrappedKeySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the wrapped key is */
            resp->wrappedKeySz = wrappedKeySz;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _HandleKeyUnwrapAndExportRequest(
    whServerContext* server, whMessageKeystore_KeyUnwrapAndExportRequest* req,
    uint8_t* reqData, uint32_t reqDataSz,
    whMessageKeystore_KeyUnwrapAndExportResponse* resp, uint8_t* respData,
    uint32_t respDataSz)
{
    int            ret;
    uint8_t*       wrappedKey;
    whNvmMetadata* metadata;
    uint8_t*       key;
    whKeyId        serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, 
                                               server->comm->client_id, 
                                               req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Key size is only passed back to the client on success */
    resp->keySz = 0;

    /* Store the metadata and key in the respData */
    metadata = (whNvmMetadata*)respData;
    key      = respData + sizeof(*metadata);

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t keySz = req->wrappedKeySz -
                             WH_KEYWRAP_AES_GCM_HEADER_SIZE - sizeof(*metadata);

            /* Check if the response data can fit the metadata + key  */
            if (respDataSz < sizeof(*metadata) + keySz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Unwrap the key */
            ret = _AesGcmKeyUnwrap(server, serverKeyId, wrappedKey,
                                   req->wrappedKeySz, metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Dynamic keyId generation for wrapped keys is not allowed */
            if (WH_KEYID_ISERASED(metadata->id)) {
                /* Wrapped keys must use explicit identifiers */
                return WH_ERROR_BADARGS;
            }

            /* Extract ownership from unwrapped metadata (preserves original
             * owner) */
            uint16_t wrappedKeyUser = WH_KEYID_USER(metadata->id);
            uint16_t wrappedKeyType = WH_KEYID_TYPE(metadata->id);

            /* Require explicit wrapped-key encoding */
            if (wrappedKeyType != WH_KEYTYPE_WRAPPED) {
                return WH_ERROR_ABORTED;
            }

            /* Check if the key is exportable */
            if (metadata->flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }

            /* Validate ownership: USER field must match requesting client.
             * The USER field specifies who owns this wrapped key. */
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
            /* Global keys (USER=0) can be exported by any client */
            if (wrappedKeyUser != WH_KEYUSER_GLOBAL &&
                wrappedKeyUser != server->comm->client_id) {
                return WH_ERROR_ACCESS;
            }
#else
            /* Without global keys, USER must match requesting client */
            if (wrappedKeyUser != server->comm->client_id) {
                return WH_ERROR_ACCESS;
            }
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

            /* Tell the client how big the key is on success */
            resp->keySz = keySz;
        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return ret;
}

static int _HandleKeyUnwrapAndCacheRequest(
    whServerContext* server, whMessageKeystore_KeyUnwrapAndCacheRequest* req,
    uint8_t* reqData, uint32_t reqDataSz,
    whMessageKeystore_KeyUnwrapAndCacheResponse* resp, uint8_t* respData,
    uint32_t respDataSz)
{
    /* The server doesn't have any extra response data to send back to the
     * client */
    (void)respData;
    (void)respDataSz;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL) {
        return WH_ERROR_BADARGS;
    }

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata = {0};
    uint16_t      keySz = 0;
    uint8_t       key[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];
    whKeyId       serverKeyId;

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, 
                                               server->comm->client_id, 
                                               req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Key ID is only passed back to the client on success */
    resp->keyId = WH_KEYID_ERASED;

    /* Unwrap the key based on the cipher type */
    switch (req->cipherType) {
#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            keySz = req->wrappedKeySz - WH_KEYWRAP_AES_GCM_HEADER_SIZE -
                    sizeof(metadata);
            resp->cipherType = WC_CIPHER_AES_GCM;

            ret = _AesGcmKeyUnwrap(server, serverKeyId, wrappedKey,
                                   req->wrappedKeySz, &metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }


        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
        default:
            return WH_ERROR_BADARGS;
    }

    /* Verify the key size argument and key size from the the metadata match */
    if (keySz != metadata.len) {
        return WH_ERROR_BADARGS;
    }

    /* Dynamic keyId generation for wrapped keys is not allowed */
    if (WH_KEYID_ISERASED(metadata.id)) {
        /* Wrapped keys must use explicit identifiers */
        return WH_ERROR_BADARGS;
    }

    /* Extract ownership from unwrapped metadata (preserves original owner) */
    uint16_t wrappedKeyUser = WH_KEYID_USER(metadata.id);
    uint16_t wrappedKeyType = WH_KEYID_TYPE(metadata.id);

    /* Require explicit wrapped-key encoding */
    if (wrappedKeyType != WH_KEYTYPE_WRAPPED) {
        return WH_ERROR_ABORTED;
    }

    /* Validate ownership: USER field must match requesting client.
     * The USER field specifies who owns this wrapped key. */
#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Global keys (USER=0): any client can unwrap and cache to global cache
     * Local keys (USER!=0): only owning client can unwrap and cache */
    if (wrappedKeyUser != WH_KEYUSER_GLOBAL &&
        wrappedKeyUser != server->comm->client_id) {
        return WH_ERROR_ACCESS;
    }
#else
    /* Without global keys, USER must match requesting client */
    if (wrappedKeyUser != server->comm->client_id) {
        return WH_ERROR_ACCESS;
    }
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

    /* Ensure a key with the unwrapped ID does not already exist in cache */
    if (_ExistsInCacheUnlocked(server, metadata.id)) {
        return WH_ERROR_ABORTED;
    }

    /* Store the assigned key ID in the response, preserving client flags */
    resp->keyId = wh_KeyId_TranslateToClient(metadata.id);

    /* Cache the key */
    return wh_Server_KeystoreCacheKey(server, &metadata, key);
}

static int _HandleDataWrapRequest(whServerContext*                   server,
                                  whMessageKeystore_DataWrapRequest* req,
                                  uint8_t* reqData, uint32_t reqDataSz,
                                  whMessageKeystore_DataWrapResponse* resp,
                                  uint8_t* respData, uint32_t respDataSz)
{

    int      ret;
    uint8_t* wrappedData;
    uint8_t  data[WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE];
    whKeyId  serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL || req->dataSz > WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the data */
    if (reqDataSz < req->dataSz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Extract the metadata and data from reqData */
    memcpy(data, reqData, req->dataSz);

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO, 
                                               server->comm->client_id, 
                                               req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Wrapped data size is only passed back to the client on success */
    resp->wrappedDataSz = 0;

    /* Store the wrapped data in the response data */
    wrappedData = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedDataSz =
                WH_KEYWRAP_AES_GCM_HEADER_SIZE + req->dataSz;

            /* Check if the response data can fit the wrapped data */
            if (respDataSz < wrappedDataSz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Wrap the data */
            ret = _AesGcmDataWrap(server, serverKeyId, data, req->dataSz,
                                  wrappedData, wrappedDataSz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the wrapped data is */
            resp->wrappedDataSz = wrappedDataSz;
            resp->cipherType    = WC_CIPHER_AES_GCM;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _HandleDataUnwrapRequest(whServerContext*                     server,
                                    whMessageKeystore_DataUnwrapRequest* req,
                                    uint8_t* reqData, uint32_t reqDataSz,
                                    whMessageKeystore_DataUnwrapResponse* resp,
                                    uint8_t* respData, uint32_t respDataSz)
{
    int      ret;
    uint8_t* wrappedData;
    uint8_t* data;
    whKeyId  serverKeyId;

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the data */
    if (reqDataSz < req->wrappedDataSz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped data to the reqData */
    wrappedData = reqData;

    /* Translate the server key id passed in from the client */
    serverKeyId = wh_KeyId_TranslateFromClient(
        WH_KEYTYPE_CRYPTO, server->comm->client_id, req->serverKeyId);

    /* Ensure the cipher type in the response matches the request */
    resp->cipherType = req->cipherType;
    /* Data size is only passed back to the client on success */
    resp->dataSz = 0;

    /* Store the unwrapped data in the respData */
    data = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t dataSz =
                req->wrappedDataSz - WH_KEYWRAP_AES_GCM_HEADER_SIZE;

            /* Check if the response data can fit the unwrapped data */
            if (respDataSz < dataSz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Unwrap the data */
            ret = _AesGcmDataUnwrap(server, serverKeyId, wrappedData,
                                    req->wrappedDataSz, data, dataSz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the unwrapped data is */
            resp->dataSz     = dataSz;
            resp->cipherType = WC_CIPHER_AES_GCM;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_KEYWRAP */

int wh_Server_HandleKeyRequest(whServerContext* server, uint16_t magic,
                               uint16_t action, uint16_t req_size,
                               const void* req_packet, uint16_t* out_resp_size,
                               void* resp_packet)
{
    (void)req_size;

    int           ret = WH_ERROR_OK;
    uint8_t*      in;
    uint8_t*      out;
    whNvmMetadata meta[1] = {{0}};

    /* validate args, even though these functions are only supposed to be
     * called by internal functions */
    if ((server == NULL) || (req_packet == NULL) || (out_resp_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_KEY_CACHE: {
            whMessageKeystore_CacheRequest  req;
            whMessageKeystore_CacheResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateCacheRequest(
                magic, (whMessageKeystore_CacheRequest*)req_packet, &req);

            /* in is after fixed size fields */
            in = (uint8_t*)req_packet + sizeof(req);

            /* set the metadata fields */
            meta->id = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = req.flags;
            meta->len    = req.sz;
            /* truncate label if it's too large */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                req.labelSz = WH_NVM_LABEL_LEN;
            }
            memcpy(meta->label, req.label, req.labelSz);

            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret     = wh_Server_KeystoreGetUniqueId(server, &meta->id);
                resp.rc = ret;
            }
            /* write the key */
            if (ret == WH_ERROR_OK) {
                ret     = wh_Server_KeystoreCacheKeyChecked(server, meta, in);
                resp.rc = ret;
            }
            if (ret == WH_ERROR_OK) {
                /* Translate server keyId back to client format with flags */
                resp.id = wh_KeyId_TranslateToClient(meta->id);
            }

            (void)wh_MessageKeystore_TranslateCacheResponse(
                magic, &resp, (whMessageKeystore_CacheResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

#ifdef WOLFHSM_CFG_DMA

        case WH_KEY_CACHE_DMA: {
            whMessageKeystore_CacheDmaRequest  req;
            whMessageKeystore_CacheDmaResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateCacheDmaRequest(
                magic, (whMessageKeystore_CacheDmaRequest*)req_packet, &req);

            /* set the metadata fields */
            meta->id = wh_KeyId_TranslateFromClient(
                WH_KEYTYPE_CRYPTO, server->comm->client_id, req.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = req.flags;
            meta->len    = req.key.sz;
            /* truncate label if it's too large */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                req.labelSz = WH_NVM_LABEL_LEN;
            }
            memcpy(meta->label, req.label, req.labelSz);

            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret     = wh_Server_KeystoreGetUniqueId(server, &meta->id);
                resp.rc = ret;
            }

            /* write the key using DMA */
            if (ret == WH_ERROR_OK) {
                ret     = wh_Server_KeystoreCacheKeyDmaChecked(server, meta,
                                                               req.key.addr);
                resp.rc = ret;
                /* propagate bad address to client if DMA operation failed */
                if (ret != WH_ERROR_OK) {
                    resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                    resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
                }
            }

            /* Translate server keyId back to client format with flags */
            resp.id = wh_KeyId_TranslateToClient(meta->id);

            (void)wh_MessageKeystore_TranslateCacheDmaResponse(
                magic, &resp, (whMessageKeystore_CacheDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_EXPORT_DMA: {
            whMessageKeystore_ExportDmaRequest  req;
            whMessageKeystore_ExportDmaResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateExportDmaRequest(
                magic, (whMessageKeystore_ExportDmaRequest*)req_packet, &req);

            ret = wh_Server_KeystoreExportKeyDmaChecked(
                server,
                wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             server->comm->client_id, req.id),
                req.key.addr, req.key.sz, meta);
            resp.rc = ret;

            /* propagate bad address to client if DMA operation failed */
            if (ret != WH_ERROR_OK) {
                resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
            }

            if (ret == WH_ERROR_OK) {
                resp.len = req.key.sz;
                memcpy(resp.label, meta->label, sizeof(meta->label));
            }

            (void)wh_MessageKeystore_TranslateExportDmaResponse(
                magic, &resp,
                (whMessageKeystore_ExportDmaResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;
#endif /* WOLFHSM_CFG_DMA */

        case WH_KEY_EVICT: {
            whMessageKeystore_EvictRequest  req;
            whMessageKeystore_EvictResponse resp = {0};

            (void)wh_MessageKeystore_TranslateEvictRequest(
                magic, (whMessageKeystore_EvictRequest*)req_packet, &req);

            ret = wh_Server_KeystoreEvictKeyChecked(
                server,
                wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             server->comm->client_id, req.id));
            resp.rc = ret;
            resp.ok = 0; /* unused */

            (void)wh_MessageKeystore_TranslateEvictResponse(
                magic, &resp, (whMessageKeystore_EvictResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_EXPORT: {
            whMessageKeystore_ExportRequest  req;
            whMessageKeystore_ExportResponse resp;
            uint32_t                         keySz;

            /* translate request */
            (void)wh_MessageKeystore_TranslateExportRequest(
                magic, (whMessageKeystore_ExportRequest*)req_packet, &req);

            /* out is after fixed size fields */
            out   = (uint8_t*)resp_packet + sizeof(resp);
            keySz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(resp);

            /* read the key */
            ret = wh_Server_KeystoreReadKeyChecked(
                server,
                wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             server->comm->client_id, req.id),
                meta, out, &keySz);

            resp.rc = ret;

            /* Only provide key output if no error */
            if (ret == WH_ERROR_OK) {
                resp.len = keySz;
            }
            else {
                resp.len = 0;
            }
            memcpy(resp.label, meta->label, sizeof(meta->label));

            (void)wh_MessageKeystore_TranslateExportResponse(
                magic, &resp, (whMessageKeystore_ExportResponse*)resp_packet);

            *out_resp_size = sizeof(resp) + resp.len;
        } break;

        case WH_KEY_COMMIT: {
            whMessageKeystore_CommitRequest  req;
            whMessageKeystore_CommitResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateCommitRequest(
                magic, (whMessageKeystore_CommitRequest*)req_packet, &req);

            ret = wh_Server_KeystoreCommitKeyChecked(
                server,
                wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             server->comm->client_id, req.id));
            resp.rc = ret;
            resp.ok = 0; /* unused */

            (void)wh_MessageKeystore_TranslateCommitResponse(
                magic, &resp, (whMessageKeystore_CommitResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_ERASE: {
            whMessageKeystore_EraseRequest  req;
            whMessageKeystore_EraseResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateEraseRequest(
                magic, (whMessageKeystore_EraseRequest*)req_packet, &req);

            ret = wh_Server_KeystoreEraseKeyChecked(
                server,
                wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             server->comm->client_id, req.id));
            resp.rc = ret;
            resp.ok = 0; /* unused */

            (void)wh_MessageKeystore_TranslateEraseResponse(
                magic, &resp, (whMessageKeystore_EraseResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_REVOKE: {
            whMessageKeystore_RevokeRequest  req;
            whMessageKeystore_RevokeResponse resp;

            (void)wh_MessageKeystore_TranslateRevokeRequest(
                magic, (whMessageKeystore_RevokeRequest*)req_packet, &req);

            ret = wh_Server_KeystoreRevokeKey(
                server,
                wh_KeyId_TranslateFromClient(WH_KEYTYPE_CRYPTO,
                                             server->comm->client_id, req.id));
            resp.rc = ret;
            ret     = WH_ERROR_OK;

            (void)wh_MessageKeystore_TranslateRevokeResponse(
                magic, &resp, (whMessageKeystore_RevokeResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

#ifdef WOLFHSM_CFG_KEYWRAP
        case WH_KEY_KEYWRAP: {
            whMessageKeystore_KeyWrapRequest  wrapReq  = {0};
            whMessageKeystore_KeyWrapResponse wrapResp = {0};
            uint8_t*                       reqData;
            uint8_t*                       respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateKeyWrapRequest(magic, req_packet,
                                                             &wrapReq);


            /* Set the request data pointer directly after the request */
            reqData =
                (uint8_t*)req_packet + sizeof(whMessageKeystore_KeyWrapRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_KeyWrapResponse);

            ret = _HandleKeyWrapRequest(server, &wrapReq, reqData, reqDataSz,
                                        &wrapResp, respData, respDataSz);
            wrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyWrapResponse(magic, &wrapResp,
                                                              resp_packet);
            *out_resp_size = sizeof(wrapResp) + wrapResp.wrappedKeySz;

        } break;

        case WH_KEY_KEYUNWRAPEXPORT: {
            whMessageKeystore_KeyUnwrapAndExportRequest  unwrapReq  = {0};
            whMessageKeystore_KeyUnwrapAndExportResponse unwrapResp = {0};
            uint8_t*                                  reqData;
            uint8_t*                                  respData;
            uint32_t reqDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapReq);
            uint32_t respDataSz =
                WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateKeyUnwrapAndExportRequest(
                magic, req_packet, &unwrapReq);

            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req_packet +
                      sizeof(whMessageKeystore_KeyUnwrapAndExportRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_KeyUnwrapAndExportResponse);

            ret = _HandleKeyUnwrapAndExportRequest(server, &unwrapReq, reqData,
                                                   reqDataSz, &unwrapResp,
                                                   respData, respDataSz);
            unwrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyUnwrapAndExportResponse(
                magic, &unwrapResp, resp_packet);

            *out_resp_size =
                sizeof(unwrapResp) + sizeof(whNvmMetadata) + unwrapResp.keySz;

        } break;

        case WH_KEY_KEYUNWRAPCACHE: {
            whMessageKeystore_KeyUnwrapAndCacheRequest  cacheReq  = {0};
            whMessageKeystore_KeyUnwrapAndCacheResponse cacheResp = {0};
            uint8_t*                                 reqData;
            uint8_t*                                 respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateKeyUnwrapAndCacheRequest(
                magic, req_packet, &cacheReq);

            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req_packet +
                      sizeof(whMessageKeystore_KeyUnwrapAndCacheRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_KeyUnwrapAndCacheResponse);

            ret = _HandleKeyUnwrapAndCacheRequest(server, &cacheReq, reqData,
                                                  reqDataSz, &cacheResp,
                                                  respData, respDataSz);
            cacheResp.rc = ret;

            (void)wh_MessageKeystore_TranslateKeyUnwrapAndCacheResponse(
                magic, &cacheResp, resp_packet);

            *out_resp_size = sizeof(cacheResp);

        } break;

        case WH_KEY_DATAWRAP: {
            whMessageKeystore_DataWrapRequest  wrapReq  = {0};
            whMessageKeystore_DataWrapResponse wrapResp = {0};
            uint8_t*                           reqData;
            uint8_t*                           respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateDataWrapRequest(magic, req_packet,
                                                              &wrapReq);


            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req_packet +
                      sizeof(whMessageKeystore_DataWrapRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_DataWrapResponse);

            ret = _HandleDataWrapRequest(server, &wrapReq, reqData, reqDataSz,
                                         &wrapResp, respData, respDataSz);
            wrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateDataWrapResponse(magic, &wrapResp,
                                                               resp_packet);
            *out_resp_size = sizeof(wrapResp) + wrapResp.wrappedDataSz;

        } break;

        case WH_KEY_DATAUNWRAP: {
            whMessageKeystore_DataUnwrapRequest  unwrapReq  = {0};
            whMessageKeystore_DataUnwrapResponse unwrapResp = {0};
            uint8_t*                             reqData;
            uint8_t*                             respData;
            uint32_t reqDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapReq);
            uint32_t respDataSz =
                WOLFHSM_CFG_COMM_DATA_LEN - sizeof(unwrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateDataUnwrapRequest(
                magic, req_packet, &unwrapReq);


            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req_packet +
                      sizeof(whMessageKeystore_DataUnwrapRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_DataUnwrapResponse);

            ret =
                _HandleDataUnwrapRequest(server, &unwrapReq, reqData, reqDataSz,
                                         &unwrapResp, respData, respDataSz);
            unwrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateDataUnwrapResponse(
                magic, &unwrapResp, resp_packet);
            *out_resp_size = sizeof(unwrapResp) + unwrapResp.dataSz;

        } break;

#endif /* WOLFHSM_CFG_KEYWRAP */

        default:
            ret = WH_ERROR_NOHANDLER;
            break;
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA

int _KeystoreCacheKeyDma(whServerContext* server, whNvmMetadata* meta,
                         uint64_t keyAddr, int checked)
{
    int                ret;
    uint8_t*           buffer   = NULL;
    whNvmMetadata*     slotMeta = NULL;

    if ((server == NULL) || (meta == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Get a cache slot, optionally checking if necessary */
    if (checked) {
        ret = _GetCacheSlotCheckedUnlocked(server, meta->id, meta->len, &buffer,
                                           &slotMeta);
    }
    else {
        ret = _GetCacheSlotUnlocked(server, meta->id, meta->len, &buffer,
                                    &slotMeta);
    }
    if (ret != 0) {
        goto cleanup;
    }

    /* Copy metadata */
    memcpy(slotMeta, meta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyFromClient(server, buffer, keyAddr, meta->len,
                                     (whServerDmaFlags){0});
    if (ret != 0) {
        /* Clear the slot on error */
        memset(buffer, 0, meta->len);
        slotMeta->id = WH_KEYID_ERASED;
    }
    else {
        _MarkKeyCommittedUnlocked(_GetCacheContext(server, meta->id), meta->id,
                                  0);
    }

cleanup:
    (void)_UnlockKeystore(server);
    return ret;
}
int wh_Server_KeystoreCacheKeyDma(whServerContext* server, whNvmMetadata* meta,
                                  uint64_t keyAddr)
{
    return _KeystoreCacheKeyDma(server, meta, keyAddr, 0);
}

int wh_Server_KeystoreCacheKeyDmaChecked(whServerContext* server,
                                         whNvmMetadata* meta, uint64_t keyAddr)
{
    return _KeystoreCacheKeyDma(server, meta, keyAddr, 1);
}

int wh_Server_KeystoreExportKeyDma(whServerContext* server, whKeyId keyId,
                                   uint64_t keyAddr, uint64_t keySz,
                                   whNvmMetadata* outMeta)
{
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* cacheMeta;

    if ((server == NULL) || (outMeta == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* bring key in cache */
    ret = _FreshenKeyUnlocked(server, keyId, &buffer, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    if (keySz < cacheMeta->len) {
        ret = WH_ERROR_NOSPACE;
        goto cleanup;
    }

    memcpy(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyToClient(server, keyAddr, buffer, outMeta->len,
                                   (whServerDmaFlags){0});

cleanup:
    (void)_UnlockKeystore(server);
    return ret;
}
int wh_Server_KeystoreExportKeyDmaChecked(whServerContext* server,
                                          whKeyId keyId, uint64_t keyAddr,
                                          uint64_t       keySz,
                                          whNvmMetadata* outMeta)
{
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* cacheMeta;

    if ((server == NULL) || (outMeta == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _KeystoreCheckPolicyUnlocked(server, WH_KS_OP_EXPORT, keyId);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* Freshen key into cache */
    ret = _FreshenKeyUnlocked(server, keyId, &buffer, &cacheMeta);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    if (keySz < cacheMeta->len) {
        ret = WH_ERROR_NOSPACE;
        goto cleanup;
    }

    memcpy(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyToClient(server, keyAddr, buffer, outMeta->len,
                                   (whServerDmaFlags){0});

cleanup:
    (void)_UnlockKeystore(server);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

int wh_Server_KeystoreEnforceKeyUsage(const whNvmMetadata* meta,
                                      whNvmFlags           requiredUsage)
{
    whNvmFlags actualFlags;

    /* Validate input parameters */
    if (meta == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* We only care about the usage flags */
    requiredUsage &= WH_NVM_FLAGS_USAGE_ANY;

    /* Check if the key has ALL the required usage flags set */
    actualFlags = meta->flags & WH_NVM_FLAGS_USAGE_ANY;
    if ((actualFlags & requiredUsage) == requiredUsage) {
        return WH_ERROR_OK;
    }

    /* Key does not have ALL the required usage flags */
    return WH_ERROR_USAGE;
}

int wh_Server_KeystoreFindEnforceKeyUsage(whServerContext* server,
                                          whKeyId          keyId,
                                          whNvmFlags       requiredUsage)
{
    int            ret;
    whNvmMetadata* meta = NULL;
    whNvmMetadata  metaCopy;

    /* Validate input parameters */
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockKeystore(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Freshen the key to obtain the metadata */
    ret = _FreshenKeyUnlocked(server, keyId, NULL, &meta);
    if (ret != WH_ERROR_OK) {
        (void)_UnlockKeystore(server);
        return ret;
    }

    /* Copy metadata while holding the lock to avoid stale reads */
    memcpy((uint8_t*)&metaCopy, (uint8_t*)meta, sizeof(metaCopy));

    (void)_UnlockKeystore(server);

    /* Enforce the usage policy with the copied metadata */
    return wh_Server_KeystoreEnforceKeyUsage(&metaCopy, requiredUsage);
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_SERVER */
