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

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif

#include "wolfhsm/wh_server_keystore.h"

static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
/**
 * @brief Check if keyId represents a global key (USER == 0)
 */
static int _IsGlobalKey(whKeyId keyId)
{
    return (WH_KEYID_USER(keyId) == WH_KEYUSER_GLOBAL);
}
#endif /* WOLFHSM_CFG_GLOBAL_KEYS */

/**
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

/**
 * @brief Find a key in the specified cache context
 */
static int _FindInKeyCache(whKeyCacheContext* ctx, whKeyId keyId,
                           int* out_index, int* out_big, uint8_t** out_buffer,
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

/**
 * @brief Get an available cache slot from the specified cache context
 */
static int _GetKeyCacheSlot(whKeyCacheContext* ctx, uint16_t keySz,
                            uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int foundIndex = -1;
    int i;

    if (ctx == NULL || outBuf == NULL || outMeta == NULL) {
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
                if (ctx->cache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* Zero slot and return pointers */
        if (foundIndex >= 0) {
            memset(&ctx->cache[foundIndex], 0, sizeof(whServerCacheSlot));
            *outBuf  = ctx->cache[foundIndex].buffer;
            *outMeta = ctx->cache[foundIndex].meta;
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
                if (ctx->bigCache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* Zero slot and return pointers */
        if (foundIndex >= 0) {
            memset(&ctx->bigCache[foundIndex], 0, sizeof(whServerBigCacheSlot));
            *outBuf  = ctx->bigCache[foundIndex].buffer;
            *outMeta = ctx->bigCache[foundIndex].meta;
        }
    }

    if (foundIndex == -1) {
        return WH_ERROR_NOSPACE;
    }

    return WH_ERROR_OK;
}

/**
 * @brief Evict a key from the specified cache context
 */
static int _EvictKeyFromCache(whKeyCacheContext* ctx, whKeyId keyId)
{
    whNvmMetadata* meta = NULL;
    int            ret  = _FindInKeyCache(ctx, keyId, NULL, NULL, NULL, &meta);

    if (ret == WH_ERROR_OK && meta != NULL) {
        meta->id = WH_KEYID_ERASED;
    }

    return ret;
}

/**
 * @brief Mark a cached key as committed
 */
static int _MarkKeyCommitted(whKeyCacheContext* ctx, whKeyId keyId,
                             int committed)
{
    int index = -1;
    int big   = -1;
    int ret   = _FindInKeyCache(ctx, keyId, &index, &big, NULL, NULL);

    if (ret == WH_ERROR_OK) {
        if (big == 0) {
            ctx->cache[index].commited = committed;
        }
        else {
            ctx->bigCache[index].commited = committed;
        }
    }

    return ret;
}

int wh_Server_KeystoreGetUniqueId(whServerContext* server, whNvmId* inout_id)
{
    int     ret = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whKeyId key_id = *inout_id;
    int     type   = WH_KEYID_TYPE(key_id);
    int     user   = WH_KEYID_USER(key_id);
    whNvmId buildId;
    whNvmId nvmId = 0;
    whNvmId keyCount;

    whKeyCacheContext* ctx = _GetCacheContext(server, key_id);

    /* try every index until we find a unique one, don't worry about capacity */
    for (id = WH_KEYID_IDMAX; id > WH_KEYID_ERASED; id--) {
        buildId = WH_MAKE_KEYID(type, user, id);

        /* Check against cache keys using unified cache functions */
        ret = _FindInKeyCache(ctx, buildId, NULL, NULL, NULL, NULL);
        if (ret == WH_ERROR_OK) {
            /* Found in cache, try next ID */
            continue;
        }

        /* Check if keyId exists in NVM */
        ret = wh_Nvm_List(server->nvm, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_ANY,
                          buildId, &keyCount, &nvmId);
        /* Break if we didn't find a match */
        if (ret == WH_ERROR_NOTFOUND || nvmId != buildId)
            break;
    }

    /* Check if we've run out of ids */
    if (id > WH_KEYID_IDMAX)
        ret = WH_ERROR_NOSPACE;

    /* Return found id */
    if (ret == 0)
        *inout_id = buildId;

    return ret;
}

/* find an available slot for the size, return the slots buffer and meta */
int wh_Server_KeystoreGetCacheSlot(whServerContext* server, whKeyId keyId,
                                   uint16_t keySz, uint8_t** outBuf,
                                   whNvmMetadata** outMeta)
{
    whKeyCacheContext* ctx;

    if (server == NULL || (keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE &&
                           keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE)) {
        return WH_ERROR_BADARGS;
    }

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, keyId);

    /* Use the unified cache slot function */
    return _GetKeyCacheSlot(ctx, keySz, outBuf, outMeta);
}

int wh_Server_KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                               uint8_t* in)
{
    int i;
    int foundIndex = -1;
    whKeyCacheContext* ctx;

    /* make sure id is valid */
    if ((server == NULL) || (meta == NULL) || (in == NULL) ||
        WH_KEYID_ISERASED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, meta->id);

    /* Check for cross-cache duplicates and evict from other cache if found */
    if (meta->len <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* We're going to use regular cache, check if key exists in big cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == meta->id) {
                /* Evict the key from big cache */
                ctx->bigCache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }
    else {
        /* We're going to use big cache, check if key exists in regular cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == meta->id) {
                /* Evict the key from regular cache */
                ctx->cache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }

    /* check if we need to use big cache instead */
    if (meta->len <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            /* check for empty slot or rewrite slot */
            if (WH_KEYID_ISERASED(ctx->cache[i].meta->id) ||
                (ctx->cache[i].meta->id == meta->id)) {
                foundIndex = i;
                break;
            }
        }

        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (ctx->cache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* write key if slot found */
        if (foundIndex != -1) {
            memcpy((uint8_t*)ctx->cache[foundIndex].buffer, in, meta->len);
            memcpy((uint8_t*)ctx->cache[foundIndex].meta, (uint8_t*)meta,
                   sizeof(whNvmMetadata));
            /* check if the key is already commited */
            if (wh_Nvm_GetMetadata(server->nvm, meta->id, meta) ==
                WH_ERROR_NOTFOUND) {
                ctx->cache[foundIndex].commited = 0;
            }
            else {
                ctx->cache[foundIndex].commited = 1;
            }
#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_CRYPTOCB_VERBOSE)
            printf("[server] cacheKey: caching keyid=%u\n", meta->id);
            wh_Utils_Hexdump("[server] cacheKey: key=", in, meta->len);
#endif
        }
    }
    else {
        /* try big key cache, don't put small keys into big cache if full */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            /* check for empty slot or rewrite slot */
            if (WH_KEYID_ISERASED(ctx->bigCache[i].meta->id) ||
                (ctx->bigCache[i].meta->id == meta->id)) {
                foundIndex = i;
                break;
            }
        }

        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (ctx->bigCache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* write key if slot found */
        if (foundIndex != -1) {
            memcpy((uint8_t*)ctx->bigCache[foundIndex].buffer, in, meta->len);
            memcpy((uint8_t*)ctx->bigCache[foundIndex].meta, (uint8_t*)meta,
                   sizeof(whNvmMetadata));
            /* check if the key is already commited */
            if (wh_Nvm_GetMetadata(server->nvm, meta->id, meta) ==
                WH_ERROR_NOTFOUND) {
                ctx->bigCache[foundIndex].commited = 0;
            }
            else {
                ctx->bigCache[foundIndex].commited = 1;
            }
        }
    }
    /* return error if we are out of cache slots */
    if (foundIndex == -1) {
        return WH_ERROR_NOSPACE;
    }
#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_CRYPTOCB_VERBOSE)
    else {
        printf("[server] hsmCacheKey: cached keyid=0x%X in slot %d, len=%u\n",
               meta->id, foundIndex, meta->len);
    }
#endif
    return 0;
}

static int _FindInCache(whServerContext* server, whKeyId keyId, int* out_index,
                        int* out_big, uint8_t** out_buffer,
                        whNvmMetadata** out_meta)
{
    whKeyCacheContext* ctx = _GetCacheContext(server, keyId);
    return _FindInKeyCache(ctx, keyId, out_index, out_big, out_buffer,
                           out_meta);
}

#ifdef WOLFHSM_CFG_KEYWRAP
static int _ExistsInCache(whServerContext* server, whKeyId keyId)
{
    int            ret           = 0;
    int            foundIndex    = -1;
    int            foundBigIndex = -1;
    whNvmMetadata* tmpMeta;
    uint8_t*       tmpBuf;

    ret = _FindInCache(server, keyId, &foundIndex, &foundBigIndex, &tmpBuf,
                       &tmpMeta);

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
    int           ret           = 0;
    int           foundIndex    = -1;
    int           foundBigIndex = -1;
    whNvmMetadata tmpMeta[1];

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _FindInCache(server, keyId, &foundIndex, &foundBigIndex, outBuf,
                       outMeta);
    if (ret != WH_ERROR_OK) {
        /* Not in cache. Check if it is in NVM */
        ret = wh_Nvm_GetMetadata(server->nvm, keyId, tmpMeta);
        if (ret == WH_ERROR_OK) {
            /* Key found in NVM, get a free cache slot */
            ret = wh_Server_KeystoreGetCacheSlot(server, keyId, tmpMeta->len,
                                                 outBuf, outMeta);
            if (ret == WH_ERROR_OK) {
                /* Read the key from NVM into the cache slot */
                ret = wh_Nvm_Read(server->nvm, keyId, 0, tmpMeta->len, *outBuf);
                if (ret == WH_ERROR_OK) {
                    /* Copy the metadata to the cache slot if key read is
                     * successful*/
                    memcpy((uint8_t*)*outMeta, (uint8_t*)tmpMeta,
                           sizeof(whNvmMetadata));
                }
            }
        }
    }
    return ret;
}

int wh_Server_KeystoreReadKey(whServerContext* server, whKeyId keyId,
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
    ret = _FindInCache(server, keyId, NULL, NULL, &cacheBuffer, &cacheMeta);
    if (ret == WH_ERROR_OK) {
        /* Found in cache */
        if (cacheMeta->len > *outSz)
            return WH_ERROR_NOSPACE;
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

    /* Not in cache, try to read the metadata from NVM */
    ret = wh_Nvm_GetMetadata(server->nvm, keyId, meta);
    if (ret == 0) {
        /* set outSz */
        *outSz = meta->len;
        /* read meta */
        if (outMeta != NULL)
            memcpy((uint8_t*)outMeta, (uint8_t*)meta, sizeof(meta));
        /* read the object */
        if (out != NULL)
            ret = wh_Nvm_Read(server->nvm, keyId, 0, *outSz, out);
    }
    /* cache key if free slot, will only kick out other commited keys */
    if (ret == 0 && out != NULL) {
        (void)wh_Server_KeystoreCacheKey(server, meta, out);
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

int wh_Server_KeystoreEvictKey(whServerContext* server, whNvmId keyId)
{
    int                ret = 0;
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, keyId);

    /* Use the unified evict function */
    ret = _EvictKeyFromCache(ctx, keyId);

#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_CRYPTOCB_VERBOSE)
    if (ret == 0) {
        printf("[server] wh_Server_KeystoreEvictKey: evicted keyid=0x%X\n",
               keyId);
    }
#endif

    return ret;
}

int wh_Server_KeystoreCommitKey(whServerContext* server, whNvmId keyId)
{
    uint8_t*           slotBuf;
    whNvmMetadata*     slotMeta;
    whNvmSize          size;
    int                ret;
    whKeyCacheContext* ctx;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, keyId);

    /* Find the key in cache.
     * Note: We call _FindInKeyCache() directly (not _FindInCache wrapper)
     * because we already obtained the correct cache context above. Using
     * the wrapper would redundantly call _GetCacheContext() again. */
    ret = _FindInKeyCache(ctx, keyId, NULL, NULL, &slotBuf, &slotMeta);
    if (ret == WH_ERROR_OK) {
        size = slotMeta->len;
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, slotMeta, size, slotBuf);
        if (ret == 0) {
            /* Mark key as committed using unified function */
            (void)_MarkKeyCommitted(ctx, keyId, 1);
        }
    }
    return ret;
}

int wh_Server_KeystoreEraseKey(whServerContext* server, whNvmId keyId)
{
    if ((server == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    /* remove the key from the cache if present */
    (void)wh_Server_KeystoreEvictKey(server, keyId);

    /* destroy the object */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &keyId);
}

#ifdef WOLFHSM_CFG_KEYWRAP
#ifndef NO_AES
#ifdef HAVE_AESGCM

#define WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE 16
#define WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE 12

static int _AesGcmWrapKey(whServerContext* server, whKeyId serverKeyId,
                          uint8_t* keyIn, uint16_t keySz,
                          whNvmMetadata* metadataIn, uint8_t* wrappedKeyOut,
                          uint16_t wrappedKeySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t  serverKey[AES_MAX_KEY_SIZE];
    uint32_t serverKeySz = sizeof(serverKey);
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
    ret = wh_Server_KeystoreReadKey(
        server,
        WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id,
                              serverKeyId),
        NULL, serverKey, &serverKeySz);
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

static int _AesGcmUnwrapKey(whServerContext* server, uint16_t serverKeyId,
                            void* wrappedKeyIn, uint16_t wrappedKeySz,
                            whNvmMetadata* metadataOut, void* keyOut,
                            uint16_t keySz)
{
    int      ret = 0;
    Aes      aes[1];
    uint8_t  authTag[WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t  iv[WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t  serverKey[AES_MAX_KEY_SIZE];
    uint32_t serverKeySz = sizeof(serverKey);
    uint8_t* encBlob   = (uint8_t*)wrappedKeyIn + sizeof(iv) + sizeof(authTag);
    uint16_t encBlobSz = wrappedKeySz - sizeof(iv) - sizeof(authTag);
    uint8_t  plainBlob[sizeof(*metadataOut) + WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];

    if (server == NULL || wrappedKeyIn == NULL || metadataOut == NULL ||
        keyOut == NULL || keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Get the server side key */
    ret = wh_Server_KeystoreReadKey(
        server,
        WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id,
                              serverKeyId),
        NULL, serverKey, &serverKeySz);
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

#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

static int _HandleWrapKeyRequest(whServerContext*               server,
                                 whMessageKeystore_WrapRequest* req,
                                 uint8_t* reqData, uint32_t reqDataSz,
                                 whMessageKeystore_WrapResponse* resp,
                                 uint8_t* respData, uint32_t respDataSz)
{

    int           ret;
    uint8_t*      wrappedKey;
    whNvmMetadata metadata;
    uint8_t       key[WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE];

    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL || req->keySz > WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Check if the reqData is big enough to hold the metadata and key */
    if (reqDataSz < sizeof(metadata) + req->keySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Extract the metadata and key from reqData */
    memcpy(&metadata, reqData, sizeof(metadata));
    memcpy(key, reqData + sizeof(metadata), req->keySz);

    /* Store the wrapped key in the response data */
    wrappedKey = respData;

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t wrappedKeySz = WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE +
                                    WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE +
                                    sizeof(metadata) + req->keySz;

            /* Check if the response data can fit the wrapped key */
            if (respDataSz < wrappedKeySz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Wrap the key */
            ret = _AesGcmWrapKey(server, req->serverKeyId, key, req->keySz,
                                 &metadata, wrappedKey, wrappedKeySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Tell the client how big the wrapped key is */
            resp->wrappedKeySz = wrappedKeySz;
            resp->cipherType   = WC_CIPHER_AES_GCM;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _HandleUnwrapAndExportKeyRequest(
    whServerContext* server, whMessageKeystore_UnwrapAndExportRequest* req,
    uint8_t* reqData, uint32_t reqDataSz,
    whMessageKeystore_UnwrapAndExportResponse* resp, uint8_t* respData,
    uint32_t respDataSz)
{
    if (server == NULL || req == NULL || reqData == NULL || resp == NULL ||
        respData == NULL) {
        return WH_ERROR_BADARGS;
    }

    int            ret;
    uint8_t*       wrappedKey;
    whNvmMetadata* metadata;
    uint8_t*       key;

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Store the metadata and key in the respData */
    metadata = (whNvmMetadata*)respData;
    key      = respData + sizeof(*metadata);

    switch (req->cipherType) {

#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            uint16_t keySz =
                req->wrappedKeySz - WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE -
                WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE - sizeof(*metadata);

            /* Check if the response data can fit the metadata + key  */
            if (respDataSz < sizeof(*metadata) + keySz) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Unwrap the key */
            ret = _AesGcmUnwrapKey(server, req->serverKeyId, wrappedKey,
                                   req->wrappedKeySz, metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Check if the key is exportable */
            if (metadata->flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }

            /* Tell the client how big the key is */
            resp->keySz      = keySz;
            resp->cipherType = WC_CIPHER_AES_GCM;

        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            return WH_ERROR_BADARGS;
    }

    return ret;
}

static int
_HandleUnwrapAndCacheKeyRequest(whServerContext*                         server,
                                whMessageKeystore_UnwrapAndCacheRequest* req,
                                uint8_t* reqData, uint32_t reqDataSz,
                                whMessageKeystore_UnwrapAndCacheResponse* resp,
                                uint8_t* respData, uint32_t respDataSz)
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

    /* Check if the reqData is big enough to hold the wrapped key */
    if (reqDataSz < req->wrappedKeySz) {
        return WH_ERROR_BUFFER_SIZE;
    }

    /* Set the wrapped key to the request data */
    wrappedKey = reqData;

    /* Unwrap the key based on the cipher type */
    switch (req->cipherType) {
#ifndef NO_AES
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM: {
            keySz = req->wrappedKeySz - WOLFHSM_KEYWRAP_AES_GCM_IV_SIZE -
                    WOLFHSM_KEYWRAP_AES_GCM_TAG_SIZE - sizeof(metadata);

            ret = _AesGcmUnwrapKey(server, req->serverKeyId, wrappedKey,
                                   req->wrappedKeySz, &metadata, key, keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            resp->cipherType = WC_CIPHER_AES_GCM;

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

    /*
     * Key ID Assignment Strategy:
     *
     * The unwrapped metadata may contain one of:
     * 1. WH_KEYID_ERASED (0x0000): Client wants server to auto-generate an ID
     * 2. A specific ID value: Client wants to control the assigned ID
     *
     * Case 1 is common when a client wraps a key for transport/storage without
     * caring about the specific ID it will have when unwrapped. The server
     * must generate a unique ID to prevent collision with existing cached keys.
     * Unwrapping to an auto-generated global keyslot is not supported.
     *
     * Case 2 is used when a client needs a fixed ID, either client-specific or
     * global (e.g., multiple clients unwrapping the same wrapped key and
     * expecting the same resulting ID).
     *
     */
    if (!WH_KEYID_ISERASED(metadata.id)) {
        /* Client specified an ID in the wrapped metadata - honor it and apply
         * global flag translation if the WH_KEYID_GLOBAL flag is set. This
         * means the key will be associated with the specified ID in either the
         * local or global cache */
        metadata.id = WH_TRANSLATE_CLIENT_KEYID(
            WH_KEYTYPE_CRYPTO, server->comm->client_id, metadata.id);
    }
    else {
        /* Client didn't specify an ID (wrapped with id=ERASED) - generate a
         * unique local key ID. Note: We always generate a LOCAL key here
         * because the metadata came from the wrapped blob, not from the client
         * request, so there's no way for the client to signal "make this
         * global" via the wrapped metadata. */
        metadata.id =
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id, 0);
        ret = wh_Server_KeystoreGetUniqueId(server, &metadata.id);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    /* Check for duplicates AFTER ID generation */
    if (_ExistsInCache(server, metadata.id)) {
        return WH_ERROR_ABORTED;
    }

    /* Store the assigned key ID in the response (ID portion only). We should
     * NOT return the upper bits back to the client */
    resp->keyId = WH_KEYID_ID(metadata.id);

    /* Cache the key */
    return wh_Server_KeystoreCacheKey(server, &metadata, key);
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
            meta->id     = WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                                 server->comm->client_id, req.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = req.flags;
            meta->len    = req.sz;
            /* validate label sz */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                memcpy(meta->label, req.label, req.labelSz);
            }
            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret     = wh_Server_KeystoreGetUniqueId(server, &meta->id);
                resp.rc = ret;
                /* TODO: Are there any fatal server errors? */
                ret = WH_ERROR_OK;
            }
            /* write the key */
            if (ret == WH_ERROR_OK) {
                ret     = wh_Server_KeystoreCacheKey(server, meta, in);
                resp.rc = ret;
                /* TODO: Are there any fatal server errors? */
                ret = WH_ERROR_OK;
            }
            if (ret == WH_ERROR_OK) {
                /* remove the client_id, client may set type */
                resp.id = WH_KEYID_ID(meta->id);

                (void)wh_MessageKeystore_TranslateCacheResponse(
                    magic, &resp,
                    (whMessageKeystore_CacheResponse*)resp_packet);

                *out_resp_size = sizeof(resp);
            }
        } break;

#ifdef WOLFHSM_CFG_DMA

        case WH_KEY_CACHE_DMA: {
            whMessageKeystore_CacheDmaRequest  req;
            whMessageKeystore_CacheDmaResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateCacheDmaRequest(
                magic, (whMessageKeystore_CacheDmaRequest*)req_packet, &req);

            /* set the metadata fields */
            meta->id     = WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                                 server->comm->client_id, req.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = req.flags;
            meta->len    = req.key.sz;

            /* validate label sz */
            if (req.labelSz > WH_NVM_LABEL_LEN) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                memcpy(meta->label, req.label, req.labelSz);
            }

            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret     = wh_Server_KeystoreGetUniqueId(server, &meta->id);
                resp.rc = ret;
            }

            /* write the key using DMA */
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_KeystoreCacheKeyDma(server, meta, req.key.addr);
                resp.rc = ret;
                /* propagate bad address to client if DMA operation failed */
                if (ret != WH_ERROR_OK) {
                    resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                    resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
                }
                /* TODO: Are there any fatal server errors? */
                ret = WH_ERROR_OK;
            }

            /* remove the client_id, client may set type */
            resp.id = WH_KEYID_ID(meta->id);

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

            ret = wh_Server_KeystoreExportKeyDma(
                server,
                WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                      server->comm->client_id, req.id),
                req.key.addr, req.key.sz, meta);
            resp.rc = ret;
            /* propagate bad address to client if DMA operation failed */
            if (ret != WH_ERROR_OK) {
                resp.dmaAddrStatus.badAddr.addr = req.key.addr;
                resp.dmaAddrStatus.badAddr.sz   = req.key.sz;
            }
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

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

            ret = wh_Server_KeystoreEvictKey(
                server, WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                              server->comm->client_id, req.id));
            resp.rc = ret;
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

            if (ret == WH_ERROR_OK) {
                resp.ok = 0;

                (void)wh_MessageKeystore_TranslateEvictResponse(
                    magic, &resp,
                    (whMessageKeystore_EvictResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
            }
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
            ret = wh_Server_KeystoreReadKey(
                server,
                WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                      server->comm->client_id, req.id),
                meta, out, &keySz);

            /* Check if key is non-exportable */
            if (ret == WH_ERROR_OK &&
                (meta->flags & WH_NVM_FLAGS_NONEXPORTABLE)) {
                ret = WH_ERROR_ACCESS;
                /* Clear any key data that may have been read */
                memset(out, 0, keySz);
            }

            resp.rc = ret;
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

            if (ret == WH_ERROR_OK) {
                /* Only provide key output if no error */
                if (resp.rc == WH_ERROR_OK) {
                    resp.len = keySz;
                }
                else {
                    resp.len = 0;
                }
                memcpy(resp.label, meta->label, sizeof(meta->label));

                (void)wh_MessageKeystore_TranslateExportResponse(
                    magic, &resp,
                    (whMessageKeystore_ExportResponse*)resp_packet);

                *out_resp_size = sizeof(resp) + resp.len;
            }
        } break;

        case WH_KEY_COMMIT: {
            whMessageKeystore_CommitRequest  req;
            whMessageKeystore_CommitResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateCommitRequest(
                magic, (whMessageKeystore_CommitRequest*)req_packet, &req);

            ret = wh_Server_KeystoreCommitKey(
                server, WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                              server->comm->client_id, req.id));
            resp.rc = ret;
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

            if (ret == WH_ERROR_OK) {
                resp.ok = 0;

                (void)wh_MessageKeystore_TranslateCommitResponse(
                    magic, &resp,
                    (whMessageKeystore_CommitResponse*)resp_packet);

                *out_resp_size = sizeof(resp);
            }
        } break;

        case WH_KEY_ERASE: {
            whMessageKeystore_EraseRequest  req;
            whMessageKeystore_EraseResponse resp;

            /* translate request */
            (void)wh_MessageKeystore_TranslateEraseRequest(
                magic, (whMessageKeystore_EraseRequest*)req_packet, &req);

            ret = wh_Server_KeystoreEraseKey(
                server, WH_TRANSLATE_CLIENT_KEYID(WH_KEYTYPE_CRYPTO,
                                              server->comm->client_id, req.id));
            resp.rc = ret;
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

            if (ret == WH_ERROR_OK) {
                resp.ok = 0;

                (void)wh_MessageKeystore_TranslateEraseResponse(
                    magic, &resp,
                    (whMessageKeystore_EraseResponse*)resp_packet);

                *out_resp_size = sizeof(resp);
            }
        } break;

#ifdef WOLFHSM_CFG_KEYWRAP
        case WH_KEY_WRAP: {
            whMessageKeystore_WrapRequest  wrapReq  = {0};
            whMessageKeystore_WrapResponse wrapResp = {0};
            uint8_t*                       reqData;
            uint8_t*                       respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(wrapResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateWrapRequest(magic, req_packet,
                                                          &wrapReq);


            /* Set the request data pointer directly after the request */
            reqData =
                (uint8_t*)req_packet + sizeof(whMessageKeystore_WrapRequest);

            /* Set the response data pointer directly after the response */
            respData =
                (uint8_t*)resp_packet + sizeof(whMessageKeystore_WrapResponse);

            ret = _HandleWrapKeyRequest(server, &wrapReq, reqData, reqDataSz,
                                        &wrapResp, respData, respDataSz);
            wrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateWrapResponse(magic, &wrapResp,
                                                           resp_packet);
            *out_resp_size = sizeof(wrapResp) + wrapResp.wrappedKeySz;

        } break;

        case WH_KEY_UNWRAPEXPORT: {
            whMessageKeystore_UnwrapAndExportRequest  unwrapReq  = {0};
            whMessageKeystore_UnwrapAndExportResponse unwrapResp = {0};
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
            (void)wh_MessageKeystore_TranslateUnwrapAndExportRequest(
                magic, req_packet, &unwrapReq);

            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req_packet +
                      sizeof(whMessageKeystore_UnwrapAndExportRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_UnwrapAndExportResponse);

            ret = _HandleUnwrapAndExportKeyRequest(server, &unwrapReq, reqData,
                                                   reqDataSz, &unwrapResp,
                                                   respData, respDataSz);
            unwrapResp.rc = ret;

            (void)wh_MessageKeystore_TranslateUnwrapAndExportResponse(
                magic, &unwrapResp, resp_packet);
            *out_resp_size =
                sizeof(unwrapResp) + sizeof(whNvmMetadata) + unwrapResp.keySz;

        } break;

        case WH_KEY_UNWRAPCACHE: {
            whMessageKeystore_UnwrapAndCacheRequest  cacheReq  = {0};
            whMessageKeystore_UnwrapAndCacheResponse cacheResp = {0};
            uint8_t*                                 reqData;
            uint8_t*                                 respData;
            uint32_t reqDataSz  = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheReq);
            uint32_t respDataSz = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(cacheResp);

            /* Validate the bounds of the request data */
            if (reqDataSz < req_size) {
                return WH_ERROR_BUFFER_SIZE;
            }

            /* Translate request */
            (void)wh_MessageKeystore_TranslateUnwrapAndCacheRequest(
                magic, req_packet, &cacheReq);

            /* Set the request data pointer directly after the request */
            reqData = (uint8_t*)req_packet +
                      sizeof(whMessageKeystore_UnwrapAndCacheRequest);

            /* Set the response data pointer directly after the response */
            respData = (uint8_t*)resp_packet +
                       sizeof(whMessageKeystore_UnwrapAndCacheResponse);

            ret = _HandleUnwrapAndCacheKeyRequest(server, &cacheReq, reqData,
                                                  reqDataSz, &cacheResp,
                                                  respData, respDataSz);
            cacheResp.rc = ret;

            (void)wh_MessageKeystore_TranslateUnwrapAndCacheResponse(
                magic, &cacheResp, resp_packet);
            *out_resp_size = sizeof(cacheResp);

        } break;

#endif /* WOLFHSM_CFG_KEYWRAP */

        default:
            ret = WH_ERROR_BADARGS;
            break;
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA

int wh_Server_KeystoreCacheKeyDma(whServerContext* server, whNvmMetadata* meta,
                                  uint64_t keyAddr)
{
    int                ret;
    uint8_t*           buffer;
    whNvmMetadata*     slotMeta;
    int                i;
    whKeyCacheContext* ctx;

    /* Get the appropriate cache context for this key */
    ctx = _GetCacheContext(server, meta->id);

    /* Check for cross-cache duplicates and evict from other cache if found */
    if (meta->len <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* We're going to use regular cache, check if key exists in big cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (ctx->bigCache[i].meta->id == meta->id) {
                /* Evict the key from big cache */
                ctx->bigCache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }
    else {
        /* We're going to use big cache, check if key exists in regular cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == meta->id) {
                /* Evict the key from regular cache */
                ctx->cache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }

    /* Get a cache slot */
    ret = wh_Server_KeystoreGetCacheSlot(server, meta->id, meta->len, &buffer,
                                         &slotMeta);
    if (ret != 0) {
        return ret;
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

    return ret;
}

int wh_Server_KeystoreExportKeyDma(whServerContext* server, whKeyId keyId,
                                   uint64_t keyAddr, uint64_t keySz,
                                   whNvmMetadata* outMeta)
{
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* cacheMeta;

    /* Find key in cache */
    ret = _FindInCache(server, keyId, NULL, NULL, &buffer, &cacheMeta);
    if (ret != 0) {
        return ret;
    }

    /* Check if key is non-exportable */
    if (cacheMeta->flags & WH_NVM_FLAGS_NONEXPORTABLE) {
        return WH_ERROR_ACCESS;
    }

    if (keySz < cacheMeta->len) {
        return WH_ERROR_NOSPACE;
    }

    memcpy(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyToClient(server, keyAddr, buffer, outMeta->len,
                                   (whServerDmaFlags){0});

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_SERVER */
