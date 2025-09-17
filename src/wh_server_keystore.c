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

static int _FindInCache(whServerContext* server, whKeyId keyId,
        int *out_index, int *out_big, uint8_t* *out_buffer,
        whNvmMetadata* *out_meta);


int wh_Server_KeystoreGetUniqueId(whServerContext* server, whNvmId* inout_id)
{
    int     i;
    int     ret = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whKeyId key_id = *inout_id;
    int     type   = WH_KEYID_TYPE(key_id);
    int     user   = WH_KEYID_USER(key_id);
    whNvmId buildId;
    whNvmId nvmId = 0;
    whNvmId keyCount;

    /* try every index until we find a unique one, don't worry about capacity */
    for (id = WH_KEYID_IDMAX; id > WH_KEYID_ERASED; id--) {
        buildId = WH_MAKE_KEYID(type, user, id);
        /* check against cache keys */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (buildId == server->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT)
            continue;
        /* check against big cache keys */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (buildId == server->bigCache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT)
            continue;
        /* if keyId exists */
        ret = wh_Nvm_List(server->nvm, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_ANY,
                          buildId, &keyCount, &nvmId);
        /* break if we didn't find a match */
        if (ret == WH_ERROR_NOTFOUND || nvmId != buildId)
            break;
    }
    /* unlikely but cover the case where we've run out of ids */
    if (id > WH_KEYID_IDMAX)
        ret = WH_ERROR_NOSPACE;
    /* ultimately, return found id */
    if (ret == 0)
        *inout_id = buildId;
    return ret;
}

/* find an available slot for the size, return the slots buffer and meta */
int wh_Server_KeystoreGetCacheSlot(whServerContext* server, uint16_t keySz,
                                   uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int i;
    int foundIndex = -1;
    if (server == NULL || (keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE &&
                           keySz > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE)) {
        return WH_ERROR_BADARGS;
    }

    if (keySz <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            /* check for empty slot or rewrite slot */
            if (foundIndex == -1 &&
                server->cache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }
        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (server->cache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* zero the cache slot and set the output buffers */
        if (foundIndex >= 0) {
            memset(&server->cache[foundIndex], 0, sizeof(whServerCacheSlot));
            *outBuf  = server->cache[foundIndex].buffer;
            *outMeta = server->cache[foundIndex].meta;
        }
    }
    else {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            /* check for empty slot or rewrite slot */
            if (foundIndex == -1 &&
                server->bigCache[i].meta->id == WH_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }
        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (server->bigCache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }
        if (foundIndex >= 0) {
            memset(&server->bigCache[foundIndex], 0,
                    sizeof(whServerBigCacheSlot));
            *outBuf  = server->bigCache[foundIndex].buffer;
            *outMeta = server->bigCache[foundIndex].meta;
        }
    }
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return WH_ERROR_NOSPACE;
    return 0;
}

int wh_Server_KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                               uint8_t* in)
{
    int i;
    int foundIndex = -1;

    /* make sure id is valid */
    if ((server == NULL) || (meta == NULL) || (in == NULL) ||
        WH_KEYID_ISERASED(meta->id) ||
        ((meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) &&
         (meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE))) {
        return WH_ERROR_BADARGS;
    }

    /* Check for cross-cache duplicates and evict from other cache if found */
    if (meta->len <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* We're going to use regular cache, check if key exists in big cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (server->bigCache[i].meta->id == meta->id) {
                /* Evict the key from big cache */
                server->bigCache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }
    else {
        /* We're going to use big cache, check if key exists in regular cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (server->cache[i].meta->id == meta->id) {
                /* Evict the key from regular cache */
                server->cache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }

    /* check if we need to use big cache instead */
    if (meta->len <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            /* check for empty slot or rewrite slot */
            if (WH_KEYID_ISERASED(server->cache[i].meta->id) ||
                (server->cache[i].meta->id == meta->id)) {
                foundIndex = i;
                break;
            }
        }

        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
                if (server->cache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* write key if slot found */
        if (foundIndex != -1) {
            memcpy((uint8_t*)server->cache[foundIndex].buffer, in, meta->len);
            memcpy((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
                    sizeof(whNvmMetadata));
            /* check if the key is already commited */
            if (wh_Nvm_GetMetadata(server->nvm, meta->id, meta) ==
                WH_ERROR_NOTFOUND) {
                server->cache[foundIndex].commited = 0;
            }
            else {
                server->cache[foundIndex].commited = 1;
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
            if (WH_KEYID_ISERASED(server->bigCache[i].meta->id) ||
                (server->bigCache[i].meta->id == meta->id)) {
                foundIndex = i;
                break;
            }
        }

        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
                if (server->bigCache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }

        /* write key if slot found */
        if (foundIndex != -1) {
            memcpy((uint8_t*)server->bigCache[foundIndex].buffer, in,
                    meta->len);
            memcpy((uint8_t*)server->bigCache[foundIndex].meta, (uint8_t*)meta,
                    sizeof(whNvmMetadata));
            /* check if the key is already commited */
            if (wh_Nvm_GetMetadata(server->nvm, meta->id, meta) ==
                WH_ERROR_NOTFOUND) {
                server->bigCache[foundIndex].commited = 0;
            }
            else {
                server->bigCache[foundIndex].commited = 1;
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
    int            ret = WH_ERROR_NOTFOUND;
    int            i;
    int            index  = -1;
    int            big    = -1;
    whNvmMetadata* meta   = NULL;
    uint8_t*       buffer = NULL;

    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (server->cache[i].meta->id == keyId) {
            big    = 0;
            index  = i;
            meta   = server->cache[i].meta;
            buffer = server->cache[i].buffer;
            break;
        }
    }
    if (index == -1) {
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (server->bigCache[i].meta->id == keyId) {
                big    = 1;
                index  = i;
                meta   = server->bigCache[i].meta;
                buffer = server->bigCache[i].buffer;
                break;
            }
        }
    }
    if (index != -1) {
        if (out_index != NULL) {
            *out_index = index;
        }
        if (out_big != NULL) {
            *out_big = big;
        }
        if (out_meta != NULL) {
            *out_meta = meta;
        }
        if (out_buffer != NULL) {
            *out_buffer = buffer;
        }
        ret = WH_ERROR_OK;
    }
    return ret;
}

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
            ret = wh_Server_KeystoreGetCacheSlot(server, tmpMeta->len, outBuf,
                                                 outMeta);
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
    int           ret = 0;
    int           i;
    whNvmMetadata meta[1];

    if ((server == NULL) || (outSz == NULL) ||
        (WH_KEYID_ISERASED(keyId) &&
         (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_SHE))) {
        return WH_ERROR_BADARGS;
    }

    /* check the cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        /* copy the meta and key before returning */
        if (server->cache[i].meta->id == keyId) {
            /* check outSz */
            if (server->cache[i].meta->len > *outSz)
                return WH_ERROR_NOSPACE;
            if (outMeta != NULL) {
                memcpy((uint8_t*)outMeta, (uint8_t*)server->cache[i].meta,
                        sizeof(whNvmMetadata));
            }
            if (out != NULL) {
                memcpy(out, server->cache[i].buffer,
                        server->cache[i].meta->len);
            }
            *outSz = server->cache[i].meta->len;
            return 0;
        }
    }
    /* check the big cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
        /* copy the meta and key before returning */
        if (server->bigCache[i].meta->id == keyId) {
            /* check outSz */
            if (server->bigCache[i].meta->len > *outSz)
                return WH_ERROR_NOSPACE;
            if (outMeta != NULL) {
                memcpy((uint8_t*)outMeta, (uint8_t*)server->bigCache[i].meta,
                        sizeof(whNvmMetadata));
            }
            if (out != NULL) {
                memcpy(out, server->bigCache[i].buffer,
                        server->bigCache[i].meta->len);
            }
            *outSz = server->bigCache[i].meta->len;
            return 0;
        }
    }
    /* try to read the metadata */
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
        /* Best-effort caching: failure does not affect read result */
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
    int            ret = 0;
    whNvmMetadata* meta;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _FindInCache(server, keyId, NULL, NULL, NULL, &meta);
    if (ret == 0) {
#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_CRYPTOCB_VERBOSE)
        printf("[server] wh_Server_KeystoreEvictKey: evicted keyid=0x%X\n",
               keyId);
#endif
        meta->id = WH_KEYID_ERASED;
    }
    return ret;
}

int wh_Server_KeystoreCommitKey(whServerContext* server, whNvmId keyId)
{
    uint8_t*       slotBuf;
    whNvmMetadata* slotMeta;
    whNvmSize      size;
    int            ret;
    int            index;
    int            big;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _FindInCache(server, keyId, &index, &big, &slotBuf, &slotMeta);
    if (ret == WH_ERROR_OK) {
        size = slotMeta->len;
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, slotMeta, size, slotBuf);
        if (ret == 0) {
            if (big == 0) {
                server->cache[index].commited = 1;
            }
            else {
                server->bigCache[index].commited = 1;
            }
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
            whMessageKeystore_CacheRequest  req = {0};
            whMessageKeystore_CacheResponse resp = {0};

            /* translate request */
            (void)wh_MessageKeystore_TranslateCacheRequest(
                magic, (whMessageKeystore_CacheRequest*)req_packet, &req);

            /* in is after fixed size fields */
            in = (uint8_t*)req_packet + sizeof(req);

            /* set the metadata fields */
            meta->id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                     (uint16_t)server->comm->client_id,
                                     (uint16_t)req.id);
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
                resp.rc = (uint32_t)ret;
                /* TODO: Are there any fatal server errors? */
                ret = WH_ERROR_OK;
            }
            /* write the key */
            if (ret == WH_ERROR_OK) {
                ret     = wh_Server_KeystoreCacheKey(server, meta, in);
                resp.rc = (uint32_t)ret;
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
            whMessageKeystore_CacheDmaRequest  req = {0};
            whMessageKeystore_CacheDmaResponse resp = {0};

            /* translate request */
            (void)wh_MessageKeystore_TranslateCacheDmaRequest(
                magic, (whMessageKeystore_CacheDmaRequest*)req_packet, &req);

            /* set the metadata fields */
            meta->id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                     (uint16_t)server->comm->client_id,
                                     (uint16_t)req.id);
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
                resp.rc = (uint32_t)ret;
            }

            /* write the key using DMA */
            if (ret == WH_ERROR_OK) {
                ret = wh_Server_KeystoreCacheKeyDma(server, meta, req.key.addr);
                resp.rc = (uint32_t)ret;
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
            whMessageKeystore_ExportDmaRequest  req = {0};
            whMessageKeystore_ExportDmaResponse resp = {0};

            /* translate request */
            (void)wh_MessageKeystore_TranslateExportDmaRequest(
                magic, (whMessageKeystore_ExportDmaRequest*)req_packet, &req);

            ret = wh_Server_KeystoreExportKeyDma(
                server,
                WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                              (uint16_t)server->comm->client_id,
                              (uint16_t)req.id),
                req.key.addr, req.key.sz, meta);
            resp.rc = (uint32_t)ret;
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
            whMessageKeystore_EvictRequest  req = {0};
            whMessageKeystore_EvictResponse resp = {0};

            (void)wh_MessageKeystore_TranslateEvictRequest(
                magic, (whMessageKeystore_EvictRequest*)req_packet, &req);

            ret = wh_Server_KeystoreEvictKey(
                server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                      (uint16_t)server->comm->client_id,
                                      (uint16_t)req.id));
            resp.rc = (uint32_t)ret;
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

            (void)wh_MessageKeystore_TranslateEvictResponse(
                magic, &resp, (whMessageKeystore_EvictResponse*)resp_packet);
            *out_resp_size = sizeof(resp);
        } break;

        case WH_KEY_EXPORT: {
            whMessageKeystore_ExportRequest  req = {0};
            whMessageKeystore_ExportResponse resp = {0};
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
                WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                              (uint16_t)server->comm->client_id,
                              (uint16_t)req.id),
                meta, out, &keySz);

            /* Check if key is non-exportable */
            if (ret == WH_ERROR_OK &&
                (meta->flags & WH_NVM_FLAGS_NONEXPORTABLE)) {
                ret = WH_ERROR_ACCESS;
                /* Clear any key data that may have been read */
                memset(out, 0, keySz);
            }

            resp.rc = (uint32_t)ret;
            /* TODO: Are there any fatal server errors? */
            ret = WH_ERROR_OK;

            if (ret == WH_ERROR_OK) {
                /* Only provide key output if no error */
                if (resp.rc == WH_ERROR_OK) {
                    resp.len = keySz;
                } else {
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
            whMessageKeystore_CommitRequest  req = {0};
            whMessageKeystore_CommitResponse resp = {0};

            /* translate request */
            (void)wh_MessageKeystore_TranslateCommitRequest(
                magic, (whMessageKeystore_CommitRequest*)req_packet, &req);

            ret = wh_Server_KeystoreCommitKey(
                server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                      (uint16_t)server->comm->client_id,
                                      (uint16_t)req.id));
            resp.rc = (uint32_t)ret;
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
            whMessageKeystore_EraseRequest  req = {0};
            whMessageKeystore_EraseResponse resp = {0};

            /* translate request */
            (void)wh_MessageKeystore_TranslateEraseRequest(
                magic, (whMessageKeystore_EraseRequest*)req_packet, &req);

            ret = wh_Server_KeystoreEraseKey(
                server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                      (uint16_t)server->comm->client_id,
                                      (uint16_t)req.id));
            resp.rc = (uint32_t)ret;
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
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* slotMeta;
    int            i;

    /* Check for cross-cache duplicates and evict from other cache if found */
    if (meta->len <= WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        /* We're going to use regular cache, check if key exists in big cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT; i++) {
            if (server->bigCache[i].meta->id == meta->id) {
                /* Evict the key from big cache */
                server->bigCache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }
    else {
        /* We're going to use big cache, check if key exists in regular cache */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (server->cache[i].meta->id == meta->id) {
                /* Evict the key from regular cache */
                server->cache[i].meta->id = WH_KEYID_ERASED;
                break;
            }
        }
    }

    /* Get a cache slot */
    ret = wh_Server_KeystoreGetCacheSlot(server, meta->len, &buffer, &slotMeta);
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
