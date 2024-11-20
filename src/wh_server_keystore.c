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

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_server.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif

#include "wolfhsm/wh_server_keystore.h"

static int _FindInCache(whServerContext* server, whKeyId keyId,
        int *out_index, int *out_big, uint8_t* *out_buffer,
        whNvmMetadata* *out_meta);

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
static int hsmCacheKeyDma32(whServerContext* server, whNvmMetadata* meta,
    uint32_t keyAddr);
static int hsmExportKeyDma32(whServerContext* server, whKeyId keyId,
    uint32_t keyAddr, uint32_t keySz, whNvmMetadata* outMeta);
#endif
#if WH_DMA_IS_64BIT
static int hsmCacheKeyDma64(whServerContext* server, whNvmMetadata* meta,
    uint64_t keyAddr);
static int hsmExportKeyDma64(whServerContext* server, whKeyId keyId,
                             uint64_t keyAddr, uint64_t keySz,
                             whNvmMetadata* outMeta);
#endif
#endif

int hsmGetUniqueId(whServerContext* server, whNvmId* inout_id)
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
int hsmCacheFindSlotAndZero(whServerContext* server, uint16_t keySz,
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
            XMEMSET(&server->cache[foundIndex], 0, sizeof(whServerCacheSlot));
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
            XMEMSET(&server->bigCache[foundIndex], 0,
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

int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in)
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
            XMEMCPY((uint8_t*)server->cache[foundIndex].buffer, in, meta->len);
            XMEMCPY((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
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
            XMEMCPY((uint8_t*)server->bigCache[foundIndex].buffer, in,
                    meta->len);
            XMEMCPY((uint8_t*)server->bigCache[foundIndex].meta, (uint8_t*)meta,
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
int hsmFreshenKey(whServerContext* server, whKeyId keyId, uint8_t** outBuf,
                  whNvmMetadata** outMeta)
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
            ret =
                hsmCacheFindSlotAndZero(server, tmpMeta->len, outBuf, outMeta);
            if (ret == WH_ERROR_OK) {
                /* Read the key from NVM into the cache slot */
                ret = wh_Nvm_Read(server->nvm, keyId, 0, tmpMeta->len, *outBuf);
                if (ret == WH_ERROR_OK) {
                    /* Copy the metadata to the cache slot if key read is
                     * successful*/
                    XMEMCPY((uint8_t*)*outMeta, (uint8_t*)tmpMeta,
                            sizeof(whNvmMetadata));
                }
            }
        }
    }
    return ret;
}

int hsmReadKey(whServerContext* server, whKeyId keyId, whNvmMetadata* outMeta,
               uint8_t* out, uint32_t* outSz)
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
                XMEMCPY((uint8_t*)outMeta, (uint8_t*)server->cache[i].meta,
                        sizeof(whNvmMetadata));
            }
            if (out != NULL) {
                XMEMCPY(out, server->cache[i].buffer,
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
                XMEMCPY((uint8_t*)outMeta, (uint8_t*)server->bigCache[i].meta,
                        sizeof(whNvmMetadata));
            }
            if (out != NULL) {
                XMEMCPY(out, server->bigCache[i].buffer,
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
            XMEMCPY((uint8_t*)outMeta, (uint8_t*)meta, sizeof(meta));
        /* read the object */
        if (out != NULL)
            ret = wh_Nvm_Read(server->nvm, keyId, 0, *outSz, out);
    }
    /* cache key if free slot, will only kick out other commited keys */
    if (ret == 0 && out != NULL) {
        hsmCacheKey(server, meta, out);
    }
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    /* use empty key of zeros if we couldn't find the master ecu key */
    if ((ret == WH_ERROR_NOTFOUND) &&
        (WH_KEYID_TYPE(keyId) == WH_KEYTYPE_SHE) &&
        (WH_KEYID_ID(keyId) == WH_SHE_MASTER_ECU_KEY_ID)) {
        XMEMSET(out, 0, WH_SHE_KEY_SZ);
        *outSz = WH_SHE_KEY_SZ;
        if (outMeta != NULL) {
            /* need empty flags and correct length and id */
            XMEMSET(outMeta, 0, sizeof(meta));
            meta->len = WH_SHE_KEY_SZ;
            meta->id  = keyId;
        }
        ret = 0;
    }
#endif
    return ret;
}

int hsmEvictKey(whServerContext* server, whNvmId keyId)
{
    int            ret = 0;
    whNvmMetadata* meta;

    if ((server == NULL) || WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _FindInCache(server, keyId, NULL, NULL, NULL, &meta);
    if (ret == 0) {
        meta->id = WH_KEYID_ERASED;
    }
    return ret;
}

int hsmCommitKey(whServerContext* server, whNvmId keyId)
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

int hsmEraseKey(whServerContext* server, whNvmId keyId)
{
    if ((server == NULL) || (WH_KEYID_ISERASED(keyId))) {
        return WH_ERROR_BADARGS;
    }

    /* remove the key from the cache if present */
    (void)hsmEvictKey(server, keyId);

    /* destroy the object */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &keyId);
}

int wh_Server_HandleKeyRequest(whServerContext* server, uint16_t magic,
                               uint16_t action, uint16_t seq, uint8_t* data,
                               uint16_t* size)
{
    int           ret = 0;
    uint32_t      field;
    uint8_t*      in;
    uint8_t*      out;
    whPacket*     packet  = (whPacket*)data;
    whNvmMetadata meta[1] = {{0}};

    /* validate args, even though these functions are only supposed to be
     * called by internal functions */
    if ((server == NULL) || (data == NULL) || (size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_KEY_CACHE:
            /* in is after fixed size fields */
            in = (uint8_t*)(&packet->keyCacheReq + 1);
            /* set the metadata fields */
            meta->id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id,
                                     packet->keyCacheReq.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = packet->keyCacheReq.flags;
            meta->len    = packet->keyCacheReq.sz;
            /* validate label sz */
            if (packet->keyCacheReq.labelSz > WH_NVM_LABEL_LEN) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                XMEMCPY(meta->label, packet->keyCacheReq.label,
                        packet->keyCacheReq.labelSz);
            }
            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret = hsmGetUniqueId(server, &meta->id);
            }
            /* write the key */
            if (ret == WH_ERROR_OK) {
                ret = hsmCacheKey(server, meta, in);
            }
            if (ret == 0) {
                /* remove the client_id, client may set type */
                packet->keyCacheRes.id = WH_KEYID_ID(meta->id);
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyCacheRes);
            }
            break;

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
        case WH_KEY_CACHE_DMA32:
            /* set the metadata fields */
            meta->id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id,
                                     packet->keyCacheDma32Req.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = packet->keyCacheDma32Req.flags;
            meta->len    = packet->keyCacheDma32Req.sz;
            /* validate label sz */
            if (packet->keyCacheDma32Req.labelSz > WH_NVM_LABEL_LEN) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                XMEMCPY(meta->label, packet->keyCacheDma32Req.label,
                        packet->keyCacheDma32Req.labelSz);
            }
            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret = hsmGetUniqueId(server, &meta->id);
            }
            /* write the key using DMA */
            if (ret == WH_ERROR_OK) {
                ret = hsmCacheKeyDma32(server, meta,
                                       packet->keyCacheDma32Req.key.addr);
            }
            if (ret == 0) {
                /* remove the client_id, client may set type */
                packet->keyCacheDma32Res.id = WH_KEYID_ID(meta->id);
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyCacheDma32Res);
            }
            break;

        case WH_KEY_EXPORT_DMA32:
            ret = hsmExportKeyDma32(server,
                                    WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                                  server->comm->client_id,
                                                  packet->keyExportDma32Req.id),
                                    packet->keyExportDma32Req.key.addr,
                                    packet->keyExportDma32Req.key.sz, meta);
            if (ret == 0) {
                /* set key len */
                packet->keyExportDma32Res.len =
                    packet->keyExportDma32Req.key.sz;
                /* set label */
                XMEMCPY(packet->keyExportDma32Res.label, meta->label,
                        sizeof(meta->label));
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyExportDma32Res);
            }
            break;
#endif /* WH_DMA_IS_32BIT */

#if WH_DMA_IS_64BIT
        case WH_KEY_CACHE_DMA64:
            /* set the metadata fields */
            meta->id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, server->comm->client_id,
                                     packet->keyCacheDma64Req.id);
            meta->access = WH_NVM_ACCESS_ANY;
            meta->flags  = packet->keyCacheDma64Req.flags;
            meta->len    = packet->keyCacheDma64Req.sz;
            /* validate label sz */
            if (packet->keyCacheDma64Req.labelSz > WH_NVM_LABEL_LEN) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                XMEMCPY(meta->label, packet->keyCacheDma64Req.label,
                        packet->keyCacheDma64Req.labelSz);
            }
            /* get a new id if one wasn't provided */
            if (WH_KEYID_ISERASED(meta->id)) {
                ret = hsmGetUniqueId(server, &meta->id);
            }
            /* write the key using DMA */
            if (ret == WH_ERROR_OK) {
                ret = hsmCacheKeyDma64(server, meta,
                                       packet->keyCacheDma64Req.key.addr);
            }
            if (ret == 0) {
                /* remove the client_id, client may set type */
                packet->keyCacheDma64Res.id = WH_KEYID_ID(meta->id);
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyCacheDma64Res);
            }
            break;

        case WH_KEY_EXPORT_DMA64:
            ret = hsmExportKeyDma64(server,
                                    WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                                  server->comm->client_id,
                                                  packet->keyExportDma64Req.id),
                                    packet->keyExportDma64Req.key.addr,
                                    packet->keyExportDma64Req.key.sz, meta);
            if (ret == 0) {
                /* set key len */
                packet->keyExportDma64Res.len =
                    packet->keyExportDma64Req.key.sz;
                /* set label */
                XMEMCPY(packet->keyExportDma64Res.label, meta->label,
                        sizeof(meta->label));
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyExportDma64Res);
            }
            break;
#endif /* WH_DMA_IS_64BIT */
#endif /* WOLFHSM_CFG_DMA */

        case WH_KEY_EVICT:
            ret = hsmEvictKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                                    server->comm->client_id,
                                                    packet->keyEvictReq.id));
            if (ret == 0) {
                packet->keyEvictRes.ok = 0;
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyEvictRes);
            }
            break;
        case WH_KEY_EXPORT:
            /* out is after fixed size fields */
            out   = (uint8_t*)(&packet->keyExportRes + 1);
            field = WOLFHSM_CFG_COMM_DATA_LEN -
                    (WH_PACKET_STUB_SIZE + sizeof(packet->keyExportRes));
            /* read the key */
            ret = hsmReadKey(server,
                             WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                           server->comm->client_id,
                                           packet->keyExportReq.id),
                             meta, out, &field);
            if (ret == 0) {
                /* set key len */
                packet->keyExportRes.len = field;
                /* set label */
                XMEMCPY(packet->keyExportRes.label, meta->label,
                        sizeof(meta->label));
                *size =
                    WH_PACKET_STUB_SIZE + sizeof(packet->keyExportRes) + field;
            }
            break;
        case WH_KEY_COMMIT:
            /* commit the cached key */
            ret = hsmCommitKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                                     server->comm->client_id,
                                                     packet->keyCommitReq.id));
            if (ret == 0) {
                packet->keyCommitRes.ok = 0;
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyCommitRes);
            }
            break;
        case WH_KEY_ERASE:
            ret = hsmEraseKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                                    server->comm->client_id,
                                                    packet->keyEraseReq.id));
            if (ret == 0) {
                packet->keyEraseRes.ok = 0;
                *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyEraseRes);
            }
            break;
        default:
            ret = WH_ERROR_BADARGS;
            break;
    }
    packet->rc = ret;
    (void)magic;
    (void)seq;
    return 0;
}

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
static int hsmCacheKeyDma32(whServerContext* server, whNvmMetadata* meta,
                            uint32_t keyAddr)
{
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* slotMeta;

    /* Get a cache slot */
    ret = hsmCacheFindSlotAndZero(server, meta->len, &buffer, &slotMeta);
    if (ret != 0) {
        return ret;
    }

    /* Copy metadata */
    XMEMCPY(slotMeta, meta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyFromClient32(server, buffer, keyAddr, meta->len,
                                       (whServerDmaFlags){0});
    if (ret != 0) {
        /* Clear the slot on error */
        XMEMSET(buffer, 0, meta->len);
        slotMeta->id = WH_KEYID_ERASED;
    }

    return ret;
}

static int hsmExportKeyDma32(whServerContext* server, whKeyId keyId,
                             uint32_t keyAddr, uint32_t keySz,
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

    if (keySz < cacheMeta->len) {
        return WH_ERROR_NOSPACE;
    }

    XMEMCPY(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyToClient32(server, keyAddr, buffer, outMeta->len,
                                     (whServerDmaFlags){0});

    return ret;
}
#endif /* WH_DMA_IS_32BIT */

#if WH_DMA_IS_64BIT
static int hsmCacheKeyDma64(whServerContext* server, whNvmMetadata* meta,
                            uint64_t keyAddr)
{
    int            ret;
    uint8_t*       buffer;
    whNvmMetadata* slotMeta;

    /* Get a cache slot */
    ret = hsmCacheFindSlotAndZero(server, meta->len, &buffer, &slotMeta);
    if (ret != 0) {
        return ret;
    }

    /* Copy metadata */
    XMEMCPY(slotMeta, meta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyFromClient64(server, buffer, keyAddr, meta->len,
                                       (whServerDmaFlags){0});
    if (ret != 0) {
        /* Clear the slot on error */
        XMEMSET(buffer, 0, meta->len);
        slotMeta->id = WH_KEYID_ERASED;
    }

    return ret;
}

static int hsmExportKeyDma64(whServerContext* server, whKeyId keyId,
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

    if (keySz < cacheMeta->len) {
        return WH_ERROR_NOSPACE;
    }

    XMEMCPY(outMeta, cacheMeta, sizeof(whNvmMetadata));

    /* Copy key data using DMA */
    ret = whServerDma_CopyToClient64(server, keyAddr, buffer, outMeta->len,
                                     (whServerDmaFlags){0});

    return ret;
}
#endif /* WH_DMA_IS_64BIT */
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFHSM_CFG_NO_CRYPTO */