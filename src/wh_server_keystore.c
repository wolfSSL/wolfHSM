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

/* Pick up server config */
#include "wolfhsm/wh_server.h"

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

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif
#include "wolfhsm/wh_server_keystore.h"

int hsmGetUniqueId(whServerContext* server, whNvmId* outId)
{
    int i;
    int ret = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whNvmId buildId = (((*outId | (server->comm->client_id << 8)) & (~WH_KEYID_MASK)));
    whNvmId nvmId = 0;
    whNvmId keyCount;
    /* try every index until we find a unique one, don't worry about capacity */
    for (id = 1; id < WH_KEYID_MASK + 1; id++) {
        buildId = ((buildId & ~WH_KEYID_MASK) | id);
        /* check against cache keys */
        for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
            if (buildId == server->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT)
            continue;
        /* if keyId exists */
        ret = wh_Nvm_List(server->nvm, WH_NVM_ACCESS_ANY,
            WH_NVM_FLAGS_ANY, buildId, &keyCount,
            &nvmId);
        /* break if we didn't find a match */
        if (ret == WH_ERROR_NOTFOUND || nvmId != buildId)
            break;
    }
    /* unlikely but cover the case where we've run out of ids */
    if (id > WH_KEYID_MASK)
        ret = WH_ERROR_NOSPACE;
    /* ultimately, return found id */
    if (ret == 0)
        *outId |= buildId;
    return ret;
}

/* return the index of a free slot */
int hsmCacheFindSlot(whServerContext* server)
{
    int i;
    int foundIndex = -1;
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        /* check for empty slot or rewrite slot */
        if (foundIndex == -1 && server->cache[i].meta->id ==
            WH_KEYID_ERASED) {
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
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return WH_ERROR_NOSPACE;
    return foundIndex;
}

int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in)
{
    int i;
    int foundIndex = -1;
    /* make sure id is valid */
    if (server == NULL || meta == NULL || in == NULL ||
        (meta->id & WH_KEYID_MASK) == WH_KEYID_ERASED ||
        meta->len > WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) {
        return WH_ERROR_BADARGS;
    }
    /* apply client_id */
    meta->id |= (server->comm->client_id << 8);
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        /* check for empty slot or rewrite slot */
        if ((foundIndex == -1 &&
            (server->cache[i].meta->id & WH_KEYID_MASK) ==
            WH_KEYID_ERASED) ||
            server->cache[i].meta->id == meta->id) {
            foundIndex = i;
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
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return WH_ERROR_NOSPACE;
    /* write key if slot found */
    XMEMCPY((uint8_t*)server->cache[foundIndex].buffer, in, meta->len);
    XMEMCPY((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
        sizeof(whNvmMetadata));
    /* check if the key is already commited */
    if (wh_Nvm_GetMetadata(server->nvm, meta->id, meta) == WH_ERROR_NOTFOUND)
        server->cache[foundIndex].commited = 0;
    else
        server->cache[foundIndex].commited = 1;
    return 0;
}

/* try to put the specified key into cache if it isn't already, return index */
int hsmFreshenKey(whServerContext* server, whKeyId keyId)
{
    int ret = 0;
    int i;
    int foundIndex = -1;
    uint32_t outSz = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE;
    whNvmMetadata meta[1];
    if (server == NULL || keyId == WH_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        /* check for empty slot or rewrite slot */
        if ((foundIndex == -1 &&
            server->cache[i].meta->id == WH_KEYID_ERASED) ||
            server->cache[i].meta->id == keyId) {
            foundIndex = i;
            if (server->cache[i].meta->id == keyId)
                return i;
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
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return WH_ERROR_NOSPACE;
    /* try to read the metadata */
    ret = wh_Nvm_GetMetadata(server->nvm, keyId, meta);
    if (ret == 0) {
        /* set meta */
        XMEMCPY((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
            sizeof(meta));
        /* read the object */
        ret = wh_Nvm_Read(server->nvm, keyId, 0, outSz,
            server->cache[foundIndex].buffer);
    }
    /* return index */
    return foundIndex;
}

int hsmReadKey(whServerContext* server, whKeyId keyId, whNvmMetadata* outMeta,
    uint8_t* out, uint32_t* outSz)
{
    int ret = 0;
    int i;
    whNvmMetadata meta[1];
    /* make sure id is valid */
    if (server == NULL || ((keyId & WH_KEYID_MASK) == WH_KEYID_ERASED
        && (keyId & WH_KEYTYPE_MASK) != WH_KEYTYPE_SHE) ||
        outSz == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
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
    if (ret == WH_ERROR_NOTFOUND &&
        (keyId & WH_KEYTYPE_MASK) == WH_KEYTYPE_SHE &&
        (keyId & WH_KEYID_MASK) == WH_SHE_MASTER_ECU_KEY_ID) {
        XMEMSET(out, 0, WH_SHE_KEY_SZ);
        *outSz = WH_SHE_KEY_SZ;
        if (outMeta != NULL) {
            /* need empty flags and corect lenth and id */
            XMEMSET(outMeta, 0, sizeof(meta));
            meta->len = WH_SHE_KEY_SZ;
            meta->id = keyId;
        }
        ret = 0;
    }
#endif
    return ret;
}

int hsmEvictKey(whServerContext* server, whNvmId keyId)
{
    int ret = 0;
    int i;
    /* make sure id is valid */
    if (server == NULL || (keyId & WH_KEYID_MASK) == WH_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* find key */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        /* mark key as erased */
        if (server->cache[i].meta->id == keyId) {
            server->cache[i].meta->id = WH_KEYID_ERASED;
            break;
        }
    }
    /* if the key wasn't found return an error */
    if (i >= WOLFHSM_CFG_SERVER_KEYCACHE_COUNT)
        ret = WH_ERROR_NOTFOUND;
    return ret;
}

int hsmCommitKey(whServerContext* server, whNvmId keyId)
{
    int i;
    int ret = 0;
    whServerCacheSlot* cacheSlot;
    /* make sure id is valid */
    if (server == NULL || keyId == WH_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* find key in cache */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (server->cache[i].meta->id == keyId) {
            cacheSlot = &server->cache[i];
            break;
        }
    }
    if (i >= WOLFHSM_CFG_SERVER_KEYCACHE_COUNT)
        return WH_ERROR_NOTFOUND;
    /* add object */
    ret = wh_Nvm_AddObjectWithReclaim(server->nvm, cacheSlot->meta,
        cacheSlot->meta->len, cacheSlot->buffer);
    if (ret == 0)
        cacheSlot->commited = 1;
    return ret;
}

int hsmEraseKey(whServerContext* server, whNvmId keyId)
{
    int i;
    if (server == NULL || keyId == WH_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* remove the key from the cache if present */
    for (i = 0; i < WOLFHSM_CFG_SERVER_KEYCACHE_COUNT; i++) {
        if (server->cache[i].meta->id == keyId) {
            server->cache[i].meta->id = WH_KEYID_ERASED;
            break;
        }
    }
    /* destroy the object */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &keyId);
}

int wh_Server_HandleKeyRequest(whServerContext* server, uint16_t magic,
    uint16_t action, uint16_t seq, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    uint32_t field;
    uint8_t* in;
    uint8_t* out;
    whPacket* packet = (whPacket*)data;
    whNvmMetadata meta[1] = {{0}};
    /* validate args, even though these functions are only supposed to be
     * called by internal functions */
    if (server == NULL || data == NULL || size == NULL)
        return WH_ERROR_BADARGS;
    switch (action)
    {
    case WH_KEY_CACHE:
        /* in is after fixed size fields */
        in = (uint8_t*)(&packet->keyCacheReq + 1);
        /* set the metadata fields */
        meta->id = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id,
            packet->keyCacheReq.id);
        meta->flags = packet->keyCacheReq.flags;
        meta->len = packet->keyCacheReq.sz;
        /* validate label sz */
        if (packet->keyCacheReq.labelSz > WH_NVM_LABEL_LEN)
            ret = WH_ERROR_BADARGS;
        else {
            XMEMCPY(meta->label, packet->keyCacheReq.label,
                packet->keyCacheReq.labelSz);
        }
        /* get a new id if one wasn't provided */
        if (packet->keyCacheReq.id == WH_KEYID_ERASED)
            ret = hsmGetUniqueId(server, &meta->id);
        /* write the key */
        if (ret == 0)
            ret = hsmCacheKey(server, meta, in);
        if (ret == 0) {
            /* remove the cleint_id, client may set type */
            packet->keyCacheRes.id = (meta->id & WH_KEYID_MASK);
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyCacheRes);
        }
        break;
    case WH_KEY_EVICT:
        ret = hsmEvictKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyEvictReq.id));
        if (ret == 0) {
            packet->keyEvictRes.ok = 0;
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyEvictRes);
        }
        break;
    case WH_KEY_EXPORT:
        /* out is after fixed size fields */
        out = (uint8_t*)(&packet->keyExportRes + 1);
        field = WOLFHSM_CFG_COMM_DATA_LEN - (WH_PACKET_STUB_SIZE +
            sizeof(packet->keyExportRes));
        /* read the key */
        ret = hsmReadKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyExportReq.id), meta, out,
            &field);
        if (ret == 0) {
            /* set key len */
            packet->keyExportRes.len = field;
            /* set label */
            XMEMCPY(packet->keyExportRes.label, meta->label,
                sizeof(meta->label));
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyExportRes) +
                field;
        }
        break;
    case WH_KEY_COMMIT:
        /* commit the cached key */
        ret = hsmCommitKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyCommitReq.id));
        if (ret == 0) {
            packet->keyCommitRes.ok = 0;
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->keyCommitRes);
        }
        break;
    case WH_KEY_ERASE:
        ret = hsmEraseKey(server, WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyEraseReq.id));
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

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
