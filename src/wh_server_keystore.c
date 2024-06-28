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
/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#ifndef WOLFHSM_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"
#ifdef WOLFHSM_SHE_EXTENSION
#include "wolfhsm/wh_server_she.h"
#endif

int hsmGetUniqueId(whServerContext* server, whNvmId* outId)
{
    int i;
    int ret = 0;
    whNvmId id;
    /* apply client_id and type which should be set by caller on outId */
    whNvmId buildId = (((*outId | (server->comm->client_id << 8)) & (~WOLFHSM_KEYID_MASK)));
    whNvmId nvmId = 0;
    whNvmId keyCount;
    /* try every index until we find a unique one, don't worry about capacity */
    for (id = 1; id < WOLFHSM_KEYID_MASK + 1; id++) {
        buildId = ((buildId & ~WOLFHSM_KEYID_MASK) | id);
        /* check against cache keys */
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            if (buildId == server->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_NUM_RAMKEYS)
            continue;
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
        /* check against big cache keys */
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            if (buildId == server->bigCache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_NUM_BIG_RAMKEYS)
            continue;
#endif
        /* if keyId exists */
        ret = wh_Nvm_List(server->nvm, WOLFHSM_NVM_ACCESS_ANY,
            WOLFHSM_NVM_FLAGS_ANY, buildId, &keyCount,
            &nvmId);
        /* break if we didn't find a match */
        if (ret == WH_ERROR_NOTFOUND || nvmId != buildId)
            break;
    }
    /* unlikely but cover the case where we've run out of ids */
    if (id > WOLFHSM_KEYID_MASK)
        ret = WH_ERROR_NOSPACE;
    /* ultimately, return found id */
    if (ret == 0)
        *outId |= buildId;
    return ret;
}

/* find an available slot for the size, return the slots buffer and meta */
int hsmCacheFindSlotAndZero(whServerContext* server, uint16_t keySz,
    uint8_t** outBuf, whNvmMetadata** outMeta)
{
    int i;
    int foundIndex = -1;
    if (server == NULL || (keySz > WOLFHSM_KEYCACHE_BUFSIZE
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
        && keySz > WOLFHSM_KEYCACHE_BIG_BUFSIZE
#endif
        )) {
        return WH_ERROR_BADARGS;
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    if (keySz <= WOLFHSM_KEYCACHE_BUFSIZE)
#endif
    {
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            /* check for empty slot or rewrite slot */
            if (foundIndex == -1 && server->cache[i].meta->id ==
                WOLFHSM_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }
        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
                if (server->cache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }
        /* zero the cache slot and set the output buffers */
        if (foundIndex >= 0) {
            XMEMSET(&server->cache[foundIndex], 0, sizeof(whServerCacheSlot));
            *outBuf = server->cache[foundIndex].buffer;
            *outMeta = server->cache[foundIndex].meta;
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    else {
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            /* check for empty slot or rewrite slot */
            if (foundIndex == -1 && server->bigCache[i].meta->id ==
                WOLFHSM_KEYID_ERASED) {
                foundIndex = i;
                break;
            }
        }
        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
                if (server->bigCache[i].commited == 1) {
                    foundIndex = i;
                    break;
                }
            }
        }
        if (foundIndex >= 0) {
            XMEMSET(&server->bigCache[foundIndex], 0,
                sizeof(whServerBigCacheSlot));
            *outBuf = server->bigCache[foundIndex].buffer;
            *outMeta = server->bigCache[foundIndex].meta;
        }
    }
#endif /* WOLFHSM_SEPARATE_BIG_CACHE */
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
    if (server == NULL || meta == NULL || in == NULL ||
        (meta->id & WOLFHSM_KEYID_MASK) == WOLFHSM_KEYID_ERASED ||
        (meta->len > WOLFHSM_KEYCACHE_BUFSIZE
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
        && meta->len > WOLFHSM_KEYCACHE_BIG_BUFSIZE
#endif
        )) {
        return WH_ERROR_BADARGS;
    }
    /* apply client_id */
    meta->id |= (server->comm->client_id << 8);
    /* check if we need to use big cache instead */
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    if (meta->len <= WOLFHSM_KEYCACHE_BUFSIZE)
#endif
    {
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            /* check for empty slot or rewrite slot */
            if ((foundIndex == -1 &&
                (server->cache[i].meta->id & WOLFHSM_KEYID_MASK) ==
                WOLFHSM_KEYID_ERASED) ||
                server->cache[i].meta->id == meta->id) {
                foundIndex = i;
            }
        }
        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
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
            else
                server->cache[foundIndex].commited = 1;
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    /* try big key cache, don't put small keys into big cache if full */
    else {
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            /* check for empty slot or rewrite slot */
            if ((foundIndex == -1 &&
                (server->bigCache[i].meta->id & WOLFHSM_KEYID_MASK) ==
                WOLFHSM_KEYID_ERASED) ||
                server->bigCache[i].meta->id == meta->id) {
                foundIndex = i;
            }
        }
        /* if no empty slots, check for a commited key we can evict */
        if (foundIndex == -1) {
            for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
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
            else
                server->bigCache[foundIndex].commited = 1;
        }
    }
#endif /* WOLFHSM_SEPARATE_BIG_CACHE */
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return WH_ERROR_NOSPACE;
    return 0;
}

/* try to put the specified key into cache if it isn't already, return index */
int hsmFreshenKey(whServerContext* server, whKeyId keyId, uint8_t** outBuf,
    whNvmMetadata** outMeta)
{
    int ret = 0;
    int i;
    int foundIndex = -1;
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    int foundBigIndex = -1;
#endif
    whNvmMetadata meta[1] = {0};
    if (server == NULL || (keyId & WOLFHSM_KEYID_MASK) == WOLFHSM_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* check for empty slot or rewrite slot */
        if ((foundIndex == -1 &&
            server->cache[i].meta->id == WOLFHSM_KEYID_ERASED) ||
            server->cache[i].meta->id == keyId) {
            foundIndex = i;
            if (server->cache[i].meta->id == keyId) {
                *outBuf = server->cache[i].buffer;
                *outMeta = server->cache[i].meta;
                return 0;
            }
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    /* check if the key is in the big cache */
    if (foundIndex != -1) {
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            /* check for empty slot or rewrite slot */
            if ((foundBigIndex == -1 &&
                server->bigCache[i].meta->id == WOLFHSM_KEYID_ERASED) ||
                server->bigCache[i].meta->id == keyId) {
                foundBigIndex = i;
                if (server->bigCache[i].meta->id == keyId) {
                    *outBuf = server->bigCache[i].buffer;
                    *outMeta = server->bigCache[i].meta;
                    return 0;
                }
            }
        }
    }
#endif /* WOLFHSM_SEPARATE_BIG_CACHE */
    /* try to read the metadata, we need to see len so we know which cache to
     * check */
    ret = wh_Nvm_GetMetadata(server->nvm, keyId, meta);
    if (ret != 0)
        return ret;
    /* if no empty slots, check for a commited key we can evict */
    if (foundIndex == -1
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
        && meta->len <= WOLFHSM_KEYCACHE_BUFSIZE
#endif
    ) {
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            if (server->cache[i].commited == 1) {
                foundIndex = i;
                break;
            }
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    else if (meta->len <= WOLFHSM_KEYCACHE_BIG_BUFSIZE && foundBigIndex == -1) {
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            if (server->bigCache[i].commited == 1) {
                foundBigIndex = i;
                break;
            }
        }
    }
#endif
    /* return error if we are out of cache slots */
    if (foundIndex == -1
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
        && foundBigIndex == -1
#endif
    ) {
        return WH_ERROR_NOSPACE;
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    if (foundIndex != -1)
#endif
    {
        /* set meta */
        XMEMCPY((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
            sizeof(meta));
        /* read the object */
        ret = wh_Nvm_Read(server->nvm, keyId, 0, WOLFHSM_KEYCACHE_BUFSIZE,
            server->cache[foundIndex].buffer);
        if (ret == 0) {
            *outBuf = server->cache[foundIndex].buffer;
            *outMeta = server->cache[foundIndex].meta;
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    else {
        /* set meta */
        XMEMCPY((uint8_t*)server->bigCache[foundBigIndex].meta, (uint8_t*)meta,
            sizeof(meta));
        /* read the object */
        ret = wh_Nvm_Read(server->nvm, keyId, 0, WOLFHSM_KEYCACHE_BIG_BUFSIZE,
            server->bigCache[foundBigIndex].buffer);
        if (ret == 0) {
            *outBuf = server->bigCache[foundBigIndex].buffer;
            *outMeta = server->bigCache[foundBigIndex].meta;
        }
    }
#endif
    /* return read result */
    return ret;
}

int hsmReadKey(whServerContext* server, whKeyId keyId, whNvmMetadata* outMeta,
    uint8_t* out, uint32_t* outSz)
{
    int ret = 0;
    int i;
    whNvmMetadata meta[1] = {0};
    /* make sure id is valid */
    if (server == NULL || ((keyId & WOLFHSM_KEYID_MASK) == WOLFHSM_KEYID_ERASED
        && (keyId & WOLFHSM_KEYTYPE_MASK) != WOLFHSM_KEYTYPE_SHE) ||
        outSz == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* check the cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
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
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    /* check the big cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
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
#endif /* WOLFHSM_SEPARATE_BIG_CACHE */
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
#ifdef WOLFHSM_SHE_EXTENSION
    /* use empty key of zeros if we couldn't find the master ecu key */
    if (ret == WH_ERROR_NOTFOUND &&
        (keyId & WOLFHSM_KEYTYPE_MASK) == WOLFHSM_KEYTYPE_SHE &&
        (keyId & WOLFHSM_KEYID_MASK) == WOLFHSM_SHE_MASTER_ECU_KEY_ID) {
        XMEMSET(out, 0, WOLFHSM_SHE_KEY_SZ);
        *outSz = WOLFHSM_SHE_KEY_SZ;
        if (outMeta != NULL) {
            /* need empty flags and corect lenth and id */
            XMEMSET(outMeta, 0, sizeof(meta));
            meta->len = WOLFHSM_SHE_KEY_SZ;
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
    if (server == NULL || (keyId & WOLFHSM_KEYID_MASK) == WOLFHSM_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* find key */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* mark key as erased */
        if (server->cache[i].meta->id == keyId) {
            server->cache[i].meta->id = WOLFHSM_KEYID_ERASED;
            break;
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    /* find key in big cache */
    if (i >= WOLFHSM_NUM_RAMKEYS) {
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            /* mark key as erased */
            if (server->bigCache[i].meta->id == keyId) {
                server->bigCache[i].meta->id = WOLFHSM_KEYID_ERASED;
                break;
            }
        }
        /* if the key wasn't found return an error */
        if (i >= WOLFHSM_NUM_BIG_RAMKEYS)
            ret = WH_ERROR_NOTFOUND;
    }
#else /* WOLFHSM_SEPARATE_BIG_CACHE */
    /* if the key wasn't found return an error */
    if (i >= WOLFHSM_NUM_RAMKEYS)
        ret = WH_ERROR_NOTFOUND;
#endif /* !WOLFHSM_SEPARATE_BIG_CACHE */
    return ret;
}

int hsmCommitKey(whServerContext* server, whNvmId keyId)
{
    uint8_t* slotCommited;
    uint8_t* slotBuf;
    whNvmMetadata* slotMeta;
    int i;
    int ret = 0;
    /* make sure id is valid */
    if (server == NULL || (keyId & WOLFHSM_KEYID_MASK) == WOLFHSM_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* find key in cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        if (server->cache[i].meta->id == keyId) {
            slotCommited = &server->cache[i].commited;
            slotBuf = server->cache[i].buffer;
            slotMeta = server->cache[i].meta;
            break;
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    /* find key in big cache */
    if (i >= WOLFHSM_NUM_RAMKEYS) {
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            if (server->bigCache[i].meta->id == keyId) {
                slotCommited = &server->bigCache[i].commited;
                slotBuf = server->bigCache[i].buffer;
                slotMeta = server->bigCache[i].meta;
                break;
            }
        }
        if (i >= WOLFHSM_NUM_BIG_RAMKEYS)
            return WH_ERROR_NOTFOUND;
    }
#else /* WOLFHSM_SEPARATE_BIG_CACHE */
    if (i >= WOLFHSM_NUM_RAMKEYS)
        return WH_ERROR_NOTFOUND;
#endif /* !WOLFHSM_SEPARATE_BIG_CACHE */
    /* add object */
    ret = wh_Nvm_AddObjectWithReclaim(server->nvm, slotMeta, slotMeta->len,
        slotBuf);
    if (ret == 0)
        *slotCommited = 1;
    return ret;
}

int hsmEraseKey(whServerContext* server, whNvmId keyId)
{
    int i;
    if (server == NULL || keyId == WOLFHSM_KEYID_ERASED)
        return WH_ERROR_BADARGS;
    /* apply client_id */
    keyId |= (server->comm->client_id << 8);
    /* remove the key from the cache if present */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        if (server->cache[i].meta->id == keyId) {
            server->cache[i].meta->id = WOLFHSM_KEYID_ERASED;
            break;
        }
    }
#ifdef WOLFHSM_SEPARATE_BIG_CACHE
    if (i >= WOLFHSM_NUM_RAMKEYS) {
        /* remove the key from the big cache if present */
        for (i = 0; i < WOLFHSM_NUM_BIG_RAMKEYS; i++) {
            if (server->bigCache[i].meta->id == keyId) {
                server->bigCache[i].meta->id = WOLFHSM_KEYID_ERASED;
                break;
            }
        }
    }
#endif /* WOLFHSM_SEPARATE_BIG_CACHE */
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
    whNvmMetadata meta[1] = {0};
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
        meta->id = MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
            server->comm->client_id,
            packet->keyCacheReq.id);
        meta->flags = packet->keyCacheReq.flags;
        meta->len = packet->keyCacheReq.sz;
        /* validate label sz */
        if (packet->keyCacheReq.labelSz > WOLFHSM_NVM_LABEL_LEN)
            ret = WH_ERROR_BADARGS;
        else {
            XMEMCPY(meta->label, packet->keyCacheReq.label,
                packet->keyCacheReq.labelSz);
        }
        /* get a new id if one wasn't provided */
        if (packet->keyCacheReq.id == WOLFHSM_KEYID_ERASED)
            ret = hsmGetUniqueId(server, &meta->id);
        /* write the key */
        if (ret == 0)
            ret = hsmCacheKey(server, meta, in);
        if (ret == 0) {
            /* remove the cleint_id, client may set type */
            packet->keyCacheRes.id = (meta->id & WOLFHSM_KEYID_MASK);
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyCacheRes);
        }
        break;
    case WH_KEY_EVICT:
        ret = hsmEvictKey(server, MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyEvictReq.id));
        if (ret == 0) {
            packet->keyEvictRes.ok = 0;
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyEvictRes);
        }
        break;
    case WH_KEY_EXPORT:
        /* out is after fixed size fields */
        out = (uint8_t*)(&packet->keyExportRes + 1);
        field = WH_COMM_DATA_LEN - (WOLFHSM_PACKET_STUB_SIZE +
            sizeof(packet->keyExportRes));
        /* read the key */
        ret = hsmReadKey(server, MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyExportReq.id), meta, out,
            &field);
        if (ret == 0) {
            /* set key len */
            packet->keyExportRes.len = field;
            /* set label */
            XMEMCPY(packet->keyExportRes.label, meta->label,
                sizeof(meta->label));
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyExportRes) +
                field;
        }
        break;
    case WH_KEY_COMMIT:
        /* commit the cached key */
        ret = hsmCommitKey(server, MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyCommitReq.id));
        if (ret == 0) {
            packet->keyCommitRes.ok = 0;
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyCommitRes);
        }
        break;
    case WH_KEY_ERASE:
        ret = hsmEraseKey(server, MAKE_WOLFHSM_KEYID(WOLFHSM_KEYTYPE_CRYPTO,
            server->comm->client_id, packet->keyEraseReq.id));
        if (ret == 0) {
            packet->keyEraseRes.ok = 0;
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyEraseRes);
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

#endif  /* WOLFHSM_NO_CRYPTO */
