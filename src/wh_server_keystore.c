/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"

int hsmGetUniqueId(whServerContext* server)
{
    int i;
    int ret = 0;
    whNvmId id;
    whNvmId nvmId = 0;
    whNvmId keyCount;
    /* try every index until we find a unique one, don't worry about capacity */
    for (id = 1; id < sizeof(whNvmId) - WOLFHSM_KEYID_MASK; id++) {
        /* check against cache keys */
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            if ((id | WOLFHSM_KEYID_CRYPTO) == server->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_NUM_RAMKEYS)
            continue;
        /* check against nvm keys */
        do {
            ret = wh_Nvm_List(server->nvm, WOLFHSM_NVM_ACCESS_ANY,
                WOLFHSM_NVM_FLAGS_ANY, nvmId, &keyCount, &nvmId);
            if (ret != 0)
                break;
            if ((id | WOLFHSM_KEYID_CRYPTO) == nvmId)
                break;
        } while (keyCount > 0);
        /* continue if nvm match */
        if ((id | WOLFHSM_KEYID_CRYPTO) == nvmId)
            continue;
        /* break if our id didn't match either cache or nvm */
        break;
    }
    /* unlikely but cover the case where we've run out of ids */
    if (id >= sizeof(whNvmId) - WOLFHSM_KEYID_MASK)
        ret = WH_ERROR_NOSPACE;
    /* ultimately, return found id */
    if (ret == 0)
        ret = (id | WOLFHSM_KEYID_CRYPTO);
    return ret;
}

int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in)
{
    int i;
    int foundIndex = -1;
    /* make sure id is valid */
    if (meta->id == WOLFHSM_ID_ERASED)
        return WH_ERROR_BADARGS;
    /* make sure the key fits in a slot */
    if (meta->len > WOLFHSM_NVM_MAX_OBJECT_SIZE)
        return WH_ERROR_NOSPACE;
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* check for empty slot or rewrite slot */
        if ((foundIndex == -1 &&
            server->cache[i].meta->id == WOLFHSM_ID_ERASED) ||
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
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return WH_ERROR_NOSPACE;
    server->cache[foundIndex].commited = 0;
    /* write key if slot found */
    XMEMCPY((uint8_t*)server->cache[foundIndex].buffer, in, meta->len);
    XMEMCPY((uint8_t*)server->cache[foundIndex].meta, (uint8_t*)meta,
        sizeof(whNvmMetadata));
#ifdef WOLFHSM_SHE_EXTENSION
    /* if this was RAM_KEY, set the global so we can export */
    if (meta->id == WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_RAM_KEY_ID))
        hsmSheRamKeyPlain = 1;
#endif
    return 0;
}

int hsmReadKey(whServerContext* server, whNvmMetadata* meta, uint8_t* out,
    uint32_t outLen)
{
    int ret = 0;
    int i;
    uint16_t searchId = meta->id;
    /* make sure id is valid */
    if (meta->id == WOLFHSM_ID_ERASED)
        return WH_ERROR_BADARGS;
    /* check the cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* copy the meta and key before returning */
        if (server->cache[i].meta->id == searchId) {
            /* check outLen */
            if (server->cache[i].meta->len > outLen)
                return WH_ERROR_NOSPACE;
            XMEMCPY((uint8_t*)meta, (uint8_t*)server->cache[i].meta,
                sizeof(whNvmMetadata));
            XMEMCPY(out, server->cache[i].buffer, meta->len);
            return 0;
        }
    }
    /* try to read the metadata */
    ret = wh_Nvm_GetMetadata(server->nvm, searchId, meta);
    /* read the object */
    if (ret == 0)
        ret = wh_Nvm_Read(server->nvm, searchId, 0, outLen, out);
    /* cache key if free slot, will only kick out other commited keys */
    if (ret == 0)
        hsmCacheKey(server, meta, out);
#ifdef WOLFHSM_SHE_EXTENSION
    /* use empty string if we couldn't find the master ecu key */
    if (ret != 0 && searchId == WOLFHSM_SHE_MASTER_ECU_KEY_ID) {
        XMEMSET(out, 0, WOLFHSM_SHE_KEY_SZ);
        meta->len = WOLFHSM_SHE_KEY_SZ;
        meta->id = searchId;
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
    if (keyId == WOLFHSM_ID_ERASED)
        return WH_ERROR_BADARGS;
    /* find key */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* mark key as erased */
        if (server->cache[i].meta->id == keyId) {
            server->cache[i].meta->id = WOLFHSM_ID_ERASED;
            break;
        }
    }
    /* if the key wasn't found return an error */
    if (i >= WOLFHSM_NUM_RAMKEYS)
        ret = WH_ERROR_BADARGS;
    return ret;
}

int hsmCommitKey(whServerContext* server, whNvmId keyId)
{
    int i;
    int ret = 0;
    CacheSlot* cacheSlot;
    /* make sure id is valid */
    if (keyId == WOLFHSM_ID_ERASED)
        return WH_ERROR_BADARGS;
    /* find key in cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        if (server->cache[i].meta->id == keyId) {
            cacheSlot = &server->cache[i];
            break;
        }
    }
    if (i >= WOLFHSM_NUM_RAMKEYS)
        return WH_ERROR_NOTFOUND;
    /* add object */
    ret = wh_Nvm_AddObject(server->nvm, server->cache[i].meta,
        cacheSlot->meta->len, cacheSlot->buffer);
    if (ret == 0) {
        cacheSlot->commited = 1;
    }
    return ret;
}

int hsmEraseKey(whServerContext* server, whNvmId keyId)
{
    int i;
    if (keyId == WOLFHSM_ID_ERASED)
        return WH_ERROR_BADARGS;
    /* remove the key from the cache if present */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        if (server->cache[i].meta->id == keyId) {
            server->cache[i].meta->id = WOLFHSM_ID_ERASED;
            break;
        }
    }
    /* destroy the object */
    return wh_Nvm_DestroyObjects(server->nvm, 1, &keyId);
}

int wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint8_t* data, uint16_t* size)
{
    int ret = 0;
    uint8_t* in;
    uint8_t* out;
    whPacket* packet = (whPacket*)data;
    whNvmMetadata meta[1] = {0};
    switch (action)
    {
    case WH_KEY_CACHE:
        /* in is after fixed size fields */
        in = (uint8_t*)(&packet->keyCacheReq + 1);
        /* set the metadata fields */
        meta->id = packet->keyCacheReq.id;
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
        if (meta->id == WOLFHSM_ID_ERASED) {
            ret =  hsmGetUniqueId(server);
            if (ret > 0) {
                meta->id = ret;
                ret = 0;
            }
        }
        /* write the key */
        if (ret == 0)
            ret = hsmCacheKey(server, meta, in);
        if (ret == 0) {
            packet->keyCacheRes.id = meta->id;
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyCacheRes);
        }
        break;
    case WH_KEY_EVICT:
        ret = hsmEvictKey(server, packet->keyEvictReq.id);
        if (ret == 0) {
            packet->keyEvictRes.ok = 0;
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyEvictRes);
        }
        break;
    case WH_KEY_EXPORT:
        /* out is after fixed size fields */
        out = (uint8_t*)(&packet->keyExportRes + 1);
        /* set the id */
        meta->id = packet->keyExportReq.id;
        /* read the key */
        ret = hsmReadKey(server, meta, out, WH_COMM_MTU -
            (WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyExportRes)));
        if (ret == 0) {
            /* set key len */
            packet->keyExportRes.len = meta->len;
            /* set label */
            XMEMCPY(packet->keyExportRes.label, meta->label,
                sizeof(meta->label));
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyExportRes) +
                meta->len;
        }
        break;
    case WH_KEY_COMMIT:
        /* commit the cached key */
        ret = hsmCommitKey(server, packet->keyCommitReq.id);
        if (ret == 0) {
            packet->keyCommitRes.ok = 0;
            *size = WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyCommitRes);
        }
        break;
    case WH_KEY_ERASE:
        ret = hsmEraseKey(server, packet->keyEraseReq.id);
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
