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

int hsmGetUniqueId(whServerContext* server)
{
    int i;
    int ret = 0;
    uint16_t id;
    /* try every index, unless both cache and nvm are full one will work */
    for (id = 1; id < WOLFHSM_NUM_RAMKEYS + 1; id++) {
        /* check against chache keys */
        for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
            if (id == server->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_NUM_RAMKEYS)
            continue;
#if 0
        /* check against nvm keys */
        for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
            if (ctx->nvmMetaCache[i].id == id) {
                break;
            }
        }
        /* try again if match */
        if (i < WOLFHSM_KEYSLOT_COUNT)
            continue;
#endif
        /* break if our id didn't match either cache or nvm */
        break;
    }
    /* if we've run out of space, return MEMORY_E */
    if (ret == 0 && id >= WOLFHSM_NUM_RAMKEYS + 1)
        ret = MEMORY_E;
    /* ultimately, return found id */
    if (ret == 0)
        ret = id;
    return ret;
}

int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in)
{
    int i;
    int foundIndex = -1;
    /* make sure id is valid */
    if (meta->id == 0)
        return BAD_FUNC_ARG;
    /* make sure the key fits in a slot */
    if (meta->len > WOLFHSM_NVM_MAX_OBJECT_SIZE)
        return BUFFER_E;
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* check for empty slot or rewrite slot */
        if (foundIndex == -1 && (server->cache[i].meta->id == 0 ||
            server->cache[i].meta->id == meta->id)) {
            foundIndex = i;
        }
    }
#if 0
    /* if no empty slots, check for a commited key we can evict */
    if (foundIndex == -1) {
        for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
            if (ctx->cache[i].commited == 1) {
                foundIndex = i;
                break;
            }
        }
    }
    /* return error if we are out of cache slots */
    if (foundIndex == -1)
        return MEMORY_E;
    ctx->cache[foundIndex].commited = 0;
    /* check if the key is in nvm, mark as commited */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT; i++) {
        /* check for duplicate id, shouldn't cache a key in nvm */
        if (ctx->nvmMetaCache[i].id == meta->id)
            ctx->cache[foundIndex].commited = 1;
    }
#endif
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

int hsmReadKey(whServerContext* server, whNvmMetadata* meta, uint8_t* out)
{
    int i;
    uint16_t searchId = meta->id;
    uint16_t outLen = meta->len;
    /* make sure id is valid */
    if (meta->id == 0)
        return BAD_FUNC_ARG;
    /* check the cache */
    for (i = 0; i < WOLFHSM_NUM_RAMKEYS; i++) {
        /* copy the meta and key before returning */
        if (server->cache[i].meta->id == searchId) {
            /* check outLen */
            if (server->cache[i].meta->len > outLen)
                return BUFFER_E;
            XMEMCPY((uint8_t*)meta, (uint8_t*)server->cache[i].meta,
                sizeof(whNvmMetadata));
            XMEMCPY(out, server->cache[i].buffer, meta->len);
            return 0;
        }
    }
    return BAD_FUNC_ARG;
#if 0
    /* setup address */
    if (ctx->partition == 1)
        addr = WOLFHSM_PART_1;
    /* find id in list */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT; i++) {
        /* check id */
        if (ctx->nvmMetaCache[i].id == searchId)
            break;
        /* keep track of length used by previous keys */
        keyOffset += ctx->nvmMetaCache[i].len;
    }
    /* if we looped to the end, no match */
    if (i >= WOLFHSM_KEYSLOT_COUNT)
        ret = BAD_FUNC_ARG;
    /* check the length, meta->len is the return size */
    if (ret == 0 && ctx->nvmMetaCache[i].len > outLen)
        ret = BUFFER_E;
    /* read key */
    if (ret == 0) {
        ret = hal_flash_read(addr + WOLFHSM_HEADER_SIZE + keyOffset, out,
            ctx->nvmMetaCache[i].len);
    }
    /* calculate key digest */
    if (ret == 0)
        ret = wc_InitSha256_ex(sha, ctx->heap, ctx->devId);
    if (ret == 0)
        ret = wc_Sha256Update(sha, out, ctx->nvmMetaCache[i].len);
    if (ret == 0)
        ret = wc_Sha256Final(sha, digest);
    /* validate key */
    if (XMEMCMP(digest, ctx->nvmMetaCache[i].confDigest, WOLFHSM_DIGEST_STUB)
        != 0) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* cache key if free slot, will only kick out other commited keys */
        hsmCacheKey(ctx, &ctx->nvmMetaCache[i], out);
        /* update out meta with nvm cache contents */
        XMEMCPY(meta, &ctx->nvmMetaCache[i], sizeof(NvmMetaData));
    }
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
#endif
}

int hsmEvictKey(whServerContext* server, uint16_t keyId)
{
    int ret = 0;
    int i;
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
        ret = BAD_FUNC_ARG;
    return ret;
}

int _wh_Server_HandleKeyRequest(whServerContext* server,
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
        meta->len = packet->keyCacheReq.len;
        XMEMCPY(meta->label, packet->keyCacheReq.label, WOLFHSM_NVM_LABEL_LEN);
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
#if 0
    case WOLFHSM_KEY_COMMIT:
        /* commit the cached key */
        ret = hsmCommitKey(ctx, packet->keyCommitReq.id);
        if (ret > 0) {
            packet->len = sizeof(packet->keyCommitRes);
            packet->keyCommitRes.ok = 0;
            ret = 0;
        }
        break;
#endif
    case WH_KEY_EXPORT:
        /* out is after fixed size fields */
        out = (uint8_t*)(&packet->keyExportRes + 1);
        /* set the metadata fields */
        meta->id = packet->keyExportReq.id;
        meta->len = WH_COMM_MTU -
            (WOLFHSM_PACKET_STUB_SIZE + sizeof(packet->keyExportRes));
        /* read the key */
        ret = hsmReadKey(server, meta, out);
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
#if 0
    case WOLFHSM_KEY_ERASE:
        ret = hsmEraseKey(ctx, packet->keyEraseReq.id);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_ERASE;
            packet->len = sizeof(packet->keyEraseRes);
            packet->keyEraseRes.ok = 0;
        }
        break;
    case WOLFHSM_VERSION_EXCHANGE:
        /* TODO should the server refuse a connection or should the client
         * decide? */
        packet->subType = WOLFHSM_VERSION_EXCHANGE;
        packet->versionExchange.version = ctx->version;
        packet->len = sizeof(packet->versionExchange);
        break;
#endif
    default:
        ret = BAD_FUNC_ARG;
        break;
    }
    /* set type here in case packet was overwritten */
    (void)magic;
    (void)seq;
    return ret;
}
