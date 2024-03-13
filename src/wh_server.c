
/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include <arpa/inet.h>
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#if 0
#include "wolfhsm/nvm.h"
#include "wolfhsm/nvm_remote.h"
#endif

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_server.h"

#ifdef WOLFHSM_SHE_EXTENSION
const uint8_t WOLFHSM_SHE_KEY_UPDATE_ENC_C[] = {0x01, 0x01, 0x53, 0x48, 0x45,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
const uint8_t WOLFHSM_SHE_KEY_UPDATE_MAC_C[] = {0x01, 0x02, 0x53, 0x48, 0x45,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
#define WOLFHSM_SHE_UID_SZ 15
const uint8_t WOLFHSM_SHE_UID[WOLFHSM_SHE_UID_SZ] = {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
const uint8_t WOLFHSM_SHE_PRNG_KEY_C[] = {0x01, 0x04, 0x53, 0x48, 0x45, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
const uint8_t WOLFHSM_SHE_PRNG_SEED_KEY_C[] = {0x01, 0x05, 0x53, 0x48, 0x45,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
const uint8_t WOLFHSM_SHE_PRNG_EXTENSION_C[] = {0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
uint8_t WOLFHSM_SHE_PRNG_KEY[WOLFHSM_SHE_KEY_SZ];
enum WOLFHSM_SHE_SB_STATE {
    WOLFHSM_SHE_SB_INIT,
    WOLFHSM_SHE_SB_UPDATE,
    WOLFHSM_SHE_SB_FINISH,
    WOLFHSM_SHE_SB_SUCCESS,
    WOLFHSM_SHE_SB_FAILURE,
};
uint8_t hsmShePrngState[WOLFHSM_SHE_KEY_SZ];
uint8_t hsmSheSbState = WOLFHSM_SHE_SB_INIT;
uint8_t hsmSheCmacKeyFound = 0;
uint8_t hsmSheRamKeyPlain = 0;
uint32_t hsmSheBlSize = 0;
uint32_t hsmSheBlSizeReceived = 0;
uint32_t hsmSheInitRng = 0;
/* cmac is global since the bootloader update can be called multiple times */
Cmac sheCmac[1];
#endif

#if 0
static int XMEMEQZERO(uint8_t* data, int sz)
{
    for (; sz >= 1; sz--) {
        if (data[sz] != 0)
            return 0;
    }
    return 1;
}

static int hsmEraseKey(WOLFHSM_CTX* ctx, uint32_t keyId);

int nvmInit(WOLFHSM_CTX* ctx)
{
    int i;
    int ret;
    uint32_t addr = WOLFHSM_PART_0;
    uint8_t header[WOLFHSM_HEADER_SIZE];
    uint32_t counterZero;
    uint32_t counterOne;
    /* check if partition 0 header is erased */
    ret = hal_flash_read(addr, header, sizeof(header));
    if (ret != 0)
        return ret;
    for (i = 0; i < sizeof(header); i++) {
        if (header[i] != WOLFHSM_ID_ERASED)
            break;
    }
    /* if the entire header isn't erased, check counters */
    if (i < sizeof(header)) {
        /* read the two counters */
        ret = hal_flash_read(WOLFHSM_PART_0, (uint8_t*)&counterZero,
            sizeof(counterZero));
        ret = hal_flash_read(WOLFHSM_PART_1, (uint8_t*)&counterOne,
            sizeof(counterOne));
        /* check if counterOne is greater than counterZero or rollover */
        if (counterOne > counterZero ||
            (counterZero == WOLFHSM_COUNTER_MAX && counterOne == 1)) {
            ctx->partition = 1;
            addr = WOLFHSM_PART_1;
        }
        else
            ctx->partition = 0;
    }
    else {
        ctx->partition = 1;
        addr = WOLFHSM_PART_1;
    }
    /* load all the nvm key metadata into the cache */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
        ret = hal_flash_read(
            addr + WOLFHSM_PART_COUNTER_SZ + i * sizeof(NvmMetaData),
            (uint8_t*)&ctx->nvmMetaCache[i],
            sizeof(NvmMetaData));
    }
    /* erase all invalid keys, invalid keys only happen on powerfailure */
    ret = hsmEraseKey(ctx, WOLFHSM_ID_ERASED);
    return ret;
}

static int hsmGetUniqueId(WOLFHSM_CTX* ctx)
{
    int i;
    int ret = 0;
    uint32_t addr = WOLFHSM_PART_0;
    uint16_t id;
    wc_Sha256 sha[1];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    uint8_t key[WOLFHSM_KEYSIZE];
    /* setup address */
    if (ctx->partition == 1) {
        addr = WOLFHSM_PART_1;
    }
    /* try every index, unless both cache and nvm are full one will work */
    for (id = 1; id < WOLFHSM_KEYSLOT_COUNT + WOLFHSM_CACHE_COUNT + 1 &&
        ret == 0; id++) {
        /* check against chache keys */
        for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
            if (id == ctx->cache[i].meta->id)
                break;
        }
        /* try again if match */
        if (i < WOLFHSM_CACHE_COUNT)
            continue;
        /* check against nvm keys */
        for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
            if (ctx->nvmMetaCache[i].id == id) {
                break;
            }
        }
        /* try again if match */
        if (i < WOLFHSM_KEYSLOT_COUNT)
            continue;
        /* break if our id didn't match either cache or nvm */
        break;
    }
    /* if we've run out of space, return MEMORY_E */
    if (ret == 0 && id >= WOLFHSM_KEYSLOT_COUNT + WOLFHSM_CACHE_COUNT + 1)
        ret = MEMORY_E;
    /* ultimately, return found id */
    if (ret == 0)
        ret = id;
    return ret;
}

static int hsmCacheKey(WOLFHSM_CTX* ctx, NvmMetaData* meta, uint8_t* in)
{
    int i;
    int foundIndex = -1;
    /* make sure id is valid */
    if (meta->id == WOLFHSM_ID_ERASED)
        return BAD_FUNC_ARG;
    /* make sure the key fits in a slot */
    if (meta->len > WOLFHSM_KEYSIZE)
        return BUFFER_E;
    for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
        /* check for empty slot or rewrite slot */
        if (foundIndex == -1 && (ctx->cache[i].meta->id == WOLFHSM_ID_ERASED ||
            ctx->cache[i].meta->id == meta->id)) {
            foundIndex = i;
        }
    }
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
    /* write key if slot found */
    XMEMCPY((uint8_t*)ctx->cache[foundIndex].buffer, in, meta->len);
    XMEMCPY((uint8_t*)ctx->cache[foundIndex].meta, (uint8_t*)meta,
        sizeof(NvmMetaData));
#ifdef WOLFHSM_SHE_EXTENSION
    /* if this was RAM_KEY, set the global so we can export */
    if (meta->id == WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_RAM_KEY_ID))
        hsmSheRamKeyPlain = 1;
#endif
    return 0;
}

static int hsmEvictKey(WOLFHSM_CTX* ctx, uint16_t keyId)
{
    int ret = 0;
    int i;
    /* find key */
    for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
        /* mark key as erased */
        if (ctx->cache[i].meta->id == keyId) {
            ctx->cache[i].meta->id = WOLFHSM_ID_ERASED;
            break;
        }
    }
    /* if the key wasn't found return an error */
    if (i >= WOLFHSM_CACHE_COUNT)
        ret = BAD_FUNC_ARG;
    return ret;
}

static int hsmCommitKey(WOLFHSM_CTX* ctx, uint16_t keyId)
{
    int cacheIndex;
    int i;
    int ret = 0;
    int foundIndex = -1;
    uint32_t keyOffset = 0;
    uint32_t addr = WOLFHSM_PART_0;
    CacheSlot* cacheSlot;
    wc_Sha256 sha[1];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    uint8_t key[WOLFHSM_KEYSIZE];
    /* find key in cache */
    for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
        if (ctx->cache[i].meta->id == keyId) {
            cacheSlot = &ctx->cache[i];
            break;
        }
    }
    if (i >= WOLFHSM_CACHE_COUNT)
        return BAD_FUNC_ARG;
    /* setup address */
    if (ctx->partition == 1) {
        addr = WOLFHSM_PART_1;
    }
    /* find an open slot */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
        /* check that the user chosen id is valid, must check every slot for
           this scheme to work */
        if (cacheSlot->meta->id == ctx->nvmMetaCache[i].id)
            ret = BAD_FUNC_ARG;
        else if (foundIndex == -1) {
            /* empty slot found */
            if (ctx->nvmMetaCache[i].id == WOLFHSM_ID_ERASED)
                foundIndex = i;
            /* keep track of the current write offset for variable keys */
            else
                keyOffset += ctx->nvmMetaCache[i].len;
        }
    }
    /* if we failed to find a slot */
    if (ret == 0 && foundIndex == -1)
        ret = MEMORY_E;
    /* write key */
    if (ret == 0) {
        ret = hal_flash_write(
            addr + WOLFHSM_HEADER_SIZE + keyOffset, cacheSlot->buffer,
            cacheSlot->meta->len);
    }
    /* calculate key digest */
    if (ret == 0)
        ret = wc_InitSha256_ex(sha, ctx->heap, ctx->devId);
    if (ret == 0)
        ret = wc_Sha256Update(sha, cacheSlot->buffer, cacheSlot->meta->len);
    if (ret == 0)
        ret = wc_Sha256Final(sha, digest);
    /* write metadata to open slot */
    if (ret == 0) {
        XMEMCPY(cacheSlot->meta->confDigest, digest, WOLFHSM_DIGEST_STUB);
        ret = hal_flash_write(
            addr + WOLFHSM_PART_COUNTER_SZ + foundIndex * sizeof(NvmMetaData),
            (uint8_t*)cacheSlot->meta,
            sizeof(NvmMetaData));
    }
    if (ret == 0) {
        /* update the metadata cache */
        XMEMCPY((uint8_t*)&ctx->nvmMetaCache[foundIndex], (uint8_t*)cacheSlot->meta,
            sizeof(NvmMetaData));
        cacheSlot->commited = 1;
        /* ultimately return id */
        ret = cacheSlot->meta->id;
    }
    return ret;
}

static int hsmReadKeyMeta(WOLFHSM_CTX* ctx, NvmMetaData* meta)
{
    int ret = 0;
    int i;
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT; i++) {
        /* check id */
        if (ctx->nvmMetaCache[i].id == meta->id)
            break;
    }
    /* if we looped to the end, no match */
    if (i >= WOLFHSM_KEYSLOT_COUNT)
        ret = BAD_FUNC_ARG;
    /* copy the cached metadata out */
    if (ret == 0)
        XMEMCPY(meta, &ctx->nvmMetaCache[i], sizeof(NvmMetaData));
    return ret;
}

static int hsmReadKey(WOLFHSM_CTX* ctx, NvmMetaData* meta, uint8_t* out)
{
    int i;
    int ret = 0;
    uint16_t searchId = meta->id;
    uint16_t outLen = meta->len;
    uint32_t addr = WOLFHSM_PART_0;
    uint32_t keyOffset = 0;
    wc_Sha256 sha[1];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    /* make sure id is valid */
    if (meta->id == WOLFHSM_ID_ERASED)
        return BAD_FUNC_ARG;
    /* check the cache */
    for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
        /* copy the meta and key before returning */
        if (ctx->cache[i].meta->id == searchId) {
            /* check outLen */
            if (ctx->cache[i].meta->len > outLen)
                return BUFFER_E;
            XMEMCPY((uint8_t*)meta, (uint8_t*)ctx->cache[i].meta,
                sizeof(NvmMetaData));
            XMEMCPY(out, ctx->cache[i].buffer, meta->len);
            return 0;
        }
    }
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
}

static int hsmEraseKey(WOLFHSM_CTX* ctx, uint32_t keyId)
{
    int i;
    int j;
    int ret;
    uint32_t readAddr = WOLFHSM_PART_0;
    uint32_t writeAddr = WOLFHSM_PART_1;
    uint32_t readKeyOffset = 0;
    uint32_t writeKeyOffset = 0;
    uint32_t counter;
    wc_Sha256 sha[1];
    uint8_t key[WOLFHSM_KEYSIZE];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    /* remove the key from the cache */
    for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
        if (ctx->cache[i].meta->id == keyId) {
            ctx->cache[i].meta->id = WOLFHSM_ID_ERASED;
            break;
        }
    }
    /* setup address */
    if (ctx->partition == 1) {
        readAddr = WOLFHSM_PART_1;
        writeAddr = WOLFHSM_PART_0;
    }
    /* swap partition */
    ctx->partition = !ctx->partition;
    /* erase the write partition */
    ret = hal_flash_erase(writeAddr, WOLFHSM_PARTITION_SIZE);
    if (ret != 0)
        return ret;
    /* copy all keys except keyId */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
        /* skip over erased keys */
        if (ctx->nvmMetaCache[i].id == WOLFHSM_ID_ERASED)
            continue;
        /* if this is the key remove it and make the list continuous */
        if (ctx->nvmMetaCache[i].id == keyId) {
            /* skip over erase key length */
            readKeyOffset += ctx->nvmMetaCache[i].len;
            /* move other keys to fill empty slot */
            for (j = i; j < WOLFHSM_KEYSLOT_COUNT - 1; j++) {
                XMEMCPY((uint8_t*)&ctx->nvmMetaCache[j],
                    (uint8_t*)&ctx->nvmMetaCache[j + 1], sizeof(NvmMetaData));
            }
            /* erase the last slot to prevent duplicate */
            XMEMSET((uint8_t*)&ctx->nvmMetaCache[j], WOLFHSM_ID_ERASED,
                sizeof(NvmMetaData));
            /*  stay at this index*/
            i--;
            continue;
        }
        /* read key */
        if (ret == 0) {
            ret = hal_flash_read(
                readAddr + WOLFHSM_HEADER_SIZE + readKeyOffset,
                key, ctx->nvmMetaCache[i].len);
        }
        /* calculate key digest */
        if (ret == 0)
            ret = wc_InitSha256_ex(sha, ctx->heap, ctx->devId);
        if (ret == 0)
            ret = wc_Sha256Update(sha, key, ctx->nvmMetaCache[i].len);
        if (ret == 0)
            ret = wc_Sha256Final(sha, digest);
        /* if invalid key skip it and make the list continuous */
        if (XMEMCMP(digest, ctx->nvmMetaCache[i].confDigest, WOLFHSM_DIGEST_STUB) != 0) {
            /* skip over erase key length */
            readKeyOffset += ctx->nvmMetaCache[i].len;
            /* move other keys to fill empty slot */
            for (j = i; j < WOLFHSM_KEYSLOT_COUNT - 1; j++) {
                XMEMCPY((uint8_t*)&ctx->nvmMetaCache[j],
                    (uint8_t*)&ctx->nvmMetaCache[j + 1], sizeof(NvmMetaData));
            }
            /* erase the last slot to prevent duplicate */
            XMEMSET((uint8_t*)&ctx->nvmMetaCache[j], WOLFHSM_ID_ERASED,
                sizeof(NvmMetaData));
            /*  stay at this index*/
            i--;
            continue;
        }
        /* write key to new partition */
        if (ret == 0) {
            ret = hal_flash_write(writeAddr + WOLFHSM_HEADER_SIZE +
                writeKeyOffset, key, ctx->nvmMetaCache[i].len);
        }
        if (ret == 0) {
            /* increment the key offsets */
            writeKeyOffset += ctx->nvmMetaCache[i].len;
            readKeyOffset += ctx->nvmMetaCache[i].len;
            /* write packed metadata */
            ret = hal_flash_write(
                writeAddr + WOLFHSM_PART_COUNTER_SZ + i * sizeof(NvmMetaData),
                (uint8_t*)&ctx->nvmMetaCache[i],
                sizeof(NvmMetaData));
        }
    }
    /* update the counter in the new partition */
    if (ret == 0)
        ret = hal_flash_read(readAddr, (uint8_t*)&counter, sizeof(counter));
    if (ret == 0) {
        /* if erased set to 1 */
        if (counter == WOLFHSM_ID_ERASED)
            counter = 1;
        else
            counter++;
        ret = hal_flash_write(writeAddr, (uint8_t*)&counter, sizeof(counter));
    }
    /* erase old partition */
    if (ret == 0)
        ret = hal_flash_erase(readAddr, WOLFHSM_PARTITION_SIZE);
    return ret;
}

static int hsmCacheKeyRsa(WOLFHSM_CTX* ctx, NvmMetaData* meta, RsaKey* key)
{
    int ret = 0;
    byte keyBuf[WOLFHSM_KEYSIZE];
    /* export key */
    ret = wc_RsaKeyToDer(key, keyBuf, sizeof(keyBuf));
    /* write key, no flags */
    if (ret > 0) {
        meta->len = ret;
        ret = hsmGetUniqueId(ctx);
    }
    if (ret > 0 ) {
        meta->id = ret;
        ret = hsmCacheKey(ctx, meta, keyBuf);
    }
    return ret;
}

static int hsmLoadKeyRsa(WOLFHSM_CTX* ctx, NvmMetaData* meta, RsaKey* key)
{
    int ret;
    uint32_t idx = 0;
    byte keyBuf[WOLFHSM_KEYSIZE];
    /* retrieve the key */
    meta->len = WOLFHSM_KEYSIZE;
    ret = hsmReadKey(ctx, meta, keyBuf);
    /* decode the key */
    if (ret == 0)
        ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, key, meta->len);

    return ret;
}

static int hsmCacheKeyEcc(WOLFHSM_CTX* ctx, NvmMetaData* meta, ecc_key* key)
{
    int ret;
    uint32_t qxLen;
    uint32_t qyLen;
    uint32_t qdLen;
    byte keyBuf[WOLFHSM_KEYSIZE];
    /* export key */
    qxLen = qyLen = qdLen = key->dp->size;
    ret = wc_ecc_export_private_raw(key, keyBuf, &qxLen,
        keyBuf + qxLen, &qyLen, keyBuf + qxLen + qyLen, &qdLen);
    /* cache key */
    if (ret == 0) {
        ret = hsmGetUniqueId(ctx);
    }
    if (ret > 0) {
        meta->len = qxLen + qyLen + qdLen;
        meta->id = ret;
        ret = hsmCacheKey(ctx, meta, keyBuf);
    }
    return ret;
}

static int hsmLoadKeyEcc(WOLFHSM_CTX* ctx, NvmMetaData* meta, ecc_key* key,
    int curveId)
{
    int ret;
    uint32_t keySz;
    byte keyBuf[WOLFHSM_KEYSIZE];
    /* retrieve the key */
    meta->len = WOLFHSM_KEYSIZE;
    ret = hsmReadKey(ctx, meta, keyBuf);
    /* decode the key */
    if (ret == 0) {
        keySz = meta->len / 3;
        ret = wc_ecc_import_unsigned(key, keyBuf, keyBuf + keySz,
            keyBuf + keySz * 2, curveId);
    }
    return ret;
}
#endif

int wh_Server_Init(whServerContext* server, whServerConfig* config)
{
    int rc = 0;
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(server, 0, sizeof(*server));
    if (
/*            ((rc = wh_Nvm_Init(server->nvm_device, config->nvm_device)) == 0) && */
        ((rc = wh_CommServer_Init(server->comm, config->comm)) == 0) &&
        ((rc = wolfCrypt_Init()) == 0) &&
        ((rc = wc_InitRng_ex(server->crypto->rng, NULL, INVALID_DEVID)) == 0) &&
/*        ((rc = server->nvm->cb->Init(server->nvm, config->nvm)) == 0) && */
        1) {
        /* All good */
    } else {
        wh_Server_Cleanup(server);
    }
    /* WC_INIT_E, WC_HW_E*/
    return rc;
}

static int _wh_Server_HandleCommRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t* out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    case WH_MESSAGE_COMM_ACTION_ECHO:
    {
        whMessageCommLenData req = {0};
        whMessageCommLenData resp = {0};

        /* Convert request struct */
        wh_MessageComm_TranslateLenData(magic,
                (whMessageCommLenData*)req_packet, &req);

        /* Process the echo action */
        resp.len = req.len;
        memcpy(resp.data, req.data, resp.len);

        /* Convert the response struct */
        wh_MessageComm_TranslateLenData(magic,
                &resp, (whMessageCommLenData*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;

    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

static int _wh_Server_HandleNvmRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
#if 0
    case WH_MESSAGE_NVM_ACTION_AVAILABLE:
    {
        whMessageNvmAvailableRequest req = {0};
        whMessageNvmAvailableResponse resp = {0};

        /* Convert request struct */
        wh_MessageNvm_TranslateAvailableRequest(magic,
                (whMessageNvmAvailableRequest*)req_packet, &req);

        /* Process the available action */
        resp.rc = server->nvm->cb->GetAvailable(server->nvm,
                &resp.available_objects, &resp.available_bytes,
                &resp.recoverable_object, &resp.recoverable_bytes);

        /* Convert the response struct */
        wh_MessageNvm_TranslateAvailableResponse(magic,
                &resp, (whMessageNvmAvailableResponse*)resp_packet);
        *out_resp_size = sizeof(resp);
    }; break;
#endif
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

static int _wh_Server_HandleCryptoRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size)
{
    int ret = 0;
    uint8_t* out;
    whPacket* packet = (whPacket*)data;
#if 0
    uint8_t* in;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* authIn;
    uint8_t* authTag;
    uint8_t* sig;
    uint8_t* hash;
    uint32_t field;
    union {
        Aes aes[1];
        RsaKey rsa[1];
        Cmac cmac[1];
        ecc_key eccPrivate[1];
    } crypto;
    ecc_key eccPublic[1];
#endif
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
    uint8_t tmpKey[AES_MAX_KEY_SIZE + AES_IV_SIZE];
#endif

    switch (action)
    {
#if 0
    case WC_ALGO_TYPE_HASH:
        break;
    case WC_ALGO_TYPE_CIPHER:
        switch (packet->cipherAnyReq.type)
        {
        case WC_CIPHER_AES_CBC:
            /* key, iv, in, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesCbcReq + 1);
            iv = key + packet->cipherAesCbcReq.keyLen;
            in = iv + AES_IV_SIZE;
            out = (uint8_t*)(&packet->cipherAesCbcRes + 1);
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* read keyId */
            meta->id = *(uint32_t*)key;
            /* load the key from keystore */
            meta->len = sizeof(tmpKey);
            ret = hsmReadKey(ctx, meta, tmpKey);
            if (ret == 0) {
                /* set key to use tmpKey data */
                key = tmpKey;
                /* overwrite keyLen with internal length */
                packet->cipherAesCbcReq.keyLen = meta->len;
            }
#endif
            /* init key with possible hardware */
            if (ret == 0)
                ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
            /* load the key */
            if (ret == 0) {
                ret = wc_AesSetKey(crypto.aes, key,
                    packet->cipherAesCbcReq.keyLen, iv,
                    packet->cipherAesCbcReq.enc == 1 ?
                    AES_ENCRYPTION : AES_DECRYPTION);
            }
            /* do the crypto operation */
            if (ret == 0) {
                /* store this since it will be overwritten */
                field = packet->cipherAesCbcReq.sz;
                if (packet->cipherAesCbcReq.enc == 1)
                    ret = wc_AesCbcEncrypt(crypto.aes, out, in, field);
                else
                    ret = wc_AesCbcDecrypt(crypto.aes, out, in, field);
            }
            wc_AesFree(crypto.aes);
            /* encode the return sz */
            if (ret == 0) {
                /* set type */
                packet->subType = WC_ALGO_TYPE_CIPHER;
                /* set len */
                packet->len = sizeof(packet->cipherAesCbcRes) + field;
                /* set sz */
                packet->cipherAesCbcRes.sz = field;
            }
            break;
        case WC_CIPHER_AES_GCM:
            /* key, iv, in, authIn, and out are after fixed size fields */
            key = (uint8_t*)(&packet->cipherAesGcmReq + 1);
            iv = key + packet->cipherAesGcmReq.keyLen;
            in = iv + packet->cipherAesGcmReq.ivSz;
            authIn = in + packet->cipherAesGcmReq.sz;
            out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
#ifdef WOLFHSM_SYMMETRIC_INTERNAL
            /* read keyId */
            meta->id = *(uint32_t*)key;
            /* load the key from keystore */
            meta->len = sizeof(tmpKey);
            ret = hsmReadKey(ctx, meta, tmpKey);
            if (ret == 0) {
                /* set key to use tmpKey data */
                key = tmpKey;
                /* overwrite keyLen with internal length */
                packet->cipherAesGcmReq.keyLen = meta->len;
            }
#endif
            /* init key with possible hardware */
            if (ret == 0)
                ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
            /* load the key */
            if (ret == 0) {
                ret = wc_AesGcmSetKey(crypto.aes, key,
                    packet->cipherAesGcmReq.keyLen);
            }
            /* do the crypto operation */
            if (ret == 0) {
                /* store this since it will be overwritten */
                field = packet->cipherAesGcmReq.sz;
                if (packet->cipherAesGcmReq.enc == 1) {
                    /* set authTag as a packet output */
                    authTag = out + field;
                    /* copy authTagSz since it will be overwritten */
                    packet->cipherAesGcmRes.authTagSz =
                        packet->cipherAesGcmReq.authTagSz;
                    ret = wc_AesGcmEncrypt(crypto.aes, out, in, field, iv,
                        packet->cipherAesGcmReq.ivSz, authTag,
                        packet->cipherAesGcmReq.authTagSz, authIn,
                        packet->cipherAesGcmReq.authInSz);
                }
                else {
                    /* set authTag as a packet input */
                    authTag = authIn + packet->cipherAesGcmReq.authInSz;
                    ret = wc_AesGcmDecrypt(crypto.aes, out, in, field, iv,
                        packet->cipherAesGcmReq.ivSz, authTag,
                        packet->cipherAesGcmReq.authTagSz, authIn,
                        packet->cipherAesGcmReq.authInSz);
                }
            }
            wc_AesFree(crypto.aes);

            /* encode the return sz */
            if (ret == 0) {
                /* set type */
                packet->subType = WC_ALGO_TYPE_CIPHER;
                /* set len */
                packet->len = sizeof(packet->cipherAesGcmRes) + field;
                /* set sz */
                packet->cipherAesGcmRes.sz = field;
            }
            break;
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
    case WC_ALGO_TYPE_PK:
        switch (packet->pkAnyReq.type)
        {
        case WC_PK_TYPE_RSA_KEYGEN:
            /* init the rsa key */
            ret = wc_InitRsaKey_ex(crypto.rsa, ctx->heap, ctx->devId);
            /* make the rsa key with the given params */
            if (ret == 0) {
                ret = wc_MakeRsaKey(crypto.rsa,
                    packet->pkRsakgReq.size,
                    packet->pkRsakgReq.e,
                    ctx->rng);
            }
            /* cache the generated key */
            if (ret == 0)
                ret = hsmCacheKeyRsa(ctx, meta, crypto.rsa);
            /* set the assigned id */
            if (ret == 0)
                packet->pkRsakgRes.keyId = meta->id;
            wc_FreeRsaKey(crypto.rsa);
            if (ret == 0) {
                /* set len */
                packet->len = sizeof(packet->pkRsakgRes);
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
                ret = 0;
            }
            break;
        case WC_PK_TYPE_RSA:
            switch (packet->pkRsaReq.opType)
            {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                    /* in and out are after the fixed size fields */
                    in = (uint8_t*)(&packet->pkRsaReq + 1);
                    out = (uint8_t*)(&packet->pkRsaRes + 1);
                    /* init rsa key */
                    ret = wc_InitRsaKey_ex(crypto.rsa, ctx->heap, ctx->devId);
                    /* load the key from the keystore */
                    if (ret == 0) {
                        meta->id = packet->pkRsaReq.keyId;
                        ret = hsmLoadKeyRsa(ctx, meta, crypto.rsa);
                    }
                    /* do the rsa operation */
                    if (ret == 0) {
                        field = packet->pkRsaReq.outLen;
                        ret = wc_RsaFunction( in, packet->pkRsaReq.inLen,
                            out, &field, packet->pkRsaReq.opType,
                            crypto.rsa, ctx->rng);
                    }
                    /* free the key */
                    wc_FreeRsaKey(crypto.rsa);
                    if (ret == 0) {
                        /* set type */
                        packet->subType = WC_ALGO_TYPE_PK;
                        /* set len */
                        packet->len = sizeof(packet->pkRsaRes) + field;
                        /*set outLen */
                        packet->pkRsaRes.outLen = field;
                    }
                    break;
            }
            break;
        case WC_PK_TYPE_RSA_GET_SIZE:
            /* init rsa key */
            ret = wc_InitRsaKey_ex(crypto.rsa, ctx->heap, ctx->devId);
            /* load the key from the keystore */
            if (ret == 0) {
                meta->id = packet->pkRsaGetSizeReq.keyId;
                ret = hsmLoadKeyRsa(ctx, meta, crypto.rsa);
            }
            /* get the size */
            if (ret == 0)
                ret = wc_RsaEncryptSize(crypto.rsa);
            wc_FreeRsaKey(crypto.rsa);
            if (ret > 0) {
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
                /* set len */
                packet->len = sizeof(packet->pkRsaGetSizeRes);
                /*set keySize */
                packet->pkRsaGetSizeRes.keySize = ret;
                ret = 0;
            }
            break;
        case WC_PK_TYPE_EC_KEYGEN:
            /* init ecc key */
            ret = wc_ecc_init_ex(crypto.eccPrivate, ctx->heap, ctx->devId);
            /* generate the key the key */
            if (ret == 0) {
                ret = wc_ecc_make_key_ex(ctx->rng, packet->pkEckgReq.sz,
                    crypto.eccPrivate, packet->pkEckgReq.curveId);
            }
            /* cache the generated key */
            if (ret == 0)
                ret = hsmCacheKeyEcc(ctx, meta, crypto.eccPrivate);
            /* set the assigned id */
            wc_ecc_free(crypto.eccPrivate);
            if (ret == 0) {
                packet->pkEckgRes.keyId = meta->id;
                /* set len */
                packet->len = sizeof(packet->pkEckgRes);
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
            }
            break;
        case WC_PK_TYPE_ECDH:
            /* out is after the fixed size fields */
            out = (uint8_t*)(&packet->pkEcdhRes + 1);
            /* init ecc key */
            ret = wc_ecc_init_ex(crypto.eccPrivate, ctx->heap, ctx->devId);
            if (ret == 0)
                ret = wc_ecc_init_ex(eccPublic, ctx->heap, ctx->devId);
            /* load the private key */
            if (ret == 0) {
                meta->id = packet->pkEcdhReq.privateKeyId;
                ret = hsmLoadKeyEcc(ctx, meta, crypto.eccPrivate,
                    packet->pkEcdhReq.curveId);
            }
            /* set rng */
            if (ret == 0)
                ret = wc_ecc_set_rng(crypto.eccPrivate, ctx->rng);
            /* load the public key */
            if (ret == 0) {
                meta->id = packet->pkEcdhReq.publicKeyId;
                ret = hsmLoadKeyEcc(ctx, meta, eccPublic,
                    packet->pkEcdhReq.curveId);
            }
            /* make shared secret */
            if (ret == 0) {
                field = crypto.eccPrivate->dp->size;
                ret = wc_ecc_shared_secret(crypto.eccPrivate, eccPublic, out,
                    &field);
            }
            wc_ecc_free(crypto.eccPrivate);
            wc_ecc_free(eccPublic);
            if (ret == 0) {
                packet->pkEcdhRes.sz = field;
                /* set len */
                packet->len = sizeof(packet->pkEcdhRes) + field;
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
            }
            break;
        case WC_PK_TYPE_ECDSA_SIGN:
            /* in and out are after the fixed size fields */
            in = (uint8_t*)(&packet->pkEccSignReq + 1);
            out = (uint8_t*)(&packet->pkEccSignRes + 1);
            /* init pivate key */
            ret = wc_ecc_init_ex(crypto.eccPrivate, ctx->heap, ctx->devId);
            /* load the private key */
            if (ret == 0) {
                meta->id = packet->pkEccSignReq.keyId;
                ret = hsmLoadKeyEcc(ctx, meta, crypto.eccPrivate,
                    packet->pkEccSignReq.curveId);
            }
            /* sign the input */
            if (ret == 0) {
                field = WOLFHSM_COMM_MTU - sizeof(packet->pkEccSignRes);
                ret = wc_ecc_sign_hash(in, packet->pkEccSignReq.sz, out,
                    &field, ctx->rng, crypto.eccPrivate);
            }
            wc_ecc_free(crypto.eccPrivate);
            if (ret == 0) {
                packet->pkEccSignRes.sz = field;
                /* set len */
                packet->len = sizeof(packet->pkEccSignRes) + field;
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
            }
            break;
        case WC_PK_TYPE_ECDSA_VERIFY:
            /* sig and hash are after the fixed size fields */
            sig = (uint8_t*)(&packet->pkEccVerifyReq + 1);
            hash = (uint8_t*)(&packet->pkEccVerifyReq + 1) +
                packet->pkEccVerifyReq.sigSz;
            /* init public key */
            ret = wc_ecc_init_ex(eccPublic, ctx->heap, ctx->devId);
            /* load the public key */
            if (ret == 0) {
                meta->id = packet->pkEccVerifyReq.keyId;
                ret = hsmLoadKeyEcc(ctx, meta, eccPublic,
                    packet->pkEccVerifyReq.curveId);
            }
            /* verify the signature */
            if (ret == 0) {
                ret = wc_ecc_verify_hash(sig, packet->pkEccVerifyReq.sigSz,
                    hash, packet->pkEccVerifyReq.hashSz, (int*)&field,
                    eccPublic);
            }
            wc_ecc_free(eccPublic);
            if (ret == 0) {
                packet->pkEccVerifyRes.res = field;
                /* set len */
                packet->len = sizeof(packet->pkEccVerifyRes);
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
            }
            break;
        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
            /* init pivate key */
            ret = wc_ecc_init_ex(crypto.eccPrivate, ctx->heap, ctx->devId);
            /* load the private key */
            if (ret == 0) {
                meta->id = packet->pkEccCheckReq.keyId;
                ret = hsmLoadKeyEcc(ctx, meta, crypto.eccPrivate,
                    packet->pkEccCheckReq.curveId);
            }
            /* check the key */
            if (ret == 0) {
                ret = wc_ecc_check_key(crypto.eccPrivate);
            }
            wc_ecc_free(crypto.eccPrivate);
            if (ret == 0) {
                packet->pkEccCheckRes.ok = 1;
                /* set len */
                packet->len = sizeof(packet->pkEccCheckRes);
                /* set type */
                packet->subType = WC_ALGO_TYPE_PK;
            }
            break;
        default:
            ret = NOT_COMPILED_IN;
            break;
        }
        break;
#endif
    case WC_ALGO_TYPE_RNG:
        /* out is after the fixed size fields */
        out = (uint8_t*)(&packet->rngRes + 1);
        /* generate the bytes */
        ret = wc_RNG_GenerateBlock(server->crypto->rng, out, packet->rngReq.sz);
        if (ret == 0) {
            *size = sizeof(packet->rngRes) + packet->rngRes.sz;
        }
        break;
#if 0
    case WC_ALGO_TYPE_SEED:
        break;
    case WC_ALGO_TYPE_HMAC:
        break;
    case WC_ALGO_TYPE_CMAC:
        /* out, in and key are after the fixed size fields */
        out = (uint8_t*)(&packet->cmacRes + 1);
        in = (uint8_t*)(&packet->cmacReq + 1);
        key = in + packet->cmacReq.inSz;
        /* set to erased until we know the keyId */
        meta->id = WOLFHSM_ID_ERASED;
        meta->len = sizeof(Cmac);
        /* req will be overwritten by res final call, store this now */
        field = packet->cmacReq.opType;
        /* do operation based on optype */
        switch (packet->cmacReq.opType) {
            case WOLFHSM_CMAC_ONESHOT:
                packet->cmacRes.outSz = packet->cmacReq.outSz;
                ret = wc_AesCmacGenerate_ex(crypto.cmac, out,
                    &packet->cmacRes.outSz, in, packet->cmacReq.inSz, key,
                    packet->cmacReq.keySz, ctx->heap, ctx->devId);
                break;
            case WOLFHSM_CMAC_INIT:
                /* initialize cmac with key and type */
                ret = wc_InitCmac_ex(crypto.cmac, key, packet->cmacReq.keySz,
                    packet->cmacReq.type, NULL, ctx->heap, ctx->devId);
                break;
            case WOLFHSM_CMAC_UPDATE:
                meta->id = packet->cmacReq.keyId;
                /* load cmac struct from cache ram */
                ret = hsmReadKey(ctx, meta, (void*)crypto.cmac);
                if (ret == 0)
                    ret = wc_CmacUpdate(crypto.cmac, in, packet->cmacReq.inSz);
                break;
            case WOLFHSM_CMAC_FINAL:
                meta->id = packet->cmacReq.keyId;
                /* load cmac struct from cache ram */
                ret = hsmReadKey(ctx, meta, (void*)crypto.cmac);
                if (ret == 0) {
                    packet->cmacRes.outSz = packet->cmacReq.outSz;
                    ret = wc_CmacFinal(crypto.cmac, out, &packet->cmacRes.outSz);
                }
                /* evict the key from cache */
                if (ret == 0)
                    ret = hsmEvictKey(ctx, meta->id);
                break;
            default:
                ret = BAD_FUNC_ARG;
                break;
        }
        if (ret == 0 && field != WOLFHSM_CMAC_FINAL &&
            field != WOLFHSM_CMAC_ONESHOT) {
            /* re-cache the updated struct */
            if (meta->id == WOLFHSM_ID_ERASED)
                meta->id = hsmGetUniqueId(ctx);
            ret = hsmCacheKey(ctx, meta, (void*)crypto.cmac);
            packet->cmacRes.outSz = 0;
        }
        if (ret == 0) {
            packet->cmacRes.keyId = meta->id;
            packet->subType = WC_ALGO_TYPE_CMAC;
            packet->len = sizeof(packet->cmacRes) + packet->cmacRes.outSz;
        }
        break;
#endif
    case WC_ALGO_TYPE_NONE:
    default:
        ret = NOT_COMPILED_IN;
        break;
    }
    return ret;
}

static int _wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
#if 0
    int ret = 0;
    uint8_t* in;
    uint8_t* out;
    switch (packet->subType)
    {
    case WOLFHSM_KEY_CACHE:
        /* in is after fixed size fields */
        in = (uint8_t*)(&packet->keyCacheReq + 1);
        /* set the metadata fields */
        meta->id = packet->keyCacheReq.id;
        meta->flags = packet->keyCacheReq.flags;
        meta->len = packet->keyCacheReq.len;
        XMEMCPY(meta->label, packet->keyCacheReq.label, WOLFHSM_NVM_LABEL_LEN);
        /* get a new id if one wasn't provided */
        if (meta->id == WOLFHSM_ID_ERASED) {
            ret =  hsmGetUniqueId(ctx);
            if (ret > 0) {
                meta->id = ret;
                ret = 0;
            }
        }
        /* write the key */
        if (ret == 0)
            ret = hsmCacheKey(ctx, meta, in);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_CACHE;
            packet->len = sizeof(packet->keyCacheRes);
            packet->keyCacheRes.id = meta->id;
        }
        break;
    case WOLFHSM_KEY_EVICT:
        ret = hsmEvictKey(ctx, packet->keyEvictReq.id);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_EVICT;
            packet->len = sizeof(packet->keyEvictRes);
            packet->keyEvictRes.ok = 0;
        }
        break;
    case WOLFHSM_KEY_COMMIT:
        /* commit the cached key */
        ret = hsmCommitKey(ctx, packet->keyCommitReq.id);
        if (ret > 0) {
            packet->subType = WOLFHSM_KEY_COMMIT;
            packet->len = sizeof(packet->keyCommitRes);
            packet->keyCommitRes.ok = 0;
            ret = 0;
        }
        break;
    case WOLFHSM_KEY_EXPORT:
        /* out is after fixed size fields */
        out = (uint8_t*)(&packet->keyExportRes + 1);
        /* set the metadata fields */
        meta->id = packet->keyExportReq.id;
        meta->len = WOLFHSM_KEYSIZE;
        /* read the key */
        ret = hsmReadKey(ctx, meta, out);
        if (ret == 0) {
            packet->subType = WOLFHSM_KEY_EXPORT;
            /* set return len */
            packet->len = sizeof(packet->keyExportRes) + meta->len;
            /* set key len */
            packet->keyExportRes.len = meta->len;
            /* set label */
            XMEMCPY(packet->keyExportRes.label, meta->label, sizeof(meta->label));
        }
        break;
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
    default:
        ret = BAD_FUNC_ARG;
        break;
    }
    /* set type here in case packet was overwritten */
    packet->type = WOLFHSM_MANAGE;
    return ret;
#endif
    (void)server;
    (void)magic;
    (void)action;
    (void)seq;
    (void)req_size;
    (void)req_packet;
    (void)out_resp_size;
    (void)resp_packet;
    return 0;
}

#ifdef WOLFHSM_SHE_EXTENSION
/* kdf function based on the Miyaguchi-Preneel one-way compression function */
static int wh_AesMp16(WOLFHSM_CTX* ctx, byte* in, word32 inSz,
    byte* messageZero, byte* out)
{
    int ret;
    int i = 0;
    int j;
    Aes aes[1];
    byte paddedInput[AES_BLOCK_SIZE];
    /* check valid inputs */
    if (in == NULL || inSz == 0 || messageZero == NULL || out == NULL)
        return BAD_FUNC_ARG;
    /* init with hw */
    ret = wc_AesInit(aes, ctx->heap, ctx->devId);
    /* do the first block with messageZero as the key */
    if (ret == 0) {
        ret = wc_AesSetKeyDirect(aes, messageZero, AES_BLOCK_SIZE, NULL,
            AES_ENCRYPTION);
    }
    while (ret == 0 && i < (int)inSz) {
        /* copy a block and pad it if we're short */
        if ((int)inSz - i < (int)AES_BLOCK_SIZE) {
            XMEMCPY(paddedInput, in + i, inSz - i);
            XMEMSET(paddedInput + inSz - i, 0, AES_BLOCK_SIZE - (inSz - i));
        }
        else
            XMEMCPY(paddedInput, in + i, AES_BLOCK_SIZE);
        /* encrypt this block */
        ret = wc_AesEncryptDirect(aes, out, paddedInput);
        /* xor with the original message and then the previous block */
        for (j = 0; j < (int)AES_BLOCK_SIZE; j++) {
            out[j] ^= paddedInput[j];
            /* use messageZero as our previous output buffer */
            out[j] ^= messageZero[j];
        }
        /* set the key for the next block */
        if (ret == 0) {
            ret = wc_AesSetKeyDirect(aes, out, AES_BLOCK_SIZE, NULL,
                AES_ENCRYPTION);
        }
        if (ret == 0) {
            /* store previous output in messageZero */
            XMEMCPY(messageZero, out, AES_BLOCK_SIZE);
            /* increment to next block */
            i += AES_BLOCK_SIZE;
        }
    }
    /* free aes for protection */
    wc_AesFree(aes);
    return ret;
}

static int hsmSheOverwriteKey(WOLFHSM_CTX* ctx, NvmMetaData* meta, uint8_t* in)
{
    int i;
    int j;
    int ret = 0;
    uint32_t readAddr = WOLFHSM_PART_0;
    uint32_t writeAddr = WOLFHSM_PART_1;
    uint32_t readKeyOffset = 0;
    uint32_t writeKeyOffset = 0;
    uint32_t counter;
    wc_Sha256 sha[1];
    uint8_t key[WOLFHSM_KEYSIZE];
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    /* setup address */
    if (ctx->partition == 1) {
        readAddr = WOLFHSM_PART_1;
        writeAddr = WOLFHSM_PART_0;
    }
    /* swap partition */
    ctx->partition = !ctx->partition;
    /* erase the write partition */
    ret = hal_flash_erase(writeAddr, WOLFHSM_PARTITION_SIZE);
    if (ret != 0)
        return ret;
    /* copy all keys except keyId */
    for (i = 0; i < WOLFHSM_KEYSLOT_COUNT && ret == 0; i++) {
        /* if erased, skip it */
        if (ctx->nvmMetaCache[i].id == WOLFHSM_ID_ERASED)
            continue;
        /* if this is the key we're overwriting erase and continue*/
        if (ctx->nvmMetaCache[i].id == meta->id) {
            /* skip over erase key length */
            readKeyOffset += ctx->nvmMetaCache[i].len;
            /* move key meta up to fill empty slot */
            for (j = i; j < WOLFHSM_KEYSLOT_COUNT - 1; j++) {
                XMEMCPY((uint8_t*)&ctx->nvmMetaCache[j],
                    (uint8_t*)&ctx->nvmMetaCache[j + 1], sizeof(NvmMetaData));
            }
            /* erase the last slot to prevent duplicate */
            XMEMSET((uint8_t*)&ctx->nvmMetaCache[j], WOLFHSM_ID_ERASED,
                sizeof(NvmMetaData));
            /*  stay at this index*/
            i--;
            continue;
        }
        /* read key */
        if (ret == 0) {
            ret = hal_flash_read(
                readAddr + WOLFHSM_HEADER_SIZE + readKeyOffset, key,
                ctx->nvmMetaCache[i].len);
        }
        /* write key to new partition */
        if (ret == 0) {
            ret = hal_flash_write(writeAddr + WOLFHSM_HEADER_SIZE +
                writeKeyOffset, key, ctx->nvmMetaCache[i].len);
        }
        if (ret == 0) {
            /* increment the key offsets */
            writeKeyOffset += ctx->nvmMetaCache[i].len;
            readKeyOffset += ctx->nvmMetaCache[i].len;
            /* write packed metadata */
            ret = hal_flash_write(
                writeAddr + WOLFHSM_PART_COUNTER_SZ + i * sizeof(NvmMetaData),
                (uint8_t*)&ctx->nvmMetaCache[i],
                sizeof(NvmMetaData));
        }
    }
    /* replace the key in the cache */
    if (ret == 0) {
        for (i = 0; i < WOLFHSM_CACHE_COUNT; i++) {
            if (ctx->cache[i].meta->id == meta->id) {
                XMEMCPY((uint8_t*)ctx->cache[i].meta, (uint8_t*)meta,
                    sizeof(NvmMetaData));
                XMEMCPY((uint8_t*)ctx->cache[i].buffer, (uint8_t*)in,
                    meta->len);
                break;
            }
        }
    }
    /* cache the key if not replaced */
    if (ret == 0 && i >= WOLFHSM_CACHE_COUNT)
        ret = hsmCacheKey(ctx, meta, in);
    /* commit the key */
    if (ret == 0) {
        ret = hsmCommitKey(ctx, meta->id);
        if (ret == meta->id)
            ret = 0;
    }
    /* update the counter in the new partition */
    if (ret == 0)
        ret = hal_flash_read(readAddr, (uint8_t*)&counter, sizeof(counter));
    if (ret == 0) {
        /* if erased set to 1 */
        if (counter == WOLFHSM_ID_ERASED)
            counter = 1;
        else
            counter++;
        ret = hal_flash_write(writeAddr, (uint8_t*)&counter, sizeof(counter));
    }
    /* erase old partition */
    if (ret == 0)
        ret = hal_flash_erase(readAddr, WOLFHSM_PARTITION_SIZE);
    return ret;
}

/* AuthID is the 4 rightmost bits of messageOne */
static inline uint16_t hsmShePopAuthId(uint8_t* messageOne)
{
    return WOLFHSM_SHE_TRANSLATE_KEY_ID(
        (*(messageOne + WOLFHSM_SHE_M1_SZ - 1) & 0x0f));
}

/* ID is the second to last 4 bits of messageOne */
static inline uint16_t hsmShePopId(uint8_t* messageOne)
{
    return WOLFHSM_SHE_TRANSLATE_KEY_ID(
        ((*(messageOne + WOLFHSM_SHE_M1_SZ - 1) & 0xf0) >> 4));
}

/* flags are the rightmost 4 bits of byte 3 as it's leftmost bits
 * and leftmost bit of byte 4 as it's rightmost bit */
static inline uint32_t hsmShePopFlags(uint8_t* messageTwo)
{
    return (((messageTwo[3] & 0x0f) << 4) | ((messageTwo[4] & 0x80) >> 7));
}

static inline int hsmHandleSHE(WOLFHSM_CTX* ctx, wh_Packet* packet,
    NvmMetaData* meta)
{
    int ret = 0;
    uint32_t field;
    uint8_t* in;
    uint8_t* out;
    uint8_t* keyOne;
    uint8_t* keyTwo;
    uint8_t* keyThree;
    uint8_t* messageThreeDigest;
    /* TODO we might be able to use the unused part of the packet here to save space since SHE keys are always only 16 bytes */
    uint8_t kdfInput[WOLFHSM_SHE_KEY_SZ * 2];
    uint8_t messageZero[WOLFHSM_SHE_KEY_SZ];
    uint8_t tmpKey[WOLFHSM_SHE_KEY_SZ];
    uint8_t cmacOutput[AES_BLOCK_SIZE];
    union {
        Aes aes[1];
    } crypto;

    switch (packet->subType)
    {
    case WOLFHSM_SHE_SECURE_BOOT_INIT:
        /* if we aren't looking for init return error */
        if (hsmSheSbState != WOLFHSM_SHE_SB_INIT)
            ret = BAD_FUNC_ARG;
        if (ret == 0) {
            /* set the expected size */
            hsmSheBlSize = packet->sheSecureBootInitReq.sz;
            /* check if the boot mac key is empty */
            meta->id =WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_BOOT_MAC_KEY_ID);
            meta->len = sizeof(kdfInput);
            ret = hsmReadKey(ctx, meta, kdfInput);
            /* if the key wasn't found */
            if (ret != 0) {
                /* return ERC_NO_SECURE_BOOT */
                ret = WOLFHSM_SHE_ERC_NO_SECURE_BOOT;
                /* skip SB process since we have no key */
                hsmSheSbState = WOLFHSM_SHE_SB_SUCCESS;
                hsmSheCmacKeyFound = 0;
            }
            else
                hsmSheCmacKeyFound = 1;
        }
        /* init the cmac, use const length since the nvm key holds both key and
         * expected digest so meta->len will be too long */
        if (ret == 0) {
            ret = wc_InitCmac_ex(sheCmac, kdfInput, WOLFHSM_SHE_KEY_SZ,
                WC_CMAC_AES, NULL, ctx->heap, ctx->devId);
        }
        /* hash 12 zeros */
        if (ret == 0) {
            XMEMSET(kdfInput, 0, WOLFHSM_SHE_BOOT_MAC_PREFIX_LEN);
            ret = wc_CmacUpdate(sheCmac, kdfInput,
                WOLFHSM_SHE_BOOT_MAC_PREFIX_LEN);
        }
        /* TODO is size big or little endian? spec says it is 32 bit */
        /* hash size */
        if (ret == 0) {
            ret = wc_CmacUpdate(sheCmac, (uint8_t*)&hsmSheBlSize,
                sizeof(hsmSheBlSize));
        }
        if (ret == 0) {
            /* advance to the next state */
            hsmSheSbState = WOLFHSM_SHE_SB_UPDATE;
            /* set subType */
            packet->subType = WOLFHSM_SHE_SECURE_BOOT_INIT;
            /* set len */
            packet->len = sizeof(packet->sheSecureBootInitRes);
            /* set ERC_NO_ERROR */
            packet->sheSecureBootInitRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    case WOLFHSM_SHE_SECURE_BOOT_UPDATE:
        /* if we aren't looking for update return error */
        if (hsmSheSbState != WOLFHSM_SHE_SB_UPDATE)
            ret = BAD_FUNC_ARG;
        if (ret == 0) {
            /* the bootloader chunk is after the fixed fields */
            in = (uint8_t*)(&packet->sheSecureBootUpdateReq + 1);
            /* increment hsmSheBlSizeReceived */
            hsmSheBlSizeReceived += packet->sheSecureBootUpdateReq.sz;
            /* check that we didn't exceed the expected bootloader size */
            if (hsmSheBlSizeReceived > hsmSheBlSize) {
                ret = BUFFER_E;
            }
        }
        /* update with the new input */
        if (ret == 0) {
            ret = wc_CmacUpdate(sheCmac, in,
                packet->sheSecureBootUpdateReq.sz);
        }
        if (ret == 0) {
            /* advance to the next state if we've cmaced the entire image */
            if (hsmSheBlSizeReceived == hsmSheBlSize)
                hsmSheSbState = WOLFHSM_SHE_SB_FINISH;
            /* set subType */
            packet->subType = WOLFHSM_SHE_SECURE_BOOT_UPDATE;
            /* set len */
            packet->len = sizeof(packet->sheSecureBootUpdateRes);
            /* set ERC_NO_ERROR */
            packet->sheSecureBootUpdateRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    case WOLFHSM_SHE_SECURE_BOOT_FINISH:
        /* if we aren't looking for finish return error */
        if (hsmSheSbState != WOLFHSM_SHE_SB_FINISH)
            ret = BAD_FUNC_ARG;
        /* call final */
        if (ret == 0) {
            field = AES_BLOCK_SIZE;
            ret = wc_CmacFinal(sheCmac, tmpKey, &field);
        }
        /* load the cmac to check */
        if (ret == 0) {
            meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_BOOT_MAC_KEY_ID);
            meta->len = sizeof(kdfInput);
            ret = hsmReadKey(ctx, meta, kdfInput);
        }
        if (ret == 0) {
            /* compare and set either success or failure */
            ret = XMEMCMP(tmpKey, kdfInput + WOLFHSM_SHE_KEY_SZ, field);
            if (ret == 0) {
                hsmSheSbState = WOLFHSM_SHE_SB_SUCCESS;
            }
            else {
                hsmSheSbState = WOLFHSM_SHE_SB_FAILURE;
            }
            /* set subType */
            packet->subType = WOLFHSM_SHE_SECURE_BOOT_FINISH;
            /* set len */
            packet->len = sizeof(packet->sheSecureBootFinishRes);
            /* set ERC_NO_ERROR */
            packet->sheSecureBootFinishRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    case WOLFHSM_SHE_GET_STATUS:
        /* TODO do we care about all the sreg fields? */
        packet->sheGetStatusRes.sreg = 0;
        /* SECURE_BOOT */
        if (hsmSheCmacKeyFound)
            packet->sheGetStatusRes.sreg |= WOLFHSM_SHE_SREG_SECURE_BOOT;
        /* BOOT_FINISHED */
        if (hsmSheSbState == WOLFHSM_SHE_SB_SUCCESS ||
            hsmSheSbState == WOLFHSM_SHE_SB_FAILURE) {
            packet->sheGetStatusRes.sreg |= WOLFHSM_SHE_SREG_BOOT_FINISHED;
        }
        /* BOOT_OK */
        if (hsmSheSbState == WOLFHSM_SHE_SB_SUCCESS)
            packet->sheGetStatusRes.sreg |= WOLFHSM_SHE_SREG_BOOT_OK;
        /* RND_INIT */
        if (hsmSheInitRng)
            packet->sheGetStatusRes.sreg |= WOLFHSM_SHE_SREG_RND_INIT;
        /* set subType */
        packet->subType = WOLFHSM_SHE_GET_STATUS;
        /* set len */
        packet->len = sizeof(packet->sheGetStatusRes);
        break;
    case WOLFHSM_SHE_LOAD_KEY:
        /* read the auth key by AuthID */
        meta->id = hsmShePopAuthId(packet->sheLoadKeyReq.messageOne);
        meta->len = sizeof(kdfInput);
        ret = hsmReadKey(ctx, meta, kdfInput);
        /* make K2 using AES-MP(authKey | WOLFHSM_SHE_KEY_UPDATE_MAC_C) */
        if (ret == 0) {
            /* add WOLFHSM_SHE_KEY_UPDATE_MAC_C to the input */
            XMEMCPY(kdfInput + meta->len, WOLFHSM_SHE_KEY_UPDATE_MAC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C));
            /* setup M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* do kdf */
            ret = wh_AesMp16(ctx, kdfInput,
                meta->len + sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C), messageZero,
                tmpKey);
        }
        /* cmac messageOne and messageTwo using K2 as the cmac key */
        if (ret == 0) {
            ret = wc_InitCmac_ex(sheCmac, tmpKey, WOLFHSM_SHE_KEY_SZ,
                WC_CMAC_AES, NULL, ctx->heap, ctx->devId);
        }
        /* hash M1 | M2 in one call */
        if (ret == 0) {
            ret = wc_CmacUpdate(sheCmac, (uint8_t*)&packet->sheLoadKeyReq,
                sizeof(packet->sheLoadKeyReq.messageOne) +
                sizeof(packet->sheLoadKeyReq.messageTwo));
        }
        /* get the digest */
        if (ret == 0) {
            field = AES_BLOCK_SIZE;
            ret = wc_CmacFinal(sheCmac, cmacOutput, &field);
        }
        /* compare digest to M3 */
        if (ret == 0 && XMEMCMP(packet->sheLoadKeyReq.messageThree,
            cmacOutput, field) != 0) {
            ret = WOLFHSM_SHE_ERC_KEY_UPDATE_ERROR;
        }
        /* make K1 using AES-MP(authKey | WOLFHSM_SHE_KEY_UPDATE_ENC_C) */
        if (ret == 0) {
            /* add WOLFHSM_SHE_KEY_UPDATE_ENC_C to the input */
            XMEMCPY(kdfInput + meta->len, WOLFHSM_SHE_KEY_UPDATE_ENC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* do kdf */
            ret = wh_AesMp16(ctx, kdfInput,
                meta->len + sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C), messageZero,
                tmpKey);
        }
        /* decrypt messageTwo */
        if (ret == 0)
            ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
        if (ret == 0) {
            ret = wc_AesSetKey(crypto.aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
                AES_DECRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesCbcDecrypt(crypto.aes, packet->sheLoadKeyReq.messageTwo,
                packet->sheLoadKeyReq.messageTwo,
                sizeof(packet->sheLoadKeyReq.messageTwo));
        }
        /* free aes for protection */
        wc_AesFree(crypto.aes);
        /* load the target key */
        if (ret == 0) {
            meta->id = hsmShePopId(packet->sheLoadKeyReq.messageOne);
            meta->len = sizeof(kdfInput);
            ret = hsmReadKey(ctx, meta, kdfInput);
            /* if the keyslot is empty or write protection is not on continue */
            if (ret == BAD_FUNC_ARG ||
                (meta->flags & WOLFHSM_SHE_FLAG_WRITE_PROTECT) == 0) {
                ret = 0;
            }
            else
                ret = WOLFHSM_SHE_ERC_WRITE_PROTECTED;
        }
        /* check UID == 0 */
        if (ret == 0 && XMEMEQZERO(packet->sheLoadKeyReq.messageOne,
            WOLFHSM_SHE_UID_SZ) == 1) {
            /* check wildcard */
            if ((meta->flags & WOLFHSM_SHE_FLAG_WILDCARD) == 0)
                ret = WOLFHSM_SHE_ERC_KEY_UPDATE_ERROR;
        }
        /* compare to UID */
        else if (ret == 0 && XMEMCMP(packet->sheLoadKeyReq.messageOne,
            WOLFHSM_SHE_UID, WOLFHSM_SHE_UID_SZ) != 0) {
            ret = WOLFHSM_SHE_ERC_KEY_UPDATE_ERROR;
        }
        /* verify counter is greater than stored value */
        if (ret == 0 &&
            ntohl(*((uint32_t*)packet->sheLoadKeyReq.messageTwo) >> 4) <=
            ntohl(meta->count)) {
            ret = WOLFHSM_SHE_ERC_KEY_UPDATE_ERROR;
        }
        /* write key with counter */
        if (ret == 0) {
            meta->id = hsmShePopId(packet->sheLoadKeyReq.messageOne);
            meta->flags = hsmShePopFlags(packet->sheLoadKeyReq.messageTwo);
            meta->count = (*(uint32_t*)packet->sheLoadKeyReq.messageTwo >> 4);
            meta->len = WOLFHSM_SHE_KEY_SZ;
            /* cache if ram key, overwrite otherwise */
            if (meta->id ==
                WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_RAM_KEY_ID)) {
                hsmEvictKey(ctx, meta->id);
                ret = hsmCacheKey(ctx, meta, packet->sheLoadKeyReq.messageTwo
                    + WOLFHSM_SHE_KEY_SZ);
            }
            else {
                ret = hsmSheOverwriteKey(ctx, meta,
                    packet->sheLoadKeyReq.messageTwo + WOLFHSM_SHE_KEY_SZ);
                /* evict the key from cache so we can read it from nvm */
                if (ret == 0)
                    ret = hsmEvictKey(ctx, meta->id);
                /* read the evicted key back from nvm */
                if (ret == 0) {
                    ret = hsmReadKey(ctx, meta, packet->sheLoadKeyReq.messageTwo
                        + WOLFHSM_SHE_KEY_SZ);
                }
            }
        }
        /* generate K3 using the updated key */
        if (ret == 0) {
            /* copy new key to kdfInput */
            XMEMCPY(kdfInput, packet->sheLoadKeyReq.messageTwo +
                WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_SZ);
            /* add WOLFHSM_SHE_KEY_UPDATE_ENC_C to the input */
            XMEMCPY(kdfInput + meta->len, WOLFHSM_SHE_KEY_UPDATE_ENC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* do kdf */
            ret = wh_AesMp16(ctx, kdfInput,
                meta->len + sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C), messageZero,
                tmpKey);
        }
        if (ret == 0)
            ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
        if (ret == 0) {
            ret = wc_AesSetKey(crypto.aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
                AES_ENCRYPTION);
        }
        if (ret == 0) {
            /* reset messageTwo with the nvm read counter, pad with a 1 bit */
            *(uint32_t*)packet->sheLoadKeyReq.messageTwo = (meta->count << 4);
            packet->sheLoadKeyReq.messageTwo[3] |= 0x08;
            /* encrypt the new counter */
            ret = wc_AesEncryptDirect(crypto.aes,
                packet->sheLoadKeyRes.messageFour + WOLFHSM_SHE_KEY_SZ,
                packet->sheLoadKeyReq.messageTwo);
        }
        /* free aes for protection */
        wc_AesFree(crypto.aes);
        /* generate K4 using the updated key */
        if (ret == 0) {
            /* set our UID, ID and AUTHID are already set from messageOne */
            XMEMCPY(packet->sheLoadKeyRes.messageFour, WOLFHSM_SHE_UID,
                WOLFHSM_SHE_UID_SZ);
            /* add WOLFHSM_SHE_KEY_UPDATE_MAC_C to the input */
            XMEMCPY(kdfInput + meta->len, WOLFHSM_SHE_KEY_UPDATE_MAC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* do kdf */
            ret = wh_AesMp16(ctx, kdfInput,
                meta->len + sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C), messageZero,
                tmpKey);
        }
        /* cmac messageFour using K4 as the cmac key */
        if (ret == 0) {
            ret = wc_InitCmac_ex(sheCmac, tmpKey, WOLFHSM_SHE_KEY_SZ,
                WC_CMAC_AES, NULL, ctx->heap, ctx->devId);
        }
        /* hash M4, store in M5 */
        if (ret == 0) {
            ret = wc_CmacUpdate(sheCmac, packet->sheLoadKeyRes.messageFour,
                sizeof(packet->sheLoadKeyRes.messageFour));
        }
        /* write M5 */
        if (ret == 0) {
            field = AES_BLOCK_SIZE;
            ret = wc_CmacFinal(sheCmac, packet->sheLoadKeyRes.messageFive,
                &field);
        }
        if (ret == 0) {
            /* set subType */
            packet->subType = WOLFHSM_SHE_LOAD_KEY;
            /* set len */
            packet->len = sizeof(packet->sheLoadKeyRes);
            /* set ERC_NO_ERROR */
            packet->sheSecureBootFinishRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    case WOLFHSM_SHE_EXPORT_RAM_KEY:
        /* check if ram key was loaded by CMD_LOAD_PLAIN_KEY */
        if (hsmSheRamKeyPlain == 0)
            return WOLFHSM_SHE_ERC_KEY_INVALID;
        /* read the auth key by AuthID */
        meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_SECRET_KEY_ID);
        meta->len = WOLFHSM_SHE_KEY_SZ;
        ret = hsmReadKey(ctx, meta, kdfInput);
        if (ret == 0) {
            /* set UID, key id and authId */
            XMEMCPY(packet->sheExportRamKeyRes.messageOne, WOLFHSM_SHE_UID,
                WOLFHSM_SHE_UID_SZ);
            packet->sheExportRamKeyRes.messageOne[15] =
                ((WOLFHSM_SHE_RAM_KEY_ID << 4) | (WOLFHSM_SHE_SECRET_KEY_ID));
            /* add WOLFHSM_SHE_KEY_UPDATE_ENC_C to the input */
            XMEMCPY(kdfInput + meta->len, WOLFHSM_SHE_KEY_UPDATE_ENC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* generate K1 */
            ret = wh_AesMp16(ctx, kdfInput,
                meta->len + sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C), messageZero,
                tmpKey);
        }
        /* build cleartext M2 */
        if (ret == 0) {
            /* set the counter, flags and ram key */
            XMEMSET(packet->sheExportRamKeyRes.messageTwo, 0,
                sizeof(packet->sheExportRamKeyRes.messageTwo));
            /* set count to 1 */
            *((uint32_t*)packet->sheExportRamKeyRes.messageTwo) = (htonl(1) << 4);
            meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_RAM_KEY_ID);
            meta->len = WOLFHSM_SHE_KEY_SZ;
            ret = hsmReadKey(ctx, meta,
                packet->sheExportRamKeyRes.messageTwo + WOLFHSM_SHE_KEY_SZ);
        }
        /* encrypt M2 with K1 */
        if (ret == 0)
            ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
        if (ret == 0) {
            ret = wc_AesSetKey(crypto.aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
                AES_ENCRYPTION);
        }
        if (ret == 0) {
            /* copy the ram key to cmacOutput before it gets encrypted */
            XMEMCPY(cmacOutput,
                packet->sheExportRamKeyRes.messageTwo + WOLFHSM_SHE_KEY_SZ,
                WOLFHSM_SHE_KEY_SZ);
            ret = wc_AesCbcEncrypt(crypto.aes,
                packet->sheExportRamKeyRes.messageTwo,
                packet->sheExportRamKeyRes.messageTwo,
                sizeof(packet->sheExportRamKeyRes.messageTwo));
        }
        /* free aes for protection */
        wc_AesFree(crypto.aes);
        if (ret == 0) {
            /* add WOLFHSM_SHE_KEY_UPDATE_MAC_C to the input */
            XMEMCPY(kdfInput + meta->len, WOLFHSM_SHE_KEY_UPDATE_MAC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* generate K2 */
            ret = wh_AesMp16(ctx, kdfInput,
                meta->len + sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C), messageZero,
                tmpKey);
        }
        if (ret == 0) {
            /* cmac messageOne and messageTwo using K2 as the cmac key */
            ret = wc_InitCmac_ex(sheCmac, tmpKey, WOLFHSM_SHE_KEY_SZ,
                WC_CMAC_AES, NULL, ctx->heap, ctx->devId);
        }
        /* hash M1 | M2 in one call */
        if (ret == 0) {
            ret = wc_CmacUpdate(sheCmac,
                (uint8_t*)&packet->sheExportRamKeyRes,
                sizeof(packet->sheExportRamKeyRes.messageOne) +
                sizeof(packet->sheExportRamKeyRes.messageTwo));
        }
        /* get the digest */
        if (ret == 0) {
            field = AES_BLOCK_SIZE;
            ret = wc_CmacFinal(sheCmac,
                packet->sheExportRamKeyRes.messageThree, &field);
        }
        if (ret == 0) {
            /* copy the ram key to kdfInput */
            XMEMCPY(kdfInput, cmacOutput, WOLFHSM_SHE_KEY_SZ);
            /* add WOLFHSM_SHE_KEY_UPDATE_ENC_C to the input */
            XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_UPDATE_ENC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* generate K3 */
            ret = wh_AesMp16(ctx, kdfInput,
                WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_KEY_UPDATE_ENC_C),
                messageZero, tmpKey);
        }
        /* set K3 as encryption key */
        if (ret == 0)
            ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
        if (ret == 0) {
            ret = wc_AesSetKey(crypto.aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
                AES_ENCRYPTION);
        }
        if (ret == 0) {
            XMEMSET(packet->sheExportRamKeyRes.messageFour, 0,
                sizeof(packet->sheExportRamKeyRes.messageFour));
            /* set counter to 1, pad with 1 bit */
            *((uint32_t*)(packet->sheExportRamKeyRes.messageFour +
                WOLFHSM_SHE_KEY_SZ)) = (htonl(1) << 4);
            packet->sheExportRamKeyRes.messageFour[WOLFHSM_SHE_KEY_SZ + 3] |=
                0x08;
            /* encrypt the new counter */
            ret = wc_AesEncryptDirect(crypto.aes,
                packet->sheExportRamKeyRes.messageFour + WOLFHSM_SHE_KEY_SZ,
                packet->sheExportRamKeyRes.messageFour + WOLFHSM_SHE_KEY_SZ);
        }
        /* free aes for protection */
        wc_AesFree(crypto.aes);
        if (ret == 0) {
            /* set UID, key id and authId */
            XMEMCPY(packet->sheExportRamKeyRes.messageFour, WOLFHSM_SHE_UID,
                WOLFHSM_SHE_UID_SZ);
            packet->sheExportRamKeyRes.messageFour[15] =
                ((WOLFHSM_SHE_RAM_KEY_ID << 4) | (WOLFHSM_SHE_SECRET_KEY_ID));
            /* add WOLFHSM_SHE_KEY_UPDATE_MAC_C to the input */
            XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_KEY_UPDATE_MAC_C,
                sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* generate K4 */
            ret = wh_AesMp16(ctx, kdfInput,
                WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_KEY_UPDATE_MAC_C),
                messageZero, tmpKey);
        }
        /* cmac messageFour using K4 as the cmac key */
        if (ret == 0) {
            ret = wc_InitCmac_ex(sheCmac, tmpKey, WOLFHSM_SHE_KEY_SZ,
                WC_CMAC_AES, NULL, ctx->heap, ctx->devId);
        }
        /* hash M4, store in M5 */
        if (ret == 0) {
            ret = wc_CmacUpdate(sheCmac,
                packet->sheExportRamKeyRes.messageFour,
                sizeof(packet->sheExportRamKeyRes.messageFour));
        }
        /* write M5 */
        if (ret == 0) {
            field = AES_BLOCK_SIZE;
            ret = wc_CmacFinal(sheCmac,
                packet->sheExportRamKeyRes.messageFive, &field);
        }
        if (ret == 0) {
            /* set subType */
            packet->subType = WOLFHSM_SHE_EXPORT_RAM_KEY;
            /* set len */
            packet->len = sizeof(packet->sheExportRamKeyRes);
            /* set ERC_NO_ERROR */
            packet->sheSecureBootFinishRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    case WOLFHSM_SHE_INIT_RNG:
        /* check that init hasn't already been called since startup */
        if (hsmSheInitRng == 1)
            return WOLFHSM_SHE_ERC_SEQUENCE_ERROR;
        /* read secret key */
        meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_SECRET_KEY_ID);
        meta->len = WOLFHSM_SHE_KEY_SZ;
        ret = hsmReadKey(ctx, meta, kdfInput);
        if (ret == 0) {
            /* add PRNG_SEED_KEY_C */
            XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_PRNG_SEED_KEY_C,
                sizeof(WOLFHSM_SHE_PRNG_SEED_KEY_C));
            /* set M0 to all zeros */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* generate PRNG_SEED_KEY */
            ret = wh_AesMp16(ctx, kdfInput,
                WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_PRNG_SEED_KEY_C),
                messageZero, tmpKey);
        }
        /* read the current PRNG_SEED, i - 1, to cmacOutput */
        if (ret == 0) {
            meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_PRNG_SEED_ID);
            meta->len = WOLFHSM_SHE_KEY_SZ;
            ret = hsmReadKey(ctx, meta, cmacOutput);
        }
        /* set up aes */
        if (ret == 0)
            ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
        if (ret == 0) {
            ret = wc_AesSetKey(crypto.aes, tmpKey, WOLFHSM_SHE_KEY_SZ, NULL,
                AES_ENCRYPTION);
        }
        /* encrypt to the PRNG_SEED, i */
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(crypto.aes, cmacOutput, cmacOutput,
                WOLFHSM_SHE_KEY_SZ);
        }
        /* free aes for protection */
        wc_AesFree(crypto.aes);
        /* save PRNG_SEED, i */
        if (ret == 0) {
            meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_PRNG_SEED_ID);
            meta->len = WOLFHSM_SHE_KEY_SZ;
            ret = hsmSheOverwriteKey(ctx, meta, cmacOutput);
        }
        if (ret == 0) {
            /* set PRNG_STATE */
            XMEMCPY(hsmShePrngState, cmacOutput, WOLFHSM_SHE_KEY_SZ);
            /* add PRNG_KEY_C to the kdf input */
            XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ, WOLFHSM_SHE_PRNG_KEY_C,
                sizeof(WOLFHSM_SHE_PRNG_KEY_C));
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* generate PRNG_KEY */
            ret = wh_AesMp16(ctx, kdfInput,
                WOLFHSM_SHE_KEY_SZ + sizeof(WOLFHSM_SHE_PRNG_KEY_C),
                messageZero, WOLFHSM_SHE_PRNG_KEY);
        }
        if (ret == 0) {
            /* set init rng to 1 */
            hsmSheInitRng = 1;
            /* set subType */
            packet->subType = WOLFHSM_SHE_INIT_RNG;
            /* set len */
            packet->len = sizeof(packet->sheInitRngRes);
            /* set ERC_NO_ERROR */
            packet->sheInitRngRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    case WOLFHSM_SHE_RND:
        /* check that rng has been inited */
        if (hsmSheInitRng == 0)
            return WOLFHSM_SHE_ERC_RNG_SEED;
        /* set up aes */
        if (ret == 0)
            ret = wc_AesInit(crypto.aes, ctx->heap, ctx->devId);
        /* use PRNG_KEY as the encryption key */
        if (ret == 0) {
            ret = wc_AesSetKey(crypto.aes, WOLFHSM_SHE_PRNG_KEY, WOLFHSM_SHE_KEY_SZ,
                NULL, AES_ENCRYPTION);
        }
        /* encrypt the PRNG_STATE, i - 1 to i */
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(crypto.aes, hsmShePrngState, hsmShePrngState,
                WOLFHSM_SHE_KEY_SZ);
        }
        /* free aes for protection */
        wc_AesFree(crypto.aes);
        if (ret == 0) {
            /* set subType */
            packet->subType = WOLFHSM_SHE_RND;
            /* set len */
            packet->len = sizeof(packet->sheRndRes);
            /* copy PRNG_STATE */
            XMEMCPY(packet->sheRndRes.rnd, hsmShePrngState, WOLFHSM_SHE_KEY_SZ);
        }
        break;
    case WOLFHSM_SHE_EXTEND_SEED:
        /* check that rng has been inited */
        if (hsmSheInitRng == 0)
            return WOLFHSM_SHE_ERC_RNG_SEED;
        if (ret == 0) {
            /* set kdfInput to PRNG_STATE */
            XMEMCPY(kdfInput, hsmShePrngState, WOLFHSM_SHE_KEY_SZ);
            /* add the user supplied entropy to kdfInput */
            XMEMCPY(kdfInput + WOLFHSM_SHE_KEY_SZ,
                packet->sheExtendSeedReq.entropy,
                sizeof(packet->sheExtendSeedReq.entropy));
            /* set M0 to all zeros */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* extend PRNG_STATE */
            ret = wh_AesMp16(ctx, kdfInput,
                WOLFHSM_SHE_KEY_SZ + sizeof(packet->sheExtendSeedReq.entropy),
                messageZero, hsmShePrngState);
        }
        /* read the PRNG_SEED into kdfInput */
        if (ret == 0) {
            meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_PRNG_SEED_ID);
            meta->len = WOLFHSM_SHE_KEY_SZ;
            ret = hsmReadKey(ctx, meta, kdfInput);
        }
        if (ret == 0) {
            /* reset M0 */
            XMEMSET(messageZero, 0, AES_BLOCK_SIZE);
            /* extend PRNG_STATE */
            ret = wh_AesMp16(ctx, kdfInput,
                WOLFHSM_SHE_KEY_SZ + sizeof(packet->sheExtendSeedReq.entropy),
                messageZero, kdfInput);
        }
        /* save PRNG_SEED */
        if (ret == 0) {
            meta->id = WOLFHSM_SHE_TRANSLATE_KEY_ID(WOLFHSM_SHE_PRNG_SEED_ID);
            meta->len = WOLFHSM_SHE_KEY_SZ;
            ret = hsmSheOverwriteKey(ctx, meta, kdfInput);
        }
        if (ret == 0) {
            /* set subType */
            packet->subType = WOLFHSM_SHE_RND;
            /* set len */
            packet->len = sizeof(packet->sheExtendSeedRes);
            /* set ERC_NO_ERROR */
            packet->sheExtendSeedRes.status = WOLFHSM_SHE_ERC_NO_ERROR;
        }
        break;
    default:
        ret = BAD_FUNC_ARG;
        break;
    }
    /* set type here in case packet was overwritten */
    packet->type = WOLFHSM_SHE;
    /* reset our SHE state */
    /* TODO is it safe to call wc_InitCmac over and over or do we need to call final first? */
    if (ret != 0 && ret != WOLFHSM_SHE_ERC_NO_SECURE_BOOT) {
        hsmSheSbState = WOLFHSM_SHE_SB_INIT;
        hsmSheBlSize = 0;
        hsmSheBlSizeReceived = 0;
        hsmSheCmacKeyFound = 0;
    }
    return ret;
}
#endif /* WOLFHSM_SHE_EXTENSION */

static int _wh_Server_HandlePkcs11Request(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    /* TODO: Add PKCS11 message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

#ifdef WOLFHSM_SHE_EXTENSION
static int _wh_Server_HandleSheRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    /* TODO: Add AUTOSAR SHE message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}
#endif

static int _wh_Server_HandleCustomRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    int rc = 0;
    switch (action) {
    /* TODO: Add custom/user callback message handling here */
    default:
        /* Unknown request. Respond with empty packet */
        *out_resp_size = 0;
    }
    return rc;
}

int wh_Server_HandleRequestMessage(whServerContext* server)
{
    uint16_t magic = 0;
    uint16_t kind = 0;
    uint16_t group = 0;
    uint16_t action = 0;
    uint16_t seq = 0;
    uint16_t size = 0;
    uint8_t data[WH_COMM_MTU] = {0};

    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }
    int rc = wh_CommServer_RecvRequest(server->comm, &magic, &kind, &seq,
            &size, data);
    /* Got a packet? */
    if (rc == 0) {
        group = WH_MESSAGE_GROUP(kind);
        action = WH_MESSAGE_ACTION(kind);
        switch (group) {
        case WH_MESSAGE_GROUP_COMM: {
            rc = _wh_Server_HandleCommRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        case WH_MESSAGE_GROUP_NVM: {
            rc = _wh_Server_HandleNvmRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        case WH_MESSAGE_GROUP_KEY: {
            rc = _wh_Server_HandleKeyRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        case WH_MESSAGE_GROUP_CRYPTO: {
            rc = _wh_Server_HandleCryptoRequest(server, action, data, &size);
        }; break;
        case WH_MESSAGE_GROUP_PKCS11: {
            rc = _wh_Server_HandlePkcs11Request(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
#ifdef WOLFHSM_SHE_EXTENSION
        case WOLFHSM_MESSAGE_GROUP_SHE: {
            rc = _wh_Server_HandleSheRequest(data, size);
        }; break;
#endif
        case WH_MESSAGE_GROUP_CUSTOM: {
            rc = _wh_Server_HandleCustomRequest(server, magic, action, seq,
                    size, data, &size, data);
        }; break;
        default:
            /* Unknown group. Return empty packet*/
            /* TODO: Respond with aux error flag */
            size = 0;
        }
    }
    /* Send a response */
    /* TODO: Response with ErrorResponse if handler returns an error */
    if (rc == 0) {
        do {
            rc = wh_CommServer_SendResponse(server->comm, magic, kind, seq,
                size, data);
        } while (rc == WH_ERROR_NOTREADY);
    }
    return rc;
}

int wh_Server_Cleanup(whServerContext* server)
{
    if (server ==NULL) {
         return WH_ERROR_BADARGS;
     }
#if 0
     if (server->nvm != NULL) {
         /*(void)wh_Nvm_Cleanup(server->nvm);*/
     }
#endif
    (void)wh_CommServer_Cleanup(server->comm);
    (void)wolfCrypt_Cleanup();
    memset(server, 0, sizeof(*server));
    return 0;
}

#if 0
/** Non-volatile counters */

int whClient_CounterSet(whCounterId counterId, uint32_t value)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_CounterGet(whCounterId counterId, uint32_t* outValue)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_CounterErase(whCounterId counterId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}


/** Key Management */
int whClient_ImportKey(whKeyId keyId, const uint8_t* inKey, uint16_t inSize)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_EraseKey(whKeyId keyId)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_ExportKey(whKeyId keyId, uint8_t* outKey, uint16_t* inoutSize)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_SetKeyRsa(RsaKey* key, whKeyId keyId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetKeyAes(Aes* aes, whKeyId keyId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetKeyHmac(Hmac* hmac, whKeyId keyId)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}


/** NVM Management */

int whClient_NvmList(uint16_t access, uint16_t flags,
    whNvmId start_id, uint16_t* out_count, whNvmId* out_id)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_NvmAvailable(uint16_t* out_size, uint16_t* out_objects)
{
    /* WC_HW_E */
    return 0;
}

int whClient_NvmReclaimable(uint16_t* out_size, uint16_t* out_objects)
{
    /* WC_HW_E */
    return 0;
}

int whClient_NvmGetMetadata(whNvmId id, whNvmMetadata* object)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_NvmAddObject(whNvmMetadata *meta, uint16_t data_len,
        const uint8_t* data)
{
    /* BAD_FUNC_ARGS, MEMORY_E, WC_HW_E */
    return 0;
}

int whClient_NvmDestroyObjects(uint16_t list_count, const whNvmId* id_list)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_NvmRead(whNvmId id, uint16_t offset, uint16_t data_len,
        uint8_t* data)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}


/** Additional HSM Features */

int whClient_SetNvmWriteLock(uint32_t code, int state)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_GetNvmWriteLock(int* outState)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetDebugLock(uint32_t code, int state)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_GetDebugLock(int* outState)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_GetBootImageVerification(uint16_t* inoutLen, uint8_t* outResult)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetBootLoaderDone(uint32_t code)
{
    /* WC_HW_E */
    return 0;
}

int whClient_GetBootLoaderDone(uint32_t* outCode)
{
    /* WC_HW_E */
    return 0;
}

int whClient_SetSheUid(uint16_t len, const uint8_t* uid)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_SetPause(uint32_t code, int state)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}

int whClient_CompareManifest(const uint8_t* address, int* outResult)
{
    /* BAD_FUNC_ARGS, WC_HW_E */
    return 0;
}
#endif

