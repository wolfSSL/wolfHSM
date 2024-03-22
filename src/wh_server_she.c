#if 0

/* System libraries */
#include <stdint.h>
#include <stdlib.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include <arpa/inet.h>


#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_packet.h"

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

int hsmHandleSHE(WOLFHSM_CTX* ctx, wh_Packet* packet,
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
#endif
