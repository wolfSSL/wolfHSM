/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test/wh_test_keywrap_util.c
 *
 * Helpers shared by the keywrap and SHE test suites. See the header.
 */
#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h"

#include "wh_test_keywrap_util.h"

const uint8_t whTest_KeywrapKek[32] = {
    0x03, 0x03, 0x0d, 0xd9, 0xeb, 0x18, 0x17, 0x2e, 0x06, 0x6e, 0x19,
    0xce, 0x98, 0x44, 0x54, 0x0d, 0x78, 0xa0, 0xbe, 0xe7, 0x35, 0x43,
    0x40, 0xa4, 0x22, 0x8a, 0xd1, 0x0e, 0xa3, 0x63, 0x1c, 0x0b};

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && defined(WOLFHSM_CFG_KEYWRAP) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_she_common.h"

#ifdef HAVE_AESGCM

int whTest_BuildSheKeyBlob(const uint8_t* kek, uint32_t kekSz, whKeyId sheKeyId,
                           uint32_t counter, uint32_t sheFlags,
                           const uint8_t* keyBytes, uint8_t* blobOut,
                           uint16_t* blobInOutSz)
{
    int           ret;
    Aes           aes[1];
    whNvmMetadata meta;
    uint8_t       plain[sizeof(whNvmMetadata) + WH_SHE_KEY_SZ];
    uint8_t       iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    uint8_t       tag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint16_t need = (uint16_t)(WH_KEYWRAP_AES_GCM_HEADER_SIZE + sizeof(meta) +
                               WH_SHE_KEY_SZ);

    if (*blobInOutSz < need) {
        return WH_ERROR_BUFFER_SIZE;
    }

    memset(&meta, 0, sizeof(meta));
    meta.id  = sheKeyId;
    meta.len = WH_SHE_KEY_SZ;
    wh_She_Meta2Label(counter, sheFlags, meta.label);

    memcpy(plain, &meta, sizeof(meta));
    memcpy(plain + sizeof(meta), keyBytes, WH_SHE_KEY_SZ);

    memset(iv, 0x24, sizeof(iv)); /* a fixed IV is fine for a test blob */

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_AesGcmSetKey(aes, kek, kekSz);
    if (ret == 0) {
        /* Bind the key-wrap domain tag so the server accepts this blob */
        ret = wc_AesGcmEncrypt(aes, blobOut + WH_KEYWRAP_AES_GCM_HEADER_SIZE,
                               plain, sizeof(plain), iv, sizeof(iv), tag,
                               sizeof(tag), (const byte*)WH_KEYWRAP_AAD_KEY_STR,
                               (word32)WH_KEYWRAP_AAD_KEY_LEN);
    }
    wc_AesFree(aes);
    if (ret != 0) {
        return ret;
    }

    memcpy(blobOut, iv, sizeof(iv));
    memcpy(blobOut + sizeof(iv), tag, sizeof(tag));
    *blobInOutSz = need;
    return 0;
}

#endif /* HAVE_AESGCM */

#endif /* WOLFHSM_CFG_SHE_EXTENSION && WOLFHSM_CFG_KEYWRAP && \
          !WOLFHSM_CFG_NO_CRYPTO */
