/*
 * Copyright (C) 2025 wolfSSL Inc.
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

#include "wolfhsm/wh_settings.h"
#ifdef WOLFHSM_CFG_WRAPKEY
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_wrapkey.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wh_demo_client_wrapkey.h"

#ifndef NO_AES
#define HAVE_AESGCM
#ifdef HAVE_AESGCM

#define WH_TEST_AES_KEYSIZE 16
#define WH_TEST_AES_TEXTSIZE 16
#define WH_TEST_AES_AUTHSIZE 16
#define WH_TEST_AES_TAGSIZE 16
#define WH_TEST_AES_WRAPPED_KEYSIZE                                     \
    (WH_TEST_AES_AUTHSIZE + WH_TEST_AES_TAGSIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))
#define WH_TEST_WRAPKEY_ID 8

int wh_DemoClient_AesGcmWrapKeyBasic(whClientContext* ctx, WC_RNG* rng)
{
    int           ret = 0;
    uint8_t       iv[AES_BLOCK_SIZE];
    uint8_t       key[WH_TEST_AES_KEYSIZE];
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint8_t       label[WH_NVM_LABEL_LEN] = "Server AES Key Label";
    whKeyId       serverKeyId;
    whKeyId       wrappedKeyId;
    whNvmMetadata metadata = {.id = WH_TEST_WRAPKEY_ID,
                              .label  = "AES Key Label",
                              .access = WH_NVM_ACCESS_ANY,
                              .len    = WH_TEST_AES_KEYSIZE};
    whNvmMetadata tmpMetadata;

    /* Randomize inputs */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        printf("Failed to wc_RNG_GenerateBlock for key %d\n", ret);
        return ret;
    }

    ret = wc_RNG_GenerateBlock(rng, plainKey, sizeof(plainKey));
    if (ret != 0) {
        printf("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        return ret;
    }

    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret != 0) {
        printf("Failed to wc_RNG_GenerateBlock for IV %d\n", ret);
        return ret;
    }

    /* Initialize the AES GCM Server key */
    ret = wh_Client_KeyCache(ctx, 0, label, sizeof(label), key, sizeof(key),
                             &serverKeyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        return ret;
    }

    ret = wh_Client_WrapKey(ctx, WC_CIPHER_AES_GCM, serverKeyId, plainKey, sizeof(plainKey),
                            &metadata, wrappedKey, sizeof(wrappedKey));
    if (ret != 0) {
        printf("Failed to wh_Client_WrapKey %d\n", ret);
        return ret;
    }

    ret = wh_Client_UnwrapKeyCache(ctx, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
                                   sizeof(wrappedKey), &wrappedKeyId);
    if (ret != 0) {
        printf("Failed to wh_Client_UnwrapKeyCache %d\n", ret);
        return ret;
    }

    ret = wh_Client_UnwrapKeyExport(ctx, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
                                    sizeof(wrappedKey), &tmpMetadata,
                                    tmpPlainKey, sizeof(tmpPlainKey));
    if (ret != 0) {
        printf("Failed to wh_Client_UnwrapKeyCache %d\n", ret);
        return ret;
    }


    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        printf("AES GCM wrap/unwrap key failed to match\n");
        return ret;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        printf("AES GCM wrap/unwrap metadata failed to match\n");
        return ret;
    }

    return ret;
}

#endif /* HAVE_AESGCM */

int wh_DemoClient_AesWrapKeyBasic(whClientContext* clientContext, WC_RNG* rng)
{
    int ret = WH_ERROR_OK;

#ifdef HAVE_AESGCM
    ret = wh_DemoClient_AesGcmWrapKeyBasic(clientContext, rng);
#endif

    return ret;
}

#endif /* !NO_AES */
int wh_DemoClient_WrapKeyBasic(whClientContext* clientContext)
{

    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifndef NO_AES
    ret = wh_DemoClient_AesWrapKeyBasic(clientContext, rng);
#endif

    wc_FreeRng(rng);
    return ret;
}

#endif /* WOLFHSM_CFG_WRAPKEY */
