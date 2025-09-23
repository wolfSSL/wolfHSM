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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wh_demo_client_keywrap.h"

#ifndef NO_AES
#define HAVE_AESGCM
#ifdef HAVE_AESGCM

#define WH_TEST_AES_KEYSIZE 16
#define WH_TEST_AES_TEXTSIZE 16
#define WH_TEST_AES_IVSIZE 12
#define WH_TEST_AES_TAGSIZE 16
#define WH_TEST_AES_WRAPPED_KEYSIZE                                     \
    (WH_TEST_AES_IVSIZE + WH_TEST_AES_TAGSIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))
#define WH_TEST_WRAPKEY_ID 8

int wh_DemoClient_AesGcmKeyWrapBasic(whClientContext* ctx, WC_RNG* rng)
{
    int           ret = 0;
    uint8_t       kek[WH_TEST_AES_KEYSIZE];
    uint8_t       clientKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpClientKey[WH_TEST_AES_KEYSIZE];
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint8_t       label[WH_NVM_LABEL_LEN] = "Server AES Key Label";
    whKeyId       serverKeyId;
    whKeyId       wrappedKeyId;
    whNvmMetadata metadata = {.id     = WH_TEST_WRAPKEY_ID,
                              .label  = "AES Key Label",
                              .access = WH_NVM_ACCESS_ANY,
                              .len    = WH_TEST_AES_KEYSIZE};
    whNvmMetadata tmpMetadata;

    /* Generate a random KEK to encrypt the client key */
    ret = wc_RNG_GenerateBlock(rng, kek, sizeof(kek));
    if (ret != 0) {
        printf("Failed to wc_RNG_GenerateBlock for key %d\n", ret);
        return ret;
    }

    /* Generate a random client key */
    ret = wc_RNG_GenerateBlock(rng, clientKey, sizeof(clientKey));
    if (ret != 0) {
        printf("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        return ret;
    }

    /* Request the server to cache the KEK and give us back a key ID*/
    ret = wh_Client_KeyCache(ctx, 0, label, sizeof(label), kek, sizeof(kek),
                             &serverKeyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyCache %d\n", ret);
        return ret;
    }

    /* Request the server to wrap the client key using the KEK we just cached */
    ret = wh_Client_KeyWrap(ctx, WC_CIPHER_AES_GCM, serverKeyId, clientKey,
                            sizeof(clientKey), &metadata, wrappedKey,
                            sizeof(wrappedKey));
    if (ret != 0) {
        printf("Failed to wh_Client_KeyWrap %d\n", ret);
        return ret;
    }

    /* Request the server to unwrap and cache the wrapped key we just created */
    ret = wh_Client_KeyUnwrapAndCache(ctx, WC_CIPHER_AES_GCM, serverKeyId,
                                      wrappedKey, sizeof(wrappedKey),
                                      &wrappedKeyId);
    if (ret != 0) {
        printf("Failed to wh_Client_KeyUnwrapAndCache %d\n", ret);
        return ret;
    }

    /* Request the server to unwrap and export the wrapped key we created */
    ret = wh_Client_KeyUnwrapAndExport(
        ctx, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey, sizeof(wrappedKey),
        &tmpMetadata, tmpClientKey, sizeof(tmpClientKey));
    if (ret != 0) {
        printf("Failed to wh_Client_KeyUnwrapAndCache %d\n", ret);
        return ret;
    }


    /* Compare the exported key to the client key we requested to wrap */
    if (memcmp(clientKey, tmpClientKey, sizeof(clientKey)) != 0) {
        printf("AES GCM wrap/unwrap key failed to match\n");
        return ret;
    }

    /* Compare the exported metadata to the metadata we requested to wrap */
    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        printf("AES GCM wrap/unwrap metadata failed to match\n");
        return ret;
    }

    return ret;
}

#endif /* HAVE_AESGCM */

int wh_DemoClient_AesKeyWrapBasic(whClientContext* clientContext, WC_RNG* rng)
{
    int ret = WH_ERROR_OK;

#ifdef HAVE_AESGCM
    ret = wh_DemoClient_AesGcmKeyWrapBasic(clientContext, rng);
#endif

    return ret;
}

#endif /* !NO_AES */
int wh_DemoClient_KeyWrapBasic(whClientContext* clientContext)
{

    int    ret;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        printf("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifndef NO_AES
    ret = wh_DemoClient_AesKeyWrapBasic(clientContext, rng);
#endif

    wc_FreeRng(rng);
    return ret;
}
