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
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#endif

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT

#ifndef WOLFHSM_CFG_NO_CRYPTO

#ifdef HAVE_AESGCM

#define WH_TEST_AES_KEYSIZE 16
#define WH_TEST_AES_TEXTSIZE 16
#define WH_TEST_AES_AUTHSIZE 16
#define WH_TEST_AES_TAGSIZE 16
#define WH_TEST_AES_WRAPPED_KEYSIZE                                     \
    (WH_TEST_AES_AUTHSIZE + WH_TEST_AES_TAGSIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))

static int whTest_Client_AesGcmKeyWrap(whClientContext* ctx, WC_RNG* rng)
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
    whNvmMetadata metadata = {.id = 8,
                              .label = "AES Key Label",
                              .len   = WH_TEST_AES_KEYSIZE};
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

    ret = wh_Client_KeyWrap(ctx, WC_CIPHER_AES_GCM, serverKeyId, plainKey, sizeof(plainKey),
                            &metadata, wrappedKey, sizeof(wrappedKey));
    if (ret != 0) {
        printf("Failed to wh_Client_AesGcmKeyWrap %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndCache(ctx, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
                                   sizeof(wrappedKey), &wrappedKeyId);
    if (ret != 0) {
        printf("Failed to wh_Client_AesGcmKeyWrapCache %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndExport(ctx, WC_CIPHER_AES_GCM, serverKeyId, wrappedKey,
                                    sizeof(wrappedKey), &tmpMetadata,
                                    tmpPlainKey, sizeof(tmpPlainKey));
    if (ret != 0) {
        printf("Failed to wh_Client_AesGcmKeyUnwrapAndCache %d\n", ret);
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
#ifndef NO_AES

static int whTest_Client_AesKeyWrap(whClientContext* ctx, WC_RNG* rng)
{
    int ret = 0;

#ifdef HAVE_AESGCM
    ret = whTest_Client_AesGcmKeyWrap(ctx, rng);

#endif

    return ret;
}

#endif /* !NO_AES */

static int whTest_Client_KeyWrap(whClientContext* ctx, int devId)
{
    int ret = 0;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifndef NO_AES
    ret = whTest_Client_AesKeyWrap(ctx, rng);
#endif

    (void)wc_FreeRng(rng);
    return ret;
}

int whTest_KeyWrapClientConfig(whClientConfig* config)
{
    int             ret       = 0;
    whClientContext client[1] = {0};

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_Init %d\n", ret);
        (void)wh_Client_Cleanup(client);
        return ret;
    }

    ret = whTest_Client_KeyWrap(client, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to whTest_Client_KeyWrap %d\n", ret);
    }

    /* Clean up used resources */
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
