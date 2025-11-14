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

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/random.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wh_demo_client_keywrap.h"

#ifdef WOLFHSM_CFG_KEYWRAP

#define WH_DEMO_KEYWRAP_KEKID 1
static int _InitServerKek(whClientContext* ctx)
{
    /* IMPORTANT NOTE: Server KEK is typically intrinsic or set during
     * provisioning. Uploading the KEK via the client is for testing purposes
     * only and not intended as a recommendation */
    whKeyId    serverKeyId             = WH_DEMO_KEYWRAP_KEKID;
    whNvmFlags flags = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_WRAP;
    uint8_t    label[WH_NVM_LABEL_LEN] = "Server KEK key";
    uint8_t    kek[] = {0x03, 0x03, 0x0d, 0xd9, 0xeb, 0x18, 0x17, 0x2e,
                        0x06, 0x6e, 0x19, 0xce, 0x98, 0x44, 0x54, 0x0d,
                        0x78, 0xa0, 0xbe, 0xe7, 0x35, 0x43, 0x40, 0xa4,
                        0x22, 0x8a, 0xd1, 0x0e, 0xa3, 0x63, 0x1c, 0x0b};

    return wh_Client_KeyCache(ctx, flags, label, sizeof(label), kek,
                              sizeof(kek), &serverKeyId);
}

static int _CleanupServerKek(whClientContext* ctx)
{
    return wh_Client_KeyErase(ctx, WH_DEMO_KEYWRAP_KEKID);
}

#ifndef NO_AES
#ifdef HAVE_AESGCM

#define WH_DEMO_KEYWRAP_AES_KEYSIZE 16
#define WH_DEMO_KEYWRAP_AES_TEXTSIZE 16
#define WH_DEMO_KEYWRAP_AES_IVSIZE 12
#define WH_DEMO_KEYWRAP_AES_TAGSIZE 16
#define WH_DEMO_KEYWRAP_AES_WRAPPED_KEYSIZE                     \
    (WH_DEMO_KEYWRAP_AES_IVSIZE + WH_DEMO_KEYWRAP_AES_TAGSIZE + \
     WH_DEMO_KEYWRAP_AES_KEYSIZE + sizeof(whNvmMetadata))
#define WH_DEMO_KEYWRAP_AESGCM_WRAPKEY_ID 8

int wh_DemoClient_AesGcmKeyWrap(whClientContext* client)
{
    int           ret = 0;
    Aes           aes[1];
    WC_RNG        rng[1];
    uint8_t       key[WH_DEMO_KEYWRAP_AES_KEYSIZE];
    uint8_t       exportedKey[WH_DEMO_KEYWRAP_AES_KEYSIZE];
    uint16_t      exportedKeySz = sizeof(exportedKey);
    whNvmMetadata metadata = {
        .id = WH_CLIENT_KEYID_MAKE_WRAPPED_META(
            client->comm->client_id, WH_DEMO_KEYWRAP_AESGCM_WRAPKEY_ID),
        .label  = "AES Key Label",
        .access = WH_NVM_ACCESS_ANY,
        .flags  = WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT,
        .len    = WH_DEMO_KEYWRAP_AES_KEYSIZE};
    whNvmMetadata exportedMetadata;
    uint8_t       wrappedKey[WH_DEMO_KEYWRAP_AES_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    whKeyId       wrappedKeyId;

    const uint8_t plaintext[] = "hello, wolfSSL AES-GCM!";
    uint8_t       ciphertext[sizeof(plaintext)];
    uint8_t       decrypted[sizeof(plaintext)];

    uint8_t       tag[WH_DEMO_KEYWRAP_AES_TAGSIZE];
    uint8_t       iv[WH_DEMO_KEYWRAP_AES_IVSIZE];
    const uint8_t aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                           0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                           0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    /* Initialize the server KEK */

    /* The key wrap feature requires the server to have a Key Encryption Key
     * (I.E. KEK) available for the client to use. In the case of this demo we
     * have the client initializing the KEK which is not recommended. Typically
     * the KEK ID would be a hard coded value that the client and server share
     * and the KEK would be provisioned on the server prior to runtime */
    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

    /* Generating and wrapping a key */

    /* Initialize the RNG so we can generate an AES GCM key to wrap */
    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
        goto cleanup_kek;
    }

    /* Now we generate the AES GCM key using the RNG */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        goto cleanup_rng;
    }

    /* Now we request the server to wrap the key using the KEK we
     * establish above in the first step. */
    ret =
        wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, WH_DEMO_KEYWRAP_KEKID, key,
                          sizeof(key), &metadata, wrappedKey, &wrappedKeySz);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyWrap %d\n", ret);
        goto cleanup_rng;
    }

    /* Now that the key is wrapped you store this in Non-Volatile Memory however
     * you wish */


    /* Using a wrapped key to do crypto operations*/

    /* Request the server to unwrap and cache the wrapped key we just created.
     * This will provide us back a key ID that the client can use to do crypto
     * operations */
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM,
                                      WH_DEMO_KEYWRAP_KEKID, wrappedKey,
                                      sizeof(wrappedKey), &wrappedKeyId);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyUnwrapAndCache %d\n", ret);
        goto cleanup_rng;
    }

    /* Initialize AES context */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesInit %d\n", ret);
        goto cleanup_cached_key;
    }

    /* Set the key id for this AES context to the wrapped key ID that the server
     * provided us */
    ret =
        wh_Client_AesSetKeyId(aes, WH_CLIENT_KEYID_MAKE_WRAPPED(wrappedKeyId));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_AesSetKeyId %d\n", ret);
        goto cleanup_aes;
    }

    /* Generate a random IV for the AES GCM encryption operation we are about to
     * do */
    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_RNG_GenerateBlock for AES-GCM key %d\n", ret);
        goto cleanup_aes;
    }

    /* Request the server to encrypt some data using the
     * unwrapped and cached key via the key ID */
    ret = wc_AesGcmEncrypt(aes, ciphertext, plaintext, sizeof(plaintext), iv,
                           sizeof(iv), tag, sizeof(tag), aad, sizeof(aad));
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wc_AesGcmEncrypt %d\n", ret);
        goto cleanup_aes;
    }

    /* Request the server to decrypt the encrypted data using the
     * unwrapped and cached key via the key ID */
    ret = wc_AesGcmDecrypt(aes, decrypted,                 /* out */
                           ciphertext, sizeof(ciphertext), /* in, inLen */
                           iv, sizeof(iv),                 /* iv, ivLen */
                           tag, sizeof(tag),  /* authTag, authTagSz */
                           aad, sizeof(aad)); /* authIn (AAD), authInSz */
    if (ret != 0) {
        ret = WH_ERROR_ABORTED;
        WOLFHSM_CFG_PRINTF("Failed to wc_AesGcmDecrypt %d\n", ret);
        goto cleanup_aes;
    }

    /* Check if the decrypted data matches an expected value */
    if (memcmp(decrypted, plaintext, sizeof(decrypted)) != 0) {
        ret = WH_ERROR_ABORTED;
        WOLFHSM_CFG_PRINTF("Decrypted value does not match expected value\n");
        goto cleanup_aes;
    }

    /* Exporting a wrapped key */

    /* Request the server to unwrap and export the wrapped key we created */
    ret = wh_Client_KeyUnwrapAndExport(
        client, WC_CIPHER_AES_GCM, WH_DEMO_KEYWRAP_KEKID, wrappedKey,
        sizeof(wrappedKey), &exportedMetadata, exportedKey, &exportedKeySz);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to wh_Client_KeyUnwrapAndCache %d\n", ret);
        goto cleanup_aes;
    }

    /* Compare the exported key to the client key we requested to wrap */
    if (memcmp(key, exportedKey, sizeof(key)) != 0) {
        ret = WH_ERROR_ABORTED;
        WOLFHSM_CFG_PRINTF("AES GCM wrap/unwrap key failed to match\n");
        goto cleanup_aes;
    }

    /* Compare the exported metadata to the metadata we requested to wrap */
    if (memcmp(&metadata, &exportedMetadata, sizeof(metadata)) != 0) {
        ret = WH_ERROR_ABORTED;
        WOLFHSM_CFG_PRINTF("AES GCM wrap/unwrap metadata failed to match\n");
        goto cleanup_aes;
    }

cleanup_aes:
    wc_AesFree(aes);
cleanup_cached_key:
    wh_Client_KeyErase(client, wrappedKeyId);
cleanup_rng:
    wc_FreeRng(rng);
cleanup_kek:
    _CleanupServerKek(client);

    return ret;
}

#endif /* HAVE_AESGCM */


#endif /* !NO_AES */

int wh_DemoClient_KeyWrap(whClientContext* client)
{

    int ret;

#ifndef NO_AES
#ifdef HAVE_AESGCM

    ret = wh_DemoClient_AesGcmKeyWrap(client);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to wh_DemoClient_AesGcmKeyWrap %d\n", ret);
        return ret;
    }

#endif /* !NO_AES */
#endif /* HAVE_AESGCM */

    return ret;
}
#endif /* WOLFHSM_CFG_KEYWRAP */
