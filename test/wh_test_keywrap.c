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
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_flash.h"

#ifdef WOLFHSM_CFG_KEYWRAP

#include "wh_test_common.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

/* Common defines */
#define WH_TEST_KEKID 1

/* AES GCM Specific defines */
#ifdef HAVE_AESGCM

#define WH_TEST_AESGCM_KEY_OFFSET 0x1000
#define WH_TEST_AESGCM_KEYID 2
#define WH_TEST_AES_KEYSIZE 32
#define WH_TEST_AES_TEXTSIZE 16
#define WH_TEST_AES_IVSIZE 12
#define WH_TEST_AES_TAGSIZE 16
#define WH_TEST_AES_WRAPPED_KEYSIZE                                   \
    (WH_TEST_AES_IVSIZE + WH_TEST_AES_TAGSIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))

#endif /* HAVE_AESGCM */

/* RSA Specific defines */
#ifndef NO_RSA

#define WH_TEST_RSA_KEY_OFFSET 0x2000
#define WH_TEST_RSA_KEYID 3
#define WH_TEST_RSA_DER_SIZE 1766
#define WH_TEST_RSA_WRAPPED_KEYSIZE                                    \
    (WH_TEST_AES_IVSIZE + WH_TEST_AES_TAGSIZE + WH_TEST_RSA_DER_SIZE + \
     sizeof(whNvmMetadata))
#endif /* !NO_RSA */

static int _InitServerKek(whClientContext* ctx)
{
    /* IMPORTANT NOTE: Server KEK is typically intrinsic or set during
     * provisioning. Uploading the KEK via the client is for testing purposes
     * only and not intended as a recommendation */
    whKeyId    serverKeyId             = WH_TEST_KEKID;
    whNvmFlags flags                   = WH_NVM_FLAGS_NONEXPORTABLE;
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
    return wh_Client_KeyErase(ctx, WH_TEST_KEKID);
}

#ifdef HAVE_AESGCM

static int _AesGcm_KeyWrap(whClientContext* ctx, WC_RNG* rng)
{

    int           ret = 0;
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    whKeyId       wrappedKeyId;
    whNvmMetadata metadata = {
        .id    = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 8),
        .label = "AES Key Label",
        .len   = WH_TEST_AES_KEYSIZE,
        .flags = WH_NVM_FLAGS_NONE,
    };
    whNvmMetadata tmpMetadata;

    ret = wc_RNG_GenerateBlock(rng, plainKey, sizeof(plainKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyWrap(ctx, WC_CIPHER_AES_GCM, WH_TEST_KEKID, plainKey,
                            sizeof(plainKey), &metadata, wrappedKey,
                            sizeof(wrappedKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyWrap %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndCache(ctx, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                      wrappedKey, sizeof(wrappedKey),
                                      &wrappedKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyWrapCache %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndExport(
        ctx, WC_CIPHER_AES_GCM, WH_TEST_KEKID, wrappedKey, sizeof(wrappedKey),
        &tmpMetadata, tmpPlainKey, sizeof(tmpPlainKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyUnwrapAndExport %d\n",
                       ret);
        return ret;
    }

    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap key failed to match\n");
        return ret;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap metadata failed to match\n");
        return ret;
    }

    return ret;
}

#endif /* HAVE_AESGCM */

int whTest_Client_KeyWrap(whClientContext* ctx)
{
    int    ret = 0;
    WC_RNG rng[1];

    _InitServerKek(ctx);

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_KeyWrap(ctx, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
    }
#endif

    _CleanupServerKek(ctx);

    (void)wc_FreeRng(rng);
    return ret;
}

int whTest_KeyWrapClientConfig(whClientConfig* clientCfg)
{
    int             ret       = 0;
    whClientContext client[1] = {0};

    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, clientCfg));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_Init %d\n", ret);
        goto cleanup_and_exit;
    }

    ret = whTest_Client_KeyWrap(client);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to whTest_Client_KeyWrap %d\n", ret);
    }

    /* Clean up used resources */
cleanup_and_exit:
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}

#ifdef HAVE_AESGCM
static int _AesGcm_WriteWrappedKeyToNvm(whClientContext* client, void* flashCtx,
                                        whFlashCb* flashCb, WC_RNG* rng)
{
    int     ret;
    whKeyId serverKekId = WH_TEST_KEKID;

    uint8_t aesGcmKey[WH_TEST_AES_KEYSIZE] = {0};
    uint8_t aesGcmWrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];

    /* This is metadata tied to the AES GCM key for the server to use */
    whNvmMetadata aesGcmKeyMetadata = {
        .label  = "AES GCM Key",
        .access = WH_NVM_ACCESS_ANY,
        .flags  = WH_NVM_FLAGS_NONE,
        .id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, WH_TEST_AESGCM_KEYID),
        .len    = WH_TEST_AES_KEYSIZE};

    /* Generate the AES-GCM Key */
    ret = wc_RNG_GenerateBlock(rng, aesGcmKey, sizeof(aesGcmKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for AES-GCM key %d\n",
                       ret);
        return ret;
    }
    /* Request the server to wrap the AES GCM key using the server KEK */
    ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, serverKekId, aesGcmKey,
                            sizeof(aesGcmKey), &aesGcmKeyMetadata,
                            aesGcmWrappedKey, sizeof(aesGcmWrappedKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyWrap %d\n", ret);
        return ret;
    }

    /* Write the wrapped AES GCM key to a specified location in NVM */
    ret = flashCb->Program(flashCtx, WH_TEST_AESGCM_KEY_OFFSET,
                           sizeof(aesGcmWrappedKey), aesGcmWrappedKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to write AES GCM key to NVM %d\n", ret);
        return ret;
    }

    ret = flashCb->Verify(flashCtx, WH_TEST_AESGCM_KEY_OFFSET,
                          sizeof(aesGcmWrappedKey), aesGcmWrappedKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to verify the AES GCM key written to flash %d\n",
                       ret);
        return ret;
    }

    return ret;
}

static int _AesGcm_UseWrappedKeyFromNvm(whClientContext* client, void* flashCtx,
                                        whFlashCb* flashCb, WC_RNG* rng)
{
    int     ret;
    whKeyId serverKekId = WH_TEST_KEKID;

    Aes     aes[1];
    whKeyId aesGcmKeyId = WH_TEST_AESGCM_KEYID;
    uint8_t aesGcmWrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];

    const uint8_t plaintext[] = "hello, wolfSSL AES-GCM!";
    uint8_t       ciphertext[sizeof(plaintext)];
    uint8_t       decrypted[sizeof(plaintext)];

    uint8_t       tag[WH_TEST_AES_TAGSIZE];
    uint8_t       iv[WH_TEST_AES_IVSIZE];
    const uint8_t aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                           0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                           0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    /* Load wrapped AES GCM key from flash into RAM */
    ret = flashCb->Read(flashCtx, WH_TEST_AESGCM_KEY_OFFSET,
                        sizeof(aesGcmWrappedKey), aesGcmWrappedKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to read the AES GCM key from NVM %d\n", ret);
        return ret;
    }

    /* Request the server to unwrap and cache the key for us */
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, serverKekId,
                                      aesGcmWrappedKey,
                                      sizeof(aesGcmWrappedKey), &aesGcmKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyUnwrapAndCache %d\n", ret);
        return ret;
    }

    /* Initialize AES context */
    ret = wc_AesInit(aes, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    ret = wh_Client_AesSetKeyId(aes, aesGcmKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesSetKeyId %d\n", ret);
        return ret;
    }

    /* Generate a random IV */
    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for AES-GCM key %d\n",
                       ret);
        return ret;
    }

    /* Request the server to encrypt some data using the
     * unwrapped and cached key via the key ID */
    ret = wc_AesGcmEncrypt(aes, ciphertext, plaintext, sizeof(plaintext), iv,
                           sizeof(iv), tag, sizeof(tag), aad, sizeof(aad));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
        return ret;
    }

    /* Request the server to decrypt the encrypted data using the
     * unwrapped and cached key via the key ID */
    ret = wc_AesGcmDecrypt(aes, decrypted,                 /* out */
                           ciphertext, sizeof(ciphertext), /* in, inLen */
                           iv, sizeof(iv),                 /* iv, ivLen */
                           tag, sizeof(tag),  /* authTag, authTagSz */
                           aad, sizeof(aad)); /* authIn (AAD), authInSz */
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n", ret);
        return ret;
    }

    /* Check if the decrypted data matches an expected value */
    if (memcmp(decrypted, plaintext, sizeof(decrypted)) != 0) {
        WH_ERROR_PRINT("Decrypted value does not match expected value\n");
        return -1;
    }

    wh_Client_KeyErase(client, aesGcmKeyId);
    wc_AesFree(aes);

    return WH_ERROR_OK;
}
#endif /* HAVE_AESGCM */

#ifndef NO_RSA

static int _Rsa_WriteWrappedKeyToNvm(whClientContext* client, void* flashCtx,
                                     whFlashCb* flashCb, WC_RNG* rng)
{
    int           ret;
    whKeyId       rsaKeyId = WH_TEST_RSA_KEYID;
    RsaKey        rsaKey[1];
    uint8_t       rsaKeyDer[WH_TEST_RSA_DER_SIZE];
    int           rsaKeyDerSz;
    uint8_t       rsaWrappedKey[WH_TEST_RSA_WRAPPED_KEYSIZE];
    whNvmMetadata rsaKeyMetadata = {
        .label  = "RSA 3072 Key",
        .access = WH_NVM_ACCESS_ANY,
        .flags  = WH_NVM_FLAGS_NONE,
        .id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, rsaKeyId),
        .len    = WH_TEST_RSA_DER_SIZE};

    /* Initialize the RSA key */
    ret = wc_InitRsaKey(rsaKey, NULL);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey %d\n", ret);
        return ret;
    }

    /* Generate the RSA key */
    ret = wc_MakeRsaKey(rsaKey, 3072, 65537, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wc_MakeRsaKey %d\n", ret);
        return ret;
    }

    /* Convert the RSA key to DER format so it can be stored in flash */
    rsaKeyDerSz = wc_RsaKeyToDer(rsaKey, rsaKeyDer, WH_TEST_RSA_DER_SIZE);
    if (rsaKeyDerSz < 0) {
        ret = rsaKeyDerSz;
        WH_ERROR_PRINT("Failed to wc_RsaKeyToDer %d\n", ret);
        return ret;
    }

    /* Validate the DER size */
    if (rsaKeyDerSz != WH_TEST_RSA_DER_SIZE) {
        WH_ERROR_PRINT("Unexpected RSA DER size\n");
        return WH_ERROR_ABORTED;
    }

    /* Request the server to wrap the RSA key using the server KEK */
    ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID, rsaKeyDer,
                            rsaKeyDerSz, &rsaKeyMetadata, rsaWrappedKey,
                            sizeof(rsaWrappedKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyWrap %d\n", ret);
        return ret;
    }

    /* Write the wrapped RSA key to a specified location in flash */
    ret = flashCb->Program(flashCtx, WH_TEST_RSA_KEY_OFFSET,
                           sizeof(rsaWrappedKey), rsaWrappedKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to write RSA key to NVM %d\n", ret);
        return ret;
    }

    ret = flashCb->Verify(flashCtx, WH_TEST_RSA_KEY_OFFSET,
                          sizeof(rsaWrappedKey), rsaWrappedKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to verify the RSA key written to flash %d\n",
                       ret);
        return ret;
    }

    return ret;
}

static int _Rsa_UseWrappedKeyFromNvm(whClientContext* client, void* flashCtx,
                                     whFlashCb* flashCb, WC_RNG* rng)
{
    int     ret;
    whKeyId serverKekId = WH_TEST_KEKID;

    RsaKey  rsa[1];
    whKeyId rsaKeyId = WH_TEST_RSA_KEYID;
    uint8_t rsaWrappedKey[WH_TEST_RSA_WRAPPED_KEYSIZE];

    const uint8_t plaintext[] = "Hello with RSA-3072!";
    uint8_t       ciphertext[384];
    uint8_t       decrypted[sizeof(ciphertext)];

    /* Load wrapped RSA key from flash into RAM */
    ret = flashCb->Read(flashCtx, WH_TEST_RSA_KEY_OFFSET, sizeof(rsaWrappedKey),
                        rsaWrappedKey);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to read the RSA wrapped key from NVM %d\n", ret);
        return ret;
    }

    /* Request the server to unwrap and cache the key for us */
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, serverKekId,
                                      rsaWrappedKey, sizeof(rsaWrappedKey),
                                      &rsaKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyUnwrapAndCache %d\n", ret);
        return ret;
    }

    /* Initialize the rsa key */
    ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
        return ret;
    }

    /* Set the assigned keyId */
    ret = wh_Client_RsaSetKeyId(rsa, rsaKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
        return ret;
    }

    /* Request the server to decrypt some data using the
     * unwrapped and cached key via the key ID */
    ret = wc_RsaPublicEncrypt_ex(plaintext, sizeof(plaintext), ciphertext,
                                 sizeof(ciphertext), rsa, rng, WC_RSA_OAEP_PAD,
                                 WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    if (ret < 0) {
        WH_ERROR_PRINT("Failed to wc_RsaPrivateEncrypt %d\n", ret);
        return ret;
    }

    /* Request the server to decrypt some data using the
     * unwrapped and cached key via the key ID */
    ret = wc_RsaPrivateDecrypt_ex(ciphertext, sizeof(ciphertext), decrypted,
                                  sizeof(decrypted), rsa, WC_RSA_OAEP_PAD,
                                  WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    if (ret < 0) {
        WH_ERROR_PRINT("Failed to wc_RsaPrivateDecrypt %d\n", ret);
        return ret;
    }

    /* Check if the decrypted data matches an expected value */
    if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
        WH_ERROR_PRINT("Decrypted value does not match expected value\n");
        return -1;
    }

    wh_Client_KeyErase(client, rsaKeyId);
    wc_FreeRsaKey(rsa);
    return WH_ERROR_OK;
}
#endif /* !NO_RSA */

int whTest_Client_WriteWrappedKeysToNvm(whClientContext* client, void* flashCtx,
                                        whFlashCb* flashCb)
{
    int    ret = WH_ERROR_OK;
    WC_RNG rng[1];

    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        _CleanupServerKek(client);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_WriteWrappedKeyToNvm(client, flashCtx, flashCb, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_WriteWrappedKeyToNvm %d\n", ret);
        goto cleanup_and_exit;
    }
#endif /* HAVE_AESGCM */

#ifndef NO_RSA
    ret = _Rsa_WriteWrappedKeyToNvm(client, flashCtx, flashCb, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _Rsa_WriteWrappedKeyToNvm %d\n", ret);
        goto cleanup_and_exit;
    }
#endif /* !NO_RSA */

cleanup_and_exit:
    wc_FreeRng(rng);
    _CleanupServerKek(client);

    return WH_ERROR_OK;
}

int whTest_Client_UseWrappedKeysFromNvm(whClientContext* client, void* flashCtx,
                                        whFlashCb* flashCb)
{
    int    ret = WH_ERROR_OK;
    WC_RNG rng[1];

    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        _CleanupServerKek(client);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_UseWrappedKeyFromNvm(client, flashCtx, flashCb, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_UseWrappedKeyToNvm %d\n", ret);
        goto cleanup_and_exit;
    }
#endif /* HAVE_AESGCM */

#ifndef NO_RSA
    ret = _Rsa_UseWrappedKeyFromNvm(client, flashCtx, flashCb, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _Rsa_UseWrappedKeyFromNvm %d\n", ret);
        goto cleanup_and_exit;
    }
#endif /* !NO_RSA */

cleanup_and_exit:
    wc_FreeRng(rng);
    _CleanupServerKek(client);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
#endif /* WOLFHSM_CFG_KEYWRAP */
