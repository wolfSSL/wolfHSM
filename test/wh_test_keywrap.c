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

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_KEYWRAP

#include "wh_test_common.h"

#ifdef WOLFHSM_CFG_HWKEYSTORE
#include "wolfhsm/wh_keyid.h"

/* Hardware keystore test fixture: the id and material of the only KEK served
 * by whTest_HwKeystoreGetKeyCb, which emulates a hardware keystore backend
 * for the in-process test servers */
#define WH_TEST_HWKEK_ID 3
#define WH_TEST_HWKEK_SIZE 32

static const uint8_t _hwKekMaterial[WH_TEST_HWKEK_SIZE] = {
    0x9a, 0x4e, 0x21, 0xc7, 0x5d, 0x10, 0xfb, 0x33, 0x6f, 0x82, 0xd4,
    0x59, 0xee, 0x07, 0xb1, 0x2c, 0x48, 0x95, 0x3a, 0xc6, 0x71, 0x0d,
    0xb8, 0xe5, 0x12, 0x6a, 0xf9, 0x84, 0x2f, 0xd0, 0x5b, 0xa7};

int whTest_HwKeystoreGetKeyCb(void* context, whKeyId keyId, uint8_t* out,
                              uint16_t* inout_len)
{
    (void)context;

    /* Only hardware-only keyIds should ever reach a hardware keystore */
    if (WH_KEYID_TYPE(keyId) != WH_KEYTYPE_HW) {
        return WH_ERROR_ACCESS;
    }

    /* Serve only the known test KEK id, refuse everything else */
    if (WH_KEYID_ID(keyId) != WH_TEST_HWKEK_ID) {
        return WH_ERROR_NOTFOUND;
    }

    if ((out == NULL) || (inout_len == NULL) ||
        (*inout_len < sizeof(_hwKekMaterial))) {
        return WH_ERROR_BUFFER_SIZE;
    }

    memcpy(out, _hwKekMaterial, sizeof(_hwKekMaterial));
    *inout_len = sizeof(_hwKekMaterial);
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_HWKEYSTORE */

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

/* Common defines */
#define WH_TEST_KEKID 10

/* AES GCM Specific defines */
#ifdef HAVE_AESGCM

#define WH_TEST_AESGCM_KEY_OFFSET 0x1000
#define WH_TEST_AESGCM_KEYID 20
#define WH_TEST_AES_KEYSIZE 32
#define WH_TEST_AES_TEXTSIZE 16
#define WH_TEST_AES_WRAPPED_KEYSIZE                         \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + WH_TEST_AES_KEYSIZE + \
     sizeof(whNvmMetadata))

#endif /* HAVE_AESGCM */

#ifndef TEST_ADMIN_USERNAME
#define TEST_ADMIN_USERNAME "admin"
#endif
#ifndef TEST_ADMIN_PIN
#define TEST_ADMIN_PIN "1234"
#endif

static int _InitServerKek(whClientContext* client)
{
    /* IMPORTANT NOTE: Server KEK is typically intrinsic or set during
     * provisioning. Uploading the KEK via the client is for testing purposes
     * only and not intended as a recommendation */
    whKeyId    serverKeyId             = WH_TEST_KEKID;
    whNvmFlags flags = WH_NVM_FLAGS_NONEXPORTABLE | WH_NVM_FLAGS_USAGE_WRAP;
    uint8_t    label[WH_NVM_LABEL_LEN] = "Server KEK key";
    uint8_t    kek[] = {0x03, 0x03, 0x0d, 0xd9, 0xeb, 0x18, 0x17, 0x2e,
                        0x06, 0x6e, 0x19, 0xce, 0x98, 0x44, 0x54, 0x0d,
                        0x78, 0xa0, 0xbe, 0xe7, 0x35, 0x43, 0x40, 0xa4,
                        0x22, 0x8a, 0xd1, 0x0e, 0xa3, 0x63, 0x1c, 0x0b};

    return wh_Client_KeyCache(client, flags, label, sizeof(label), kek,
                              sizeof(kek), &serverKeyId);
}

static int _CleanupServerKek(whClientContext* client)
{
    return wh_Client_KeyEvict(client, WH_TEST_KEKID);
}

#ifdef HAVE_AESGCM

static int _AesGcm_TestKeyWrap(whClientContext* client, WC_RNG* rng)
{

    int           ret = 0;
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpPlainKeySz = sizeof(tmpPlainKey);
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    whKeyId       wrappedKeyId = WH_KEYID_ERASED;
    whNvmMetadata metadata     = {
            .id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                       WH_TEST_AESGCM_KEYID),
            .label = "AES Key Label",
            .len   = WH_TEST_AES_KEYSIZE,
            .flags = WH_NVM_FLAGS_USAGE_ANY,
    };
    whNvmMetadata tmpMetadata = {0};

    Aes           aes[1];
    const uint8_t plaintext[] = "hello, wolfSSL AES-GCM!";
    uint8_t       ciphertext[sizeof(plaintext)];
    uint8_t       decrypted[sizeof(plaintext)];

    uint8_t       tag[WH_KEYWRAP_AES_GCM_TAG_SIZE];
    uint8_t       iv[WH_KEYWRAP_AES_GCM_IV_SIZE];
    const uint8_t aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                           0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                           0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};


    ret = wc_RNG_GenerateBlock(rng, plainKey, sizeof(plainKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID, plainKey,
                            sizeof(plainKey), &metadata, wrappedKey,
                            &wrappedKeySz);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyWrap %d\n", ret);
        return ret;
    }

    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                      wrappedKey, wrappedKeySz, &wrappedKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_AesGcmKeyWrapCache %d\n", ret);
        return ret;
    }

    /* Initialize AES context */
    ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        return ret;
    }

    ret =
        wh_Client_AesSetKeyId(aes, WH_CLIENT_KEYID_MAKE_WRAPPED(wrappedKeyId));
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

    ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                       wrappedKey, wrappedKeySz, &tmpMetadata,
                                       tmpPlainKey, &tmpPlainKeySz);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyUnwrapAndExport %d\n", ret);
        return ret;
    }

    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap key failed to match\n");
        return -1;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        WH_ERROR_PRINT("AES GCM wrap/unwrap metadata failed to match\n");
        return -1;
    }

    /* Cache a local key using the same numeric ID to confirm coexistence */
    {
        whKeyId       localKeyId = WH_TEST_AESGCM_KEYID;
        uint8_t       localLabel[WH_NVM_LABEL_LEN] = "LocalKeySameId";
        const uint8_t localKey[WH_TEST_AES_KEYSIZE] = {0};

        ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE, localLabel,
                                 (uint16_t)sizeof("LocalKeySameId"),
                                 (uint8_t*)localKey, sizeof(localKey),
                                 &localKeyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache local key with shared ID %d\n", ret);
            return ret;
        }
        if (localKeyId != WH_TEST_AESGCM_KEYID) {
            WH_ERROR_PRINT("Local key ID mismatch (expected %u, got %u)\n",
                           WH_TEST_AESGCM_KEYID, localKeyId);
            return WH_ERROR_ABORTED;
        }
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, localKeyId));
    }

    wh_Client_KeyEvict(client, wrappedKeyId);
    wc_AesFree(aes);

    return ret;
}

static int _AesGcm_TestDataWrap(whClientContext* client)
{
    int     ret                                           = 0;
    uint8_t data[]                                        = "Example data!";
    uint8_t unwrappedData[sizeof(data)]                   = {0};
    uint32_t unwrappedDataSz = sizeof(unwrappedData);
    uint8_t  wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE] = {0};
    uint32_t wrappedDataSz = sizeof(wrappedData);

    ret = wh_Client_DataWrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID, data,
                             sizeof(data), wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_DataWrap %d\n", ret);
        return ret;
    }

    ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                               wrappedData, sizeof(wrappedData), unwrappedData,
                               &unwrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_DataUnwrap %d\n", ret);
        return ret;
    }

    if (memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("Unwrapped data failed to match input data\n");
        return -1;
    }

    return ret;
}

static int _AesGcm_TestKeyUnwrapUnderflow(whClientContext* client)
{
    int           ret;
    uint8_t       dummyBuf[1] = {0};
    whNvmMetadata tmpMetadata = {0};
    uint8_t       tmpKey[WH_TEST_AES_KEYSIZE] = {0};
    uint16_t      tmpKeySz = sizeof(tmpKey);
    whKeyId       wrappedKeyId = WH_KEYID_ERASED;

    /* wrappedKeySz=0: must return WH_ERROR_BADARGS, not underflow */
    ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                       dummyBuf, 0, &tmpMetadata, tmpKey,
                                       &tmpKeySz);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndExport(sz=0) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* wrappedKeySz=1: must return WH_ERROR_BADARGS, not underflow */
    tmpKeySz = sizeof(tmpKey);
    ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                       dummyBuf, 1, &tmpMetadata, tmpKey,
                                       &tmpKeySz);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndExport(sz=1) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* wrappedKeySz=0: test KeyUnwrapAndCache path */
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                      dummyBuf, 0, &wrappedKeyId);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndCache(sz=0) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* wrappedKeySz=1: test KeyUnwrapAndCache path */
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                      dummyBuf, 1, &wrappedKeyId);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("KeyUnwrapAndCache(sz=1) expected BADARGS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

static int _AesGcm_TestDataUnwrapUnderflow(whClientContext* client)
{
    int      ret;
    uint8_t  dummyBuf[1] = {0};
    uint8_t  outBuf[32]  = {0};
    uint32_t outSz       = sizeof(outBuf);

    /* wrappedDataSz=0: must return WH_ERROR_BADARGS, not underflow */
    ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                               dummyBuf, 0, outBuf, &outSz);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("DataUnwrap(sz=0) expected BADARGS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

    /* wrappedDataSz=1: must return WH_ERROR_BADARGS, not underflow */
    outSz = sizeof(outBuf);
    ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                               dummyBuf, 1, outBuf, &outSz);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("DataUnwrap(sz=1) expected BADARGS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_HWKEYSTORE

static int _AesGcm_TestHwKeystoreKeyWrap(whClientContext* client, WC_RNG* rng)
{
    int           ret;
    whKeyId       hwKekId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpPlainKeySz = sizeof(tmpPlainKey);
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz   = sizeof(wrappedKey);
    whKeyId       unwrappedKeyId = WH_KEYID_ERASED;
    whNvmMetadata metadata       = {
              .id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                         WH_TEST_AESGCM_KEYID),
              .label = "HW KEK wrapped key",
              .len   = WH_TEST_AES_KEYSIZE,
              .flags = WH_NVM_FLAGS_USAGE_ANY,
    };
    whNvmMetadata tmpMetadata = {0};

    ret = wc_RNG_GenerateBlock(rng, plainKey, sizeof(plainKey));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock for key data %d\n", ret);
        return ret;
    }

    /* Wrap a key using the hardware-only KEK */
    ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, hwKekId, plainKey,
                            sizeof(plainKey), &metadata, wrappedKey,
                            &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyWrap with HW KEK %d\n", ret);
        return ret;
    }

    /* Unwrap and export with the hardware-only KEK, check the roundtrip */
    ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, hwKekId,
                                       wrappedKey, wrappedKeySz, &tmpMetadata,
                                       tmpPlainKey, &tmpPlainKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT(
            "Failed to wh_Client_KeyUnwrapAndExport with HW KEK %d\n", ret);
        return ret;
    }

    if (memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("HW KEK wrap/unwrap key failed to match\n");
        return WH_TEST_FAIL;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        WH_ERROR_PRINT("HW KEK wrap/unwrap metadata failed to match\n");
        return WH_TEST_FAIL;
    }

    /* Unwrap-and-cache with the hardware-only KEK: the wrapped payload is an
     * ordinary key and may enter the cache; only the KEK itself is
     * hardware-resident */
    ret =
        wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, hwKekId,
                                    wrappedKey, wrappedKeySz, &unwrappedKeyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyUnwrapAndCache with HW KEK %d\n",
                       ret);
        return ret;
    }
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, unwrappedKeyId));

    /* A wrapped+hardware-only KEK id must behave as hardware-only (the
     * hardware-only flag takes precedence) */
    wrappedKeySz = sizeof(wrappedKey);
    ret          = wh_Client_KeyWrap(
        client, WC_CIPHER_AES_GCM, hwKekId | WH_KEYID_CLIENT_WRAPPED_FLAG,
        plainKey, sizeof(plainKey), &metadata, wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyWrap with wrapped+HW KEK %d\n",
                       ret);
        return ret;
    }

    /* Unwrapping a hardware-KEK-wrapped blob with a different, cached KEK
     * must fail authentication, proving distinct key material was used */
    WH_TEST_RETURN_ON_FAIL(_InitServerKek(client));
    tmpPlainKeySz = sizeof(tmpPlainKey);
    ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                       wrappedKey, wrappedKeySz, &tmpMetadata,
                                       tmpPlainKey, &tmpPlainKeySz);
    WH_TEST_RETURN_ON_FAIL(_CleanupServerKek(client));
    if (ret == WH_ERROR_OK) {
        WH_ERROR_PRINT("Unwrap with wrong KEK unexpectedly succeeded\n");
        return WH_TEST_FAIL;
    }

    /* A hardware KEK id the backend does not serve must fail */
    wrappedKeySz = sizeof(wrappedKey);
    ret          = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM,
                                     WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID + 1),
                                     plainKey, sizeof(plainKey), &metadata, wrappedKey,
                                     &wrappedKeySz);
    if (ret != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("KeyWrap with unserved HW KEK expected NOTFOUND, "
                       "got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

static int _AesGcm_TestHwKeystoreDataWrap(whClientContext* client)
{
    int      ret;
    whKeyId  hwKekId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t  data[]  = "Example data!";
    uint8_t  unwrappedData[sizeof(data)] = {0};
    uint32_t unwrappedDataSz             = sizeof(unwrappedData);
    uint8_t  wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE] = {0};
    uint32_t wrappedDataSz = sizeof(wrappedData);

    ret = wh_Client_DataWrap(client, WC_CIPHER_AES_GCM, hwKekId, data,
                             sizeof(data), wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_DataWrap with HW KEK %d\n", ret);
        return ret;
    }

    ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, hwKekId, wrappedData,
                               sizeof(wrappedData), unwrappedData,
                               &unwrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_DataUnwrap with HW KEK %d\n", ret);
        return ret;
    }

    if (memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("HW KEK unwrapped data failed to match input data\n");
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

/* Hardware-only keys must be rejected by every keystore operation and by
 * crypto key use; only the keywrap KEK paths may resolve them */
static int _TestHwKeystoreKeystoreRejections(whClientContext* client)
{
    int      ret;
    whKeyId  hwKeyId = WH_CLIENT_KEYID_MAKE_HW(WH_TEST_HWKEK_ID);
    uint8_t  buf[WH_TEST_HWKEK_SIZE] = {0};
    uint16_t bufSz                   = sizeof(buf);
    uint8_t  label[WH_NVM_LABEL_LEN] = "hwonly reject";
    whKeyId  cacheKeyId              = hwKeyId;

    /* Caching key material under a hardware-only id must be rejected */
    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE, label, sizeof(label),
                             buf, sizeof(buf), &cacheKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCache of HW-only id expected ACCESS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

#ifdef WOLFHSM_CFG_DMA
    /* The DMA cache path must reject hardware-only ids as well */
    cacheKeyId = hwKeyId;
    ret = wh_Client_KeyCacheDma(client, WH_NVM_FLAGS_NONE, label, sizeof(label),
                                buf, sizeof(buf), &cacheKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCacheDma of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }
#endif

    /* Exporting a hardware-only key must be rejected */
    ret =
        wh_Client_KeyExport(client, hwKeyId, label, sizeof(label), buf, &bufSz);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyExport of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* Commit/evict/erase/revoke of a hardware-only key must be rejected */
    ret = wh_Client_KeyCommit(client, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyCommit of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    ret = wh_Client_KeyEvict(client, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyEvict of HW-only id expected ACCESS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

    ret = wh_Client_KeyErase(client, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyErase of HW-only id expected ACCESS, got %d\n", ret);
        return WH_TEST_FAIL;
    }

    ret = wh_Client_KeyRevoke(client, hwKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("KeyRevoke of HW-only id expected ACCESS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    /* Crypto operations must not be able to use hardware-only keys */
    {
        Aes           aes[1];
        const uint8_t plaintext[16] = {0};
        uint8_t       ciphertext[sizeof(plaintext)];
        uint8_t       iv[WH_KEYWRAP_AES_GCM_IV_SIZE]   = {0};
        uint8_t       tag[WH_KEYWRAP_AES_GCM_TAG_SIZE] = {0};

        WH_TEST_RETURN_ON_FAIL(wc_AesInit(aes, NULL, WH_DEV_ID));
        WH_TEST_RETURN_ON_FAIL(wh_Client_AesSetKeyId(aes, hwKeyId));

        ret = wc_AesGcmEncrypt(aes, ciphertext, plaintext, sizeof(plaintext),
                               iv, sizeof(iv), tag, sizeof(tag), NULL, 0);
        wc_AesFree(aes);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("AES-GCM with HW-only key expected ACCESS, "
                           "got %d\n",
                           ret);
            return WH_TEST_FAIL;
        }
    }

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_HWKEYSTORE */

#endif /* HAVE_AESGCM */

int whTest_Client_KeyWrap(whClientContext* client)
{
    int    ret = 0;
    WC_RNG rng[1];

    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(client));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_TestKeyWrap(client, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_TestKeyWrap %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestKeyUnwrapUnderflow(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestKeyUnwrapUnderflow %d\n",
                           ret);
        }
    }
#endif

    _CleanupServerKek(client);

    (void)wc_FreeRng(rng);
    return ret;
}

int whTest_Client_DataWrap(whClientContext* client)
{
    int ret = 0;

    ret = _InitServerKek(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _InitServerKek %d\n", ret);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_TestDataWrap(client);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_TestDataWrap %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestDataUnwrapUnderflow(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestDataUnwrapUnderflow %d\n",
                           ret);
        }
    }
#endif

    _CleanupServerKek(client);

    return ret;
}

#ifdef WOLFHSM_CFG_HWKEYSTORE
/* Requires a server with a hardware keystore backed by
 * whTest_HwKeystoreGetKeyCb */
int whTest_Client_HwKeystore(whClientContext* client)
{
    int    ret = 0;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

#ifdef HAVE_AESGCM
    ret = _AesGcm_TestHwKeystoreKeyWrap(client, rng);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to _AesGcm_TestHwKeystoreKeyWrap %d\n", ret);
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestHwKeystoreDataWrap(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestHwKeystoreDataWrap %d\n",
                           ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = _TestHwKeystoreKeystoreRejections(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _TestHwKeystoreKeystoreRejections %d\n",
                           ret);
        }
    }
#endif

    if (ret == WH_ERROR_OK) {
        WH_TEST_PRINT("HW KEYSTORE KEYWRAP TESTS SUCCESS\n");
    }

    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* WOLFHSM_CFG_HWKEYSTORE */

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

#ifdef WOLFHSM_CFG_ENABLE_AUTHENTICATION
    /* Log in as an admin user for the rest of the tests */
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
    WH_TEST_ASSERT_RETURN(ret == 0);
#endif /* WOLFHSM_CFG_ENABLE_AUTHENTICATION */

    ret = whTest_Client_KeyWrap(client);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to whTest_Client_KeyWrap %d\n", ret);
    }
    else {
        WH_TEST_PRINT("KEYWRAP TESTS SUCCESS\n");
    }

    ret = whTest_Client_DataWrap(client);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to whTest_Client_DataWrap %d\n", ret);
    }
    else {
        WH_TEST_PRINT("DATAWRAP TESTS SUCCESS\n");
    }

    /* Clean up used resources */
cleanup_and_exit:
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */
#endif /* WOLFHSM_CFG_KEYWRAP */
