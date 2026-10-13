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
#include "wolfssl/wolfcrypt/kdf.h" /* for HKDF and WC_SHA256 in trusted-KEK test */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_KEYWRAP

#include "wh_test_common.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

/* Common defines */
#define WH_TEST_KEKID 10

/* AES GCM Specific defines */
#ifdef HAVE_AESGCM

#define WH_TEST_AESGCM_KEY_OFFSET 0x1000
#define WH_TEST_AESGCM_KEYID 20
#define WH_TEST_WRAPEXPORT_KEYID 21
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

/* Positive software-KEK round trip; needs no trusted KEK, so it runs in every
 * build. Wrap a plaintext key under the plain software KEK (WH_TEST_KEKID from
 * _InitServerKek), unwrap-and-export the blob, and confirm the key material and
 * metadata come back unchanged. Only the unwrap-and-cache path needs a trusted
 * KEK, which test-refactor/misc/wh_test_portkey.c covers. */
static int _AesGcm_TestSwKekRoundTrip(whClientContext* client, WC_RNG* rng)
{
    int           ret;
    uint8_t       plainKey[WH_TEST_AES_KEYSIZE];
    uint8_t       tmpPlainKey[WH_TEST_AES_KEYSIZE];
    uint16_t      tmpPlainKeySz = sizeof(tmpPlainKey);
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    whNvmMetadata metadata     = {
            .id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                       WH_TEST_AESGCM_KEYID),
            .label = "SwKek Key Label",
            .len   = WH_TEST_AES_KEYSIZE,
            .flags = WH_NVM_FLAGS_USAGE_ANY,
    };
    whNvmMetadata tmpMetadata = {0};

    ret = wc_RNG_GenerateBlock(rng, plainKey, sizeof(plainKey));
    if (ret != 0) {
        WH_ERROR_PRINT("sw-kek: RNG generate failed %d\n", ret);
        return ret;
    }

    /* Wrap the plaintext key under the plain software KEK. */
    ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID, plainKey,
                            sizeof(plainKey), &metadata, wrappedKey,
                            &wrappedKeySz);
    if (ret != 0) {
        WH_ERROR_PRINT("sw-kek: KeyWrap failed %d\n", ret);
        return ret;
    }

    /* Unwrap-and-export the blob and confirm the material round-trips. */
    ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                       wrappedKey, wrappedKeySz, &tmpMetadata,
                                       tmpPlainKey, &tmpPlainKeySz);
    if (ret != 0) {
        WH_ERROR_PRINT("sw-kek: KeyUnwrapAndExport failed %d\n", ret);
        return ret;
    }

    if (tmpPlainKeySz != sizeof(plainKey) ||
        memcmp(plainKey, tmpPlainKey, sizeof(plainKey)) != 0) {
        WH_ERROR_PRINT("sw-kek: unwrapped key material mismatch\n");
        return WH_TEST_FAIL;
    }

    if (memcmp(&metadata, &tmpMetadata, sizeof(metadata)) != 0) {
        WH_ERROR_PRINT("sw-kek: unwrapped metadata mismatch\n");
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

/* The wrap-export and unwrap-and-cache operations require a trusted KEK. Prove
 * that (a) a plain client-cached USAGE_WRAP key (WH_TEST_KEKID, provisioned by
 * _InitServerKek) is refused as their KEK, and (b) a client cannot forge a
 * trusted KEK by setting WH_NVM_FLAGS_TRUSTED itself -- the server strips the
 * flag, so the key is still refused. Needs no port keys, so it runs
 * against any server. */
static int _AesGcm_TestTrustedKekPolicy(whClientContext* client, WC_RNG* rng)
{
    int           ret;
    uint8_t       srcKey[WH_TEST_AES_KEYSIZE];
    whKeyId       srcKeyId                = WH_TEST_WRAPEXPORT_KEYID;
    whKeyId       forgeId                 = WH_TEST_KEKID + 1;
    uint8_t       label[WH_NVM_LABEL_LEN] = "TrustedKek key";
    uint8_t       wrappedKey[WH_TEST_AES_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    whKeyId       wrappedKeyId = WH_KEYID_ERASED;
    whNvmMetadata wrapMeta     = {
            .id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                       WH_TEST_AESGCM_KEYID),
            .label = "TrustedKek blob",
            .len   = WH_TEST_AES_KEYSIZE,
            .flags = WH_NVM_FLAGS_USAGE_ANY,
    };

    ret = wc_RNG_GenerateBlock(rng, srcKey, sizeof(srcKey));
    if (ret != 0) {
        return ret;
    }

    /* Cache an ordinary, exportable source key to try to wrap-export. */
    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, label,
                             (uint16_t)sizeof(label), srcKey, sizeof(srcKey),
                             &srcKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("trusted-kek: cache src failed %d\n", ret);
        return ret;
    }

    /* (a) wrap-export under a plain client KEK must be refused. */
    ret = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                  WH_KEYTYPE_CRYPTO, WH_TEST_KEKID, wrappedKey,
                                  &wrappedKeySz);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: wrap-export with plain KEK expected "
                       "ACCESS, got %d\n",
                       ret);
        (void)wh_Client_KeyEvict(client, srcKeyId);
        return WH_TEST_FAIL;
    }

    /* (a) unwrap-and-cache under a plain client KEK must be refused. Build a
     * correctly sized blob under the same plain KEK (KeyWrap itself does not
     * require a trusted KEK); the trusted-KEK check rejects the cache attempt
     * before authentication. */
    wrappedKeySz = sizeof(wrappedKey);
    ret =
        wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID, srcKey,
                          sizeof(srcKey), &wrapMeta, wrappedKey, &wrappedKeySz);
    if (ret != 0) {
        WH_ERROR_PRINT("trusted-kek: KeyWrap (plain KEK) failed %d\n", ret);
        (void)wh_Client_KeyEvict(client, srcKeyId);
        return ret;
    }
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, WH_TEST_KEKID,
                                      wrappedKey, wrappedKeySz, &wrappedKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: unwrap-and-cache with plain KEK expected "
                       "ACCESS, got %d\n",
                       ret);
        (void)wh_Client_KeyEvict(client, srcKeyId);
        return WH_TEST_FAIL;
    }

    /* (b) A client provisioning an NVM object with WH_NVM_FLAGS_TRUSTED
     * at a crypto key ID must not obtain a trusted KEK. */
    {
        whKeyId nvmForgeId    = WH_TEST_KEKID + 2;
        whNvmId nvmObjId      = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO,
                                              client->comm->client_id, nvmForgeId);
        int32_t nvmRc         = 0;
        int32_t expectedAddRc = 0;
        int     expectedRc;

#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
        expectedAddRc = WH_ERROR_BADARGS;
#endif

        ret = wh_Client_NvmAddObject(
            client, nvmObjId, WH_NVM_ACCESS_ANY,
            WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, sizeof(label),
            label, sizeof(srcKey), srcKey, &nvmRc);
        if (ret != 0 || nvmRc != expectedAddRc) {
            WH_ERROR_PRINT("trusted-kek: NvmAddObject expected rc=%d, got "
                           "ret=%d rc=%d\n",
                           (int)expectedAddRc, ret, (int)nvmRc);
            (void)wh_Client_KeyEvict(client, srcKeyId);
            return (ret != 0) ? ret : WH_TEST_FAIL;
        }
        wrappedKeySz = sizeof(wrappedKey);
        ret = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                      WH_KEYTYPE_CRYPTO, nvmForgeId, wrappedKey,
                                      &wrappedKeySz);
        {
            int32_t destroyRc = 0;
            (void)wh_Client_NvmDestroyObjects(client, 1, &nvmObjId, &destroyRc);
        }
#ifdef WOLFHSM_CFG_LEGACY_CLIENT_NVM
        /* In legacy flat ID mode, TRUSTED flag is stripped on add */
        expectedRc = WH_ERROR_ACCESS;
#else
        /* In translated mode, adding with crypto key type is rejected */
        expectedRc = WH_ERROR_NOTFOUND;
#endif
        if (ret != expectedRc) {
            WH_ERROR_PRINT("trusted-kek: wrap-export with NVM-forged KEK "
                           "expected %d, got %d\n",
                           expectedRc, ret);
            (void)wh_Client_KeyEvict(client, srcKeyId);
            return WH_TEST_FAIL;
        }
    }

#ifdef HAVE_HKDF
    /* (c) A client that derives a key with HKDF and asks for it to be cached
     * carrying WH_NVM_FLAGS_TRUSTED must not obtain a trusted KEK: the crypto
     * cache-import path strips the flag too. HKDF is deterministic over the
     * client-supplied inputs, so the client knows the derived bytes; without
     * the strip it could wrap-export a server secret under a KEK it can
     * reproduce locally. */
    {
        whKeyId       hkdfKekId                   = WH_KEYID_ERASED;
        const uint8_t hkdfIkm[]                   = "trusted-kek hkdf ikm";
        uint8_t       hkdfLabel[WH_NVM_LABEL_LEN] = "TrustedKek hkdf";

        ret = wh_Client_HkdfMakeCacheKey(
            client, WC_SHA256, WH_KEYID_ERASED, hkdfIkm,
            (uint32_t)sizeof(hkdfIkm), NULL, 0, NULL, 0, &hkdfKekId,
            WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, hkdfLabel,
            (uint32_t)sizeof(hkdfLabel), WH_TEST_AES_KEYSIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("trusted-kek: HKDF cache-key make failed %d\n", ret);
            (void)wh_Client_KeyEvict(client, srcKeyId);
            return ret;
        }
        wrappedKeySz = sizeof(wrappedKey);
        ret = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                      WH_KEYTYPE_CRYPTO, hkdfKekId, wrappedKey,
                                      &wrappedKeySz);
        (void)wh_Client_KeyEvict(client, hkdfKekId);
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("trusted-kek: wrap-export with HKDF-derived KEK "
                           "expected ACCESS, got %d\n",
                           ret);
            (void)wh_Client_KeyEvict(client, srcKeyId);
            return WH_TEST_FAIL;
        }
    }
#endif /* HAVE_HKDF */

    /* (d) A client that sets WH_NVM_FLAGS_TRUSTED in its own cache request
     * must not obtain a trusted KEK: the server strips the flag, so using
     * the key as a KEK for wrap-export is still refused. */
    ret = wh_Client_KeyCache(
        client, WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, label,
        (uint16_t)sizeof(label), srcKey, sizeof(srcKey), &forgeId);
    if (ret != 0) {
        WH_ERROR_PRINT("trusted-kek: cache forged KEK failed %d\n", ret);
        (void)wh_Client_KeyEvict(client, srcKeyId);
        return ret;
    }
    wrappedKeySz = sizeof(wrappedKey);
    ret          = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                           WH_KEYTYPE_CRYPTO, forgeId, wrappedKey,
                                           &wrappedKeySz);
    (void)wh_Client_KeyEvict(client, forgeId);
    (void)wh_Client_KeyEvict(client, srcKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: wrap-export with client-flagged KEK "
                       "expected ACCESS, got %d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    return WH_ERROR_OK;
}

static int _AesGcm_TestDataWrap(whClientContext* client)
{
    int     ret                                           = 0;
    uint8_t data[]                                        = "Example data spanning several AES blocks to catch overlap bugs!";
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

    /* Negative: data wrap requires USAGE_WRAP on the KEK, like the key
     * operations. A key without it must be refused with WH_ERROR_USAGE. */
    {
        whKeyId  noWrapId = WH_TEST_KEKID + 3;
        uint8_t  noWrapKey[WH_TEST_AES_KEYSIZE];
        uint8_t  nwLabel[WH_NVM_LABEL_LEN] = "DataWrap NoWrap";
        uint32_t nwSz                      = sizeof(wrappedData);

        memset(noWrapKey, 0x5c, sizeof(noWrapKey));
        ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT, nwLabel,
                                 sizeof(nwLabel), noWrapKey, sizeof(noWrapKey),
                                 &noWrapId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to cache non-WRAP key %d\n", ret);
            return ret;
        }
        ret = wh_Client_DataWrap(client, WC_CIPHER_AES_GCM, noWrapId, data,
                                 sizeof(data), wrappedData, &nwSz);
        (void)wh_Client_KeyEvict(client, noWrapId);
        if (ret != WH_ERROR_USAGE) {
            WH_ERROR_PRINT(
                "DataWrap under non-WRAP KEK expected USAGE, got %d\n", ret);
            return WH_ERROR_ABORTED;
        }
    }

    return WH_ERROR_OK;
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
    /* Positive software-KEK round trip, runs in every build. */
    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestSwKekRoundTrip(client, rng);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestSwKekRoundTrip %d\n", ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestKeyUnwrapUnderflow(client);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestKeyUnwrapUnderflow %d\n",
                           ret);
        }
    }

    if (ret == WH_ERROR_OK) {
        ret = _AesGcm_TestTrustedKekPolicy(client, rng);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to _AesGcm_TestTrustedKekPolicy %d\n", ret);
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
    /* Attempt log in as an admin user for the rest of the tests. The server
     * may not support auth, so do not require the login itself to succeed. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_AuthLogin(
        client, WH_AUTH_METHOD_PIN, TEST_ADMIN_USERNAME, TEST_ADMIN_PIN,
        strlen(TEST_ADMIN_PIN), &ret, NULL));
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
