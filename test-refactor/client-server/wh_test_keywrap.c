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
 * test-refactor/client-server/wh_test_keywrap.c
 *
 * Keywrap policy and input-validation coverage that runs against any server:
 * the negatives prove a client cannot mint a trusted KEK or slip an
 * undersized blob past the size checks.
 *   _whTest_KeywrapTrustedKekPolicy - wrap-export and unwrap-and-cache must
 *                                    refuse a plain client KEK, and a client
 *                                    cannot forge WH_NVM_FLAGS_TRUSTED via the
 *                                    NVM add, HKDF cache, key cache, or key
 *                                    cache-random paths
 *   _whTest_KeywrapDataWrapUsage   - data wrap requires USAGE_WRAP on the KEK
 *   _whTest_KeywrapKeyUnwrapUnderflow - undersized wrapped-key blobs must
 *                                    return WH_ERROR_BADARGS, not underflow
 *   _whTest_KeywrapDataUnwrapUnderflow - undersized wrapped-data blobs must
 *                                    return WH_ERROR_BADARGS, not underflow
 *   _whTest_KeywrapOversizeRequest - payloads past the configured maximum must
 *                                    be refused before any copy
 *
 * The positive wrap/unwrap-and-export round trip under a plain client KEK
 * lives in wh_test_crypto_keywrap.c. The trusted-KEK positive paths
 * (wrap-export round-trip, unwrap-and-cache) live in
 * misc/wh_test_hwkeystore.c against the hardware KEK, and in
 * misc/wh_test_multiclient.c against an NVM-provisioned KEK.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_KEYWRAP) && \
    !defined(NO_AES) && defined(HAVE_AESGCM)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/kdf.h" /* for HKDF and WC_SHA256 */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_keystore.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define WH_TEST_KW_KEYSIZE 32
#define WH_TEST_KW_WRAPPED_KEYSIZE                         \
    (WH_KEYWRAP_AES_GCM_HEADER_SIZE + WH_TEST_KW_KEYSIZE + \
     sizeof(whNvmMetadata))

/* One byte past the configured maximum. The comm data buffer always has room
 * for the maximum plus its header, so this is the binding limit */
#define WH_TEST_KW_OVER_KEY (WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE + 1)
#define WH_TEST_KW_OVER_DATA (WOLFHSM_CFG_KEYWRAP_MAX_DATA_SIZE + 1)

/* Distinct id range so nothing collides with other client-group suites; every
 * subtest cleans up its own keys */
#define WH_TEST_KW_SWKEK_ID 0x60
#define WH_TEST_KW_SRC_ID 0x61
#define WH_TEST_KW_CACHE_FORGE_ID 0x62
#define WH_TEST_KW_NVM_FORGE_ID 0x63
#define WH_TEST_KW_NOWRAP_ID 0x64
#define WH_TEST_KW_META_ID 0x65
#define WH_TEST_KW_RAND_FORGE_ID 0x66

/* Cache a plain software KEK with wrap usage. It is an ordinary client key:
 * good enough for KeyWrap/KeyUnwrapAndExport, never for the trusted-KEK
 * operations */
static int _CacheSwKek(whClientContext* client, whKeyId* outKekId)
{
    whKeyId kekId                   = WH_TEST_KW_SWKEK_ID;
    uint8_t label[WH_NVM_LABEL_LEN] = "KW sw KEK";
    uint8_t kek[WH_TEST_KW_KEYSIZE];
    size_t  i;

    for (i = 0; i < sizeof(kek); i++) {
        kek[i] = (uint8_t)(0xC2 ^ i);
    }
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_WRAP,
                                              label, (uint16_t)sizeof(label),
                                              kek, sizeof(kek), &kekId));
    *outKekId = kekId;
    return WH_ERROR_OK;
}

/* The wrap-export and unwrap-and-cache operations require a trusted KEK (HW or
 * WH_NVM_FLAGS_TRUSTED). Prove that (a) a plain client-cached USAGE_WRAP key is
 * refused as their KEK, and that a client cannot forge a trusted KEK by
 * setting WH_NVM_FLAGS_TRUSTED itself through (b) the checked NVM add path, (c)
 * the HKDF cache-import path, (d) the key cache path, or (e) the cache-random
 * path -- the server strips the flag on each, so the key is still refused */
static int _whTest_KeywrapTrustedKekPolicy(whClientContext* client)
{
    int           ret;
    whKeyId       kekId       = WH_KEYID_ERASED;
    whKeyId       srcKeyId    = WH_TEST_KW_SRC_ID;
    whKeyId       forgeId     = WH_TEST_KW_CACHE_FORGE_ID;
    whKeyId       randForgeId = WH_TEST_KW_RAND_FORGE_ID;
    uint8_t       srcKey[WH_TEST_KW_KEYSIZE];
    uint8_t       label[WH_NVM_LABEL_LEN] = "TrustedKek key";
    uint8_t       wrappedKey[WH_TEST_KW_WRAPPED_KEYSIZE];
    uint16_t      wrappedKeySz = sizeof(wrappedKey);
    uint16_t      wrappedKeyId = WH_KEYID_ERASED;
    whNvmMetadata wrapMeta     = {0};
    size_t        i;

    wrapMeta.id    = WH_CLIENT_KEYID_MAKE_WRAPPED_META(client->comm->client_id,
                                                       WH_TEST_KW_META_ID);
    wrapMeta.len   = WH_TEST_KW_KEYSIZE;
    wrapMeta.flags = WH_NVM_FLAGS_USAGE_ANY;
    memcpy(wrapMeta.label, "TrustedKek blob", sizeof("TrustedKek blob"));

    for (i = 0; i < sizeof(srcKey); i++) {
        srcKey[i] = (uint8_t)(0x19 ^ i);
    }

    WH_TEST_RETURN_ON_FAIL(_CacheSwKek(client, &kekId));

    /* Cache an ordinary, exportable source key to try to wrap-export */
    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, label,
                             (uint16_t)sizeof(label), srcKey, sizeof(srcKey),
                             &srcKeyId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("trusted-kek: cache src failed %d\n", ret);
        (void)wh_Client_KeyEvict(client, kekId);
        return ret;
    }

    /* (a) wrap-export under a plain client KEK must be refused */
    ret = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                  WH_KEYTYPE_CRYPTO, kekId, wrappedKey,
                                  &wrappedKeySz);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: wrap-export with plain KEK expected "
                       "ACCESS, got %d\n",
                       ret);
        ret = WH_ERROR_ABORTED;
        goto cleanup;
    }

    /* (a) unwrap-and-cache under a plain client KEK must be refused. Build a
     * correctly sized blob under the same plain KEK (KeyWrap itself does not
     * require a trusted KEK); the trusted-KEK check rejects the cache attempt
     * before authentication */
    wrappedKeySz = sizeof(wrappedKey);
    ret =
        wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, kekId, srcKey,
                          sizeof(srcKey), &wrapMeta, wrappedKey, &wrappedKeySz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("trusted-kek: KeyWrap (plain KEK) failed %d\n", ret);
        goto cleanup;
    }
    ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                      wrappedKey, wrappedKeySz, &wrappedKeyId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: unwrap-and-cache with plain KEK expected "
                       "ACCESS, got %d\n",
                       ret);
        ret = WH_ERROR_ABORTED;
        goto cleanup;
    }

    /* (b) A client that provisions an NVM object carrying
     * WH_NVM_FLAGS_TRUSTED at a crypto-key id must not obtain a trusted KEK
     * either. The forged id embeds the client id in the USER bits, which
     * overlap the client WRAPPED/HW flag bits, so depending on the client id
     * the checked add either rejects the id outright or stores the object
     * outside the crypto-key id space; either way no KEK may appear at the
     * crypto-key id. */
    {
        whNvmId nvmObjId =
            WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, client->comm->client_id,
                          WH_TEST_KW_NVM_FORGE_ID);
        int32_t nvmRc         = 0;
        int32_t expectedAddRc = 0;
        int     expectedRc;

#ifndef WOLFHSM_CFG_LEGACY_CLIENT_NVM
        if ((nvmObjId &
             (WH_KEYID_CLIENT_WRAPPED_FLAG | WH_KEYID_CLIENT_HW_FLAG)) != 0) {
            /* Forged id aliases a client flag bit; the checked add rejects
             * it before storing anything. */
            expectedAddRc = WH_ERROR_BADARGS;
        }
#ifndef WOLFHSM_CFG_GLOBAL_KEYS
        if ((nvmObjId & WH_KEYID_CLIENT_GLOBAL_FLAG) != 0) {
            /* Without global keys an aliased GLOBAL bit is rejected too */
            expectedAddRc = WH_ERROR_BADARGS;
        }
#endif
#endif

        ret = wh_Client_NvmAddObject(
            client, nvmObjId, WH_NVM_ACCESS_ANY,
            WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, sizeof(label),
            label, sizeof(srcKey), srcKey, &nvmRc);
        if (ret != 0 || nvmRc != expectedAddRc) {
            WH_ERROR_PRINT("trusted-kek: NvmAddObject expected rc=%d, got "
                           "ret=%d rc=%d\n",
                           (int)expectedAddRc, ret, (int)nvmRc);
            ret = (ret != 0) ? ret : WH_ERROR_ABORTED;
            goto cleanup;
        }
        wrappedKeySz = sizeof(wrappedKey);
        ret          = wh_Client_KeyWrapExport(
            client, WC_CIPHER_AES_GCM, srcKeyId, WH_KEYTYPE_CRYPTO,
            WH_TEST_KW_NVM_FORGE_ID, wrappedKey, &wrappedKeySz);
        {
            int32_t destroyRc = 0;
            (void)wh_Client_NvmDestroyObjects(client, 1, &nvmObjId, &destroyRc);
        }
#ifdef WOLFHSM_CFG_LEGACY_CLIENT_NVM
        /* Legacy flat id space: the forged object lands at the crypto-key
         * id; the checked NVM add stripped the TRUSTED flag, so KEK use is
         * refused. */
        expectedRc = WH_ERROR_ACCESS;
#else
        /* An accepted forge is stored as a plain NVM object in the caller's
         * namespace and a rejected one stores nothing, so no KEK exists at
         * the crypto-key id either way. */
        expectedRc = WH_ERROR_NOTFOUND;
#endif
        if (ret != expectedRc) {
            WH_ERROR_PRINT("trusted-kek: wrap-export with NVM-forged KEK "
                           "expected %d, got %d\n",
                           expectedRc, ret);
            ret = WH_ERROR_ABORTED;
            goto cleanup;
        }
    }

#ifdef HAVE_HKDF
    /* (c) A client that derives a key with HKDF and asks for it to be cached
     * carrying WH_NVM_FLAGS_TRUSTED must not obtain a trusted KEK: the crypto
     * cache-import path strips the flag too. HKDF is deterministic over the
     * client-supplied inputs, so the client knows the derived bytes; without
     * the strip it could wrap-export a server secret under a KEK it can
     * reproduce locally */
    {
        whKeyId       hkdfKekId                   = WH_KEYID_ERASED;
        const uint8_t hkdfIkm[]                   = "trusted-kek hkdf ikm";
        uint8_t       hkdfLabel[WH_NVM_LABEL_LEN] = "TrustedKek hkdf";

        ret = wh_Client_HkdfMakeCacheKey(
            client, WC_SHA256, WH_KEYID_ERASED, hkdfIkm,
            (uint32_t)sizeof(hkdfIkm), NULL, 0, NULL, 0, &hkdfKekId,
            WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, hkdfLabel,
            (uint32_t)sizeof(hkdfLabel), WH_TEST_KW_KEYSIZE);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("trusted-kek: HKDF cache-key make failed %d\n", ret);
            goto cleanup;
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
            ret = WH_ERROR_ABORTED;
            goto cleanup;
        }
    }
#endif /* HAVE_HKDF */

    /* (d) A client that sets WH_NVM_FLAGS_TRUSTED in its own cache request must
     * not obtain a trusted KEK: the server strips the flag, so using the key
     * as a KEK for wrap-export is still refused */
    ret = wh_Client_KeyCache(
        client, WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, label,
        (uint16_t)sizeof(label), srcKey, sizeof(srcKey), &forgeId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("trusted-kek: cache forged KEK failed %d\n", ret);
        goto cleanup;
    }
    wrappedKeySz = sizeof(wrappedKey);
    ret          = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                           WH_KEYTYPE_CRYPTO, forgeId, wrappedKey,
                                           &wrappedKeySz);
    (void)wh_Client_KeyEvict(client, forgeId);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: wrap-export with client-flagged KEK "
                       "expected ACCESS, got %d\n",
                       ret);
        ret = WH_ERROR_ABORTED;
        goto cleanup;
    }

    /* (e) Same forgery through the cache-random path, where the server picks
     * the key material. The evict must succeed too: an unstripped TRUSTED flag
     * freezes the slot against every client op, evict included */
    ret = wh_Client_KeyCacheRandom(
        client, WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP, label,
        (uint16_t)sizeof(label), WH_TEST_KW_KEYSIZE, &randForgeId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("trusted-kek: cache-random forged KEK failed %d\n", ret);
        goto cleanup;
    }
    wrappedKeySz = sizeof(wrappedKey);
    ret = wh_Client_KeyWrapExport(client, WC_CIPHER_AES_GCM, srcKeyId,
                                  WH_KEYTYPE_CRYPTO, randForgeId, wrappedKey,
                                  &wrappedKeySz);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("trusted-kek: wrap-export with cache-random KEK "
                       "expected ACCESS, got %d\n",
                       ret);
        (void)wh_Client_KeyEvict(client, randForgeId);
        ret = WH_ERROR_ABORTED;
        goto cleanup;
    }
    ret = wh_Client_KeyEvict(client, randForgeId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("trusted-kek: evict cache-random KEK expected OK, got "
                       "%d\n",
                       ret);
        ret = WH_ERROR_ABORTED;
        goto cleanup;
    }
    ret = WH_ERROR_OK;

cleanup:
    (void)wh_Client_KeyEvict(client, srcKeyId);
    (void)wh_Client_KeyEvict(client, kekId);
    return ret;
}

/* Data wrap requires USAGE_WRAP on the KEK, like the key operations: a
 * USAGE_WRAP KEK round-trips data, a key without it is refused with
 * WH_ERROR_USAGE */
static int _whTest_KeywrapDataWrapUsage(whClientContext* client)
{
    int      ret;
    whKeyId  kekId                       = WH_KEYID_ERASED;
    uint8_t  data[]                      = "Example data!";
    uint8_t  unwrappedData[sizeof(data)] = {0};
    uint32_t unwrappedDataSz             = sizeof(unwrappedData);
    uint8_t  wrappedData[sizeof(data) + WH_KEYWRAP_AES_GCM_HEADER_SIZE] = {0};
    uint32_t wrappedDataSz = sizeof(wrappedData);

    WH_TEST_RETURN_ON_FAIL(_CacheSwKek(client, &kekId));

    ret = wh_Client_DataWrap(client, WC_CIPHER_AES_GCM, kekId, data,
                             sizeof(data), wrappedData, &wrappedDataSz);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_DataWrap %d\n", ret);
        (void)wh_Client_KeyEvict(client, kekId);
        return ret;
    }

    ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, kekId, wrappedData,
                               wrappedDataSz, unwrappedData, &unwrappedDataSz);
    (void)wh_Client_KeyEvict(client, kekId);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("Failed to wh_Client_DataUnwrap %d\n", ret);
        return ret;
    }

    if (memcmp(data, unwrappedData, sizeof(data)) != 0) {
        WH_ERROR_PRINT("unwrapped data does not match input data\n");
        return WH_ERROR_ABORTED;
    }

    /* Negative: a KEK without USAGE_WRAP must be refused with WH_ERROR_USAGE */
    {
        whKeyId  noWrapId = WH_TEST_KW_NOWRAP_ID;
        uint8_t  noWrapKey[WH_TEST_KW_KEYSIZE];
        uint8_t  nwLabel[WH_NVM_LABEL_LEN] = "DataWrap NoWrap";
        uint32_t nwSz                      = sizeof(wrappedData);

        memset(noWrapKey, 0x5c, sizeof(noWrapKey));
        ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT, nwLabel,
                                 (uint16_t)sizeof(nwLabel), noWrapKey,
                                 sizeof(noWrapKey), &noWrapId);
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

/* A wrapped blob smaller than its own header must be refused with
 * WH_ERROR_BADARGS rather than underflowing the payload length. A usable KEK
 * is cached first so the rejection can only come from the size check, not
 * from KEK resolution */
static int _whTest_KeywrapKeyUnwrapUnderflow(whClientContext* client)
{
    const uint16_t shortSizes[] = {0, 1};
    int            ret          = WH_ERROR_OK;
    whKeyId        kekId        = WH_KEYID_ERASED;
    uint8_t        blob[1]      = {0};
    size_t         i;

    WH_TEST_RETURN_ON_FAIL(_CacheSwKek(client, &kekId));

    for (i = 0; i < sizeof(shortSizes) / sizeof(shortSizes[0]); i++) {
        whNvmMetadata meta                       = {0};
        uint8_t       keyOut[WH_TEST_KW_KEYSIZE] = {0};
        uint16_t      keyOutSz                   = sizeof(keyOut);
        uint16_t      cachedId                   = WH_KEYID_ERASED;

        ret = wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, kekId,
                                           blob, shortSizes[i], &meta, keyOut,
                                           &keyOutSz);
        if (ret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("KeyUnwrapAndExport(sz=%u) expected BADARGS, "
                           "got %d\n",
                           (unsigned)shortSizes[i], ret);
            ret = WH_ERROR_ABORTED;
            break;
        }

        ret = wh_Client_KeyUnwrapAndCache(client, WC_CIPHER_AES_GCM, kekId,
                                          blob, shortSizes[i], &cachedId);
        if (ret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("KeyUnwrapAndCache(sz=%u) expected BADARGS, "
                           "got %d\n",
                           (unsigned)shortSizes[i], ret);
            ret = WH_ERROR_ABORTED;
            break;
        }
        ret = WH_ERROR_OK;
    }

    (void)wh_Client_KeyEvict(client, kekId);
    return ret;
}

/* Same underflow guard on the opaque data path */
static int _whTest_KeywrapDataUnwrapUnderflow(whClientContext* client)
{
    const uint32_t shortSizes[] = {0, 1};
    int            ret          = WH_ERROR_OK;
    whKeyId        kekId        = WH_KEYID_ERASED;
    uint8_t        blob[1]      = {0};
    size_t         i;

    WH_TEST_RETURN_ON_FAIL(_CacheSwKek(client, &kekId));

    for (i = 0; i < sizeof(shortSizes) / sizeof(shortSizes[0]); i++) {
        uint8_t  dataOut[WH_TEST_KW_KEYSIZE] = {0};
        uint32_t dataOutSz                   = sizeof(dataOut);

        ret = wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, kekId, blob,
                                   shortSizes[i], dataOut, &dataOutSz);
        if (ret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("DataUnwrap(sz=%u) expected BADARGS, got %d\n",
                           (unsigned)shortSizes[i], ret);
            ret = WH_ERROR_ABORTED;
            break;
        }
        ret = WH_ERROR_OK;
    }

    (void)wh_Client_KeyEvict(client, kekId);
    return ret;
}

/* Report whether an oversize request was rejected as expected */
static int _CheckOversizeRejected(const char* what, int ret)
{
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("%s oversize expected BADARGS, got %d\n", what, ret);
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/* A payload past the configured maximum must be refused before any copy. The
 * input buffer stays small on purpose: a builder that copied first would read
 * off the end of it and trip ASan */
static int _whTest_KeywrapOversizeRequest(whClientContext* client)
{
    int           ret                             = WH_ERROR_OK;
    whKeyId       kekId                           = WH_KEYID_ERASED;
    whNvmMetadata meta                            = {0};
    uint16_t      cachedId                        = WH_KEYID_ERASED;
    uint8_t       in[WH_TEST_KW_KEYSIZE]          = {0};
    uint8_t       out[WH_TEST_KW_WRAPPED_KEYSIZE] = {0};
    uint16_t      keyOutSz                        = (uint16_t)sizeof(out);
    uint32_t      dataOutSz                       = (uint32_t)sizeof(out);

    WH_TEST_RETURN_ON_FAIL(_CacheSwKek(client, &kekId));

    ret = _CheckOversizeRejected(
        "KeyWrap", wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, kekId, in,
                                     (uint16_t)WH_TEST_KW_OVER_KEY, &meta, out,
                                     &keyOutSz));

    if (ret == WH_ERROR_OK) {
        ret = _CheckOversizeRejected(
            "KeyUnwrapAndExport",
            wh_Client_KeyUnwrapAndExport(client, WC_CIPHER_AES_GCM, kekId, in,
                                         (uint16_t)WH_TEST_KW_OVER_KEY, &meta,
                                         out, &keyOutSz));
    }

    if (ret == WH_ERROR_OK) {
        ret = _CheckOversizeRejected(
            "KeyUnwrapAndCache", wh_Client_KeyUnwrapAndCache(
                                     client, WC_CIPHER_AES_GCM, kekId, in,
                                     (uint16_t)WH_TEST_KW_OVER_KEY, &cachedId));
    }

    if (ret == WH_ERROR_OK) {
        ret = _CheckOversizeRejected(
            "DataWrap",
            wh_Client_DataWrap(client, WC_CIPHER_AES_GCM, kekId, in,
                               WH_TEST_KW_OVER_DATA, out, &dataOutSz));
    }

    if (ret == WH_ERROR_OK) {
        ret = _CheckOversizeRejected(
            "DataUnwrap",
            wh_Client_DataUnwrap(client, WC_CIPHER_AES_GCM, kekId, in,
                                 WH_TEST_KW_OVER_DATA, out, &dataOutSz));
    }

    (void)wh_Client_KeyEvict(client, kekId);
    return ret;
}

int whTest_KeyWrap(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_KeywrapTrustedKekPolicy(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeywrapDataWrapUsage(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeywrapKeyUnwrapUnderflow(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeywrapDataUnwrapUnderflow(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_KeywrapOversizeRequest(ctx));

    WH_TEST_PRINT("KEYWRAP POLICY SUCCESS\n");
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_KEYWRAP && !NO_AES && \
          HAVE_AESGCM */
