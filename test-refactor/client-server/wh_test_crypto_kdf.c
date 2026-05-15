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
 * test-refactor/client-server/wh_test_crypto_kdf.c
 *
 * HKDF (RFC 5869) and CMAC-KDF (NIST SP 800-108 / SP 800-56C two-step) routed
 * through the server. Each test exercises three paths: the wolfCrypt API
 * dispatched via the cryptocb, wh_Client_*MakeExportKey returning the derived
 * key to the client, and wh_Client_*MakeCacheKey caching the derived key on
 * the server (verified by exporting and comparing). Each KDF also has a
 * cached-input variant where the raw key material is first cached and then
 * referenced by key id.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/kdf.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef HAVE_HKDF
#define WH_TEST_HKDF_IKM_SIZE 22
#define WH_TEST_HKDF_SALT_SIZE 13
#define WH_TEST_HKDF_INFO_SIZE 10
#define WH_TEST_HKDF_OKM_SIZE 42

static int _whTest_CryptoHkdf(whClientContext* ctx)
{
    int     devId = WH_DEV_ID;
    int     ret   = WH_ERROR_OK;
    whKeyId keyId = WH_KEYID_ERASED;

    /* RFC 5869 Test Case 1 */
    const uint8_t ikm[WH_TEST_HKDF_IKM_SIZE]   = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const uint8_t salt[WH_TEST_HKDF_SALT_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04,
                                                  0x05, 0x06, 0x07, 0x08, 0x09,
                                                  0x0a, 0x0b, 0x0c};
    const uint8_t info[WH_TEST_HKDF_INFO_SIZE] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                                  0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    const uint8_t expected[WH_TEST_HKDF_OKM_SIZE] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    uint8_t okm[WH_TEST_HKDF_OKM_SIZE];
    uint8_t okm2[WH_TEST_HKDF_OKM_SIZE];
    uint8_t label[] = "HKDF Test Label";

    /* 1. wc_HKDF dispatched through the cryptocb */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
                     WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, okm,
                     WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_HKDF_ex: %d\n", ret);
        return ret;
    }
    if (memcmp(okm, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
        WH_ERROR_PRINT("HKDF output mismatch (wc_HKDF_ex)\n");
        return -1;
    }

    /* 2. wc_HKDF without salt -- no expected vector, just no error */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, NULL, 0, info,
                     WH_TEST_HKDF_INFO_SIZE, okm, WH_TEST_HKDF_OKM_SIZE, NULL,
                     devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_HKDF_ex (no salt): %d\n", ret);
        return ret;
    }

    /* 3. wc_HKDF without info */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
                     WH_TEST_HKDF_SALT_SIZE, NULL, 0, okm, WH_TEST_HKDF_OKM_SIZE,
                     NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_HKDF_ex (no info): %d\n", ret);
        return ret;
    }

    /* 4. wh_Client_HkdfMakeExportKey */
    memset(okm, 0, sizeof(okm));
    ret = wh_Client_HkdfMakeExportKey(
        ctx, WC_SHA256, WH_KEYID_ERASED, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
        WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, okm,
        WH_TEST_HKDF_OKM_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_HkdfMakeExportKey: %d\n", ret);
        return ret;
    }
    if (memcmp(okm, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
        WH_ERROR_PRINT("HKDF output mismatch (MakeExportKey)\n");
        return -1;
    }

    /* 5. wh_Client_HkdfMakeCacheKey -- derive into a cached key, then export
     *    it back to verify the server-side derivation. */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_HkdfMakeCacheKey(
          ctx, WC_SHA256, WH_KEYID_ERASED, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
          WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, &keyId,
          WH_NVM_FLAGS_NONE, label, sizeof(label), WH_TEST_HKDF_OKM_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_HkdfMakeCacheKey: %d\n", ret);
        return ret;
    }
    if (keyId == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("HKDF cache did not return a key id\n");
        return -1;
    }
    {
        uint8_t  exportLabel[sizeof(label)] = {0};
        uint16_t exportLen                  = WH_TEST_HKDF_OKM_SIZE;
        memset(okm2, 0, sizeof(okm2));
        ret = wh_Client_KeyExport(ctx, keyId, exportLabel, sizeof(exportLabel),
                                  okm2, &exportLen);
        if (ret == 0 && exportLen != WH_TEST_HKDF_OKM_SIZE) {
            WH_ERROR_PRINT("HKDF exported length mismatch: %u != %u\n",
                           exportLen, WH_TEST_HKDF_OKM_SIZE);
            ret = -1;
        }
        if (ret == 0 && memcmp(okm2, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
            WH_ERROR_PRINT("HKDF output mismatch (MakeCacheKey)\n");
            ret = -1;
        }
    }
    (void)wh_Client_KeyEvict(ctx, keyId);
    if (ret != 0) {
        return ret;
    }

    /* 6. HKDF with a cached input key id -- derives the same OKM as direct
     *    buffers when the IKM lives in the keystore. */
    {
        whKeyId       keyIdIn      = WH_KEYID_ERASED;
        uint8_t       label_in[]   = "input-key";
        const uint8_t ikm2[]       = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                                      0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
                                      0x3E, 0x3F};
        const uint8_t salt2[]      = {0xB0, 0xB1, 0xB2, 0xB3};
        const uint8_t info2[]      = {0xC0, 0xC1, 0xC2};
        uint8_t       okmCached[WH_TEST_HKDF_OKM_SIZE];
        uint8_t       okmDirect[WH_TEST_HKDF_OKM_SIZE];

        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_DERIVE, label_in,
                                 sizeof(label_in), (uint8_t*)ikm2, sizeof(ikm2),
                                 &keyIdIn);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache HKDF input key: %d\n", ret);
            return ret;
        }

        memset(okmCached, 0, sizeof(okmCached));
        ret = wh_Client_HkdfMakeExportKey(
            ctx, WC_SHA256, keyIdIn, NULL, 0, salt2, sizeof(salt2), info2,
            sizeof(info2), okmCached, sizeof(okmCached));
        if (ret == 0) {
            memset(okmDirect, 0, sizeof(okmDirect));
            ret = wh_Client_HkdfMakeExportKey(
                ctx, WC_SHA256, WH_KEYID_ERASED, ikm2, sizeof(ikm2), salt2,
                sizeof(salt2), info2, sizeof(info2), okmDirect,
                sizeof(okmDirect));
        }
        if (ret == 0 &&
            memcmp(okmCached, okmDirect, sizeof(okmCached)) != 0) {
            WH_ERROR_PRINT("HKDF mismatch (cached vs direct input key)\n");
            ret = -1;
        }
        (void)wh_Client_KeyEvict(ctx, keyIdIn);
        if (ret != 0) {
            return ret;
        }
    }

    WH_TEST_PRINT("HKDF DEVID=0x%X SUCCESS\n", devId);
    return 0;
}
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
#define WH_TEST_CMAC_KDF_SALT_SIZE 24
#define WH_TEST_CMAC_KDF_Z_SIZE 32
#define WH_TEST_CMAC_KDF_FIXED_INFO_SIZE 60
#define WH_TEST_CMAC_KDF_OUT_SIZE 40

static int _whTest_CryptoCmacKdf(whClientContext* ctx)
{
    int     devId = WH_DEV_ID;
    int     ret   = WH_ERROR_OK;
    whKeyId keyId = WH_KEYID_ERASED;

    /* NIST SP 800-108 KDF in Counter Mode using CMAC -- vectors from the
     * wolfSSL CMAC KDF implementation tests. */
    static const uint8_t salt[WH_TEST_CMAC_KDF_SALT_SIZE] = {
        0x20, 0x51, 0xaf, 0x34, 0x76, 0x2e, 0xbe, 0x55, 0x6f, 0x72, 0xa5, 0xc6,
        0xed, 0xc7, 0x77, 0x1e, 0xb9, 0x24, 0x5f, 0xad, 0x76, 0xf0, 0x34, 0xbe};
    static const uint8_t z[WH_TEST_CMAC_KDF_Z_SIZE] = {
        0xae, 0x8e, 0x93, 0xc9, 0xc9, 0x91, 0xcf, 0x89, 0x6a, 0x49, 0x1a,
        0x89, 0x07, 0xdf, 0x4e, 0x4b, 0xe5, 0x18, 0x6a, 0xe4, 0x96, 0xcd,
        0x34, 0x0d, 0xc1, 0x9b, 0x23, 0x78, 0x21, 0xdb, 0x7b, 0x60};
    static const uint8_t fixedInfo[WH_TEST_CMAC_KDF_FIXED_INFO_SIZE] = {
        0xa2, 0x59, 0xca, 0xe2, 0xc4, 0xa3, 0x6b, 0x89, 0x56, 0x3c, 0xb1, 0x48,
        0xc7, 0x82, 0x51, 0x34, 0x3b, 0xbf, 0xab, 0xdc, 0x13, 0xca, 0x7a, 0xc2,
        0x17, 0x1c, 0x2e, 0xb6, 0x02, 0x1f, 0x44, 0x77, 0xfe, 0xa3, 0x3b, 0x28,
        0x72, 0x4d, 0xa7, 0x21, 0xee, 0x08, 0x7b, 0xff, 0xd7, 0x94, 0xa1, 0x56,
        0x37, 0x54, 0xb4, 0x25, 0xa8, 0xd0, 0x9b, 0x3e, 0x0d, 0xa5, 0xff, 0xed};
    static const uint8_t expected[WH_TEST_CMAC_KDF_OUT_SIZE] = {
        0xb4, 0x0c, 0x32, 0xbe, 0x01, 0x27, 0x93, 0xba, 0xfd, 0xf7,
        0x78, 0xc5, 0xf4, 0x54, 0x43, 0xf4, 0xc9, 0x71, 0x23, 0x93,
        0x17, 0x63, 0xd8, 0x3a, 0x59, 0x27, 0x07, 0xbf, 0xf2, 0xd3,
        0x60, 0x59, 0x50, 0x27, 0x29, 0xca, 0xb8, 0x8b, 0x29, 0x38};

    uint8_t  out[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  exported[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  exportLabel[12] = {0};
    uint16_t exportLen;
    uint8_t  keyLabel[]      = "CMAC KDF Key";

    /* 1. Direct wolfCrypt API dispatched via the cryptocb */
    memset(out, 0, sizeof(out));
    ret = wc_KDA_KDF_twostep_cmac(salt, WH_TEST_CMAC_KDF_SALT_SIZE, z,
                                  WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo,
                                  WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, out,
                                  WH_TEST_CMAC_KDF_OUT_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_KDA_KDF_twostep_cmac: %d\n", ret);
        return ret;
    }
    if (memcmp(out, expected, sizeof(out)) != 0) {
        WH_ERROR_PRINT("CMAC KDF mismatch (direct wolfCrypt)\n");
        return -1;
    }

    /* 2. Client export with direct salt and Z */
    memset(out, 0, sizeof(out));
    ret = wh_Client_CmacKdfMakeExportKey(
        ctx, WH_KEYID_ERASED, salt, WH_TEST_CMAC_KDF_SALT_SIZE, WH_KEYID_ERASED,
        z, WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo, WH_TEST_CMAC_KDF_FIXED_INFO_SIZE,
        out, sizeof(out));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_CmacKdfMakeExportKey: %d\n", ret);
        return ret;
    }
    if (memcmp(out, expected, sizeof(out)) != 0) {
        WH_ERROR_PRINT("CMAC KDF mismatch (export key)\n");
        return -1;
    }

    /* 3. Client cache with direct salt and Z, then export to compare */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_CmacKdfMakeCacheKey(
          ctx, WH_KEYID_ERASED, salt, WH_TEST_CMAC_KDF_SALT_SIZE, WH_KEYID_ERASED,
          z, WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo, WH_TEST_CMAC_KDF_FIXED_INFO_SIZE,
          &keyId, WH_NVM_FLAGS_NONE, keyLabel, sizeof(keyLabel),
          WH_TEST_CMAC_KDF_OUT_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_CmacKdfMakeCacheKey: %d\n", ret);
        return ret;
    }
    if (keyId == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("CMAC KDF cache did not return a key id\n");
        return -1;
    }
    memset(exported, 0, sizeof(exported));
    exportLen = (uint16_t)sizeof(exported);
    ret = wh_Client_KeyExport(ctx, keyId, exportLabel, sizeof(exportLabel),
                              exported, &exportLen);
    if (ret == 0 &&
        (exportLen != WH_TEST_CMAC_KDF_OUT_SIZE ||
         memcmp(exported, expected, sizeof(exported)) != 0)) {
        WH_ERROR_PRINT("Exported CMAC KDF key mismatch\n");
        ret = -1;
    }
    (void)wh_Client_KeyEvict(ctx, keyId);
    if (ret != 0) {
        return ret;
    }

    /* 4. Cached salt and cached Z. Caches both inputs first, then derives by
     *    key id with NULL/0 raw buffers. Derives via both export and cache. */
    {
        whKeyId saltKeyId = WH_KEYID_ERASED;
        whKeyId zKeyId    = WH_KEYID_ERASED;

        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0,
                                 (uint8_t*)salt, WH_TEST_CMAC_KDF_SALT_SIZE,
                                 &saltKeyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache CMAC KDF salt: %d\n", ret);
            return ret;
        }
        ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0,
                                 (uint8_t*)z, WH_TEST_CMAC_KDF_Z_SIZE, &zKeyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache CMAC KDF Z: %d\n", ret);
            (void)wh_Client_KeyEvict(ctx, saltKeyId);
            return ret;
        }

        memset(out, 0, sizeof(out));
        ret = wh_Client_CmacKdfMakeExportKey(
            ctx, saltKeyId, NULL, 0, zKeyId, NULL, 0, fixedInfo,
            WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, out, sizeof(out));
        if (ret == 0 && memcmp(out, expected, sizeof(out)) != 0) {
            WH_ERROR_PRINT("CMAC KDF mismatch (cached inputs export)\n");
            ret = -1;
        }

        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_CmacKdfMakeCacheKey(
                  ctx, saltKeyId, NULL, 0, zKeyId, NULL, 0, fixedInfo,
                  WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, &keyId, WH_NVM_FLAGS_NONE,
                  keyLabel, sizeof(keyLabel), WH_TEST_CMAC_KDF_OUT_SIZE);
            if (ret == 0 && keyId == WH_KEYID_ERASED) {
                WH_ERROR_PRINT("CMAC KDF cache (cached inputs) returned no "
                               "key id\n");
                ret = -1;
            }
            if (ret == 0) {
                memset(exported, 0, sizeof(exported));
                exportLen = (uint16_t)sizeof(exported);
                ret       = wh_Client_KeyExport(ctx, keyId, exportLabel,
                                                sizeof(exportLabel), exported,
                                                &exportLen);
                if (ret == 0 &&
                    (exportLen != WH_TEST_CMAC_KDF_OUT_SIZE ||
                     memcmp(exported, expected, sizeof(exported)) != 0)) {
                    WH_ERROR_PRINT("CMAC KDF mismatch (cached inputs cache)\n");
                    ret = -1;
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
        }

        (void)wh_Client_KeyEvict(ctx, saltKeyId);
        (void)wh_Client_KeyEvict(ctx, zKeyId);
        if (ret != 0) {
            return ret;
        }
    }

    WH_TEST_PRINT("CMAC KDF DEVID=0x%X SUCCESS\n", devId);
    return 0;
}
#endif /* HAVE_CMAC_KDF */

int whTest_Crypto_Kdf(whClientContext* ctx)
{
#ifdef HAVE_HKDF
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoHkdf(ctx));
#endif
#ifdef HAVE_CMAC_KDF
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCmacKdf(ctx));
#endif
    (void)ctx;
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
