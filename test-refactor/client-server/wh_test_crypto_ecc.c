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
 * test-refactor/client-server/wh_test_crypto_ecc.c
 *
 * ECC tests routed through the server via the per-client devId
 * (WH_CLIENT_DEVID):
 *   _whTest_CryptoEcc             - ECDH + ECDSA across ephemeral / export /
 *                                  cache key paths
 *   _whTest_CryptoEccCacheDuplicate - cache slot replacement semantics
 *   _whTest_CryptoEccCrossVerify  - HSM<->SW signature interop, P-256/384/521
 *   _whTest_CryptoEccAsync        - async sign/verify, ECDH, server keygen
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)

/* Full coverage of ECDH + ECDSA across the three key-management paths:
 *   - ephemeral wolfCrypt keys with the per-client devId
 *   - server-generated keys exported back to the client
 *   - server-cached keys referenced via keyId */
#define TEST_ECC_KEYSIZE  32
#define TEST_ECC_CURVE_ID ECC_SECP256R1

static int _whTest_CryptoEcc(whClientContext* ctx)
{
    int     devId = WH_CLIENT_DEVID(ctx);
    int     ret   = WH_ERROR_OK;
    WC_RNG  rng[1];
    ecc_key bobKey[1];
    ecc_key aliceKey[1];
    uint8_t shared_ab[TEST_ECC_KEYSIZE]    = {0};
    uint8_t shared_ba[TEST_ECC_KEYSIZE]    = {0};
    uint8_t hash[TEST_ECC_KEYSIZE]         = {0};
    uint8_t sig[ECC_MAX_SIG_SIZE]          = {0};
    whKeyId keyIdPrivate                   = WH_KEYID_ERASED;
    whKeyId checkKeyId                     = WH_KEYID_ERASED;
    whNvmFlags flags = WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
                       WH_NVM_FLAGS_USAGE_DERIVE;
    uint8_t labelPrivate[WH_NVM_LABEL_LEN] = "ECC Private Key";

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    /* Test Case 1: Using ephemeral key (normal wolfCrypt flow) */
    ret = wc_ecc_init_ex(bobKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
    }
    else {
        ret = wc_ecc_init_ex(aliceKey, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
        }
        else {
            ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, bobKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
            }
            else {
                ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, aliceKey);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
                }
                else {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret           = wc_ecc_shared_secret(
                        bobKey, aliceKey, (byte*)shared_ab, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute secret %d\n", ret);
                    }
                    else {
                        ret = wc_ecc_shared_secret(aliceKey, bobKey,
                                                   (byte*)shared_ba, &secLen);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to compute secret %d\n",
                                           ret);
                        }
                        else if (memcmp(shared_ab, shared_ba, secLen) == 0) {
                            WH_TEST_PRINT("ECC ephemeral ECDH SUCCESS\n");
                        }
                        else {
                            WH_ERROR_PRINT(
                                "ECC ephemeral ECDH FAILED TO MATCH\n");
                            ret = -1;
                        }
                    }
                    if (ret == 0) {
                        word32 sigLen = sizeof(sig);
                        memcpy(hash, shared_ba, sizeof(hash));
                        ret = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                               (void*)sig, &sigLen, rng,
                                               bobKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_ecc_sign_hash %d\n",
                                           ret);
                        }
                        else {
                            int res = 0;
                            ret     = wc_ecc_verify_hash(
                                (void*)sig, sigLen, (void*)hash,
                                sizeof(hash), &res, bobKey);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to wc_ecc_verify_hash %d\n", ret);
                            }
                            else if (res == 1) {
                                WH_TEST_PRINT(
                                    "ECC ephemeral SIGN/VERIFY SUCCESS\n");
                            }
                            else {
                                WH_ERROR_PRINT(
                                    "ECC ephemeral SIGN/VERIFY FAIL\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            wc_ecc_free(aliceKey);
        }
        wc_ecc_free(bobKey);
    }

    /* Test Case 2: Server creates the keys and exports them to the client. */
    if (ret == 0) {
        memset(shared_ab, 0, sizeof(shared_ab));
        memset(shared_ba, 0, sizeof(shared_ba));
        memset(sig, 0, sizeof(sig));

        ret = wc_ecc_init_ex(bobKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex for export key %d\n", ret);
        }
        else {
            ret = wc_ecc_init_ex(aliceKey, NULL, WH_CLIENT_DEVID(ctx));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_init_ex for export key %d\n",
                               ret);
            }
            else {
                ret = wh_Client_EccMakeExportKey(ctx, TEST_ECC_KEYSIZE,
                                                 TEST_ECC_CURVE_ID, bobKey);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed to wh_Client_EccMakeExportKey %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_EccMakeExportKey(
                        ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, aliceKey);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to wh_Client_EccMakeExportKey %d\n", ret);
                    }
                }
                if (ret == 0) {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret           = wc_ecc_shared_secret(
                        bobKey, aliceKey, (byte*)shared_ab, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute export key secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret           = wc_ecc_shared_secret(
                        aliceKey, bobKey, (byte*)shared_ba, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute export key secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    if (memcmp(shared_ab, shared_ba, TEST_ECC_KEYSIZE) != 0) {
                        WH_ERROR_PRINT(
                            "ECC export key ECDH FAILED TO MATCH\n");
                        ret = -1;
                    }
                    else {
                        WH_TEST_PRINT("ECC export key ECDH SUCCESS\n");
                    }
                }
                if (ret == 0) {
                    word32 sigLen = sizeof(sig);
                    memcpy(hash, shared_ba, sizeof(hash));
                    ret = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                           (void*)sig, &sigLen, rng, bobKey);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to sign with export key %d\n",
                                       ret);
                    }
                    else {
                        int res = 0;
                        ret     = wc_ecc_verify_hash((void*)sig, sigLen,
                                                     (void*)hash, sizeof(hash),
                                                     &res, bobKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to verify with export key %d\n", ret);
                        }
                        else if (res != 1) {
                            WH_ERROR_PRINT(
                                "ECC export key SIGN/VERIFY FAIL\n");
                            ret = -1;
                        }
                        else {
                            WH_TEST_PRINT(
                                "ECC export key SIGN/VERIFY SUCCESS\n");
                        }
                    }
                }
                wc_ecc_free(aliceKey);
            }
            wc_ecc_free(bobKey);
        }
    }

    /* Test Case 3: Use ONE server-cached key plus an ephemeral peer for ECDH.
     * Limited to a single cached key so we don't blow the cache budget. */
    if (ret == 0) {
        memset(shared_ab, 0, sizeof(shared_ab));
        memset(shared_ba, 0, sizeof(shared_ba));
        memset(sig, 0, sizeof(sig));
        keyIdPrivate = WH_KEYID_ERASED;

        ret = wh_Client_EccMakeCacheKey(ctx, TEST_ECC_KEYSIZE,
                                        TEST_ECC_CURVE_ID, &keyIdPrivate, flags,
                                        sizeof(labelPrivate), labelPrivate);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_EccMakeCacheKey %d\n", ret);
        }
        if (ret == 0) {
            ret = wc_ecc_init_ex(bobKey, NULL, WH_CLIENT_DEVID(ctx));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_init_ex for cache key %d\n",
                               ret);
            }
            else {
                ret = wh_Client_EccSetKeyId(bobKey, keyIdPrivate);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_EccSetKeyId %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_EccGetKeyId(bobKey, &checkKeyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_EccGetKeyId %d\n",
                                       ret);
                    }
                    else if (checkKeyId != keyIdPrivate) {
                        WH_ERROR_PRINT(
                            "ECC key ID mismatch: got %u, expected %u\n",
                            checkKeyId, keyIdPrivate);
                        ret = -1;
                    }
                }
                if (ret == 0) {
                    /* Required: cached key has no usable curve params yet. */
                    ret = wc_ecc_set_curve(bobKey, TEST_ECC_KEYSIZE,
                                           TEST_ECC_CURVE_ID);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_ecc_set_curve %d\n", ret);
                    }
                }
                if (ret == 0) {
                    ret = wc_ecc_init_ex(aliceKey, NULL, WH_CLIENT_DEVID(ctx));
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to wc_ecc_init_ex for peer key %d\n", ret);
                    }
                    else {
                        ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, aliceKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to wc_ecc_make_key for peer %d\n", ret);
                        }
                        if (ret == 0) {
                            word32 secLen = TEST_ECC_KEYSIZE;
                            ret           = wc_ecc_shared_secret(
                                bobKey, aliceKey, (byte*)shared_ab, &secLen);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to compute cache key secret %d\n",
                                    ret);
                            }
                        }
                        if (ret == 0) {
                            word32 secLen = TEST_ECC_KEYSIZE;
                            ret           = wc_ecc_shared_secret(
                                aliceKey, bobKey, (byte*)shared_ba, &secLen);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to compute peer secret %d\n", ret);
                            }
                        }
                        if (ret == 0) {
                            if (memcmp(shared_ab, shared_ba,
                                       TEST_ECC_KEYSIZE) != 0) {
                                WH_ERROR_PRINT(
                                    "ECC cache key ECDH FAILED TO MATCH\n");
                                ret = -1;
                            }
                            else {
                                WH_TEST_PRINT("ECC cache key ECDH SUCCESS\n");
                            }
                        }
                        wc_ecc_free(aliceKey);
                    }
                }
                if (ret == 0) {
                    word32 sigLen = sizeof(sig);
                    memcpy(hash, shared_ba, sizeof(hash));
                    ret = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                           (void*)sig, &sigLen, rng, bobKey);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to sign with cache key %d\n",
                                       ret);
                    }
                    else {
                        int res = 0;
                        ret     = wc_ecc_verify_hash((void*)sig, sigLen,
                                                     (void*)hash, sizeof(hash),
                                                     &res, bobKey);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to verify with cache key %d\n", ret);
                        }
                        else if (res != 1) {
                            WH_ERROR_PRINT(
                                "ECC cache key SIGN/VERIFY FAIL\n");
                            ret = -1;
                        }
                        else {
                            WH_TEST_PRINT(
                                "ECC cache key SIGN/VERIFY SUCCESS\n");
                        }
                    }
                }
                wc_ecc_free(bobKey);
            }
        }
        if (!WH_KEYID_ISERASED(keyIdPrivate)) {
            (void)wh_Client_KeyEvict(ctx, keyIdPrivate);
        }
    }

    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("ECC SUCCESS\n");
    }
    return ret;
}

/* Cache slot replacement: a second MakeCacheKey on the same keyId must
 * return the new key on subsequent export, not the original. */
static int _whTest_CryptoEccCacheDuplicate(whClientContext* ctx)
{
    int      ret   = WH_ERROR_OK;
    whKeyId  keyId = WH_KEYID_ERASED;
    uint8_t  key1[ECC_BUFSIZE];
    uint8_t  key2[ECC_BUFSIZE];
    uint16_t key1Len = sizeof(key1);
    uint16_t key2Len = sizeof(key2);

    WH_TEST_PRINT("  Testing ECC cache duplicate returns latest key...\n");

    ret = wh_Client_EccMakeCacheKey(ctx, 32, ECC_SECP256R1, &keyId,
                                    WH_NVM_FLAGS_NONE, 0, NULL);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyExport(ctx, keyId, NULL, 0, key1, &key1Len);
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Client_EccMakeCacheKey(ctx, 32, ECC_SECP256R1, &keyId,
                                        WH_NVM_FLAGS_NONE, 0, NULL);
    }

    if (ret == WH_ERROR_OK) {
        key2Len = sizeof(key2);
        ret     = wh_Client_KeyExport(ctx, keyId, NULL, 0, key2, &key2Len);
    }

    if (ret == WH_ERROR_OK) {
        if ((key1Len == key2Len) && (memcmp(key1, key2, key1Len) == 0)) {
            WH_ERROR_PRINT("    FAIL: Export returned original ECC key after "
                           "duplicate insert\n");
            ret = WH_ERROR_ABORTED;
        }
        else {
            WH_TEST_PRINT(
                "    PASS: Export returned most recent cached ECC key\n");
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    return ret;
}

/* Cache a NONEXPORTABLE ECC P-256 keypair on the server, sign a hash there,
 * then export only the public half via wh_Client_EccExportPublicKey and
 * verify the signature client-side. */
static int _whTest_CryptoEccExportPublicKey(whClientContext* ctx)
{
    int      devId   = WH_CLIENT_DEVID(ctx);
    int      ret     = 0;
    WC_RNG   rng[1];
    ecc_key  hsmKey[1];
    ecc_key  pubKey[1];
    whKeyId  keyId   = WH_KEYID_ERASED;
    /* Non-zero hash: wolfCrypt rejects all-zero hashes for ECDSA sign/verify
     * (returns ECC_BAD_ARG_E) unless WC_ALLOW_ECC_ZERO_HASH is defined. */
    uint8_t  hash[TEST_ECC_KEYSIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t  sig[ECC_MAX_SIG_SIZE];
    word32   sigLen  = sizeof(sig);
    int      verify  = 0;
    uint8_t  denyBuf[256];
    uint16_t denyLen = sizeof(denyBuf);

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_EccMakeCacheKey(
        ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
            WH_NVM_FLAGS_NONEXPORTABLE,
        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to make NONEXPORTABLE cached ECC key %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    /* Full export must be denied by the NONEXPORTABLE policy. */
    {
        int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                          &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE ECC full export was not denied: %d\n", denyRet);
            ret = -1;
        }
    }

    /* Sign on the server using the cached private key. */
    if (ret == 0) {
        ret = wc_ecc_init_ex(hsmKey, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_EccSetKeyId(hsmKey, keyId);
        }
        if (ret == 0) {
            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng,
                                   hsmKey);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM ECC sign failed %d\n", ret);
            }
        }
        wc_ecc_free(hsmKey);
    }

    /* Public-only export must succeed and verify the signature client-side. */
    if (ret == 0) {
        ret = wc_ecc_init_ex(pubKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_EccExportPublicKey(ctx, keyId, pubKey, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_EccExportPublicKey failed %d\n", ret);
            }
            else if (pubKey->type != ECC_PUBLICKEY) {
                WH_ERROR_PRINT(
                    "Exported ECC key is not public-only (type=%d)\n",
                    pubKey->type);
                ret = -1;
            }
            else {
                ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash),
                                         &verify, pubKey);
                if (ret != 0 || verify != 1) {
                    WH_ERROR_PRINT(
                        "Client-side ECC verify failed ret=%d verify=%d\n",
                        ret, verify);
                    if (ret == 0) {
                        ret = -1;
                    }
                }
            }
            wc_ecc_free(pubKey);
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("ECC EXPORT-PUBLIC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_EccExportPublicKey and that
 * it verifies a signature made by the cached private key. */
static int _whTest_CryptoEccCacheKeyAndExportPublic(whClientContext* ctx)
{
    int      devId    = WH_CLIENT_DEVID(ctx);
    int      ret      = 0;
    WC_RNG   rng[1];
    ecc_key  genPub[1];
    ecc_key  refPub[1] = {0};
    whKeyId  keyId    = WH_KEYID_ERASED;
    uint8_t  hash[TEST_ECC_KEYSIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t  sig[ECC_MAX_SIG_SIZE];
    word32   sigLen   = sizeof(sig);
    int      verify   = 0;
    byte     genDer[256];
    byte     refDer[256];
    int      genDerSz = 0;
    int      refDerSz = 0;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ecc_init_ex(genPub, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wh_Client_EccMakeCacheKeyAndExportPublic(
        ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, 0, NULL, genPub);
    if (ret != 0) {
        WH_ERROR_PRINT("EccMakeCacheKeyAndExportPublic failed %d\n", ret);
    }

    /* Cross-check against a separate public export of the same keyId. */
    if (ret == 0) {
        ret = wc_ecc_init_ex(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_EccExportPublicKey(ctx, keyId, refPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_EccExportPublicKey failed %d\n", ret);
            }
            else {
                genDerSz =
                    wc_EccPublicKeyToDer(genPub, genDer, sizeof(genDer), 1);
                refDerSz =
                    wc_EccPublicKeyToDer(refPub, refDer, sizeof(refDer), 1);
                if ((genDerSz <= 0) || (genDerSz != refDerSz) ||
                    (memcmp(genDer, refDer, (size_t)genDerSz) != 0)) {
                    WH_ERROR_PRINT("keygen pubkey mismatch vs export\n");
                    ret = -1;
                }
            }
        }
    }

    /* Sign on the server using genPub directly as the HSM private-key handle
     * (no separate key object), then verify locally with the independently
     * exported public key (refPub) the client holds. */
    if (ret == 0) {
        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, genPub);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM ECC sign failed %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &verify,
                                 refPub);
        if ((ret != 0) || (verify != 1)) {
            WH_ERROR_PRINT("verify with keygen pub failed ret=%d verify=%d\n",
                           ret, verify);
            if (ret == 0) {
                ret = -1;
            }
        }
    }

    wc_ecc_free(refPub);
    wc_ecc_free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("ECC CACHE-AND-EXPORT-PUBLIC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

#if !defined(WOLF_CRYPTO_CB_ONLY_ECC)

/* Curve sizes used by the cross-verify and async test families. */
#define WH_TEST_ECC_P256_KEY_SIZE 32
#define WH_TEST_ECC_P384_KEY_SIZE 48
#define WH_TEST_ECC_P521_KEY_SIZE 66
/* Use maximum digest size for all curves to test hash truncation edge cases.
 * ECDSA implementations must properly truncate hashes larger than the curve
 * order. */
#define WH_TEST_ECC_HASH_SIZE WC_MAX_DIGEST_SIZE

static int whTest_CryptoEccCrossVerify_OneCurve(whClientContext* ctx,
                                                WC_RNG* rng, int keySize,
                                                int curveId, const char* name)
{
    ecc_key hsmKey[1]                   = {0};
    ecc_key swKey[1]                    = {0};
    uint8_t hash[WH_TEST_ECC_HASH_SIZE] = {0};
    uint8_t sig[ECC_MAX_SIG_SIZE]       = {0};
    uint8_t pubX[ECC_MAXSIZE]           = {0};
    uint8_t pubY[ECC_MAXSIZE]           = {0};
    word32  pubXLen                     = 0;
    word32  pubYLen                     = 0;
    word32  sigLen                      = 0;
    int     res                         = 0;
    whKeyId keyId                       = WH_KEYID_ERASED;
    int     hsmKeyInit                  = 0;
    int     swKeyInit                   = 0;
    int     ret                         = WH_ERROR_OK;
    int     i;

    /* Use non-repeating pattern to detect hash truncation bugs */
    for (i = 0; i < WH_TEST_ECC_HASH_SIZE; i++) {
        hash[i] = (uint8_t)i;
    }

    WH_TEST_PRINT("  Testing %s curve...\n", name);

    pubXLen = keySize;
    pubYLen = keySize;

    /* Test 1: HSM sign + Software verify */
    ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("%s: Failed to init HSM key: %d\n", name, ret);
    }
    else {
        hsmKeyInit = 1;
    }
    if (ret == 0) {
        ret = wc_ecc_make_key(rng, keySize, hsmKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to generate HSM key: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_export_public_raw(hsmKey, pubX, &pubXLen, pubY, &pubYLen);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to export HSM public key: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        sigLen = sizeof(sig);
        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, hsmKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: HSM sign failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to init SW key: %d\n", name, ret);
        }
        else {
            swKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(swKey, pubX, pubY, NULL, curveId);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to import public to SW: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        res = 0;
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res, swKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: SW verify failed: %d\n", name, ret);
        }
        else if (res != 1) {
            WH_ERROR_PRINT("%s: HSM sign + SW verify: signature invalid\n",
                           name);
            ret = -1;
        }
        else {
            WH_TEST_PRINT("    HSM sign + SW verify: PASS\n");
        }
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
        swKeyInit = 0;
    }
    if (hsmKeyInit) {
        if (wh_Client_EccGetKeyId(hsmKey, &keyId) == 0 &&
            !WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
        wc_ecc_free(hsmKey);
        hsmKeyInit = 0;
    }

    /* Test 2: Software sign + HSM verify */
    if (ret == 0) {
        memset(sig, 0, sizeof(sig));
        memset(pubX, 0, sizeof(pubX));
        memset(pubY, 0, sizeof(pubY));
        pubXLen = keySize;
        pubYLen = keySize;
        keyId   = WH_KEYID_ERASED;

        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to init SW key: %d\n", name, ret);
        }
        else {
            swKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_make_key(rng, keySize, swKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to generate SW key: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_export_public_raw(swKey, pubX, &pubXLen, pubY, &pubYLen);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to export SW public key: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        sigLen = sizeof(sig);
        ret    = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng, swKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: SW sign failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to init HSM key: %d\n", name, ret);
        }
        else {
            hsmKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wc_ecc_import_unsigned(hsmKey, pubX, pubY, NULL, curveId);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: Failed to import public to HSM: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        res = 0;
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res, hsmKey);
        if (ret != 0) {
            WH_ERROR_PRINT("%s: HSM verify failed: %d\n", name, ret);
        }
        else if (res != 1) {
            WH_ERROR_PRINT("%s: SW sign + HSM verify: signature invalid\n",
                           name);
            ret = -1;
        }
        else {
            WH_TEST_PRINT("    SW sign + HSM verify: PASS\n");
        }
    }
    if (hsmKeyInit) {
        if (wh_Client_EccGetKeyId(hsmKey, &keyId) == 0 &&
            !WH_KEYID_ISERASED(keyId)) {
            (void)wh_Client_KeyEvict(ctx, keyId);
        }
        wc_ecc_free(hsmKey);
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
    }
    return ret;
}

static int _whTest_CryptoEccCrossVerify(whClientContext* ctx)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret   = WH_ERROR_OK;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    WH_TEST_PRINT("Testing ECDSA cross-verification (HSM<->SW)...\n");

#if !defined(NO_ECC256)
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#endif

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#endif

#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
    if (ret == 0) {
        ret = whTest_CryptoEccCrossVerify_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#endif

    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("ECDSA cross-verification SUCCESS\n");
    }
    return ret;
}

/* Async sign/verify per curve. Generates a server-cached signing key, signs
 * via wh_Client_EccSign{Request,Response}, software-verifies, then imports
 * the public key into a separate cache slot and async-verifies. Also covers
 * BADARGS and stuck-ctx invariants. */
static int whTest_CryptoEccSignVerifyAsync_OneCurve(whClientContext* ctx,
                                                    WC_RNG* rng, int keySize,
                                                    int         curveId,
                                                    const char* name)
{
    ecc_key  hsmKey[1]                   = {0};
    ecc_key  swKey[1]                    = {0};
    uint8_t  hash[WH_TEST_ECC_HASH_SIZE] = {0};
    uint8_t  sig[ECC_MAX_SIG_SIZE]       = {0};
    uint8_t  pubX[ECC_MAXSIZE]           = {0};
    uint8_t  pubY[ECC_MAXSIZE]           = {0};
    word32   pubXLen                     = 0;
    word32   pubYLen                     = 0;
    uint16_t sigLen                      = 0;
    int      res                         = 0;
    whKeyId  signKeyId                   = WH_KEYID_ERASED;
    whKeyId  verifyKeyId                 = WH_KEYID_ERASED;
    int      hsmKeyInit                  = 0;
    int      swKeyInit                   = 0;
    int      ret                         = WH_ERROR_OK;
    int      i;

    for (i = 0; i < WH_TEST_ECC_HASH_SIZE; i++) {
        hash[i] = (uint8_t)i;
    }

    WH_TEST_PRINT("  Testing async Sign/Verify %s curve...\n", name);

    pubXLen = keySize;
    pubYLen = keySize;

    ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
        hsmKeyInit = 1;
        ret        = wc_ecc_make_key(rng, keySize, hsmKey);
    }
    if (ret == 0) {
        uint8_t signLabel[] = "TestEccAsyncSign";
        signKeyId           = WH_KEYID_ERASED;
        ret                 = wh_Client_EccImportKey(
            ctx, hsmKey, &signKeyId, WH_NVM_FLAGS_USAGE_SIGN,
            sizeof(signLabel), signLabel);
    }

    if (ret == 0) {
        sigLen = sizeof(sig);
        ret    = wh_Client_EccSignRequest(ctx, signKeyId, hash, sizeof(hash));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccSignRequest failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccSignResponse(ctx, sig, &sigLen);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccSignResponse failed: %d\n", name, ret);
        }
    }

    if (ret == 0) {
        int badret =
            wh_Client_EccSignRequest(ctx, WH_KEYID_ERASED, hash, sizeof(hash));
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: EccSignRequest with erased keyId returned %d "
                           "(want BADARGS)\n",
                           name, badret);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = wc_ecc_export_public_raw(hsmKey, pubX, &pubXLen, pubY, &pubYLen);
    }

    if (ret == 0) {
        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            swKeyInit = 1;
            ret = wc_ecc_import_unsigned(swKey, pubX, pubY, NULL, curveId);
        }
    }
    if (ret == 0) {
        res = 0;
        ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res, swKey);
        if (ret == 0 && res != 1) {
            WH_ERROR_PRINT("%s: async sign produced invalid signature\n", name);
            ret = -1;
        }
    }

    if (ret == 0) {
        ecc_key pubOnly[1] = {0};
        uint8_t label[]    = "TestEccAsyncVerify";

        ret = wc_ecc_init_ex(pubOnly, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_ecc_import_unsigned(pubOnly, pubX, pubY, NULL, curveId);
        }
        if (ret == 0) {
            verifyKeyId = WH_KEYID_ERASED;
            ret         = wh_Client_EccImportKey(
                ctx, pubOnly, &verifyKeyId, WH_NVM_FLAGS_USAGE_VERIFY,
                sizeof(label), label);
        }
        wc_ecc_free(pubOnly);
    }
    if (ret == 0) {
        ret = wh_Client_EccVerifyRequest(ctx, verifyKeyId, sig, sigLen, hash,
                                         sizeof(hash));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccVerifyRequest failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        res = 0;
        do {
            ret = wh_Client_EccVerifyResponse(ctx, NULL, &res);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccVerifyResponse failed: %d\n", name, ret);
        }
        else if (res != 1) {
            WH_ERROR_PRINT("%s: async verify returned res=%d (want 1)\n", name,
                           res);
            ret = -1;
        }
    }
    if (ret == 0) {
        int badret = wh_Client_EccVerifyRequest(ctx, WH_KEYID_ERASED, sig,
                                                sigLen, hash, sizeof(hash));
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: EccVerifyRequest with erased keyId returned %d "
                "(want BADARGS)\n",
                name, badret);
            ret = -1;
        }
    }

    /* NULL ctx must be rejected by every async half. */
    if (ret == 0) {
        int rc1 = wh_Client_EccSignRequest(NULL, signKeyId, hash, sizeof(hash));
        int rc2 = wh_Client_EccSignResponse(NULL, sig, &sigLen);
        int rc3 = wh_Client_EccVerifyRequest(NULL, verifyKeyId, sig, sigLen,
                                             hash, sizeof(hash));
        int rc4 = wh_Client_EccVerifyResponse(NULL, NULL, &res);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS ||
            rc3 != WH_ERROR_BADARGS || rc4 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: NULL ctx async API rc=(%d,%d,%d,%d) want all "
                           "BADARGS\n",
                           name, rc1, rc2, rc3, rc4);
            ret = -1;
        }
    }

    /* Mismatched output-arg shape on Response must BADARGS pre-Recv. */
    if (ret == 0) {
        int rc1 = wh_Client_EccSignResponse(ctx, sig, NULL);
        int rc2 = wh_Client_EccVerifyResponse(ctx, NULL, NULL);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: bad-arg Response rc=(%d,%d) want both BADARGS\n", name,
                rc1, rc2);
            ret = -1;
        }
    }

    /* Wrapper-level: response-side bad args must be caught before SendRequest
     * so the caller's ctx is not left stuck-pending. */
    if (ret == 0) {
        int badret = wh_Client_EccVerify(ctx, hsmKey, sig, sigLen, hash,
                                         sizeof(hash), NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: EccVerify with NULL out_res returned %d "
                           "(want BADARGS)\n",
                           name, badret);
            ret = -1;
        }
    }

    if (ret == 0) {
        int rc;
        sigLen = sizeof(sig);
        rc     = wh_Client_EccSignRequest(ctx, signKeyId, hash, sizeof(hash));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSignResponse(ctx, sig, &sigLen);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: ctx stuck after wrapper BADARGS (rc=%d)\n",
                           name, rc);
            ret = -1;
        }
    }

    /* Too-small sig buffer: must return BUFFER_SIZE with required size in
     * *inout_sig_len, and must not leak partial signature bytes. */
    if (ret == 0) {
        uint8_t  small_buf[1] = {0xAA};
        uint16_t small_len    = sizeof(small_buf);
        int      rc;
        rc = wh_Client_EccSignRequest(ctx, signKeyId, hash, sizeof(hash));
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSignResponse(ctx, small_buf, &small_len);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "%s: too-small buffer Sign Response rc=%d (want BUFFER_SIZE)\n",
                name, rc);
            ret = -1;
        }
        else if (small_len <= 1 || small_len > ECC_MAX_SIG_SIZE) {
            WH_ERROR_PRINT("%s: too-small buffer Sign required size=%u "
                           "(want > 1 and <= ECC_MAX_SIG_SIZE)\n",
                           name, (unsigned)small_len);
            ret = -1;
        }
        else if (small_buf[0] != 0xAA) {
            WH_ERROR_PRINT(
                "%s: partial signature leaked into too-small buffer\n", name);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("    async Sign/Verify %s: PASS\n", name);
    }

    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }
    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
    }
    if (hsmKeyInit) {
        wc_ecc_free(hsmKey);
    }
    return ret;
}

#ifdef HAVE_ECC_DHE
/* Async ECDH per curve: generate two cached private keys, import each side's
 * public into a separate cache slot, run async SharedSecret both directions,
 * compare. Plus BUFFER_SIZE and BADARGS contracts on both wrapper and async
 * halves. */
static int whTest_CryptoEccSharedSecretAsync_OneCurve(whClientContext* ctx,
                                                      WC_RNG* rng, int keySize,
                                                      int         curveId,
                                                      const char* name)
{
    ecc_key  keyA[1]                = {0};
    ecc_key  keyB[1]                = {0};
    ecc_key  pubA[1]                = {0};
    ecc_key  pubB[1]                = {0};
    uint8_t  pubAx[ECC_MAXSIZE]     = {0};
    uint8_t  pubAy[ECC_MAXSIZE]     = {0};
    uint8_t  pubBx[ECC_MAXSIZE]     = {0};
    uint8_t  pubBy[ECC_MAXSIZE]     = {0};
    word32   pubAxLen               = 0;
    word32   pubAyLen               = 0;
    word32   pubBxLen               = 0;
    word32   pubByLen               = 0;
    uint8_t  secret_AB[ECC_MAXSIZE] = {0};
    uint8_t  secret_BA[ECC_MAXSIZE] = {0};
    uint16_t secret_AB_len          = sizeof(secret_AB);
    uint16_t secret_BA_len          = sizeof(secret_BA);
    whKeyId  privAId                = WH_KEYID_ERASED;
    whKeyId  privBId                = WH_KEYID_ERASED;
    whKeyId  pubAId                 = WH_KEYID_ERASED;
    whKeyId  pubBId                 = WH_KEYID_ERASED;
    int      keyAInit               = 0;
    int      keyBInit               = 0;
    int      pubAInit               = 0;
    int      pubBInit               = 0;
    uint8_t  labelA[]               = "TestEccDhAsyncA";
    uint8_t  labelB[]               = "TestEccDhAsyncB";
    int      ret                    = WH_ERROR_OK;

    WH_TEST_PRINT("  Testing async ECDH %s curve...\n", name);

    pubAxLen = pubAyLen = pubBxLen = pubByLen = keySize;

    ret = wc_ecc_init_ex(keyA, NULL, WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
        keyAInit = 1;
        ret      = wc_ecc_make_key(rng, keySize, keyA);
    }
    if (ret == 0) {
        uint8_t privLabelA[] = "TestEccDhAsyncPrivA";
        privAId              = WH_KEYID_ERASED;
        ret                  = wh_Client_EccImportKey(
            ctx, keyA, &privAId, WH_NVM_FLAGS_USAGE_DERIVE,
            sizeof(privLabelA), privLabelA);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(keyB, NULL, WH_CLIENT_DEVID(ctx));
    }
    if (ret == 0) {
        keyBInit = 1;
        ret      = wc_ecc_make_key(rng, keySize, keyB);
    }
    if (ret == 0) {
        uint8_t privLabelB[] = "TestEccDhAsyncPrivB";
        privBId              = WH_KEYID_ERASED;
        ret                  = wh_Client_EccImportKey(
            ctx, keyB, &privBId, WH_NVM_FLAGS_USAGE_DERIVE,
            sizeof(privLabelB), privLabelB);
    }

    if (ret == 0) {
        ret =
            wc_ecc_export_public_raw(keyA, pubAx, &pubAxLen, pubAy, &pubAyLen);
    }
    if (ret == 0) {
        ret =
            wc_ecc_export_public_raw(keyB, pubBx, &pubBxLen, pubBy, &pubByLen);
    }

    if (ret == 0) {
        ret = wc_ecc_init_ex(pubA, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubAInit = 1;
            ret = wc_ecc_import_unsigned(pubA, pubAx, pubAy, NULL, curveId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_EccImportKey(ctx, pubA, &pubAId,
                                     WH_NVM_FLAGS_USAGE_DERIVE, sizeof(labelA),
                                     labelA);
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(pubB, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubBInit = 1;
            ret = wc_ecc_import_unsigned(pubB, pubBx, pubBy, NULL, curveId);
        }
    }
    if (ret == 0) {
        ret = wh_Client_EccImportKey(ctx, pubB, &pubBId,
                                     WH_NVM_FLAGS_USAGE_DERIVE, sizeof(labelB),
                                     labelB);
    }

    if (ret == 0) {
        ret = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccSharedSecretResponse(ctx, secret_AB,
                                                    &secret_AB_len);
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == 0) {
        ret = wh_Client_EccSharedSecretRequest(ctx, privBId, pubAId);
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccSharedSecretResponse(ctx, secret_BA,
                                                    &secret_BA_len);
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == 0) {
        if (secret_AB_len != secret_BA_len ||
            memcmp(secret_AB, secret_BA, secret_AB_len) != 0) {
            WH_ERROR_PRINT("%s: async ECDH secrets differ across sides\n",
                           name);
            ret = -1;
        }
    }

    /* Too-small output buffer: BUFFER_SIZE + required size, no leak. */
    if (ret == 0) {
        uint8_t  small_buf[1] = {0xAA};
        uint16_t small_len    = sizeof(small_buf);
        int      rc;
        rc = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSharedSecretResponse(ctx, small_buf,
                                                       &small_len);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "%s: too-small buffer ECDH Response rc=%d (want BUFFER_SIZE)\n",
                name, rc);
            ret = -1;
        }
        else if (small_len != secret_AB_len) {
            WH_ERROR_PRINT("%s: too-small buffer required size=%u (want %u)\n",
                           name, (unsigned)small_len,
                           (unsigned)secret_AB_len);
            ret = -1;
        }
        else if (small_buf[0] != 0xAA) {
            WH_ERROR_PRINT("%s: partial secret leaked into too-small buffer\n",
                           name);
            ret = -1;
        }
    }

    if (ret == 0) {
        uint8_t  small_buf[1] = {0xAA};
        uint16_t small_len    = sizeof(small_buf);
        int      rc =
            wh_Client_EccSharedSecret(ctx, keyA, pubB, small_buf, &small_len);
        if (rc != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT(
                "%s: too-small buffer ECDH wrapper rc=%d (want BUFFER_SIZE)\n",
                name, rc);
            ret = -1;
        }
        else if (small_len != secret_AB_len) {
            WH_ERROR_PRINT(
                "%s: wrapper too-small required size=%u (want %u)\n", name,
                (unsigned)small_len, (unsigned)secret_AB_len);
            ret = -1;
        }
        else if (small_buf[0] != 0xAA) {
            WH_ERROR_PRINT(
                "%s: wrapper leaked partial secret into too-small buffer\n",
                name);
            ret = -1;
        }
    }

    if (ret == 0) {
        int badret =
            wh_Client_EccSharedSecretRequest(ctx, WH_KEYID_ERASED, pubBId);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: ECDH Request with erased priv keyId returned %d\n", name,
                badret);
            ret = -1;
        }
    }
    if (ret == 0) {
        int badret =
            wh_Client_EccSharedSecretRequest(ctx, privAId, WH_KEYID_ERASED);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: ECDH Request with erased pub keyId returned %d\n", name,
                badret);
            ret = -1;
        }
    }

    if (ret == 0) {
        int rc1 = wh_Client_EccSharedSecretRequest(NULL, privAId, pubBId);
        int rc2 = wh_Client_EccSharedSecretResponse(NULL, secret_AB,
                                                    &secret_AB_len);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: NULL ctx async ECDH rc=(%d,%d) want BADARGS\n", name, rc1,
                rc2);
            ret = -1;
        }
    }

    if (ret == 0) {
        int rc = wh_Client_EccSharedSecretResponse(ctx, secret_AB, NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: SharedSecretResponse(out, NULL) returned %d "
                           "(want BADARGS)\n",
                           name, rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        int badret =
            wh_Client_EccSharedSecret(ctx, keyA, pubB, secret_AB, NULL);
        if (badret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: EccSharedSecret with NULL inout_size returned %d "
                "(want BADARGS)\n",
                name, badret);
            ret = -1;
        }
    }

    if (ret == 0) {
        int rc;
        secret_AB_len = sizeof(secret_AB);
        rc            = wh_Client_EccSharedSecretRequest(ctx, privAId, pubBId);
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccSharedSecretResponse(ctx, secret_AB,
                                                       &secret_AB_len);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT(
                "%s: ctx stuck after ECDH wrapper BADARGS (rc=%d)\n", name, rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("    async ECDH %s: PASS\n", name);
    }

    if (!WH_KEYID_ISERASED(pubBId)) {
        (void)wh_Client_KeyEvict(ctx, pubBId);
    }
    if (!WH_KEYID_ISERASED(pubAId)) {
        (void)wh_Client_KeyEvict(ctx, pubAId);
    }
    if (!WH_KEYID_ISERASED(privBId)) {
        (void)wh_Client_KeyEvict(ctx, privBId);
    }
    if (!WH_KEYID_ISERASED(privAId)) {
        (void)wh_Client_KeyEvict(ctx, privAId);
    }
    if (pubBInit) {
        wc_ecc_free(pubB);
    }
    if (pubAInit) {
        wc_ecc_free(pubA);
    }
    if (keyBInit) {
        wc_ecc_free(keyB);
    }
    if (keyAInit) {
        wc_ecc_free(keyA);
    }
    return ret;
}
#endif /* HAVE_ECC_DHE */

/* Async server-side keygen per curve: MakeCacheKey async (then sign/verify
 * proves the cached key is usable), MakeExportKey async (then local
 * sign/verify proves the exported struct is well-formed), plus arg-shape
 * contracts on every async half. */
static int whTest_CryptoEccMakeKeyAsync_OneCurve(whClientContext* ctx,
                                                 WC_RNG* rng, int keySize,
                                                 int curveId, const char* name)
{
    ecc_key  exportKey[1]                = {0};
    ecc_key  swKey[1]                    = {0};
    uint8_t  hash[WH_TEST_ECC_HASH_SIZE] = {0};
    uint8_t  sig[ECC_MAX_SIG_SIZE]       = {0};
    uint8_t  pubX[ECC_MAXSIZE]           = {0};
    uint8_t  pubY[ECC_MAXSIZE]           = {0};
    word32   pubXLen                     = 0;
    word32   pubYLen                     = 0;
    uint16_t sigLen                      = 0;
    int      res                         = 0;
    whKeyId  cacheKeyId                  = WH_KEYID_ERASED;
    int      exportKeyInit               = 0;
    int      swKeyInit                   = 0;
    uint8_t  cacheLabel[]                = "TestEccAsyncCacheGen";
    int      ret                         = WH_ERROR_OK;
    int      i;

    for (i = 0; i < WH_TEST_ECC_HASH_SIZE; i++) {
        hash[i] = (uint8_t)i;
    }

    pubXLen = keySize;
    pubYLen = keySize;

    WH_TEST_PRINT("  Testing async MakeKey %s curve...\n", name);

    if (ret == 0) {
        ret = wh_Client_EccMakeCacheKeyRequest(
            ctx, keySize, curveId, WH_KEYID_ERASED, WH_NVM_FLAGS_USAGE_SIGN,
            sizeof(cacheLabel), cacheLabel);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeCacheKeyRequest failed: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccMakeCacheKeyResponse(ctx, &cacheKeyId);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeCacheKeyResponse failed: %d\n", name,
                           ret);
        }
        else if (WH_KEYID_ISERASED(cacheKeyId)) {
            WH_ERROR_PRINT("%s: server returned erased keyId\n", name);
            ret = -1;
        }
    }
    if (ret == 0) {
        sigLen = sizeof(sig);
        ret    = wh_Client_EccSignRequest(ctx, cacheKeyId, hash, sizeof(hash));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_EccSignResponse(ctx, sig, &sigLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: sign with cache-generated keyId failed: %d\n",
                           name, ret);
        }
    }
    if (ret == 0) {
        ecc_key pubOnly[1] = {0};
        uint8_t labelBuf[WH_NVM_LABEL_LEN];
        ret = wc_ecc_init_ex(pubOnly, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_EccExportKey(ctx, cacheKeyId, pubOnly,
                                         sizeof(labelBuf), labelBuf);
            if (ret == 0) {
                ret = wc_ecc_export_public_raw(pubOnly, pubX, &pubXLen, pubY,
                                               &pubYLen);
            }
            wc_ecc_free(pubOnly);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("%s: export of cached pub failed: %d\n", name, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ecc_init_ex(swKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            swKeyInit = 1;
            ret = wc_ecc_import_unsigned(swKey, pubX, pubY, NULL, curveId);
        }
        if (ret == 0) {
            res = 0;
            ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &res,
                                     swKey);
            if (ret == 0 && res != 1) {
                WH_ERROR_PRINT(
                    "%s: software verify of cache-generated key failed\n",
                    name);
                ret = -1;
            }
        }
    }
    if (swKeyInit) {
        wc_ecc_free(swKey);
    }

    if (ret == 0) {
        ret = wc_ecc_init_ex(exportKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            exportKeyInit = 1;
        }
    }
    if (ret == 0) {
        ret = wh_Client_EccMakeExportKeyRequest(ctx, keySize, curveId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeExportKeyRequest failed: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        do {
            ret = wh_Client_EccMakeExportKeyResponse(ctx, exportKey);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: EccMakeExportKeyResponse failed: %d\n", name,
                           ret);
        }
    }
    if (ret == 0) {
        word32 swSigLen = sizeof(sig);
        memset(sig, 0, sizeof(sig));
        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &swSigLen, rng,
                               exportKey);
        if (ret == 0) {
            res = 0;
            ret = wc_ecc_verify_hash(sig, swSigLen, hash, sizeof(hash), &res,
                                     exportKey);
            if (ret == 0 && res != 1) {
                WH_ERROR_PRINT(
                    "%s: local verify of exported keygen key failed\n", name);
                ret = -1;
            }
        }
        if (ret != 0) {
            WH_ERROR_PRINT(
                "%s: local sign/verify of exported keygen key failed: %d\n",
                name, ret);
        }
    }

    if (ret == 0) {
        int rc1 = wh_Client_EccMakeCacheKeyRequest(NULL, keySize, curveId,
                                                   WH_KEYID_ERASED,
                                                   WH_NVM_FLAGS_NONE, 0, NULL);
        int rc2 = wh_Client_EccMakeCacheKeyResponse(NULL, &cacheKeyId);
        int rc3 = wh_Client_EccMakeExportKeyRequest(NULL, keySize, curveId);
        int rc4 = wh_Client_EccMakeExportKeyResponse(NULL, exportKey);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS ||
            rc3 != WH_ERROR_BADARGS || rc4 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: NULL ctx async MakeKey rc=(%d,%d,%d,%d) want all "
                "BADARGS\n",
                name, rc1, rc2, rc3, rc4);
            ret = -1;
        }
    }

    if (ret == 0) {
        int rc1 = wh_Client_EccMakeCacheKeyResponse(ctx, NULL);
        int rc2 = wh_Client_EccMakeExportKeyResponse(ctx, NULL);
        if (rc1 != WH_ERROR_BADARGS || rc2 != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "%s: NULL out arg Response rc=(%d,%d) want both BADARGS\n",
                name, rc1, rc2);
            ret = -1;
        }
    }

    /* EPHEMERAL flag must be rejected by the cache Request so the export pair
     * unambiguously owns ephemeral keygen. */
    if (ret == 0) {
        int rc = wh_Client_EccMakeCacheKeyRequest(
            ctx, keySize, curveId, WH_KEYID_ERASED, WH_NVM_FLAGS_EPHEMERAL, 0,
            NULL);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s: cache Request with EPHEMERAL flag returned %d "
                           "(want BADARGS)\n",
                           name, rc);
            ret = -1;
        }
    }

    if (ret == 0) {
        whKeyId tmpId = WH_KEYID_ERASED;
        int     rc    = wh_Client_EccMakeCacheKeyRequest(
            ctx, keySize, curveId, WH_KEYID_ERASED, WH_NVM_FLAGS_USAGE_SIGN,
            sizeof(cacheLabel), cacheLabel);
        if (rc == WH_ERROR_OK) {
            do {
                rc = wh_Client_EccMakeCacheKeyResponse(ctx, &tmpId);
            } while (rc == WH_ERROR_NOTREADY);
        }
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s: ctx stuck after MakeKey BADARGS (rc=%d)\n",
                           name, rc);
            ret = -1;
        }
        if (!WH_KEYID_ISERASED(tmpId)) {
            (void)wh_Client_KeyEvict(ctx, tmpId);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("    async MakeKey %s: PASS\n", name);
    }

    if (!WH_KEYID_ISERASED(cacheKeyId)) {
        (void)wh_Client_KeyEvict(ctx, cacheKeyId);
    }
    if (exportKeyInit) {
        wc_ecc_free(exportKey);
    }
    return ret;
}

static int _whTest_CryptoEccAsync(whClientContext* ctx)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret   = WH_ERROR_OK;
    WC_RNG rng[1];

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    WH_TEST_PRINT("Testing ECC async API...\n");

#if !defined(NO_ECC256)
    if (ret == 0) {
        ret = whTest_CryptoEccSignVerifyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#endif
    if (ret == 0) {
        ret = whTest_CryptoEccMakeKeyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P256_KEY_SIZE, ECC_SECP256R1, "P-256");
    }
#endif

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    if (ret == 0) {
        ret = whTest_CryptoEccSignVerifyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#endif
    if (ret == 0) {
        ret = whTest_CryptoEccMakeKeyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P384_KEY_SIZE, ECC_SECP384R1, "P-384");
    }
#endif

#if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
    if (ret == 0) {
        ret = whTest_CryptoEccSignVerifyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#ifdef HAVE_ECC_DHE
    if (ret == 0) {
        ret = whTest_CryptoEccSharedSecretAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#endif
    if (ret == 0) {
        ret = whTest_CryptoEccMakeKeyAsync_OneCurve(
            ctx, rng, WH_TEST_ECC_P521_KEY_SIZE, ECC_SECP521R1, "P-521");
    }
#endif

    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("ECC async API SUCCESS\n");
    }
    return ret;
}

#endif /* !WOLF_CRYPTO_CB_ONLY_ECC */

#ifdef WOLFHSM_CFG_DMA
/*
 * ECC public-key export over the generic DMA transport
 * (wh_Client_KeyExportPublicDma). ECC has no DMA cryptocb path, so this
 * exercises the explicit DMA key-export API directly and runs once rather than
 * looping over devIds. Mirrors _whTest_CryptoEccExportPublicKey but pulls the
 * public half out via DMA, then verifies a server-made signature client-side.
 */
static int _whTest_CryptoEccExportPublicKeyDma(whClientContext* ctx)
{
    int      ret    = 0;
    WC_RNG   rng[1];
    whKeyId  keyId  = WH_KEYID_ERASED;
    ecc_key  pubKey[1];
    /* Non-zero hash: wolfCrypt rejects all-zero hashes for ECDSA. */
    uint8_t  hash[TEST_ECC_KEYSIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    uint8_t  sig[ECC_MAX_SIG_SIZE];
    word32   sigLen = sizeof(sig);
    int      verify = 0;
    uint8_t  derBuf[256];
    uint16_t derSz  = sizeof(derBuf);

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_EccMakeCacheKey(
        ctx, TEST_ECC_KEYSIZE, TEST_ECC_CURVE_ID, &keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY |
            WH_NVM_FLAGS_NONEXPORTABLE,
        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to make NONEXPORTABLE cached ECC key (DMA) %d\n",
                       ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    /* Sign on the server with the cached private key. */
    if (ret == 0) {
        ecc_key hsmKey[1];
        ret = wc_ecc_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
        if (ret == 0) {
            ret = wh_Client_EccSetKeyId(hsmKey, keyId);
        }
        if (ret == 0) {
            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, rng,
                                   hsmKey);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM ECC sign failed (DMA) %d\n", ret);
            }
        }
        wc_ecc_free(hsmKey);
    }

    /* Pull the public half out of the HSM via the generic DMA transport. */
    if (ret == 0) {
        ret = wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_ECC, derBuf,
                                           derSz, NULL, 0, &derSz);
        if (ret != 0) {
            WH_ERROR_PRINT("wh_Client_KeyExportPublicDma(ECC) failed %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_ecc_init_ex(pubKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Crypto_EccDeserializeKeyDer(derBuf, derSz, pubKey);
        }
        if (ret == 0 && pubKey->type != ECC_PUBLICKEY) {
            WH_ERROR_PRINT(
                "Exported ECC key (DMA) is not public-only (type=%d)\n",
                pubKey->type);
            ret = -1;
        }
        if (ret == 0) {
            ret = wc_ecc_verify_hash(sig, sigLen, hash, sizeof(hash), &verify,
                                     pubKey);
            if (ret != 0 || verify != 1) {
                WH_ERROR_PRINT(
                    "Client-side ECC verify (DMA) failed ret=%d verify=%d\n",
                    ret, verify);
                if (ret == 0) {
                    ret = -1;
                }
            }
        }
        wc_ecc_free(pubKey);
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("ECC EXPORT-PUBLIC DMA SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_Crypto_Ecc(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEcc(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEccCacheDuplicate(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEccExportPublicKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEccCacheKeyAndExportPublic(ctx));
#if !defined(WOLF_CRYPTO_CB_ONLY_ECC)
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEccCrossVerify(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEccAsync(ctx));
#endif
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEccExportPublicKeyDma(ctx));
#endif
    return 0;
}

#endif /* HAVE_ECC && HAVE_ECC_SIGN && HAVE_ECC_VERIFY */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

