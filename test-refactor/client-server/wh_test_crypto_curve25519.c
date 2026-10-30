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
 * test-refactor/client-server/wh_test_crypto_curve25519.c
 *
 * Curve25519 ECDH round-trips routed through the server via the per-client
 * devId (WH_CLIENT_DEVID),
 * across ephemeral / server-export / server-cache key paths.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef HAVE_CURVE25519
static int _whTest_CryptoCurve25519(whClientContext* ctx)
{
    int            devId    = WH_CLIENT_DEVID(ctx);
    int            ret      = 0;
    WC_RNG         rng[1];
    curve25519_key key_a[1] = {0};
    curve25519_key key_b[1] = {0};
    uint8_t shared_ab[CURVE25519_KEYSIZE]   = {0};
    uint8_t shared_ba[CURVE25519_KEYSIZE]   = {0};
    int     key_size                        = CURVE25519_KEYSIZE;
    whNvmFlags flags                        = WH_NVM_FLAGS_USAGE_DERIVE;
    whKeyId    key_id_a                     = WH_KEYID_ERASED;
    uint8_t    label_a[WH_NVM_LABEL_LEN]    = "Curve25519 Label A";
    whKeyId    key_id_b                     = 42;
    uint8_t    label_b[WH_NVM_LABEL_LEN]    = "Curve25519 Label B";
    word32     len                          = 0;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    /* Test 1: ephemeral wolfCrypt keys via the per-client devId */
    ret = wc_curve25519_init_ex(key_a, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
    }
    else {
        ret = wc_curve25519_init_ex(key_b, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        }
        else {
            ret = wc_curve25519_make_key(rng, key_size, key_a);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n", ret);
            }
            if (ret == 0) {
                ret = wc_curve25519_make_key(rng, key_size, key_b);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n",
                                   ret);
                }
            }
            if (ret == 0) {
                len = sizeof(shared_ab);
                ret =
                    wc_curve25519_shared_secret(key_a, key_b, shared_ab, &len);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to compute shared secret %d\n", ret);
                }
            }
            if (ret == 0) {
                len = sizeof(shared_ba);
                ret =
                    wc_curve25519_shared_secret(key_b, key_a, shared_ba, &len);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to compute shared secret %d\n", ret);
                }
            }
            if (ret == 0) {
                if (memcmp(shared_ab, shared_ba, len) != 0) {
                    WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                    ret = -1;
                }
            }
            wc_curve25519_free(key_b);
        }
        wc_curve25519_free(key_a);
    }

    /* Test 2: server creates keys and exports them to client */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        }
        else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            }
            else {
                ret = wh_Client_Curve25519MakeExportKey(ctx, key_size, key_a);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeExportKey(ctx, key_size,
                                                            key_b);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to make exported key %d\n",
                                       ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ab);
                    ret = wc_curve25519_shared_secret(key_a, key_b, shared_ab,
                                                      &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute shared secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(key_b, key_a, shared_ba,
                                                      &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute shared secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    if (memcmp(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }

    /* Test 3: server-cached keys referenced via keyId */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        }
        else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            }
            else {
                ret = wh_Client_Curve25519MakeCacheKey(
                    ctx, key_size, &key_id_a, flags, label_a, sizeof(label_a));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeCacheKey(
                        ctx, key_size, &key_id_b, flags, label_b,
                        sizeof(label_b));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ab);
                    wh_Client_Curve25519SetKeyId(key_a, key_id_a);
                    wh_Client_Curve25519SetKeyId(key_b, key_id_b);
                    ret = wc_curve25519_shared_secret(key_a, key_b, shared_ab,
                                                      &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute shared secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(key_b, key_a, shared_ba,
                                                      &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to compute shared secret %d\n", ret);
                    }
                }
                if (ret == 0) {
                    if (memcmp(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                if (!WH_KEYID_ISERASED(key_id_a)) {
                    (void)wh_Client_KeyEvict(ctx, key_id_a);
                }
                if (!WH_KEYID_ISERASED(key_id_b)) {
                    (void)wh_Client_KeyEvict(ctx, key_id_b);
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }

    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 SUCCESS\n");
    }
    return ret;
}

/* Cached X25519 secret must match ref and label, or be NONEXPORTABLE */
static int _whTest_Curve25519CheckCachedSecret(
    whClientContext* ctx, whKeyId keyId, whNvmFlags flags, const uint8_t* ref,
    uint16_t ref_len, const uint8_t* label, uint16_t label_len)
{
    uint8_t  secret[CURVE25519_KEYSIZE] = {0};
    uint16_t secret_len                 = sizeof(secret);
    uint8_t  labelOut[WH_NVM_LABEL_LEN] = {0};
    int      ret;

    ret = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut), secret,
                              &secret_len);
    if ((flags & WH_NVM_FLAGS_NONEXPORTABLE) != 0) {
        if (ret != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT("X25519: KeyExport on NONEXPORTABLE secret "
                           "returned %d (expected WH_ERROR_ACCESS)\n",
                           ret);
            return WH_ERROR_ABORTED;
        }
        return WH_ERROR_OK;
    }
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("X25519: failed to export cached secret "
                       "(keyId=0x%x): %d\n",
                       (unsigned)keyId, ret);
    }
    else if ((secret_len != ref_len) || (memcmp(secret, ref, ref_len) != 0)) {
        WH_ERROR_PRINT("X25519: cached secret does not match reference\n");
        ret = WH_ERROR_ABORTED;
    }
    else if ((label != NULL) && (memcmp(labelOut, label, label_len) != 0)) {
        WH_ERROR_PRINT("X25519: cached secret label mismatch\n");
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

/* Cache-mode X25519 must match the export-mode secret */
static int _whTest_CryptoCurve25519SharedSecretCacheKey(whClientContext* ctx)
{
    typedef struct {
        whKeyId    keyId;
        whNvmFlags flags;
    } CacheCase;

    const CacheCase cases[] = {
        {WH_KEYID_ERASED, WH_NVM_FLAGS_USAGE_DERIVE},
        {0x42, WH_NVM_FLAGS_USAGE_DERIVE},
        {WH_KEYID_ERASED,
         WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_NONEXPORTABLE},
    };
    const uint8_t  secretLabel[] = "TestX25519CachedSecret";
    int            devId         = WH_CLIENT_DEVID(ctx);
    WC_RNG         rng[1];
    curve25519_key key_a[1]                      = {0};
    curve25519_key key_b[1]                      = {0};
    curve25519_key pubB[1]                       = {0};
    uint8_t        refSecret[CURVE25519_KEYSIZE] = {0};
    uint16_t       refSecretLen                  = sizeof(refSecret);
    whKeyId        privAId                       = WH_KEYID_ERASED;
    whKeyId        privBId                       = WH_KEYID_ERASED;
    whKeyId        pubBId                        = WH_KEYID_ERASED;
    int            keyAInit                      = 0;
    int            keyBInit                      = 0;
    int            pubBInit                      = 0;
    size_t         i;
    int            ret;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_curve25519_init_ex(key_a, NULL, devId);
    if (ret == 0) {
        keyAInit = 1;
        ret      = wc_curve25519_init_ex(key_b, NULL, devId);
    }
    if (ret == 0) {
        keyBInit = 1;
        ret      = wh_Client_Curve25519MakeCacheKey(
            ctx, CURVE25519_KEYSIZE, &privAId, WH_NVM_FLAGS_USAGE_DERIVE,
            (const uint8_t*)"X25519CachePrivA", 16);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519MakeCacheKey(
            ctx, CURVE25519_KEYSIZE, &privBId, WH_NVM_FLAGS_USAGE_DERIVE,
            (const uint8_t*)"X25519CachePrivB", 16);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519SetKeyId(key_a, privAId);
    }
    if (ret == 0) {
        ret = wh_Client_Curve25519SetKeyId(key_b, privBId);
    }

    /* Public-only copy of B, so the calls get a (private, public) pair */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(pubB, NULL, INVALID_DEVID);
        if (ret == 0) {
            pubBInit = 1;
            ret = wh_Client_Curve25519ExportPublicKey(ctx, privBId, pubB, 0,
                                                      NULL);
        }
    }
    if (ret == 0) {
        uint8_t lbl[] = "X25519CachePubB";
        ret           = wh_Client_Curve25519ImportKey(
            ctx, pubB, &pubBId, WH_NVM_FLAGS_USAGE_DERIVE, sizeof(lbl), lbl);
    }

    /* Reference: export-mode secret through the async pair */
    if (ret == 0) {
        ret = wh_Client_Curve25519SharedSecretRequest(ctx, privAId, pubBId,
                                                      EC25519_LITTLE_ENDIAN);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Curve25519SharedSecretResponse(ctx, refSecret,
                                                               &refSecretLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    for (i = 0; (ret == 0) && (i < sizeof(cases) / sizeof(cases[0])); i++) {
        whKeyId secretId = cases[i].keyId;

        ret = wh_Client_Curve25519SharedSecretCacheKeyRequest(
            ctx, privAId, pubBId, EC25519_LITTLE_ENDIAN, secretId,
            cases[i].flags, secretLabel, sizeof(secretLabel));
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Curve25519SharedSecretCacheKeyResponse(
                    ctx, &secretId);
            } while (ret == WH_ERROR_NOTREADY);
        }
        /* The server must assign a keyId, or keep the one supplied */
        if ((ret == WH_ERROR_OK) && (WH_KEYID_ISERASED(secretId) ||
                                     (!WH_KEYID_ISERASED(cases[i].keyId) &&
                                      (secretId != cases[i].keyId)))) {
            WH_ERROR_PRINT("X25519: cache case %u returned keyId 0x%x "
                           "(asked 0x%x)\n",
                           (unsigned)i, (unsigned)secretId,
                           (unsigned)cases[i].keyId);
            ret = WH_ERROR_ABORTED;
        }
        if (ret == WH_ERROR_OK) {
            ret = _whTest_Curve25519CheckCachedSecret(
                ctx, secretId, cases[i].flags, refSecret, refSecretLen,
                secretLabel, sizeof(secretLabel));
        }
        if (!WH_KEYID_ISERASED(secretId)) {
            (void)wh_Client_KeyEvict(ctx, secretId);
        }
    }

    if (ret == 0) {
        whKeyId tmp = WH_KEYID_ERASED;
        int     rc  = wh_Client_Curve25519SharedSecretCacheKey(
            ctx, key_a, key_b, EC25519_LITTLE_ENDIAN, &tmp,
            WH_NVM_FLAGS_EPHEMERAL | WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("X25519: CacheKey with EPHEMERAL returned %d "
                           "(expected BADARGS)\n",
                           rc);
            ret = -1;
        }
    }
    if (ret == 0) {
        int rc = wh_Client_Curve25519SharedSecretCacheKey(
            ctx, key_a, key_b, EC25519_LITTLE_ENDIAN, NULL,
            WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        if (rc != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT(
                "X25519: CacheKey NULL inout returned %d (expected BADARGS)\n",
                rc);
            ret = -1;
        }
    }

    /* Blocking wrapper with local keys, which it imports */
    if (ret == 0) {
        curve25519_key keyC[1]                            = {0};
        curve25519_key keyD[1]                            = {0};
        int            keyCInit                           = 0;
        int            keyDInit                           = 0;
        whKeyId        blockId                            = WH_KEYID_ERASED;
        uint8_t        blockRefSecret[CURVE25519_KEYSIZE] = {0};
        uint16_t       blockRefSecretLen = sizeof(blockRefSecret);

        ret = wc_curve25519_init_ex(keyC, NULL, INVALID_DEVID);
        if (ret == 0) {
            keyCInit = 1;
            ret      = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, keyC);
        }
        if (ret == 0) {
            ret = wc_curve25519_init_ex(keyD, NULL, INVALID_DEVID);
        }
        if (ret == 0) {
            keyDInit = 1;
            ret      = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, keyD);
        }
        if (ret == 0) {
            ret = wh_Client_Curve25519SharedSecret(
                ctx, keyC, keyD, EC25519_LITTLE_ENDIAN, blockRefSecret,
                &blockRefSecretLen);
        }
        if (ret == 0) {
            ret = wh_Client_Curve25519SharedSecretCacheKey(
                ctx, keyC, keyD, EC25519_LITTLE_ENDIAN, &blockId,
                WH_NVM_FLAGS_USAGE_DERIVE, NULL, 0);
        }
        if ((ret == 0) && WH_KEYID_ISERASED(blockId)) {
            WH_ERROR_PRINT("X25519: blocking CacheKey returned erased keyId\n");
            ret = WH_ERROR_ABORTED;
        }
        if (ret == 0) {
            ret = _whTest_Curve25519CheckCachedSecret(
                ctx, blockId, WH_NVM_FLAGS_USAGE_DERIVE, blockRefSecret,
                blockRefSecretLen, NULL, 0);
        }
        if (!WH_KEYID_ISERASED(blockId)) {
            (void)wh_Client_KeyEvict(ctx, blockId);
        }
        if (keyDInit) {
            wc_curve25519_free(keyD);
        }
        if (keyCInit) {
            wc_curve25519_free(keyC);
        }
    }

    if (!WH_KEYID_ISERASED(pubBId)) {
        (void)wh_Client_KeyEvict(ctx, pubBId);
    }
    if (!WH_KEYID_ISERASED(privBId)) {
        (void)wh_Client_KeyEvict(ctx, privBId);
    }
    if (!WH_KEYID_ISERASED(privAId)) {
        (void)wh_Client_KeyEvict(ctx, privAId);
    }
    if (pubBInit) {
        wc_curve25519_free(pubB);
    }
    if (keyBInit) {
        wc_curve25519_free(key_b);
    }
    if (keyAInit) {
        wc_curve25519_free(key_a);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 CACHE-MODE SHARED SECRET DEVID=0x%X "
                      "SUCCESS\n",
                      devId);
    }
    return ret;
}

/* Cache a NONEXPORTABLE Curve25519 keypair on the server, then verify the
 * server-side ECDH (private cached, public local) produces the same shared
 * secret as a client-side ECDH (private local, public exported via
 * wh_Client_Curve25519ExportPublicKey). */
static int _whTest_CryptoCurve25519ExportPublicKey(whClientContext* ctx)
{
    int            devId      = WH_CLIENT_DEVID(ctx);
    int            ret        = 0;
    WC_RNG         rng[1];
    curve25519_key hsmPub[1]   = {0};
    curve25519_key hsmPriv[1]  = {0};
    curve25519_key localKey[1] = {0};
    uint8_t        sharedHsm[CURVE25519_KEYSIZE]   = {0};
    uint8_t        sharedLocal[CURVE25519_KEYSIZE] = {0};
    word32         secLen     = 0;
    whKeyId        keyId      = WH_KEYID_ERASED;
    uint8_t        denyBuf[256];
    uint16_t       denyLen    = sizeof(denyBuf);

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_Curve25519MakeCacheKey(
        ctx, (uint16_t)CURVE25519_KEYSIZE, &keyId,
        WH_NVM_FLAGS_USAGE_DERIVE | WH_NVM_FLAGS_NONEXPORTABLE, NULL, 0);
    if (ret != 0) {
        WH_ERROR_PRINT(
            "Failed to make NONEXPORTABLE cached Curve25519 key %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    /* Full export must be denied by the NONEXPORTABLE policy. */
    {
        int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                          &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE Curve25519 full export was not denied: %d\n",
                denyRet);
            ret = -1;
        }
    }

    /* Public-only export must succeed and parse into a usable key struct. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(hsmPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Curve25519ExportPublicKey(ctx, keyId, hsmPub, 0,
                                                      NULL);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "wh_Client_Curve25519ExportPublicKey failed %d\n", ret);
            }
        }
    }

    /* Generate a local ephemeral keypair to ECDH against the exported pub. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(localKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, localKey);
        }
    }

    /* Local side: localPriv * exportedHsmPub. */
    if (ret == 0) {
        secLen = sizeof(sharedLocal);
        ret = wc_curve25519_shared_secret(localKey, hsmPub, sharedLocal,
                                          &secLen);
        if (ret != 0) {
            WH_ERROR_PRINT("Local Curve25519 shared secret failed %d\n", ret);
        }
    }

    /* HSM side: hsmPriv-by-keyId * localPub, dispatched through cryptoCb. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(hsmPriv, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_Curve25519SetKeyId(hsmPriv, keyId);
        }
        if (ret == 0) {
            secLen = sizeof(sharedHsm);
            ret = wc_curve25519_shared_secret(hsmPriv, localKey, sharedHsm,
                                              &secLen);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM Curve25519 shared secret failed %d\n", ret);
            }
        }
        wc_curve25519_free(hsmPriv);
    }

    if (ret == 0 && memcmp(sharedHsm, sharedLocal, secLen) != 0) {
        WH_ERROR_PRINT("Curve25519 shared secrets don't match\n");
        ret = -1;
    }

    wc_curve25519_free(localKey);
    wc_curve25519_free(hsmPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 EXPORT-PUBLIC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_Curve25519ExportPublicKey and
 * that an X25519 shared secret round-trips against the cached private key. */
static int _whTest_CryptoCurve25519CacheKeyAndExportPublic(whClientContext* ctx)
{
    int            devId      = WH_CLIENT_DEVID(ctx);
    int            ret        = 0;
    WC_RNG         rng[1];
    curve25519_key genPub[1]   = {0};
    curve25519_key refPub[1]   = {0};
    curve25519_key localKey[1] = {0};
    uint8_t        genRaw[CURVE25519_KEYSIZE] = {0};
    uint8_t        refRaw[CURVE25519_KEYSIZE] = {0};
    word32         genRawLen  = sizeof(genRaw);
    word32         refRawLen  = sizeof(refRaw);
    uint8_t        sharedHsm[CURVE25519_KEYSIZE]   = {0};
    uint8_t        sharedLocal[CURVE25519_KEYSIZE] = {0};
    word32         secLen     = 0;
    whKeyId        keyId      = WH_KEYID_ERASED;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_curve25519_init_ex(genPub, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wh_Client_Curve25519MakeCacheKeyAndExportPublic(
        ctx, (uint16_t)CURVE25519_KEYSIZE, &keyId, WH_NVM_FLAGS_USAGE_DERIVE,
        NULL, 0, genPub);
    if (ret != 0) {
        WH_ERROR_PRINT("Curve25519MakeCacheKeyAndExportPublic failed %d\n", ret);
    }

    /* Cross-check against a separate public export of the same keyId. */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Curve25519ExportPublicKey(ctx, keyId, refPub, 0,
                                                      NULL);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "wh_Client_Curve25519ExportPublicKey failed %d\n", ret);
            }
        }
    }
    if (ret == 0) {
        ret = wc_curve25519_export_public(genPub, genRaw, &genRawLen);
        if (ret == 0) {
            ret = wc_curve25519_export_public(refPub, refRaw, &refRawLen);
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Curve25519 export_public failed %d\n", ret);
        }
        else if ((genRawLen != refRawLen) ||
                 (memcmp(genRaw, refRaw, genRawLen) != 0)) {
            WH_ERROR_PRINT("keygen pubkey mismatch vs export\n");
            ret = -1;
        }
    }

    /* Shared-secret round-trip using genPub directly as the HSM private-key
     * handle (no separate key object): our local private key * genPub's
     * exported public key (computed locally) must equal genPub's HSM private
     * key * our local public key (computed on the server). */
    if (ret == 0) {
        ret = wc_curve25519_init_ex(localKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, localKey);
        }
    }
    if (ret == 0) {
        secLen = sizeof(sharedLocal);
        ret = wc_curve25519_shared_secret(localKey, genPub, sharedLocal,
                                          &secLen);
        if (ret != 0) {
            WH_ERROR_PRINT("Local Curve25519 shared secret failed %d\n", ret);
        }
    }
    if (ret == 0) {
        secLen = sizeof(sharedHsm);
        ret = wc_curve25519_shared_secret(genPub, localKey, sharedHsm, &secLen);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM Curve25519 shared secret failed %d\n", ret);
        }
    }
    if (ret == 0 && memcmp(sharedHsm, sharedLocal, secLen) != 0) {
        WH_ERROR_PRINT("Curve25519 keygen-pub shared secret mismatch\n");
        ret = -1;
    }

    wc_curve25519_free(localKey);
    wc_curve25519_free(refPub);
    wc_curve25519_free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    (void)wc_FreeRng(rng);

    if (ret == 0) {
        WH_TEST_PRINT("CURVE25519 CACHE-AND-EXPORT-PUBLIC DEVID=0x%X SUCCESS\n",
                      devId);
    }
    return ret;
}

/* Cache keygen must reject WH_NVM_FLAGS_EPHEMERAL */
static int _whTest_CryptoCurve25519MakeCacheKeyEphemeral(whClientContext* ctx)
{
    whKeyId keyId = WH_KEYID_ERASED;
    int     ret;

    ret = wh_Client_Curve25519MakeCacheKey(ctx, CURVE25519_KEYSIZE, &keyId,
                                           WH_NVM_FLAGS_EPHEMERAL, NULL, 0);
    if (ret != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Curve25519MakeCacheKey with EPHEMERAL returned %d "
                       "(expected BADARGS)\n",
                       ret);
        return WH_TEST_FAIL;
    }
    WH_TEST_PRINT("CURVE25519 CACHE-KEY EPHEMERAL REJECT SUCCESS\n");
    return 0;
}

int whTest_Crypto_Curve25519(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519SharedSecretCacheKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519ExportPublicKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519CacheKeyAndExportPublic(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519MakeCacheKeyEphemeral(ctx));
    return 0;
}
#endif /* HAVE_CURVE25519 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
