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

int whTest_Crypto_Curve25519(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoCurve25519ExportPublicKey(ctx));
    return 0;
}
#endif /* HAVE_CURVE25519 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
