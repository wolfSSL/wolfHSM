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
 * test-refactor/client-server/wh_test_crypto_falcon.c
 *
 * Falcon tests routed through the server:
 *   _whTest_CryptoFalconWolfCrypt - plain wolfCrypt API, so the crypto
 *                                   callback is what reaches the server
 *   _whTest_CryptoFalconClient    - direct client API against a key that
 *                                   never leaves the server
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/falcon.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef HAVE_FALCON

#ifndef WOLFSSL_FALCON_VERIFY_ONLY

/* Use the wolfCrypt API so only the crypto callback reaches the server */
static int _whTest_CryptoFalconWolfCrypt(whClientContext* ctx, int level)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    int        verified = 0;
    falcon_key key[1];
    WC_RNG     rng[1];
    byte       msg[] = "Test message for Falcon crypto callback";
    byte       sig[FALCON_MAX_SIG_SIZE];
    word32     sigLen = sizeof(sig);

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_falcon_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_falcon_set_level(key, (byte)level);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set Falcon level %d: %d\n", level, ret);
    }

    if (ret == 0) {
        ret = wc_falcon_make_key(key, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to make Falcon key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_falcon_sign_msg(msg, sizeof(msg), sig, &sigLen, key, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with Falcon: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret =
            wc_falcon_verify_msg(sig, sigLen, msg, sizeof(msg), &verified, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify Falcon signature: %d\n", ret);
        }
        else if (!verified) {
            WH_ERROR_PRINT("Falcon signature did not verify\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* A tampered message must fail verification without an error */
    if (ret == 0) {
        msg[0] ^= 0xFF;
        verified = 1;
        ret =
            wc_falcon_verify_msg(sig, sigLen, msg, sizeof(msg), &verified, key);
        msg[0] ^= 0xFF;
        if (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            ret      = 0;
            verified = 0;
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify a tampered message: %d\n", ret);
        }
        else if (verified) {
            WH_ERROR_PRINT("Falcon verified a tampered message\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* A corrupted nonce must also fail verification without an error */
    if (ret == 0) {
        byte badSig[FALCON_MAX_SIG_SIZE];

        memcpy(badSig, sig, sigLen);
        badSig[1] ^= 0xFF;
        verified = 1;
        ret = wc_falcon_verify_msg(badSig, sigLen, msg, sizeof(msg), &verified,
                                   key);
        if (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            ret      = 0;
            verified = 0;
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify a corrupt signature: %d\n", ret);
        }
        else if (verified) {
            WH_ERROR_PRINT("Falcon verified a corrupt signature\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* A corrupted header is undecodable, so expect an error not a verdict */
    if (ret == 0) {
        byte badSig[FALCON_MAX_SIG_SIZE];
        int  vret;

        memcpy(badSig, sig, sigLen);
        badSig[0] ^= 0xFF;
        verified = 1;
        vret = wc_falcon_verify_msg(badSig, sigLen, msg, sizeof(msg), &verified,
                                    key);
        if (vret == 0) {
            WH_ERROR_PRINT("Malformed Falcon signature was not rejected\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* The key check runs on the server, which holds the private half */
    if (ret == 0) {
        ret = wc_falcon_check_key(key);
        if (ret != 0) {
            WH_ERROR_PRINT("Falcon key check failed: %d\n", ret);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("Falcon wolfCrypt level %d DEVID=0x%X SUCCESS\n", level,
                      devId);
    }

    wc_falcon_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}

/* Exercise the Falcon client API against a key that stays on the server. */
static int _whTest_CryptoFalconClient(whClientContext* ctx, int level)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    int        verified = 0;
    falcon_key key[1];
    whKeyId    keyId = WH_KEYID_ERASED;
    byte       msg[] = "Test message for Falcon client API";
    byte       sig[FALCON_MAX_SIG_SIZE];
    word32     sigLen  = sizeof(sig);
    uint8_t    label[] = "FalconClientKey";

    ret = wc_falcon_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wc_falcon_set_level(key, (byte)level);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set Falcon level %d: %d\n", level, ret);
    }

    /* Generate a key that never leaves the server */
    if (ret == 0) {
        ret = wh_Client_FalconMakeCacheKey(
            ctx, level, &keyId, WH_NVM_FLAGS_USAGE_ANY, sizeof(label), label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache a Falcon key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_FalconSetKeyId(key, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to set Falcon key id: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_FalconSign(ctx, msg, sizeof(msg), sig, &sigLen, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with a cached Falcon key: %d\n",
                           ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_FalconVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                     &verified, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify with a cached Falcon key: %d\n",
                           ret);
        }
        else if (!verified) {
            WH_ERROR_PRINT("Cached Falcon key did not verify its own sig\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* A tampered message must not verify */
    if (ret == 0) {
        msg[0] ^= 0xFF;
        verified = 1;
        ret      = wh_Client_FalconVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                          &verified, key);
        msg[0] ^= 0xFF;
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify a tampered message: %d\n", ret);
        }
        else if (verified) {
            WH_ERROR_PRINT("Falcon verified a tampered message\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Pull back the public half and confirm the cached private key matches */
    if (ret == 0) {
        falcon_key pub[1];

        ret = wc_falcon_init_ex(pub, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_FalconExportPublicKey(ctx, keyId, pub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to export Falcon public key: %d\n", ret);
            }
            else {
                int pubSz = wc_falcon_pub_size(pub);

                if (pubSz <= 0) {
                    WH_ERROR_PRINT("Bad Falcon public key size: %d\n", pubSz);
                    ret = WH_ERROR_ABORTED;
                }
                else {
                    byte wrongPub[FALCON_MAX_PUB_KEY_SIZE];

                    ret = wh_Client_FalconCheckPrivKey(ctx, key, pub->p,
                                                       (word32)pubSz);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Falcon check priv key failed: %d\n",
                                       ret);
                    }

                    /* A public key that does not match must be rejected */
                    if (ret == 0) {
                        memcpy(wrongPub, pub->p, (size_t)pubSz);
                        wrongPub[0] ^= 0xFF;
                        if (wh_Client_FalconCheckPrivKey(ctx, key, wrongPub,
                                                         (word32)pubSz) == 0) {
                            WH_ERROR_PRINT(
                                "Falcon accepted a mismatched public key\n");
                            ret = WH_ERROR_ABORTED;
                        }
                    }
                }
            }
            wc_falcon_free(pub);
        }
    }

    /* Sign a message the signature fully overlaps in the shared buffer */
    if (ret == 0) {
        byte   longMsg[FALCON_MAX_SIG_SIZE];
        word32 longSigLen = sizeof(sig);
        word32 i;

        for (i = 0; i < sizeof(longMsg); i++) {
            longMsg[i] = (byte)i;
        }

        ret = wh_Client_FalconSign(ctx, longMsg, sizeof(longMsg), sig,
                                   &longSigLen, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign an overlapping message: %d\n", ret);
        }
        else {
            verified = 0;
            ret      = wh_Client_FalconVerify(ctx, sig, longSigLen, longMsg,
                                              sizeof(longMsg), &verified, key);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify an overlapping message: %d\n",
                               ret);
            }
            else if (!verified) {
                WH_ERROR_PRINT("Falcon signature did not cover the message\n");
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    /* Signing with the wrong level for the cached key must fail */
    if (ret == 0) {
        const byte otherLevel =
            (level == FALCON_LEVEL1) ? FALCON_LEVEL5 : FALCON_LEVEL1;
        word32 badLen = sizeof(sig);

        if (wc_falcon_set_level(key, otherLevel) == 0) {
            (void)wh_Client_FalconSetKeyId(key, keyId);
            if (wh_Client_FalconSign(ctx, msg, sizeof(msg), sig, &badLen,
                                     key) == 0) {
                WH_ERROR_PRINT("Falcon signed at a mismatched level\n");
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Falcon client level %d DEVID=0x%X SUCCESS\n", level,
                      devId);
    }

    wc_falcon_free(key);
    return ret;
}

/* Export a cached keypair and check the key id accessors */
static int _whTest_CryptoFalconExportKey(whClientContext* ctx, int level)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    falcon_key key[1];
    falcon_key out[1];
    whKeyId    keyId = WH_KEYID_ERASED;
    whKeyId    gotId = WH_KEYID_ERASED;
    /* Deliberately longer than WH_NVM_LABEL_LEN, so the clamp is exercised */
    uint8_t label[WH_NVM_LABEL_LEN + 8];

    memset(label, 'F', sizeof(label));

    ret = wc_falcon_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wh_Client_FalconMakeCacheKey(
        ctx, level, &keyId, WH_NVM_FLAGS_USAGE_ANY, sizeof(label), label);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache a Falcon key: %d\n", ret);
        wc_falcon_free(key);
        return ret;
    }

    ret = wh_Client_FalconSetKeyId(key, keyId);
    if (ret == 0) {
        ret = wh_Client_FalconGetKeyId(key, &gotId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to read back the Falcon key id: %d\n", ret);
        }
        else if (gotId != keyId) {
            WH_ERROR_PRINT("Falcon key id did not round trip\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    if (ret == 0) {
        ret = wc_falcon_init_ex(out, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_FalconExportKey(ctx, keyId, out, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to export a Falcon key: %d\n", ret);
            }
            else if ((out->level != (byte)level) || !out->prvKeySet ||
                     !out->pubKeySet) {
                WH_ERROR_PRINT("Exported Falcon key is incomplete\n");
                ret = WH_ERROR_ABORTED;
            }
            else {
                /* The exported key is real, so check it locally */
                int localRet;

                out->devId = INVALID_DEVID;
                localRet   = wc_falcon_check_key(out);
                out->devId = devId;
                if (localRet != 0) {
                    WH_ERROR_PRINT("Exported Falcon key failed its own "
                                   "check: %d\n",
                                   localRet);
                    ret = WH_ERROR_ABORTED;
                }
            }
            wc_falcon_free(out);
        }
    }

    (void)wh_Client_KeyEvict(ctx, keyId);
    wc_falcon_free(key);

    if (ret == 0) {
        WH_TEST_PRINT("Falcon export-key level %d DEVID=0x%X SUCCESS\n", level,
                      devId);
    }
    return ret;
}

/* Cache a public-only key, as for a peer, and verify with it */
static int _whTest_CryptoFalconPublicOnly(whClientContext* ctx, int level)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    int        verified = 0;
    falcon_key signer[1];
    falcon_key pub[1];
    whKeyId    pubId = WH_KEYID_ERASED;
    byte       msg[] = "Falcon public-only verify";
    byte       sig[FALCON_MAX_SIG_SIZE];
    byte       pubRaw[FALCON_MAX_PUB_KEY_SIZE];
    word32     sigLen  = sizeof(sig);
    word32     pubLen  = sizeof(pubRaw);
    uint8_t    label[] = "FalconPubOnly";

    ret = wc_falcon_init_ex(signer, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wc_falcon_set_level(signer, (byte)level);
    if (ret == 0) {
        ret = wh_Client_FalconMakeExportKey(ctx, level, signer);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate a Falcon key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_falcon_sign_msg(msg, sizeof(msg), sig, &sigLen, signer, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign for public-only verify: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_falcon_export_public(signer, pubRaw, &pubLen);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export the Falcon public key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_falcon_init_ex(pub, NULL, devId);
        if (ret == 0) {
            ret = wc_falcon_set_level(pub, (byte)level);
            if (ret == 0) {
                ret = wc_falcon_import_public(pubRaw, pubLen, pub);
            }
            if (ret == 0) {
                ret = wh_Client_FalconImportKey(ctx, pub, &pubId,
                                                WH_NVM_FLAGS_USAGE_VERIFY,
                                                sizeof(label), label);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to cache a public-only Falcon "
                                   "key: %d\n",
                                   ret);
                }
            }
            /* Use the cached key rather than a temporary import */
            if (ret == 0) {
                ret = wh_Client_FalconSetKeyId(pub, pubId);
            }
            if (ret == 0) {
                ret = wh_Client_FalconVerify(ctx, sig, sigLen, msg, sizeof(msg),
                                             &verified, pub);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to verify with a public-only "
                                   "key: %d\n",
                                   ret);
                }
                else if (!verified) {
                    WH_ERROR_PRINT("Public-only Falcon key did not verify\n");
                    ret = WH_ERROR_ABORTED;
                }
            }
            /* The stored verify-only policy must refuse signing */
            if (ret == 0) {
                word32 badLen = sizeof(sig);
                int    sret;

                sret = wh_Client_FalconSign(ctx, msg, sizeof(msg), sig, &badLen,
                                            pub);
                if (sret != WH_ERROR_USAGE) {
                    WH_ERROR_PRINT("Verify-only Falcon key sign returned %d\n",
                                   sret);
                    ret = WH_ERROR_ABORTED;
                }
            }
            if (!WH_KEYID_ISERASED(pubId)) {
                (void)wh_Client_KeyEvict(ctx, pubId);
            }
            wc_falcon_free(pub);
        }
    }

    wc_falcon_free(signer);

    if (ret == 0) {
        WH_TEST_PRINT("Falcon public-only level %d DEVID=0x%X SUCCESS\n", level,
                      devId);
    }
    return ret;
}

/* Cache a private-only key and sign with it */
static int _whTest_CryptoFalconPrivateOnly(whClientContext* ctx, int level)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    int        verified = 0;
    falcon_key full[1];
    falcon_key priv[1];
    whKeyId    privId = WH_KEYID_ERASED;
    byte       msg[]  = "Falcon private-only sign";
    byte       sig[FALCON_MAX_SIG_SIZE];
    byte       privRaw[FALCON_MAX_KEY_SIZE];
    word32     sigLen  = sizeof(sig);
    word32     privLen = sizeof(privRaw);
    uint8_t    label[] = "FalconPrivOnly";

    ret = wc_falcon_init_ex(full, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wc_falcon_set_level(full, (byte)level);
    if (ret == 0) {
        ret = wh_Client_FalconMakeExportKey(ctx, level, full);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate a Falcon key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wc_falcon_export_private_only(full, privRaw, &privLen);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export the Falcon private key: %d\n",
                           ret);
        }
    }

    if (ret == 0) {
        ret = wc_falcon_init_ex(priv, NULL, devId);
        if (ret == 0) {
            ret = wc_falcon_set_level(priv, (byte)level);
            if (ret == 0) {
                ret = wc_falcon_import_private_only(privRaw, privLen, priv);
            }
            if (ret == 0) {
                ret = wh_Client_FalconImportKey(ctx, priv, &privId,
                                                WH_NVM_FLAGS_USAGE_SIGN,
                                                sizeof(label), label);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to cache a private-only Falcon "
                                   "key: %d\n",
                                   ret);
                }
            }
            /* Use the cached key rather than a temporary import */
            if (ret == 0) {
                ret = wh_Client_FalconSetKeyId(priv, privId);
            }
            if (ret == 0) {
                ret = wh_Client_FalconSign(ctx, msg, sizeof(msg), sig, &sigLen,
                                           priv);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to sign with a private-only "
                                   "key: %d\n",
                                   ret);
                }
            }
            if (ret == 0) {
                /* Verify locally with the public half the server never saw */
                full->devId = INVALID_DEVID;
                ret = wc_falcon_verify_msg(sig, sigLen, msg, sizeof(msg),
                                           &verified, full);
                full->devId = devId;
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to verify a private-only "
                                   "signature: %d\n",
                                   ret);
                }
                else if (!verified) {
                    WH_ERROR_PRINT("Private-only Falcon signature is wrong\n");
                    ret = WH_ERROR_ABORTED;
                }
            }
            /* The stored sign-only policy must refuse verification */
            if (ret == 0) {
                int vret;

                vret = wh_Client_FalconVerify(ctx, sig, sigLen, msg,
                                              sizeof(msg), &verified, priv);
                if (vret != WH_ERROR_USAGE) {
                    WH_ERROR_PRINT("Sign-only Falcon key verify returned %d\n",
                                   vret);
                    ret = WH_ERROR_ABORTED;
                }
            }
            if (!WH_KEYID_ISERASED(privId)) {
                (void)wh_Client_KeyEvict(ctx, privId);
            }
            wc_falcon_free(priv);
        }
    }

    wc_falcon_free(full);

    if (ret == 0) {
        WH_TEST_PRINT("Falcon private-only level %d DEVID=0x%X SUCCESS\n",
                      level, devId);
    }
    return ret;
}

/* A short output buffer must report the needed size, not truncate */
static int _whTest_CryptoFalconBufferTooSmall(whClientContext* ctx)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    falcon_key key[1];
    byte       msg[] = "falcon buf size test";
    byte       smallSig[16];
    byte       fullSig[FALCON_MAX_SIG_SIZE];
    word32     smallLen = (word32)sizeof(smallSig);
    word32     fullLen  = (word32)sizeof(fullSig);

    ret = wc_falcon_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wc_falcon_set_level(key, FALCON_LEVEL1);
    if (ret == 0) {
        ret = wh_Client_FalconMakeExportKey(ctx, FALCON_LEVEL1, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate a Falcon key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_FalconSign(ctx, msg, sizeof(msg), smallSig, &smallLen,
                                   key);
        if (ret != WH_ERROR_BUFFER_SIZE) {
            WH_ERROR_PRINT("Falcon sign into a small buffer returned %d\n",
                           ret);
            ret = WH_ERROR_ABORTED;
        }
        else if (smallLen <= (word32)sizeof(smallSig)) {
            WH_ERROR_PRINT("Falcon sign did not report the size needed\n");
            ret = WH_ERROR_ABORTED;
        }
        else {
            ret = 0;
        }
    }

    /* The same call with room must still succeed afterwards */
    if (ret == 0) {
        ret =
            wh_Client_FalconSign(ctx, msg, sizeof(msg), fullSig, &fullLen, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Falcon sign with a full buffer failed: %d\n", ret);
        }
    }

    wc_falcon_free(key);

    if (ret == 0) {
        WH_TEST_PRINT("Falcon buffer-size DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

/* Client must refuse an oversize message and release any imported key */
static int _whTest_CryptoFalconOversize(whClientContext* ctx)
{
    /* Static so a large communication buffer does not land on the stack */
    static byte bigMsg[WOLFHSM_CFG_COMM_DATA_LEN];
    int         devId = WH_CLIENT_DEVID(ctx);
    int         ret;
    int         verified = 0;
    falcon_key  key[1];
    byte        sig[FALCON_MAX_SIG_SIZE];
    word32      sigLen = sizeof(sig);

    memset(bigMsg, 0xA5, sizeof(bigMsg));

    ret = wc_falcon_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wc_falcon_set_level(key, FALCON_LEVEL1);
    if (ret == 0) {
        ret = wh_Client_FalconMakeExportKey(ctx, FALCON_LEVEL1, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate a Falcon key: %d\n", ret);
        }
    }

    if (ret == 0) {
        if (wh_Client_FalconSign(ctx, bigMsg, sizeof(bigMsg), sig, &sigLen,
                                 key) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Falcon sign accepted an oversized message\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    if (ret == 0) {
        if (wh_Client_FalconVerify(ctx, sig, sizeof(sig), bigMsg,
                                   sizeof(bigMsg), &verified,
                                   key) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Falcon verify accepted an oversized message\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    if (ret == 0) {
        if (wh_Client_FalconCheckPrivKey(ctx, key, bigMsg, sizeof(bigMsg)) !=
            WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("Falcon check-priv-key accepted an oversized "
                           "public key\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* Slots used by the rejected calls must be free again */
    if (ret == 0) {
        byte   msg[]  = "still working";
        word32 outLen = sizeof(sig);

        ret = wh_Client_FalconSign(ctx, msg, sizeof(msg), sig, &outLen, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Falcon sign failed after an oversized one: %d\n",
                           ret);
        }
    }

    wc_falcon_free(key);

    if (ret == 0) {
        WH_TEST_PRINT("Falcon oversize DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

/* The client entry points must reject bad arguments before going on the wire */
static int _whTest_CryptoFalconBadArgs(whClientContext* ctx)
{
    const whKeyId reqId = 1;
    falcon_key    key[1];
    whKeyId       keyId = WH_KEYID_ERASED;
    byte          buf[8];
    word32        len = (word32)sizeof(buf);
    int           res = 0;

    if (wc_falcon_init_ex(key, NULL, WH_CLIENT_DEVID(ctx)) != 0) {
        return WH_ERROR_ABORTED;
    }

    if ((wh_Client_FalconSetKeyId(NULL, keyId) != WH_ERROR_BADARGS) ||
        (wh_Client_FalconGetKeyId(key, NULL) != WH_ERROR_BADARGS) ||
        (wh_Client_FalconGetKeyId(NULL, &keyId) != WH_ERROR_BADARGS) ||
        /* A NULL id would strand the cached key, so it is refused */
        (wh_Client_FalconMakeCacheKey(ctx, FALCON_LEVEL1, NULL,
                                      WH_NVM_FLAGS_USAGE_ANY, 0,
                                      NULL) != WH_ERROR_BADARGS) ||
        (wh_Client_FalconMakeExportKey(ctx, FALCON_LEVEL1, NULL) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconExportKey(ctx, WH_KEYID_ERASED, key, 0, NULL) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconExportPublicKey(ctx, WH_KEYID_ERASED, key, 0, NULL) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconImportKey(ctx, NULL, &keyId, WH_NVM_FLAGS_NONE, 0,
                                   NULL) != WH_ERROR_BADARGS) ||
        (wh_Client_FalconSign(ctx, buf, len, NULL, &len, key) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconSign(ctx, buf, len, buf, NULL, key) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconVerify(ctx, NULL, len, buf, len, &res, key) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconVerify(ctx, buf, len, buf, len, NULL, key) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_FalconCheckPrivKey(ctx, key, NULL, len) !=
         WH_ERROR_BADARGS)) {
        WH_ERROR_PRINT("A Falcon client call accepted bad arguments\n");
        wc_falcon_free(key);
        return WH_ERROR_ABORTED;
    }

    /* Ephemeral keygen belongs to the export path; the id must not change */
    keyId = reqId;
    if ((wh_Client_FalconMakeCacheKey(ctx, FALCON_LEVEL1, &keyId,
                                      WH_NVM_FLAGS_EPHEMERAL, 0,
                                      NULL) != WH_ERROR_BADARGS) ||
        (keyId != reqId)) {
        WH_ERROR_PRINT("Falcon cache keygen accepted the ephemeral flag\n");
        wc_falcon_free(key);
        return WH_ERROR_ABORTED;
    }

    wc_falcon_free(key);
    WH_TEST_PRINT("Falcon bad-args SUCCESS\n");
    return 0;
}

/* Falcon-512 known answer vectors, from the wolfCrypt tests */
static const char falcon512KatMsg[] = "wolfSSL Falcon differential KAT";

static const byte falcon512KatPub[] = {
    0x09, 0xb5, 0x78, 0xda, 0xb5, 0x88, 0xee, 0x60, 0x41, 0xb2, 0xe3, 0xb3,
    0xd8, 0x02, 0x2b, 0x97, 0x98, 0x8d, 0x55, 0xd8, 0x5c, 0xf5, 0xba, 0xbc,
    0x18, 0x0b, 0x5e, 0x12, 0xda, 0x92, 0x6e, 0x2d, 0xfa, 0x34, 0xdf, 0x23,
    0xad, 0x49, 0x21, 0x57, 0xd5, 0xa4, 0x7c, 0x30, 0x48, 0x7a, 0x30, 0x16,
    0xdb, 0x62, 0xa3, 0x4c, 0xaf, 0x7b, 0x14, 0x14, 0xa5, 0xa2, 0x9d, 0x5b,
    0xbb, 0xe7, 0xce, 0x29, 0x79, 0x65, 0x0e, 0x26, 0x8f, 0x89, 0xf5, 0x2f,
    0xc9, 0x19, 0x00, 0x8e, 0x2d, 0x72, 0x65, 0xda, 0xe2, 0x01, 0x83, 0x01,
    0x6c, 0x00, 0xd4, 0xeb, 0xc3, 0x3d, 0x2a, 0xe2, 0x5e, 0x52, 0x7b, 0xa2,
    0xee, 0x47, 0x20, 0xbc, 0x99, 0x3d, 0xa7, 0xf9, 0xa2, 0x53, 0x2f, 0x6c,
    0xb8, 0x46, 0xa2, 0x59, 0xc5, 0xab, 0x72, 0xf2, 0x3b, 0xf2, 0xee, 0x5f,
    0x1b, 0xe6, 0xa5, 0x89, 0x9a, 0x95, 0x38, 0x9e, 0x5e, 0x33, 0xea, 0x45,
    0xaa, 0x13, 0x97, 0x7e, 0x3b, 0x33, 0x1a, 0x41, 0x81, 0xb9, 0x12, 0x8d,
    0x36, 0xb9, 0x47, 0xb8, 0x1b, 0xb8, 0x85, 0x56, 0x9c, 0x9a, 0xc0, 0x4c,
    0x64, 0x7e, 0x39, 0xdf, 0x67, 0x6b, 0x4f, 0x6e, 0x99, 0x85, 0x43, 0x82,
    0x1d, 0x2c, 0x59, 0xf1, 0x59, 0x82, 0x9b, 0xfa, 0x8b, 0x15, 0x11, 0x59,
    0x20, 0x51, 0x65, 0x32, 0x81, 0xc4, 0x86, 0xe4, 0x5e, 0x81, 0xac, 0xc8,
    0x0b, 0x29, 0x14, 0xdc, 0xa6, 0x25, 0x04, 0x61, 0x87, 0x5f, 0x95, 0x82,
    0xa2, 0xc4, 0x1d, 0x18, 0x56, 0x44, 0x35, 0xb2, 0xf0, 0x1d, 0xd4, 0x91,
    0xa6, 0x90, 0x2b, 0x4d, 0x03, 0x10, 0xf9, 0x49, 0xe9, 0x72, 0xe8, 0x5a,
    0xfa, 0x61, 0xc5, 0x85, 0x33, 0xf4, 0xb1, 0x96, 0xc3, 0x07, 0x8b, 0xb5,
    0x5c, 0x33, 0xe5, 0xab, 0xc3, 0x5a, 0x02, 0x59, 0x68, 0xe9, 0x97, 0x66,
    0x69, 0x78, 0x40, 0xbe, 0x23, 0xcd, 0x16, 0xc3, 0x86, 0x98, 0x10, 0xf8,
    0x95, 0x83, 0x8e, 0x7c, 0xc8, 0xe6, 0xc7, 0xf1, 0x1f, 0x61, 0xa8, 0x99,
    0xc9, 0xd2, 0xe9, 0x6b, 0x2f, 0x31, 0x1d, 0x44, 0xd1, 0x8b, 0x64, 0xef,
    0x05, 0xee, 0x6c, 0x20, 0x0c, 0xee, 0x33, 0x3c, 0x1e, 0xdb, 0xb8, 0x8e,
    0x4a, 0x00, 0x33, 0x0d, 0x65, 0x2b, 0x66, 0x1c, 0xee, 0x60, 0x01, 0xc7,
    0xd5, 0x9e, 0xaa, 0xd9, 0x2c, 0xb9, 0x76, 0x12, 0x8f, 0x4a, 0x66, 0x78,
    0x84, 0xb3, 0xf5, 0xaf, 0xe3, 0xfd, 0xb2, 0x90, 0x18, 0x50, 0x9c, 0x99,
    0xbd, 0x6b, 0x2a, 0x65, 0xa8, 0x9e, 0xcc, 0x8b, 0x85, 0xce, 0xa0, 0x54,
    0x70, 0xae, 0x19, 0xad, 0xb1, 0xef, 0xc2, 0x5b, 0xa7, 0x96, 0x95, 0x12,
    0xa8, 0x30, 0x8b, 0x15, 0xc3, 0x21, 0x4d, 0x57, 0x88, 0xfd, 0x58, 0x76,
    0x6a, 0x62, 0xcf, 0x15, 0x39, 0x09, 0x5f, 0x47, 0x32, 0x03, 0xe6, 0x38,
    0xad, 0x1a, 0x4e, 0xfd, 0x1b, 0x12, 0xe8, 0x2b, 0x5d, 0x29, 0xc1, 0x61,
    0xaa, 0x7e, 0x85, 0x20, 0xad, 0x10, 0xfa, 0x62, 0x8e, 0x4a, 0xed, 0x62,
    0x74, 0x3e, 0xd1, 0xbd, 0xdf, 0xbe, 0x24, 0x15, 0x24, 0xf1, 0xbe, 0x61,
    0xe0, 0x8a, 0x09, 0x7c, 0x24, 0x78, 0xee, 0x31, 0x96, 0x36, 0xdf, 0xa0,
    0x53, 0xab, 0x0c, 0x25, 0x50, 0x9f, 0x70, 0x80, 0x43, 0x80, 0x58, 0x8a,
    0x17, 0xb0, 0x1f, 0x25, 0x3a, 0x37, 0xd0, 0xd5, 0xa0, 0xfd, 0x5c, 0x8b,
    0x41, 0x69, 0x79, 0x63, 0x7c, 0x63, 0xc9, 0xa6, 0x51, 0x6a, 0xe4, 0x01,
    0x8c, 0x7e, 0x65, 0xe1, 0x3c, 0x37, 0xc7, 0x14, 0x28, 0x49, 0x89, 0x89,
    0xeb, 0x8e, 0x8e, 0xd4, 0x2a, 0x96, 0x6e, 0x25, 0x00, 0x82, 0x1d, 0x9b,
    0xcc, 0xdc, 0x5a, 0xad, 0x66, 0xa8, 0xa1, 0xbc, 0xaa, 0x80, 0x63, 0xe0,
    0x69, 0x28, 0x42, 0x16, 0xc2, 0xbc, 0xca, 0xae, 0xa3, 0xec, 0xab, 0xca,
    0xf2, 0x65, 0xe8, 0x70, 0x44, 0x6a, 0x37, 0x64, 0xeb, 0xe5, 0x6a, 0x94,
    0x0f, 0x76, 0x80, 0x63, 0x73, 0x5e, 0x61, 0xb8, 0xf6, 0xc7, 0x1b, 0x05,
    0x77, 0xcc, 0x20, 0xc2, 0x80, 0x63, 0x5e, 0x68, 0xe4, 0x0e, 0x33, 0xf5,
    0x03, 0x06, 0x5f, 0x04, 0xaf, 0x1a, 0x08, 0xd7, 0x57, 0x3b, 0x59, 0xbb,
    0x05, 0xc7, 0x9b, 0xf0, 0x99, 0x7c, 0x37, 0x43, 0xb6, 0x0f, 0xac, 0x17,
    0x34, 0x99, 0xc9, 0xa3, 0x62, 0x86, 0x70, 0xd0, 0x35, 0x33, 0x56, 0xec,
    0xa8, 0x8f, 0xd6, 0x6c, 0x56, 0xef, 0xca, 0x08, 0x72, 0xca, 0x31, 0x18,
    0xa8, 0x6d, 0x1d, 0x7c, 0x1c, 0xee, 0x71, 0x00, 0x46, 0x13, 0x88, 0x64,
    0x18, 0x26, 0x33, 0x4f, 0x4f, 0x93, 0xd8, 0xbd, 0x21, 0xe3, 0x55, 0x2d,
    0x79, 0x9a, 0x83, 0xf6, 0xe7, 0x63, 0x9b, 0x87, 0xbd, 0xc6, 0xa8, 0x64,
    0xec, 0x8b, 0xb7, 0x34, 0x4f, 0xa5, 0xe7, 0x2a, 0x91, 0x98, 0x50, 0x18,
    0x75, 0xbe, 0x20, 0x5f, 0x15, 0x4d, 0xd6, 0x8a, 0x43, 0xc4, 0xf4, 0x1f,
    0x41, 0x34, 0xa8, 0xf0, 0x21, 0xa1, 0x6d, 0xfd, 0x8b, 0xf5, 0xa0, 0xee,
    0x27, 0x1a, 0x6d, 0xb0, 0xcb, 0xf9, 0x11, 0x16, 0x87, 0x5d, 0xf1, 0xa6,
    0x64, 0xe1, 0xae, 0x68, 0x1c, 0xd1, 0x90, 0xf4, 0xda, 0xc5, 0x9f, 0x38,
    0xbc, 0x06, 0xd0, 0x5f, 0x1c, 0x0c, 0xfa, 0x52, 0xa4, 0xa8, 0x59, 0xb8,
    0x9b, 0xf2, 0x0b, 0x26, 0x6c, 0xdf, 0x25, 0x54, 0x8c, 0x78, 0x02, 0x1e,
    0x4f, 0xff, 0x77, 0x61, 0xc3, 0xcb, 0x96, 0xac, 0xb2, 0x7e, 0xb2, 0xba,
    0x3b, 0x46, 0x56, 0xe6, 0x6d, 0xce, 0x8e, 0x52, 0x30, 0x54, 0x95, 0x9f,
    0xb4, 0x37, 0xd8, 0x7e, 0x28, 0x29, 0x3b, 0x50, 0x75, 0x40, 0xfa, 0x5b,
    0x1e, 0xae, 0xee, 0x7c, 0x31, 0x90, 0x01, 0x4e, 0x6a, 0xfa, 0x0e, 0x44,
    0x42, 0x11, 0xa4, 0xb9, 0x6a, 0xcf, 0x36, 0x60, 0x9d, 0xac, 0xa6, 0x15,
    0x4c, 0x60, 0x77, 0xee, 0x82, 0x55, 0x20, 0x92, 0x66, 0xd8, 0x57, 0xe0,
    0xa9, 0xc6, 0x8a, 0x4a, 0x31, 0x2b, 0x94, 0x61, 0x30, 0x44, 0x51, 0x63,
    0xcb, 0x8f, 0x62, 0x9c, 0x01, 0x48, 0xb8, 0x1d, 0x92, 0x45, 0x76, 0x96,
    0xb0, 0xf7, 0xd4, 0xd6, 0x81, 0x46, 0x6f, 0xab, 0xc1, 0x40, 0xc8, 0x74,
    0x00, 0xbf, 0x38, 0xe8, 0xe0, 0x7b, 0xad, 0x25, 0xe0, 0x2b, 0x45, 0x15,
    0xc8, 0x96, 0x60, 0x1b, 0xd8, 0xed, 0xe2, 0x5a, 0x0c, 0x41, 0xf3, 0x0a,
    0x2c, 0x57, 0x57, 0x55, 0x50, 0x2e, 0x91, 0x34, 0x0c, 0xa1, 0x4a, 0x70,
    0x18, 0xc3, 0xa2, 0x0f, 0x3d, 0x46, 0xbc, 0x0b, 0xa7, 0xfc, 0xd3, 0x7d,
    0x23, 0x09, 0x85, 0x5b, 0x29, 0xe7, 0xed, 0x5a, 0x20, 0x0e, 0x85, 0x91,
    0xa5, 0x3a, 0x4c, 0x18, 0xa6, 0x35, 0xd4, 0xd3, 0x98};

static const byte falcon512KatSig[] = {
    0x39, 0x47, 0xc1, 0x48, 0x7c, 0x58, 0xb7, 0x4a, 0xa4, 0x23, 0x4d, 0x62,
    0xd4, 0xa1, 0x12, 0x1a, 0x92, 0x3c, 0x3f, 0xe9, 0x14, 0x60, 0xc4, 0x20,
    0x0d, 0xdc, 0x8d, 0xdb, 0xf1, 0x60, 0xb2, 0x70, 0x31, 0x2f, 0x3c, 0x0d,
    0x45, 0x8b, 0x53, 0x55, 0x91, 0x51, 0x89, 0xc4, 0xc8, 0x61, 0x82, 0xe0,
    0xe0, 0xe8, 0x28, 0x62, 0xf8, 0xb4, 0x50, 0xbe, 0xef, 0x4c, 0xe9, 0x0f,
    0x60, 0xe7, 0x04, 0x1c, 0x68, 0xcc, 0x27, 0x60, 0xdf, 0x70, 0x58, 0xc7,
    0x0f, 0xc0, 0xd0, 0x61, 0xa3, 0xae, 0x1b, 0x2b, 0x3a, 0x98, 0xa3, 0xcf,
    0xa5, 0x5e, 0x59, 0x5a, 0x8f, 0x18, 0x83, 0x87, 0xc5, 0x65, 0x69, 0x7b,
    0x2d, 0xfc, 0x7a, 0x0b, 0x1b, 0x53, 0x16, 0xc9, 0x1c, 0xe1, 0xb6, 0xf4,
    0x93, 0x08, 0x56, 0xf3, 0xed, 0x3a, 0x9c, 0xd1, 0x27, 0xfb, 0xee, 0x1e,
    0x44, 0xd5, 0x35, 0xf5, 0x6e, 0x17, 0xcf, 0xb2, 0xdd, 0x99, 0x93, 0xaa,
    0xc4, 0x52, 0x6e, 0x98, 0x6a, 0x0b, 0x49, 0x3f, 0x7f, 0xb4, 0xdc, 0x52,
    0x04, 0x45, 0x9b, 0xa6, 0x80, 0x97, 0x26, 0x26, 0x55, 0x8c, 0x94, 0xd9,
    0x46, 0x34, 0xe0, 0xac, 0xf4, 0xbe, 0xa2, 0xf0, 0xc2, 0x35, 0x19, 0xc9,
    0x7e, 0x4e, 0x34, 0x63, 0x2c, 0x71, 0x48, 0x7a, 0xad, 0x8c, 0xe1, 0xa2,
    0xb2, 0x78, 0x5c, 0x05, 0xa5, 0x8e, 0x66, 0x8d, 0x4a, 0x9e, 0x89, 0x5b,
    0xe3, 0x4b, 0x66, 0xb5, 0x5b, 0xd0, 0x35, 0x13, 0x47, 0x0e, 0x55, 0x54,
    0xea, 0xba, 0x5f, 0xf1, 0x61, 0x83, 0xab, 0x05, 0x38, 0xbd, 0xb8, 0xdf,
    0x5b, 0x9d, 0x4b, 0x50, 0xac, 0x6f, 0xd4, 0x62, 0x6c, 0x81, 0x5b, 0x22,
    0xca, 0x15, 0x16, 0x83, 0x4e, 0x8d, 0xc6, 0x7f, 0x6a, 0x5e, 0x96, 0x92,
    0x87, 0x9a, 0x95, 0x8f, 0xb5, 0xb2, 0x2b, 0xd8, 0xb9, 0xbf, 0x0e, 0x6f,
    0x89, 0x68, 0x3d, 0xdd, 0xb6, 0x65, 0x21, 0xd6, 0x79, 0x98, 0x66, 0xdf,
    0x5f, 0x0a, 0x4d, 0x39, 0x3d, 0x6a, 0x45, 0xe2, 0x07, 0x50, 0xe4, 0x4d,
    0x1c, 0x09, 0x2e, 0x18, 0xcc, 0x2b, 0x2d, 0x45, 0x22, 0x26, 0xc1, 0x1d,
    0x2d, 0x84, 0x85, 0x03, 0x79, 0xef, 0x7a, 0xde, 0x7f, 0x3a, 0x0e, 0x2d,
    0x94, 0x33, 0x06, 0x93, 0x68, 0xca, 0x7c, 0x3c, 0x8f, 0x5e, 0x3a, 0x5d,
    0x96, 0x5f, 0x2b, 0x12, 0x35, 0xed, 0xd3, 0x2c, 0xf8, 0x69, 0xe0, 0xf3,
    0x64, 0xb7, 0x2d, 0xa9, 0x2f, 0x31, 0x23, 0x1a, 0xd0, 0xa2, 0x7b, 0x88,
    0xa5, 0x52, 0x36, 0x40, 0x48, 0xf5, 0x35, 0x05, 0x52, 0x61, 0x0c, 0x5d,
    0xeb, 0x05, 0x8b, 0x52, 0x2c, 0x34, 0xa6, 0x3e, 0x1e, 0xaf, 0x7f, 0xf7,
    0xd8, 0xca, 0x68, 0xc0, 0x13, 0xf7, 0x76, 0x9d, 0xc1, 0x20, 0x3c, 0xe8,
    0xc4, 0x87, 0xd7, 0xe8, 0x78, 0xfb, 0x79, 0xc4, 0x9a, 0xa0, 0x48, 0xcd,
    0x7c, 0xd2, 0x6c, 0xa8, 0x2b, 0x72, 0xb3, 0x52, 0x82, 0x3f, 0xb8, 0x93,
    0x41, 0x0f, 0xf0, 0xeb, 0x25, 0x94, 0x6b, 0xb4, 0x56, 0xd9, 0x6d, 0x90,
    0x62, 0x4e, 0x4a, 0x77, 0x6f, 0xe4, 0x37, 0xb5, 0x27, 0x7d, 0x06, 0x5b,
    0x65, 0x78, 0xd4, 0x34, 0x86, 0xb3, 0x11, 0x81, 0x13, 0x31, 0x42, 0x03,
    0x98, 0x8d, 0xfd, 0x53, 0xcc, 0x23, 0x1b, 0x76, 0xda, 0x3f, 0xcf, 0x8e,
    0x6a, 0x0e, 0xc6, 0xae, 0x8e, 0x1a, 0xcc, 0xe2, 0xe2, 0xd2, 0x65, 0x63,
    0xa5, 0xbf, 0xc9, 0xf1, 0xb1, 0x7f, 0xff, 0x86, 0x5b, 0x25, 0x7c, 0xae,
    0x88, 0x3b, 0x4a, 0x77, 0xd0, 0xca, 0xf6, 0xc7, 0xa7, 0x42, 0xca, 0x8a,
    0x47, 0x8d, 0x41, 0xa7, 0x71, 0x59, 0x5c, 0xb1, 0x9a, 0x8d, 0x6a, 0xdb,
    0xbd, 0x22, 0x3c, 0x60, 0x0c, 0xc0, 0x96, 0xf9, 0x0f, 0x6e, 0xd3, 0xf3,
    0x50, 0x28, 0xc9, 0x11, 0x55, 0x84, 0xa4, 0x0d, 0xec, 0xc9, 0xa6, 0x42,
    0x1c, 0xbc, 0x75, 0xde, 0x79, 0x20, 0xc2, 0x3e, 0xb0, 0x6e, 0xb4, 0x25,
    0x8a, 0xf1, 0x66, 0x50, 0x22, 0x00, 0x23, 0x01, 0x8b, 0xa7, 0xe1, 0xb2,
    0x8a, 0x82, 0xc7, 0xbb, 0x93, 0xb8, 0x4b, 0xaa, 0x8b, 0x18, 0xa5, 0xa8,
    0x34, 0xc7, 0xb7, 0xaf, 0xcf, 0x26, 0xc4, 0xa6, 0x38, 0xb5, 0xec, 0x9d,
    0xc7, 0x10, 0xad, 0xf1, 0x57, 0x8e, 0x84, 0x8e, 0x4a, 0xcc, 0x4a, 0x51,
    0xfd, 0xa3, 0x0e, 0x86, 0x51, 0xeb, 0xd6, 0x18, 0x72, 0xa7, 0xf4, 0xac,
    0x26, 0xc9, 0xd7, 0x73, 0x2a, 0x8d, 0x22, 0x4d, 0x82, 0x2f, 0x83, 0x33,
    0x28, 0x29, 0x99, 0xcf, 0x77, 0x52, 0x37, 0x8a, 0x23, 0xe8, 0x47, 0xc5,
    0xd4, 0xa4, 0x19, 0xc9, 0xc4, 0x1e, 0x16, 0xac, 0x66, 0xb5, 0x7f, 0x06,
    0xd2, 0x0a, 0xaa, 0x78, 0x52, 0xb9, 0x00, 0xed, 0xf3, 0xca, 0xf6, 0x13,
    0xbb, 0x29, 0x62, 0x4a, 0x1d, 0x0f, 0x36, 0x47, 0x28, 0x88, 0xfd, 0x5b,
    0xb6, 0x81, 0xfc, 0xfb, 0x95, 0x7e, 0xe5, 0x8a};

/* Verify a known signature with a cached public key; needs no keygen or sign */
static int _whTest_CryptoFalconVerifyKat(whClientContext* ctx)
{
    int        devId = WH_CLIENT_DEVID(ctx);
    int        ret;
    int        verified = 0;
    falcon_key key[1];
    whKeyId    keyId = WH_KEYID_ERASED;
    byte       msg[sizeof(falcon512KatMsg) - 1];
    uint8_t    label[] = "FalconKat";

    memcpy(msg, falcon512KatMsg, sizeof(msg));

    ret = wc_falcon_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Falcon key: %d\n", ret);
        return ret;
    }

    ret = wc_falcon_set_level(key, FALCON_LEVEL1);
    if (ret == 0) {
        ret = wc_falcon_import_public(falcon512KatPub, sizeof(falcon512KatPub),
                                      key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import the Falcon KAT key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_FalconImportKey(
            ctx, key, &keyId, WH_NVM_FLAGS_USAGE_VERIFY, sizeof(label), label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache the Falcon KAT key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_FalconSetKeyId(key, keyId);
    }

    /* wolfCrypt API, so the crypto callback reaches the cached key */
    if (ret == 0) {
        ret = wc_falcon_verify_msg(falcon512KatSig, sizeof(falcon512KatSig),
                                   msg, sizeof(msg), &verified, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify the Falcon KAT: %d\n", ret);
        }
        else if (!verified) {
            WH_ERROR_PRINT("Falcon KAT signature did not verify\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* A tampered message must fail verification without an error */
    if (ret == 0) {
        msg[0] ^= 0xFF;
        verified = 1;
        ret = wc_falcon_verify_msg(falcon512KatSig, sizeof(falcon512KatSig),
                                   msg, sizeof(msg), &verified, key);
        msg[0] ^= 0xFF;
        if (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) {
            ret      = 0;
            verified = 0;
        }
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify a tampered KAT message: %d\n",
                           ret);
        }
        else if (verified) {
            WH_ERROR_PRINT("Falcon verified a tampered KAT message\n");
            ret = WH_ERROR_ABORTED;
        }
    }

    /* The cached public key must come back unchanged */
    if (ret == 0) {
        falcon_key out[1];

        ret = wc_falcon_init_ex(out, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_FalconExportPublicKey(ctx, keyId, out, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to export the Falcon KAT key: %d\n",
                               ret);
            }
            else if ((wc_falcon_pub_size(out) !=
                      (int)sizeof(falcon512KatPub)) ||
                     (memcmp(out->p, falcon512KatPub,
                             sizeof(falcon512KatPub)) != 0)) {
                WH_ERROR_PRINT("Exported Falcon KAT key does not match\n");
                ret = WH_ERROR_ABORTED;
            }
            wc_falcon_free(out);
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    wc_falcon_free(key);

    if (ret == 0) {
        WH_TEST_PRINT("Falcon verify KAT DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}

int whTest_Crypto_Falcon(whClientContext* ctx)
{
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
    const int levels[] = {FALCON_LEVEL1, FALCON_LEVEL5};
    const int levelCnt = (int)(sizeof(levels) / sizeof(levels[0]));
    int       i;
#endif

    /* Falcon has no DMA path yet, so keep the client in non-DMA mode */
    (void)wh_Client_SetDmaMode(ctx, 0);

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
    for (i = 0; i < levelCnt; i++) {
        WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconWolfCrypt(ctx, levels[i]));
        WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconClient(ctx, levels[i]));
        WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconExportKey(ctx, levels[i]));
        WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconPublicOnly(ctx, levels[i]));
        WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconPrivateOnly(ctx, levels[i]));
    }
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconBufferTooSmall(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconOversize(ctx));
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconVerifyKat(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFalconBadArgs(ctx));
    return 0;
}

#endif /* HAVE_FALCON */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
