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
 * test-refactor/client-server/wh_test_crypto_ed25519.c
 *
 * Ed25519 sign/verify routed through the server via the per-client devId
 * (WH_CLIENT_DEVID):
 *   _whTest_CryptoEd25519Inline    - pure wolfCrypt (sign+verify locally,
 *                                    plus negative case for tampered sig)
 *   _whTest_CryptoEd25519ServerKey - server-cached sign and verify keyIds
 *   _whTest_CryptoEd25519Dma       - same, via the DMA messaging path
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/random.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef HAVE_ED25519

/* Imports the supplied private key into the server cache as a sign-only
 * keyId, and the matching public key as a verify-only keyId. Wipes the
 * client-side key material afterward and rebinds each ed25519_key struct
 * to its server-side keyId so the caller can use them as opaque handles.
 *
 * Output keyIds are written as soon as each import succeeds, even if a
 * later step fails. Callers must evict any non-erased keyId on the error
 * path. */
static int whTest_Ed25519ImportToServer(whClientContext* ctx, int devId,
                                        ed25519_key* key, ed25519_key* pubKey,
                                        uint8_t* label, uint16_t labelLen,
                                        whKeyId* outSignKeyId,
                                        whKeyId* outVerifyKeyId)
{
    int     ret = 0;
    byte    pubKeyRaw[ED25519_PUB_KEY_SIZE];
    word32  pubKeySize  = sizeof(pubKeyRaw);
    whKeyId signKeyId   = WH_KEYID_ERASED;
    whKeyId verifyKeyId = WH_KEYID_ERASED;

    ret = wc_ed25519_export_public(key, pubKeyRaw, &pubKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export Ed25519 public key: %d\n", ret);
    }
    else {
        ret = wc_ed25519_import_public(pubKeyRaw, pubKeySize, pubKey);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import Ed25519 public key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519ImportKey(
            ctx, key, &signKeyId, WH_NVM_FLAGS_USAGE_SIGN, labelLen, label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import Ed25519 key to server: %d\n",
                           ret);
        }
        else {
            if (outSignKeyId != NULL) {
                *outSignKeyId = signKeyId;
            }
            wc_ed25519_free(key);
            ret = wc_ed25519_init_ex(key, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to re-initialize Ed25519 key: %d\n",
                               ret);
            }
            else {
                wh_Client_Ed25519SetKeyId(key, signKeyId);
            }
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519ImportKey(ctx, pubKey, &verifyKeyId,
                                         WH_NVM_FLAGS_USAGE_VERIFY, labelLen,
                                         label);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to import Ed25519 public key to server: %d\n", ret);
        }
        else {
            if (outVerifyKeyId != NULL) {
                *outVerifyKeyId = verifyKeyId;
            }
            wc_ed25519_free(pubKey);
            ret = wc_ed25519_init_ex(pubKey, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to re-initialize Ed25519 public key: %d\n", ret);
            }
            else {
                wh_Client_Ed25519SetKeyId(pubKey, verifyKeyId);
            }
        }
    }

    return ret;
}

static int _whTest_CryptoEd25519Inline(whClientContext* ctx)
{
    int          devId    = WH_CLIENT_DEVID(ctx);
    int          ret      = 0;
    WC_RNG       rng[1];
    ed25519_key  key[1]    = {0};
    ed25519_key  pubKey[1] = {0};
    byte         msg[]     = "Test message for Ed25519 signing";
    byte         sig[ED25519_SIG_SIZE];
    word32       sigSz                          = sizeof(sig);
    int          verified                       = 0;
    const word32 msgSz                          = (word32)sizeof(msg);
    byte         pubKeyRaw[ED25519_PUB_KEY_SIZE];
    word32       pubKeySize                     = sizeof(pubKeyRaw);

    (void)ctx;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 public key: %d\n", ret);
        wc_ed25519_free(key);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate Ed25519 key: %d\n", ret);
    }
    else {
        ret = wc_ed25519_export_public(key, pubKeyRaw, &pubKeySize);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export Ed25519 public key: %d\n", ret);
        }
        else {
            ret = wc_ed25519_import_public(pubKeyRaw, pubKeySize, pubKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to import Ed25519 public key: %d\n",
                               ret);
            }
        }
    }

    if (ret == 0) {
        sigSz = sizeof(sig);
        ret   = wc_ed25519_sign_msg(msg, msgSz, sig, &sigSz, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign message with Ed25519: %d\n", ret);
        }
        else {
            ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, &verified,
                                        pubKey);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify Ed25519 signature: %d\n",
                               ret);
            }
            else if (verified != 1) {
                WH_ERROR_PRINT("Ed25519 signature verification failed\n");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Tampered signature must fail verification. wolfCrypt may signal
         * rejection either as ret==0 with verified==0, or as ret==SIG_VERIFY_E
         * (path-dependent inside wolfCrypt). Anything else is a real error. */
        sig[0] ^= 0xFF;
        verified = 0;
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, &verified, pubKey);
        if (verified != 0) {
            WH_ERROR_PRINT(
                "Modified Ed25519 signature unexpectedly verified\n");
            ret = -1;
        }
        else if (ret == 0 || ret == SIG_VERIFY_E) {
            ret = 0;
        }
        else {
            WH_ERROR_PRINT(
                "wc_ed25519_verify_msg of tampered sig errored: %d\n", ret);
        }
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 INLINE DEVID=0x%X SUCCESS\n", devId);
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}

static int _whTest_CryptoEd25519ServerKey(whClientContext* ctx)
{
    int         devId       = WH_CLIENT_DEVID(ctx);
    int         ret         = 0;
    WC_RNG      rng[1];
    ed25519_key key[1]      = {0};
    ed25519_key pubKey[1]   = {0};
    whKeyId     signKeyId   = WH_KEYID_ERASED;
    whKeyId     verifyKeyId = WH_KEYID_ERASED;
    byte        msg[]       = "Ed25519 server key message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz    = sizeof(sig);
    int         verified = 0;
    uint8_t     label[]  = "Ed25519 Server Key";

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 public key: %d\n", ret);
        wc_ed25519_free(key);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate Ed25519 key: %d\n", ret);
    }
    else {
        ret = whTest_Ed25519ImportToServer(ctx, devId, key, pubKey, label,
                                           sizeof(label), &signKeyId,
                                           &verifyKeyId);
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519Sign(ctx, key, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with server Ed25519 key: %d\n",
                           ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519Verify(ctx, pubKey, sig, sigSz, msg,
                                      (uint32_t)sizeof(msg), (uint8_t)Ed25519,
                                      NULL, 0, &verified);
        if (ret != 0) {
            WH_ERROR_PRINT(
                "Failed to verify server Ed25519 signature: %d\n", ret);
        }
        else if (verified != 1) {
            WH_ERROR_PRINT(
                "Server Ed25519 signature verification failed\n");
            ret = -1;
        }
    }

    /* Sign-only keyId must be rejected by Verify with WH_ERROR_USAGE. */
    if (ret == 0) {
        int negVerified = 0;
        int negRet      = wh_Client_Ed25519Verify(
            ctx, key, sig, sigSz, msg, (uint32_t)sizeof(msg),
            (uint8_t)Ed25519, NULL, 0, &negVerified);
        if (negRet != WH_ERROR_USAGE) {
            WH_ERROR_PRINT(
                "Sign-only Ed25519 key Verify expected WH_ERROR_USAGE (%d), "
                "got %d\n",
                WH_ERROR_USAGE, negRet);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Same shape as the inline tampered-sig case above. */
        sig[0] ^= 0xAA;
        verified = 0;
        ret      = wh_Client_Ed25519Verify(
            ctx, pubKey, sig, sigSz, msg, (uint32_t)sizeof(msg),
            (uint8_t)Ed25519, NULL, 0, &verified);
        if (verified != 0) {
            WH_ERROR_PRINT("Modified server Ed25519 signature unexpectedly "
                           "verified\n");
            ret = -1;
        }
        else if (ret == 0 || ret == SIG_VERIFY_E) {
            ret = 0;
        }
        else {
            WH_ERROR_PRINT(
                "Server Ed25519 verify of tampered sig errored: %d\n", ret);
        }
    }

    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 SERVER KEY DEVID=0x%X SUCCESS\n", devId);
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int _whTest_CryptoEd25519Dma(whClientContext* ctx)
{
    int         devId       = WH_CLIENT_DEVID(ctx);
    int         ret         = 0;
    WC_RNG      rng[1];
    ed25519_key key[1]      = {0};
    ed25519_key pubKey[1]   = {0};
    whKeyId     signKeyId   = WH_KEYID_ERASED;
    whKeyId     verifyKeyId = WH_KEYID_ERASED;
    byte        msg[]       = "Ed25519 DMA message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz    = sizeof(sig);
    int         verified = 0;
    uint8_t     label[]  = "Ed25519 DMA Key";

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key (DMA): %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 public key (DMA): %d\n",
                       ret);
        wc_ed25519_free(key);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate Ed25519 key (DMA): %d\n", ret);
    }
    else {
        ret = whTest_Ed25519ImportToServer(ctx, devId, key, pubKey, label,
                                           sizeof(label), &signKeyId,
                                           &verifyKeyId);
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519SignDma(ctx, key, msg, (uint32_t)sizeof(msg),
                                       (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign via DMA Ed25519 key: %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = wh_Client_Ed25519VerifyDma(ctx, pubKey, sig, sigSz, msg,
                                         (uint32_t)sizeof(msg),
                                         (uint8_t)Ed25519, NULL, 0, &verified);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify DMA Ed25519 signature: %d\n",
                           ret);
        }
        else if (verified != 1) {
            WH_ERROR_PRINT("DMA Ed25519 signature verification failed\n");
            ret = -1;
        }
    }

    /* Sign-only keyId must be rejected by VerifyDma with WH_ERROR_USAGE. */
    if (ret == 0) {
        int negVerified = 0;
        int negRet      = wh_Client_Ed25519VerifyDma(
            ctx, key, sig, sigSz, msg, (uint32_t)sizeof(msg),
            (uint8_t)Ed25519, NULL, 0, &negVerified);
        if (negRet != WH_ERROR_USAGE) {
            WH_ERROR_PRINT(
                "Sign-only Ed25519 key VerifyDma expected WH_ERROR_USAGE (%d), "
                "got %d\n",
                WH_ERROR_USAGE, negRet);
            ret = -1;
        }
    }

    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 DMA DEVID=0x%X SUCCESS\n", devId);
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

/* Cache a NONEXPORTABLE Ed25519 keypair on the server, sign a message there,
 * then export only the public half via wh_Client_Ed25519ExportPublicKey and
 * verify the signature client-side. */
static int _whTest_CryptoEd25519ExportPublicKey(whClientContext* ctx)
{
    int         devId    = WH_CLIENT_DEVID(ctx);
    int         ret      = 0;
    ed25519_key hsmKey[1] = {0};
    ed25519_key pubKey[1] = {0};
    whKeyId     keyId     = WH_KEYID_ERASED;
    byte        msg[]     = "Ed25519 export-public message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz    = sizeof(sig);
    int         verified = 0;
    uint8_t     denyBuf[256];
    uint16_t    denyLen  = sizeof(denyBuf);

    ret = wh_Client_Ed25519MakeCacheKey(ctx, &keyId,
                                        WH_NVM_FLAGS_USAGE_SIGN |
                                            WH_NVM_FLAGS_USAGE_VERIFY |
                                            WH_NVM_FLAGS_NONEXPORTABLE,
                                        0, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to make NONEXPORTABLE cached Ed25519 key %d\n",
                       ret);
        return ret;
    }

    /* Full export must be denied by the NONEXPORTABLE policy. */
    {
        int denyRet = wh_Client_KeyExport(ctx, keyId, NULL, 0, denyBuf,
                                          &denyLen);
        if (denyRet != WH_ERROR_ACCESS) {
            WH_ERROR_PRINT(
                "NONEXPORTABLE Ed25519 full export was not denied: %d\n",
                denyRet);
            ret = -1;
        }
    }

    /* Sign on the server using the cached private key. */
    if (ret == 0) {
        ret = wc_ed25519_init_ex(hsmKey, NULL, devId);
        if (ret == 0) {
            ret = wh_Client_Ed25519SetKeyId(hsmKey, keyId);
        }
        if (ret == 0) {
            ret = wh_Client_Ed25519Sign(ctx, hsmKey, msg, (uint32_t)sizeof(msg),
                                        (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
            if (ret != 0) {
                WH_ERROR_PRINT("HSM Ed25519 sign failed %d\n", ret);
            }
        }
        wc_ed25519_free(hsmKey);
    }

    /* Public-only export must succeed and verify the signature client-side. */
    if (ret == 0) {
        ret = wc_ed25519_init_ex(pubKey, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Ed25519ExportPublicKey(ctx, keyId, pubKey, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_Ed25519ExportPublicKey failed %d\n",
                               ret);
            }
            else if (pubKey->pubKeySet != 1 || pubKey->privKeySet != 0) {
                WH_ERROR_PRINT(
                    "Exported Ed25519 key flags wrong: pub=%d priv=%d\n",
                    (int)pubKey->pubKeySet, (int)pubKey->privKeySet);
                ret = -1;
            }
            else {
                ret = wc_ed25519_verify_msg(sig, sigSz, msg,
                                            (word32)sizeof(msg), &verified,
                                            pubKey);
                if (ret != 0 || verified != 1) {
                    WH_ERROR_PRINT(
                        "Client-side Ed25519 verify failed ret=%d verify=%d\n",
                        ret, verified);
                    if (ret == 0) {
                        ret = -1;
                    }
                }
            }
            wc_ed25519_free(pubKey);
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 EXPORT-PUBLIC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}


/* Exercises wh_Client_Ed25519Sign with an undersized output buffer: must
 * return WH_ERROR_BUFFER_SIZE and report the required signature length. */
static int _whTest_CryptoEd25519BufferTooSmall(whClientContext* ctx)
{
    int          devId = WH_CLIENT_DEVID(ctx);
    int          ret;
    WC_RNG       rng[1];
    ed25519_key  key[1];
    const byte   msg[]                           = "ed25519 buf size test";
    uint8_t      small_sig[ED25519_SIG_SIZE - 1] = {0};
    uint8_t      full_sig[ED25519_SIG_SIZE]      = {0};
    uint32_t     sig_len;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ed25519_init_ex %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ed25519_make_key %d\n", ret);
        goto done;
    }

    sig_len = (uint32_t)sizeof(small_sig);
    ret     = wh_Client_Ed25519Sign(ctx, key, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, small_sig,
                                    &sig_len);
    if (ret != WH_ERROR_BUFFER_SIZE) {
        WH_ERROR_PRINT(
            "Ed25519Sign small buf expected WH_ERROR_BUFFER_SIZE, got %d\n",
            ret);
        ret = WH_TEST_FAIL;
        goto done;
    }
    if (sig_len != ED25519_SIG_SIZE) {
        WH_ERROR_PRINT("Ed25519Sign small buf reported size %u, expected %u\n",
                       (unsigned)sig_len, (unsigned)ED25519_SIG_SIZE);
        ret = WH_TEST_FAIL;
        goto done;
    }

    sig_len = (uint32_t)sizeof(full_sig);
    ret     = wh_Client_Ed25519Sign(ctx, key, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, full_sig,
                                    &sig_len);
    if (ret != 0) {
        WH_ERROR_PRINT("Ed25519Sign full buf failed: %d\n", ret);
        goto done;
    }
    if (sig_len != ED25519_SIG_SIZE) {
        WH_ERROR_PRINT("Ed25519Sign full buf size %u, expected %u\n",
                       (unsigned)sig_len, (unsigned)ED25519_SIG_SIZE);
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("Ed25519 buffer-size DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    (void)wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}

int whTest_Crypto_Ed25519(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519Inline(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519ServerKey(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519Dma(ctx));
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519ExportPublicKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519BufferTooSmall(ctx));
    return 0;
}
#endif /* HAVE_ED25519 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
