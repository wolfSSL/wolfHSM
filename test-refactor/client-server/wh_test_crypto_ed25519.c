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
 *   _whTest_CryptoEd25519Dma       - same, with verify over DMA (sign has no
 *                                    DMA variant)
 *   _whTest_CryptoEd25519DmaDevId  - wolfCrypt sign/verify (pure and ph)
 *                                    with server-held keys: sign works in DMA
 *                                    mode, verify works on WH_DEV_ID_DMA
 *   _whTest_CryptoEd25519SignMsgSize - the inline sign request limit, with and
 *                                    without a context
 *   _whTest_CryptoEd25519DmaModeMsgSize - in DMA mode sign is limited to the
 *                                    comm buffer; Ed25519ph covers longer
 *                                    messages
 *   _whTest_CryptoEd25519SignDmaRefused - the DMA callback declines sign and
 *                                    the server refuses a raw DMA sign request
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_crypto.h"

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

    /* Sign has no DMA variant */
    if (ret == 0) {
        ret = wh_Client_Ed25519Sign(ctx, key, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign with Ed25519 key: %d\n", ret);
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

#ifndef WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
/* wolfCrypt Ed25519 with keys held only by the server, with DMA. Sign has no
 * DMA variant, so the DMA callback reports it unavailable:
 *  - in DMA dispatch mode, sign (pure and prehashed) is retried as a standard
 *    request and succeeds, while verify uses DMA;
 *  - on WH_DEV_ID_DMA verify works (sign being declined there is checked in
 *    _whTest_CryptoEd25519SignDmaRefused). */
static int _whTest_CryptoEd25519DmaDevId(whClientContext* ctx)
{
    int         ret = 0;
    WC_RNG      rng[1];
    ed25519_key key[1]      = {0};
    ed25519_key pubKey[1]   = {0};
    whKeyId     signKeyId   = WH_KEYID_ERASED;
    whKeyId     verifyKeyId = WH_KEYID_ERASED;
    byte        msg[]       = "Ed25519 DMA devId message";
    byte        sig[ED25519_SIG_SIZE];
    byte        sigPh[ED25519_SIG_SIZE];
    word32      sigSz    = sizeof(sig);
    word32      sigPhSz  = sizeof(sigPh);
    int         verified = 0;
    int         prevDma  = 0;
    uint8_t     label[]  = "Ed25519 DMA devId";

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, INVALID_DEVID);
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
        /* Rebinds both structs to the client devId and their server keyIds */
        ret = whTest_Ed25519ImportToServer(ctx, WH_CLIENT_DEVID(ctx), key,
                                           pubKey, label, sizeof(label),
                                           &signKeyId, &verifyKeyId);
    }

    /* DMA dispatch mode: sign falls back to a standard request */
    if (ret == 0) {
        ret = wh_Client_GetDmaMode(ctx, &prevDma);
    }
    if (ret == 0) {
        ret = wh_Client_SetDmaMode(ctx, 1);
    }
    if (ret == 0) {
        ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &sigSz, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 sign in DMA mode failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, sizeof(msg), &verified,
                                    pubKey);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519 verify in DMA mode failed: %d %d\n", ret,
                           verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }
    if (ret == 0) {
        verified = 0;
        ret      = wc_ed25519ph_sign_msg(msg, sizeof(msg), sigPh, &sigPhSz, key,
                                         NULL, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519ph sign in DMA mode failed: %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_ed25519ph_verify_msg(sigPh, sigPhSz, msg, sizeof(msg),
                                      &verified, pubKey, NULL, 0);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519ph verify in DMA mode failed: %d %d\n", ret,
                           verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }
    (void)wh_Client_SetDmaMode(ctx, prevDma);

    /* WH_DEV_ID_DMA: verify works */
    if (ret == 0) {
        wc_ed25519_free(pubKey);
        ret = wc_ed25519_init_ex(pubKey, NULL, WH_DEV_ID_DMA);
        if (ret == 0) {
            ret = wh_Client_Ed25519SetKeyId(pubKey, verifyKeyId);
        }
    }
    if (ret == 0) {
        verified = 0;
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, sizeof(msg), &verified,
                                    pubKey);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519 verify on WH_DEV_ID_DMA failed: %d %d\n",
                           ret, verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }
    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT(
            "Ed25519 DMA MODE AND WH_DEV_ID_DMA SIGN/VERIFY SUCCESS\n");
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}
/* Without a DMA variant, Ed25519 sign in DMA mode carries the message inline,
 * so it must fit in the comm buffer. The largest message that fits signs and
 * verifies, a longer one is refused with an error (not passed to wolfCrypt's
 * software path), and Ed25519ph, which sends only the prehash, signs it. */
static int _whTest_CryptoEd25519DmaModeMsgSize(whClientContext* ctx)
{
    /* static: keep the comm-buffer-sized message off the stack */
    static byte  bigMsg[WOLFHSM_CFG_COMM_DATA_LEN + 1];
    const word32 maxMsgLen =
        (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                 sizeof(whMessageCrypto_GenericRequestHeader) -
                 sizeof(whMessageCrypto_Ed25519SignRequest));
    int         ret = 0;
    WC_RNG      rng[1];
    ed25519_key key[1]      = {0};
    ed25519_key pubKey[1]   = {0};
    whKeyId     signKeyId   = WH_KEYID_ERASED;
    whKeyId     verifyKeyId = WH_KEYID_ERASED;
    byte        sig[ED25519_SIG_SIZE];
    word32      sigSz    = sizeof(sig);
    int         verified = 0;
    int         prevDma  = 0;
    uint8_t     label[]  = "Ed25519 DMA msg size";

    memset(bigMsg, 0xA5, sizeof(bigMsg));

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    ret = wc_ed25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize Ed25519 key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_ed25519_init_ex(pubKey, NULL, INVALID_DEVID);
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
        ret = whTest_Ed25519ImportToServer(ctx, WH_CLIENT_DEVID(ctx), key,
                                           pubKey, label, sizeof(label),
                                           &signKeyId, &verifyKeyId);
    }

    if (ret == 0) {
        ret = wh_Client_GetDmaMode(ctx, &prevDma);
    }
    if (ret == 0) {
        ret = wh_Client_SetDmaMode(ctx, 1);
    }

    /* The largest message that fits */
    if (ret == 0) {
        ret = wc_ed25519_sign_msg(bigMsg, maxMsgLen, sig, &sigSz, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519 sign of %u bytes in DMA mode failed: %d\n",
                           (unsigned)maxMsgLen, ret);
        }
    }
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(sig, sigSz, bigMsg, maxMsgLen, &verified,
                                    pubKey);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519 verify of %u bytes failed: %d %d\n",
                           (unsigned)maxMsgLen, ret, verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }

    /* One byte more is refused */
    if (ret == 0) {
        sigSz = sizeof(sig);
        ret   = wc_ed25519_sign_msg(bigMsg, maxMsgLen + 1, sig, &sigSz, key);
        if (ret != BAD_FUNC_ARG) {
            WH_ERROR_PRINT("Oversized Ed25519 sign in DMA mode returned %d, "
                           "expected BAD_FUNC_ARG\n",
                           ret);
            ret = WH_TEST_FAIL;
        }
        else {
            ret = 0;
        }
    }

    /* Ed25519ph signs the oversized message */
    if (ret == 0) {
        sigSz    = sizeof(sig);
        verified = 0;
        ret = wc_ed25519ph_sign_msg(bigMsg, maxMsgLen + 1, sig, &sigSz, key,
                                    NULL, 0);
        if (ret != 0) {
            WH_ERROR_PRINT("Ed25519ph sign of oversized message failed: %d\n",
                           ret);
        }
    }
    if (ret == 0) {
        ret = wc_ed25519ph_verify_msg(sig, sigSz, bigMsg, maxMsgLen + 1,
                                      &verified, pubKey, NULL, 0);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519ph verify of oversized message failed: "
                           "%d %d\n",
                           ret, verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }
    (void)wh_Client_SetDmaMode(ctx, prevDma);

    if (!WH_KEYID_ISERASED(signKeyId)) {
        (void)wh_Client_KeyEvict(ctx, signKeyId);
    }
    if (!WH_KEYID_ISERASED(verifyKeyId)) {
        (void)wh_Client_KeyEvict(ctx, verifyKeyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 DMA MODE MESSAGE SIZE SUCCESS\n");
    }

    wc_ed25519_free(pubKey);
    wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}
#endif /* !WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT */

/* Ed25519 sign has no DMA variant: the server would read the message twice in
 * client memory, and a client changing it in between recovers the private
 * key. Check both ends:
 *  - the client DMA callback declines the operation without contacting the
 *    server;
 *  - the server refuses a raw DMA sign request, as a client not using the
 *    wolfHSM client library could send, before reading the body. The body has
 *    the size of the removed request struct. */
static int _whTest_CryptoEd25519SignDmaRefused(whClientContext* ctx)
{
    whMessageCrypto_GenericRequestHeader*  reqHdr;
    whMessageCrypto_GenericResponseHeader* resHdr;
    uint8_t* dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    uint16_t group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint16_t action  = WC_ALGO_TYPE_PK;
    uint16_t reqLen  = (uint16_t)(sizeof(*reqHdr) + 64);
    uint16_t resLen  = 0;
    int      ret;
#ifdef WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
    /* The DMA callback fails every operation in this configuration */
    const int cbExpected = WC_HW_E;
#else
    const int cbExpected = CRYPTOCB_UNAVAILABLE;
#endif
    wc_CryptoInfo info;
    ed25519_key   key[1];
    byte          msg[] = "Ed25519 DMA sign declined";
    byte          sig[ED25519_SIG_SIZE];
    word32        sigSz = sizeof(sig);

    ret = wc_ed25519_init_ex(key, NULL, WH_DEV_ID_DMA);
    WH_TEST_ASSERT_RETURN(ret == 0);
    memset(&info, 0, sizeof(info));
    info.algo_type             = WC_ALGO_TYPE_PK;
    info.pk.type               = WC_PK_TYPE_ED25519_SIGN;
    info.pk.ed25519sign.key    = key;
    info.pk.ed25519sign.in     = msg;
    info.pk.ed25519sign.inLen  = sizeof(msg);
    info.pk.ed25519sign.out    = sig;
    info.pk.ed25519sign.outLen = &sigSz;
    info.pk.ed25519sign.type   = (byte)Ed25519;
    ret = wh_Client_CryptoCbDma(WH_DEV_ID_DMA, &info, ctx);
    wc_ed25519_free(key);
    if (ret != cbExpected) {
        WH_ERROR_PRINT("Ed25519 sign on the DMA callback returned %d, "
                       "expected %d\n",
                       ret, cbExpected);
        return WH_TEST_FAIL;
    }

    WH_TEST_ASSERT_RETURN(dataPtr != NULL);
    memset(dataPtr, 0, reqLen);
    reqHdr              = (whMessageCrypto_GenericRequestHeader*)dataPtr;
    reqHdr->algoType    = WC_PK_TYPE_ED25519_SIGN;
    reqHdr->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    reqHdr->affinity    = ctx->cryptoAffinity;

    ret = wh_Client_SendRequest(ctx, group, action, reqLen, dataPtr);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    do {
        ret = wh_Client_RecvResponse(ctx, &group, &action, &resLen,
                                     WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    } while (ret == WH_ERROR_NOTREADY);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(group == WH_MESSAGE_GROUP_CRYPTO_DMA);
    WH_TEST_ASSERT_RETURN(action == WC_ALGO_TYPE_PK);
    WH_TEST_ASSERT_RETURN(resLen == sizeof(*resHdr));

    resHdr = (whMessageCrypto_GenericResponseHeader*)dataPtr;
    if (resHdr->rc != NOT_COMPILED_IN) {
        WH_ERROR_PRINT("Raw Ed25519 DMA sign request returned %d, expected "
                       "NOT_COMPILED_IN (%d)\n",
                       (int)resHdr->rc, NOT_COMPILED_IN);
        return WH_TEST_FAIL;
    }
    WH_TEST_PRINT("Ed25519 DMA SIGN DECLINED AND REFUSED SUCCESS\n");
    return 0;
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

/* One keygen call caches the private key and returns the public key. Verify
 * the returned public key byte-matches wh_Client_Ed25519ExportPublicKey and
 * that it verifies a signature made by the cached private key. */
static int _whTest_CryptoEd25519CacheKeyAndExportPublic(whClientContext* ctx)
{
    int         devId    = WH_CLIENT_DEVID(ctx);
    int         ret      = 0;
    ed25519_key genPub[1] = {0};
    ed25519_key refPub[1] = {0};
    whKeyId     keyId     = WH_KEYID_ERASED;
    byte        msg[]     = "Ed25519 cache-export-public message";
    byte        sig[ED25519_SIG_SIZE];
    uint32_t    sigSz     = sizeof(sig);
    int         verified  = 0;
    byte        genDer[128];
    byte        refDer[128];
    int         genDerSz  = 0;
    int         refDerSz  = 0;

    ret = wc_ed25519_init_ex(genPub, NULL, INVALID_DEVID);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ed25519_init_ex %d\n", ret);
        return ret;
    }

    ret = wh_Client_Ed25519MakeCacheKeyAndExportPublic(
        ctx, &keyId, WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, 0,
        NULL, genPub);
    if (ret != 0) {
        WH_ERROR_PRINT("Ed25519MakeCacheKeyAndExportPublic failed %d\n", ret);
    }

    /* Cross-check against a separate public export of the same keyId. */
    if (ret == 0) {
        ret = wc_ed25519_init_ex(refPub, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wh_Client_Ed25519ExportPublicKey(ctx, keyId, refPub, 0, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("wh_Client_Ed25519ExportPublicKey failed %d\n",
                               ret);
            }
            else {
                genDerSz =
                    wc_Ed25519PublicKeyToDer(genPub, genDer, sizeof(genDer), 1);
                refDerSz =
                    wc_Ed25519PublicKeyToDer(refPub, refDer, sizeof(refDer), 1);
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
        ret = wh_Client_Ed25519Sign(ctx, genPub, msg, (uint32_t)sizeof(msg),
                                    (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != 0) {
            WH_ERROR_PRINT("HSM Ed25519 sign failed %d\n", ret);
        }
    }
    if (ret == 0) {
        ret = wc_ed25519_verify_msg(sig, sigSz, msg, (word32)sizeof(msg),
                                    &verified, refPub);
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("verify with keygen pub failed ret=%d verify=%d\n",
                           ret, verified);
            if (ret == 0) {
                ret = -1;
            }
        }
    }

    wc_ed25519_free(refPub);
    wc_ed25519_free(genPub);
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }

    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 CACHE-AND-EXPORT-PUBLIC DEVID=0x%X SUCCESS\n",
                      devId);
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

/* Cache keygen argument checks, including WH_NVM_FLAGS_EPHEMERAL */
static int _whTest_CryptoEd25519MakeCacheKeyArgs(whClientContext* ctx)
{
    int         ret    = 0;
    whKeyId     keyId  = WH_KEYID_ERASED;
    ed25519_key pub[1] = {0};

    if (wh_Client_Ed25519MakeCacheKey(ctx, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0,
                                      NULL) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("Ed25519 cache keygen accepted EPHEMERAL\n");
        ret = WH_TEST_FAIL;
    }
    if ((wh_Client_Ed25519MakeCacheKeyAndExportPublic(
             ctx, &keyId, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, pub) !=
         WH_ERROR_BADARGS) ||
        (wh_Client_Ed25519MakeCacheKeyAndExportPublic(
             ctx, NULL, WH_NVM_FLAGS_NONE, 0, NULL, pub) != WH_ERROR_BADARGS) ||
        (wh_Client_Ed25519MakeCacheKeyAndExportPublic(
             ctx, &keyId, WH_NVM_FLAGS_NONE, 0, NULL, NULL) !=
         WH_ERROR_BADARGS)) {
        WH_ERROR_PRINT("Ed25519 cache keygen argument check failed\n");
        ret = WH_TEST_FAIL;
    }
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 CACHE-KEY ARGS SUCCESS\n");
    }
    return ret;
}

/* A NULL key must be rejected before its devCtx is read */
static int _whTest_CryptoEd25519NullKey(whClientContext* ctx)
{
    const uint8_t msg[]                 = "ed25519 null key";
    uint8_t       sig[ED25519_SIG_SIZE] = {0};
    uint32_t      sigLen                = (uint32_t)sizeof(sig);
    int           res                   = 0;
    int           ret;

    ret = wh_Client_Ed25519Sign(ctx, NULL, msg, (uint32_t)sizeof(msg),
                                (uint8_t)Ed25519, NULL, 0, sig, &sigLen);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
    ret = wh_Client_Ed25519Verify(ctx, NULL, sig, (uint32_t)sizeof(sig), msg,
                                  (uint32_t)sizeof(msg), (uint8_t)Ed25519,
                                  NULL, 0, &res);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
#ifdef WOLFHSM_CFG_DMA
    ret = wh_Client_Ed25519VerifyDma(ctx, NULL, sig, (uint32_t)sizeof(sig),
                                     msg, (uint32_t)sizeof(msg),
                                     (uint8_t)Ed25519, NULL, 0, &res);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_BADARGS);
#endif
    WH_TEST_PRINT("Ed25519 NULL KEY REJECT SUCCESS\n");
    return 0;
}

/* wh_Client_Ed25519Sign carries the message and context inline, so together
 * they must fit in the comm buffer. Sign at the limit, with and without a
 * context, and check that one byte more is refused with
 * WH_ERROR_REQUEST_SIZE. Signatures are verified locally. */
static int _whTest_CryptoEd25519SignMsgSize(whClientContext* ctx)
{
    /* static: keep the comm-buffer-sized message off the stack */
    static byte  bigMsg[WOLFHSM_CFG_COMM_DATA_LEN];
    const word32 maxLen =
        (word32)(WOLFHSM_CFG_COMM_DATA_LEN -
                 sizeof(whMessageCrypto_GenericRequestHeader) -
                 sizeof(whMessageCrypto_Ed25519SignRequest));
    const byte   context[]  = "Ed25519ctx size-limit context";
    const word32 contextLen = (word32)sizeof(context);
    int          ret        = 0;
    WC_RNG       rng[1];
    ed25519_key  key[1]    = {0};
    ed25519_key  hsmKey[1] = {0};
    whKeyId      keyId     = WH_KEYID_ERASED;
    byte         sig[ED25519_SIG_SIZE];
    uint32_t     sigSz    = sizeof(sig);
    int          verified = 0;
    uint8_t      label[]  = "Ed25519 msg size";

    memset(bigMsg, 0x5A, sizeof(bigMsg));

    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(ctx));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    /* key stays local for verification, hsmKey references the server copy */
    ret = wc_ed25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, key);
    }
    if (ret == 0) {
        ret = wh_Client_Ed25519ImportKey(
            ctx, key, &keyId, WH_NVM_FLAGS_USAGE_SIGN, sizeof(label), label);
    }
    if (ret == 0) {
        ret = wc_ed25519_init_ex(hsmKey, NULL, WH_CLIENT_DEVID(ctx));
    }
    if (ret == 0) {
        ret = wh_Client_Ed25519SetKeyId(hsmKey, keyId);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set up Ed25519 key: %d\n", ret);
    }

    /* Pure Ed25519: the largest message signs, one byte more is refused */
    if (ret == 0) {
        ret = wh_Client_Ed25519Sign(ctx, hsmKey, bigMsg, maxLen,
                                    (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret == 0) {
            ret = wc_ed25519_verify_msg(sig, sigSz, bigMsg, maxLen, &verified,
                                        key);
        }
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519 sign of %u bytes failed: %d %d\n",
                           (unsigned)maxLen, ret, verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }
    if (ret == 0) {
        sigSz = sizeof(sig);
        ret   = wh_Client_Ed25519Sign(ctx, hsmKey, bigMsg, maxLen + 1,
                                      (uint8_t)Ed25519, NULL, 0, sig, &sigSz);
        if (ret != WH_ERROR_REQUEST_SIZE) {
            WH_ERROR_PRINT("Oversized Ed25519 sign returned %d, expected "
                           "WH_ERROR_REQUEST_SIZE\n",
                           ret);
            ret = WH_TEST_FAIL;
        }
        else {
            ret = 0;
        }
    }

    /* Ed25519ctx: the context counts towards the same limit */
    if (ret == 0) {
        sigSz    = sizeof(sig);
        verified = 0;
        ret = wh_Client_Ed25519Sign(ctx, hsmKey, bigMsg, maxLen - contextLen,
                                    (uint8_t)Ed25519ctx, context, contextLen,
                                    sig, &sigSz);
        if (ret == 0) {
            ret = wc_ed25519ctx_verify_msg(sig, sigSz, bigMsg,
                                           maxLen - contextLen, &verified, key,
                                           context, (byte)contextLen);
        }
        if ((ret != 0) || (verified != 1)) {
            WH_ERROR_PRINT("Ed25519ctx sign at the limit failed: %d %d\n", ret,
                           verified);
            ret = (ret != 0) ? ret : WH_TEST_FAIL;
        }
    }
    if (ret == 0) {
        sigSz = sizeof(sig);
        ret   = wh_Client_Ed25519Sign(
            ctx, hsmKey, bigMsg, maxLen - contextLen + 1, (uint8_t)Ed25519ctx,
            context, contextLen, sig, &sigSz);
        if (ret != WH_ERROR_REQUEST_SIZE) {
            WH_ERROR_PRINT("Oversized Ed25519ctx sign returned %d, expected "
                           "WH_ERROR_REQUEST_SIZE\n",
                           ret);
            ret = WH_TEST_FAIL;
        }
        else {
            ret = 0;
        }
    }

    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        WH_TEST_PRINT("Ed25519 SIGN MESSAGE SIZE SUCCESS\n");
    }

    wc_ed25519_free(hsmKey);
    wc_ed25519_free(key);
    (void)wc_FreeRng(rng);
    return ret;
}

int whTest_Crypto_Ed25519(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519Inline(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519ServerKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519SignMsgSize(ctx));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519Dma(ctx));
#ifndef WOLFHSM_CFG_DMA_REQUIRE_ALIGNED_PADDED_OUTPUT
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519DmaDevId(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519DmaModeMsgSize(ctx));
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519SignDmaRefused(ctx));
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519ExportPublicKey(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519CacheKeyAndExportPublic(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519BufferTooSmall(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519MakeCacheKeyArgs(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoEd25519NullKey(ctx));
    return 0;
}
#endif /* HAVE_ED25519 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
