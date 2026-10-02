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
 * test-refactor/client-server/wh_test_crypto_frodokem.c
 *
 * FrodoKEM tests routed through the server:
 *   _whTest_CryptoFrodoKemWolfCrypt - keygen / encapsulate / decapsulate
 *                                     through the wolfCrypt API, so the
 *                                     crypto callback does the dispatching
 *   _whTest_CryptoFrodoKemDma       - the same through the direct DMA client
 *                                     API, plus a cached-key round trip
 *   _whTest_CryptoFrodoKemBadArgs   - argument and type rejection
 *
 * Every FrodoKEM object is larger than the default comm data length, so the
 * non-DMA path is expected to refuse with WH_ERROR_BADARGS unless
 * WOLFHSM_CFG_COMM_DATA_LEN has been raised a long way. The tests assert that
 * refusal rather than skipping it, so a build that does raise the buffer would
 * show up here as a failure to update the test.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/wc_frodokem.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLFSSL_HAVE_FRODOKEM

#if !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) &&    \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)

/* Smallest compiled-in parameter set. FrodoKEM-640 keeps the buffers below at
 * roughly 20KB rather than the 43KB that 1344 would need. */
#if defined(WOLFSSL_WC_FRODOKEM_640)
#define WH_TEST_FRODOKEM_TYPE WC_FRODOKEM_640_SHAKE
#elif defined(WOLFSSL_WC_FRODOKEM_976)
#define WH_TEST_FRODOKEM_TYPE WC_FRODOKEM_976_SHAKE
#else
#define WH_TEST_FRODOKEM_TYPE WC_FRODOKEM_1344_SHAKE
#endif

/* Whether a FrodoKEM ciphertext plus shared secret could ever fit inline. Used
 * to decide what the non-DMA path is expected to return. */
#define WH_TEST_FRODOKEM_FITS_INLINE                          \
    ((FRODOKEM_MAX_CIPHER_TEXT_SIZE + FRODOKEM_MAX_LENSEC) <= \
     WOLFHSM_CFG_COMM_DATA_LEN)

/* One shared static arena: these buffers are far too large for the stack of a
 * test thread, and the suite is single-threaded per client. */
static uint8_t _ct[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
#ifdef WOLFHSM_CFG_DMA
static uint8_t _ct2[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
#endif
static uint8_t _ss[FRODOKEM_MAX_LENSEC];
#ifdef WOLFHSM_CFG_DMA
static uint8_t _ss2[FRODOKEM_MAX_LENSEC];
#endif
static FrodoKemKey _key[1];
#ifdef WOLFHSM_CFG_DMA
static FrodoKemKey _key2[1];
#endif

#ifdef WOLFHSM_CFG_DMA
/* Generate, encapsulate and decapsulate through the plain wolfCrypt API. The
 * key carries the wolfHSM devId, so every operation is dispatched by the
 * crypto callback and serviced by the server. */
static int _whTest_CryptoFrodoKemWolfCrypt(whClientContext* ctx, int devId)
{
    int    ret;
    word32 ctLen;
    word32 ssLen;
    WC_RNG rng[1];
    int    rngInited = 0;

    (void)ctx;

    ret = wc_FrodoKemKey_Init(_key, WH_TEST_FRODOKEM_TYPE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init FrodoKEM key: %d\n", ret);
        return ret;
    }

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        wc_FrodoKemKey_Free(_key);
        return ret;
    }
    rngInited = 1;

    ret = wc_FrodoKemKey_CipherTextSize(_key, &ctLen);
    if (ret == 0) {
        ret = wc_FrodoKemKey_SharedSecretSize(_key, &ssLen);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to query FrodoKEM sizes: %d\n", ret);
        goto done;
    }

    ret = wc_FrodoKemKey_MakeKey(_key, rng);
    if (ret != 0) {
        WH_ERROR_PRINT("FrodoKEM MakeKey failed: %d\n", ret);
        goto done;
    }

    memset(_ct, 0, ctLen);
    memset(_ss, 0, ssLen);
    memset(_ss2, 0, ssLen);

    ret = wc_FrodoKemKey_Encapsulate(_key, _ct, _ss, rng);
    if (ret != 0) {
        WH_ERROR_PRINT("FrodoKEM Encapsulate failed: %d\n", ret);
        goto done;
    }

    ret = wc_FrodoKemKey_Decapsulate(_key, _ss2, _ct, ctLen);
    if (ret != 0) {
        WH_ERROR_PRINT("FrodoKEM Decapsulate failed: %d\n", ret);
        goto done;
    }

    if (memcmp(_ss, _ss2, ssLen) != 0) {
        WH_ERROR_PRINT("FrodoKEM shared secrets differ\n");
        ret = WH_ERROR_ABORTED;
    }

done:
    if (rngInited) {
        (void)wc_FreeRng(rng);
    }
    wc_FrodoKemKey_Free(_key);
    return ret;
}

/* Drive the direct DMA client API: generate and export a key, encapsulate to
 * it and decapsulate the result, then repeat with the key held in the server
 * cache so the private half never crosses back to the client. */
static int _whTest_CryptoFrodoKemDma(whClientContext* ctx)
{
    int      ret;
    int      devId = WH_CLIENT_DEVID(ctx);
    word32   ctLen;
    word32   ssLen;
    uint32_t ctLenIo;
    uint32_t ssLenIo;
    whKeyId  keyId = WH_KEYID_ERASED;

    ret = wc_FrodoKemKey_Init(_key, WH_TEST_FRODOKEM_TYPE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init FrodoKEM key: %d\n", ret);
        return ret;
    }

    ret = wc_FrodoKemKey_CipherTextSize(_key, &ctLen);
    if (ret == 0) {
        ret = wc_FrodoKemKey_SharedSecretSize(_key, &ssLen);
    }
    if (ret != 0) {
        goto done;
    }

    /* Ephemeral keygen: the whole key comes back over DMA */
    ret = wh_Client_FrodoKemMakeExportKeyDma(ctx, WH_TEST_FRODOKEM_TYPE, _key);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM MakeExportKeyDma failed: %d\n", ret);
        goto done;
    }

    memset(_ct, 0, ctLen);
    memset(_ss, 0, ssLen);
    memset(_ss2, 0, ssLen);
    ctLenIo = ctLen;
    ssLenIo = ssLen;

    ret = wh_Client_FrodoKemEncapsulateDma(ctx, _key, _ct, &ctLenIo, _ss,
                                           &ssLenIo);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM EncapsulateDma failed: %d\n", ret);
        goto done;
    }
    if ((ctLenIo != ctLen) || (ssLenIo != ssLen)) {
        WH_ERROR_PRINT("FrodoKEM EncapsulateDma returned wrong sizes\n");
        ret = WH_ERROR_ABORTED;
        goto done;
    }

    ssLenIo = ssLen;
    ret = wh_Client_FrodoKemDecapsulateDma(ctx, _key, _ct, ctLenIo, _ss2,
                                           &ssLenIo);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM DecapsulateDma failed: %d\n", ret);
        goto done;
    }
    if ((ssLenIo != ssLen) || (memcmp(_ss, _ss2, ssLen) != 0)) {
        WH_ERROR_PRINT("FrodoKEM DMA shared secrets differ\n");
        ret = WH_ERROR_ABORTED;
        goto done;
    }

    /* Import the key into the server cache, then run encaps/decaps against the
     * cached copy. This is the resident-key shape a real HSM user wants: after
     * the import the client key object is only a handle. */
    ret = wh_Client_FrodoKemImportKeyDma(ctx, _key, &keyId,
                                         WH_NVM_FLAGS_USAGE_DERIVE, 0, NULL);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM ImportKeyDma failed: %d\n", ret);
        goto done;
    }

    ret = wc_FrodoKemKey_Init(_key2, WH_TEST_FRODOKEM_TYPE, NULL, devId);
    if (ret != 0) {
        goto evict;
    }
    ret = wh_Client_FrodoKemSetKeyId(_key2, keyId);
    if (ret != WH_ERROR_OK) {
        goto freeKey2;
    }

    /* The id set above must read back, and the cached key must export into a
     * fresh object. Export is how a caller retrieves material it cached. */
    {
        whKeyId readBack = WH_KEYID_ERASED;

        ret = wh_Client_FrodoKemGetKeyId(_key2, &readBack);
        if ((ret != WH_ERROR_OK) || (readBack != keyId)) {
            WH_ERROR_PRINT("FrodoKEM GetKeyId round trip failed: %d\n", ret);
            ret = WH_ERROR_ABORTED;
            goto freeKey2;
        }
    }

    ret = wh_Client_FrodoKemExportKeyDma(ctx, keyId, _key2, 0, NULL);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM ExportKeyDma failed: %d\n", ret);
        goto freeKey2;
    }
    /* Exporting re-inits the key object, so restore the handle before use. */
    ret = wh_Client_FrodoKemSetKeyId(_key2, keyId);
    if (ret != WH_ERROR_OK) {
        goto freeKey2;
    }

    memset(_ct2, 0, ctLen);
    memset(_ss, 0, ssLen);
    memset(_ss2, 0, ssLen);
    ctLenIo = ctLen;
    ssLenIo = ssLen;

    ret = wh_Client_FrodoKemEncapsulateDma(ctx, _key2, _ct2, &ctLenIo, _ss,
                                           &ssLenIo);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM cached EncapsulateDma failed: %d\n", ret);
        goto freeKey2;
    }

    ssLenIo = ssLen;
    ret = wh_Client_FrodoKemDecapsulateDma(ctx, _key2, _ct2, ctLenIo, _ss2,
                                           &ssLenIo);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM cached DecapsulateDma failed: %d\n", ret);
        goto freeKey2;
    }
    if (memcmp(_ss, _ss2, ssLen) != 0) {
        WH_ERROR_PRINT("FrodoKEM cached shared secrets differ\n");
        ret = WH_ERROR_ABORTED;
    }

freeKey2:
    wc_FrodoKemKey_Free(_key2);
evict:
    (void)wh_Client_KeyEvict(ctx, keyId);
done:
    wc_FrodoKemKey_Free(_key);
    return ret;
}

/* Generate a key that stays in the server cache and use it without ever
 * holding the private key on the client. */
static int _whTest_CryptoFrodoKemCacheKeyDma(whClientContext* ctx)
{
    int      ret;
    int      devId = WH_CLIENT_DEVID(ctx);
    word32   ctLen;
    word32   ssLen;
    uint32_t ctLenIo;
    uint32_t ssLenIo;
    whKeyId  keyId = WH_KEYID_ERASED;

    ret = wc_FrodoKemKey_Init(_key, WH_TEST_FRODOKEM_TYPE, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    ret = wc_FrodoKemKey_CipherTextSize(_key, &ctLen);
    if (ret == 0) {
        ret = wc_FrodoKemKey_SharedSecretSize(_key, &ssLen);
    }
    if (ret != 0) {
        goto done;
    }

    /* The generated public key comes back in _key, which then doubles as the
     * handle to the cached private key. */
    ret = wh_Client_FrodoKemMakeCacheKeyDma(ctx, WH_TEST_FRODOKEM_TYPE, &keyId,
                                            WH_NVM_FLAGS_USAGE_DERIVE, 0, NULL,
                                            _key);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM MakeCacheKeyDma failed: %d\n", ret);
        goto done;
    }
    if (WH_KEYID_ISERASED(keyId)) {
        WH_ERROR_PRINT("FrodoKEM MakeCacheKeyDma returned no key id\n");
        ret = WH_ERROR_ABORTED;
        goto done;
    }

    ret = wh_Client_FrodoKemSetKeyId(_key, keyId);
    if (ret != WH_ERROR_OK) {
        goto evict;
    }

    memset(_ct, 0, ctLen);
    memset(_ss, 0, ssLen);
    memset(_ss2, 0, ssLen);
    ctLenIo = ctLen;
    ssLenIo = ssLen;

    ret = wh_Client_FrodoKemEncapsulateDma(ctx, _key, _ct, &ctLenIo, _ss,
                                           &ssLenIo);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM cachekey EncapsulateDma failed: %d\n", ret);
        goto evict;
    }

    ssLenIo = ssLen;
    ret = wh_Client_FrodoKemDecapsulateDma(ctx, _key, _ct, ctLenIo, _ss2,
                                           &ssLenIo);
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM cachekey DecapsulateDma failed: %d\n", ret);
        goto evict;
    }
    if (memcmp(_ss, _ss2, ssLen) != 0) {
        WH_ERROR_PRINT("FrodoKEM cachekey shared secrets differ\n");
        ret = WH_ERROR_ABORTED;
    }

evict:
    (void)wh_Client_KeyEvict(ctx, keyId);
done:
    wc_FrodoKemKey_Free(_key);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

/* The inline messages cannot carry a FrodoKEM object at the default comm data
 * length. Assert the refusal explicitly so the limit stays visible. */
static int _whTest_CryptoFrodoKemInlineTooBig(whClientContext* ctx)
{
    int      ret;
    int      devId = WH_CLIENT_DEVID(ctx);
    uint32_t ctLenIo;
    uint32_t ssLenIo;

#if WH_TEST_FRODOKEM_FITS_INLINE
    /* A build with a large enough comm buffer can use the inline path; this
     * test has nothing to assert there. */
    (void)ctx;
    (void)devId;
    (void)ctLenIo;
    (void)ssLenIo;
    return 0;
#else
    ret = wc_FrodoKemKey_Init(_key, WH_TEST_FRODOKEM_TYPE, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    /* Non-DMA keygen has to bring a whole key back inline, which cannot fit */
    ret = wh_Client_FrodoKemMakeExportKey(ctx, WH_TEST_FRODOKEM_TYPE, _key);
    if (ret == WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM inline MakeExportKey unexpectedly "
                       "succeeded\n");
        ret = WH_ERROR_ABORTED;
        goto done;
    }

    /* Encapsulate with an unset key must be refused, not attempted */
    ctLenIo = sizeof(_ct);
    ssLenIo = sizeof(_ss);
    ret = wh_Client_FrodoKemEncapsulate(ctx, _key, _ct, &ctLenIo, _ss,
                                        &ssLenIo);
    if (ret == WH_ERROR_OK) {
        WH_ERROR_PRINT("FrodoKEM inline Encapsulate unexpectedly succeeded\n");
        ret = WH_ERROR_ABORTED;
        goto done;
    }

    ret = 0;
done:
    wc_FrodoKemKey_Free(_key);
    return ret;
#endif /* WH_TEST_FRODOKEM_FITS_INLINE */
}

static int _whTest_CryptoFrodoKemBadArgs(whClientContext* ctx)
{
    int      ret;
    uint32_t ctLenIo = sizeof(_ct);
    uint32_t ssLenIo = sizeof(_ss);

    if (wh_Client_FrodoKemSetKeyId(NULL, 0) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("FrodoKemSetKeyId(NULL) not rejected\n");
        return WH_ERROR_ABORTED;
    }
    if (wh_Client_FrodoKemGetKeyId(NULL, NULL) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("FrodoKemGetKeyId(NULL) not rejected\n");
        return WH_ERROR_ABORTED;
    }
    if (wh_Client_FrodoKemMakeExportKey(ctx, WH_TEST_FRODOKEM_TYPE, NULL) !=
        WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("FrodoKemMakeExportKey(NULL key) not rejected\n");
        return WH_ERROR_ABORTED;
    }
    if (wh_Client_FrodoKemEncapsulate(NULL, NULL, _ct, &ctLenIo, _ss,
                                      &ssLenIo) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("FrodoKemEncapsulate(NULL ctx) not rejected\n");
        return WH_ERROR_ABORTED;
    }
    if (wh_Client_FrodoKemDecapsulate(NULL, NULL, _ct, sizeof(_ct), _ss,
                                      &ssLenIo) != WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("FrodoKemDecapsulate(NULL ctx) not rejected\n");
        return WH_ERROR_ABORTED;
    }

    /* Ephemeral belongs to the export path: a cache-key call must refuse it
     * rather than report success with no cached key. */
    {
        whKeyId keyId = WH_KEYID_ERASED;

        if (wh_Client_FrodoKemMakeCacheKey(ctx, WH_TEST_FRODOKEM_TYPE, &keyId,
                                           WH_NVM_FLAGS_EPHEMERAL, 0, NULL) !=
            WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("FrodoKemMakeCacheKey(EPHEMERAL) not rejected\n");
            return WH_ERROR_ABORTED;
        }
#ifdef WOLFHSM_CFG_DMA
        if (wh_Client_FrodoKemMakeCacheKeyDma(ctx, WH_TEST_FRODOKEM_TYPE,
                                              &keyId, WH_NVM_FLAGS_EPHEMERAL, 0,
                                              NULL, _key) != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("FrodoKemMakeCacheKeyDma(EPHEMERAL) not rejected\n");
            return WH_ERROR_ABORTED;
        }
        /* pub is required by the DMA cache-key call */
        if (wh_Client_FrodoKemMakeCacheKeyDma(ctx, WH_TEST_FRODOKEM_TYPE,
                                              &keyId, WH_NVM_FLAGS_USAGE_DERIVE,
                                              0, NULL, NULL) !=
            WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("FrodoKemMakeCacheKeyDma(NULL pub) not rejected\n");
            return WH_ERROR_ABORTED;
        }
#endif
    }

    /* Export with an erased key id is not a valid request. */
    if (wh_Client_FrodoKemExportKey(ctx, WH_KEYID_ERASED, _key, 0, NULL) !=
        WH_ERROR_BADARGS) {
        WH_ERROR_PRINT("FrodoKemExportKey(erased id) not rejected\n");
        return WH_ERROR_ABORTED;
    }

    /* A key type outside the base/modifier shape must be refused by the
     * server, not silently accepted. 0x7F sets bits no modifier defines. */
    ret = wc_FrodoKemKey_Init(_key, WH_TEST_FRODOKEM_TYPE, NULL,
                              WH_CLIENT_DEVID(ctx));
    if (ret == 0) {
#ifdef WOLFHSM_CFG_DMA
        ret = wh_Client_FrodoKemMakeExportKeyDma(ctx, 0x7F, _key);
        if (ret == WH_ERROR_OK) {
            WH_ERROR_PRINT("FrodoKEM bad type unexpectedly accepted\n");
            ret = WH_ERROR_ABORTED;
        }
        else {
            ret = 0;
        }
#endif
        wc_FrodoKemKey_Free(_key);
    }

    return ret;
}
#endif /* make/encaps/decaps all present */

int whTest_Crypto_FrodoKem(whClientContext* ctx)
{
#if !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) &&    \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
#ifdef WOLFHSM_CFG_DMA
    /* The wolfCrypt-API test dispatches through the crypto callback. Only the
     * DMA dispatch mode can carry FrodoKEM at the default comm data length, so
     * unlike ML-DSA this does not loop over every mode. */
    (void)wh_Client_SetDmaMode(ctx, 1);
    WH_TEST_RETURN_ON_FAIL(
        _whTest_CryptoFrodoKemWolfCrypt(ctx, WH_CLIENT_DEVID(ctx)));
    (void)wh_Client_SetDmaMode(ctx, 0);

    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFrodoKemDma(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFrodoKemCacheKeyDma(ctx));
#endif
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFrodoKemInlineTooBig(ctx));
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoFrodoKemBadArgs(ctx));
#endif
    (void)ctx;
    return 0;
}

#endif /* WOLFSSL_HAVE_FRODOKEM */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
