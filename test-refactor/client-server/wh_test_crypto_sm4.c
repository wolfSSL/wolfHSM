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
 * test-refactor/client-server/wh_test_crypto_sm4.c
 *
 * SM4 tests routed through the server, in every mode.
 *
 * Each mode is driven through the plain wolfCrypt API with the client devId,
 * which is the path an application takes, and the result is checked against a
 * known answer or against the same operation run locally in software. The
 * software comparison is what catches a callback that returns plausible but
 * wrong output.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/sm4.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLFSSL_SM4

/* GB/T 32907-2016 SM4 example key */
static const byte whTestSm4Key[SM4_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};

static const byte whTestSm4Iv[SM4_IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

/* Two blocks so chaining modes actually chain */
static const byte whTestSm4Plain[32] = {
    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
    0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD,
    0xEE, 0xEE, 0xEE, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB
};

#ifdef WOLFSSL_SM4_ECB
/* GB/T 32907-2016 ECB answer for the key and plaintext above */
static const byte whTestSm4EcbKat[32] = {
    0x5E, 0xC8, 0x14, 0x3D, 0xE5, 0x09, 0xCF, 0xF7,
    0xB5, 0x17, 0x9F, 0x8F, 0x47, 0x4B, 0x86, 0x19,
    0x2F, 0x1D, 0x30, 0x5A, 0x7F, 0xB1, 0x7D, 0xF9,
    0x85, 0xF8, 0x1C, 0x84, 0x82, 0x19, 0x23, 0x04
};

static int _whTest_Sm4Ecb(whClientContext* ctx)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret;
    wc_Sm4 sm4[1];
    byte   cipher[sizeof(whTestSm4Plain)];
    byte   plain[sizeof(whTestSm4Plain)];

    ret = wc_Sm4Init(sm4, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_Sm4Init %d\n", ret);
        return ret;
    }

    ret = wc_Sm4SetKey(sm4, whTestSm4Key, sizeof(whTestSm4Key));
    if (ret == 0) {
        ret = wc_Sm4EcbEncrypt(sm4, cipher, whTestSm4Plain,
                               sizeof(whTestSm4Plain));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-ECB encrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(cipher, whTestSm4EcbKat, sizeof(whTestSm4EcbKat)) != 0) {
        WH_ERROR_PRINT("SM4-ECB ciphertext does not match the KAT\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    ret = wc_Sm4EcbDecrypt(sm4, plain, cipher, sizeof(cipher));
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-ECB decrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(plain, whTestSm4Plain, sizeof(whTestSm4Plain)) != 0) {
        WH_ERROR_PRINT("SM4-ECB round trip mismatch\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SM4 ECB DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_Sm4Free(sm4);
    return ret;
}
#endif /* WOLFSSL_SM4_ECB */

#ifdef WOLFSSL_SM4_CBC
/* Offloaded CBC must agree byte for byte with the local software result, and
 * must leave the IV chained so a split call continues correctly. */
static int _whTest_Sm4Cbc(whClientContext* ctx)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret;
    wc_Sm4 hsm[1];
    wc_Sm4 sw[1];
    byte   cipher[sizeof(whTestSm4Plain)];
    byte   expect[sizeof(whTestSm4Plain)];
    byte   plain[sizeof(whTestSm4Plain)];

    ret = wc_Sm4Init(sw, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Sm4SetKey(sw, whTestSm4Key, sizeof(whTestSm4Key));
    if (ret == 0) {
        ret = wc_Sm4SetIV(sw, whTestSm4Iv);
    }
    if (ret == 0) {
        ret = wc_Sm4CbcEncrypt(sw, expect, whTestSm4Plain,
                               sizeof(whTestSm4Plain));
    }
    wc_Sm4Free(sw);
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CBC software reference failed %d\n", ret);
        return ret;
    }

    ret = wc_Sm4Init(hsm, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Sm4SetKey(hsm, whTestSm4Key, sizeof(whTestSm4Key));
    if (ret == 0) {
        ret = wc_Sm4SetIV(hsm, whTestSm4Iv);
    }
    /* Two calls of one block each, so the IV returned by the first has to be
     * carried into the second. */
    if (ret == 0) {
        ret = wc_Sm4CbcEncrypt(hsm, cipher, whTestSm4Plain, SM4_BLOCK_SIZE);
    }
    if (ret == 0) {
        ret = wc_Sm4CbcEncrypt(hsm, cipher + SM4_BLOCK_SIZE,
                               whTestSm4Plain + SM4_BLOCK_SIZE,
                               SM4_BLOCK_SIZE);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CBC encrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(cipher, expect, sizeof(expect)) != 0) {
        WH_ERROR_PRINT("SM4-CBC offload disagrees with software\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    ret = wc_Sm4SetIV(hsm, whTestSm4Iv);
    if (ret == 0) {
        ret = wc_Sm4CbcDecrypt(hsm, plain, cipher, sizeof(cipher));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CBC decrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(plain, whTestSm4Plain, sizeof(whTestSm4Plain)) != 0) {
        WH_ERROR_PRINT("SM4-CBC round trip mismatch\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SM4 CBC DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_Sm4Free(hsm);
    return ret;
}
#endif /* WOLFSSL_SM4_CBC */

#ifdef WOLFSSL_SM4_CTR
/* CTR is checked with a deliberately unaligned split, which only works if the
 * leftover keystream travels with the request. */
static int _whTest_Sm4Ctr(whClientContext* ctx)
{
    int          devId = WH_CLIENT_DEVID(ctx);
    int          ret;
    wc_Sm4       hsm[1];
    wc_Sm4       sw[1];
    const word32 split = 5; /* not a block boundary */
    byte         cipher[sizeof(whTestSm4Plain)];
    byte         expect[sizeof(whTestSm4Plain)];
    byte         plain[sizeof(whTestSm4Plain)];

    ret = wc_Sm4Init(sw, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Sm4SetKey(sw, whTestSm4Key, sizeof(whTestSm4Key));
    if (ret == 0) {
        ret = wc_Sm4SetIV(sw, whTestSm4Iv);
    }
    if (ret == 0) {
        ret = wc_Sm4CtrEncrypt(sw, expect, whTestSm4Plain,
                               sizeof(whTestSm4Plain));
    }
    wc_Sm4Free(sw);
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CTR software reference failed %d\n", ret);
        return ret;
    }

    ret = wc_Sm4Init(hsm, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Sm4SetKey(hsm, whTestSm4Key, sizeof(whTestSm4Key));
    if (ret == 0) {
        ret = wc_Sm4SetIV(hsm, whTestSm4Iv);
    }
    if (ret == 0) {
        ret = wc_Sm4CtrEncrypt(hsm, cipher, whTestSm4Plain, split);
    }
    if (ret == 0) {
        ret = wc_Sm4CtrEncrypt(hsm, cipher + split, whTestSm4Plain + split,
                               (word32)sizeof(whTestSm4Plain) - split);
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CTR encrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(cipher, expect, sizeof(expect)) != 0) {
        WH_ERROR_PRINT("SM4-CTR split stream disagrees with software\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    /* CTR is its own inverse */
    ret = wc_Sm4SetIV(hsm, whTestSm4Iv);
    if (ret == 0) {
        ret = wc_Sm4CtrEncrypt(hsm, plain, cipher, sizeof(cipher));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CTR decrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(plain, whTestSm4Plain, sizeof(whTestSm4Plain)) != 0) {
        WH_ERROR_PRINT("SM4-CTR round trip mismatch\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SM4 CTR DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    wc_Sm4Free(hsm);
    return ret;
}
#endif /* WOLFSSL_SM4_CTR */

#if defined(WOLFSSL_SM4_GCM) || defined(WOLFSSL_SM4_CCM)
static const byte whTestSm4Aad[] = {'w', 'o', 'l', 'f', 'H', 'S', 'M'};

/* Shared body for the two authenticated modes: round trip, then confirm a
 * flipped tag bit is rejected rather than quietly returning plaintext. */
static int _whTest_Sm4Auth(whClientContext* ctx, int isCcm)
{
    int    devId = WH_CLIENT_DEVID(ctx);
    int    ret;
    wc_Sm4 sm4[1];
    byte   cipher[sizeof(whTestSm4Plain)];
    byte   plain[sizeof(whTestSm4Plain)];
    byte   tag[SM4_BLOCK_SIZE];
    byte   nonce[12];
    const char* name = isCcm ? "CCM" : "GCM";

    memset(nonce, 0x5A, sizeof(nonce));
    memset(plain, 0, sizeof(plain));

    ret = wc_Sm4Init(sm4, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    if (isCcm == 0) {
#ifdef WOLFSSL_SM4_GCM
        ret = wc_Sm4GcmSetKey(sm4, whTestSm4Key, sizeof(whTestSm4Key));
        if (ret == 0) {
            ret = wc_Sm4GcmEncrypt(sm4, cipher, whTestSm4Plain,
                                   sizeof(whTestSm4Plain), nonce,
                                   sizeof(nonce), tag, sizeof(tag),
                                   whTestSm4Aad, sizeof(whTestSm4Aad));
        }
#endif
    }
    else {
#ifdef WOLFSSL_SM4_CCM
        ret = wc_Sm4SetKey(sm4, whTestSm4Key, sizeof(whTestSm4Key));
        if (ret == 0) {
            ret = wc_Sm4CcmEncrypt(sm4, cipher, whTestSm4Plain,
                                   sizeof(whTestSm4Plain), nonce,
                                   sizeof(nonce), tag, sizeof(tag),
                                   whTestSm4Aad, sizeof(whTestSm4Aad));
        }
#endif
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-%s encrypt failed %d\n", name, ret);
        goto done;
    }

    if (isCcm == 0) {
#ifdef WOLFSSL_SM4_GCM
        ret = wc_Sm4GcmDecrypt(sm4, plain, cipher, sizeof(cipher), nonce,
                               sizeof(nonce), tag, sizeof(tag), whTestSm4Aad,
                               sizeof(whTestSm4Aad));
#endif
    }
    else {
#ifdef WOLFSSL_SM4_CCM
        ret = wc_Sm4CcmDecrypt(sm4, plain, cipher, sizeof(cipher), nonce,
                               sizeof(nonce), tag, sizeof(tag), whTestSm4Aad,
                               sizeof(whTestSm4Aad));
#endif
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-%s decrypt failed %d\n", name, ret);
        goto done;
    }
    if (memcmp(plain, whTestSm4Plain, sizeof(whTestSm4Plain)) != 0) {
        WH_ERROR_PRINT("SM4-%s round trip mismatch\n", name);
        ret = WH_TEST_FAIL;
        goto done;
    }

    /* A tampered tag must fail authentication */
    tag[0] ^= 0xFF;
    if (isCcm == 0) {
#ifdef WOLFSSL_SM4_GCM
        ret = wc_Sm4GcmDecrypt(sm4, plain, cipher, sizeof(cipher), nonce,
                               sizeof(nonce), tag, sizeof(tag), whTestSm4Aad,
                               sizeof(whTestSm4Aad));
#endif
    }
    else {
#ifdef WOLFSSL_SM4_CCM
        ret = wc_Sm4CcmDecrypt(sm4, plain, cipher, sizeof(cipher), nonce,
                               sizeof(nonce), tag, sizeof(tag), whTestSm4Aad,
                               sizeof(whTestSm4Aad));
#endif
    }
    if (ret == 0) {
        WH_ERROR_PRINT("SM4-%s accepted a tampered tag\n", name);
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SM4 %s DEVID=0x%X SUCCESS\n", name, devId);
    ret = 0;

done:
    wc_Sm4Free(sm4);
    return ret;
}
#endif /* WOLFSSL_SM4_GCM || WOLFSSL_SM4_CCM */

#ifdef WOLFSSL_SM4_CBC
/* The point of the HSM: the key stays on the server and the client holds
 * nothing but a key id. */
static int _whTest_Sm4CachedKey(whClientContext* ctx)
{
    int     devId = WH_CLIENT_DEVID(ctx);
    int     ret;
    wc_Sm4  sm4[1];
    whKeyId keyId   = WH_KEYID_ERASED;
    uint8_t label[] = "sm4-cached";
    byte    cipher[sizeof(whTestSm4Plain)];
    byte    expect[sizeof(whTestSm4Plain)];
    byte    plain[sizeof(whTestSm4Plain)];
    wc_Sm4  sw[1];

    /* Software reference with the same key */
    ret = wc_Sm4Init(sw, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Sm4SetKey(sw, whTestSm4Key, sizeof(whTestSm4Key));
    if (ret == 0) {
        ret = wc_Sm4SetIV(sw, whTestSm4Iv);
    }
    if (ret == 0) {
        ret = wc_Sm4CbcEncrypt(sw, expect, whTestSm4Plain,
                               sizeof(whTestSm4Plain));
    }
    wc_Sm4Free(sw);
    if (ret != 0) {
        return ret;
    }

    ret = wc_Sm4Init(sm4, NULL, devId);
    if (ret != 0) {
        return ret;
    }

    ret = wh_Client_KeyCache(
        ctx, WH_NVM_FLAGS_USAGE_ENCRYPT | WH_NVM_FLAGS_USAGE_DECRYPT, label,
        sizeof(label), whTestSm4Key, sizeof(whTestSm4Key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache the SM4 key %d\n", ret);
        goto done;
    }

    ret = wh_Client_Sm4SetKeyId(sm4, keyId);
    if (ret == 0) {
        /* Deliberately no wc_Sm4SetKey: the client has no key material */
        ret = wc_Sm4SetIV(sm4, whTestSm4Iv);
    }
    if (ret == 0) {
        ret = wc_Sm4CbcEncrypt(sm4, cipher, whTestSm4Plain,
                               sizeof(whTestSm4Plain));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("SM4-CBC with a cached key failed %d\n", ret);
        goto done;
    }
    if (memcmp(cipher, expect, sizeof(expect)) != 0) {
        WH_ERROR_PRINT("Cached-key SM4-CBC disagrees with software\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    ret = wc_Sm4SetIV(sm4, whTestSm4Iv);
    if (ret == 0) {
        ret = wc_Sm4CbcDecrypt(sm4, plain, cipher, sizeof(cipher));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Cached-key SM4-CBC decrypt failed %d\n", ret);
        goto done;
    }
    if (memcmp(plain, whTestSm4Plain, sizeof(whTestSm4Plain)) != 0) {
        WH_ERROR_PRINT("Cached-key SM4-CBC round trip mismatch\n");
        ret = WH_TEST_FAIL;
        goto done;
    }

    WH_TEST_PRINT("SM4 CACHED KEY DEVID=0x%X SUCCESS\n", devId);
    ret = 0;

done:
    if (!WH_KEYID_ISERASED(keyId)) {
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    wc_Sm4Free(sm4);
    return ret;
}
#endif /* WOLFSSL_SM4_CBC */


int whTest_Crypto_Sm4(whClientContext* ctx)
{
    int i;

    /* Every mode runs in each dispatch mode the build offers, so the DMA and
     * comm-buffer paths are held to the same known answers. The wolfCrypt API
     * is identical either way; only the transport underneath changes. */
    for (i = 0; i < WH_TEST_DMA_MODE_CNT; i++) {
        (void)wh_Client_SetDmaMode(ctx, i);

#ifdef WOLFSSL_SM4_ECB
        WH_TEST_RETURN_ON_FAIL(_whTest_Sm4Ecb(ctx));
#endif
#ifdef WOLFSSL_SM4_CBC
        WH_TEST_RETURN_ON_FAIL(_whTest_Sm4Cbc(ctx));
#endif
#ifdef WOLFSSL_SM4_CTR
        WH_TEST_RETURN_ON_FAIL(_whTest_Sm4Ctr(ctx));
#endif
#ifdef WOLFSSL_SM4_GCM
        WH_TEST_RETURN_ON_FAIL(_whTest_Sm4Auth(ctx, 0));
#endif
#ifdef WOLFSSL_SM4_CCM
        WH_TEST_RETURN_ON_FAIL(_whTest_Sm4Auth(ctx, 1));
#endif
#ifdef WOLFSSL_SM4_CBC
        WH_TEST_RETURN_ON_FAIL(_whTest_Sm4CachedKey(ctx));
#endif
    }
    (void)wh_Client_SetDmaMode(ctx, 0);

    (void)ctx;
    return 0;
}

#endif /* WOLFSSL_SM4 */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
