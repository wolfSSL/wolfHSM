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
 * test-refactor/wh_test_crypto.c
 *
 * Basic crypto test suite. Minimal SHA256 and AES-CBC
 * round-trips routed through the server via WH_DEV_ID.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifndef NO_SHA256
int whTest_CryptoSha256(whClientContext* ctx)
{
    int              devId = WH_DEV_ID;
    int              ret   = WH_ERROR_OK;
    wc_Sha256        sha256[1];
    uint8_t          out[WC_SHA256_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA256_DIGEST_SIZE] = {
        0xff, 0xe0, 0x54, 0xfe, 0x7a, 0xe0, 0xcb, 0x6d, 0xc6, 0x5c, 0x3a,
        0xf9, 0xb6, 0x1d, 0x52, 0x09, 0xf4, 0x39, 0x85, 0x1d, 0xb4, 0x3d,
        0x0b, 0xa5, 0x99, 0x73, 0x37, 0xdf, 0x15, 0x46, 0x68, 0xeb};

    (void)ctx;

    /* Initialize SHA256 structure */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha256 on devId 0x%X: %d\n", devId,
                ret);
    } else {
        /* Single-block update should trigger a server transaction */
        ret = wc_Sha256Update(sha256,
                (const byte*)inOne,
                WC_SHA256_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha256Update %d\n", ret);
        } else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha256Final(sha256, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n", ret);
            } else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA256_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA256 hash does not match expected.\n");
                    ret = -1;
                }
            }
        }
        (void)wc_Sha256Free(sha256);
    }
    if (ret == 0) {
        WH_TEST_PRINT("SHA256 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* !NO_SHA256 */


#if !defined(NO_AES) && defined(HAVE_AES_CBC)
int whTest_CryptoAes(whClientContext* ctx)
{
    int              devId = WH_DEV_ID;
    int              ret   = 0;
    Aes              aes[1];
    uint8_t          cipher[AES_BLOCK_SIZE]   = {0};
    uint8_t          plainOut[AES_BLOCK_SIZE] = {0};
    /* NIST SP 800-38B test vectors (same k128 / m used by the CMAC test
     * in test/wh_test_crypto.c). Using a fixed vector keeps this suite
     * self-contained, no RNG needed. */
    const uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t plainIn[AES_BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    (void)ctx;

    /* test aes CBC with client side key */
    ret = wc_AesInit(aes, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
    } else {
        ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
        } else {
            ret = wc_AesCbcEncrypt(aes, cipher, plainIn,
                    sizeof(plainIn));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n", ret);
            } else {
                ret = wc_AesSetKey(aes, key, sizeof(key), iv,
                        AES_DECRYPTION);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
                } else {
                    ret = wc_AesCbcDecrypt(aes, plainOut, cipher,
                            sizeof(cipher));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesCbcDecrypt %d\n",
                                ret);
                    } else {
                        if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                            0) {
                            WH_ERROR_PRINT("Failed to match AES-CBC\n");
                            ret = -1;
                        }
                    }
                }
            }
        }
        (void)wc_AesFree(aes);
    }
    if (ret == 0) {
        WH_TEST_PRINT("AES CBC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* !NO_AES && HAVE_AES_CBC */


#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(HAVE_ECC_VERIFY)
int whTest_CryptoEcc256(whClientContext* ctx)
{
    int              devId  = WH_DEV_ID;
    int              ret    = 0;
    WC_RNG           rng[1];
    ecc_key          key[1];
    /* Non-zero digest: wolfCrypt rejects all-zero hashes with ECC_BAD_ARG_E
     * unless WC_ALLOW_ECC_ZERO_HASH is defined. */
    uint8_t          hash[32];
    uint8_t          sig[ECC_MAX_SIG_SIZE] = {0};
    word32           sigLen                = sizeof(sig);
    int              verify                = 0;
    word32           i;

    (void)ctx;

    for (i = 0; i < sizeof(hash); i++) {
        hash[i] = (uint8_t)(i + 1);
    }

    /* Minimal P-256 sign/verify round-trip routed through the server via
     * WH_DEV_ID. Key size 32 selects SECP256R1 as wolfCrypt's default. */
    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
    } else {
        ret = wc_ecc_init_ex(key, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
        } else {
            ret = wc_ecc_make_key(rng, 32, key);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
            } else {
                ret = wc_ecc_sign_hash(hash, sizeof(hash),
                        sig, &sigLen, rng, key);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_ecc_sign_hash %d\n",
                            ret);
                } else {
                    ret = wc_ecc_verify_hash(sig, sigLen,
                            hash, sizeof(hash), &verify, key);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_ecc_verify_hash %d\n",
                                ret);
                    } else if (verify != 1) {
                        WH_ERROR_PRINT("ECC256 verify mismatch\n");
                        ret = -1;
                    }
                }
            }
            (void)wc_ecc_free(key);
        }
        (void)wc_FreeRng(rng);
    }
    if (ret == 0) {
        WH_TEST_PRINT("ECC256 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* HAVE_ECC && HAVE_ECC_SIGN && HAVE_ECC_VERIFY */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
