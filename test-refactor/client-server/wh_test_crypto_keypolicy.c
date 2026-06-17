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
 * test-refactor/client-server/wh_test_crypto_keypolicy.c
 *
 * Per-cached-key usage policy enforcement and revocation lifecycle:
 *   _whTest_CryptoKeyUsagePolicies      - cache keys with restricted
 *                                        WH_NVM_FLAGS_USAGE_* bits, confirm
 *                                        operations outside that policy fail
 *                                        with WH_ERROR_USAGE
 *   _whTest_CryptoKeyRevocationAesCbc   - revoke a cached AES key, confirm
 *                                        it cannot be used or erased; commit
 *                                        + revoke an NVM-backed key with the
 *                                        same expectation
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

static int _whTest_CryptoKeyUsagePolicies(whClientContext* client)
{
    int      devId          = WH_CLIENT_DEVID(client);
    int      ret            = 0;
    WC_RNG   rng[1];
    uint8_t  plaintext[16]  = {0};
    uint8_t  ciphertext[16] = {0};
    uint8_t  key[32]        = {0};
    uint32_t keyLen         = sizeof(key);
    whKeyId  keyId          = WH_KEYID_ERASED;

    (void)ciphertext;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    WH_TEST_PRINT("Testing Key Usage Policies...\n");

    ret = wc_RNG_GenerateBlock(rng, plaintext, sizeof(plaintext));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate random data: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate random key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

#ifndef NO_AES
#ifdef HAVE_AES_CBC
    WH_TEST_PRINT("  Testing AES CBC encrypt without ENCRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                   (uint8_t*)"aes-no-enc", strlen("aes-no-enc"),
                                   key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret == 0) {
                        ret = wc_AesCbcEncrypt(aes, ciphertext, plaintext,
                                               sizeof(plaintext));
                        if (ret == WH_ERROR_USAGE) {
                            WH_TEST_PRINT(
                                "    PASS: Correctly denied encryption\n");
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "    FAIL: Expected WH_ERROR_USAGE, got %d\n",
                                ret);
                            ret = WH_ERROR_ABORTED;
                        }
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }

    WH_TEST_PRINT("  Testing AES CBC decrypt without DECRYPT flag...\n");
    {
        Aes     aes[1];
        uint8_t iv[AES_BLOCK_SIZE] = {0};
        uint8_t decrypted[16]      = {0};
        uint8_t tempCipher[16]     = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ENCRYPT,
                                   (uint8_t*)"aes-enc-only",
                                   strlen("aes-enc-only"), key, keyLen, &keyId);
        if (ret == 0) {
            ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret == 0) {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret == 0) {
                        ret = wc_AesCbcEncrypt(aes, tempCipher, plaintext,
                                               sizeof(plaintext));
                    }
                }
                wc_AesFree(aes);
            }
            wh_Client_KeyEvict(client, keyId);
        }

        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                client, WH_NVM_FLAGS_USAGE_ENCRYPT, (uint8_t*)"aes-no-dec",
                strlen("aes-no-dec"), key, keyLen, &keyId);
            if (ret == 0) {
                ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
                if (ret == 0) {
                    ret = wh_Client_AesSetKeyId(aes, keyId);
                    if (ret == 0) {
                        ret = wc_AesSetIV(aes, iv);
                        if (ret == 0) {
                            ret = wc_AesCbcDecrypt(aes, decrypted, tempCipher,
                                                   sizeof(tempCipher));
                            if (ret == WH_ERROR_USAGE) {
                                WH_TEST_PRINT(
                                    "    PASS: Correctly denied decryption\n");
                                ret = 0;
                            }
                            else {
                                WH_ERROR_PRINT("    FAIL: Expected "
                                               "WH_ERROR_USAGE, got %d\n",
                                               ret);
                                ret = WH_ERROR_ABORTED;
                            }
                        }
                    }
                    wc_AesFree(aes);
                }
                wh_Client_KeyEvict(client, keyId);
            }
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }
#endif /* HAVE_AES_CBC */
#endif /* !NO_AES */

#ifdef HAVE_ECC
#ifdef HAVE_ECC_SIGN
    WH_TEST_PRINT("  Testing ECDSA sign without SIGN flag...\n");
    {
        ecc_key eccKey[1];
        uint8_t sig[ECC_MAX_SIG_SIZE]       = {0};
        word32  sigLen                      = sizeof(sig);
        uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_EccMakeCacheKey(
            client, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_NONE,
            strlen("ecc-no-sign"), (uint8_t*)"ecc-no-sign");
        if (ret == 0) {
            ret = wc_ecc_init_ex(eccKey, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wc_ecc_set_curve(eccKey, 32, ECC_SECP256R1);
                if (ret == 0) {
                    ret = wh_Client_EccSetKeyId(eccKey, keyId);
                    if (ret == 0) {
                        ret = wc_RNG_GenerateBlock(rng, hash, sizeof(hash));
                        if (ret == 0) {
                            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig,
                                                   &sigLen, rng, eccKey);
                            if (ret == WH_ERROR_USAGE) {
                                WH_TEST_PRINT(
                                    "    PASS: Correctly denied signing\n");
                                ret = 0;
                            }
                            else {
                                WH_ERROR_PRINT("    FAIL: Expected "
                                               "WH_ERROR_USAGE, got %d\n",
                                               ret);
                                ret = WH_ERROR_ABORTED;
                            }
                        }
                    }
                }
                wc_ecc_free(eccKey);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_DHE
    WH_TEST_PRINT("  Testing ECDH without DERIVE flag...\n");
    {
        ecc_key privKey[1];
        ecc_key pubKey[1];
        uint8_t sharedSecret[ECC_MAXSIZE] = {0};
        word32  secretLen                 = sizeof(sharedSecret);

        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_EccMakeCacheKey(
            client, 32, ECC_SECP256R1, &keyId, WH_NVM_FLAGS_NONE,
            strlen("ecc-no-derive"), (uint8_t*)"ecc-no-derive");
        if (ret == 0) {
            ret = wc_ecc_init_ex(privKey, NULL, WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wc_ecc_set_curve(privKey, 32, ECC_SECP256R1);
                if (ret == 0) {
                    ret = wh_Client_EccSetKeyId(privKey, keyId);
                }
                if (ret == 0) {
                    const byte qx[] = {
                        0xbb, 0x33, 0xac, 0x4c, 0x27, 0x50, 0x4a, 0xc6,
                        0x4a, 0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f, 0x36,
                        0xdb, 0x72, 0x2d, 0xce, 0x94, 0xea, 0x2b, 0xfa,
                        0xcb, 0x20, 0x09, 0x39, 0x2c, 0x16, 0xe8, 0x61};
                    const byte qy[] = {
                        0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93, 0x9a,
                        0x31, 0x5b, 0x97, 0x92, 0x21, 0x7f, 0xf0, 0xcf,
                        0x18, 0xda, 0x91, 0x11, 0x02, 0x34, 0x86, 0xe8,
                        0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89, 0xd8};
                    int curveId = ECC_SECP256R1;

                    ret = wc_ecc_init_ex(pubKey, NULL, INVALID_DEVID);
                    if (ret == 0) {
                        ret = wc_ecc_import_unsigned(pubKey, qx, qy, NULL,
                                                     curveId);
                        if (ret == 0) {
                            ret = wc_ecc_shared_secret(privKey, pubKey,
                                                       sharedSecret,
                                                       &secretLen);
                            if (ret == WH_ERROR_USAGE) {
                                WH_TEST_PRINT("    PASS: Correctly denied key "
                                              "derivation\n");
                                ret = 0;
                            }
                            else {
                                WH_ERROR_PRINT("    FAIL: Expected "
                                               "WH_ERROR_USAGE, got %d\n",
                                               ret);
                                ret = WH_ERROR_ABORTED;
                            }
                        }
                        wc_ecc_free(pubKey);
                    }
                }
                wc_ecc_free(privKey);
            }
            wh_Client_KeyEvict(client, keyId);
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }
#endif /* HAVE_ECC_DHE */
#endif /* HAVE_ECC */

#ifdef HAVE_HKDF
    WH_TEST_PRINT("  Testing HKDF without DERIVE flag...\n");
    {
        uint8_t ikm[32]  = {0};
        whKeyId outKeyId = WH_KEYID_ERASED;

        ret = wc_RNG_GenerateBlock(rng, ikm, sizeof(ikm));
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(
                client, WH_NVM_FLAGS_NONE, (uint8_t*)"hkdf-no-derive",
                strlen("hkdf-no-derive"), ikm, sizeof(ikm), &keyId);
            if (ret == 0) {
                ret = wh_Client_HkdfMakeCacheKey(
                    client, WC_SHA256, keyId, NULL, 0, NULL, 0, NULL, 0,
                    &outKeyId, WH_NVM_FLAGS_EPHEMERAL, (uint8_t*)"hkdf-out",
                    strlen("hkdf-out"), 32);
                if (ret == WH_ERROR_USAGE) {
                    WH_TEST_PRINT(
                        "    PASS: Correctly denied HKDF derivation\n");
                    ret = 0;
                }
                else {
                    WH_ERROR_PRINT(
                        "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                    ret = WH_ERROR_ABORTED;
                }
                wh_Client_KeyEvict(client, keyId);
                if (!WH_KEYID_ISERASED(outKeyId)) {
                    wh_Client_KeyEvict(client, outKeyId);
                }
            }
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }
#endif /* HAVE_HKDF */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    WH_TEST_PRINT("  Testing CMAC generate without SIGN flag...\n");
    {
        Cmac    cmac;
        whKeyId cmacKeyId = WH_KEYID_ERASED;
        uint8_t message[64];
        uint8_t tag[AES_BLOCK_SIZE];
        word32  tagLen = sizeof(tag);

        ret = wc_RNG_GenerateBlock(rng, message, sizeof(message));
        if (ret == 0) {
            ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                     (uint8_t*)"cmac-no-sign",
                                     strlen("cmac-no-sign"), key,
                                     AES_128_KEY_SIZE, &cmacKeyId);
        }
        if (ret == 0) {
            ret = wc_InitCmac_ex(&cmac, NULL, 0, WC_CMAC_AES, NULL, NULL,
                                 WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_CmacSetKeyId(&cmac, cmacKeyId);
                if (ret == 0) {
                    ret = wc_AesCmacGenerate_ex(&cmac, tag, &tagLen, message,
                                                sizeof(message), NULL, 0, NULL,
                                                WH_CLIENT_DEVID(client));
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT(
                            "    PASS: Correctly denied CMAC generate\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_CmacFree(&cmac);
            }
            wh_Client_KeyEvict(client, cmacKeyId);
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }

    WH_TEST_PRINT("  Testing CMAC verify without VERIFY flag...\n");
    {
        Cmac    cmac;
        whKeyId cmacKeyId = WH_KEYID_ERASED;
        uint8_t message[64];
        uint8_t tag[AES_BLOCK_SIZE];
        word32  tagLen = sizeof(tag);

        ret = wc_RNG_GenerateBlock(rng, message, sizeof(message));
        if (ret == 0) {
            ret = wc_RNG_GenerateBlock(rng, tag, sizeof(tag));
        }
        if (ret == 0) {
            ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                     (uint8_t*)"cmac-no-verify",
                                     strlen("cmac-no-verify"), key,
                                     AES_128_KEY_SIZE, &cmacKeyId);
        }
        if (ret == 0) {
            ret = wc_InitCmac_ex(&cmac, NULL, 0, WC_CMAC_AES, NULL, NULL,
                                 WH_CLIENT_DEVID(client));
            if (ret == 0) {
                ret = wh_Client_CmacSetKeyId(&cmac, cmacKeyId);
                if (ret == 0) {
                    ret = wc_AesCmacVerify_ex(&cmac, tag, tagLen, message,
                                              sizeof(message), NULL, 0, NULL,
                                              WH_CLIENT_DEVID(client));
                    if (ret == WH_ERROR_USAGE) {
                        WH_TEST_PRINT(
                            "    PASS: Correctly denied CMAC verify\n");
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT(
                            "    FAIL: Expected WH_ERROR_USAGE, got %d\n",
                            ret);
                        ret = WH_ERROR_ABORTED;
                    }
                }
                wc_CmacFree(&cmac);
            }
            wh_Client_KeyEvict(client, cmacKeyId);
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifdef WOLFHSM_CFG_KEYWRAP
    WH_TEST_PRINT("  Testing key wrap without WRAP flag...\n");
    {
        uint8_t       kek[32]         = {0};
        uint8_t       dataKey[32]     = {0};
        uint8_t       wrappedKey[256] = {0};
        uint16_t      wrappedKeySz    = sizeof(wrappedKey);
        whKeyId       kekId           = WH_KEYID_ERASED;
        const whKeyId wrappedId       = 1;
        whNvmMetadata meta            = {0};

        ret = wc_RNG_GenerateBlock(rng, kek, sizeof(kek));
        if (ret == 0) {
            ret = wc_RNG_GenerateBlock(rng, dataKey, sizeof(dataKey));
        }
        if (ret == 0) {
            ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_NONE,
                                     (uint8_t*)"kek-no-wrap",
                                     strlen("kek-no-wrap"), kek, sizeof(kek),
                                     &kekId);
            if (ret == 0) {
                meta.id = WH_CLIENT_KEYID_MAKE_WRAPPED_META(
                    client->comm->client_id, wrappedId);
                meta.flags = WH_NVM_FLAGS_NONE;
                meta.len   = sizeof(dataKey);

                ret = wh_Client_KeyWrap(client, WC_CIPHER_AES_GCM, kekId,
                                        dataKey, sizeof(dataKey), &meta,
                                        wrappedKey, &wrappedKeySz);
                if (ret == WH_ERROR_USAGE) {
                    WH_TEST_PRINT("    PASS: Correctly denied key wrapping\n");
                    ret = 0;
                }
                else {
                    WH_ERROR_PRINT(
                        "    FAIL: Expected WH_ERROR_USAGE, got %d\n", ret);
                    ret = WH_ERROR_ABORTED;
                }
                wh_Client_KeyEvict(client, kekId);
            }
        }
    }
    if (ret != 0) {
        (void)wc_FreeRng(rng);
        return ret;
    }
#endif /* WOLFHSM_CFG_KEYWRAP */

    (void)wc_FreeRng(rng);
    WH_TEST_PRINT("Key Usage Policy Tests PASSED\n");
    return 0;
}

#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
static int whTest_RevocationTryAESEncrypt(whKeyId keyId, WC_RNG* rng,
                                          int* encryptRes)
{
    int     ret;
    Aes     aes[1];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t plaintext[16];
    uint8_t ciphertext[16] = {0};

    ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
    if (ret == 0) {
        ret = wc_RNG_GenerateBlock(rng, plaintext, sizeof(plaintext));
    }
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate AES revocation test inputs: %d\n",
                       ret);
        return ret;
    }
    ret = wc_AesInit(aes, NULL, WH_CLIENT_DEVID(client));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to init AES for revoked key test: %d\n", ret);
        return ret;
    }
    ret = wh_Client_AesSetKeyId(aes, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set AES keyId for revoked key test: %d\n",
                       ret);
        wc_AesFree(aes);
        return ret;
    }
    ret = wc_AesSetIV(aes, iv);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set AES IV for revoked key test: %d\n", ret);
        wc_AesFree(aes);
        return ret;
    }
    ret = wc_AesCbcEncrypt(aes, ciphertext, plaintext,
                           (word32)sizeof(plaintext));
    wc_AesFree(aes);
    *encryptRes = ret;
    return WH_ERROR_OK;
}

static int _whTest_CryptoKeyRevocationAesCbc(whClientContext* client)
{
    int           devId            = WH_CLIENT_DEVID(client);
    int           ret              = 0;
    WC_RNG        rng[1];
    uint8_t       key[32]          = {0};
    const uint8_t label[]          = "revocation-aes-cbc";
    whKeyId       keyId            = WH_KEYID_ERASED;
    const int     expectedEraseErr = WH_ERROR_ACCESS;
    int           encryptRes       = 0;

    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
        return ret;
    }

    WH_TEST_PRINT("Testing Key Revocation...\n");
    WH_TEST_PRINT("  AES-CBC key revoke flow...\n");

    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate AES revocation inputs: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, (uint8_t*)label,
                             sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache AES key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = whTest_RevocationTryAESEncrypt(keyId, rng, &encryptRes);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to encrypt with unrevoked AES key: %d\n", ret);
        (void)wh_Client_KeyEvict(client, keyId);
        (void)wc_FreeRng(rng);
        return ret;
    }
    if (encryptRes != 0) {
        WH_ERROR_PRINT("Encrypt with unrevoked AES key failed: %d\n",
                       encryptRes);
        (void)wc_FreeRng(rng);
        return encryptRes;
    }

    ret = wh_Client_KeyRevoke(client, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to revoke AES key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = whTest_RevocationTryAESEncrypt(keyId, rng, &encryptRes);
    if (ret != 0 || encryptRes != WH_ERROR_USAGE) {
        WH_ERROR_PRINT(
            "Encrypt with revoked AES key should fail (%d), got %d\n",
            WH_ERROR_USAGE, encryptRes);
        (void)wc_FreeRng(rng);
        return WH_ERROR_ABORTED;
    }

    ret = wh_Client_KeyCommit(client, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to commit revoked AES key: %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }

    ret = whTest_RevocationTryAESEncrypt(keyId, rng, &encryptRes);
    if (ret != 0 || encryptRes != WH_ERROR_USAGE) {
        WH_ERROR_PRINT(
            "Encrypt with revoked AES key should fail (%d), got %d\n",
            WH_ERROR_USAGE, encryptRes);
        (void)wc_FreeRng(rng);
        return WH_ERROR_ABORTED;
    }

    ret = wh_Client_KeyErase(client, keyId);
    if (ret != expectedEraseErr) {
        WH_ERROR_PRINT("Revoked key erase should fail (%d), got %d\n",
                       expectedEraseErr, ret);
        (void)wc_FreeRng(rng);
        return WH_ERROR_ABORTED;
    }

    /* Slightly different flow: cache + commit + evict + revoke */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_KeyCache(client, WH_NVM_FLAGS_USAGE_ANY, (uint8_t*)label,
                               sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache AES key (2nd time): %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }
    ret = wh_Client_KeyCommit(client, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to commit AES key (2nd time): %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }
    ret = whTest_RevocationTryAESEncrypt(keyId, rng, &encryptRes);
    if (ret != 0 || encryptRes != 0) {
        WH_ERROR_PRINT(
            "Failed to encrypt with unrevoked AES key (2nd time): %d\n", ret);
        (void)wh_Client_KeyEvict(client, keyId);
        (void)wc_FreeRng(rng);
        return ret != 0 ? ret : encryptRes;
    }
    ret = wh_Client_KeyEvict(client, keyId);
    if (ret != 0 && ret != WH_ERROR_NOTFOUND) {
        WH_ERROR_PRINT("Failed to evict AES key (2nd time): %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }
    ret = wh_Client_KeyRevoke(client, keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to revoke AES key (2nd time): %d\n", ret);
        (void)wc_FreeRng(rng);
        return ret;
    }
    ret = whTest_RevocationTryAESEncrypt(keyId, rng, &encryptRes);
    if (ret != 0 || encryptRes != WH_ERROR_USAGE) {
        WH_ERROR_PRINT(
            "Encrypt with revoked AES key should fail (%d), got %d\n",
            WH_ERROR_USAGE, encryptRes);
        (void)wh_Client_KeyEvict(client, keyId);
        (void)wc_FreeRng(rng);
        return WH_ERROR_ABORTED;
    }

    WH_TEST_PRINT("  AES-CBC revocation enforcement: PASS\n");
    (void)wc_FreeRng(rng);
    return 0;
}
#endif /* !NO_AES && HAVE_AES_CBC && \
          WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS */

int whTest_Crypto_KeyPolicy(whClientContext* ctx)
{
    /* A preceding suite may leave the DMA-preferred dispatch mode set; reset
     * to the std path so this suite runs the same way in every config. */
    (void)wh_Client_SetDmaMode(ctx, 0);
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoKeyUsagePolicies(ctx));
#if !defined(NO_AES) && defined(HAVE_AES_CBC) && \
    defined(WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS)
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoKeyRevocationAesCbc(ctx));
#endif
    return 0;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
