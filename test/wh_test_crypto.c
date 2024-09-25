/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * test/wh_test.c
 *
 */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */
#include <unistd.h> /* For sleep */

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

enum {
        REQ_SIZE = 32,
        RESP_SIZE = 64,
        BUFFER_SIZE = 4096,
    };


#define PLAINTEXT "mytextisbigplain"

#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
/* Flag causing the server loop to sleep(1) */
int serverDelay = 0;
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX)
/* pointer to expose server context cancel sequence to the client cancel
 * callback */
static uint16_t* cancelSeqP;

/* Test client cancel callback that directly sets the sequence to cancel in the
 * server context */
static int _cancelCb(uint16_t seq)
{
    *cancelSeqP = seq;
    return 0;
}
#endif

#ifdef WOLFHSM_CFG_TEST_VERBOSE
static int whTest_ShowNvmAvailable(whClientContext* ctx)
{
    int ret = 0;
    int32_t  server_rc       = 0;
    whNvmId  avail_objects   = 0;
    whNvmId  reclaim_objects = 0;
    uint32_t avail_size      = 0;
    uint32_t reclaim_size    = 0;

    ret = wh_Client_NvmGetAvailable(ctx, &server_rc, &avail_size,
                                        &avail_objects, &reclaim_size,
                                        &reclaim_objects);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to get available NVM status\n");
    } else {
        printf("CRYPTO TEST NVM STATUS: NvmGetAvailable:%d, server_rc:%d "
                "avail_size:%d avail_objects:%d, reclaim_size:%d "
                "reclaim_objects:%d\n",
               ret, (int)server_rc, (int)avail_size, (int)avail_objects,
               (int)reclaim_size, (int)reclaim_objects);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_TEST_VERBOSE */

static int whTest_CryptoRng(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx; /* Unused */

#define WH_TEST_RNG_LIL 7
#define WH_TEST_RNG_MED 1024
#define WH_TEST_RNG_BIG (WOLFHSM_CFG_COMM_DATA_LEN * 2)
    int ret;
    uint8_t lil[WH_TEST_RNG_LIL];
    uint8_t med[WH_TEST_RNG_MED];
    uint8_t big[WH_TEST_RNG_BIG];

    /* test rng.  Note this rng is used for many tests so is left inited */
    ret = wc_InitRng_ex(rng, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRng_ex %d\n", ret);
    } else {
        ret = wc_RNG_GenerateBlock(rng, lil, sizeof(lil));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        } else {
            ret = wc_RNG_GenerateBlock(rng, med, sizeof(med));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
            } else {
                ret = wc_RNG_GenerateBlock(rng, big, sizeof(big));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
                }
            }
        }
    }
    if (ret == 0) {
        printf("RNG SUCCESS\n");
    }
    return ret;
}

#ifndef NO_RSA
static int whTest_CryptoRsa(whClientContext* ctx, int devId, WC_RNG* rng)
{
#define RSA_KEY_BITS 2048
#define RSA_KEY_BYTES (RSA_KEY_BITS/8)
#define RSA_EXPONENT WC_RSA_EXPONENT

    int ret = WH_ERROR_OK;
    RsaKey rsa[1];
    char plainText[sizeof(PLAINTEXT)] = PLAINTEXT;
    char cipherText[RSA_KEY_BYTES];
    char finalText[RSA_KEY_BYTES];
    whKeyId keyId = WH_KEYID_ERASED;

    /* Using ephemeral key */
    memset(cipherText, 0, sizeof(cipherText));
    memset(finalText, 0, sizeof(finalText));
    ret = wc_InitRsaKey_ex(rsa, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
    } else {
        ret = wc_MakeRsaKey(rsa, RSA_KEY_BITS, RSA_EXPONENT, rng);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_MakeRsaKey %d\n", ret);
        } else {
            ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                    (byte*)cipherText, sizeof(cipherText), rsa, rng);
            if (ret < 0) {
                WH_ERROR_PRINT("Failed to wc_RsaPublicEncrypt %d\n", ret);
            } else {
                ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret,
                        (byte*)finalText, sizeof(finalText), rsa);
                if (ret < 0) {
                    WH_ERROR_PRINT("Failed to wc_RsaPrivateDecrypt %d\n", ret);
                } else {
                    ret = 0;
                    if (memcmp(plainText, finalText, sizeof(plainText)) != 0) {
                        WH_ERROR_PRINT("Failed to match\n");
                        ret = -1;
                    }
                }
            }
        }
        (void)wc_FreeRsaKey(rsa);
    }

    if (ret == 0) {
        /* Using client export key */
        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
        if (ret!= 0) {
            WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
        } else {
            ret = wh_Client_RsaMakeExportKey(ctx, RSA_KEY_BITS, RSA_EXPONENT,
                    rsa);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
            } else {
                ret = wc_RsaPublicEncrypt((byte*)plainText, sizeof(plainText),
                        (byte*)cipherText, sizeof(cipherText), rsa, rng);
                if (ret < 0) {
                    WH_ERROR_PRINT("Failed to encrypt %d\n", ret);
                } else {
                    ret = wc_RsaPrivateDecrypt((byte*)cipherText, ret,
                            (byte*)finalText, sizeof(finalText), rsa);
                    if (ret < 0) {
                        WH_ERROR_PRINT("Failed to decrypt %d\n", ret);
                    } else {
                        ret = 0;
                        if (memcmp(plainText, finalText,
                                sizeof(plainText)) != 0) {
                            WH_ERROR_PRINT("Failed to match\n");
                            ret = -1;
                        }
                    }
                }
            }
            (void)wc_FreeRsaKey(rsa);
        }
    }

    if (ret == 0) {
        /* Using keyCache key */
        memset(cipherText, 0, sizeof(cipherText));
        memset(finalText, 0, sizeof(finalText));
        ret = wh_Client_RsaMakeCacheKey(ctx, RSA_KEY_BITS, RSA_EXPONENT,
                &keyId, WH_NVM_FLAGS_NONE, 0, NULL);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
        } else {
            ret = wc_InitRsaKey_ex(rsa, NULL, WH_DEV_ID);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_InitRsaKey_ex %d\n", ret);
            } else {
                ret = wh_Client_RsaSetKeyId(rsa, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdRsa %d\n", ret);
                } else {
                    ret = wh_Client_RsaGetKeyId(rsa, &keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_GetKeyIdRsa %d\n", ret);
                    } else {
                        ret = wc_RsaPublicEncrypt(
                                (byte*)plainText, sizeof(plainText),
                                (byte*)cipherText, sizeof(cipherText), rsa,
                                rng);
                        if (ret < 0) {
                            WH_ERROR_PRINT("Failed to encrypt %d\n", ret);
                        } else {
                            ret = wc_RsaPrivateDecrypt(
                                    (byte*)cipherText, ret,
                                    (byte*)finalText, sizeof(finalText), rsa);
                            if (ret < 0) {
                                WH_ERROR_PRINT("Failed to decrypt %d\n", ret);
                            } else {
                                ret = 0;
                                if (memcmp(plainText, finalText,
                                        sizeof(plainText)) != 0) {
                                    WH_ERROR_PRINT("Failed to match\n");
                                    ret = -1;
                                }
                            }
                        }
                    }
                }
                (void)wc_FreeRsaKey(rsa);
            }
        }
        (void)wh_Client_KeyEvict(ctx, keyId);
    }
    if (ret == 0) {
        printf("RSA SUCCESS\n");
    }
    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC
static int whTest_CryptoEcc(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int ret = WH_ERROR_OK;
    ecc_key eccPrivate[1];
    ecc_key eccPublic[1];
#define TEST_ECC_KEYSIZE 32
    uint8_t shared_ab[TEST_ECC_KEYSIZE] = {0};
    uint8_t shared_ba[TEST_ECC_KEYSIZE] = {0};
    uint8_t hash[TEST_ECC_KEYSIZE] = {0};
    uint8_t sig[ECC_MAX_SIG_SIZE] = {0};

#if 0
    whNvmFlags flags = WH_NVM_FLAGS_NONE;
    whKeyId key_id_a = WH_KEYID_ERASED;
    uint8_t* label_a = (uint8_t*)("Ecc Label A");
    whKeyId key_id_b = 24;
    uint8_t* label_b = (uint8_t*)("Ecc Label B");
#endif

    ret = wc_ecc_init_ex(eccPrivate, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
    } else {
        ret = wc_ecc_init_ex(eccPublic, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_ecc_init_ex %d\n", ret);
        } else {
            ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, eccPrivate);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
            } else {
                ret = wc_ecc_make_key(rng, TEST_ECC_KEYSIZE, eccPublic);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_ecc_make_key %d\n", ret);
                } else {
                    word32 secLen = TEST_ECC_KEYSIZE;
                    ret = wc_ecc_shared_secret(eccPrivate, eccPublic,
                            (byte*)shared_ab, &secLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute secret %d\n", ret);
                    } else {
                        ret = wc_ecc_shared_secret(eccPublic, eccPrivate,
                                (byte*)shared_ba, &secLen);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to compute secret %d\n",
                                    ret);
                        } else {
                            if (memcmp(shared_ab, shared_ba, secLen) == 0) {
                                printf("ECDH SUCCESS\n");
                            } else {
                                WH_ERROR_PRINT("ECDH FAILED TO MATCH\n");
                                ret = -1;
                            }
                        }
                    }
                    /*Use the shared secret as a random hash */
                    memcpy(hash, shared_ba, sizeof(hash));
                    word32 sigLen = sizeof(sig);
                    ret = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                            (void*)sig, &sigLen, rng, eccPrivate);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_ecc_sign_hash %d\n", ret);
                    } else {
                        int res = 0;
                        ret = wc_ecc_verify_hash((void*)sig, sigLen,
                                (void*)hash, sizeof(hash), &res,
                                eccPrivate);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_ecc_verify_hash %d\n",
                                    ret);
                        } else {
                            if (res == 1) {
                                printf("ECC SIGN/VERIFY SUCCESS\n");
                            } else {
                                WH_ERROR_PRINT("ECC SIGN/VERIFY FAIL\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            wc_ecc_free(eccPublic);
        }
        wc_ecc_free(eccPrivate);
    }
    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
static int whTest_CryptoCurve25519(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int ret = 0;
    curve25519_key key_a[1] = {0};
    curve25519_key key_b[1] = {0};
    uint8_t shared_ab[CURVE25519_KEYSIZE] = {0};
    uint8_t shared_ba[CURVE25519_KEYSIZE] = {0};
    int key_size = CURVE25519_KEYSIZE;
    whNvmFlags flags = WH_NVM_FLAGS_NONE;
    whKeyId key_id_a = WH_KEYID_ERASED;
    uint8_t label_a[WH_NVM_LABEL_LEN] = "Curve25519 Label A";
    whKeyId key_id_b = 42;
    uint8_t label_b[WH_NVM_LABEL_LEN] = "Curve25519 Label B";
    word32 len = 0;

    if (ret == 0) {
        /* Use wolfcrypt ephemeral local keys */
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            } else {
                ret = wc_curve25519_make_key(rng, key_size, key_a);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_curve25519_make_key %d\n",
                            ret);
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
                    ret = wc_curve25519_shared_secret(
                            key_a, key_b, shared_ab, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(
                            key_b, key_a, shared_ba, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    if (XMEMCMP(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }

    if (ret == 0) {
        /* Test using wh_Client ephemeral local keys */
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            } else {
                ret = wh_Client_Curve25519MakeExportKey(ctx, key_size, key_a);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeExportKey(ctx, key_size,
                            key_b);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to make exported key %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ab);
                    ret = wc_curve25519_shared_secret(
                            key_a, key_b, shared_ab, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(
                            key_b, key_a, shared_ba, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    if (XMEMCMP(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }
    if (ret == 0) {
        /* Test using wolfHSM server keys */
        ret = wc_curve25519_init_ex(key_a, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
            ret = wc_curve25519_init_ex(key_b, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
            } else {
                ret = wh_Client_Curve25519MakeCacheKey(ctx, key_size,
                        &key_id_a, flags, sizeof(label_a), label_a);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeCacheKey(ctx, key_size,
                            &key_id_b, flags, sizeof(label_b), label_b);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ab);
                    wh_Client_Curve25519SetKeyId(key_a, key_id_a);
                    wh_Client_Curve25519SetKeyId(key_b, key_id_b);
                    ret = wc_curve25519_shared_secret(
                            key_a, key_b, shared_ab, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    len = sizeof(shared_ba);
                    ret = wc_curve25519_shared_secret(
                            key_b, key_a, shared_ba, &len);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to compute shared secret %d\n",
                                ret);
                    }
                }
                if (ret == 0) {
                    if (XMEMCMP(shared_ab, shared_ba, len) != 0) {
                        WH_ERROR_PRINT("CURVE25519 secrets don't match\n");
                        ret = -1;
                    }
                }
                wc_curve25519_free(key_b);
            }
            wc_curve25519_free(key_a);
        }
    }
    if (ret == 0) {
        printf("CURVE25519 SUCCESS\n");
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#ifndef NO_SHA256
static int whTest_CryptoSha256(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx; (void)rng; /* Not currently used */
    int ret = WH_ERROR_OK;
    wc_Sha256 sha256[1];
    uint8_t   out[WC_SHA256_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA256_DIGEST_SIZE] = {
        0xff, 0xe0, 0x54, 0xfe, 0x7a, 0xe0, 0xcb, 0x6d, 0xc6, 0x5c, 0x3a,
        0xf9, 0xb6, 0x1d, 0x52, 0x09, 0xf4, 0x39, 0x85, 0x1d, 0xb4, 0x3d,
        0x0b, 0xa5, 0x99, 0x73, 0x37, 0xdf, 0x15, 0x46, 0x68, 0xeb};
    /* Vector long enough to span a SHA256 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA256_DIGEST_SIZE] = {
        0x7b, 0x54, 0x45, 0x86, 0xb3, 0x51, 0x43, 0x4e, 0xf6, 0x83, 0xdb,
        0x78, 0x1d, 0x94, 0xd6, 0xb0, 0x36, 0x9b, 0x36, 0x56, 0x93, 0x0e,
        0xf4, 0x47, 0x9b, 0xae, 0xff, 0xfa, 0x1f, 0x36, 0x38, 0x64};

    /* Initialize SHA256 structure */
    ret = wc_InitSha256_ex(sha256, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha256 on devId 0x%X: %d\n", devId,
                ret);
    } else {
        /* Test SHA256 on a single block worth of data. Should trigger a server
         * transaction */
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
                if (memcmp(out, expectedOutOne,
                           WC_SHA256_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA256 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA256_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha256Free(sha256);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha256_ex(sha256, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha256 for devId 0x%X: %d\n",
                    devId, ret);
        } else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha256Update(sha256,
                    (const byte*)inMulti,
                    1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha256Update (first) %d\n", ret);
            } else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha256Update(sha256,
                        (const byte*)inMulti + 1,
                        WC_SHA256_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha256Update (mid) %d\n", ret);
                } else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha256Update(sha256,
                            (const byte*)inMulti + 1 + WC_SHA256_BLOCK_SIZE,
                           strlen(inMulti) - 1 - WC_SHA256_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha256Update (last) %d\n",
                                ret);
                    } else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha256Final(sha256, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha256Final %d\n",
                                    ret);
                        } else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA256_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA256 hash does not match the "
                                        "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha256Free(sha256);
        }
    }
    if (ret == 0) {
        printf("SHA256 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* !NO_SHA256 */

static int whTest_CacheExportKey(whClientContext* ctx, whKeyId* inout_key_id,
        uint8_t* label_in,  uint8_t* label_out, uint16_t label_len,
        uint8_t* key_in, uint8_t* key_out, uint16_t key_len)
{
    int ret = 0;
    uint16_t label_len_out = label_len;
    uint16_t key_len_out = key_len;
    whKeyId key_id_out = *inout_key_id;
    ret = wh_Client_KeyCache(ctx, 0, label_in, label_len, key_in, key_len,
            &key_id_out);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
    } else {
        ret = wh_Client_KeyExport(ctx, key_id_out, label_out, label_len_out,
                key_out, &key_len_out);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n", ret);
        } else {
            if ((key_len_out != key_len) ||
                (memcmp(key_in, key_out, key_len_out) != 0) ||
                (memcmp(label_in, label_out, label_len) != 0) ) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}

static int whTest_KeyCache(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)devId; (void)rng; /* Unused */

#define WH_TEST_KEYCACHE_KEYSIZE 16
    int ret;
    int i;
    uint16_t outLen;
    uint16_t keyId;
    uint8_t key[WH_TEST_KEYCACHE_KEYSIZE];
    uint8_t keyOut[WH_TEST_KEYCACHE_KEYSIZE] = {0};
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "KeyCache Test Label";
    uint8_t labelOut[WH_NVM_LABEL_LEN] = {0};

    /* Randomize inputs */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
    }

    /* test cache/export */
    keyId = WH_KEYID_ERASED;
    if (ret == 0) {
        ret = whTest_CacheExportKey(ctx, &keyId,
            labelIn, labelOut, sizeof(labelIn),
            key, keyOut, sizeof(key));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to Test CacheExportKey %d\n", ret);
        } else {
            printf("KEY CACHE/EXPORT SUCCESS\n");
        }
    }
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
    /* WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS protects the client test code that
     * expects to interop with the custom server (also defined in this
     * file), so that this test can be run against a standard server app
     *
     * TODO: This is a temporary bodge until we properly split tests into
     * single client and multi client */

    if (ret == 0) {
        /* test cache with duplicate keyId for a different user */
        ret = wh_Client_CommClose(ctx);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to CommClose:%d\n",ret);
        } else {
            ctx->comm->client_id = 2;
            ret = wh_Client_CommInit(ctx, NULL, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to CommInit:%d\n", ret);
            } else {
                /* Check that evicting the other client's key fails */
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != WH_ERROR_NOTFOUND) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n",
                            ret);
                } else {
                    ret = whTest_CacheExportKey(ctx, &keyId,
                            labelIn, labelOut, sizeof(labelIn),
                            key, keyOut, sizeof(key));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to Test CacheExportKey %d\n",
                                ret);
                    } else {
                        /* evict for this client */
                        (void)wh_Client_KeyEvict(ctx, keyId);
                    }
                }
                /* switch back and verify original key */
                (void)wh_Client_CommClose(ctx);
                ctx->comm->client_id = 1;
                ret = wh_Client_CommInit(ctx, NULL, NULL);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to reconnect: %d\n", ret);
                } else {
                    outLen = sizeof(keyOut);
                    ret = wh_Client_KeyExport(ctx, keyId, labelOut,
                            sizeof(labelOut), keyOut, &outLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n",
                                ret);
                    } else {
                        if ( (outLen != sizeof(key)) ||
                                (memcmp(key, keyOut, outLen) != 0) ||
                                (memcmp(labelIn, labelOut,
                                        sizeof(labelIn)) != 0) ) {
                            WH_ERROR_PRINT("Failed to match\n");
                            ret = -1;
                        } else {
                            printf("KEY CACHE USER EXCLUSION SUCCESS\n");
                        }
                    }
                }
            }
        }
    }
#endif /* !WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS */
    if (ret == 0) {
        /* test evict for original client */
        ret = wh_Client_KeyEvict(ctx, keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
        } else {
            outLen = sizeof(keyOut);
            ret = wh_Client_KeyExport(ctx, keyId, labelOut, sizeof(labelOut),
                    keyOut, &outLen);
            if (ret != WH_ERROR_NOTFOUND) {
                WH_ERROR_PRINT("Failed to not find evicted key %d\n", ret);
            } else {
                printf("KEY CACHE EVICT SUCCESS\n");
                ret = 0;
            }
        }
    }

    if (ret == 0) {
        /* test commit/erase */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                sizeof(key), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        } else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            } else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                } else {
                    outLen = sizeof(keyOut);
                    ret = wh_Client_KeyExport(ctx, keyId, labelOut,
                            sizeof(labelOut), keyOut, &outLen);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_KeyExport %d\n",
                                ret);
                    } else {
                        if ((outLen != sizeof(key) ||
                                (memcmp(key, keyOut, outLen) != 0) ||
                                (memcmp(labelIn, labelOut,
                                        sizeof(labelIn))) != 0) ) {
                            WH_ERROR_PRINT("Failed to match committed key\n");
                            ret = -1;
                        } else {
                            /* verify commit isn't using new nvm objects */
                            for (i = 0; i < WOLFHSM_CFG_NVM_OBJECT_COUNT; i++) {
                                ret = wh_Client_KeyCommit(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to over commit %d\n",
                                            ret);
                                }
                            }
                            if (ret == 0) {
                                ret = wh_Client_KeyErase(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to erase key %d\n",
                                            ret);
                                } else {
                                    outLen = sizeof(keyOut);
                                    ret = wh_Client_KeyExport(ctx, keyId,
                                            labelOut, sizeof(labelOut), keyOut,
                                            &outLen);
                                    if (ret != WH_ERROR_NOTFOUND) {
                                        WH_ERROR_PRINT("Failed to not find "
                                                        "erased key\n");
                                        ret = -1;
                                    } else {
                                        ret = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (ret == 0) {
            printf("KEY COMMIT/ERASE SUCCESS\n");
        }
    }
    return ret;
}

#ifndef NO_AES
static int whTestCrypto_Aes(whClientContext* ctx, int devId, WC_RNG* rng)
{
#define WH_TEST_AES_KEYSIZE 16
#define WH_TEST_AES_TEXTSIZE 16
    int ret = 0;
    Aes aes[1];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t key[WH_TEST_AES_KEYSIZE];
    uint8_t plainIn[WH_TEST_AES_TEXTSIZE];
    uint8_t cipher[WH_TEST_AES_TEXTSIZE] = { 0 };
    uint8_t plainOut[WH_TEST_AES_TEXTSIZE] = { 0 };
    whKeyId keyId = WH_KEYID_ERASED;
    uint8_t labelIn[WH_NVM_LABEL_LEN] = "AES Key Label";

    XMEMCPY(plainIn, PLAINTEXT, sizeof(plainIn));

    /* Randomize inputs */
    ret = wc_RNG_GenerateBlock(rng, key, sizeof(key));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
    } else {
        ret = wc_RNG_GenerateBlock(rng, iv, sizeof(iv));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        }
    }

#ifdef HAVE_AES_CBC
    if (ret == 0) {
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
                            if (memcmp(plainIn, plainOut,
                                    sizeof(plainIn)) != 0) {
                                WH_ERROR_PRINT("Failed to match AES-CBC\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
    }
    if (ret == 0) {
        /* test aes CBC with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            keyId = WH_KEYID_ERASED;
            ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn),
                    key, sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            } else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdAes %d\n", ret);
                } else {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n", ret);
                    } else {
                        ret = wc_AesCbcEncrypt(aes, cipher, plainIn,
                                sizeof(plainIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCbcEncrypt %d\n",
                                    ret);
                        } else {
                            /* Reset the IV to support decryption */
                            ret = wc_AesSetIV(aes, iv);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n",
                                        ret);
                            } else {
                                ret = wc_AesCbcDecrypt(aes, plainOut,
                                        cipher, sizeof(plainIn));
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to decrypt %d\n",
                                            ret);
                                } else {
                                    if (memcmp(plainIn, plainOut,
                                            sizeof(plainIn)) != 0) {
                                        WH_ERROR_PRINT("Failed to match\n");
                                        ret = -1;
                                    }
                                }
                            }
                        }
                    }
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
        if (ret == 0) {
            printf("AES CBC SUCCESS\n");
        }
    }
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
#define WH_TEST_AES_AUTHSIZE 16
#define WH_TEST_AES_TAGSIZE 16
    uint8_t authIn[WH_TEST_AES_AUTHSIZE];
    uint8_t authTag[WH_TEST_AES_TAGSIZE] = { 0 };

    /* Generate random auth */
    if (ret == 0){
        ret = wc_RNG_GenerateBlock(rng, authIn, sizeof(authIn));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_RNG_GenerateBlock %d\n", ret);
        }
    }

    if (ret == 0) {
        /* test aes GCM with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            ret = wc_AesGcmSetKey(aes, key, sizeof(key));
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesGcmSetKey %d\n", ret);
            } else {
                ret = wc_AesGcmEncrypt(aes, cipher, plainIn,
                        sizeof(plainIn), iv, sizeof(iv), authTag,
                        sizeof(authTag), authIn, sizeof(authIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
                } else {
                    ret = wc_AesGcmDecrypt(aes, plainOut, cipher,
                            sizeof(plainIn), iv, sizeof(iv), authTag,
                            sizeof(authTag), authIn, sizeof(authIn));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n", ret);
                    } else {
                        if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                            WH_ERROR_PRINT("AES GCM FAILED TO MATCH\n");
                            ret = -1;
                        }
                    }
                }
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
            memset(authTag, 0, sizeof(authTag));
        }
    }

    if (ret == 0) {
        /* test aes GCM with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        } else {
            keyId = WH_KEYID_ERASED;
            ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key, sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            } else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to set key id:%d\n", ret);
                } else {
                    ret = wc_AesGcmEncrypt(aes, (byte*)cipher, (byte*)plainIn, sizeof(plainIn), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
                    } else {
                        ret = wc_AesGcmDecrypt(aes, (byte*)plainOut, (byte*)cipher, sizeof(plainIn), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n", ret);
                        } else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) != 0) {
                                WH_ERROR_PRINT("AES GCM FAILED TO MATCH\n");
                                ret = -1;
                            }
                        }
                    }
                }
                (void)wh_Client_KeyEvict(ctx, keyId);
            }
            (void)wc_AesFree(aes);
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
            memset(authTag, 0, sizeof(authTag));
        }
        if (ret == 0) {
            printf("AES GCM SUCCESS\n");
        }
    }
#endif /* HAVE_AES_GCM */
    return ret;
}
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
static int whTestCrypto_Cmac(whClientContext* ctx, int devId, WC_RNG* rng)
{
    int ret;
    /* test cmac */
    Cmac cmac[1];
    uint8_t knownCmacKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t knownCmacMessage[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f,
        0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a,
        0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1,
        0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t knownCmacTag[AES_BLOCK_SIZE] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

    uint8_t labelIn[WH_NVM_LABEL_LEN] = "CMAC Key Label";

    uint8_t keyEnd[sizeof(knownCmacKey)] = {0};
    uint8_t labelEnd[WH_NVM_LABEL_LEN] = {0};
    uint16_t outLen = 0;
    uint8_t macOut[AES_BLOCK_SIZE] = {0};
    word32 macLen;
    whKeyId keyId;

    ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES, NULL, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
    } else {
        ret = wc_CmacUpdate(cmac, knownCmacMessage, sizeof(knownCmacMessage));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        } else {
            macLen = sizeof(macOut);
            ret = wc_CmacFinal(cmac, macOut, &macLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
            } else {
                if (memcmp(knownCmacTag, macOut, sizeof(knownCmacTag)) != 0) {
                    WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
                    ret = -1;
                }
            }
        }
        wc_CmacFree(cmac);
        memset(macOut, 0, sizeof(macOut));
    }

    if (ret == 0) {
        /* test oneshot verify */
        ret = wc_AesCmacVerify_ex(cmac, knownCmacTag, sizeof(knownCmacTag), knownCmacMessage, sizeof(knownCmacMessage), knownCmacKey, sizeof(knownCmacKey), NULL, WH_DEV_ID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesCmacVerify_ex %d\n", ret);
        }
    }

    if (ret == 0) {
        /* test oneshot generate with pre-cached key */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), knownCmacKey, sizeof(knownCmacKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        } else {
            macLen = sizeof(macOut);
            ret = wh_Client_CmacAesGenerate(cmac, macOut, &macLen, knownCmacMessage, sizeof(knownCmacMessage), keyId, NULL);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_AesCmacGenerate %d\n", ret);
            } else {
                if (memcmp(knownCmacTag, macOut, sizeof(knownCmacTag)) != 0) {
                    WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
                    ret = -1;
                } else {
                    /* TODO: Eliminate this autoevict */
                    /* verify the key was evicted after oneshot */
                    outLen = sizeof(keyEnd);
                    ret = wh_Client_KeyExport(ctx, keyId, labelEnd, sizeof(labelEnd), keyEnd, &outLen);
                    if (ret != WH_ERROR_NOTFOUND) {
                        WH_ERROR_PRINT("Failed to not find evicted key: %d\n", ret);
                        ret = -1;
                    } else {
                        ret = 0;
                    }
                }
            }
        }
    }

    if (ret == 0) {
        /* test oneshot verify with commited key */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), knownCmacKey, sizeof(knownCmacKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        } else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            } else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                } else {
                    macLen = sizeof(macOut);
                    ret = wh_Client_CmacAesVerify(cmac, macOut, macLen, (byte*)knownCmacMessage, sizeof(knownCmacMessage), keyId, NULL);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_AesCmacVerify %d\n", ret);
                    } else {
                        /* test finished, erase key */
                        ret = wh_Client_KeyErase(ctx, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wh_Client_KeyErase %d\n", ret);
                        }
                    }
                }
            }
        }
    }

    if (ret == 0) {
        /* test CMAC cancellation */
#define WH_TEST_CMAC_TEXTSIZE 1000
        char cmacFodder[WH_TEST_CMAC_TEXTSIZE] = {0};

        ret = wh_Client_EnableCancel(ctx);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_EnableCancel %d\n", ret);
        } else {
            ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES, NULL, NULL, devId);
            printf("cancel init cmac-type:%d\n", cmac->type);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
            } else {
                ret = wh_Client_CmacCancelableResponse(ctx, cmac, NULL, 0);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
                } else {
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
                    /* TODO: use hsm pause/resume functionality on real hardware */
                    /* delay the server so scheduling doesn't interfere with the timing */
                    serverDelay = 1;
#endif
                    printf("cancel update cmac->type:%d\n", cmac->type);
                    ret = wc_CmacUpdate(cmac, (byte*)cmacFodder, sizeof(cmacFodder));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
                    } else {
                        ret = wh_Client_CancelRequest(ctx);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wh_Client_CancelRequest %d\n", ret);
                        } else {
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
                            serverDelay = 0;
#endif
                            do {
                                ret = wh_Client_CancelResponse(ctx);
                            } while (ret == WH_ERROR_NOTREADY);
                            if(     (ret != 0) &&
#if defined(WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS)
                                    (ret != WH_ERROR_CANCEL_LATE) &&
#endif
                                    (!0) ) {
                                WH_ERROR_PRINT("Failed to wh_Client_CancelResponse %d\n", ret);
                            }
                        }
                    }
                }
            }

            if (ret == 0) {
                /* test cancelable request and response work for standard CMAC request with no cancellation */
                ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES, NULL, NULL, devId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
                } else {
                    ret = wh_Client_CmacCancelableResponse(ctx, cmac, NULL, 0);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
                    } else {
                        ret = wc_CmacUpdate(cmac, (byte*)knownCmacMessage, sizeof(knownCmacMessage));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
                        } else {
                            ret = wh_Client_CmacCancelableResponse(ctx, cmac, NULL, 0);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
                            } else {
                                macLen = sizeof(knownCmacTag);
                                ret = wc_CmacFinal(cmac, macOut, &macLen);
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
                                } else {
                                    ret = wh_Client_CmacCancelableResponse(ctx, cmac, macOut, &outLen);
                                    if (ret != 0) {
                                        WH_ERROR_PRINT("Failed to wh_Client_CmacCancelableResponse %d\n", ret);
                                    } else {
                                        if (memcmp(knownCmacTag, macOut, sizeof(knownCmacTag)) != 0) {
                                            WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
                                            ret = -1;
                                        } else {
                                            ret = wh_Client_DisableCancel(ctx);
                                            if (ret != 0) {
                                                WH_ERROR_PRINT("Failed to wh_Client_DisableCancel %d\n", ret);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (ret == 0) {
        printf("CMAC SUCCESS\n");
    }
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */


int whTest_CryptoClientConfig(whClientConfig* config)
{
    int i;
    whClientContext client[1] = {0};
    int ret = 0;
    /* wolfcrypt */
    WC_RNG rng[1];

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, config));

    ret = wh_Client_CommInit(client, NULL, NULL);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to comm init:%d\n", ret);
    }

#ifdef WOLFHSM_CFG_TEST_VERBOSE
    if (ret == 0) {
        (void)whTest_ShowNvmAvailable(ctx);
    }
#endif /* WOLFHSM_CFG_TEST_VERBOSE */

    if (ret == 0) {
        ret = whTest_CryptoRng(client, WH_DEV_ID, rng);
    }

    if (ret == 0) {
        /* Test Key Cache functions */
        ret = whTest_KeyCache(client, WH_DEV_ID, rng);
    }

#ifndef NO_AES
    if (ret == 0) {
        ret = whTestCrypto_Aes(client, WH_DEV_ID, rng);
    }
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    if (ret == 0) {
        ret = whTestCrypto_Cmac(client, WH_DEV_ID, rng);
    }
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifndef NO_RSA
    if (ret == 0) {
        ret = whTest_CryptoRsa(client, WH_DEV_ID, rng);
    }
#endif /* NO_RSA */

#ifdef HAVE_ECC
    if (ret == 0) {
        ret = whTest_CryptoEcc(client, WH_DEV_ID, rng);
    }
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
    /* test curve25519 */
    if (ret == 0) {
        ret = whTest_CryptoCurve25519(client, WH_DEV_ID, rng);
    }
#endif /* HAVE_CURVE25519 */

#ifndef NO_SHA256
    i = 0;
    while ( (ret == WH_ERROR_OK) &&
            (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha256(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* !NO_SHA256 */


#ifdef WOLFHSM_CFG_TEST_VERBOSE
    if (ret == 0) {
        (void)whTest_ShowNvmAvailable(ctx);
    }
#endif /* WOLFHSM_CFG_TEST_VERBOSE */

    /* Clean up used resources */
    (void)wc_FreeRng(rng);
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}

int whTest_CryptoServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
    int userChange = 0;
#endif

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

#if defined(WOLFHSM_CFG_TEST_POSIX)
    /* expose server ctx to client cancel callback */
    cancelSeqP = &server->cancelSeq;
#endif

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
    server->comm->client_id = 1;

    while(am_connected == WH_COMM_CONNECTED) {
#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
        while (serverDelay == 1) {
#ifdef WOLFHSM_CFG_TEST_POSIX
            sleep(1);
#endif
        }
#endif
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) &&
                (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n", ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);

#ifndef WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS
        /* keep alive for 2 user changes */
        if (am_connected != WH_COMM_CONNECTED && userChange < 2) {
            if (userChange == 0)
                server->comm->client_id = 2;
            else if (userChange == 1)
                server->comm->client_id = 1;
            userChange++;
            am_connected = WH_COMM_CONNECTED;
            WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
        }
#endif /* !WOLFHSM_CFG_TEST_NO_CUSTOM_SERVERS */
    }

    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    } else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}

#if defined(WOLFHSM_CFG_TEST_POSIX)
static void* _whClientTask(void *cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoClientConfig(cf));
    return NULL;
}

static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoServerConfig(cf));
    return NULL;
}


static void _whClientServerThreadTest(whClientConfig* c_conf,
                                whServerConfig* s_conf)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};

    void* retval;
    int rc = 0;

    rc = pthread_create(&sthread, NULL, _whServerTask, s_conf);
    if (rc == 0) {
        rc = pthread_create(&cthread, NULL, _whClientTask, c_conf);
        if (rc == 0) {
            /* All good. Block on joining */
            pthread_join(cthread, &retval);
            pthread_join(sthread, &retval);
        } else {
            /* Cancel the server thread */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);

        }
    }
}

static int wh_ClientServer_MemThreadTest(void)
{
    uint8_t req[BUFFER_SIZE] = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

    whTransportMemConfig tmcf[1] = {{
        .req        = (whTransportMemCsr*)req,
        .req_size   = sizeof(req),
        .resp       = (whTransportMemCsr*)resp,
        .resp_size  = sizeof(resp),
    }};
    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]   = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]   = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 1,
    }};
    whClientConfig c_conf[1] = {{
       .comm = cc_conf,
       .cancelCb = _cancelCb,
    }};
    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1] = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = 1024 * 1024, /* 1MB  Flash */
        .sectorSize = 128 * 1024,  /* 128KB  Sector Size */
        .pageSize   = 8,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
    }};
    const whFlashCb  fcb[1]          = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig nf_conf[1] = {{
        .cb      = fcb,
        .context = fc,
        .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1] = {0};
    whNvmCb nfcb[1] = {WH_NVM_FLASH_CB};

    whNvmConfig n_conf[1] = {{
            .cb = nfcb,
            .context = nfc,
            .config = nf_conf,
    }};
    whNvmContext nvm[1] = {{0}};

    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
            .devId = INVALID_DEVID,
    }};

    whServerConfig                  s_conf[1] = {{
       .comm_config = cs_conf,
       .nvm = nvm,
       .crypto = crypto,
       .devId = INVALID_DEVID,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));

    _whClientServerThreadTest(c_conf, s_conf);

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

int whTest_Crypto(void)
{
#if defined(WOLFHSM_CFG_TEST_POSIX)
    printf("Testing crypto: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(wh_ClientServer_MemThreadTest());
#endif
    return 0;
}

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
