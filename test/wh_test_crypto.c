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

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>
#include <stdio.h>  /* For printf */
#include <string.h> /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/kdf.h"

#include "wolfhsm/wh_error.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#endif

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
/* Pull in client keywrap tests to run against server */
#include "wh_test_keywrap.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#endif

#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <unistd.h> /* For sleep */
#include <pthread.h> /* For pthread_create/cancel/join/_t */
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_flash_file.h"
#endif

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8) /* 8B */

#define ALT_CLIENT_ID (2)

enum {
    /* Total size needs to fit:
     * - Transport CSR (whTransportMemCsr)
     * - Comm header (whCommHeader)
     * - Max data size (WOLFHSM_CFG_COMM_DATA_LEN)
     */
    BUFFER_SIZE = sizeof(whTransportMemCsr) + sizeof(whCommHeader) +
                  WOLFHSM_CFG_COMM_DATA_LEN,
};


#define PLAINTEXT "mytextisbigplain"

#ifdef WOLFHSM_CFG_IS_TEST_SERVER
/* Flag causing the server loop to sleep(1) */
int serverDelay = 0;

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && defined(WOLFHSM_CFG_CANCEL_API)
/* pointer to expose server context cancel sequence to the client cancel
 * callback */
static uint16_t* cancelSeqP;

#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER && WOLFHSM_CFG_CANCEL_API */
#endif /* WOLFHSM_CFG_IS_TEST_SERVER */

#if defined(WOLFHSM_CFG_TEST_VERBOSE) && defined(WOLFHSM_CFG_ENABLE_CLIENT)
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
#endif /* WOLFHSM_CFG_TEST_VERBOSE && WOLFHSM_CFG_ENABLE_CLIENT */

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
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
            ret = wc_FreeRng(rng);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_FreeRng %d\n", ret);
            }
        }
    }
    if (ret == 0) {
        printf("RNG DEVID=0x%X SUCCESS\n", devId);
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
                        if (memcmp(plainText, finalText, sizeof(plainText)) !=
                            0) {
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
    (void)ctx;

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
                            }
                            else {
                                WH_ERROR_PRINT("ECDH FAILED TO MATCH\n");
                            }
                        }
                    }
                    if (ret == 0) {
                        /*Use the shared secret as a random hash */
                        memcpy(hash, shared_ba, sizeof(hash));
                        word32 sigLen = sizeof(sig);
                        ret = wc_ecc_sign_hash((void*)hash, sizeof(hash),
                                               (void*)sig, &sigLen, rng,
                                               eccPrivate);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_ecc_sign_hash %d\n",
                                           ret);
                        } else {
                            int res = 0;
                            ret     = wc_ecc_verify_hash((void*)sig, sigLen,
                                                         (void*)hash, sizeof(hash),
                                                         &res, eccPrivate);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_ecc_verify_hash"
                                               " %d\n",
                                               ret);
                            }
                            else {
                                if (res == 1) {
                                    printf("ECC SIGN/VERIFY SUCCESS\n");
                                }
                                else {
                                    WH_ERROR_PRINT("ECC SIGN/VERIFY FAIL\n");
                                    ret = -1;
                                }
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

    /* Use wolfcrypt ephemeral local keys */
    ret = wc_curve25519_init_ex(key_a, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
    }
    else {
        ret = wc_curve25519_init_ex(key_b, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_curve25519_init_ex %d\n", ret);
        } else {
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
                        &key_id_a, flags, label_a, sizeof(label_a));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to make cached key %d\n", ret);
                }
                if (ret == 0) {
                    ret = wh_Client_Curve25519MakeCacheKey(ctx, key_size,
                            &key_id_b, flags, label_b, sizeof(label_b));
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
                if (memcmp(out, expectedOutOne, WC_SHA256_DIGEST_SIZE) != 0) {
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

#ifdef WOLFSSL_SHA224
static int whTest_CryptoSha224(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha224 sha224[1];
    uint8_t   out[WC_SHA224_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA224_DIGEST_SIZE] = {
        0xa8, 0x8c, 0xd5, 0xcd, 0xe6, 0xd6, 0xfe, 0x91, 0x36, 0xa4,
        0xe5, 0x8b, 0x49, 0x16, 0x74, 0x61, 0xea, 0x95, 0xd3, 0x88,
        0xca, 0x2b, 0xdb, 0x7a, 0xfd, 0xc3, 0xcb, 0xf4};
    /* Vector long enough to span a SHA224 block */
    const char inMulti[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
                           "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA224_DIGEST_SIZE] = {
        0xb4, 0x22, 0xdc, 0xe8, 0xf9, 0x48, 0x8c, 0x4b, 0xc3, 0xef,
        0x8e, 0x7d, 0xbe, 0x11, 0xc7, 0x21, 0xba, 0x38, 0xcb, 0x61,
        0xf5, 0x6b, 0x7d, 0xc5, 0x30, 0xa7, 0x9c, 0xfd};
    /* Initialize SHA224 structure */
    ret = wc_InitSha224_ex(sha224, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha224 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA224 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha224Update(sha224, (const byte*)inOne, WC_SHA224_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha224Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha224Final(sha224, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha224Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA224_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA224 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA224_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha224Free(sha224);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha224_ex(sha224, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha224 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha224Update(sha224, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha224Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha224Update(sha224, (const byte*)inMulti + 1,
                                      WC_SHA224_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha224Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha224Update(
                        sha224, (const byte*)inMulti + 1 + WC_SHA224_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA224_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha224Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha224Final(sha224, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha224Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA224_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA224 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha224Free(sha224);
        }
    }
    if (ret == 0) {
        printf("SHA224 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
static int whTest_CryptoSha384(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha384 sha384[1];
    uint8_t   out[WC_SHA384_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA384_DIGEST_SIZE] = {
        0xed, 0xb1, 0x27, 0x30, 0xa3, 0x66, 0x09, 0x8b, 0x3b, 0x2b, 0xea, 0xc7,
        0x5a, 0x3b, 0xef, 0x1b, 0x09, 0x69, 0xb1, 0x5c, 0x48, 0xe2, 0x16, 0x3c,
        0x23, 0xd9, 0x69, 0x94, 0xf8, 0xd1, 0xbe, 0xf7, 0x60, 0xc7, 0xe2, 0x7f,
        0x3c, 0x46, 0x4d, 0x38, 0x29, 0xf5, 0x6c, 0x0d, 0x53, 0x80, 0x8b, 0x0b};
    /* Vector long enough to span a SHA384 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA384_DIGEST_SIZE] = {
        0xe2, 0x56, 0x2a, 0x4b, 0xe2, 0x0a, 0x40, 0x34, 0xc1, 0x23, 0x8b, 0x1d,
        0x68, 0x49, 0x17, 0xdb, 0x8d, 0x3a, 0x78, 0xab, 0x22, 0xf3, 0xa1, 0x51,
        0x70, 0xae, 0x26, 0x80, 0x06, 0x25, 0x99, 0xa5, 0x3d, 0x0f, 0xc3, 0x7a,
        0xbd, 0xe1, 0xe2, 0xc6, 0x07, 0xdf, 0xd9, 0x6a, 0x89, 0xa8, 0x2b, 0x99};
    /* Initialize SHA384 structure */
    ret = wc_InitSha384_ex(sha384, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha384 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA384on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha384Update(sha384, (const byte*)inOne, WC_SHA384_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha384Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha384Final(sha384, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha384Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA384_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA384 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA384_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha384Free(sha384);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha384_ex(sha384, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha384 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha384Update(sha384, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha384Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha384Update(sha384, (const byte*)inMulti + 1,
                                      WC_SHA384_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha384Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha384Update(
                        sha384, (const byte*)inMulti + 1 + WC_SHA384_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA384_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha384Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha384Final(sha384, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha384Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA384_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA384 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha384Free(sha384);
        }
    }
    if (ret == 0) {
        printf("SHA384 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
static int whTest_CryptoSha512(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng; /* Not currently used */
    int       ret = WH_ERROR_OK;
    wc_Sha512 sha512[1];
    uint8_t   out[WC_SHA512_DIGEST_SIZE];
    /* Vector exactly one block size in length */
    const char inOne[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint8_t expectedOutOne[WC_SHA512_DIGEST_SIZE] = {
        0xb7, 0x3d, 0x19, 0x29, 0xaa, 0x61, 0x59, 0x34, 0xe6, 0x1a, 0x87,
        0x15, 0x96, 0xb3, 0xf3, 0xb3, 0x33, 0x59, 0xf4, 0x2b, 0x81, 0x75,
        0x60, 0x2e, 0x89, 0xf7, 0xe0, 0x6e, 0x5f, 0x65, 0x8a, 0x24, 0x36,
        0x67, 0x80, 0x7e, 0xd3, 0x00, 0x31, 0x4b, 0x95, 0xca, 0xcd, 0xd5,
        0x79, 0xf3, 0xe3, 0x3a, 0xbd, 0xfb, 0xe3, 0x51, 0x90, 0x95, 0x19,
        0xa8, 0x46, 0xd4, 0x65, 0xc5, 0x95, 0x82, 0xf3, 0x21};
    /* Vector long enough to span a SHA512 block */
    const char inMulti[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
        "YZ1234567890abcdefghi";
    const uint8_t expectedOutMulti[WC_SHA512_DIGEST_SIZE] = {
        0xf9, 0x09, 0xb7, 0xb7, 0x7d, 0xa2, 0x32, 0xc8, 0xcf, 0xa8, 0xcc,
        0xde, 0xc4, 0x36, 0x44, 0x74, 0x29, 0x4f, 0xc4, 0x9a, 0xcb, 0x60,
        0x13, 0x6b, 0xdb, 0x10, 0xd6, 0xa6, 0x9d, 0x1b, 0x45, 0xb2, 0x70,
        0xf5, 0x27, 0x9c, 0xe7, 0x80, 0x99, 0x19, 0x9b, 0x91, 0xb3, 0x83,
        0x7f, 0x70, 0xaf, 0x8e, 0x02, 0xd9, 0x6d, 0x20, 0xab, 0x1e, 0x72,
        0xde, 0x7a, 0x25, 0xa3, 0xe5, 0x60, 0x9e, 0xb0, 0x43};
    /* Initialize SHA512 structure */
    ret = wc_InitSha512_ex(sha512, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitSha512 on devId 0x%X: %d\n", devId,
                       ret);
    }
    else {
        /* Test SHA512 on a single block worth of data. Should trigger a server
         * transaction */
        ret = wc_Sha512Update(sha512, (const byte*)inOne, WC_SHA512_BLOCK_SIZE);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_Sha512Update %d\n", ret);
        }
        else {
            /* Finalize should trigger a server transaction with empty buffer */
            ret = wc_Sha512Final(sha512, out);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha512Final %d\n", ret);
            }
            else {
                /* Compare the computed hash with the expected output */
                if (memcmp(out, expectedOutOne, WC_SHA512_DIGEST_SIZE) != 0) {
                    WH_ERROR_PRINT("SHA512 hash does not match expected.\n");
                    ret = -1;
                }
                memset(out, 0, WC_SHA512_DIGEST_SIZE);
            }
        }
        /* Reset state for multi block test */
        (void)wc_Sha512Free(sha512);
    }
    if (ret == 0) {
        /* Multiblock test */
        ret = wc_InitSha512_ex(sha512, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_InitSha512 for devId 0x%X: %d\n",
                           devId, ret);
        }
        else {
            /* Update with a non-block aligned length. Will not trigger server
             * transaction */
            ret = wc_Sha512Update(sha512, (const byte*)inMulti, 1);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_Sha512Update (first) %d\n", ret);
            }
            else {
                /* Update with a full block, will trigger block to be sent to
                 * server and one additional byte to be buffered */
                ret = wc_Sha512Update(sha512, (const byte*)inMulti + 1,
                                      WC_SHA512_BLOCK_SIZE);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_Sha512Update (mid) %d\n", ret);
                }
                else {
                    /* Update with the remaining data, should not trigger server
                     * transaction */
                    ret = wc_Sha512Update(
                        sha512, (const byte*)inMulti + 1 + WC_SHA512_BLOCK_SIZE,
                        strlen(inMulti) - 1 - WC_SHA512_BLOCK_SIZE);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_Sha512Update (last) %d\n",
                                       ret);
                    }
                    else {
                        /* Finalize should trigger a server transaction on the
                         * remaining partial buffer */
                        ret = wc_Sha512Final(sha512, out);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_Sha512Final %d\n",
                                           ret);
                        }
                        else {
                            /* Compare the computed hash with the expected
                             * output */
                            if (memcmp(out, expectedOutMulti,
                                       WC_SHA512_DIGEST_SIZE) != 0) {
                                WH_ERROR_PRINT("SHA512 hash does not match the "
                                               "expected output.\n");
                                ret = -1;
                            }
                        }
                    }
                }
            }
            (void)wc_Sha512Free(sha512);
        }
    }
    if (ret == 0) {
        printf("SHA512 DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFSSL_SHA512 */

#ifdef HAVE_HKDF
static int whTest_CryptoHkdf(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)rng; /* Not currently used */

    int ret = WH_ERROR_OK;

#define WH_TEST_HKDF_IKM_SIZE 22
#define WH_TEST_HKDF_SALT_SIZE 13
#define WH_TEST_HKDF_INFO_SIZE 10
#define WH_TEST_HKDF_OKM_SIZE 42

    /* Test vectors from RFC 5869 Test Case 1 */
    const uint8_t ikm[WH_TEST_HKDF_IKM_SIZE] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const uint8_t salt[WH_TEST_HKDF_SALT_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04,
                                                  0x05, 0x06, 0x07, 0x08, 0x09,
                                                  0x0a, 0x0b, 0x0c};
    const uint8_t info[WH_TEST_HKDF_INFO_SIZE] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                                                  0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    const uint8_t expected[WH_TEST_HKDF_OKM_SIZE] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    uint8_t okm[WH_TEST_HKDF_OKM_SIZE];
    uint8_t okm2[WH_TEST_HKDF_OKM_SIZE];
    whKeyId key_id  = WH_KEYID_ERASED;
    uint8_t label[] = "HKDF Test Label";

    /* Test 1: Direct wc_HKDF call (uses crypto callback) */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
                     WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, okm,
                     WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_HKDF: %d\n", ret);
        return ret;
    }

    /* Verify output matches expected */
    if (memcmp(okm, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
        WH_ERROR_PRINT("HKDF output does not match expected (wc_HKDF)\n");
        return -1;
    }

    /* Test 2: HKDF without salt. Just ensure no errors */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(
        WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, NULL, 0, /* No salt */
        info, WH_TEST_HKDF_INFO_SIZE, okm, WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_HKDF (no salt): %d\n", ret);
        return ret;
    }

    /* Test 3: HKDF without info. Just ensure no errors */
    memset(okm, 0, sizeof(okm));
    ret = wc_HKDF_ex(WC_SHA256, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
                     WH_TEST_HKDF_SALT_SIZE, NULL, 0, /* No info */
                     okm, WH_TEST_HKDF_OKM_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_HKDF (no info): %d\n", ret);
        return ret;
    }

    /* Test 4: wh_Client_HkdfMakeExportKey */
    memset(okm, 0, sizeof(okm));
    ret = wh_Client_HkdfMakeExportKey(
        ctx, WC_SHA256, WH_KEYID_ERASED, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
        WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, okm,
        WH_TEST_HKDF_OKM_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_HkdfMakeExportKey: %d\n", ret);
        return ret;
    }

    /* Verify output matches expected vector, should be same as wolfCrypt API */
    if (memcmp(okm, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
        WH_ERROR_PRINT("HKDF output does not match expected (MakeExportKey)\n");
        return -1;
    }

    /* Test 5: wh_Client_HkdfMakeCacheKey */
    key_id = WH_KEYID_ERASED;
    ret    = wh_Client_HkdfMakeCacheKey(
           ctx, WC_SHA256, WH_KEYID_ERASED, ikm, WH_TEST_HKDF_IKM_SIZE, salt,
           WH_TEST_HKDF_SALT_SIZE, info, WH_TEST_HKDF_INFO_SIZE, &key_id,
           WH_NVM_FLAGS_NONE, label, sizeof(label), WH_TEST_HKDF_OKM_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_HkdfMakeCacheKey: %d\n", ret);
        return ret;
    }

    /* Verify key was cached */
    if (key_id == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("Key ID was not assigned\n");
        return -1;
    }

    /* Export the cached key to verify its contents */
    memset(okm2, 0, sizeof(okm2));
    {
        uint8_t  export_label[sizeof(label)] = {0};
        uint16_t export_len                  = WH_TEST_HKDF_OKM_SIZE;
        ret = wh_Client_KeyExport(ctx, key_id, export_label,
                                  sizeof(export_label), okm2, &export_len);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExport: %d\n", ret);
            return ret;
        }

        /* Verify exported length matches expected */
        if (export_len != WH_TEST_HKDF_OKM_SIZE) {
            WH_ERROR_PRINT("Exported key length mismatch: %u != %u\n",
                           export_len, WH_TEST_HKDF_OKM_SIZE);
            return -1;
        }

        /* Verify output matches expected */
        if (memcmp(okm2, expected, WH_TEST_HKDF_OKM_SIZE) != 0) {
            WH_ERROR_PRINT(
                "HKDF output does not match expected (MakeCacheKey)\n");
            return -1;
        }
    }

    /* Test 6: HKDF with cached input key */
    {
        whKeyId keyIdIn    = WH_KEYID_ERASED;
        uint8_t label_in[] = "input-key";
        byte    ikm2[]     = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                              0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};
        byte    salt2[]    = {0xB0, 0xB1, 0xB2, 0xB3};
        byte    info2[]    = {0xC0, 0xC1, 0xC2};
        byte    okm_cache[WH_TEST_HKDF_OKM_SIZE];
        byte    okm_direct[WH_TEST_HKDF_OKM_SIZE];

        /* First, cache the input key */
        ret = wh_Client_KeyCache(ctx, 0, label_in, sizeof(label_in), ikm2,
                                 sizeof(ikm2), &keyIdIn);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache input key: %d\n", ret);
            return ret;
        }

        /* Derive using cached input key (inKey=NULL, inKeySz=0) */
        memset(okm_cache, 0, sizeof(okm_cache));
        ret = wh_Client_HkdfMakeExportKey(
            ctx, WC_SHA256, keyIdIn, NULL, 0, salt2, sizeof(salt2), info2,
            sizeof(info2), okm_cache, sizeof(okm_cache));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed HKDF with cached input key: %d\n", ret);
            (void)wh_Client_KeyEvict(ctx, keyIdIn);
            return ret;
        }

        /* Derive the same way but with direct key input for comparison */
        memset(okm_direct, 0, sizeof(okm_direct));
        ret = wh_Client_HkdfMakeExportKey(ctx, WC_SHA256, WH_KEYID_ERASED, ikm2,
                                          sizeof(ikm2), salt2, sizeof(salt2),
                                          info2, sizeof(info2), okm_direct,
                                          sizeof(okm_direct));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed HKDF with direct input key: %d\n", ret);
            (void)wh_Client_KeyEvict(ctx, keyIdIn);
            return ret;
        }

        /* Verify both methods produce the same output */
        if (memcmp(okm_cache, okm_direct, sizeof(okm_cache)) != 0) {
            WH_ERROR_PRINT(
                "HKDF output mismatch (cached vs direct input key)\n");
            (void)wh_Client_KeyEvict(ctx, keyIdIn);
            return -1;
        }

        /* Clean up - evict the cached input key */
        ret = wh_Client_KeyEvict(ctx, keyIdIn);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to evict input key: %d\n", ret);
            return ret;
        }
    }

    printf("HKDF SUCCESS\n");
    return 0;
}
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
#define WH_TEST_CMAC_KDF_SALT_SIZE 24
#define WH_TEST_CMAC_KDF_Z_SIZE 32
#define WH_TEST_CMAC_KDF_FIXED_INFO_SIZE 60
#define WH_TEST_CMAC_KDF_OUT_SIZE 40

static int whTest_CryptoCmacKdf(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)rng;

    int ret = WH_ERROR_OK;

    /* Test vectors based on wolfSSL CMAC KDF implementation test vectors for
     * NIST SP 800-108 KDF in Counter Mode using CMAC */
    static const uint8_t salt[WH_TEST_CMAC_KDF_SALT_SIZE] = {
        0x20, 0x51, 0xaf, 0x34, 0x76, 0x2e, 0xbe, 0x55, 0x6f, 0x72, 0xa5, 0xc6,
        0xed, 0xc7, 0x77, 0x1e, 0xb9, 0x24, 0x5f, 0xad, 0x76, 0xf0, 0x34, 0xbe};
    static const uint8_t z[WH_TEST_CMAC_KDF_Z_SIZE] = {
        0xae, 0x8e, 0x93, 0xc9, 0xc9, 0x91, 0xcf, 0x89, 0x6a, 0x49, 0x1a,
        0x89, 0x07, 0xdf, 0x4e, 0x4b, 0xe5, 0x18, 0x6a, 0xe4, 0x96, 0xcd,
        0x34, 0x0d, 0xc1, 0x9b, 0x23, 0x78, 0x21, 0xdb, 0x7b, 0x60};
    static const uint8_t fixedInfo[WH_TEST_CMAC_KDF_FIXED_INFO_SIZE] = {
        0xa2, 0x59, 0xca, 0xe2, 0xc4, 0xa3, 0x6b, 0x89, 0x56, 0x3c, 0xb1, 0x48,
        0xc7, 0x82, 0x51, 0x34, 0x3b, 0xbf, 0xab, 0xdc, 0x13, 0xca, 0x7a, 0xc2,
        0x17, 0x1c, 0x2e, 0xb6, 0x02, 0x1f, 0x44, 0x77, 0xfe, 0xa3, 0x3b, 0x28,
        0x72, 0x4d, 0xa7, 0x21, 0xee, 0x08, 0x7b, 0xff, 0xd7, 0x94, 0xa1, 0x56,
        0x37, 0x54, 0xb4, 0x25, 0xa8, 0xd0, 0x9b, 0x3e, 0x0d, 0xa5, 0xff, 0xed};
    static const uint8_t expected[WH_TEST_CMAC_KDF_OUT_SIZE] = {
        0xb4, 0x0c, 0x32, 0xbe, 0x01, 0x27, 0x93, 0xba, 0xfd, 0xf7,
        0x78, 0xc5, 0xf4, 0x54, 0x43, 0xf4, 0xc9, 0x71, 0x23, 0x93,
        0x17, 0x63, 0xd8, 0x3a, 0x59, 0x27, 0x07, 0xbf, 0xf2, 0xd3,
        0x60, 0x59, 0x50, 0x27, 0x29, 0xca, 0xb8, 0x8b, 0x29, 0x38};

    uint8_t  out[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  out_direct[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  out_cached_input[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  exported[WH_TEST_CMAC_KDF_OUT_SIZE];
    uint8_t  exportLabel[12] = {0};
    uint16_t export_len      = WH_TEST_CMAC_KDF_OUT_SIZE;
    whKeyId  key_id          = WH_KEYID_ERASED;
    uint8_t  keyLabel[]      = "CMAC KDF Key";

    /* 1. Direct wolfCrypt API call that routes through the callback */
    memset(out, 0, sizeof(out));
    ret = wc_KDA_KDF_twostep_cmac(salt, WH_TEST_CMAC_KDF_SALT_SIZE, z,
                                  WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo,
                                  WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, out,
                                  WH_TEST_CMAC_KDF_OUT_SIZE, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wc_KDA_KDF_twostep_cmac: %d\n", ret);
        return ret;
    }
    if (memcmp(out, expected, sizeof(out)) != 0) {
        WH_ERROR_PRINT("CMAC KDF output mismatch (direct wolfCrypt)\n");
        return -1;
    }

    /* 2. Client export path using direct input buffers */
    memset(out_direct, 0, sizeof(out_direct));
    ret = wh_Client_CmacKdfMakeExportKey(
        ctx, WH_KEYID_ERASED, salt, WH_TEST_CMAC_KDF_SALT_SIZE, WH_KEYID_ERASED,
        z, WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo, WH_TEST_CMAC_KDF_FIXED_INFO_SIZE,
        out_direct, sizeof(out_direct));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_CmacKdfMakeExportKey: %d\n", ret);
        return ret;
    }
    if (memcmp(out_direct, expected, sizeof(out_direct)) != 0) {
        WH_ERROR_PRINT("CMAC KDF output mismatch (export key)\n");
        return -1;
    }

    /* 3. Client cache path with direct input buffers */
    key_id = WH_KEYID_ERASED;
    ret    = wh_Client_CmacKdfMakeCacheKey(
           ctx, WH_KEYID_ERASED, salt, WH_TEST_CMAC_KDF_SALT_SIZE, WH_KEYID_ERASED,
           z, WH_TEST_CMAC_KDF_Z_SIZE, fixedInfo, WH_TEST_CMAC_KDF_FIXED_INFO_SIZE,
           &key_id, WH_NVM_FLAGS_NONE, keyLabel, sizeof(keyLabel),
           WH_TEST_CMAC_KDF_OUT_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed wh_Client_CmacKdfMakeCacheKey: %d\n", ret);
        return ret;
    }
    if (key_id == WH_KEYID_ERASED) {
        WH_ERROR_PRINT("CMAC KDF cache did not return a key id\n");
        return -1;
    }

    memset(exported, 0, sizeof(exported));
    export_len = (uint16_t)sizeof(exported);
    memset(exportLabel, 0, sizeof(exportLabel));
    ret = wh_Client_KeyExport(ctx, key_id, exportLabel, sizeof(exportLabel),
                              exported, &export_len);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export cached CMAC KDF key: %d\n", ret);
        (void)wh_Client_KeyEvict(ctx, key_id);
        return ret;
    }
    if ((export_len != WH_TEST_CMAC_KDF_OUT_SIZE) ||
        (memcmp(exported, expected, sizeof(exported)) != 0)) {
        WH_ERROR_PRINT("Exported CMAC KDF key mismatch\n");
        (void)wh_Client_KeyEvict(ctx, key_id);
        return -1;
    }
    ret = wh_Client_KeyEvict(ctx, key_id);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to evict cached CMAC KDF key: %d\n", ret);
        return ret;
    }

    /* 4. Use cached salt and Z inputs */
    whKeyId saltKeyId = WH_KEYID_ERASED;
    whKeyId zKeyId    = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, NULL, 0, salt,
                             WH_TEST_CMAC_KDF_SALT_SIZE, &saltKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache CMAC KDF salt: %d\n", ret);
        return ret;
    }
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, NULL, 0, z,
                             WH_TEST_CMAC_KDF_Z_SIZE, &zKeyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache CMAC KDF Z input: %d\n", ret);
        (void)wh_Client_KeyEvict(ctx, saltKeyId);
        return ret;
    }

    memset(out_cached_input, 0, sizeof(out_cached_input));
    ret = wh_Client_CmacKdfMakeExportKey(
        ctx, saltKeyId, NULL, 0, zKeyId, NULL, 0, fixedInfo,
        WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, out_cached_input,
        sizeof(out_cached_input));
    if (ret != 0) {
        WH_ERROR_PRINT("Failed CMAC KDF export with cached inputs: %d\n", ret);
        goto cleanup_inputs;
    }
    if (memcmp(out_cached_input, expected, sizeof(out_cached_input)) != 0) {
        WH_ERROR_PRINT("CMAC KDF mismatch (cached inputs export)\n");
        ret = -1;
        goto cleanup_inputs;
    }

    key_id = WH_KEYID_ERASED;
    ret    = wh_Client_CmacKdfMakeCacheKey(
           ctx, saltKeyId, NULL, 0, zKeyId, NULL, 0, fixedInfo,
           WH_TEST_CMAC_KDF_FIXED_INFO_SIZE, &key_id, WH_NVM_FLAGS_NONE, keyLabel,
           sizeof(keyLabel), WH_TEST_CMAC_KDF_OUT_SIZE);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed CMAC KDF cache with cached inputs: %d\n", ret);
        goto cleanup_inputs;
    }
    if (key_id == WH_KEYID_ERASED) {
        WH_ERROR_PRINT(
            "CMAC KDF cache (cached inputs) did not return key id\n");
        ret = -1;
        goto cleanup_inputs;
    }

    memset(exported, 0, sizeof(exported));
    export_len = (uint16_t)sizeof(exported);
    memset(exportLabel, 0, sizeof(exportLabel));
    ret = wh_Client_KeyExport(ctx, key_id, exportLabel, sizeof(exportLabel),
                              exported, &export_len);
    if ((ret != 0) || (export_len != WH_TEST_CMAC_KDF_OUT_SIZE) ||
        (memcmp(exported, expected, sizeof(exported)) != 0)) {
        WH_ERROR_PRINT("Export mismatch for CMAC KDF cached inputs (ret=%d)\n",
                       ret);
        if (ret == 0) {
            ret = -1;
        }
    }

    (void)wh_Client_KeyEvict(ctx, key_id);

cleanup_inputs:
    (void)wh_Client_KeyEvict(ctx, saltKeyId);
    (void)wh_Client_KeyEvict(ctx, zKeyId);

    if (ret != WH_ERROR_OK) {
        return ret;
    }

    printf("CMAC KDF SUCCESS\n");
    return 0;
}
#endif /* HAVE_CMAC_KDF */

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
                (memcmp(label_in, label_out, label_len) != 0)) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTest_CacheExportKeyDma(whClientContext* ctx, whKeyId* inout_key_id,
                                    uint8_t* label_in, uint8_t* label_out,
                                    uint16_t label_len, uint8_t* key_in,
                                    uint8_t* key_out, uint16_t key_len)
{
    int      ret           = 0;
    uint16_t label_len_out = label_len;
    uint16_t key_len_out   = key_len;
    whKeyId  key_id_out    = *inout_key_id;

    ret = wh_Client_KeyCacheDma(ctx, 0, label_in, label_len, key_in, key_len,
                                &key_id_out);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wh_Client_KeyCacheDma %d\n", ret);
    }
    else {
        ret = wh_Client_KeyExportDma(ctx, key_id_out, key_out, key_len_out,
                                     label_out, label_len_out, &key_len_out);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyExportDma %d\n", ret);
        }
        else {
            if ((key_len_out != key_len) ||
                (memcmp(key_in, key_out, key_len_out) != 0) ||
                (memcmp(label_in, label_out, label_len) != 0)) {
                ret = -1;
            }
        }
    }
    *inout_key_id = key_id_out;
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

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

    /* test regular cache/export */
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
#ifdef WOLFHSM_CFG_IS_TEST_SERVER
    /* WOLFHSM_CFG_IS_TEST_SERVER protects the client test code that
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
            ctx->comm->client_id = ALT_CLIENT_ID;
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
                ctx->comm->client_id = WH_TEST_DEFAULT_CLIENT_ID;
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
                        if ((outLen != sizeof(key)) ||
                            (memcmp(key, keyOut, outLen) != 0) ||
                            (memcmp(labelIn, labelOut, sizeof(labelIn)) != 0)) {
                            WH_ERROR_PRINT("Failed to match\n");
                            ret = -1;
                        }
                        else {
                            printf("KEY CACHE USER EXCLUSION SUCCESS\n");
                        }
                    }
                }
            }
        }
    }
#endif /* WOLFHSM_CFG_IS_TEST_SERVER */
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
                             (memcmp(labelIn, labelOut, sizeof(labelIn))) !=
                                 0)) {
                            WH_ERROR_PRINT("Failed to match committed key\n");
                            ret = -1;
                        }
                        else {
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

    /* Test cross-cache key eviction and replacement */
    if (ret == 0) {
        uint16_t keyId;
        /* Key for regular cache (≤ WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t smallKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2;
        uint8_t      smallKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE/2];
        /* Key for big cache (> WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t bigKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100;
        uint8_t      bigKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE+100];

        uint8_t labelSmall[WH_NVM_LABEL_LEN] = "Small Key Label";
        uint8_t labelBig[WH_NVM_LABEL_LEN]   = "Big Key Label";

        /* Buffer for exported key and metadata */
        uint8_t  exportedKey[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE+100];
        uint8_t  exportedLabel[WH_NVM_LABEL_LEN];
        uint16_t exportedKeySize;

        /* Initialize test keys with different data */
        memset(smallKey, 0xAA, sizeof(smallKey));
        memset(bigKey, 0xBB, sizeof(bigKey));

        /* Test 1: Cache small key first, then cache same keyId with big key */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCache(ctx, 0, labelSmall, sizeof(labelSmall),
                                   smallKey, sizeof(smallKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache small key: %d\n", ret);
        }
        else {
            /* Now cache big key with same keyId - should succeed and evict the
             * small key */
            ret = wh_Client_KeyCache(ctx, 0, labelBig, sizeof(labelBig), bigKey,
                                     sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to cache big key (expected success): %d\n", ret);
            }
            else {
                /* Verify the cached key is the big key by exporting it */
                exportedKeySize = sizeof(exportedKey);
                ret = wh_Client_KeyExport(ctx, keyId, exportedLabel,
                                          sizeof(exportedLabel), exportedKey,
                                          &exportedKeySize);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to export key after cache: %d\n",
                                   ret);
                }
                else {
                    /* Verify exported key matches the big key */
                    if (exportedKeySize != bigKeySize ||
                        memcmp(exportedKey, bigKey, bigKeySize) != 0) {
                        WH_ERROR_PRINT(
                            "Exported key data doesn't match big key\n");
                        ret = -1;
                    }
                    /* Verify exported label matches the big key label */
                    else if (memcmp(exportedLabel, labelBig,
                                    sizeof(labelBig)) != 0) {
                        WH_ERROR_PRINT(
                            "Exported label doesn't match big key label\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                    }
                }
                /* Clean up */
                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                    }
                }
                else {
                    /* On error, try our best to clean up */
                    (void)wh_Client_KeyEvict(ctx, keyId);
                }

                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        /* double evict should fail */
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT("Double evict shouldn't succeed, "
                                       "cross-cache duplication test failed\n");
                        ret = -1;
                    }
                }
            }
        }

        /* Test 2: Cache big key first, then cache same keyId with small key */
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret = wh_Client_KeyCache(ctx, 0, labelBig, sizeof(labelBig), bigKey,
                                     sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache big key: %d\n", ret);
            }
            else {
                /* Now cache small key with same keyId - should succeed and
                 * evict the big key */
                ret = wh_Client_KeyCache(ctx, 0, labelSmall, sizeof(labelSmall),
                                         smallKey, sizeof(smallKey), &keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed to cache small key (expected success): %d\n",
                        ret);
                }
                else {
                    /* Verify the cached key is the small key by exporting it */
                    exportedKeySize = sizeof(exportedKey);
                    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel,
                                              sizeof(exportedLabel),
                                              exportedKey, &exportedKeySize);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to export key after cache: %d\n", ret);
                    }
                    else {
                        /* Verify exported key matches the small key */
                        if (exportedKeySize != smallKeySize ||
                            memcmp(exportedKey, smallKey, smallKeySize) != 0) {
                            WH_ERROR_PRINT(
                                "Exported key data doesn't match small key\n");
                            ret = -1;
                        }
                        /* Verify exported label matches the small key label */
                        else if (memcmp(exportedLabel, labelSmall,
                                        sizeof(labelSmall)) != 0) {
                            WH_ERROR_PRINT("Exported label doesn't match small "
                                           "key label\n");
                            ret = -1;
                        }
                        else {
                            ret = 0;
                        }
                    }
                    /* Clean up */
                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                        }
                    }
                    else {
                        /* On error, try our best to clean up */
                        (void)wh_Client_KeyEvict(ctx, keyId);
                    }

                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            /* double evict should fail */
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "Double evict shouldn't succeed, "
                                "cross-cache duplication test failed\n");
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (ret == 0) {
            printf("KEY CROSS-CACHE EVICTION AND REPLACEMENT SUCCESS\n");
        }
    }

#ifdef WOLFHSM_CFG_DMA
    /* test cache/export using DMA */
    if (ret == 0) {
        keyId = WH_KEYID_ERASED;
        ret =
            whTest_CacheExportKeyDma(ctx, &keyId, labelIn, labelOut,
                                     sizeof(labelIn), key, keyOut, sizeof(key));
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to Test CacheExportKeyDma %d\n", ret);
        }
        else {
            ret = wh_Client_KeyEvict(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
            }
            else {
                printf("KEY CACHE/EXPORT DMA SUCCESS\n");
            }
        }
    }

    /* Test cross-cache key eviction and replacement with DMA */
    if (ret == 0) {
        uint16_t keyId;
        /* Key for regular cache (≤ WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t smallKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE / 2;
        uint8_t      smallKey[smallKeySize];
        /* Key for big cache (> WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE) */
        const size_t bigKeySize = WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE + 100;
        uint8_t      bigKey[bigKeySize];

        uint8_t labelSmall[WH_NVM_LABEL_LEN] = "Small DMA Key Label";
        uint8_t labelBig[WH_NVM_LABEL_LEN]   = "Big DMA Key Label";

        /* Buffer for exported key and metadata */
        uint8_t  exportedKey[bigKeySize];
        uint8_t  exportedLabel[WH_NVM_LABEL_LEN];
        uint16_t exportedKeySize;

        /* Initialize test keys with different data */
        memset(smallKey, 0xCC, sizeof(smallKey));
        memset(bigKey, 0xDD, sizeof(bigKey));

        /* Test 1: Cache small key with DMA first, then cache same keyId
         * with big key using DMA */
        keyId = WH_KEYID_ERASED;
        ret   = wh_Client_KeyCacheDma(ctx, 0, labelSmall, sizeof(labelSmall),
                                      smallKey, sizeof(smallKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to cache small key with DMA: %d\n", ret);
        }
        else {
            /* Now cache big key with same keyId using DMA - should succeed and
             * evict the small key */
            ret = wh_Client_KeyCacheDma(ctx, 0, labelBig, sizeof(labelBig),
                                        bigKey, sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT(
                    "Failed to cache big key with DMA (expected success): %d\n",
                    ret);
            }
            else {
                /* Verify the cached key is the big key by exporting it */
                exportedKeySize = bigKeySize;
                ret             = wh_Client_KeyExportDma(
                    ctx, keyId, exportedKey, exportedKeySize, exportedLabel,
                    sizeof(exportedLabel), &exportedKeySize);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to export key after cache: %d\n",
                                   ret);
                }
                else {
                    /* Verify exported key matches the big key */
                    if (exportedKeySize != bigKeySize ||
                        memcmp(exportedKey, bigKey, bigKeySize) != 0) {
                        WH_ERROR_PRINT(
                            "Exported key data doesn't match big key\n");
                        ret = -1;
                    }
                    /* Verify exported label matches the big key label */
                    else if (memcmp(exportedLabel, labelBig,
                                    sizeof(labelBig)) != 0) {
                        WH_ERROR_PRINT(
                            "Exported label doesn't match big key label\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                    }
                }
                /* Clean up */
                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                    }
                }
                else {
                    /* On error, try our best to clean up */
                    (void)wh_Client_KeyEvict(ctx, keyId);
                }

                if (ret == 0) {
                    ret = wh_Client_KeyEvict(ctx, keyId);
                    if (ret != 0) {
                        /* double evict should fail */
                        ret = 0;
                    }
                    else {
                        WH_ERROR_PRINT("Double evict shouldn't succeed, "
                                       "cross-cache duplication test failed\n");
                        ret = -1;
                    }
                }
            }
        }

        /* Test 2: Cache big key with DMA first, then cache
         * same keyId with small key using DMA */
        if (ret == 0) {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCacheDma(ctx, 0, labelBig, sizeof(labelBig),
                                          bigKey, sizeof(bigKey), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to cache big key with DMA: %d\n", ret);
            }
            else {
                /* Now cache small key with same keyId using DMA - should
                 * succeed and evict the big key */
                ret = wh_Client_KeyCacheDma(ctx, 0, labelSmall,
                                            sizeof(labelSmall), smallKey,
                                            sizeof(smallKey), &keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to cache small key with DMA "
                                   "(expected success): %d\n",
                                   ret);
                }
                else {
                    /* Verify the cached key is the small key by exporting it */
                    exportedKeySize = smallKeySize;
                    ret             = wh_Client_KeyExportDma(
                        ctx, keyId, exportedKey, exportedKeySize, exportedLabel,
                        sizeof(exportedLabel), &exportedKeySize);
                    if (ret != 0) {
                        WH_ERROR_PRINT(
                            "Failed to export key after cache: %d\n", ret);
                    }
                    else {
                        /* Verify exported key matches the small key */
                        if (exportedKeySize != smallKeySize ||
                            memcmp(exportedKey, smallKey, smallKeySize) != 0) {
                            WH_ERROR_PRINT(
                                "Exported key data doesn't match small key\n");
                            ret = -1;
                        }
                        /* Verify exported label matches the small key label */
                        else if (memcmp(exportedLabel, labelSmall,
                                        sizeof(labelSmall)) != 0) {
                            WH_ERROR_PRINT("Exported label doesn't match small "
                                           "key label\n");
                            ret = -1;
                        }
                        else {
                            ret = 0;
                        }
                    }
                    /* Clean up */
                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to evict key: %d\n", ret);
                        }
                    }
                    else {
                        /* On error, try our best to clean up */
                        (void)wh_Client_KeyEvict(ctx, keyId);
                    }

                    if (ret == 0) {
                        ret = wh_Client_KeyEvict(ctx, keyId);
                        if (ret != 0) {
                            /* double evict should fail */
                            ret = 0;
                        }
                        else {
                            WH_ERROR_PRINT(
                                "Double evict shouldn't succeed, "
                                "cross-cache duplication test failed\n");
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (ret == 0) {
            printf("KEY CROSS-CACHE EVICTION AND REPLACEMENT DMA SUCCESS\n");
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    return ret;
}

static int whTest_NonExportableKeystore(whClientContext* ctx, int devId,
                                        WC_RNG* rng)
{
    (void)devId;
    (void)rng;

    int     ret                   = 0;
    whKeyId keyId                 = WH_KEYID_ERASED;
    uint8_t key[AES_256_KEY_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
    uint8_t  exportedKey[AES_256_KEY_SIZE]   = {0};
    uint8_t  label[WH_NVM_LABEL_LEN]         = "NonExportableTestKey";
    uint8_t  exportedLabel[WH_NVM_LABEL_LEN] = {0};
    uint16_t exportedKeySize;

    printf("Testing non-exportable keystore enforcement...\n");

    /* Test 1: Cache a key with non-exportable flag and try to export it */
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONEXPORTABLE, label,
                             sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache non-exportable key: %d\n", ret);
        return ret;
    }

    /* Try to export the non-exportable key - should fail */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel, sizeof(exportedLabel),
                              exportedKey, &exportedKeySize);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT("Non-exportable key was exported unexpectedly: %d\n",
                       ret);
        return -1;
    }

    printf("Non-exportable key export correctly denied\n");

    /* Clean up the key */
    wh_Client_KeyEvict(ctx, keyId);

    /* Test 2: Cache a key without non-exportable flag and verify it can be
     * exported */
    keyId = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache exportable key: %d\n", ret);
        return ret;
    }

    /* Try to export the exportable key - should succeed */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExport(ctx, keyId, exportedLabel, sizeof(exportedLabel),
                              exportedKey, &exportedKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export exportable key: %d\n", ret);
        return ret;
    }

    /* Verify exported data matches original */
    if (exportedKeySize != sizeof(key) ||
        memcmp(key, exportedKey, exportedKeySize) != 0 ||
        memcmp(label, exportedLabel, sizeof(label)) != 0) {
        WH_ERROR_PRINT("Exported key data doesn't match original\n");
        return -1;
    }

    printf("Exportable key export succeeded\n");

    /* Clean up */
    wh_Client_KeyEvict(ctx, keyId);

#ifdef WOLFHSM_CFG_DMA
    /* Test 3: Test DMA export with non-exportable key */
    printf("Testing DMA key export protection...\n");

    /* Cache a key with non-exportable flag */
    keyId = WH_KEYID_ERASED;
    ret   = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONEXPORTABLE, label,
                               sizeof(label), key, sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache non-exportable key for DMA test: %d\n",
                       ret);
        return ret;
    }

    /* Try to export the non-exportable key via DMA - should fail */
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExportDma(ctx, keyId, exportedKey, sizeof(exportedKey),
                                 exportedLabel, sizeof(exportedLabel),
                                 &exportedKeySize);
    if (ret != WH_ERROR_ACCESS) {
        WH_ERROR_PRINT(
            "Non-exportable key was exported via DMA unexpectedly: %d\n", ret);
        return -1;
    }

    printf("Non-exportable key DMA export correctly denied\n");

    /* Clean up the key */
    wh_Client_KeyEvict(ctx, keyId);

    /* Test 4: Test DMA export with exportable key */
    keyId = WH_KEYID_ERASED;
    ret = wh_Client_KeyCache(ctx, WH_NVM_FLAGS_NONE, label, sizeof(label), key,
                             sizeof(key), &keyId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to cache exportable key for DMA test: %d\n",
                       ret);
        return ret;
    }

    /* Try to export the exportable key via DMA - should succeed */
    memset(exportedKey, 0, sizeof(exportedKey));
    memset(exportedLabel, 0, sizeof(exportedLabel));
    exportedKeySize = sizeof(exportedKey);
    ret = wh_Client_KeyExportDma(ctx, keyId, exportedKey, sizeof(exportedKey),
                                 exportedLabel, sizeof(exportedLabel),
                                 &exportedKeySize);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to export exportable key via DMA: %d\n", ret);
        return ret;
    }

    /* Verify exported data matches original */
    if (exportedKeySize != sizeof(key) ||
        memcmp(key, exportedKey, exportedKeySize) != 0 ||
        memcmp(label, exportedLabel, sizeof(label)) != 0) {
        WH_ERROR_PRINT("DMA exported key data doesn't match original\n");
        return -1;
    }

    printf("Exportable key DMA export succeeded\n");

    /* Clean up */
    wh_Client_KeyEvict(ctx, keyId);
#endif /* WOLFHSM_CFG_DMA */

    printf("NON-EXPORTABLE KEYSTORE TEST SUCCESS\n");
    return 0;
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

    memcpy(plainIn, PLAINTEXT, sizeof(plainIn));

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
#ifdef WOLFSSL_AES_COUNTER
    if (ret == 0
#ifdef WOLFHSM_CFG_DMA
        && devId != WH_DEV_ID_DMA
#endif
    ) {
        /* test aes CTR with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n", ret);
            }
            else {
                ret = wc_AesCtrEncrypt(aes, cipher, plainIn, sizeof(plainIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n", ret);
                }
                else {
                    ret = wc_AesSetKeyDirect(aes, key, sizeof(key), iv,
                                             AES_DECRYPTION);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetKeyDirect %d\n",
                                       ret);
                    }
                    else {
                        ret = wc_AesCtrEncrypt(aes, plainOut, cipher,
                                               sizeof(cipher));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n",
                                           ret);
                        }
                        else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
                                WH_ERROR_PRINT("Failed to match AES-CTR\n");
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
        /* test aes CTR with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                       sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            }
            else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdAes %d\n", ret);
                }
                else {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n", ret);
                    }
                    else {
                        ret = wc_AesCtrEncrypt(aes, cipher, plainIn,
                                               sizeof(plainIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesCtrEncrypt %d\n",
                                           ret);
                        }
                        else {
                            /* Reset the IV to support decryption */
                            ret = wc_AesSetIV(aes, iv);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n",
                                               ret);
                            }
                            else {
                                ret = wc_AesCtrEncrypt(aes, plainOut, cipher,
                                                       sizeof(plainIn));
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to decrypt %d\n",
                                                   ret);
                                }
                                else {
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
            printf("AES CTR DEVID=0x%X SUCCESS\n", devId);
        }
    }
#endif


#ifdef HAVE_AES_ECB
    if (ret == 0) {
        /* test aes ECB with client side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            ret = wc_AesSetKey(aes, key, sizeof(key), iv, AES_ENCRYPTION);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
            }
            else {
                ret = wc_AesEcbEncrypt(aes, cipher, plainIn, sizeof(plainIn));
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wc_AesEcbEncrypt %d\n", ret);
                }
                else {
                    ret =
                        wc_AesSetKey(aes, key, sizeof(key), iv, AES_DECRYPTION);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetKey %d\n", ret);
                    }
                    else {
                        ret = wc_AesEcbDecrypt(aes, plainOut, cipher,
                                               sizeof(cipher));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesEcbDecrypt %d\n",
                                           ret);
                        }
                        else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
                                WH_ERROR_PRINT("Failed to match AES-ECB\n");
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
        /* test aes ECB with HSM side key */
        ret = wc_AesInit(aes, NULL, devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesInit %d\n", ret);
        }
        else {
            keyId = WH_KEYID_ERASED;
            ret   = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                       sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            }
            else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_SetKeyIdAes %d\n", ret);
                }
                else {
                    ret = wc_AesSetIV(aes, iv);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n", ret);
                    }
                    else {
                        ret = wc_AesEcbEncrypt(aes, cipher, plainIn,
                                               sizeof(plainIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesEcbEncrypt %d\n",
                                           ret);
                        }
                        else {
                            /* Reset the IV to support decryption */
                            ret = wc_AesSetIV(aes, iv);
                            if (ret != 0) {
                                WH_ERROR_PRINT("Failed to wc_AesSetIV %d\n",
                                               ret);
                            }
                            else {
                                ret = wc_AesEcbDecrypt(aes, plainOut, cipher,
                                                       sizeof(plainIn));
                                if (ret != 0) {
                                    WH_ERROR_PRINT("Failed to decrypt %d\n",
                                                   ret);
                                }
                                else {
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
            printf("AES ECB DEVID=0x%X SUCCESS\n", devId);
        }
    }
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
    if (ret == 0
#ifdef WOLFHSM_CFG_DMA
        && devId != WH_DEV_ID_DMA
#endif
    ) {
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
            memset(cipher, 0, sizeof(cipher));
            memset(plainOut, 0, sizeof(plainOut));
        }
    }
    if (ret == 0
#ifdef WOLFHSM_CFG_DMA
        && devId != WH_DEV_ID_DMA
#endif
    ) {
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
            printf("AES CBC DEVID=0x%X SUCCESS\n", devId);
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
            ret   = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), key,
                                       sizeof(key), &keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
            } else {
                ret = wh_Client_AesSetKeyId(aes, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to set key id:%d\n", ret);
                } else {
                    ret = wc_AesGcmEncrypt(aes, (byte*)cipher, (byte*)plainIn,
                                           sizeof(plainIn), iv, sizeof(iv),
                                           authTag, sizeof(authTag), authIn,
                                           sizeof(authIn));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_AesGcmEncrypt %d\n", ret);
                    } else {
                        ret = wc_AesGcmDecrypt(
                            aes, (byte*)plainOut, (byte*)cipher,
                            sizeof(plainIn), iv, sizeof(iv), authTag,
                            sizeof(authTag), authIn, sizeof(authIn));
                        if (ret != 0) {
                            WH_ERROR_PRINT("Failed to wc_AesGcmDecrypt %d\n",
                                           ret);
                        } else {
                            if (memcmp(plainIn, plainOut, sizeof(plainIn)) !=
                                0) {
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
            printf("AES GCM DEVID=0x%X SUCCESS\n", devId);
        }
    }
#endif /* HAVE_AES_GCM */
    return ret;
}
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
static int whTestCrypto_Cmac(whClientContext* ctx, int devId, WC_RNG* rng)
{
    (void)ctx;
    (void)rng;

    int ret;
    /* test cmac */
    Cmac    cmac[1];
    uint8_t knownCmacKey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t knownCmacMessage[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t knownCmacTag[AES_BLOCK_SIZE] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b,
                                            0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17,
                                            0x79, 0x36, 0x3c, 0xfe};

    uint8_t labelIn[WH_NVM_LABEL_LEN] = "CMAC Key Label";

    uint8_t  keyEnd[sizeof(knownCmacKey)] = {0};
    uint8_t  labelEnd[WH_NVM_LABEL_LEN]   = {0};
    uint16_t outLen                       = 0;
    uint8_t  macOut[AES_BLOCK_SIZE]       = {0};
    word32   macLen;
    whKeyId  keyId;

    ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey), WC_CMAC_AES,
                         NULL, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
    }
    else {
        ret = wc_CmacUpdate(cmac, knownCmacMessage, sizeof(knownCmacMessage));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
        }
        else {
            macLen = sizeof(macOut);
            ret    = wc_CmacFinal(cmac, macOut, &macLen);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_CmacFinal %d\n", ret);
            }
            else {
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
        ret = wc_AesCmacVerify_ex(cmac, knownCmacTag, sizeof(knownCmacTag),
                                  knownCmacMessage, sizeof(knownCmacMessage),
                                  knownCmacKey, sizeof(knownCmacKey), NULL,
                                  devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wc_AesCmacVerify_ex %d\n", ret);
        }
    }

    if (ret == 0) {
        /* test oneshot generate with pre-cached key */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), knownCmacKey,
                                 sizeof(knownCmacKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        }
        else {
            ret = wh_Client_CmacSetKeyId(cmac, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_CmacSetKeyId %d\n", ret);
            }
            else {
                macLen = sizeof(macOut);
                ret    = wc_AesCmacGenerate_ex(
                    cmac, macOut, &macLen, knownCmacMessage,
                    sizeof(knownCmacMessage), NULL, 0, NULL, devId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_AesCmacGenerate %d\n",
                                   ret);
                }
                else {
                    if (memcmp(knownCmacTag, macOut, sizeof(knownCmacTag)) !=
                        0) {
                        WH_ERROR_PRINT("CMAC FAILED KNOWN ANSWER TEST\n");
                        ret = -1;
                    }
                    else {
#ifdef WOLFHSM_CFG_DMA
                        /* DMA doesn't autoevict keys after use */
                        /* TODO: should we instead match autoevict behavior for
                         * DMA
                         */
                        if (devId == WH_DEV_ID_DMA) {
                            ret = wh_Client_KeyEvict(ctx, keyId);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to wh_Client_KeyEvict %d\n", ret);
                                ret = -1;
                            }
                        }
                        else
#endif /* WOLFHSM_CFG_DMA */
                        {
                            /* TODO: Eliminate this autoevict */
                            /* verify the key was evicted after oneshot */
                            outLen = sizeof(keyEnd);
                            ret    = wh_Client_KeyExport(ctx, keyId, labelEnd,
                                                         sizeof(labelEnd), keyEnd,
                                                         &outLen);
                            if (ret != WH_ERROR_NOTFOUND) {
                                WH_ERROR_PRINT(
                                    "Failed to not find evicted key: %d\n",
                                    ret);
                                ret = -1;
                            }
                            else {
                                ret = 0;
                            }
                        }
                    }
                }
            }
        }
    }

    if (ret == 0) {
        /* test oneshot verify with committed key */
        keyId = WH_KEYID_ERASED;
        ret = wh_Client_KeyCache(ctx, 0, labelIn, sizeof(labelIn), knownCmacKey,
                                 sizeof(knownCmacKey), &keyId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_KeyCache %d\n", ret);
        }
        else {
            ret = wh_Client_KeyCommit(ctx, keyId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wh_Client_KeyCommit %d\n", ret);
            }
            else {
                ret = wh_Client_KeyEvict(ctx, keyId);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to wh_Client_KeyEvict %d\n", ret);
                }
                else {
                    ret =
                        wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey),
                                       WC_CMAC_AES, NULL, NULL, devId);
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
                    }
                    else {
                        ret = wh_Client_CmacSetKeyId(cmac, keyId);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to wh_Client_CmacSetKeyId %d\n", ret);
                        }
                        else {
                            macLen = sizeof(macOut);
                            ret    = wc_AesCmacVerify_ex(
                                cmac, knownCmacTag, sizeof(knownCmacTag),
                                (byte*)knownCmacMessage,
                                sizeof(knownCmacMessage), NULL, 0, NULL, devId);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to wh_Client_AesCmacVerify %d\n",
                                    ret);
                            }
                            else {
                                /* test finished, erase key */
                                ret = wh_Client_KeyErase(ctx, keyId);
                                if (ret != 0) {
                                    WH_ERROR_PRINT(
                                        "Failed to wh_Client_KeyErase %d\n",
                                        ret);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

#if defined(WOLFHSM_CFG_CANCEL_API) && \
    !defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP)
    /* test CMAC cancellation for supported devIds */
    if (ret == 0
#ifdef WOLFHSM_CFG_DMA
        && devId != WH_DEV_ID_DMA
#endif
    ) {
#define WH_TEST_CMAC_TEXTSIZE 1000
        char cmacFodder[WH_TEST_CMAC_TEXTSIZE] = {0};

        ret = wh_Client_EnableCancel(ctx);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to wh_Client_EnableCancel %d\n", ret);
        }
        if (ret == 0) {
            ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey),
                                 WC_CMAC_AES, NULL, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
            }
            else {
                ret = wh_Client_CmacCancelableResponse(ctx, cmac, NULL, 0);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed to wh_Client_CmacCancelableResponse %d\n", ret);
                }
                else {

#if WOLFHSM_CFG_IS_TEST_SERVER
                    /* TODO: use hsm pause/resume functionality on real hardware
                     */
                    /* delay the server so scheduling doesn't interfere with the
                     * timing */
                    serverDelay = 1;
#endif

                    ret = wc_CmacUpdate(cmac, (byte*)cmacFodder,
                                        sizeof(cmacFodder));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
                    }
                    else {
                        ret = wh_Client_CancelRequest(ctx);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to wh_Client_CancelRequest %d\n", ret);
                        }
                        else {
#if WOLFHSM_CFG_IS_TEST_SERVER
                            serverDelay = 0;
#endif
                            do {
                                ret = wh_Client_CancelResponse(ctx);
                            } while (ret == WH_ERROR_NOTREADY);
                            if ((ret != 0) &&
                                (ret != WH_ERROR_CANCEL_LATE)) {
                                WH_ERROR_PRINT(
                                    "Failed to wh_Client_CancelResponse %d\n",
                                    ret);
                            }
                        }
                    }
                }
            }
        }
        if (ret == 0) {
            /* test cancelable request and response work for standard CMAC
                * request with no cancellation */
            ret = wc_InitCmac_ex(cmac, knownCmacKey, sizeof(knownCmacKey),
                                    WC_CMAC_AES, NULL, NULL, devId);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to wc_InitCmac_ex %d\n", ret);
            }
            else {
                ret = wh_Client_CmacCancelableResponse(ctx, cmac, NULL, 0);
                if (ret != 0) {
                    WH_ERROR_PRINT(
                        "Failed to wh_Client_CmacCancelableResponse %d\n",
                        ret);
                }
                else {
                    ret = wc_CmacUpdate(cmac, (byte*)knownCmacMessage,
                                        sizeof(knownCmacMessage));
                    if (ret != 0) {
                        WH_ERROR_PRINT("Failed to wc_CmacUpdate %d\n", ret);
                    }
                    else {
                        ret = wh_Client_CmacCancelableResponse(ctx, cmac,
                                                                NULL, 0);
                        if (ret != 0) {
                            WH_ERROR_PRINT(
                                "Failed to "
                                "wh_Client_CmacCancelableResponse %d\n",
                                ret);
                        }
                        else {
                            macLen = sizeof(knownCmacTag);
                            ret    = wc_CmacFinal(cmac, macOut, &macLen);
                            if (ret != 0) {
                                WH_ERROR_PRINT(
                                    "Failed to wc_CmacFinal %d\n", ret);
                            }
                            else {
                                ret = wh_Client_CmacCancelableResponse(
                                    ctx, cmac, macOut, &outLen);
                                if (ret != 0) {
                                    WH_ERROR_PRINT(
                                        "Failed to "
                                        "wh_Client_CmacCancelableResponse "
                                        "%d\n",
                                        ret);
                                }
                                else {
                                    if (memcmp(knownCmacTag, macOut,
                                                sizeof(knownCmacTag)) != 0) {
                                        WH_ERROR_PRINT("CMAC FAILED KNOWN "
                                                        "ANSWER TEST\n");
                                        ret = -1;
                                    }
                                    else {
                                        ret = wh_Client_DisableCancel(ctx);
                                        if (ret != 0) {
                                            WH_ERROR_PRINT(
                                                "Failed to "
                                                "wh_Client_DisableCancel "
                                                "%d\n",
                                                ret);
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
#endif /* WOLFHSM_CFG_CANCEL_API */
    if (ret == 0) {
        printf("CMAC DEVID=0x%X SUCCESS\n", devId);
    }
    return ret;
}
#endif /* WOLFSSL_CMAC && !NO_AES && WOLFSSL_AES_DIRECT */

#ifdef HAVE_DILITHIUM

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_DILITHIUM_NO_SIGN) &&   \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
static int whTestCrypto_MlDsaWolfCrypt(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    (void)ctx;

    int ret      = 0;
    int verified = 0;

    /* Test ML DSA key generation, signing and verification */
    MlDsaKey key;
    byte     msg[] = "Test message for ML DSA signing";
    byte     sig[DILITHIUM_ML_DSA_44_SIG_SIZE];
    word32   sigSz = sizeof(sig);

    /* Initialize key */
    ret = wc_MlDsaKey_Init(&key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML DSA key: %d\n", ret);
        return ret;
    }

    /* Set security level to 44-bit */
    ret = wc_MlDsaKey_SetParams(&key, WC_ML_DSA_44);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to set ML DSA params: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Generate key pair */
    ret = wc_MlDsaKey_MakeKey(&key, rng);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to generate ML DSA key: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Get the signature size */
    ret = wc_MlDsaKey_GetSigLen(&key, (int*)&sigSz);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to get ML DSA signature length: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Sign message */
    ret = wc_MlDsaKey_Sign(&key, sig, &sigSz, msg, sizeof(msg), rng);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to sign with ML DSA: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    /* Verify signature */
    ret = wc_MlDsaKey_Verify(&key, sig, sigSz, msg, sizeof(msg), &verified);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to verify ML DSA signature: %d\n", ret);
        wc_MlDsaKey_Free(&key);
        return ret;
    }

    if (!verified) {
        WH_ERROR_PRINT("ML DSA signature verification failed\n");
    }
    if (ret == 0) {
        /* Modify signature to ensure verification fails */
        sig[0] ^= 1;

        ret = wc_MlDsaKey_Verify(&key, sig, sigSz, msg, sizeof(msg), &verified);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to verify modified ML DSA signature: %d\n",
                           ret);
        }
        else if (verified) {
            WH_ERROR_PRINT("ML DSA signature verification succeeded when it"
                           " should have failed\n");
            ret = -1;
        }
        else {
            printf("ML-DSA DEVID=0x%X SUCCESS\n", devId);
        }
    }

    wc_MlDsaKey_Free(&key);

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
static int whTestCrypto_MlDsaDmaClient(whClientContext* ctx, int devId,
                                       WC_RNG* rng)
{
    (void)rng;

    int      ret = 0;
    MlDsaKey key[1];
    MlDsaKey imported_key[1];
    whKeyId  keyId       = WH_KEYID_ERASED;
    uint8_t  label[]     = "ML-DSA Test Key";
    int      keyImported = 0;

    /* Buffers for comparing serialized keys */
    byte   key_der1[DILITHIUM_MAX_PRV_KEY_SIZE];
    byte   key_der2[DILITHIUM_MAX_PRV_KEY_SIZE];
    word32 key_der1_len = sizeof(key_der1);
    word32 key_der2_len = sizeof(key_der2);

    /* Initialize keys */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }

    ret = wc_MlDsaKey_Init(imported_key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize imported ML-DSA key: %d\n", ret);
        wc_MlDsaKey_Free(key);
        return ret;
    }

    /* Generate ephemeral key using DMA */
    if (ret == 0) {
        ret = wh_Client_MlDsaMakeExportKeyDma(ctx, WC_ML_DSA_44, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to generate ML-DSA key using DMA: %d\n",
                           ret);
        }
    }

    /* Serialize the generated key for comparison */
    if (ret == 0) {
        ret = wc_Dilithium_PrivateKeyToDer(key, key_der1, key_der1_len);
        if (ret < 0) {
            WH_ERROR_PRINT("Failed to serialize generated key: %d\n", ret);
        }
        else {
            key_der1_len = ret;
            ret          = 0;
        }
    }

    /* Import the key to cache using DMA */
    if (ret == 0) {
        ret = wh_Client_MlDsaImportKeyDma(ctx, key, &keyId, WH_NVM_FLAGS_NONE,
                                          sizeof(label), label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import ML-DSA key using DMA: %d\n", ret);
        }
        keyImported = (ret == 0);
    }

    /* Export the key back using DMA */
    if (ret == 0) {
        ret = wh_Client_MlDsaExportKeyDma(ctx, keyId, imported_key,
                                          sizeof(label), label);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to export ML-DSA key using DMA: %d\n", ret);
        }
    }

    /* Serialize the exported key for comparison */
    if (ret == 0) {
        ret =
            wc_Dilithium_PrivateKeyToDer(imported_key, key_der2, key_der2_len);
        if (ret < 0) {
            WH_ERROR_PRINT("Failed to serialize exported key: %d\n", ret);
        }
        else {
            key_der2_len = ret;
            ret          = 0;
        }
    }

    /* Compare the keys */
    if (ret == 0) {
        if (key_der1_len != key_der2_len ||
            memcmp(key_der1, key_der2, key_der1_len) != 0) {
            WH_ERROR_PRINT("Exported key does not match generated key\n");
            ret = -1;
        }
    }
    /* Test signing and verification */
    if (ret == 0) {
        byte   msg[] = "Test message to sign";
        byte   sig[DILITHIUM_MAX_SIG_SIZE];
        word32 sigLen   = sizeof(sig);
        int    verified = 0;

        /* Sign the message */
        ret = wh_Client_MlDsaSignDma(ctx, msg, sizeof(msg), sig, &sigLen, key);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to sign message using ML-DSA: %d\n", ret);
        }
        else {
            /* Verify the signature - should succeed */
            ret = wh_Client_MlDsaVerifyDma(ctx, sig, sigLen, msg, sizeof(msg),
                                           &verified, key);
            if (ret != 0) {
                WH_ERROR_PRINT("Failed to verify signature using ML-DSA: %d\n",
                               ret);
            }
            else if (!verified) {
                WH_ERROR_PRINT("Signature verification failed when it should "
                               "have succeeded\n");
                ret = -1;
            }
            else {
                /* Modify signature and verify again - should fail */
                sig[0] ^= 0xFF;
                ret = wh_Client_MlDsaVerifyDma(ctx, sig, sigLen, msg,
                                               sizeof(msg), &verified, key);
                if (ret != 0) {
                    WH_ERROR_PRINT("Failed to verify modified signature using "
                                   "ML-DSA: %d\n",
                                   ret);
                }
                else if (verified) {
                    WH_ERROR_PRINT("Signature verification succeeded when it "
                                   "should have failed\n");
                    ret = -1;
                }
                else {
                    /* Test passed - verification failed as expected */
                    ret = 0;
                }
            }
        }
    }

    /* Clean up the cached key if it was imported */
    if (keyImported) {
        int evict_ret = wh_Client_KeyEvict(ctx, keyId);
        if (evict_ret != 0) {
            WH_ERROR_PRINT("Failed to evict ML-DSA key: %d\n", evict_ret);
            if (ret == 0) {
                ret = evict_ret;
            }
        }
    }


    if (ret == 0) {
        printf("ML-DSA Client DMA API SUCCESS\n");
    }

    wc_MlDsaKey_Free(key);
    wc_MlDsaKey_Free(imported_key);
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) &&   \
          !defined(WOLFSSL_DILITHIUM_NO_SIGN) &&     \
          !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) */

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && \
    defined(WOLFHSM_CFG_DMA)
int whTestCrypto_MlDsaVerifyOnlyDma(whClientContext* ctx, int devId,
                                    WC_RNG* rng)
{
    (void)rng;

    /* Vectors from wolfCrypt test vectors, but decoupled for isolated usage */
    const byte ml_dsa_44_pub_key[] = {
        0xd8, 0xac, 0xaf, 0xd8, 0x2e, 0x14, 0x23, 0x78, 0xf7, 0x0d, 0x9a, 0x04,
        0x2b, 0x92, 0x48, 0x67, 0x60, 0x55, 0x34, 0xd9, 0xac, 0x0b, 0xc4, 0x1f,
        0x46, 0xe8, 0x85, 0xb9, 0x2e, 0x1b, 0x10, 0x3a, 0x75, 0x7a, 0xc2, 0xbc,
        0x76, 0xf0, 0x6d, 0x05, 0xa4, 0x78, 0x48, 0x84, 0x26, 0x69, 0xbd, 0x26,
        0x1d, 0x73, 0x60, 0xaa, 0x57, 0x9d, 0x8c, 0x66, 0xb1, 0x19, 0xea, 0x11,
        0xff, 0xbb, 0xf6, 0xeb, 0x26, 0x26, 0xac, 0x78, 0x74, 0x46, 0x6d, 0x51,
        0x6e, 0x92, 0xdf, 0x6a, 0x98, 0x41, 0xe9, 0x10, 0xf2, 0xcc, 0xa8, 0x7a,
        0x50, 0xdb, 0x1f, 0x4c, 0x42, 0x19, 0xd5, 0xbc, 0x76, 0x20, 0x6f, 0x2f,
        0xbf, 0xc2, 0xc9, 0x1b, 0x02, 0xb5, 0xb1, 0x09, 0x46, 0x06, 0x87, 0x02,
        0xac, 0x3d, 0xcf, 0xc3, 0xa5, 0x1b, 0xf0, 0xce, 0xd4, 0x9e, 0x84, 0x34,
        0x3c, 0x24, 0x7d, 0x89, 0xf3, 0xbf, 0x9c, 0x18, 0x9d, 0x1b, 0x1d, 0xd4,
        0xf6, 0xda, 0xc9, 0xa4, 0x14, 0xc4, 0x6b, 0xd7, 0x05, 0x6d, 0xed, 0x54,
        0x42, 0x6b, 0x5f, 0x6d, 0x1e, 0xda, 0x6b, 0x47, 0x70, 0xe5, 0x4e, 0xe7,
        0x25, 0x06, 0xf8, 0x28, 0x24, 0x34, 0xd6, 0xe5, 0xbe, 0xc5, 0x4f, 0x9e,
        0x5d, 0x33, 0xfc, 0xef, 0xe4, 0xe9, 0x55, 0x67, 0x93, 0x1f, 0x2e, 0x11,
        0x3a, 0x2e, 0xf2, 0xbb, 0x82, 0x09, 0x8d, 0xb2, 0x09, 0xf3, 0x2f, 0xef,
        0x6f, 0x38, 0xc6, 0x56, 0xf2, 0x23, 0x08, 0x63, 0x99, 0x7f, 0x4e, 0xc0,
        0x9d, 0x08, 0x9d, 0xa1, 0x59, 0x6e, 0xe1, 0x00, 0x2c, 0x99, 0xec, 0x83,
        0x2f, 0x12, 0x97, 0x2f, 0x75, 0x04, 0x67, 0x44, 0xb5, 0x95, 0xce, 0xc6,
        0x3e, 0x7a, 0x10, 0x77, 0x5e, 0xbe, 0x9c, 0x0f, 0xb3, 0xc7, 0x38, 0xbf,
        0x9e, 0x35, 0x8f, 0xe4, 0x8d, 0x19, 0xc3, 0x41, 0xb1, 0x0b, 0x8c, 0x10,
        0x9a, 0x58, 0xec, 0x4f, 0xb3, 0xe9, 0x5b, 0x72, 0x4b, 0xb8, 0x99, 0x34,
        0x9a, 0xcd, 0xb0, 0x69, 0xd0, 0x67, 0xef, 0x96, 0xb9, 0xe5, 0x54, 0x92,
        0xb7, 0x1a, 0x52, 0xf6, 0x0a, 0xc2, 0x23, 0x8d, 0x4f, 0xad, 0x00, 0xae,
        0x0f, 0x97, 0xfa, 0xce, 0x96, 0xba, 0xe7, 0x74, 0x55, 0xd4, 0xaf, 0xbf,
        0xa1, 0x32, 0x91, 0x2d, 0x03, 0x9f, 0xe3, 0x10, 0x8c, 0x77, 0x5d, 0x26,
        0x76, 0xf1, 0x87, 0x90, 0xf0, 0x20, 0xd1, 0xea, 0xf7, 0xa4, 0xe8, 0x2c,
        0x32, 0x1c, 0x55, 0xc0, 0x5d, 0xc9, 0xcd, 0x4e, 0x8f, 0x0d, 0xef, 0x0a,
        0x27, 0xb6, 0x4f, 0xa4, 0xd3, 0xa4, 0xed, 0x33, 0x22, 0xa1, 0xd3, 0x15,
        0xac, 0x1a, 0x20, 0x4e, 0x28, 0x8c, 0x8c, 0xd0, 0x71, 0xd1, 0xf2, 0xdb,
        0x33, 0x63, 0xb6, 0xa4, 0xf2, 0x17, 0x3c, 0x12, 0xb0, 0xad, 0xef, 0x31,
        0x91, 0xfe, 0xe5, 0x53, 0x99, 0xb6, 0x85, 0x63, 0xfa, 0xe6, 0xcd, 0xf6,
        0xb9, 0xce, 0x4a, 0x7d, 0x4a, 0x49, 0x29, 0xd2, 0xd9, 0xc9, 0x47, 0x4a,
        0x8a, 0x5c, 0x14, 0x5e, 0x0f, 0x7c, 0xc3, 0x91, 0xb0, 0xab, 0x37, 0xf5,
        0x26, 0x8d, 0x46, 0x74, 0x49, 0xad, 0x51, 0xc3, 0x11, 0xfa, 0x85, 0x15,
        0xa5, 0x84, 0xc1, 0xe0, 0x3c, 0x13, 0x6d, 0x13, 0xa3, 0xe6, 0xa8, 0x3c,
        0x22, 0xac, 0x17, 0x48, 0x57, 0x7c, 0x81, 0xe2, 0x4e, 0xd8, 0x33, 0x5d,
        0x4d, 0x65, 0xf7, 0xe1, 0xb8, 0x00, 0x78, 0x09, 0x16, 0xb0, 0x0b, 0xca,
        0x15, 0x0d, 0xcd, 0x9a, 0xd8, 0x47, 0x4c, 0x9b, 0x69, 0xb2, 0xa0, 0x9d,
        0x96, 0x96, 0x52, 0x6d, 0x89, 0xad, 0xff, 0x55, 0xde, 0x7b, 0xd6, 0x3d,
        0x1d, 0x5e, 0x8d, 0xf1, 0xfc, 0x48, 0x1c, 0x50, 0x59, 0x55, 0xb9, 0x07,
        0xfd, 0x6b, 0xcb, 0x95, 0xa6, 0x14, 0x73, 0xdb, 0x40, 0x40, 0x1c, 0x44,
        0xe6, 0x79, 0x30, 0x88, 0xbd, 0xa0, 0xde, 0x9b, 0xb8, 0x76, 0xf8, 0x98,
        0x56, 0x4b, 0xb9, 0x7a, 0xf6, 0xd4, 0x73, 0x89, 0x6b, 0xf7, 0x7d, 0x05,
        0x33, 0xbe, 0xb6, 0x1c, 0x4d, 0xa7, 0x12, 0x3b, 0x3f, 0xed, 0x4a, 0x0f,
        0xae, 0xa7, 0x6a, 0x26, 0x0d, 0x01, 0x84, 0x84, 0xa8, 0x0e, 0xc1, 0xc1,
        0xfd, 0xe4, 0xa9, 0xe2, 0x3f, 0xab, 0xce, 0x20, 0x90, 0x86, 0x79, 0xa2,
        0x40, 0xd0, 0xef, 0x79, 0x34, 0x2b, 0xe8, 0xc9, 0x54, 0xa7, 0x19, 0x62,
        0xcc, 0x20, 0x79, 0x3f, 0x5b, 0x9c, 0x61, 0xc2, 0xc1, 0xd2, 0x36, 0x7c,
        0x8e, 0xe3, 0x01, 0xbe, 0xc4, 0xb2, 0xb8, 0x07, 0x51, 0x23, 0x5b, 0x5d,
        0x00, 0xe6, 0x7f, 0xd6, 0xbb, 0x32, 0xa9, 0x7e, 0xb4, 0x30, 0xeb, 0x5e,
        0x6d, 0xed, 0xb2, 0xc3, 0x88, 0x81, 0xa3, 0x3b, 0x1f, 0x1e, 0xf9, 0x48,
        0x10, 0xd6, 0x01, 0x65, 0x5f, 0x6d, 0xc5, 0xeb, 0x76, 0x5f, 0x10, 0x79,
        0xaa, 0xc0, 0x86, 0xe7, 0x44, 0x95, 0x44, 0x4b, 0x54, 0x0c, 0x46, 0x2a,
        0x98, 0x01, 0x6e, 0xc0, 0xb9, 0x59, 0x2a, 0xff, 0x8f, 0xb3, 0x80, 0x15,
        0xec, 0xcd, 0x39, 0x36, 0xd7, 0x2f, 0x20, 0x9e, 0x3a, 0xc1, 0x90, 0xe5,
        0x99, 0x27, 0x16, 0xd7, 0x6c, 0x30, 0x10, 0x12, 0x03, 0x3e, 0xdc, 0xb9,
        0x03, 0x25, 0xb0, 0x8a, 0x27, 0x4d, 0x1a, 0x32, 0x36, 0x54, 0xc0, 0xba,
        0x22, 0xb2, 0xe2, 0xf6, 0x39, 0x23, 0x03, 0xc4, 0xc9, 0xe4, 0x0d, 0x99,
        0xfb, 0x98, 0xa5, 0x9b, 0x12, 0x9b, 0x58, 0x44, 0x74, 0x9f, 0x65, 0x61,
        0x51, 0xba, 0x31, 0x60, 0x9c, 0xec, 0xf8, 0x4d, 0x36, 0x61, 0xd1, 0x33,
        0x6d, 0xa6, 0x28, 0x75, 0xba, 0x7c, 0x82, 0xcb, 0x7e, 0xbe, 0x8f, 0x2d,
        0x21, 0x84, 0xb9, 0xf2, 0x4e, 0x7b, 0x95, 0x99, 0x11, 0xf3, 0xe1, 0xc0,
        0x6a, 0x44, 0xae, 0x11, 0xcb, 0x04, 0xa0, 0xf2, 0x3e, 0x17, 0xdf, 0xb2,
        0x6a, 0xdf, 0x5c, 0xf3, 0x8a, 0xf8, 0x90, 0x86, 0x64, 0xea, 0x0a, 0x32,
        0x7f, 0x9f, 0x90, 0xa8, 0x9d, 0x33, 0x12, 0xa6, 0xa4, 0xe7, 0x74, 0xa0,
        0x75, 0xa9, 0x65, 0xf8, 0x39, 0xae, 0x14, 0x32, 0x79, 0xcc, 0xaa, 0x34,
        0x86, 0x55, 0xcc, 0x99, 0xb7, 0x00, 0x05, 0x8b, 0xe3, 0x76, 0x28, 0x12,
        0xb6, 0x2a, 0x3e, 0x44, 0x8d, 0xf4, 0xba, 0xef, 0xf6, 0xdc, 0x29, 0x08,
        0x29, 0x7d, 0xd1, 0x1d, 0x17, 0x15, 0xb6, 0xb6, 0x58, 0x67, 0xd5, 0xd3,
        0x12, 0x05, 0x4e, 0xb0, 0xc3, 0x83, 0xe0, 0x35, 0x30, 0x60, 0x59, 0xa0,
        0xc5, 0x97, 0x5b, 0x81, 0xd3, 0x68, 0x6c, 0x8c, 0x17, 0x28, 0xa9, 0x24,
        0x4f, 0x80, 0x20, 0xa5, 0x21, 0x9f, 0x8f, 0x15, 0x89, 0x2d, 0x87, 0xae,
        0x2e, 0xcc, 0x73, 0x3e, 0x06, 0x43, 0xbc, 0xb3, 0x1b, 0xa6, 0x72, 0xaa,
        0xa3, 0xaa, 0xbb, 0x6f, 0x2d, 0x68, 0x60, 0xcf, 0x05, 0x94, 0x25, 0x3e,
        0x59, 0xf3, 0x64, 0x61, 0x5e, 0x78, 0x9a, 0x7e, 0x0d, 0x50, 0x45, 0x78,
        0x51, 0xab, 0x11, 0xb1, 0xc6, 0x95, 0xfc, 0x29, 0x28, 0x10, 0x9c, 0x1a,
        0x8c, 0x37, 0xb5, 0x4f, 0x0e, 0xed, 0x4a, 0x28, 0x6c, 0xaa, 0xb7, 0x0d,
        0x12, 0xfa, 0x87, 0x5d, 0xd4, 0x9a, 0xb7, 0x2b, 0x46, 0x90, 0x58, 0x4e,
        0xd7, 0x8b, 0x41, 0x1b, 0xf8, 0xc4, 0xc2, 0xde, 0xda, 0xec, 0x61, 0xe7,
        0xbf, 0x11, 0xdd, 0x6e, 0x4e, 0x6a, 0xd4, 0x87, 0x01, 0xe4, 0xac, 0xe8,
        0xaf, 0x2b, 0x01, 0xe1, 0x09, 0x20, 0xe0, 0xbd, 0x7d, 0x03, 0x73, 0x23,
        0xdf, 0x77, 0x71, 0xa4, 0x25, 0x8b, 0x0a, 0x93, 0x49, 0x32, 0x45, 0x1a,
        0xa4, 0x94, 0x31, 0x61, 0x2e, 0x17, 0x39, 0x8a, 0x66, 0xc9, 0xf9, 0x20,
        0x2d, 0x6a, 0x97, 0x2f, 0xe7, 0x26, 0xd8, 0x01, 0x42, 0x65, 0xcf, 0xce,
        0xd4, 0x24, 0x41, 0xfb, 0x9b, 0x6f, 0xf1, 0xc2, 0x9e, 0xd5, 0x08, 0x0c,
        0xdc, 0x4d, 0x8e, 0xae, 0xcb, 0x5f, 0xd4, 0xcd, 0x7c, 0xf6, 0x82, 0xc6,
        0xee, 0xf9, 0x88, 0x3a, 0x34, 0x07, 0x04, 0xb4, 0x84, 0x69, 0xb3, 0xa4,
        0x67, 0xab, 0x09, 0xc0, 0x83, 0xfe, 0x59, 0xaf, 0x18, 0x2c, 0xc8, 0x09,
        0xc1, 0xbb, 0x13, 0x7c, 0xce, 0x01, 0x5d, 0x85, 0xaa, 0x10, 0x28, 0xa2,
        0x96, 0x98, 0x69, 0x23, 0xa3, 0xe7, 0x67, 0xbc, 0x7c, 0x7e, 0xde, 0x4b,
        0x36, 0xab, 0x94, 0xd2, 0xb8, 0xf9, 0xdf, 0xee, 0xa1, 0x69, 0xa1, 0xc8,
        0xe9, 0x83, 0x21, 0xac, 0x1b, 0x39, 0xf7, 0x6d, 0xbf, 0x8c, 0xdb, 0xd6,
        0x2f, 0xc9, 0x3c, 0x3d, 0x50, 0xcf, 0x7f, 0xbe, 0x4a, 0x8d, 0xd8, 0x14,
        0xad, 0x69, 0xb0, 0x3e, 0x8a, 0xaf, 0xeb, 0xd9, 0x1a, 0x15, 0x4a, 0xe4,
        0xdd, 0xd9, 0xb2, 0xf8, 0x6b, 0xe2, 0x42, 0x9e, 0x29, 0x16, 0xfc, 0x85,
        0x9c, 0x47, 0x4b, 0x1f, 0x3d, 0x7b, 0x8c, 0xe1, 0x6d, 0xa3, 0xb8, 0x0a,
        0xe6, 0xfa, 0x27, 0xfe, 0x52, 0x72, 0xab, 0x3a, 0xa6, 0x58, 0xd7, 0x53,
        0xaf, 0x9f, 0xee, 0x03, 0x85, 0xfc, 0xa4, 0x7a, 0x72, 0x29, 0x7e, 0x62,
        0x28, 0x08, 0x79, 0xa8, 0xb8, 0xc7, 0x51, 0x8d, 0xaa, 0x40, 0x2d, 0x4a,
        0xd9, 0x47, 0xb4, 0xa8, 0xa2, 0x0a, 0x43, 0xd0, 0xe0, 0x4a, 0x39, 0xa3,
        0x06, 0x08, 0x9a, 0xe2, 0xf3, 0xf2, 0xf8, 0xb9, 0x9f, 0x63, 0x32, 0xa0,
        0x65, 0x0b, 0xb0, 0x50, 0x96, 0xa6, 0xa8, 0x7a, 0x18, 0xdd, 0x6c, 0xd1,
        0x9b, 0xd9, 0x4e, 0x76, 0x8f, 0xfb, 0x22, 0xa6, 0x1d, 0x29, 0xfc, 0xb8,
        0x47, 0x29, 0xb6, 0xd1, 0xb1, 0x63, 0x4a, 0x36, 0x1b, 0x10, 0xe6, 0x4c,
        0x65, 0x68, 0x1f, 0xad, 0x4f, 0x7d, 0x6b, 0x01, 0x41, 0x18, 0x5f, 0xba,
        0x3d, 0xa6, 0x54, 0x28, 0x58, 0xd5, 0x81, 0x60, 0xdf, 0x84, 0x76, 0x00,
        0x21, 0x53, 0xeb, 0xd3, 0xa6, 0xec, 0x7d, 0x3c, 0xb8, 0xcd, 0x91, 0x4c,
        0x2f, 0x4b, 0x2e, 0x23, 0x4c, 0x0f, 0x0f, 0xe0, 0x14, 0xa5, 0xe7, 0xe5,
        0x70, 0x8d, 0x8b, 0x9c};
    const byte ml_dsa_44_sig[] = {
        0x27, 0x3b, 0x58, 0xa0, 0xcf, 0x00, 0x29, 0x5e, 0x1a, 0x63, 0xbf, 0xb4,
        0x97, 0x16, 0xa1, 0x9c, 0x78, 0xd1, 0x33, 0xdc, 0x72, 0xde, 0xa3, 0xfc,
        0xf4, 0x09, 0xb1, 0x09, 0x16, 0x3f, 0x80, 0x72, 0x22, 0x68, 0x65, 0x68,
        0xb9, 0x80, 0x5a, 0x4a, 0x0d, 0x73, 0x49, 0xe1, 0xc6, 0xde, 0xca, 0x08,
        0x4f, 0xca, 0xf8, 0xb2, 0xf8, 0x45, 0x3b, 0x6b, 0x8c, 0x6c, 0xfd, 0x3a,
        0xf4, 0xde, 0xde, 0x82, 0xd8, 0x04, 0xbe, 0x4f, 0x4a, 0xdb, 0x92, 0x47,
        0x83, 0x2d, 0xc4, 0x55, 0xed, 0x20, 0x4f, 0x71, 0xb1, 0x58, 0xd9, 0x70,
        0x73, 0xbd, 0xb0, 0x3a, 0xb4, 0x8f, 0xd6, 0x9e, 0x32, 0x98, 0x2b, 0x9e,
        0xff, 0x2a, 0x7c, 0xcb, 0x05, 0x1b, 0x8e, 0xe6, 0x3a, 0x45, 0xc6, 0x7a,
        0xc8, 0xaf, 0x62, 0xd3, 0x04, 0xfa, 0x69, 0x4f, 0xda, 0x1b, 0x74, 0x16,
        0x0d, 0xb3, 0x1a, 0xee, 0x71, 0xd7, 0xb0, 0xef, 0x69, 0xf5, 0xe2, 0xe9,
        0xc2, 0xcc, 0x15, 0x66, 0x28, 0x0a, 0xac, 0xe2, 0x63, 0x06, 0xb7, 0x21,
        0x0d, 0xd8, 0x5c, 0x94, 0x63, 0xfd, 0x51, 0x18, 0x9f, 0x07, 0x19, 0x3d,
        0xa2, 0x50, 0x40, 0xd3, 0xe9, 0x05, 0xd4, 0x11, 0x13, 0x15, 0xaa, 0x46,
        0xda, 0x3e, 0x5f, 0xcd, 0x3c, 0xfa, 0x42, 0xba, 0x79, 0x4a, 0xb7, 0x43,
        0x91, 0xa5, 0xcb, 0xbc, 0xeb, 0x37, 0x94, 0xf1, 0x9c, 0xb9, 0xdb, 0x41,
        0x06, 0xd8, 0x7b, 0x5e, 0x90, 0xe3, 0x3c, 0x8a, 0x10, 0x62, 0x9a, 0x15,
        0x27, 0x78, 0xed, 0x69, 0x11, 0x2c, 0xb5, 0xb4, 0xdb, 0xc8, 0x70, 0x50,
        0x62, 0x47, 0x96, 0xcb, 0xd9, 0xb2, 0x3e, 0x59, 0x2f, 0x1c, 0xac, 0xcb,
        0xcf, 0x22, 0xc2, 0x9b, 0xc7, 0x92, 0xe9, 0x4d, 0x8d, 0x5d, 0xcf, 0x06,
        0x53, 0x7e, 0xf4, 0x4e, 0xfe, 0x9e, 0x41, 0x5d, 0x00, 0x8c, 0x08, 0xf4,
        0x02, 0x79, 0x33, 0x1c, 0x27, 0x1d, 0xe3, 0x94, 0xac, 0xe6, 0x87, 0xa0,
        0x08, 0xb4, 0x60, 0x0c, 0xff, 0x47, 0xdc, 0x16, 0x3a, 0x1d, 0x89, 0xc0,
        0x6a, 0xa4, 0x3d, 0x71, 0x33, 0xdd, 0x1e, 0x70, 0xfe, 0xd4, 0x8b, 0xed,
        0x7c, 0x91, 0xe4, 0xe2, 0x15, 0x06, 0xc1, 0x83, 0x24, 0x55, 0xa7, 0x2a,
        0x9f, 0x4e, 0xd9, 0x56, 0x7a, 0x95, 0xa8, 0xdd, 0xc4, 0xf0, 0x71, 0x3a,
        0x99, 0x65, 0x31, 0x4b, 0xb7, 0x96, 0x2c, 0x53, 0x54, 0x83, 0xec, 0xc9,
        0x97, 0x2f, 0x0c, 0xa4, 0x8f, 0xbb, 0x93, 0x9d, 0xea, 0xae, 0xf9, 0xcb,
        0xb2, 0xb9, 0xa3, 0x61, 0x5f, 0x77, 0x8c, 0xb6, 0x5a, 0x56, 0xbe, 0x5f,
        0x85, 0xd1, 0xb5, 0x0a, 0x53, 0xe2, 0xc7, 0xbf, 0x76, 0x8b, 0x97, 0x6f,
        0x10, 0xdd, 0x1f, 0x44, 0x69, 0x66, 0x03, 0xc4, 0x6b, 0x59, 0xf7, 0xb4,
        0xc1, 0x12, 0xcc, 0x00, 0x70, 0xe8, 0xbd, 0x44, 0x28, 0xf5, 0xfa, 0x96,
        0xf3, 0x59, 0xed, 0x81, 0x67, 0xe0, 0xbe, 0x47, 0x75, 0xb3, 0xa8, 0x9f,
        0x21, 0x70, 0x2e, 0x6f, 0xef, 0x54, 0x11, 0x3f, 0x34, 0xaf, 0x0d, 0x73,
        0x5b, 0x9e, 0x6d, 0x86, 0x58, 0xb7, 0x34, 0xc2, 0xc2, 0xb3, 0x64, 0xd5,
        0x9b, 0x6e, 0xb9, 0x99, 0x6a, 0xe4, 0xfd, 0xc3, 0x17, 0xf3, 0x10, 0xfc,
        0x6e, 0xf5, 0x65, 0xe1, 0x9c, 0x59, 0x15, 0x11, 0x00, 0xea, 0x96, 0x81,
        0x69, 0x9b, 0x05, 0x4d, 0xf3, 0xce, 0xf3, 0xf0, 0xa9, 0x01, 0x3f, 0x13,
        0xbb, 0xb0, 0xac, 0xc3, 0x92, 0x1c, 0x2b, 0x61, 0xe3, 0x01, 0x22, 0x45,
        0x4a, 0x23, 0x19, 0x80, 0xca, 0xb9, 0xef, 0x4e, 0x76, 0x52, 0xc5, 0x9d,
        0x91, 0x33, 0x17, 0xc4, 0x28, 0x83, 0x55, 0x61, 0x49, 0x72, 0x04, 0xaa,
        0xf8, 0xe3, 0x4b, 0x20, 0xf7, 0x6a, 0x74, 0x56, 0x64, 0xf9, 0xb3, 0xc9,
        0x67, 0x5b, 0x55, 0x29, 0x9a, 0x89, 0xa5, 0x14, 0x67, 0xea, 0x6d, 0x6a,
        0xde, 0x98, 0x58, 0x73, 0x25, 0xa3, 0xdb, 0xed, 0x3d, 0x62, 0xaa, 0xe0,
        0x79, 0x7f, 0xa3, 0xd9, 0xb5, 0x4c, 0xe9, 0xa8, 0xdf, 0xfd, 0x59, 0x31,
        0x42, 0x81, 0x9e, 0xb7, 0x81, 0x3f, 0x0e, 0xfb, 0xef, 0x80, 0x71, 0x9d,
        0xb7, 0xa5, 0xfc, 0xb1, 0x80, 0xc9, 0x7e, 0x31, 0xd9, 0x47, 0xe2, 0xca,
        0x10, 0x7b, 0xd1, 0xa1, 0x1c, 0x28, 0xc7, 0x7f, 0x51, 0x26, 0xb1, 0x4e,
        0x57, 0xdd, 0x7d, 0x76, 0x5c, 0x5a, 0x85, 0xa7, 0x7b, 0x8c, 0xc5, 0x6e,
        0xac, 0x20, 0xf8, 0x49, 0x16, 0xd6, 0x64, 0xf5, 0xf4, 0x2c, 0x32, 0xa1,
        0x5d, 0xfb, 0x87, 0xb6, 0x14, 0xfe, 0x68, 0x7c, 0x4d, 0xce, 0xd7, 0x94,
        0xf9, 0x8b, 0xf0, 0x61, 0xfd, 0xe0, 0x83, 0x7f, 0x13, 0xec, 0x7a, 0xb7,
        0x41, 0x04, 0x51, 0x6e, 0x30, 0xa2, 0x01, 0xf7, 0x30, 0x12, 0xec, 0xd2,
        0x8f, 0x73, 0xe7, 0x8e, 0x12, 0xb4, 0xe5, 0xc1, 0xff, 0xdf, 0x67, 0x14,
        0xb1, 0xe9, 0xba, 0x36, 0x19, 0x18, 0xf4, 0xaa, 0xe0, 0xe4, 0x9d, 0xcd,
        0xe8, 0xe7, 0x2b, 0x33, 0xb3, 0xdc, 0xb9, 0x19, 0xd7, 0xad, 0xa4, 0x68,
        0xcd, 0x83, 0x77, 0x98, 0x36, 0x49, 0xd9, 0x32, 0x20, 0xfd, 0xfc, 0x34,
        0xe7, 0x54, 0xd9, 0xb5, 0x05, 0xab, 0x0e, 0x08, 0x0e, 0x16, 0x8a, 0x7d,
        0x91, 0x4c, 0xaa, 0x19, 0x04, 0x37, 0x35, 0xa5, 0xab, 0x6c, 0xee, 0xc4,
        0x90, 0xf0, 0x5f, 0xc7, 0xae, 0x82, 0xfd, 0x59, 0x53, 0xe5, 0x36, 0x5a,
        0x56, 0x37, 0x61, 0x69, 0xda, 0xe5, 0x8f, 0xfd, 0x2e, 0xd4, 0x9c, 0x7f,
        0xb6, 0x39, 0xa4, 0x8d, 0x0a, 0xab, 0x82, 0x0f, 0xfe, 0x84, 0x69, 0x44,
        0x8a, 0xa6, 0xd0, 0x39, 0xf9, 0x72, 0x68, 0xe7, 0x97, 0xd8, 0x6c, 0x7b,
        0xec, 0x85, 0x8c, 0x52, 0xc9, 0x97, 0xbb, 0xc4, 0x7a, 0x67, 0x22, 0x60,
        0x46, 0x9f, 0x16, 0xf1, 0x67, 0x0e, 0x1b, 0x50, 0x7c, 0xc4, 0x29, 0x15,
        0xbc, 0x55, 0x6a, 0x67, 0xf6, 0xa8, 0x85, 0x66, 0x89, 0x9f, 0xff, 0x38,
        0x28, 0xaa, 0x87, 0x91, 0xce, 0xde, 0x8d, 0x45, 0x5c, 0xa1, 0x25, 0x95,
        0xe2, 0x86, 0xdd, 0xa1, 0x87, 0x6a, 0x0a, 0xa8, 0x3e, 0x63, 0x0e, 0x21,
        0xa5, 0x6e, 0x08, 0x4d, 0x07, 0xb6, 0x26, 0xa8, 0x92, 0xdb, 0xed, 0x13,
        0x01, 0xc3, 0xba, 0xcf, 0xad, 0x01, 0xbc, 0xe5, 0xc0, 0xba, 0xbe, 0x7c,
        0x75, 0xf1, 0xb9, 0xfe, 0xd3, 0xf0, 0xa5, 0x2c, 0x8e, 0x10, 0xff, 0x99,
        0xcb, 0xe2, 0x2d, 0xdc, 0x2f, 0x76, 0x00, 0xf8, 0x51, 0x7c, 0xcc, 0x52,
        0x16, 0x0f, 0x18, 0x98, 0xea, 0x34, 0x06, 0x7f, 0xb7, 0x2e, 0xe9, 0x40,
        0xf0, 0x2d, 0x30, 0x3d, 0xc0, 0x67, 0x4c, 0xe6, 0x63, 0x40, 0x41, 0x42,
        0x96, 0xbb, 0x0b, 0xd6, 0xc9, 0x1c, 0x22, 0x7a, 0xa9, 0x4d, 0xcc, 0x5b,
        0xaa, 0x03, 0xc6, 0x3b, 0x1e, 0x2f, 0x11, 0xae, 0x34, 0x6f, 0x0c, 0xe9,
        0x16, 0x9c, 0x82, 0x3b, 0x90, 0x4c, 0x0e, 0xf0, 0xf9, 0x7f, 0x02, 0xca,
        0xb9, 0xa9, 0x49, 0x6d, 0x27, 0x73, 0xd0, 0xbf, 0x15, 0x61, 0x52, 0xbc,
        0xd6, 0x31, 0x59, 0x2b, 0x52, 0x5b, 0xaf, 0x3c, 0xc0, 0x8f, 0xdc, 0xd5,
        0x2c, 0x1d, 0xe4, 0xe9, 0x41, 0xe8, 0xd3, 0x35, 0xd6, 0xb1, 0xf3, 0x32,
        0xe0, 0x52, 0x08, 0x73, 0x99, 0xb6, 0x6b, 0xbc, 0x26, 0xfb, 0x2e, 0xa7,
        0xb7, 0xcd, 0x14, 0xf0, 0xf9, 0xe5, 0x3a, 0xd0, 0x05, 0x5b, 0x2b, 0x38,
        0xbd, 0x7c, 0xda, 0xd4, 0x15, 0x45, 0xfa, 0x3b, 0x6f, 0x94, 0x8e, 0x22,
        0xce, 0xfa, 0x53, 0xe0, 0x5f, 0xa6, 0x9d, 0x1c, 0x26, 0x91, 0x8a, 0xab,
        0x72, 0x5b, 0x18, 0x78, 0x69, 0x98, 0x3f, 0x8d, 0x33, 0x7c, 0x21, 0x93,
        0x9e, 0xf0, 0xaf, 0xb7, 0x30, 0xc8, 0xac, 0xbc, 0xdb, 0x9c, 0x29, 0x17,
        0x6b, 0x9d, 0x0f, 0x16, 0xd6, 0xc0, 0xcc, 0x3b, 0xce, 0x11, 0xe9, 0x64,
        0xc8, 0xd4, 0x4c, 0x98, 0x7c, 0x8f, 0xf1, 0x5e, 0x84, 0xe4, 0x72, 0xf9,
        0x69, 0xf5, 0x9d, 0xad, 0x95, 0x3b, 0xfb, 0x6d, 0x30, 0x7e, 0x0a, 0x47,
        0x5b, 0x26, 0xb2, 0x4e, 0xeb, 0x1a, 0xc3, 0x37, 0x16, 0x28, 0x79, 0x62,
        0xb4, 0x36, 0x85, 0x4a, 0x15, 0x5a, 0xc3, 0x6e, 0xbe, 0x7e, 0x00, 0xe9,
        0x4a, 0xa5, 0xd7, 0x90, 0xcf, 0x59, 0x63, 0x2d, 0x2b, 0xc2, 0xc6, 0x47,
        0xe6, 0x77, 0xb7, 0x6e, 0x9b, 0xc8, 0x0d, 0x18, 0x2b, 0x45, 0x2b, 0xc9,
        0x5a, 0x6e, 0xb4, 0x50, 0xa5, 0x23, 0x7d, 0x17, 0xcc, 0x49, 0xe2, 0xb3,
        0xf4, 0x6d, 0xb4, 0xb7, 0xbb, 0x9e, 0xdd, 0x20, 0x99, 0x19, 0xf5, 0x53,
        0x1f, 0xd0, 0xff, 0x67, 0xf3, 0x8e, 0x6a, 0xcd, 0x2a, 0x6e, 0x2b, 0x0a,
        0x90, 0xd7, 0xdb, 0xe1, 0xff, 0x1c, 0x40, 0xa1, 0xb0, 0x5d, 0x94, 0x4d,
        0x20, 0x14, 0x01, 0xa1, 0xa8, 0xd1, 0x15, 0xd2, 0xd9, 0x1b, 0xbf, 0xc2,
        0x8a, 0xd0, 0x02, 0xf6, 0x16, 0xa1, 0xb7, 0x40, 0xe0, 0x36, 0x88, 0xc8,
        0x17, 0x0a, 0xf0, 0xb6, 0x0d, 0x3c, 0x53, 0xb9, 0x51, 0xed, 0xef, 0x20,
        0x6f, 0xf3, 0x0c, 0xb5, 0xce, 0x0e, 0x9e, 0xfd, 0x0f, 0x5e, 0x3f, 0x8f,
        0x3c, 0xb7, 0x2a, 0xdb, 0xc6, 0xa7, 0xf2, 0x11, 0x6e, 0xdc, 0x05, 0x33,
        0xd4, 0xd8, 0xb0, 0x2d, 0x8a, 0xe5, 0x39, 0x82, 0x00, 0x49, 0x7d, 0xfd,
        0x32, 0x29, 0xbb, 0x79, 0x5d, 0xcb, 0x21, 0x7b, 0x2d, 0x36, 0x58, 0x73,
        0x52, 0x57, 0x52, 0x96, 0x4d, 0x89, 0x61, 0xf4, 0xad, 0x1f, 0x48, 0xd5,
        0x7a, 0x4a, 0xaa, 0x1c, 0xa1, 0xf4, 0xb4, 0x9c, 0x43, 0x3b, 0x95, 0x72,
        0xd0, 0x0e, 0x35, 0x82, 0x26, 0xd4, 0x2e, 0xe3, 0x83, 0x96, 0x97, 0x5a,
        0x7b, 0xfc, 0x48, 0x17, 0x3c, 0xba, 0x9e, 0x5f, 0x46, 0x1a, 0x53, 0xe3,
        0x2e, 0x78, 0x79, 0x80, 0xf6, 0x2d, 0x24, 0xcf, 0x62, 0xb6, 0x86, 0xeb,
        0xee, 0xec, 0xf2, 0x1d, 0x00, 0xc8, 0x28, 0x9d, 0x93, 0x16, 0xa7, 0xd9,
        0x11, 0x47, 0xe3, 0xc4, 0xb6, 0xc4, 0xa0, 0x99, 0x83, 0xc1, 0x17, 0xd8,
        0x8e, 0xde, 0x69, 0x1d, 0xcb, 0xdd, 0xe7, 0x86, 0x6f, 0xf2, 0x36, 0x07,
        0x23, 0x86, 0x0d, 0xe9, 0xad, 0x87, 0xae, 0x76, 0x98, 0x95, 0x51, 0xf2,
        0xb3, 0x11, 0xc5, 0x34, 0xf0, 0x0c, 0xf8, 0x29, 0x9c, 0x84, 0x4f, 0x81,
        0x49, 0x85, 0x63, 0x25, 0x16, 0xb0, 0xc3, 0xaa, 0xd7, 0x8a, 0x2e, 0x4b,
        0x97, 0x60, 0x74, 0xf8, 0xa7, 0x39, 0xec, 0x6c, 0x2c, 0x9b, 0x33, 0x3a,
        0x11, 0xbd, 0xa6, 0x90, 0x48, 0x65, 0xb1, 0xe7, 0x38, 0x53, 0x47, 0x1b,
        0x62, 0xd5, 0xb7, 0xa8, 0xd4, 0xae, 0xf5, 0x12, 0x06, 0x12, 0x54, 0xa2,
        0xce, 0xf1, 0x6b, 0x3a, 0xda, 0x63, 0x2e, 0x37, 0x2a, 0x25, 0x89, 0x30,
        0x98, 0x77, 0x1d, 0x4b, 0x5a, 0x1e, 0xb7, 0x3d, 0xed, 0x19, 0xec, 0x9f,
        0x64, 0x46, 0xa8, 0x2a, 0x79, 0xf3, 0x70, 0x39, 0x9f, 0x8c, 0xc3, 0x28,
        0xcc, 0x2a, 0xc0, 0xd0, 0xe6, 0x80, 0xf5, 0x01, 0x78, 0x72, 0x7f, 0xe7,
        0x2e, 0x7b, 0x5f, 0x05, 0xc3, 0x41, 0x33, 0x07, 0xdb, 0x9c, 0xa8, 0x96,
        0xa7, 0x21, 0x20, 0x23, 0xd0, 0x59, 0x39, 0x06, 0x19, 0xa4, 0x29, 0xe5,
        0x72, 0x39, 0x69, 0x23, 0xe3, 0xfa, 0x28, 0x63, 0xf5, 0x42, 0x3b, 0xca,
        0x88, 0x5d, 0x7e, 0x47, 0x93, 0xa8, 0x8c, 0x75, 0xf2, 0x19, 0x44, 0x43,
        0x15, 0x39, 0x03, 0x42, 0xd8, 0x1d, 0x81, 0x30, 0x8e, 0x84, 0x31, 0x24,
        0x75, 0x67, 0x4e, 0xbe, 0xfe, 0x0a, 0xd8, 0xc3, 0xe7, 0x5b, 0xe1, 0xd5,
        0x12, 0x6a, 0x69, 0x99, 0xcd, 0x35, 0xca, 0x22, 0x02, 0x65, 0xb3, 0x0f,
        0x50, 0xb6, 0xaa, 0xc6, 0x91, 0x5c, 0x4d, 0xd4, 0x07, 0x93, 0x46, 0xf0,
        0xcc, 0xe1, 0x92, 0x14, 0x91, 0x21, 0x43, 0xc4, 0xba, 0x45, 0x1c, 0x47,
        0x29, 0xdf, 0xff, 0x89, 0x60, 0xee, 0x89, 0x1e, 0xc3, 0xb4, 0xb9, 0x0b,
        0xc9, 0x7e, 0xd9, 0x15, 0xb0, 0x80, 0x91, 0xbe, 0xb9, 0x43, 0x48, 0x12,
        0x86, 0x8e, 0x79, 0x38, 0x4d, 0xce, 0x36, 0x7f, 0xc3, 0xe8, 0xb7, 0xb9,
        0x92, 0xbf, 0x27, 0x20, 0x54, 0xc8, 0x05, 0x63, 0x3b, 0xf5, 0x48, 0x1a,
        0xa9, 0x04, 0x6c, 0xb6, 0x0e, 0x11, 0xea, 0xf3, 0x59, 0xb9, 0xa6, 0xf6,
        0xf8, 0x0b, 0x15, 0xed, 0x30, 0xf9, 0xe4, 0xe5, 0x26, 0x2d, 0xbb, 0xc6,
        0x5b, 0x36, 0xbb, 0x73, 0xa6, 0x4f, 0xf5, 0x43, 0x9f, 0xd7, 0xb9, 0x0f,
        0xbc, 0x4f, 0x8d, 0xb8, 0xec, 0x1d, 0x42, 0x19, 0x56, 0x37, 0xc4, 0xcb,
        0xd0, 0x16, 0x85, 0xff, 0xd3, 0x9b, 0xef, 0xc8, 0x75, 0x37, 0xd1, 0x92,
        0xad, 0x21, 0x94, 0x1e, 0x9a, 0xf6, 0x2f, 0x6d, 0x30, 0xba, 0x37, 0xc3,
        0xdc, 0x11, 0xe0, 0x79, 0xa4, 0x92, 0x1f, 0xe4, 0xaa, 0x7a, 0x6b, 0x2a,
        0xe4, 0x04, 0xb7, 0xf9, 0x86, 0x95, 0xdb, 0xa8, 0xfc, 0x8a, 0x53, 0x21,
        0x31, 0x14, 0xf7, 0x40, 0x01, 0x78, 0x4e, 0x73, 0x18, 0xb3, 0x54, 0xd7,
        0xa6, 0x93, 0xf0, 0x70, 0x04, 0x1c, 0xe0, 0x2b, 0xef, 0xee, 0xd4, 0x64,
        0xa7, 0xd9, 0x9f, 0x81, 0x4f, 0xe5, 0x1e, 0xbe, 0x6e, 0xd2, 0xf6, 0x3a,
        0xba, 0xcf, 0x8c, 0x96, 0x2a, 0x3d, 0xf7, 0xe5, 0x5c, 0x59, 0x40, 0x9c,
        0xe3, 0xf9, 0x2b, 0x6d, 0x3d, 0xf2, 0x6f, 0x81, 0xd6, 0xab, 0x9c, 0xab,
        0xc6, 0xf7, 0x8f, 0xaa, 0xe5, 0x71, 0xe3, 0xc9, 0x8c, 0x1a, 0xeb, 0xc5,
        0x87, 0xe7, 0xb0, 0xde, 0x18, 0xba, 0xaa, 0x1e, 0xda, 0x12, 0x32, 0x16,
        0x94, 0x3a, 0x6e, 0x4f, 0x84, 0x06, 0x8e, 0x33, 0xf7, 0xfa, 0x35, 0xb8,
        0x45, 0xe4, 0x5e, 0x9e, 0x46, 0x05, 0x7a, 0xf7, 0xf4, 0x99, 0xad, 0xb9,
        0xdd, 0x55, 0xd9, 0x52, 0x3b, 0x93, 0xe3, 0x9b, 0x54, 0x1b, 0xe6, 0xa9,
        0x70, 0xd3, 0x48, 0xf9, 0x3d, 0xdb, 0x88, 0x63, 0x66, 0xa0, 0xab, 0x72,
        0x83, 0x6e, 0x8f, 0x78, 0x9d, 0x55, 0x46, 0x21, 0xca, 0x7c, 0xb7, 0x5d,
        0x16, 0xe8, 0x66, 0x3b, 0x7b, 0xaa, 0xfe, 0x9c, 0x9c, 0x33, 0xc9, 0xc2,
        0xa4, 0x3c, 0x78, 0x97, 0xf3, 0x5b, 0xc2, 0x29, 0x36, 0x98, 0x68, 0x28,
        0xfe, 0x0a, 0xae, 0x6f, 0xe5, 0xf7, 0xfb, 0x9d, 0xf8, 0x8c, 0xd9, 0xd0,
        0x4d, 0xfe, 0xc7, 0xd0, 0xb0, 0xe3, 0x9c, 0xdb, 0xac, 0x9e, 0x1b, 0x55,
        0x7e, 0x24, 0xfe, 0xc4, 0x12, 0xcb, 0xc2, 0xdd, 0x0a, 0xda, 0x31, 0x40,
        0x41, 0xb7, 0xfc, 0x3f, 0x6d, 0xe2, 0xd3, 0x8a, 0x0f, 0x21, 0x33, 0x3a,
        0xbc, 0xa7, 0x62, 0x18, 0xb3, 0xaf, 0x48, 0xc6, 0xe2, 0xa3, 0xdd, 0x1d,
        0x20, 0x62, 0xe4, 0x4b, 0x81, 0x6b, 0x3a, 0xc5, 0xb1, 0x07, 0xe1, 0xf1,
        0xe1, 0xba, 0xf6, 0x01, 0xc6, 0xf2, 0xea, 0xc0, 0x97, 0x73, 0x79, 0x19,
        0x06, 0xaa, 0x62, 0x42, 0xcb, 0x21, 0x5f, 0x08, 0x97, 0x7d, 0x72, 0xb5,
        0x39, 0x4d, 0x99, 0xe3, 0xa2, 0x3f, 0xb9, 0xb4, 0xed, 0xf4, 0x61, 0x35,
        0xe1, 0x50, 0xfb, 0x56, 0x7c, 0x35, 0xfd, 0x44, 0x8a, 0x57, 0x22, 0xed,
        0x30, 0x33, 0xc3, 0x0b, 0xf1, 0x88, 0xe4, 0x44, 0x46, 0xf5, 0x73, 0x6d,
        0x9b, 0x98, 0x88, 0x92, 0xf5, 0x34, 0x85, 0x18, 0x66, 0xef, 0x70, 0xbe,
        0x7b, 0xc1, 0x0f, 0x1c, 0x78, 0x2d, 0x42, 0x13, 0x2d, 0x2f, 0x4d, 0x40,
        0x8e, 0xe2, 0x6f, 0xe0, 0x04, 0xdb, 0x58, 0xbc, 0x65, 0x80, 0xba, 0xfc,
        0x89, 0xee, 0xf3, 0x78, 0xb2, 0xd9, 0x78, 0x93, 0x6d, 0xbf, 0xd4, 0x74,
        0x24, 0xf4, 0x5c, 0x37, 0x89, 0x0c, 0x14, 0xd5, 0xbd, 0xc5, 0xfc, 0x37,
        0xe8, 0x8b, 0xe0, 0xc5, 0x89, 0xc9, 0x70, 0xb3, 0x76, 0x46, 0xce, 0x0d,
        0x7c, 0x3d, 0xa4, 0x5d, 0x02, 0x95, 0x03, 0xba, 0x24, 0xaa, 0xf7, 0xd0,
        0x75, 0x35, 0x78, 0x27, 0x9c, 0x6d, 0x2a, 0xef, 0xaa, 0xac, 0x85, 0xef,
        0x8d, 0xfc, 0xc0, 0xfc, 0x72, 0x02, 0xf4, 0xa3, 0xd3, 0x87, 0xfc, 0x4d,
        0xce, 0x3d, 0xcb, 0xc2, 0x74, 0x5b, 0xb0, 0x83, 0xc5, 0x72, 0x72, 0xd6,
        0xa1, 0x67, 0x4d, 0xa1, 0xd6, 0xaa, 0xe7, 0x9b, 0xe7, 0xc0, 0xfd, 0x86,
        0x91, 0x08, 0xfa, 0x48, 0x2f, 0x50, 0xce, 0x17, 0xea, 0x1c, 0xe3, 0x90,
        0x35, 0xe6, 0x6c, 0xc9, 0x66, 0x7d, 0x51, 0x32, 0x20, 0x0c, 0x2d, 0x4b,
        0xa1, 0xbf, 0x78, 0x87, 0xe1, 0x5a, 0x28, 0x0e, 0x9a, 0x85, 0xf6, 0x7e,
        0x39, 0x60, 0xbc, 0x64, 0x42, 0x5d, 0xf0, 0x0a, 0xd7, 0x3e, 0xbb, 0xa0,
        0x6d, 0x7c, 0xfa, 0x75, 0xee, 0x34, 0x39, 0x23, 0x0e, 0xbd, 0x50, 0x19,
        0x7a, 0x2a, 0xb7, 0x17, 0x3a, 0x8b, 0xb7, 0xb6, 0xf4, 0xd8, 0x47, 0x71,
        0x6b, 0x21, 0x1b, 0x56, 0xcc, 0xfb, 0x7b, 0x81, 0x99, 0x46, 0x88, 0x23,
        0x40, 0x49, 0x66, 0x8b, 0xac, 0x84, 0x16, 0x8a, 0x86, 0xae, 0x38, 0xc4,
        0x5b, 0x1f, 0x2b, 0xfa, 0xf2, 0x8b, 0x81, 0xc1, 0x22, 0x61, 0x61, 0x6c,
        0x43, 0x16, 0x8c, 0x1d, 0x37, 0xb2, 0xaf, 0x3c, 0x3a, 0x90, 0x33, 0xed,
        0xf5, 0x08, 0x78, 0xfd, 0x5a, 0xde, 0xd3, 0x38, 0x6d, 0xd7, 0x1c, 0x23,
        0xeb, 0xb4, 0x9b, 0x8e, 0xc2, 0x48, 0x47, 0x8e, 0x84, 0xbb, 0xc4, 0xd0,
        0xcc, 0xf9, 0x55, 0x5a, 0x57, 0xb9, 0x99, 0x52, 0x82, 0x21, 0x3b, 0x83,
        0xda, 0x8f, 0xa3, 0x88, 0x9c, 0x57, 0xe0, 0x4b, 0xc1, 0xce, 0xbe, 0xd3,
        0xea, 0xdd, 0xf2, 0x07, 0xc1, 0x73, 0x6f, 0xc0, 0x5e, 0x8e, 0x85, 0x72,
        0xab, 0x2f, 0xa9, 0xac, 0x39, 0xee, 0x05, 0x34, 0x13, 0x16, 0x1b, 0x1c,
        0x21, 0x24, 0x41, 0x49, 0x78, 0x87, 0x8b, 0x97, 0x9c, 0x9f, 0xa3, 0xa8,
        0xb9, 0xbc, 0xc6, 0xcc, 0xf2, 0xfd, 0x18, 0x2a, 0x46, 0x58, 0x5a, 0x88,
        0xa2, 0xb5, 0xcc, 0xd2, 0xda, 0xe1, 0xe3, 0x0d, 0x20, 0x23, 0x2b, 0x2f,
        0x47, 0x57, 0x5e, 0x64, 0x87, 0x97, 0x9c, 0xa7, 0xaa, 0xbc, 0xc1, 0xe4,
        0xe5, 0xea, 0x0b, 0x16, 0x3b, 0x3c, 0x3e, 0x45, 0x58, 0x63, 0x6a, 0x6f,
        0x7c, 0x8c, 0x8d, 0x92, 0x99, 0x9c, 0xad, 0xb5, 0xb7, 0xce, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x16, 0x23, 0x36, 0x4a};
    static byte test_msg[512] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
        0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
        0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
        0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
        0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
        0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
        0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3,
        0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
        0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
        0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
        0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    int      ret;
    MlDsaKey key[1];
    whNvmId  keyId    = WH_KEYID_ERASED;
    int      evictKey = 0;

    /* Initialize keys */
    ret = wc_MlDsaKey_Init(key, NULL, devId);
    if (ret != 0) {
        WH_ERROR_PRINT("Failed to initialize ML-DSA key: %d\n", ret);
        return ret;
    }
    else {
        ret = wc_dilithium_set_level(key, WC_ML_DSA_44);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to set ML-DSA level: %d\n", ret);
        }
    }

    /* make dummy msg */
    int i = 0;
    for (i = 0; i < (int)sizeof(test_msg); i++) {
        test_msg[i] = (byte)i;
    }

    /* Import the raw public key into the wolfCrypt structure */
    if (ret == 0) {
        ret = wc_MlDsaKey_ImportPubRaw(key, ml_dsa_44_pub_key,
                                       sizeof(ml_dsa_44_pub_key));
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to import ML-DSA public key: %d\n", ret);
        }
    }
    /* Import the key into wolfHSM via the wolfCrypt structure */
    if (ret == 0) {
        if (devId == WH_DEV_ID_DMA) {
            ret = wh_Client_MlDsaImportKeyDma(ctx, key, &keyId, 0, 0, NULL);
        }
        else {
            ret = wh_Client_MlDsaImportKey(ctx, key, &keyId, 0, 0, NULL);
        }
        if (ret == WH_ERROR_OK) {
            evictKey = 1;
        }
        else {
            WH_ERROR_PRINT("Failed to import ML-DSA key: %d\n", ret);
        }
    }

    /* Cache the key using DMA and set the key ID */
    if (ret == 0) {
        ret = wh_Client_MlDsaSetKeyId(key, keyId);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Failed to set key ID: %d\n", ret);
        }
    }

    /* Verify the message signature */
    if (ret == 0) {
        int verifyResult;
        ret = wc_MlDsaKey_Verify(key, ml_dsa_44_sig, sizeof(ml_dsa_44_sig),
                                 test_msg, sizeof(test_msg), &verifyResult);
        if (ret != 0) {
            WH_ERROR_PRINT("Signature did not verify\n");
        }
    }

    if (evictKey) {
        if (WH_ERROR_OK != wh_Client_KeyEvict(ctx, keyId)) {
            WH_ERROR_PRINT("Failed to evict key\n");
        }
    }
    wc_MlDsaKey_Free(key);

    if (ret == WH_ERROR_OK) {
        printf("ML-DSA VERIFY ONLY: SUCCESS\n");
    }

    return ret;
}
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) && \
          defined(WOLFHSM_CFG_DMA) */


#endif /* HAVE_DILITHIUM */


int whTest_CryptoClientConfig(whClientConfig* config)
{
    int i;
    int rngInited = 0;
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
        (void)whTest_ShowNvmAvailable(client);
    }
#endif /* WOLFHSM_CFG_TEST_VERBOSE */

    /* First crypto test should be of RNG so we can iterate over and test all
     * devIds before choosing one to run the rest of the tests on */
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoRng(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            wc_FreeRng(rng);
            i++;
        }
    }

    /* Now that we have tested all RNG devIds, reinitialize the default RNG
     * devId (non-DMA) that will be used by the remainder of the tests for
     * random input generation */
    if (ret == 0) {
        ret = wc_InitRng_ex(rng, NULL, WH_DEV_ID);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to reinitialize RNG %d\n", ret);
        }
        else {
            rngInited = 1;
        }
    }

    if (ret == 0) {
        /* Test Key Cache functions */
        ret = whTest_KeyCache(client, WH_DEV_ID, rng);
    }

    if (ret == 0) {
        /* Test Non-Exportable Flag enforcement on keystore */
        ret = whTest_NonExportableKeystore(client, WH_DEV_ID, rng);
    }

#ifdef WOLFHSM_CFG_KEYWRAP
    if (ret == 0) {
        /* Test keywrap functionality */
        ret = whTest_Client_KeyWrap(client);
    }
#endif

#ifndef NO_AES
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTestCrypto_Aes(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* !NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTestCrypto_Cmac(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
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
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha256(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha224(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha384(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
    i = 0;
    while ((ret == WH_ERROR_OK) && (i < WH_NUM_DEVIDS)) {
        ret = whTest_CryptoSha512(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }
#endif /* WOLFSSL_SHA512 */

#ifdef HAVE_HKDF
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoHkdf(client, WH_DEV_ID, rng);
    }
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
    if (ret == WH_ERROR_OK) {
        ret = whTest_CryptoCmacKdf(client, WH_DEV_ID, rng);
    }
#endif /* HAVE_CMAC_KDF */

#ifdef HAVE_DILITHIUM

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
    !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_NO_ML_DSA_44)

    i = 0;
    while (ret == WH_ERROR_OK && i < WH_NUM_DEVIDS) {
#ifdef WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY
        if (WH_DEV_IDS_ARRAY[i] != WH_DEV_ID_DMA) {
            i++;
            continue;
        }
#endif /* WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY */
        ret = whTestCrypto_MlDsaWolfCrypt(client, WH_DEV_IDS_ARRAY[i], rng);
        if (ret == WH_ERROR_OK) {
            i++;
        }
    }

#ifdef WOLFHSM_CFG_DMA
    if (ret == 0) {
        ret = whTestCrypto_MlDsaDmaClient(client, WH_DEV_ID_DMA, rng);
    }
#endif /* WOLFHSM_CFG_DMA*/
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
          !defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
          !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) */

#if !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && \
    defined(WOLFHSM_CFG_DMA)
    if (ret == 0) {
        ret = whTestCrypto_MlDsaVerifyOnlyDma(client, WH_DEV_ID_DMA, rng);
    }
#endif /* !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
          !defined(WOLFSSL_NO_ML_DSA_44) && \
          defined(WOLFHSM_CFG_DMA) */

#endif /* HAVE_DILITHIUM */

#ifdef WOLFHSM_CFG_TEST_VERBOSE
    if (ret == 0) {
        (void)whTest_ShowNvmAvailable(client);
    }
#endif /* WOLFHSM_CFG_TEST_VERBOSE */

    /* Clean up used resources */
    if (rngInited) {
        (void)wc_FreeRng(rng);
    }
    (void)wh_Client_CommClose(client);
    (void)wh_Client_Cleanup(client);

    return ret;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#ifndef NO_WOLFHSM_CFG_TEST_CRYPTSVR_CFG
int whTest_CryptoServerConfig(whServerConfig* config)
{
    whServerContext server[1] = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int ret = 0;
#ifdef WOLFHSM_CFG_IS_TEST_SERVER
    int userChange = 0;
#endif

    if (config == NULL) {
        return WH_ERROR_BADARGS;
    }

#if defined(WOLFHSM_CFG_IS_TEST_SERVER) && defined(WOLFHSM_CFG_TEST_POSIX) && \
    defined(WOLFHSM_CFG_CANCEL_API)
    /* expose server ctx to client cancel callback */
    cancelSeqP = &server->cancelSeq;
#endif

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, config));
    WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
    server->comm->client_id = WH_TEST_DEFAULT_CLIENT_ID;

    while(am_connected == WH_COMM_CONNECTED) {
#ifdef WOLFHSM_CFG_IS_TEST_SERVER
        while (serverDelay == 1) {
#ifdef WOLFHSM_CFG_TEST_POSIX
            sleep(1);
#endif
        }
#endif
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) &&
                (ret != WH_ERROR_OK)) {
            WH_ERROR_PRINT("Failed to wh_Server_HandleRequestMessage: %d\n",
                           ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);

#ifdef WOLFHSM_CFG_IS_TEST_SERVER
        /* keep alive for 2 user changes */
        if (am_connected != WH_COMM_CONNECTED && userChange < 2) {
            if (userChange == 0)
                server->comm->client_id = ALT_CLIENT_ID;
            else if (userChange == 1)
                server->comm->client_id = WH_TEST_DEFAULT_CLIENT_ID;
            userChange++;
            am_connected = WH_COMM_CONNECTED;
            WH_TEST_RETURN_ON_FAIL(wh_Server_SetConnected(server, am_connected));
        }
#endif /* WOLFHSM_CFG_IS_TEST_SERVER */
    }

    if ((ret == 0) || (ret == WH_ERROR_NOTREADY)) {
        WH_TEST_RETURN_ON_FAIL(wh_Server_Cleanup(server));
    } else {
        ret = wh_Server_Cleanup(server);
    }

    return ret;
}
#endif /* NO_WOLFHSM_CFG_TEST_CRYPTSVR_CFG */
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    !defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP)
static void* _whClientTask(void *cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoClientConfig(cf));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_SERVER)
static void* _whServerTask(void* cf)
{
    WH_TEST_ASSERT(0 == whTest_CryptoServerConfig(cf));
    return NULL;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)

#if defined(WOLFHSM_CFG_IS_TEST_SERVER) && defined(WOLFHSM_CFG_CANCEL_API)
/* Test client cancel callback that directly sets the sequence to cancel in the
 * server context */
static int _cancelCb(uint16_t seq)
{
    *cancelSeqP = seq;
    return 0;
}
#endif

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


static int wh_ClientServer_MemThreadTest(whTestNvmBackendType nvmType)
{
    int     ret               = 0;
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
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};

#ifdef WOLFHSM_CFG_DMA
    whClientDmaConfig clientDmaConfig = {0};
#endif
    whClientConfig c_conf[1] = {{
        .comm = cc_conf,
#ifdef WOLFHSM_CFG_DMA
        .dmaConfig = &clientDmaConfig,
#endif
#ifdef WOLFHSM_CFG_CANCEL_API
        .cancelCb = _cancelCb,
#endif
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
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1] = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE, /* 1MB  Flash */
        .sectorSize = FLASH_SECTOR_SIZE,  /* 128KB  Sector Size */
        .pageSize   = FLASH_PAGE_SIZE,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb  fcb[1]          = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1];
    whNvmContext nvm[1] = {{0}};

    WH_TEST_RETURN_ON_FAIL(
        whTest_NvmCfgBackend(nvmType, &nvm_setup, n_conf, fc_conf, fc, fcb));

    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
            .devId = INVALID_DEVID,
    }};


    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
        .crypto      = crypto,
        .devId       = INVALID_DEVID,
    }};

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));

    ret = wolfCrypt_Init();
    if (ret == 0) {
        ret = wc_InitRng_ex(crypto->rng, NULL, crypto->devId);
        if (ret != 0) {
            WH_ERROR_PRINT("Failed to initialize wolfCrypt rng: %d\n", ret);
        }
        else {
            _whClientServerThreadTest(c_conf, s_conf);
        }
    }
    else {
        WH_ERROR_PRINT("Failed to initialize wolfCrypt: %d\n", ret);
    }

    wh_Nvm_Cleanup(nvm);
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_TEST_POSIX */

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)
int whTest_Crypto(void)
{
    printf("Testing crypto: (pthread) mem...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_ClientServer_MemThreadTest(WH_NVM_TEST_BACKEND_FLASH));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    printf("Testing crypto: (pthread) mem (flash log)...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_ClientServer_MemThreadTest(WH_NVM_TEST_BACKEND_FLASH_LOG));
#endif

    return 0;
}
#endif /* WOLFHSM_CFG_TEST_POSIX && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
