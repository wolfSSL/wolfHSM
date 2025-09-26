/*
 * Copyright (C) 2025 wolfSSL Inc.
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
#include <stdint.h>
#include <string.h> /* For memset, memcpy */

#if defined(WOLFHSM_CFG_TEST_POSIX)
#include <sys/time.h> /* For gettimeofday and struct timeval */
#include <pthread.h>  /* For pthread_create/cancel/join/_t */
#include <unistd.h>   /* For sleep */
#endif

#include "wolfhsm/wh_settings.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_utils.h"

#if defined(WOLFHSM_CFG_TEST_POSIX)
/* Include transport-specific headers */
#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"
#endif /* WOLFHSM_CFG_TEST_POSIX */

#include "wh_bench.h"
#include "wh_bench_mod_all.h"
#include "wh_bench_ops.h"
#include "wh_bench_utils.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

/* Buffer sizes for transport */
/* Large enough to handle an RSA 4096 key */
#define BUFFER_SIZE \
    sizeof(whTransportMemCsr) + sizeof(whCommHeader) + WOLFHSM_CFG_COMM_DATA_LEN
#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */

typedef struct BenchModule {
    /* Name and function pointer should be supplied at array initialization */
    const char* const             name;
    const wh_BenchModuleFunc      func;
    const whBenchOpThroughputType tpType;
    /* ID and parameters are set after registration */
    int   id;
    void* params;
} BenchModule;

/* Enum for benchmark module types. These values serve as indices for the
 * array of benchmark modules to be registered, so must be contiguous. The size
 * of the array will be BENCH_MODULE_IDX_COUNT */
typedef enum BenchModuleIdx {
    BENCH_MODULE_IDX_ECHO = 0,

/* RNG */
#if !defined(WC_NO_RNG)
    BENCH_MODULE_IDX_RNG,
#endif /* !(WC_NO_RNG) */

/* AES */
#if !defined(NO_AES)
#if defined(WOLFSSL_AES_COUNTER)
    BENCH_MODULE_IDX_AES_128_CTR_ENCRYPT,
    BENCH_MODULE_IDX_AES_128_CTR_DECRYPT,
    BENCH_MODULE_IDX_AES_256_CTR_ENCRYPT,
    BENCH_MODULE_IDX_AES_256_CTR_DECRYPT,
#endif /* WOLFSSL_AES_COUNTER */
#if defined(HAVE_AES_ECB)
    BENCH_MODULE_IDX_AES_128_ECB_ENCRYPT,
    BENCH_MODULE_IDX_AES_128_ECB_DECRYPT,
    BENCH_MODULE_IDX_AES_256_ECB_ENCRYPT,
    BENCH_MODULE_IDX_AES_256_ECB_DECRYPT,
#endif /* HAVE_AES_ECB */
#if defined(HAVE_AES_CBC)
    BENCH_MODULE_IDX_AES_128_CBC_ENCRYPT,
    BENCH_MODULE_IDX_AES_128_CBC_DECRYPT,
    BENCH_MODULE_IDX_AES_256_CBC_ENCRYPT,
    BENCH_MODULE_IDX_AES_256_CBC_DECRYPT,
#endif /* HAVE_AES_CBC */
#if defined(HAVE_AESGCM)
    BENCH_MODULE_IDX_AES_128_GCM_ENCRYPT,
    BENCH_MODULE_IDX_AES_128_GCM_DECRYPT,
    BENCH_MODULE_IDX_AES_128_GCM_ENCRYPT_DMA,
    BENCH_MODULE_IDX_AES_128_GCM_DECRYPT_DMA,
    BENCH_MODULE_IDX_AES_256_GCM_ENCRYPT,
    BENCH_MODULE_IDX_AES_256_GCM_DECRYPT,
    BENCH_MODULE_IDX_AES_256_GCM_ENCRYPT_DMA,
    BENCH_MODULE_IDX_AES_256_GCM_DECRYPT_DMA,
#endif /* HAVE_AESGCM */
#endif /* !(NO_AES) */

/* CMAC */
#if defined(WOLFSSL_CMAC)
    BENCH_MODULE_IDX_CMAC_128,
    BENCH_MODULE_IDX_CMAC_128_DMA,
    BENCH_MODULE_IDX_CMAC_256,
    BENCH_MODULE_IDX_CMAC_256_DMA,
#endif /* WOLFSSL_CMAC */


/* SHA2 */
#if !defined(NO_SHA256)
    BENCH_MODULE_IDX_SHA2_256,
    BENCH_MODULE_IDX_SHA2_256_DMA,
#endif /* !(NO_SHA256) */

#if defined(WOLFSSL_SHA224)
    BENCH_MODULE_IDX_SHA2_224,
    BENCH_MODULE_IDX_SHA2_224_DMA,
#endif /* WOLFSSL_SHA224 */

#if defined(WOLFSSL_SHA384)
    BENCH_MODULE_IDX_SHA2_384,
    BENCH_MODULE_IDX_SHA2_384_DMA,
#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_SHA512)
    BENCH_MODULE_IDX_SHA2_512,
    BENCH_MODULE_IDX_SHA2_512_DMA,
#endif /* WOLFSSL_SHA512 */

/* SHA3 */
#if defined(WOLFSSL_SHA3)
    BENCH_MODULE_IDX_SHA3_256,
    BENCH_MODULE_IDX_SHA3_256_DMA,
#endif /* WOLFSSL_SHA3 */

/* HMAC */
#if !defined(NO_HMAC)
#if !defined(NO_SHA256)
    BENCH_MODULE_IDX_HMAC_SHA2_256,
    BENCH_MODULE_IDX_HMAC_SHA2_256_DMA,
#endif /* !(NO_SHA256) */
#if defined(WOLFSSL_SHA3)
    BENCH_MODULE_IDX_HMAC_SHA3_256,
    BENCH_MODULE_IDX_HMAC_SHA3_256_DMA,
#endif /* WOLFSSL_SHA3 */
#endif /* !(NO_HMAC) */

/* ECC */
#if defined(HAVE_ECC)
    BENCH_MODULE_IDX_ECC_P256_SIGN,
    BENCH_MODULE_IDX_ECC_P256_SIGN_DMA,
    BENCH_MODULE_IDX_ECC_P256_VERIFY,
    BENCH_MODULE_IDX_ECC_P256_VERIFY_DMA,
    BENCH_MODULE_IDX_ECC_P256_KEY_GEN,
    BENCH_MODULE_IDX_ECC_P256_ECDH,
#endif /* HAVE_ECC */

/* RSA */
#if !defined(NO_RSA)
    /* 2048 */
    BENCH_MODULE_IDX_RSA_2048_ENCRYPT,
    BENCH_MODULE_IDX_RSA_2048_ENCRYPT_DMA,
    BENCH_MODULE_IDX_RSA_2048_DECRYPT,
    BENCH_MODULE_IDX_RSA_2048_DECRYPT_DMA,
    BENCH_MODULE_IDX_RSA_2048_SIGN,
    BENCH_MODULE_IDX_RSA_2048_SIGN_DMA,
    BENCH_MODULE_IDX_RSA_2048_VERIFY,
    BENCH_MODULE_IDX_RSA_2048_VERIFY_DMA,
    BENCH_MODULE_IDX_RSA_2048_KEY_GEN,
    BENCH_MODULE_IDX_RSA_2048_KEY_GEN_DMA,
    /* 4096 */
    BENCH_MODULE_IDX_RSA_4096_ENCRYPT,
    BENCH_MODULE_IDX_RSA_4096_ENCRYPT_DMA,
    BENCH_MODULE_IDX_RSA_4096_DECRYPT,
    BENCH_MODULE_IDX_RSA_4096_DECRYPT_DMA,
    BENCH_MODULE_IDX_RSA_4096_SIGN,
    BENCH_MODULE_IDX_RSA_4096_SIGN_DMA,
    BENCH_MODULE_IDX_RSA_4096_VERIFY,
    BENCH_MODULE_IDX_RSA_4096_VERIFY_DMA,
    BENCH_MODULE_IDX_RSA_4096_KEY_GEN,
    BENCH_MODULE_IDX_RSA_4096_KEY_GEN_DMA,
#endif /* !(NO_RSA) */

/* Curve25519 */
#if defined(HAVE_CURVE25519)
    BENCH_MODULE_IDX_CURVE25519_KEY_GEN,
    BENCH_MODULE_IDX_CURVE25519_SHARED_SECRET,
#endif /* HAVE_CURVE25519 */

/* ML-DSA */
#if defined(HAVE_DILITHIUM)
#if !defined(WOLFSSL_NO_ML_DSA_44)
    BENCH_MODULE_IDX_ML_DSA_44_SIGN,
    BENCH_MODULE_IDX_ML_DSA_44_SIGN_DMA,
    BENCH_MODULE_IDX_ML_DSA_44_VERIFY,
    BENCH_MODULE_IDX_ML_DSA_44_VERIFY_DMA,
    BENCH_MODULE_IDX_ML_DSA_44_KEY_GEN,
    BENCH_MODULE_IDX_ML_DSA_44_KEY_GEN_DMA,
#endif /* !(WOLFSSL_NO_ML_DSA_44) */
#if !defined(WOLFSSL_NO_ML_DSA_65)
    BENCH_MODULE_IDX_ML_DSA_65_SIGN,
    BENCH_MODULE_IDX_ML_DSA_65_SIGN_DMA,
    BENCH_MODULE_IDX_ML_DSA_65_VERIFY,
    BENCH_MODULE_IDX_ML_DSA_65_VERIFY_DMA,
    BENCH_MODULE_IDX_ML_DSA_65_KEY_GEN,
    BENCH_MODULE_IDX_ML_DSA_65_KEY_GEN_DMA,
#endif /* !(WOLFSSL_NO_ML_DSA_65) */
#if !defined(WOLFSSL_NO_ML_DSA_87)
    BENCH_MODULE_IDX_ML_DSA_87_SIGN,
    BENCH_MODULE_IDX_ML_DSA_87_SIGN_DMA,
    BENCH_MODULE_IDX_ML_DSA_87_VERIFY,
    BENCH_MODULE_IDX_ML_DSA_87_VERIFY_DMA,
    BENCH_MODULE_IDX_ML_DSA_87_KEY_GEN,
    BENCH_MODULE_IDX_ML_DSA_87_KEY_GEN_DMA,
#endif /* !(WOLFSSL_NO_ML_DSA_87) */
#endif /* HAVE_DILITHIUM */

    /* number of modules. This must be the last entry and will be used as the
     * size of the global modules array */
    BENCH_MODULE_IDX_COUNT
} BenchModuleIdx;

/* Ensure we have enough space for all modules in the context */
WH_UTILS_STATIC_ASSERT(MAX_BENCH_OPS > BENCH_MODULE_IDX_COUNT,
                       "More modules expected than MAX_BENCH_OPS");

/* clang-format off */
static BenchModule g_benchModules[] = {
    [BENCH_MODULE_IDX_ECHO]                    = {"ECHO",                         wh_Bench_Mod_Echo,                 BENCH_THROUGHPUT_XBPS, 0, NULL},

    /* RNG */
#if !defined(WC_NO_RNG)
    [BENCH_MODULE_IDX_RNG]                     = {"RNG",                          wh_Bench_Mod_Rng,                  BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* !(WC_NO_RNG) */

    /* AES */
#if !defined(NO_AES)
#if defined(WOLFSSL_AES_COUNTER)
    [BENCH_MODULE_IDX_AES_128_CTR_ENCRYPT]     = {"AES-128-CTR-Encrypt",          wh_Bench_Mod_Aes128CTREncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_128_CTR_DECRYPT]     = {"AES-128-CTR-Decrypt",          wh_Bench_Mod_Aes128CTRDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_CTR_ENCRYPT]     = {"AES-256-CTR-Encrypt",          wh_Bench_Mod_Aes256CTREncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_CTR_DECRYPT]     = {"AES-256-CTR-Decrypt",          wh_Bench_Mod_Aes256CTRDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* WOLFSSL_AES_COUNTER */
#if defined(HAVE_AES_ECB)
    [BENCH_MODULE_IDX_AES_128_ECB_ENCRYPT]     = {"AES-128-ECB-Encrypt",          wh_Bench_Mod_Aes128ECBEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_128_ECB_DECRYPT]     = {"AES-128-ECB-Decrypt",          wh_Bench_Mod_Aes128ECBDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_ECB_ENCRYPT]     = {"AES-256-ECB-Encrypt",          wh_Bench_Mod_Aes256ECBEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_ECB_DECRYPT]     = {"AES-256-ECB-Decrypt",          wh_Bench_Mod_Aes256ECBDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* HAVE_AES_ECB */
#if defined(HAVE_AES_CBC)
    [BENCH_MODULE_IDX_AES_128_CBC_ENCRYPT]     = {"AES-128-CBC-Encrypt",          wh_Bench_Mod_Aes128CBCEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_128_CBC_DECRYPT]     = {"AES-128-CBC-Decrypt",          wh_Bench_Mod_Aes128CBCDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_CBC_ENCRYPT]     = {"AES-256-CBC-Encrypt",          wh_Bench_Mod_Aes256CBCEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_CBC_DECRYPT]     = {"AES-256-CBC-Decrypt",          wh_Bench_Mod_Aes256CBCDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* HAVE_AES_CBC */
#if defined(HAVE_AESGCM)
    [BENCH_MODULE_IDX_AES_128_GCM_ENCRYPT]     = {"AES-128-GCM-Encrypt",          wh_Bench_Mod_Aes128GCMEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_128_GCM_DECRYPT]     = {"AES-128-GCM-Decrypt",          wh_Bench_Mod_Aes128GCMDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_128_GCM_ENCRYPT_DMA] = {"AES-128-GCM-Encrypt-DMA",      wh_Bench_Mod_Aes128GCMEncryptDma,  BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_128_GCM_DECRYPT_DMA] = {"AES-128-GCM-Decrypt-DMA",      wh_Bench_Mod_Aes128GCMDecryptDma,  BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_GCM_ENCRYPT]     = {"AES-256-GCM-Encrypt",          wh_Bench_Mod_Aes256GCMEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_GCM_DECRYPT]     = {"AES-256-GCM-Decrypt",          wh_Bench_Mod_Aes256GCMDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_GCM_ENCRYPT_DMA] = {"AES-256-GCM-Encrypt-DMA",      wh_Bench_Mod_Aes256GCMEncryptDma,  BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_GCM_DECRYPT_DMA] = {"AES-256-GCM-Decrypt-DMA",      wh_Bench_Mod_Aes256GCMDecryptDma,  BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* HAVE_AESGCM */
#endif /* !(NO_AES) */

    /* CMAC */
#if defined(WOLFSSL_CMAC)
    [BENCH_MODULE_IDX_CMAC_128]                = {"AES-CMAC-128",                 wh_Bench_Mod_CmacAes128,           BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_CMAC_128_DMA]            = {"AES-CMAC-128-DMA",             wh_Bench_Mod_CmacAes128Dma,        BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_CMAC_256]                = {"AES-CMAC-256",                 wh_Bench_Mod_CmacAes256,           BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_CMAC_256_DMA]            = {"AES-CMAC-256-DMA",             wh_Bench_Mod_CmacAes256Dma,        BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* WOLFSSL_CMAC */

    /* SHA2 */
#if !defined(NO_SHA256)
    [BENCH_MODULE_IDX_SHA2_256]                = {"SHA2-256",                     wh_Bench_Mod_Sha256,               BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_SHA2_256_DMA]            = {"SHA2-256-DMA",                 wh_Bench_Mod_Sha256Dma,            BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* !(NO_SHA256) */
#if defined(WOLFSSL_SHA224)
    [BENCH_MODULE_IDX_SHA2_224]                = {"SHA2-224",                     wh_Bench_Mod_Sha224,               BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_SHA2_224_DMA]            = {"SHA2-224-DMA",                 wh_Bench_Mod_Sha224Dma,            BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* WOLFSSL_SHA224 */
#if defined(WOLFSSL_SHA384)
    [BENCH_MODULE_IDX_SHA2_384]                = {"SHA2-384",                     wh_Bench_Mod_Sha384,               BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_SHA2_384_DMA]            = {"SHA2-384-DMA",                 wh_Bench_Mod_Sha384Dma,            BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* WOLFSSL_SHA384 */
#if defined(WOLFSSL_SHA512)
    [BENCH_MODULE_IDX_SHA2_512]                = {"SHA2-512",                     wh_Bench_Mod_Sha512,               BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_SHA2_512_DMA]            = {"SHA2-512-DMA",                 wh_Bench_Mod_Sha512Dma,            BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* WOLFSSL_SHA512 */
    /* SHA3 */
#if defined(WOLFSSL_SHA3)
    [BENCH_MODULE_IDX_SHA3_256]                = {"SHA3-256",                     wh_Bench_Mod_Sha3256,               BENCH_THROUGHPUT_NONE, 0, NULL},
    [BENCH_MODULE_IDX_SHA3_256_DMA]            = {"SHA3-256-DMA",                 wh_Bench_Mod_Sha3256Dma,            BENCH_THROUGHPUT_NONE, 0, NULL},
#endif /* WOLFSSL_SHA3 */

    /* HMAC */
#if !defined(NO_HMAC)
#if !defined(NO_SHA256)
    [BENCH_MODULE_IDX_HMAC_SHA2_256]           = {"HMAC-SHA2-256",                wh_Bench_Mod_HmacSha256,            BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_HMAC_SHA2_256_DMA]       = {"HMAC-SHA2-256-DMA",            wh_Bench_Mod_HmacSha256Dma,         BENCH_THROUGHPUT_XBPS, 0, NULL},
#endif /* !(NO_SHA256) */
#if defined(WOLFSSL_SHA3)
    [BENCH_MODULE_IDX_HMAC_SHA3_256]           = {"HMAC-SHA3-256",                wh_Bench_Mod_HmacSha3256,           BENCH_THROUGHPUT_NONE, 0, NULL},
    [BENCH_MODULE_IDX_HMAC_SHA3_256_DMA]       = {"HMAC-SHA3-256-DMA",            wh_Bench_Mod_HmacSha3256Dma,        BENCH_THROUGHPUT_NONE, 0, NULL},
#endif /* WOLFSSL_SHA3 */
#endif /* !(NO_HMAC) */

    /* ECC */
#if defined(HAVE_ECC)
    [BENCH_MODULE_IDX_ECC_P256_SIGN]           = {"ECC-P256-SIGN",                wh_Bench_Mod_EccP256Sign,            BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ECC_P256_SIGN_DMA]       = {"ECC-P256-SIGN-DMA",            wh_Bench_Mod_EccP256SignDma,         BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ECC_P256_VERIFY]         = {"ECC-P256-VERIFY",              wh_Bench_Mod_EccP256Verify,          BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ECC_P256_VERIFY_DMA]     = {"ECC-P256-VERIFY-DMA",          wh_Bench_Mod_EccP256VerifyDma,       BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ECC_P256_KEY_GEN]        = {"ECC-P256-KEY-GEN",             wh_Bench_Mod_EccP256KeyGen,          BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ECC_P256_ECDH]           = {"ECC-P256-ECDH",                wh_Bench_Mod_EccP256Ecdh,            BENCH_THROUGHPUT_OPS, 0, NULL},
#endif /* HAVE_ECC */

    /* RSA */
#if !defined(NO_RSA)
    /* 2048 */
    [BENCH_MODULE_IDX_RSA_2048_ENCRYPT]        = {"RSA-2048-PUBLIC-ENCRYPT",      wh_Bench_Mod_Rsa2048PubEncrypt,      BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_ENCRYPT_DMA]    = {"RSA-2048-PUBLIC-ENCRYPT-DMA",  wh_Bench_Mod_Rsa2048PubEncryptDma,   BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_DECRYPT]        = {"RSA-2048-PRIVATE-DECRYPT",     wh_Bench_Mod_Rsa2048PrvDecrypt,      BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_DECRYPT_DMA]    = {"RSA-2048-PRIVATE-DECRYPT-DMA", wh_Bench_Mod_Rsa2048PrvDecryptDma,   BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_SIGN]           = {"RSA-2048-SIGN",                wh_Bench_Mod_Rsa2048Sign,            BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_SIGN_DMA]       = {"RSA-2048-SIGN-DMA",            wh_Bench_Mod_Rsa2048SignDma,         BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_VERIFY]         = {"RSA-2048-VERIFY",              wh_Bench_Mod_Rsa2048Verify,          BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_VERIFY_DMA]     = {"RSA-2048-VERIFY-DMA",          wh_Bench_Mod_Rsa2048VerifyDma,       BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_KEY_GEN]        = {"RSA-2048-KEY-GEN",             wh_Bench_Mod_Rsa2048KeyGen,          BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_2048_KEY_GEN_DMA]    = {"RSA-2048-KEY-GEN-DMA",         wh_Bench_Mod_Rsa2048KeyGenDma,       BENCH_THROUGHPUT_OPS,  0, NULL},
    /* 4096 */
    [BENCH_MODULE_IDX_RSA_4096_ENCRYPT]        = {"RSA-4096-PUBLIC-ENCRYPT",      wh_Bench_Mod_Rsa4096PubEncrypt,      BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_ENCRYPT_DMA]    = {"RSA-4096-PUBLIC-ENCRYPT-DMA",  wh_Bench_Mod_Rsa4096PubEncryptDma,   BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_DECRYPT]        = {"RSA-4096-PRIVATE-DECRYPT",     wh_Bench_Mod_Rsa4096PrvDecrypt,      BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_DECRYPT_DMA]    = {"RSA-4096-PRIVATE-DECRYPT-DMA", wh_Bench_Mod_Rsa4096PrvDecryptDma,   BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_SIGN]           = {"RSA-4096-SIGN",                wh_Bench_Mod_Rsa4096Sign,            BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_SIGN_DMA]       = {"RSA-4096-SIGN-DMA",            wh_Bench_Mod_Rsa4096SignDma,         BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_VERIFY]         = {"RSA-4096-VERIFY",              wh_Bench_Mod_Rsa4096Verify,          BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_VERIFY_DMA]     = {"RSA-4096-VERIFY-DMA",          wh_Bench_Mod_Rsa4096VerifyDma,       BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_KEY_GEN]        = {"RSA-4096-KEY-GEN",             wh_Bench_Mod_Rsa4096KeyGen,          BENCH_THROUGHPUT_OPS,  0, NULL},
    [BENCH_MODULE_IDX_RSA_4096_KEY_GEN_DMA]    = {"RSA-4096-KEY-GEN-DMA",         wh_Bench_Mod_Rsa4096KeyGenDma,       BENCH_THROUGHPUT_OPS,  0, NULL},

#endif /* !(NO_RSA) */

    /* Curve25519 */
#if defined(HAVE_CURVE25519)
    [BENCH_MODULE_IDX_CURVE25519_KEY_GEN]      = {"CURVE25519-KEY-GEN",           wh_Bench_Mod_Curve25519KeyGen,        BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_CURVE25519_SHARED_SECRET]= {"CURVE25519-SHARED-SECRET",     wh_Bench_Mod_Curve25519SharedSecret,  BENCH_THROUGHPUT_OPS, 0, NULL},
#endif /* HAVE_CURVE25519 */

    /* ML-DSA */
#if defined(HAVE_DILITHIUM)
#if !defined(WOLFSSL_NO_ML_DSA_44)
    [BENCH_MODULE_IDX_ML_DSA_44_SIGN]          = {"ML-DSA-44-SIGN",               wh_Bench_Mod_MlDsa44Sign,             BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_44_SIGN_DMA]      = {"ML-DSA-44-SIGN-DMA",           wh_Bench_Mod_MlDsa44SignDma,          BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_44_VERIFY]        = {"ML-DSA-44-VERIFY",             wh_Bench_Mod_MlDsa44Verify,           BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_44_VERIFY_DMA]    = {"ML-DSA-44-VERIFY-DMA",         wh_Bench_Mod_MlDsa44VerifyDma,        BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_44_KEY_GEN]       = {"ML-DSA-44-KEY-GEN",            wh_Bench_Mod_MlDsa44KeyGen,           BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_44_KEY_GEN_DMA]   = {"ML-DSA-44-KEY-GEN-DMA",        wh_Bench_Mod_MlDsa44KeyGenDma,        BENCH_THROUGHPUT_OPS, 0, NULL},
#endif /* !(WOLFSSL_NO_ML_DSA_44) */
#if !defined(WOLFSSL_NO_ML_DSA_65)
    [BENCH_MODULE_IDX_ML_DSA_65_SIGN]          = {"ML-DSA-65-SIGN",               wh_Bench_Mod_MlDsa65Sign,             BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_65_SIGN_DMA]      = {"ML-DSA-65-SIGN-DMA",           wh_Bench_Mod_MlDsa65SignDma,          BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_65_VERIFY]        = {"ML-DSA-65-VERIFY",             wh_Bench_Mod_MlDsa65Verify,           BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_65_VERIFY_DMA]    = {"ML-DSA-65-VERIFY-DMA",         wh_Bench_Mod_MlDsa65VerifyDma,        BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_65_KEY_GEN]       = {"ML-DSA-65-KEY-GEN",            wh_Bench_Mod_MlDsa65KeyGen,           BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_65_KEY_GEN_DMA]   = {"ML-DSA-65-KEY-GEN-DMA",        wh_Bench_Mod_MlDsa65KeyGenDma,        BENCH_THROUGHPUT_OPS, 0, NULL},
#endif /* !(WOLFSSL_NO_ML_DSA_65) */
#if !defined(WOLFSSL_NO_ML_DSA_87)
    [BENCH_MODULE_IDX_ML_DSA_87_SIGN]          = {"ML-DSA-87-SIGN",               wh_Bench_Mod_MlDsa87Sign,             BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_87_SIGN_DMA]      = {"ML-DSA-87-SIGN-DMA",           wh_Bench_Mod_MlDsa87SignDma,          BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_87_VERIFY]        = {"ML-DSA-87-VERIFY",             wh_Bench_Mod_MlDsa87Verify,           BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_87_VERIFY_DMA]    = {"ML-DSA-87-VERIFY-DMA",         wh_Bench_Mod_MlDsa87VerifyDma,        BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_87_KEY_GEN]       = {"ML-DSA-87-KEY-GEN",            wh_Bench_Mod_MlDsa87KeyGen,           BENCH_THROUGHPUT_OPS, 0, NULL},
    [BENCH_MODULE_IDX_ML_DSA_87_KEY_GEN_DMA]   = {"ML-DSA-87-KEY-GEN-DMA",        wh_Bench_Mod_MlDsa87KeyGenDma,        BENCH_THROUGHPUT_OPS, 0, NULL},
#endif /* !(WOLFSSL_NO_ML_DSA_87) */
#endif /* HAVE_DILITHIUM */
};
/* clang-format on */

static int _registerBenchModules(whBenchOpContext* benchCtx)
{
    int ret = 0;
    int i;
    for (i = 0; i < BENCH_MODULE_IDX_COUNT; i++) {
        ret = wh_Bench_RegisterOp(benchCtx, g_benchModules[i].name,
                                  g_benchModules[i].tpType,
                                  &g_benchModules[i].id);
        if (ret != WH_ERROR_OK) {
            WH_BENCH_PRINTF("Failed to register benchmark module \"%s\": %d\n",
                            g_benchModules[i].name, ret);
            return ret;
        }
    }
    return ret;
}

void wh_Bench_ListModules(void)
{
    int i;
    WH_BENCH_PRINTF("Modules:\n");
    WH_BENCH_PRINTF("Index: Name\n");
    for (i = 0; i < BENCH_MODULE_IDX_COUNT; i++) {
        WH_BENCH_PRINTF("%d: %s\n", i, g_benchModules[i].name);
    }
}

/* Placeholder for the benchmarking function */
static int _runClientBenchmarks(whClientContext* client, int transport,
                                int moduleIndex)
{
    int              ret = 0;
    whBenchOpContext benchCtx;
    int              i;

    WH_BENCH_PRINTF("Running benchmarks...\n");

    /* Initialize benchmark context */
    ret = wh_Bench_Init(&benchCtx);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize benchmark context: %d\n", ret);
        return ret;
    }
    benchCtx.transportType = transport;

    /* Register operations to benchmark */
    ret = _registerBenchModules(&benchCtx);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to register benchmark modules: %d\n", ret);
        return ret;
    }

    /* Run specific module or all modules */
    if (moduleIndex >= 0 && moduleIndex < BENCH_MODULE_IDX_COUNT) {
        /* Run specific module */
        i = moduleIndex;
        WH_BENCH_PRINTF("Benchmarking \"%s\"...\n", g_benchModules[i].name);
        ret = g_benchModules[i].func(client, &benchCtx, g_benchModules[i].id,
                                     g_benchModules[i].params);
        /* Allow skipping not implemented modules. Return code could be
         * wolfCrypt or wolfSSL error */
        if (ret != 0) {
            if (ret == WH_ERROR_NOTIMPL) {
                WH_BENCH_PRINTF(" -> SKIPPED \"%s\"\n", g_benchModules[i].name);
                ret = 0;
            }
            else {
                WH_BENCH_PRINTF(
                    "Benchmark module \"%s\" failed with error: %d\n",
                    g_benchModules[i].name, ret);
                return ret;
            }
        }
        else {
            /* Print results for this module */
            wh_Bench_PrintIntermediateResult(&benchCtx, g_benchModules[i].id);
        }
    }
    else {
        /* Run all modules */
        for (i = 0; i < BENCH_MODULE_IDX_COUNT; i++) {
            WH_BENCH_PRINTF("Benchmarking \"%s\"...\n", g_benchModules[i].name);
            ret =
                g_benchModules[i].func(client, &benchCtx, g_benchModules[i].id,
                                       g_benchModules[i].params);
            /* Allow skipping not implemented modules. Return code could be
             * wolfCrypt or wolfSSL error */
            if (ret != 0) {
                if (ret == WH_ERROR_NOTIMPL) {
                    WH_BENCH_PRINTF(" -> SKIPPED \"%s\"\n",
                                    g_benchModules[i].name);
                    ret = 0;
                }
                else {
                    WH_BENCH_PRINTF(
                        "Benchmark module \"%s\" failed with error: %d\n",
                        g_benchModules[i].name, ret);
                    return ret;
                }
            }
            else {
                /* Print results for this module */
                wh_Bench_PrintIntermediateResult(&benchCtx,
                                                 g_benchModules[i].id);
            }
        }
    }

    /* Print benchmark results */
    wh_Bench_PrintResults(&benchCtx);

    /* Clean up benchmark context */
    wh_Bench_Cleanup(&benchCtx);

    if (ret == 0) {
        WH_BENCH_PRINTF("Benchmarks completed.\n");
    }

    return ret;
}


/* additional sanity check in case main() is not used for if the transport
 * requested has been enabled */
static int wh_Bench_CheckTransport(int transport)
{
    switch (transport) {
        case WH_BENCH_TRANSPORT_MEM:
            break;
        case WH_BENCH_TRANSPORT_POSIX_DMA:
#if !defined(WOLFSSL_STATIC_MEMORY) || !defined(WOLFHSM_CFG_TEST_POSIX)
            return WH_ERROR_BADARGS;
#else
            break;
#endif
        case WH_BENCH_TRANSPORT_POSIX_TCP:
#if !defined(WOLFHSM_CFG_TEST_POSIX)
            return WH_ERROR_BADARGS;
#else
            break;
#endif
        case WH_BENCH_TRANSPORT_POSIX_SHM:
#if !defined(WOLFHSM_CFG_TEST_POSIX)
            return WH_ERROR_BADARGS;
#else
            break;
#endif
        default:
            return WH_ERROR_BADARGS;
    }
    return WH_ERROR_OK;
}

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFHSM_CFG_TEST_POSIX)
static int _whBench_ClientCfg_PosixDmaHeap(posixTransportShmContext* shmCtx)
{
    static const unsigned int listSz     = 9;
    static const uint32_t     sizeList[] = {176,  256,  288,  704,  1056,
                                            1712, 2112, 2368, 33800};
    static const uint32_t     distList[] = {3, 1, 1, 1, 1, 1, 1, 3, 2};
    WOLFSSL_HEAP_HINT*        heap       = NULL;
    void*                     dma;
    size_t                    dmaSz;
    int ret = 0;

    ret = posixTransportShm_GetDma(shmCtx, &dma, &dmaSz);
    if (ret != 0) {
        printf("Failed to get DMA\n");
        return ret;
    }

    ret = wc_LoadStaticMemory_ex(&heap, listSz, sizeList, distList, dma,
                                 dmaSz, 0, 0);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to load static memory: %d\n", ret);
        return ret;
    }
    ret = posixTransportShm_SetDmaHeap(shmCtx, (void*)heap);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set heap: %d\n", ret);
        return ret;
    }

    return ret;
}
#endif

/* Initializes a client context based on the provided config, runs the
 * benchmarks, then cleans up the context */
int wh_Bench_ClientCfg(whClientConfig* clientCfg, int transport)
{
    int             ret       = 0;
    whClientContext client[1] = {0};
    uint32_t        client_id = 0;
    uint32_t        server_id = 0;

    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Bench_CheckTransport(transport);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Transport not supported: %d\n", ret);
        return ret;
    }

    /* Initialize the client */
    ret = wh_Client_Init(client, clientCfg);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize client: %d\n", ret);
        return ret;
    }

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFHSM_CFG_TEST_POSIX)
    if (transport == WH_BENCH_TRANSPORT_POSIX_DMA) {
        ret = _whBench_ClientCfg_PosixDmaHeap((posixTransportShmContext*)
                                    clientCfg->comm->transport_context);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to load static memory: %d\n", ret);
            return ret;
        }
    }
#endif

    /* Establish communication with the server */
    ret = wh_Client_CommInit(client, &client_id, &server_id);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to establish communication with server: %d\n",
                        ret);
        wh_Client_Cleanup(client);
        return ret;
    }

    /* Run the benchmarks */
    ret = _runClientBenchmarks(client, transport,
                               -1); /* -1 means run all modules */

    /* Clean up */
    wh_Client_CommClose(client);
    wh_Client_Cleanup(client);

    return ret;
}

/* Runs the benchmarks on an already initialized client context */
int wh_Bench_ClientCtx(whClientContext* client, int transport)
{
    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _runClientBenchmarks(client, transport,
                                -1); /* -1 means run all modules */
}


int wh_Bench_ServerCfgLoop(whServerConfig* serverCfg)
{
    whServerContext server[1]    = {0};
    whCommConnected am_connected = WH_COMM_CONNECTED;
    int             ret          = 0;

    if (serverCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize the server */
    ret = wh_Server_Init(server, serverCfg);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize server: %d\n", ret);
        return ret;
    }

    /* Set the server as connected */
    ret = wh_Server_SetConnected(server, am_connected);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set server connected: %d\n", ret);
        wh_Server_Cleanup(server);
        return ret;
    }

    /* Process requests until disconnected */
    while (am_connected == WH_COMM_CONNECTED) {
        ret = wh_Server_HandleRequestMessage(server);
        if ((ret != WH_ERROR_NOTREADY) && (ret != WH_ERROR_OK)) {
            WH_BENCH_PRINTF("Failed to handle request message: %d\n", ret);
            break;
        }
        wh_Server_GetConnected(server, &am_connected);
    }

    /* Clean up */
    if (ret == WH_ERROR_NOTREADY) {
        /* Ignore not ready status */
        ret = WH_ERROR_OK;
    }
    (void)wh_Server_Cleanup(server);

    return ret;
}

#if defined(WOLFHSM_CFG_TEST_POSIX)
typedef struct {
    whClientConfig* config;
    int             moduleIndex;
    int             transport;
} whBenchClientTaskData;

static void* _whBenchClientTask(void* data)
{
    whBenchClientTaskData* taskData  = (whBenchClientTaskData*)data;
    whClientContext        client[1] = {0};
    uint32_t               client_id = 0;
    uint32_t               server_id = 0;
    int                    ret       = 0;

    /* Initialize the client */
    sleep(1); /* Give the server a chance to setup DMA */
    ret = wh_Client_Init(client, taskData->config);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to initialize client: %d\n", ret);
        return NULL;
    }

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFHSM_CFG_TEST_POSIX)
    if (taskData->transport == WH_BENCH_TRANSPORT_POSIX_DMA) {
        ret = _whBench_ClientCfg_PosixDmaHeap((posixTransportShmContext*)
                                    taskData->config->comm->transport_context);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to load static memory: %d\n", ret);
            return NULL;
        }
    }
#endif

    /* Establish communication with the server */
    ret = wh_Client_CommInit(client, &client_id, &server_id);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to establish communication with server: %d\n",
                        ret);
        wh_Client_Cleanup(client);
        return NULL;
    }

    /* Run the benchmarks */
    ret = _runClientBenchmarks(client, taskData->transport,
                               taskData->moduleIndex);
    if (ret != 0) {
        WH_BENCH_PRINTF("Client benchmark failed: %d\n", ret);
    }

    /* Clean up */
    wh_Client_CommClose(client);
    wh_Client_Cleanup(client);
    return NULL;
}

static void* _whBenchServerTask(void* cf)
{
    if (wh_Bench_ServerCfgLoop(cf) != 0) {
        WH_BENCH_PRINTF("Server benchmark failed\n");
    }
    return NULL;
}

static void _whBenchClientServerThreadTest(whClientConfig* c_conf,
                                           whServerConfig* s_conf,
                                           int moduleIndex, int transport)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};
    void*     retval;
    int       rc = 0;
    whBenchClientTaskData clientData = {c_conf, moduleIndex, transport};

    /* Create server thread first */
    rc = pthread_create(&sthread, NULL, _whBenchServerTask, s_conf);
    if (rc == 0) {
        /* Create client thread */
        rc = pthread_create(&cthread, NULL, _whBenchClientTask, &clientData);
        if (rc == 0) {
            /* Wait for client to finish, then cancel server */
            pthread_join(cthread, &retval);
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);
        }
        else {
            /* If client thread creation failed, cancel server */
            pthread_cancel(sthread);
            pthread_join(sthread, &retval);
        }
    }
}

/* Global static variables for transport configurations */
static uint8_t              g_mem_req[BUFFER_SIZE]  = {0};
static uint8_t              g_mem_resp[BUFFER_SIZE] = {0};
static whTransportMemConfig g_mem_tmcf              = {
                 .req       = (whTransportMemCsr*)g_mem_req,
                 .req_size  = sizeof(g_mem_req),
                 .resp      = (whTransportMemCsr*)g_mem_resp,
                 .resp_size = sizeof(g_mem_resp),
};
static whTransportClientCb         g_mem_tccb    = WH_TRANSPORT_MEM_CLIENT_CB;
static whTransportMemClientContext g_mem_tmcc    = {0};
static whCommClientConfig          g_mem_cc_conf = {
             .transport_cb      = &g_mem_tccb,
             .transport_context = (void*)&g_mem_tmcc,
             .transport_config  = (void*)&g_mem_tmcf,
             .client_id         = 123,
};

static whTransportServerCb         g_mem_tscb    = WH_TRANSPORT_MEM_SERVER_CB;
static whTransportMemServerContext g_mem_tmsc    = {0};
static whCommServerConfig          g_mem_cs_conf = {
             .transport_cb      = &g_mem_tscb,
             .transport_context = (void*)&g_mem_tmsc,
             .transport_config  = (void*)&g_mem_tmcf,
             .server_id         = 124,
};

/* Helper function to configure client transport based on type */
static int _configureClientTransport(whBenchTransportType transport,
                                     whClientConfig*      c_conf)
{
    int ret = WH_ERROR_OK;

    switch (transport) {
        case WH_BENCH_TRANSPORT_MEM: {
            /* Memory transport configuration */
            c_conf->comm = &g_mem_cc_conf;
            break;
        }

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFHSM_CFG_TEST_POSIX)
        case WH_BENCH_TRANSPORT_POSIX_DMA: {
            static whClientDmaConfig dmaConfig;

            dmaConfig.cb = posixTransportShm_ClientStaticMemDmaCallback;
            dmaConfig.dmaAddrAllowList = NULL;
            c_conf->dmaConfig          = &dmaConfig;
        };
            __attribute__((fallthrough));
            /* Fall through */
#endif

        case WH_BENCH_TRANSPORT_POSIX_SHM: {
            /* Shared memory transport configuration */
            static whTransportClientCb pttcClientShmCb[1] = {
                POSIX_TRANSPORT_SHM_CLIENT_CB};
            static posixTransportShmClientContext tccShm;
            static posixTransportShmConfig        myshmconfig = {
                       .name      = "wh_bench_shm",
                       .req_size  = 7000,
                       .resp_size = 7000,
                       .dma_size  = 80000,
            };
            static whCommClientConfig ccShmConf = {
                .transport_cb      = pttcClientShmCb,
                .transport_context = (void*)&tccShm,
                .transport_config  = (void*)&myshmconfig,
                .client_id         = 12,
            };

            memset(&tccShm, 0, sizeof(posixTransportShmClientContext));
            c_conf->comm = &ccShmConf;
            break;
        }

        case WH_BENCH_TRANSPORT_POSIX_TCP: {
            /* TCP transport configuration */
            static whTransportClientCb pttcClientTcpCb = PTT_CLIENT_CB;
            static posixTransportTcpClientContext tccTcp;
            static posixTransportTcpConfig        mytcpconfig = {
                       .server_ip_string = "127.0.0.1",
                       .server_port      = 23456,
            };
            static whCommClientConfig ccTcpConf = {
                .transport_cb      = &pttcClientTcpCb,
                .transport_context = (void*)&tccTcp,
                .transport_config  = (void*)&mytcpconfig,
                .client_id         = 12,
            };

            memset(&tccTcp, 0, sizeof(posixTransportTcpClientContext));
            c_conf->comm = &ccTcpConf;
            break;
        }
        default:
            ret = WH_ERROR_BADARGS;
            break;
    }

    return ret;
}

/* Helper function to configure server transport based on type */
static int _configureServerTransport(whBenchTransportType transport,
                                     whServerConfig*      s_conf)
{
    int ret = WH_ERROR_OK;

    switch (transport) {
        case WH_BENCH_TRANSPORT_MEM: {
            /* Memory transport configuration */
            s_conf->comm_config = &g_mem_cs_conf;
            break;
        }

#if defined(WOLFSSL_STATIC_MEMORY) && defined(WOLFHSM_CFG_TEST_POSIX)
        case WH_BENCH_TRANSPORT_POSIX_DMA: {
            static whServerDmaConfig dmaConfig;

            dmaConfig.cb = posixTransportShm_ServerStaticMemDmaCallback;
            dmaConfig.dmaAddrAllowList = NULL;
            s_conf->dmaConfig          = &dmaConfig;
        };
            __attribute__((fallthrough));
            /* Fall through */
#endif

        case WH_BENCH_TRANSPORT_POSIX_SHM: {
            /* Shared memory transport configuration */
            static whTransportServerCb pttServerShmCb[1] = {
                POSIX_TRANSPORT_SHM_SERVER_CB};
            static posixTransportShmServerContext tscShm;
            static posixTransportShmConfig        myshmconfig = {
                       .name      = "wh_bench_shm",
                       .req_size  = 7000,
                       .resp_size = 7000,
                       .dma_size  = 80000,
            };
            static whCommServerConfig csShmConf = {
                .transport_cb      = pttServerShmCb,
                .transport_context = (void*)&tscShm,
                .transport_config  = (void*)&myshmconfig,
                .server_id         = 57,
            };

            memset(&tscShm, 0, sizeof(posixTransportShmServerContext));
            s_conf->comm_config = &csShmConf;
            break;
        }

        case WH_BENCH_TRANSPORT_POSIX_TCP: {
            /* TCP transport configuration */
            static whTransportServerCb pttServerTcpCb = PTT_SERVER_CB;
            static posixTransportTcpServerContext tscTcp;
            static posixTransportTcpConfig        mytcpconfig = {
                       .server_ip_string = "127.0.0.1",
                       .server_port      = 23456,
            };
            static whCommServerConfig csTcpConf = {
                .transport_cb      = &pttServerTcpCb,
                .transport_context = (void*)&tscTcp,
                .transport_config  = (void*)&mytcpconfig,
                .server_id         = 57,
            };

            memset(&tscTcp, 0, sizeof(posixTransportTcpServerContext));
            s_conf->comm_config = &csTcpConf;
            break;
        }

        default:
            ret = WH_ERROR_BADARGS;
            break;
    }

    return ret;
}


/* transport is the type of transport to use */
int wh_Bench_ClientServer_Posix(int transport, int moduleIndex)
{
    static uint8_t memory[FLASH_RAM_SIZE] = {0};
    int            ret                    = WH_ERROR_OK;

    /* Client configuration/contexts */
    whClientConfig c_conf[1] = {{0}};

    /* Server configuration/contexts */
    whServerConfig s_conf[1] = {{0}};

    /* Configure transport based on type */
    ret = _configureClientTransport(transport, c_conf);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to configure client transport: %d\n", ret);
        return ret;
    }

    ret = _configureServerTransport(transport, s_conf);
    if (ret != WH_ERROR_OK) {
        WH_BENCH_PRINTF("Failed to configure server transport: %d\n", ret);
        return ret;
    }

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE / 2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Crypto context */
    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};
#endif

    /* Set up server configuration with NVM and crypto */
    s_conf[0].nvm = nvm;
#ifndef WOLFHSM_CFG_NO_CRYPTO
    s_conf[0].crypto = crypto;
    s_conf[0].devId  = INVALID_DEVID;
#endif

    /* Initialize Flash first */
    ret = whFlashRamsim_Init(fc, fc_conf);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize Flash: %d\n", ret);
        return ret;
    }

    /* Initialize NVM */
    ret = wh_Nvm_Init(nvm, n_conf);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize NVM: %d\n", ret);
        whFlashRamsim_Cleanup(fc);
        return ret;
    }

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Initialize wolfCrypt */
    ret = wolfCrypt_Init();
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize wolfCrypt: %d\n", ret);
        wh_Nvm_Cleanup(nvm);
        whFlashRamsim_Cleanup(fc);
        return ret;
    }

    /* Initialize RNG */
    ret = wc_InitRng_ex(crypto->rng, NULL, crypto->devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize RNG: %d\n", ret);
        wolfCrypt_Cleanup();
        wh_Nvm_Cleanup(nvm);
        whFlashRamsim_Cleanup(fc);
        return ret;
    }
#endif

    /* Run client and server in separate threads */
    _whBenchClientServerThreadTest(c_conf, s_conf, moduleIndex, transport);

    /* Clean up */
    wh_Nvm_Cleanup(nvm);
    whFlashRamsim_Cleanup(fc);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return WH_ERROR_OK;
}


#endif /* WOLFHSM_CFG_TEST_POSIX */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
