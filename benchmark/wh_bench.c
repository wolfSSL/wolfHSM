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
    BENCH_MODULE_IDX_AES_256_GCM_ENCRYPT,
    BENCH_MODULE_IDX_AES_256_GCM_DECRYPT,
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
    [BENCH_MODULE_IDX_AES_256_GCM_ENCRYPT]     = {"AES-256-GCM-Encrypt",          wh_Bench_Mod_Aes256GCMEncrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
    [BENCH_MODULE_IDX_AES_256_GCM_DECRYPT]     = {"AES-256-GCM-Decrypt",          wh_Bench_Mod_Aes256GCMDecrypt,     BENCH_THROUGHPUT_XBPS, 0, NULL},
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

/* Placeholder for the benchmarking function */
static int _runClientBenchmarks(whClientContext* client)
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

    /* Register operations to benchmark */
    ret = _registerBenchModules(&benchCtx);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to register benchmark modules: %d\n", ret);
        return ret;
    }

    /* Iterate over all benchmark modules and run them */
    for (i = 0; i < BENCH_MODULE_IDX_COUNT; i++) {
        WH_BENCH_PRINTF("Benchmarking \"%s\"...\n", g_benchModules[i].name);
        ret = g_benchModules[i].func(client, &benchCtx, g_benchModules[i].id,
                                     g_benchModules[i].params);
        /* Allow skipping not implemented modules. Return code could be
         * wolfCrypt or wolfSSL error */
        if (ret != 0) {
            if (ret == WH_ERROR_NOTIMPL) {
                WH_BENCH_PRINTF(" -> SKIPPED \"%s\"\n", g_benchModules[i].name);
                ret = 0;
                continue;
            }
            WH_BENCH_PRINTF("Benchmark module \"%s\" failed with error: %d\n",
                            g_benchModules[i].name, ret);
            return ret;
        }
        else {
            /* Print results for this module */
            wh_Bench_PrintIntermediateResult(&benchCtx, g_benchModules[i].id);
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

/* Initializes a client context based on the provided config, runs the
 * benchmarks, then cleans up the context */
int wh_Bench_ClientCfg(whClientConfig* clientCfg)
{
    int             ret       = 0;
    whClientContext client[1] = {0};
    uint32_t        client_id = 0;
    uint32_t        server_id = 0;

    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize the client */
    ret = wh_Client_Init(client, clientCfg);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize client: %d\n", ret);
        return ret;
    }

    /* Establish communication with the server */
    ret = wh_Client_CommInit(client, &client_id, &server_id);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to establish communication with server: %d\n",
                        ret);
        wh_Client_Cleanup(client);
        return ret;
    }

    /* Run the benchmarks */
    ret = _runClientBenchmarks(client);

    /* Clean up */
    wh_Client_CommClose(client);
    wh_Client_Cleanup(client);

    return ret;
}

/* Runs the benchmarks on an already initialized client context */
int wh_Bench_ClientCtx(whClientContext* client)
{
    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _runClientBenchmarks(client);
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
static void* _whBenchClientTask(void* cf)
{
    if (wh_Bench_ClientCfg(cf) != 0) {
        WH_BENCH_PRINTF("Client benchmark failed\n");
    }
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
                                           whServerConfig* s_conf)
{
    pthread_t cthread = {0};
    pthread_t sthread = {0};
    void*     retval;
    int       rc = 0;

    /* Create server thread first */
    rc = pthread_create(&sthread, NULL, _whBenchServerTask, s_conf);
    if (rc == 0) {
        /* Create client thread */
        rc = pthread_create(&cthread, NULL, _whBenchClientTask, c_conf);
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

int wh_Bench_ClientServer_Posix(void)
{
    uint8_t req[BUFFER_SIZE]  = {0};
    uint8_t resp[BUFFER_SIZE] = {0};

    /* Transport memory configuration */
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    /* Client configuration/contexts */
    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = 123,
    }};
    whClientConfig              c_conf[1]  = {{
                      .comm = cc_conf,
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};

    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,
        .sectorSize = FLASH_RAM_SIZE / 2,
        .pageSize   = 8,
        .erasedByte = (uint8_t)0,
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

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = crypto,
        .devId  = INVALID_DEVID,
#endif
    }};

    /* Initialize NVM */
    int ret = wh_Nvm_Init(nvm, n_conf);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize NVM: %d\n", ret);
        return ret;
    }

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Initialize wolfCrypt */
    ret = wolfCrypt_Init();
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize wolfCrypt: %d\n", ret);
        wh_Nvm_Cleanup(nvm);
        return ret;
    }

    /* Initialize RNG */
    ret = wc_InitRng_ex(crypto->rng, NULL, crypto->devId);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to initialize RNG: %d\n", ret);
        wolfCrypt_Cleanup();
        wh_Nvm_Cleanup(nvm);
        return ret;
    }
#endif

    /* Run client and server in separate threads */
    _whBenchClientServerThreadTest(c_conf, s_conf);

    /* Clean up */
    wh_Nvm_Cleanup(nvm);

#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return WH_ERROR_OK;
}


#endif /* WOLFHSM_CFG_TEST_POSIX */

#endif /* WOLFHSM_CFG_BENCH_ENABLE */