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
 * user_settings.h
 *
 * Configured to support library testing
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/** Settings specific to the host arch, OS, and compiler */
/* #define BIG_ENDIAN_ORDER */
/* #define SINGLE_THREADED */
/* #define WC_NO_ASYNC_THREADING */

/** wolfHSM required settings for wolfCrypt */
#define WOLFCRYPT_ONLY
#define WOLF_CRYPTO_CB
#define HAVE_HASHDRBG
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

/** Math library selection for test */
#define USE_FAST_MATH

/** wolfHSM recommended */
#define WOLFSSL_NO_MALLOC
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/** Remove unneeded features*/
#define NO_MAIN_DRIVER
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_FILESYSTEM
#define NO_INLINE
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define NO_DO178

/** Remove unneded namespace */
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/** RSA Options */
/* #define NO_RSA  */
#define HAVE_RSA
#define WOLFSSL_KEY_GEN
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define FP_MAX_BITS 4096

/** ECC Options */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_SUPPORTED_CURVES

/** Curve25519 Options */
#define HAVE_CURVE25519

/** DH and DHE Options */
#define NO_DH
#define HAVE_DH_DEFAULT_PARAMS
#define HAVE_FFDHE_2048

/** AES Options */
#define HAVE_AES
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_CMAC

/** SHA Options */
#define NO_SHA
/* #define WOLFSSL_SHA384 */
/* #define WOLFSSL_SHA512 */
#define WOLFSSL_HASH_FLAGS

/** Composite features */
#define HAVE_HKDF

/* Remove unneeded crypto */
#define NO_DSA
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_PWDBASED


/* Allows custom "custom_time()" function to be used for benchmark */
/*
#define WOLFSSL_USER_CURRTIME
#define USER_TICKS
#define HAVE_WC_INTROSPECTION
*/

/* Standard Lib - C89 */
/*
#define XSTRCASECMP(s1,s2) strcmp((s1),(s2))
*/

/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */
#if 0
    /* Static memory requires fast math or SP math with no malloc */
    #define WOLFSSL_STATIC_MEMORY

    /* Disable fallback malloc/free */
    #define WOLFSSL_NO_MALLOC
    #if 1
        #define WOLFSSL_MALLOC_CHECK /* trap malloc failure */
    #endif
#endif


#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
