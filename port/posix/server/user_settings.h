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
 * port/posix/server/user_settings.h
 *
 * wolfSSL compile-time options for the POSIX generic server.
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/** wolfHSM required settings for wolfCrypt */
#define WOLF_CRYPTO_CB
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

/* These macros reduce footprint size when TLS functionality is not needed */
#define NO_TLS
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_TLS12
#define NO_PSK

/* For ACert support (also requires WOLFSSL_ASN_TEMPLATE) */
#define WOLFSSL_ACERT

/** Math library selection */
#define USE_FAST_MATH

/** wolfHSM recommended */
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/** Remove unneeded features */
#define NO_MAIN_DRIVER
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_INLINE
#define NO_OLD_TLS
#define NO_DO178
#define WC_NO_DEFAULT_DEVID

/** Remove unneeded namespace */
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/** RSA Options */
#define RSA_MIN_SIZE 1024
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define FP_MAX_BITS 8192

/** ECC Options */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR

/** Curve25519 Options */
#define HAVE_CURVE25519

/** Ed25519 Options */
#define HAVE_ED25519

/** DH and DHE Options */
#define HAVE_DH_DEFAULT_PARAMS
#define HAVE_FFDHE_2048

/** AES Options */
#define HAVE_AESGCM
#define WOLFSSL_AES_COUNTER
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_CMAC

/** SHA Options */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA512_HASHTYPE

/* Dilithium Options */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/** Composite features */
#define HAVE_HKDF
#define HAVE_CMAC_KDF

/* Remove unneeded crypto */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5

/* POSIX version of strcasecmp */
#include <strings.h>

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
