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
 * port/template/server/user_settings.h
 *
 * Template wolfSSL compile-time options for a server build.
 * The server typically needs a broader set of crypto algorithms than the
 * client since it must support all operations clients may request.
 */

#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/** wolfHSM required settings */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE

/* TLS is not needed for wolfHSM server operation */
#define NO_TLS
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_TLS12
#define NO_PSK

/** Math library selection
 * TODO: Choose the math library appropriate for your platform.
 * USE_FAST_MATH is recommended for most platforms. */
#define USE_FAST_MATH

/** wolfHSM recommended */
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_IGNORE_FILE_WARN
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* C90 compatibility */
#define NO_INLINE
#define NO_MAIN_DRIVER

/** Remove unneeded features
 * TODO: Adjust based on your requirements. */
#define NO_ERROR_STRINGS
#define NO_ERROR_QUEUE
#define NO_OLD_TLS
#define NO_DO178
#define WC_NO_DEFAULT_DEVID
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

/** Crypto algorithm selection
 * TODO: Enable the algorithms your application needs. The server should
 * support all algorithms that any client may request. */
/* #define HAVE_ECC */
/* #define TFM_ECC256 */
/* #define ECC_SHAMIR */
/* #define HAVE_CURVE25519 */
/* #define HAVE_ED25519 */
/* #define HAVE_AESGCM */
/* #define WOLFSSL_AES_COUNTER */
/* #define WOLFSSL_AES_DIRECT */
/* #define HAVE_AES_ECB */
/* #define WOLFSSL_CMAC */
/* #define HAVE_HKDF */

/** Remove unneeded crypto
 * TODO: Disable algorithms you don't need. */
#define NO_DSA
#define NO_RC4
#define NO_MD4

#endif /* USER_SETTINGS_H_ */
