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
 * port/posix/client/user_settings.h
 *
 * wolfSSL compile-time options for the POSIX generic client.
 */

#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/** wolfHSM Client required settings */

/* CryptoCB support */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1

/* Key DER export/import support */
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE

/* C90 compatibility, which doesn't support inline keyword */
#define NO_INLINE
/* Suppresses warning in evp.c */
#define WOLFSSL_IGNORE_FILE_WARN

/* Either NO_HARDEN or set resistance and blinding */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/** Application Settings */

/* Crypto Algo Options */
#define HAVE_CURVE25519
#define HAVE_ECC
#define HAVE_AES_CBC
#define WOLFSSL_AES_COUNTER
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_CMAC
#define HAVE_HKDF

/* Disable PKCS12 (not needed for HSM operations) */
#define NO_PKCS12

/* wolfCrypt test/benchmark settings */
#define NO_MAIN_DRIVER
#define NO_FILESYSTEM

/* Include to ensure clock_gettime is declared for benchmark.c */
#include <time.h>
/* Include to support strcasecmp with POSIX build */
#include <strings.h>

#endif /* USER_SETTINGS_H_ */
