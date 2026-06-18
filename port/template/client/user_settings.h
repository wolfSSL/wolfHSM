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
 * port/template/client/user_settings.h
 *
 * Template wolfSSL compile-time options for a client build.
 * Enable the crypto algorithms and features your application requires.
 */

#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/** wolfHSM required settings */
#define WOLF_CRYPTO_CB
#define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_BASE64_ENCODE

/* C90 compatibility */
#define NO_INLINE
#define WOLFSSL_IGNORE_FILE_WARN

/* Side-channel resistance */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/** Crypto algorithm selection
 * TODO: Enable the algorithms your application needs. Common choices: */
/* #define HAVE_ECC */
/* #define HAVE_CURVE25519 */
/* #define HAVE_AES_CBC */
/* #define HAVE_AESGCM */
/* #define WOLFSSL_AES_COUNTER */
/* #define WOLFSSL_AES_DIRECT */
/* #define WOLFSSL_CMAC */
/* #define HAVE_HKDF */

/** Platform settings
 * TODO: Adjust for your platform. */
#define NO_MAIN_DRIVER
/* #define NO_FILESYSTEM */

#endif /* USER_SETTINGS_H_ */
