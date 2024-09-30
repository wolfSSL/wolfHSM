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
 * wolfhsm/wh_crypto.h
 *
 * Common crypto functions for both the client and server
 *
 */

#ifndef WOLFHSM_WH_CRYPTO_H_
#define WOLFHSM_WH_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"

#ifndef NO_AES
int wh_Crypto_SerializeAesKey(Aes* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
int wh_Crypto_DeserializeAesKey(uint16_t size, const uint8_t* buffer,
        Aes* key);
#endif /* !NO_AES */

#ifndef NO_RSA
/* Store a RsaKey to a byte sequence (currently DER format) */
int wh_Crypto_RsaSerializeKeyDer(const RsaKey* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
/* Restore a RsaKey from a byte sequence (currently DER format) */
int wh_Crypto_RsaDeserializeKeyDer(uint16_t size, const uint8_t* buffer,
        RsaKey* key);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/* Store an ecc_key to a byte sequence */
int wh_Crypto_EccSerializeKeyDer(ecc_key* key,
        uint16_t max_size, uint8_t* buffer, uint16_t *out_size);

/* Restore an ecc_key from a byte sequence */
int wh_Crypto_EccDeserializeKeyDer(const uint8_t* buffer, uint16_t pub_size,
        ecc_key* key);

/* Helper to update an ECC private-only key with the corresponding public key,
 * similiar to wc_ecc_make_pub().  The incoming byte array of the public key is
 * expected to have been exported using wc_EccPublicKeyToDer().
 */
int wh_Crypto_EccUpdatePrivateOnlyKeyDer(ecc_key* key, uint16_t pub_size,
        const uint8_t* pub_buffer);

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Store a curve25519_key to a byte sequence */
int wh_Crypto_Curve25519SerializeKey(curve25519_key* key,
        uint16_t max_size, uint8_t* buffer, uint16_t *out_size);
/* Restore a curve25519_key from a byte sequence */
int wh_Crypto_Curve25519DeserializeKey(uint16_t size,
        const uint8_t* buffer, curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_WH_CRYPTO_H_ */

