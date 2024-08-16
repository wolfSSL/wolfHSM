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
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"


#ifndef NO_RSA
/* Store a RsaKey to a byte sequence (currently DER format) */
int wh_Crypto_SerializeRsaKey(RsaKey* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
/* Restore a RsaKey from a byte sequence (currently DER format) */
int wh_Crypto_DeserializeRsaKey(uint16_t size, const uint8_t* buffer,
        RsaKey* key);
#endif /* !NO_RSA */


#ifdef HAVE_CURVE25519
/* Store a curve25519_key to a byte sequence */
int wh_Crypto_SerializeCurve25519Key(curve25519_key* key,
        uint16_t max_size, uint8_t* buffer, uint16_t *out_size);
/* Restore a curve25519_key from a byte sequence */
int wh_Crypto_DeserializeCurve25519Key(uint16_t size,
        const uint8_t* buffer, curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_WH_CRYPTO_H_ */

