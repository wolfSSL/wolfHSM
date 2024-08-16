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
 * src/wh_crypto.c
 *
 * Common crypto functions for both the client and server
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */
#include <string.h>  /* For memset, memcpy */

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_crypto.h"

#ifndef NO_RSA

int wh_Crypto_SerializeRsaKey(RsaKey* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size)
{
    int ret = 0;
    int der_size = 0;

    if (    (key == NULL) ||
            (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }

    der_size = wc_RsaKeyToDer(key, buffer, max_size);
    if (der_size >= 0) {
        ret = 0;
        if (out_size != NULL) {
            *out_size = der_size;
        }
    } else {
        /* Error serializing.  Clear the buffer */
        ret = der_size;
        memset(buffer, 0, max_size);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[server] SerializeRsaKey: ret:%d key_size:%d der_size:%u\n",
            ret, wc_RsaEncryptSize(key), der_size);
#endif

    return ret;
}

int wh_Crypto_DeserializeRsaKey(uint16_t size, const uint8_t* buffer,
        RsaKey* key)
{
    int ret;
    word32 idx = 0;

    if (    (size == 0) ||
            (buffer == NULL) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }
    /* Deserialize the RSA key */
    ret = wc_RsaPrivateKeyDecode(buffer, &idx, key, size);
    return ret;
}

#endif /* !NO_RSA */


#ifdef HAVE_CURVE25519
 int wh_Crypto_SerializeCurve25519Key(curve25519_key* key,
        uint16_t max_size, uint8_t* buffer, uint16_t *out_size)
{
    int ret = 0;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_KEYSIZE;

    if (    (key == NULL) ||
            (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_curve25519_export_key_raw(key,
            buffer + CURVE25519_KEYSIZE, &privSz,
            buffer, &pubSz);
    if (    (ret == 0) &&
            (out_size != NULL)) {
        *out_size = CURVE25519_KEYSIZE * 2;
    }
    return ret;
}

int wh_Crypto_DeserializeCurve25519Key(uint16_t size,
        const uint8_t* buffer, curve25519_key* key)
{
    int ret = 0;
    word32 privSz = CURVE25519_KEYSIZE;
    word32 pubSz = CURVE25519_KEYSIZE;

    if (    (size < CURVE25519_KEYSIZE) ||
            (buffer == NULL) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* decode the key */
    if (ret == 0)
        ret = wc_curve25519_import_public(
                buffer,
                pubSz,
                key);
    /* only import private if what we got back holds 2 keys */
    if (    (ret == 0) &&
            (size == CURVE25519_KEYSIZE * 2)) {
        ret = wc_curve25519_import_private(
                buffer + CURVE25519_KEYSIZE,
                privSz,
                key);
    }
    return ret;
}
#endif /* HAVE_CURVE25519 */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
