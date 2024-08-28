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

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/ecc.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"

#include "wolfhsm/wh_crypto.h"

#ifdef HAVE_ECC
int wh_Crypto_SerializeEccKey(ecc_key* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size)
{
    int ret = 0;

    if (    (key == NULL) ||
            (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }
#if 1
    int der_size = 0;
    der_size = wc_EccKeyToDer(key, (byte*)buffer, (word32)max_size);
    if (der_size >= 0) {
        printf("Serialized private and public keys\n");
        ret = 0;
        if (out_size != NULL) {
            *out_size = der_size;
        }
    } else  if (der_size == ECC_PRIVATEONLY_E) {
        /* Private only.  ok. */
        der_size = wc_EccPrivateKeyToDer(key, (byte*)buffer, (word32)max_size);
        printf("Serialized private key\n");
        ret = 0;
        if (out_size != NULL) {
            *out_size = der_size;
        }
    } else {
        /* Error private serializing.  Try it as a public key only */
        printf("Problem serializing private key:%d\n", der_size);

        der_size = wc_EccPublicKeyToDer(key, (byte*)buffer, (word32)max_size, 1);
        if (der_size >= 0) {
            ret = 0;
            if (out_size != NULL) {
                *out_size = der_size;
            }
            printf("Serialized public key\n");

        } else {
            /* Error serializing.  Clear the buffer */
            ret = der_size;
            printf("Problem serializing public key:%d\n", der_size);
            memset(buffer, 0, max_size);
        }
    }
#else
    word32 len = max_size;
    ret = wc_ecc_export_x963(key, buffer, &len);
    if (ret == 0) {
        if(out_size != NULL) {
            *out_size = len;
        }
        wh_Utils_Hexdump("Crypto_SerializeEccKey:\n", buffer, len);
    }
#endif
    return ret;
}

int wh_Crypto_DeserializeEccKey(uint16_t size, const uint8_t* buffer,
        ecc_key* key)
{
    int ret;

    if (    (size == 0) ||
            (buffer == NULL) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }
#if 1
    word32 idx = 0;
    /* Update the key structure */
    ret = wc_EccPrivateKeyDecode(
            buffer, &idx,
            key,
            size);
    if (ret == 0) {
        printf("Private key decode type:%d\n", key->type);
        /* Determine if this was a private only key */
/*
        key->type = ECC_PRIVATEKEY_ONLY;
        key->type = ECC_PRIVATEKEY;
        */
    } else  {
        /* Try it as a public only */
        idx = 0;
        ret = wc_EccPublicKeyDecode(
                buffer, &idx,
                key,
                size);
        if (ret == 0) {
            printf("Public key decode type:%d\n", key->type);
            /* Public only key */
            key->type = ECC_PUBLICKEY;

        }
    }
#else
    wh_Utils_Hexdump("Crypto_DerializeEccKey:\n", (uint8_t*)buffer, size);

    ret = wc_ecc_import_x963(buffer, size, key);
#endif
    return ret;
}
#endif /* HAVE_ECC */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
