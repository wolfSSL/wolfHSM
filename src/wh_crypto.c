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
int wh_Crypto_EccSerializeKeyDer(ecc_key* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size)
{
    int ret = 0;

    if (    (key == NULL) ||
            (buffer == NULL)) {
        return WH_ERROR_BADARGS;
    }

    switch (key->type) {
    case ECC_PUBLICKEY:
        ret = wc_EccPublicKeyToDer(key, (byte*)buffer, (word32)max_size, 1);
        break;
    case ECC_PRIVATEKEY:
        ret = wc_EccKeyToDer(key, (byte*)buffer, (word32)max_size);
        break;
    case ECC_PRIVATEKEY_ONLY:
        ret = wc_EccPrivateKeyToDer(key, (byte*)buffer, (word32)max_size);
        break;
    default:
        ret = WH_ERROR_BADARGS;
    }
    if (ret >= 0) {
        if (out_size != NULL) {
            *out_size = (uint16_t)ret;
        }
        ret = WH_ERROR_OK;
    }
    return ret;
}

int wh_Crypto_EccDeserializeKeyDer(const uint8_t* buffer, uint16_t size,
        ecc_key* key)
{
    int ret;
    word32 idx = 0;

    if (    (size == 0) ||
            (buffer == NULL) ||
            (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Try decoding as a key pair or private only */
    ret = wc_EccPrivateKeyDecode(buffer, &idx, key, size);
    if (ret != 0) {
        /* Try it as a public only */
        idx = 0;
        ret = wc_EccPublicKeyDecode(buffer, &idx, key, size);
    }
    return ret;
}

int wh_Crypto_UpdatePrivateOnlyEccKey(ecc_key* key, uint16_t pub_size,
        const uint8_t* pub_buffer)
{
    int ret = 0;
    ecc_key pub_only[1];
    word32 idx = 0;
    uint8_t x[ECC_MAXSIZE];
    word32 x_len = sizeof(x);
    uint8_t y[ECC_MAXSIZE];
    word32 y_len = sizeof(y);
    uint8_t d[ECC_MAXSIZE];
    word32 d_len = sizeof(d);
    int curve_id;

    if (    (key == NULL) ||
            ((pub_size > 0) && (pub_buffer == NULL)) ) {
        return WH_ERROR_BADARGS;
    }
    if (key->type != ECC_PRIVATEKEY_ONLY) {
        /* No need to update anything */
        return 0;
    }

    curve_id = wc_ecc_get_curve_id(key->idx);
    if (curve_id < 0) {
        ret = curve_id;
    }
    /* TODO: Find more efficient way to doing this */
    if (ret == 0) {
        ret = wc_ecc_export_private_only(key, d, &d_len);
    }
    if (ret == 0) {
        ret = wc_ecc_init(pub_only);
        if (ret == 0) {
            ret = wc_EccPublicKeyDecode(pub_buffer, &idx, pub_only, pub_size);
        }
        if (ret == 0) {
            ret = wc_ecc_export_public_raw(pub_only, x, &x_len, y, &y_len);
        }
        if (ret == 0) {
            ret = wc_ecc_import_unsigned(key, x, y, d, curve_id);
        }
        wc_ecc_free(pub_only);
    }

    return ret;
}
#endif /* HAVE_ECC */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */
