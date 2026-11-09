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
 * port/autosar/common/include/wh_autosar_safe_compare.h
 */

#ifndef WH_AUTOSAR_SAFE_COMPARE_H_
#define WH_AUTOSAR_SAFE_COMPARE_H_

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 when a verify or AEAD-decrypt rc means the input was rejected
 * (signature, tag or encoding invalid) rather than that the call failed. */
static inline int wh_Autosar_IsVerifyRejection(int rc)
{
    switch (rc) {
        case SIG_VERIFY_E:
        case BAD_PADDING_E:
        case RSA_PAD_E:
        case RSA_BUFFER_E:
        case PSS_SALTLEN_E:
        case AES_GCM_AUTH_E:
        case ASN_PARSE_E:
        case ASN_GETINT_E:
        case ASN_EXPECT_0_E:
        case ASN_INPUT_E:
        case ASN_ECC_KEY_E:
        case ECC_OUT_OF_RANGE_E:
        case MP_VAL:
        case MP_ZERO_E:
            return 1;
        default:
            return 0;
    }
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WH_AUTOSAR_SAFE_COMPARE_H_ */
