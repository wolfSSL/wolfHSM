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
 *
 * Shared helpers used by both the Classic and Adaptive ports:
 *
 *   - wh_Autosar_IsVerifyRejection: classifies a wolfHSM client
 *     negative return code as a wolfCrypt-side signature rejection
 *     (translatable to E_OK + verifyPtr=NOT_OK) versus a wolfHSM
 *     transport-level error.
 *
 *   - wh_Autosar_ConstantCompare: constant-time byte compare for
 *     authenticated-value equality (MAC verify, RSA recovered hash
 *     comparison). Uses the OR-of-XOR construction so timing is a
 *     function of length only, not of where the first mismatching
 *     byte sits.
 *
 * Header-only so the C dispatcher and the C++ Adaptive provider link
 * a single copy each via static inline.
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
    return (rc < 0 && rc > -2000) ? 1 : 0;
}

/* Constant-time byte comparison. Returns 1 iff every byte of a[0..n-1]
 * equals b[0..n-1]. Timing depends only on n, not on the contents.
 * Use this for any equality check whose result is observable to an
 * attacker (MAC verify, RSA-PKCS1 v1.5 recovered-hash compare, etc.). */
static inline int wh_Autosar_ConstantCompare(const uint8_t* a, const uint8_t* b,
                                             size_t n)
{
    size_t  i;
    uint8_t diff = 0u;
    for (i = 0u; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WH_AUTOSAR_SAFE_COMPARE_H_ */
