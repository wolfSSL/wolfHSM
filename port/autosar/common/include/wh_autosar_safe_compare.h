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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Boundary between "verification failed" and "transport failed".
 *
 * wolfHSM's own error space (see wolfhsm/wh_error.h) starts at
 * WH_ERROR_NOTREADY = -2001 and walks downward (-2002 BADARGS,
 * -2003 LOCKED, ...). Every wolfHSM transport / dispatch / protocol
 * error therefore satisfies rc <= -2000.
 *
 * Everything in the range -1 ... -1999 originates from wolfCrypt's
 * own error.h (and the libtommath / ASN sub-ranges it tunnels):
 * BAD_FUNC_ARG (-173), ASN_PARSE_E (~-140), SIG_VERIFY_E, MP_VAL,
 * AES_GCM_AUTH_E (~-180), BAD_PADDING_E, and so on. For the verify
 * and AEAD-decrypt primitives every one of these is a "the
 * cryptography rejected the input", not "the API itself failed", so
 * AUTOSAR-shaped callers surface them as `E_OK + verifyPtr=NOT_OK`
 * rather than `E_NOT_OK`.
 *
 * The boundary is exact (rc > -2000 selects the wolfCrypt range) but
 * load-bearing: if either project ever extends its error space across
 * the -2000 line, this helper and every caller of it has to be
 * revisited. The wolfHSM client guards (-2001..) and the wolfSSL
 * upper-bound (currently around -300 with plenty of headroom) make
 * that unlikely in the near term. */
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
