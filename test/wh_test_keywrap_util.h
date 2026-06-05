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
 * test/wh_test_keywrap_util.h
 *
 * Helpers shared by the keywrap and SHE test suites (test/ and test-refactor/)
 * so the trusted-KEK test bytes and the wrapped-blob layout live in one place.
 */
#ifndef WH_TEST_KEYWRAP_UTIL_H_
#define WH_TEST_KEYWRAP_UTIL_H_

#include <stdint.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h" /* whKeyId */

/* KEK bytes shared by the keywrap/SHE tests. Each suite provisions this key
 * server-side (in NVM or the cache, with WH_NVM_FLAGS_TRUSTED) as its trusted
 * KEK and, where it builds blobs itself, wraps under the same bytes. The
 * bytes are fixed but arbitrary. */
extern const uint8_t whTest_KeywrapKek[32];

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && defined(WOLFHSM_CFG_KEYWRAP) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)
/* Build an AES-GCM wrapped-key blob for a SHE key the same way the server's
 * KEK would, so a test can drive unwrap-and-cache without first having to get
 * the key into the server. Uses software AES with the known KEK bytes. Blob
 * layout matches the server: [IV(12) || authTag(16) || GCM(metadata || key)].
 * Only defined when AES-GCM is available (HAVE_AESGCM). */
int whTest_BuildSheKeyBlob(const uint8_t* kek, uint32_t kekSz, whKeyId sheKeyId,
                           uint32_t counter, uint32_t sheFlags,
                           const uint8_t* keyBytes, uint8_t* blobOut,
                           uint16_t* blobInOutSz);
#endif /* WOLFHSM_CFG_SHE_EXTENSION && WOLFHSM_CFG_KEYWRAP && \
          !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WH_TEST_KEYWRAP_UTIL_H_ */
