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

/* Endian-translation coverage for the NVM message structs. A loopback test
 * cannot observe peers that disagree on byte order, so these call the
 * translation helpers directly with the magic of a foreign-endian peer. */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message_nvm.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Magic of a peer whose byte order is the opposite of ours */
#define WH_TEST_MAGIC_FOREIGN ((uint16_t)WH_COMM_MAGIC_SWAP)
#define WH_TEST_MAGIC_LOCAL ((uint16_t)WH_COMM_MAGIC_NATIVE)

/* Non-palindromic field values, and the same values byte-reversed */
#define WH_TEST_NVM_META_ID 0x0102u
#define WH_TEST_NVM_META_ACCESS 0x1234u
#define WH_TEST_NVM_META_FLAGS 0x5678u
#define WH_TEST_NVM_META_LEN 0x0a0bu

#define WH_TEST_NVM_META_ID_SWAPPED 0x0201u
#define WH_TEST_NVM_META_ACCESS_SWAPPED 0x3412u
#define WH_TEST_NVM_META_FLAGS_SWAPPED 0x7856u
#define WH_TEST_NVM_META_LEN_SWAPPED 0x0b0au

/* Fill with distinct byte values so any missed swap is visible */
static void _whTest_FillPattern(uint8_t* buf, uint32_t len, uint8_t seed)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

/* The key wrap messages carry this struct raw, so every scalar swaps and the
 * label, a plain byte array, must stay put */
static int _whTest_MessageNvmMetadata(void)
{
    whNvmMetadata src;
    whNvmMetadata dest;
    whNvmMetadata back;

    memset(&src, 0, sizeof(src));
    memset(&dest, 0, sizeof(dest));
    memset(&back, 0, sizeof(back));

    src.id     = (whNvmId)WH_TEST_NVM_META_ID;
    src.access = (whNvmAccess)WH_TEST_NVM_META_ACCESS;
    src.flags  = (whNvmFlags)WH_TEST_NVM_META_FLAGS;
    src.len    = (whNvmSize)WH_TEST_NVM_META_LEN;
    _whTest_FillPattern(src.label, (uint32_t)sizeof(src.label), 0x70);

    /* A same-endian peer must see the metadata unchanged */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageNvm_TranslateMetadata(WH_TEST_MAGIC_LOCAL, &src, &dest));
    WH_TEST_ASSERT_RETURN(memcmp(&dest, &src, sizeof(src)) == 0);

    /* A cross-endian peer swaps every scalar. The expected values are written
     * out rather than derived, so they do not share the code under test */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageNvm_TranslateMetadata(WH_TEST_MAGIC_FOREIGN, &src, &dest));
    WH_TEST_ASSERT_RETURN(dest.id == (whNvmId)WH_TEST_NVM_META_ID_SWAPPED);
    WH_TEST_ASSERT_RETURN(dest.access ==
                          (whNvmAccess)WH_TEST_NVM_META_ACCESS_SWAPPED);
    WH_TEST_ASSERT_RETURN(dest.flags ==
                          (whNvmFlags)WH_TEST_NVM_META_FLAGS_SWAPPED);
    WH_TEST_ASSERT_RETURN(dest.len == (whNvmSize)WH_TEST_NVM_META_LEN_SWAPPED);
    WH_TEST_ASSERT_RETURN(memcmp(dest.label, src.label, sizeof(src.label)) ==
                          0);

    /* Translation is its own inverse */
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageNvm_TranslateMetadata(WH_TEST_MAGIC_FOREIGN, &dest, &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &src, sizeof(src)) == 0);

    /* In-place translation must give the same result */
    memcpy(&back, &src, sizeof(back));
    WH_TEST_RETURN_ON_FAIL(
        wh_MessageNvm_TranslateMetadata(WH_TEST_MAGIC_FOREIGN, &back, &back));
    WH_TEST_ASSERT_RETURN(memcmp(&back, &dest, sizeof(src)) == 0);

    WH_TEST_ASSERT_RETURN(wh_MessageNvm_TranslateMetadata(
                              WH_TEST_MAGIC_FOREIGN, NULL, &dest) ==
                          WH_ERROR_BADARGS);
    WH_TEST_ASSERT_RETURN(wh_MessageNvm_TranslateMetadata(
                              WH_TEST_MAGIC_FOREIGN, &src, NULL) ==
                          WH_ERROR_BADARGS);

    return WH_TEST_SUCCESS;
}

int whTest_MessageNvmTranslate(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing NVM message translation...\n");

    WH_TEST_RETURN_ON_FAIL(_whTest_MessageNvmMetadata());

    return WH_TEST_SUCCESS;
}
