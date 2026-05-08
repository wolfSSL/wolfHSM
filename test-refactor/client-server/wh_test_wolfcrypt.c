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
 * test-refactor/client-server/wh_test_wolfcrypt.c
 *
 * Runs the upstream wolfCrypt test suite against a live wolfHSM
 * client. The Makefile sets WC_USE_DEVID so wolfCrypt routes its
 * ops through the cryptocb the client registered at init time.
 */

#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/test/test.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

int whTest_WolfCryptTest(whClientContext* ctx)
{
    (void)ctx;
    return (int)wolfcrypt_test(NULL);
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_TEST_WOLFCRYPTTEST */
