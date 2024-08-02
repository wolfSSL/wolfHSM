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
 * test/wh_test.c
 *
 */

#include <assert.h>
#include <string.h>

#include "wh_test_common.h"

/* Individual unit test drivers */
#include "wh_test_comm.h"
#include "wh_test_flash_ramsim.h"
#include "wh_test_nvm_flash.h"
#include "wh_test_crypto.h"
#include "wh_test_she.h"
#include "wh_test_clientserver.h"

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
#include "wh_test_wolfcrypt_test.h"
#endif


/* Default test args */


int whTest_Unit(void)
{
    printf("Enter unit tests\n");
    /* Component Tests */
    WH_TEST_ASSERT(0 == whTest_Flash_RamSim());
    WH_TEST_ASSERT(0 == whTest_NvmFlash());

    /* Comm tests */
    WH_TEST_ASSERT(0 == whTest_Comm());
    WH_TEST_ASSERT(0 == whTest_ClientServer());

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Crypto Tests */
    WH_TEST_ASSERT(0 == whTest_Crypto());

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    WH_TEST_ASSERT(0 == whTest_She());
#endif /* WOLFHSM_SHE_EXTENTION */

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
    WH_TEST_ASSERT(0 == whTest_WolfCryptTest());
#endif

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

    return 0;
}


#if !defined(WOLFHSM_CFG_TEST_UNIT_NO_MAIN)

int main(void)
{
    return whTest_Unit();
}

#endif
