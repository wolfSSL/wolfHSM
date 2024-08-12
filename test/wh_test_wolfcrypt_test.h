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
 * test/wh_test_wolfcrypt_test.h
 *
 */

#ifndef TEST_WH_TEST_WOLFCRYPT_TEST_H_
#define TEST_WH_TEST_WOLFCRYPT_TEST_H_

/*
 * Runs wolfCrypt test suite on top of wolfHSM using a memory transport backend.
 * and optionally the POSIX TCP backent if WOLFHSM_CFG_TEST_POSIX is defined
 *
 * Returns 0 on success and a non-zero error code on failure
 */
int whTest_WolfCryptTestCfg(whClientConfig* config);
int whTest_WolfCryptTest(void);

#endif /* TEST_WH_TEST_WOLFCRYPT_TEST_H_ */
