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
 * test/wh_test_posix_threadsafe_stress.h
 *
 * POSIX multithreaded stress test for thread safety validation.
 * This test uses POSIX threading primitives (pthreads).
 */

#ifndef TEST_WH_TEST_POSIX_THREADSAFE_STRESS_H_
#define TEST_WH_TEST_POSIX_THREADSAFE_STRESS_H_

/*
 * Runs multithreaded stress tests for thread safety validation.
 * Tests concurrent access to shared NVM and global key cache from
 * multiple client threads via separate server contexts.
 *
 * Requires: WOLFHSM_CFG_THREADSAFE, WOLFHSM_CFG_TEST_POSIX,
 *           WOLFHSM_CFG_GLOBAL_KEYS
 *
 * Returns 0 on success, non-zero on failure.
 */
int whTest_ThreadSafeStress(void);

#endif /* TEST_WH_TEST_POSIX_THREADSAFE_STRESS_H_ */
