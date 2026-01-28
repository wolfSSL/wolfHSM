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
 * test/wh_test_lock.h
 *
 * Thread-safety lock tests
 */
#ifndef TEST_WH_TEST_LOCK_H_
#define TEST_WH_TEST_LOCK_H_

#include "wolfhsm/wh_lock.h" /* For whLockConfig type */

/*
 * Runs all lock tests using the supplied lock configuration.
 *   - Tests lock lifecycle (init/cleanup) if lockConfig is not NULL
 *   - Tests NULL config results in no-op locking
 *   - Tests NVM with lock config
 *
 * @param lockConfig Pointer to lock configuration. If NULL, the lock lifecycle
 *                   test will be skipped but other tests will still run.
 * Returns 0 on success, and a non-zero error code on failure
 */
int whTest_LockConfig(whLockConfig* lockConfig);

#if defined(WOLFHSM_CFG_TEST_POSIX)

/*
 * Runs all lock tests using the POSIX lock backend ontop of POSIX sim
 *   - Tests lock lifecycle (init/cleanup)
 *   - Tests NULL config results in no-op locking
 *   - Tests NVM with lock config
 * Returns 0 on success, and a non-zero error code on failure
 */
int whTest_LockPosix(void);
#endif /* WOLFHSM_CFG_TEST_POSIX */

#endif /* TEST_WH_TEST_LOCK_H_ */
