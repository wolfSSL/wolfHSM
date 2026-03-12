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
 * test/wh_test_timeout.h
 *
 */

#ifndef TEST_WH_TEST_TIMEOUT_H_
#define TEST_WH_TEST_TIMEOUT_H_

#include "wolfhsm/wh_client.h"

/**
 * Runs timeout module tests against the given client configuration.
 *
 * @param[in] config Client configuration with timeout support enabled.
 * @return 0 on success and a non-zero error code on failure.
 */
int whTest_TimeoutClientConfig(whClientConfig* config);

/**
 * Runs timeout tests using a default POSIX configuration.
 *
 * @return 0 on success and a non-zero error code on failure.
 */
int whTest_TimeoutPosix(void);

#endif /* TEST_WH_TEST_TIMEOUT_H_ */
