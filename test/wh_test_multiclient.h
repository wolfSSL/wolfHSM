/*
 * Copyright (C) 2025 wolfSSL Inc.
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
#ifndef WH_TEST_MULTICLIENT_H_
#define WH_TEST_MULTICLIENT_H_

/**
 * @brief Multi-client test framework and test suite
 *
 * This test module provides a framework for testing features that require
 * multiple clients connecting to separate servers sharing a common NVM context.
 *
 * The framework provides generic setup/teardown for:
 * - Two client contexts with separate transport memory configs
 * - Two server contexts sharing a single NVM context
 * - Shared flash/NVM and crypto initialization
 * - Sequential single-threaded test execution using memory transport
 *
 * Current test suites:
 * - Global keys: Tests shared key functionality across multiple clients
 *
 * Future test suites can be added for features like:
 * - Access control policies
 * - Shared counter synchronization
 * - Cross-client key operations
 *
 * @return 0 on success, error code on failure
 */
int whTest_MultiClient(void);

#endif /* WH_TEST_MULTICLIENT_H_ */
