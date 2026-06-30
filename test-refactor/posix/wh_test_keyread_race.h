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
 * test-refactor/posix/wh_test_keyread_race.h
 *
 * Concurrent cached-key read test. See the .c file for details.
 */

#ifndef WH_TEST_KEYREAD_RACE_H_
#define WH_TEST_KEYREAD_RACE_H_

/* Self-contained: spins up its own shared NVM and N client/server pairs.
 * Matches the whTestGroup_RunOne() entry-point contract; ctx is unused.
 * Returns WH_TEST_SUCCESS, WH_TEST_SKIPPED when the required build features
 * are absent, or a negative error code on failure. */
int whTest_KeyReadRace(void* ctx);

#endif /* WH_TEST_KEYREAD_RACE_H_ */
