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
 * wolfhsm_cfg.h
 *
 * wolfHSM compile-time options for the test-refactor suite. Sibling of
 * test/config/wolfhsm_cfg.h; the two are intentionally allowed to diverge
 * as the refactor matures.
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_

#include "port/posix/posix_time.h"
#define WOLFHSM_CFG_PORT_GETTIME posixGetTime

#ifndef WOLFHSM_CFG_COMM_DATA_LEN
#define WOLFHSM_CFG_COMM_DATA_LEN (1024 * 8)
#endif

/* Disable global keys if WOLFHSM_CFG_TEST_NO_GLOBAL_KEYS is set */
#ifndef WOLFHSM_CFG_TEST_NO_GLOBAL_KEYS
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

#define WOLFHSM_CFG_LOGGING

#define WOLFHSM_CFG_NVM_OBJECT_COUNT 64
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 9
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 300
#define WOLFHSM_CFG_DMAADDR_COUNT 8
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 6

#define WOLFHSM_CFG_CERTIFICATE_MANAGER
#define WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT

#define WOLFHSM_CFG_SERVER_IMG_MGR

#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_HWKEYSTORE
#endif

/* Test-only SHE key management APIs. Bypass authenticated update protocols. */
#define WOLFHSM_CFG_SHE_ENABLE_TEST_KEY_MGMT

/* Test log-based NVM flash backend */
#define WOLFHSM_CFG_SERVER_NVM_FLASH_LOG

/* WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS is intentionally NOT
 * defined here. Not implemented yet. */

#define WOLFHSM_CFG_ENABLE_TIMEOUT

/* Route the single-line cache operations to a recorder, so
 * misc/wh_test_cache.c can check which lines wh_Utils_CacheFlush and
 * wh_Utils_CacheInvalidate visit. The recorder only stores addresses while
 * that test runs, otherwise these are no-ops like the defaults. */
#define WOLFHSM_CFG_TEST_CACHE_RECORD
#include <stdint.h>
void whTest_CacheRecord(int invalidate, uintptr_t addr);
#define XCACHEFLUSH(_p) whTest_CacheRecord(0, (uintptr_t)(_p))
#define XCACHEINVLD(_p) whTest_CacheRecord(1, (uintptr_t)(_p))

#endif /* WOLFHSM_CFG_H_ */
