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
 * wolfHSM compile-time options.  Override here for your application
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_

#include "port/posix/posix_time.h"
#define WOLFHSM_CFG_PORT_GETTIME posixGetTime


/** wolfHSM settings.  Simple overrides to show they work */
/* #define WOLFHSM_CFG_NO_CRYPTO */
/* #define WOLFHSM_CFG_SHE_EXTENSION */

#define WOLFHSM_CFG_COMM_DATA_LEN (1024 * 8)

/* Enable global keys feature for testing. NOGLOBALKEYS=1 builds leave it
 * disabled to cover that configuration. */
#ifndef WOLFHSM_CFG_TEST_NO_GLOBAL_KEYS
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

/* Enable logging feature for testing */
#define WOLFHSM_CFG_LOGGING

#define WOLFHSM_CFG_NVM_OBJECT_COUNT 64
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 9
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 300
#define WOLFHSM_CFG_DMAADDR_COUNT 8
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 6

#define WOLFHSM_CFG_CERTIFICATE_MANAGER
#define WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT

/* Enable Image Manager feature */
#define WOLFHSM_CFG_SERVER_IMG_MGR

#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_HWKEYSTORE
#endif

/* Test log-based NVM flash backend */
#define WOLFHSM_CFG_SERVER_NVM_FLASH_LOG

/* Allow persistent NVM artifacts in tests */
#define WOLFHSM_CFG_TEST_ALLOW_PERSISTENT_NVM_ARTIFACTS

/* Enable SHE preprogram/destroy test-only key-management APIs. These bypass
 * the authenticated SHE key-update protocol and are not part of the SHE
 * specification, so they must never be enabled in production builds. */
#define WOLFHSM_CFG_SHE_ENABLE_TEST_KEY_MGMT

#define WOLFHSM_CFG_ENABLE_TIMEOUT

#endif /* WOLFHSM_CFG_H_ */
