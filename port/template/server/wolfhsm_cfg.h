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
 * port/template/server/wolfhsm_cfg.h
 *
 * Template wolfHSM compile-time options for a server build.
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_

/* TODO: Include your platform's time function header and define
 * WOLFHSM_CFG_PORT_GETTIME to a function returning uint64_t microseconds.
 *
 * #include "port/<platform>/<platform>_time.h"
 * #define WOLFHSM_CFG_PORT_GETTIME myPlatformGetTime
 */

/* TODO: Define a printf-like function for your platform if the default
 * stdlib printf is not available.
 *
 * #define WOLFHSM_CFG_PRINTF myPlatformPrintf
 */

/** Port configuration
 * TODO: Set these to match your platform. */
#define WOLFHSM_CFG_PORT_SERVER_ID      57
#define WOLFHSM_CFG_PORT_SERVER_COUNT   1
/* TODO: Add transport-specific defines here, e.g.:
 * #define WOLFHSM_CFG_PORT_TCP_PORT      23456
 * #define WOLFHSM_CFG_PORT_TCP_IPSTRING  "127.0.0.1"
 */

/* TODO: Define flash size for NVM storage. Example for RAM simulation:
 * #define WOLFHSM_CFG_PORT_FLASH_RAM_SIZE (1024 * 1024)
 */

/** wolfHSM settings */
#define WOLFHSM_CFG_ENABLE_SERVER

/* Communication data length — must match client */
#define WOLFHSM_CFG_COMM_DATA_LEN              5000

/* NVM object count — must match client */
#define WOLFHSM_CFG_NVM_OBJECT_COUNT            30

/** Server resource configuration */
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT        9
#define WOLFHSM_CFG_SERVER_KEYCACHE_SIZE         1024
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT    5
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE  4096
#define WOLFHSM_CFG_SERVER_DMAADDR_COUNT         8
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT        6

/* TODO: Uncomment if your platform needs a memory fence override:
 * #define XMEMFENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)
 */

#define WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE  5000

#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

#endif /* WOLFHSM_CFG_H_ */
