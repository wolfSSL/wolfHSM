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
 * port/template/client/wolfhsm_cfg.h
 *
 * Template wolfHSM compile-time options for a client build.
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
 * TODO: Set these to match your platform and server configuration. */
#define WOLFHSM_CFG_PORT_CLIENT_ID    12
/* TODO: Add transport-specific defines here, e.g.:
 * #define WOLFHSM_CFG_PORT_TCP_PORT      23456
 * #define WOLFHSM_CFG_PORT_TCP_IPSTRING  "127.0.0.1"
 */

/** wolfHSM settings */
#define WOLFHSM_CFG_ENABLE_CLIENT

/* Communication data length — must match server */
#define WOLFHSM_CFG_COMM_DATA_LEN     5000

/* NVM object count — must match server */
#define WOLFHSM_CFG_NVM_OBJECT_COUNT  30

/* TODO: Uncomment to enable tests and benchmarks:
 * #define WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS
 * #define WOLFHSM_CFG_TEST_WOLFCRYPTTEST
 * #define WOLFHSM_CFG_TEST_UNIT_NO_MAIN
 * #define WOLFHSM_CFG_TEST_CLIENT_ONLY
 * #define WOLFHSM_CFG_PORT_ENABLE_BENCHMARK
 * #define WOLFHSM_CFG_BENCH_ENABLE
 * #include "benchmark/wh_bench_ops.h"
 * #define WOLFHSM_CFG_PORT_BENCH_TRANSPORT WH_BENCH_TRANSPORT_...
 */

#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

#endif /* WOLFHSM_CFG_H_ */
