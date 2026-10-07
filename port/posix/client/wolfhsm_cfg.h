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
 * port/posix/client/wolfhsm_cfg.h
 *
 * wolfHSM compile-time options for the POSIX generic client.
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_

#include "port/posix/posix_time.h"

#define WOLFHSM_CFG_PORT_GETTIME posixGetTime

/** Port configuration */
#define WOLFHSM_CFG_PORT_CLIENT_ID 12
#define WOLFHSM_CFG_PORT_TCP_PORT 23456
#define WOLFHSM_CFG_PORT_TCP_IPSTRING "127.0.0.1"
#define WOLFHSM_CFG_PORT_NOTIFY_PATH "/tmp/wolfhsm_notify"

/** wolfHSM settings */
#define WOLFHSM_CFG_ENABLE_CLIENT
#define WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS
#define WOLFHSM_CFG_TEST_WOLFCRYPTTEST
#define WOLFHSM_CFG_TEST_UNIT_NO_MAIN
#define WOLFHSM_CFG_TEST_POSIX
#define WOLFHSM_CFG_TEST_CLIENT_ONLY
#define WOLFHSM_CFG_PORT_ENABLE_BENCHMARK
#define WOLFHSM_CFG_BENCH_ENABLE
#include "benchmark/wh_bench_ops.h"
#define WOLFHSM_CFG_PORT_BENCH_TRANSPORT WH_BENCH_TRANSPORT_POSIX_TCP
#define WOLFHSM_CFG_COMM_DATA_LEN 5000
#define WOLFHSM_CFG_NVM_OBJECT_COUNT 30

#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

#endif /* WOLFHSM_CFG_H_ */
