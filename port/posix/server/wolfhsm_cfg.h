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
 * port/posix/server/wolfhsm_cfg.h
 *
 * wolfHSM compile-time options for the POSIX generic server.
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_

#include "port/posix/posix_time.h"

#define WOLFHSM_CFG_PORT_GETTIME posixGetTime

/** Port configuration */
#define WOLFHSM_CFG_PORT_SERVER_ID 57
#define WOLFHSM_CFG_PORT_SERVER_COUNT 1
#define WOLFHSM_CFG_PORT_TCP_PORT 23456
#define WOLFHSM_CFG_PORT_TCP_IPSTRING "127.0.0.1"
#define WOLFHSM_CFG_PORT_NOTIFY_PATH "/tmp/wolfhsm_notify"
#define WOLFHSM_CFG_PORT_FLASH_RAM_SIZE (1024 * 1024) /* 1MB */

/** wolfHSM settings */
#define WOLFHSM_CFG_ENABLE_SERVER

/* Large enough for ML-DSA level 5 key */
#define WOLFHSM_CFG_COMM_DATA_LEN 5000

#define WOLFHSM_CFG_NVM_OBJECT_COUNT 30
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 9
#define WOLFHSM_CFG_SERVER_KEYCACHE_SIZE 1024
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE 4096
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT 5

#define WOLFHSM_CFG_SERVER_DMAADDR_COUNT 8
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 6

#define WOLFHSM_CFG_CERTIFICATE_MANAGER
#define WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT

#define XMEMFENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)

#define WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE 5000

#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

#endif /* WOLFHSM_CFG_H_ */
