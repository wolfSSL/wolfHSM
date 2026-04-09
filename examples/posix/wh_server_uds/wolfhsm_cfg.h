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
 * wolfHSM compile-time options for the wh_server_uds daemon.
 *
 * Design decisions:
 *   COMM_DATA_LEN = 5000: large enough for a 4096-bit RSA key in DER (~3 KB)
 *   plus an ML-DSA level-5 key (~4.6 KB), giving headroom.
 *
 *   NVM_OBJECT_COUNT = 64: accommodates all PKCS#11 store types × reasonable
 *   slot/token/object counts.  Each PKCS#11 NVM object fits in one NVM slot.
 *
 *   Key cache sizes: sized for one large (ML-DSA) key and several RSA/ECC keys
 *   simultaneously active in the server's RAM cache.
 */

#ifndef WOLFHSM_CFG_H_
#define WOLFHSM_CFG_H_

#include "port/posix/posix_time.h"

/* Daemon is both server (wolfHSM backend) and client (wolfPKCS11 frontend) */
#define WOLFHSM_CFG_ENABLE_SERVER
#define WOLFHSM_CFG_ENABLE_CLIENT

#define WOLFHSM_CFG_PORT_GETTIME posixGetTime

/* Maximum payload per RPC message.  Must hold the largest key DER a client
 * will ever send.  ML-DSA-87 key: ~4.6 KB. */
#define WOLFHSM_CFG_COMM_DATA_LEN 5000

/* NVM object slots available in the server's flash partition */
#define WOLFHSM_CFG_NVM_OBJECT_COUNT 64

/* RAM key cache for the server (holds active session keys) */
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT     9
#define WOLFHSM_CFG_SERVER_KEYCACHE_SIZE      1024
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE 5000
#define WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT   3

#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 4

/* Memory fence for x86 */
#define XMEMFENCE() __atomic_thread_fence(__ATOMIC_SEQ_CST)

/* Key wrap support */
#ifndef WOLFHSM_CFG_NO_CRYPTO
#define WOLFHSM_CFG_KEYWRAP
#define WOLFHSM_CFG_KEYWRAP_MAX_KEY_SIZE 5000
#define WOLFHSM_CFG_GLOBAL_KEYS
#endif

#endif /* WOLFHSM_CFG_H_ */
