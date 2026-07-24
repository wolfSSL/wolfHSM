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

#define WOLFHSM_CFG_ENABLE_CLIENT
#define WOLFHSM_CFG_ENABLE_SERVER

/* wh_settings.h includes this file before user_settings.h, so the
 * WOLFSSL_NO_ML_DSA_xx feature gates below would not be visible yet at this
 * point in the translation unit. Pull user_settings.h in early so
 * WOLFHSM_CFG_COMM_DATA_LEN can be sized to the largest enabled ML-DSA level.
 * user_settings.h is just a flat set of #define statements guarded by its
 * own include guard, so wh_settings.h's later #include is a no-op. */
#ifdef WOLFSSL_USER_SETTINGS
#include "user_settings.h"
#endif

/* Non-DMA client/server messages carry the full request/response body
 * (signature, key material, etc.) in this buffer, so it must be large
 * enough for the biggest enabled ML-DSA security level's KeyGen/Verify
 * payload. Smaller devices that disable the larger levels can shrink this
 * buffer accordingly. */
#if !defined(WOLFSSL_NO_ML_DSA_87)
#define WOLFHSM_CFG_COMM_DATA_LEN (1280 * 8)
#elif !defined(WOLFSSL_NO_ML_DSA_65)
#define WOLFHSM_CFG_COMM_DATA_LEN (1280 * 5)
#else
#define WOLFHSM_CFG_COMM_DATA_LEN (1280 * 4)
#endif

#define WOLFHSM_CFG_NVM_OBJECT_COUNT 30
#define WOLFHSM_CFG_SERVER_KEYCACHE_COUNT 9
#define WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE 300
#define WOLFHSM_CFG_DMAADDR_COUNT 8
#define WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT 6

#define WOLFHSM_CFG_CERTIFICATE_MANAGER
#define WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT

/* Benchmark configs */
#define WOLFHSM_CFG_BENCH_ENABLE
#define WOLFHSM_CFG_BENCH_MAIN
#endif /* WOLFHSM_CFG_H_ */
