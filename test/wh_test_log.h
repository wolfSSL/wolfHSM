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
 * test/wh_test_log.h
 *
 */

#ifndef TEST_WH_TEST_LOG_H_
#define TEST_WH_TEST_LOG_H_

#include <stdint.h>

#include "wolfhsm/wh_log.h"

/*
 * Configuration structure for backend testing
 */
typedef struct {
    const char* backend_name;    /* Backend name for test output */
    whLogCb*    cb;              /* Backend callback table */
    void*       config;          /* Backend-specific config */
    size_t      config_size;     /* Size of config structure */
    void*       backend_context; /* Pre-allocated backend context */

    /* Capabilities */
    int expected_capacity;   /* Max entries (-1 = unlimited) */
    int supports_concurrent; /* supports multithreaded use */

    /* Optional hooks */
    int (*setup)(void** context);   /* Setup hook (optional) */
    int (*teardown)(void* context); /* Teardown hook (optional) */
    void* test_context;             /* Context for setup/teardown */
} whTestLogBackendTestConfig;

/*
 * Runs all generic test suites for the built-in backends.
 * Returns 0 on success, non-zero on failure.
 */
int whTest_LogBackend_RunAll(whTestLogBackendTestConfig* cfg);


/*
 * Runs all logging module tests including frontend API, macros, and
 * POSIX file backend tests (if WOLFHSM_CFG_TEST_POSIX is defined).
 *
 * Returns 0 on success and a non-zero error code on failure
 */
int whTest_Log(void);

#endif /* TEST_WH_TEST_LOG_H_ */
