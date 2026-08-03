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
 * test-refactor/misc/wh_test_log_backend.h
 *
 * Backend-agnostic log harness shared by the portable Misc log tests
 * (mock, ring buffer) and the POSIX port log tests (file backend). The
 * caller supplies a backend callback table and context; the harness runs
 * the same suite against it.
 */

#ifndef WH_TEST_LOG_BACKEND_H_
#define WH_TEST_LOG_BACKEND_H_

#include <stddef.h>

#include "wolfhsm/wh_log.h"

/* Configuration describing a backend under test. */
typedef struct {
    const char* backend_name;    /* Backend name for test output */
    whLogCb*    cb;              /* Backend callback table */
    void*       config;          /* Backend-specific config */
    size_t      config_size;     /* Size of context structure */
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
 * Runs all generic test suites against the supplied backend.
 * Returns WH_ERROR_OK on success, non-zero on failure.
 */
int whTest_LogBackend_RunAll(whTestLogBackendTestConfig* cfg);

#endif /* WH_TEST_LOG_BACKEND_H_ */
