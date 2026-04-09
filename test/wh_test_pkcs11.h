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
 * test/wh_test_pkcs11.h
 *
 * PKCS#11 integration test via the wh_server_uds daemon and p11-kit-client.so.
 *
 * Build guards:
 *   WOLFHSM_CFG_TEST_POSIX    — enables POSIX-specific tests (fork/exec/dlopen)
 *   WOLFHSM_CFG_TEST_PKCS11   — enables this test specifically; requires:
 *                                  - p11-kit headers in the include path
 *                                  - p11-kit-client.so on the system
 *                                  - the wh_server_uds daemon binary built
 *
 * The daemon binary path is resolved in priority order:
 *   1. WH_TEST_PKCS11_DAEMON_PATH compile-time define
 *   2. WH_TEST_PKCS11_DAEMON_PATH environment variable at runtime
 *   3. Default relative path ../examples/posix/wh_server_uds/Build/wh_server_uds
 */

#ifndef WH_TEST_PKCS11_H_
#define WH_TEST_PKCS11_H_

/*
 * whTest_Pkcs11 — run the PKCS#11 integration test suite.
 *
 * Forks wh_server_uds, connects via p11-kit-client.so, exercises key
 * generation, sign/verify (EC), and random generation.
 *
 * Returns 0 on success, non-zero on any failure.
 *
 * Only compiled when WOLFHSM_CFG_TEST_POSIX and WOLFHSM_CFG_TEST_PKCS11
 * are both defined.
 */
#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_TEST_PKCS11)
int whTest_Pkcs11(void);
#endif

#endif /* WH_TEST_PKCS11_H_ */
