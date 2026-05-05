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
 * test-refactor/wh_test_groups.h
 *
 * Portable entry points for the three test groups. The port's
 * main() owns the client/server contexts and hands them to the
 * group functions, which run every suite that belongs to the
 * group (gated by the applicable compile-time config flags).
 *
 *   - Misc:   standalone suites, no client or server needed
 *   - Server: server-side suites; takes a whServerContext*
 *   - Client: client-side suites; takes a whClientContext*
 *             (the server must already be running -- on
 *             single-process ports the port sets it up before
 *             calling into this group)
 *
 * A client-only port calls Client (and optionally Misc).
 * A server-only port calls Server (and optionally Misc).
 * A combined port calls all three.
 */

#ifndef WH_TEST_GROUPS_H_
#define WH_TEST_GROUPS_H_

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"


int whTestGroup_Misc(void);
int whTestGroup_Server(whServerContext* server);
int whTestGroup_Client(whClientContext* client);

/*
 * Run a single test outside the portable registry, print its
 * result in the standard format, and feed the summary tally.
 * Used by ports to invoke platform-specific tests (e.g. POSIX
 * host-sim suites) so they appear in the final tally alongside
 * the portable groups. Returns the test's rc unchanged.
 */
int whTestGroup_RunOne(const char* name, int (*fn)(void*), void* ctx);

/*
 * Print a wolfCrypt-style tally ("All N tests passed!" or
 * "N passed, M skipped, K failed of T tests") using the
 * counters accumulated by whTestGroup_{Misc,Server,Client}.
 * Call once from main after the last group returns.
 * Returns 0 if no failures, non-zero otherwise.
 */
int whTestGroup_Summary(void);

#endif /* WH_TEST_GROUPS_H_ */
