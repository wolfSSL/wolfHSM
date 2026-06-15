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
 * test-refactor/wh_test_posix_server.h
 *
 * POSIX server-side init. Allocates the NVM, crypto,
 * transport, and server backing state the test main needs,
 * and wires them into a whServerContext. A real target would
 * do this in its normal boot flow; this file stands in for
 * that flow in the POSIX test harness.
 *
 * Also exposes the shared mem-transport config so the POSIX
 * client side can wire its end onto the same
 * request/response buffers.
 */

#ifndef WH_TEST_POSIX_SERVER_H_
#define WH_TEST_POSIX_SERVER_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_transport_mem.h"

/*
 * Initialize the server context plus all backing state
 * (flash, NVM, crypto, transport). Caller owns `server`.
 */
int whTestPosix_Server_Init(whServerContext* server);

/*
 * Tear down the server context plus backing state. Matches
 * Server_Init one-for-one.
 */
int whTestPosix_Server_Cleanup(whServerContext* server);

/*
 * Returns the shared mem-transport config (buffers + sizes).
 * Used by the POSIX client side to wire its end onto the
 * same buffers the server publishes through.
 */
whTransportMemConfig* whTestPosix_Server_GetTransportConfig(void);

/*
 * Verify the server's configured request-authorization callback was
 * actually invoked. Skip when authentication is disabled.
 */
int whTestPosix_Server_VerifyAuthCallbacks(void);

#endif /* WH_TEST_POSIX_SERVER_H_ */
