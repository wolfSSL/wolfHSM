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
 * test-refactor/wh_test_port.h
 *
 * Port-implemented hooks. Every port must implement these.
 */

#ifndef WH_TEST_PORT_H_
#define WH_TEST_PORT_H_

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

/*
 * Port-implemented reset hooks. whTestGroup_Server and
 * whTestGroup_Client invoke these before each test in the group
 * so the port can scrub any persistent state (NVM objects, key
 * cache, connection state, ...) the previous test left behind.
 * A non-zero return aborts the group with that rc. Implementations
 * may be empty stubs that return 0 if the port has nothing to reset.
 */
int whTestPort_ResetServer(whServerContext* server);
int whTestPort_ResetClient(whClientContext* client);

#endif /* WH_TEST_PORT_H_ */
