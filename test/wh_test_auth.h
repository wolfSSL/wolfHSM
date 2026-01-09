/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 * test/wh_test_auth.h
 */

#ifndef WOLFHSM_WH_TEST_AUTH_H_
#define WOLFHSM_WH_TEST_AUTH_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_client.h"

#include "wolfhsm/wh_auth.h"
#include "wh_test_common.h"


/* Self-contained test that creates client and server with auth */
int whTest_Auth(void);

/* Individual test functions that require a connected client */
int whTest_AuthLogin(whClientContext* client);
int whTest_AuthLogout(whClientContext* client);
int whTest_AuthAddUser(whClientContext* client);
int whTest_AuthDeleteUser(whClientContext* client);
int whTest_AuthSetPermissions(whClientContext* client);
int whTest_AuthSetCredentials(whClientContext* client);

#endif /* WOLFHSM_WH_TEST_AUTH_H_ */