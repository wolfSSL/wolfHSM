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
 * test/wh_test_auth.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_auth.h"
#include "wolfhsm/wh_auth_base.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"

#include "wh_test_common.h"
#include "wh_test_auth.h"


/* test cases */

/* Logout tests */
/* test logout before login */
/* test logout after login */
/* test logout with invalid user id */

/* Login tests */
/* test login with invalid credentials */
/* test login with valid credentials */
/* test login with invalid user name */
/* test login if already logged in */

/* Add user tests */
/* test add user with invalid user name (too long?) */
/* test add user with invalid permissions */
/* test add user if already exists */

/* Delete user tests */
/* test delete user with invalid user id */
/* test delete user that does not exist */
/* test delete user when not logged in */

/* Set user permissions tests */
/* test set user permissions with invalid user id */
/* test set user permissions with invalid permissions */
/* test set user permissions that does not exist */
/* test set user permissions when not logged in */

/* Set user credentials tests */
/* test set user credentials with invalid user id */
/* test set user credentials with invalid credentials (wrong method) */
/* test set user credentials for a userthat does not exist */
/* test an admin user setting credentials for non admin user */

/* Tests for authorization checks */
/* try operation when not logged in and not allowed */
/* re-try operation when logged in and allowed */
/* try operation when logged in and not allowed */
/* try operation when logged in as different user and allowed */
/* try operation when logged in as different user and not allowed */

/* Tests for key authorization checks */
/* test of access to key ID that is not allowed */
/* test of access to key ID that is allowed */
/* test of access to key ID that is allowed for different user */
