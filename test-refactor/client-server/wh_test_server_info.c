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
 * test-refactor/wh_test_server_info.c
 *
 * Server info query test. Uses blocking client APIs; the port
 * is responsible for pumping the server in parallel.
 */

#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_message_comm.h"

#include "wh_test_common.h"
#include "wh_test_list.h"


/*
 * Query server info and verify the response contains
 * valid data.
 */
int whTest_ServerInfo(whClientContext* ctx)
{
    uint8_t  version[WH_INFO_VERSION_LEN + 1] = {0};
    uint8_t  build[WH_INFO_VERSION_LEN + 1]   = {0};
    uint32_t comm_data_len     = 0;
    uint32_t nvm_object_count  = 0;
    uint32_t keycache_count    = 0;
    uint32_t keycache_bufsize  = 0;
    uint32_t keycache_bigcount = 0;
    uint32_t keycache_bigbufsz = 0;
    uint32_t customcb_count    = 0;
    uint32_t dmaaddr_count     = 0;
    uint32_t debug_state       = 0;
    uint32_t boot_state        = 0;
    uint32_t lifecycle_state   = 0;
    uint32_t nvm_state         = 0;

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInfo(ctx,
            version, build,
            &comm_data_len,
            &nvm_object_count,
            &keycache_count,
            &keycache_bufsize,
            &keycache_bigcount,
            &keycache_bigbufsz,
            &customcb_count,
            &dmaaddr_count,
            &debug_state,
            &boot_state,
            &lifecycle_state,
            &nvm_state));

    /* Comm data length must be nonzero */
    WH_TEST_ASSERT_RETURN(comm_data_len > 0);

    return 0;
}
