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
 * test-refactor/wh_test_echo.c
 *
 * Echo round-trip test. Uses blocking client APIs; the port
 * is responsible for pumping the server in parallel.
 */

#include <stdio.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define REPEAT_COUNT 10

/*
 * Echo a message to the server and verify the response
 * matches. Repeats several times with different payloads.
 */
int whTest_Echo(whClientContext* ctx)
{
    char     send_buf[WOLFHSM_CFG_COMM_DATA_LEN];
    char     recv_buf[WOLFHSM_CFG_COMM_DATA_LEN];
    uint16_t send_len = 0;
    uint16_t recv_len = 0;
    int      i;

    for (i = 0; i < REPEAT_COUNT; i++) {
        send_len = snprintf(send_buf, sizeof(send_buf),
            "Echo test %d", i);

        recv_len = 0;
        memset(recv_buf, 0, sizeof(recv_buf));

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_Echo(ctx,
                send_len, send_buf,
                &recv_len, recv_buf));

        WH_TEST_ASSERT_RETURN(recv_len == send_len);
        WH_TEST_ASSERT_RETURN(
            memcmp(recv_buf, send_buf, recv_len) == 0);
    }

    return 0;
}
