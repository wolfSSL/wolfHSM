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
#include <stdint.h>
#include <string.h>
#include "wh_bench_mod.h"

#if defined(WOLFHSM_CFG_BENCH_ENABLE)

int wh_Bench_Mod_Echo(whClientContext* client, BenchOpContext* benchCtx, int id,
                      void* params)
{
    int      i;
    int      ret;
    uint16_t send_len;
    uint16_t recv_len;
    uint8_t  send_buffer[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t  recv_buffer[WOLFHSM_CFG_COMM_DATA_LEN];
    int      startRet;
    int      stopRet;

    /* Send an entire comm buffer's worth of data */
    memset(send_buffer, 0xAA, sizeof(send_buffer));
    memset(recv_buffer, 0x55, sizeof(recv_buffer));
    send_len = sizeof(send_buffer);
    recv_len = 0;

    ret = wh_Bench_SetDataSize(benchCtx, id, send_len);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to set data size: %d\n", ret);
        return ret;
    }

    /* Run echo test multiple times to gather statistics */
    for (i = 0; i < WOLFHSM_CFG_BENCH_CRYPT_ITERS; i++) {

        /* Start timing the echo operation */
        startRet = wh_Bench_StartOp(benchCtx, id);

        /* Send echo request and receive response */
        ret = wh_Client_Echo(client, send_len, send_buffer, &recv_len,
                             recv_buffer);

        /* Stop timing the operation */
        stopRet = wh_Bench_StopOp(benchCtx, id);

        /* Deferred error checking */
        if (startRet != 0) {
            WH_BENCH_PRINTF("Failed to start timing echo operation: %d\n",
                            startRet);
            break;
        }
        if (ret != 0) {
            WH_BENCH_PRINTF("Echo test failed with error: %d\n", ret);
            break;
        }
        if (stopRet != 0) {
            WH_BENCH_PRINTF("Failed to stop timing echo operation: %d\n",
                            stopRet);
            break;
        }

        /* Verify response */
        if (recv_len != send_len ||
            memcmp(recv_buffer, send_buffer, recv_len) != 0) {
            WH_BENCH_PRINTF(
                "Echo response mismatch! Expected: %.*s, Received: %.*s\n",
                send_len, send_buffer, recv_len, recv_buffer);
            ret = -1;
            break;
        }
    }

    return ret;
}

#endif /* WOLFHSM_CFG_BENCH_ENABLE */
