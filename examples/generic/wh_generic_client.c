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
 * examples/generic/wh_generic_client.c
 *
 * Generic client entry point using the wh_Port_* abstraction API.
 */

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_port.h"

#ifdef WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS
#include "test/wh_test.h"
#endif /* WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS */

#ifdef WOLFHSM_CFG_PORT_ENABLE_BENCHMARK
#include "benchmark/wh_bench.h"
#endif /* WOLFHSM_CFG_PORT_ENABLE_BENCHMARK */

int main(void)
{
    int             err;
    whClientConfig  clientCfg;
    whClientContext clientCtx;

    WOLFHSM_CFG_PRINTF("Starting generic client...\n");

    err = wh_Port_InitBoard();
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Port_InitBoard failed: %d\n", err);
        goto loop;
    }

    err = wh_Port_ConfigureClient(&clientCfg);
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Port_ConfigureClient failed: %d\n", err);
        goto loop;
    }

#ifdef WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS

    WOLFHSM_CFG_PRINTF("\n========== CLIENT TESTS ==========\n\n");
    err = whTest_ClientConfig(&clientCfg);
    if (err) {
        WOLFHSM_CFG_PRINTF("whTest_ClientConfig failed: %d\n", err);
        goto loop;
    }

#endif /* WOLFHSM_CFG_PORT_ENABLE_WOLFHSM_TESTS */

#ifdef WOLFHSM_CFG_PORT_ENABLE_BENCHMARK

    WOLFHSM_CFG_PRINTF("\n========== BENCHMARKS ==========\n\n");
    err = wh_Bench_ClientCfg(&clientCfg, WOLFHSM_CFG_PORT_BENCH_TRANSPORT);
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Bench_ClientCfg failed: %d\n", err);
        goto loop;
    }

#endif /* WOLFHSM_CFG_PORT_ENABLE_BENCHMARK */

    WOLFHSM_CFG_PRINTF("Connecting to server...\n");
    err = wh_Port_InitClient(&clientCfg, &clientCtx);
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Port_InitClient failed: %d\n", err);
        goto loop;
    }
    WOLFHSM_CFG_PRINTF("Client initialized\n");

    WOLFHSM_CFG_PRINTF("Running client...\n");
    err = wh_Port_RunClient(&clientCtx);
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Port_RunClient failed: %d\n", err);
    }

    err = wh_Port_CleanupClient(&clientCtx);
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Port_CleanupClient failed: %d\n", err);
    }

    WOLFHSM_CFG_PRINTF("Client finished\n");
    wh_Port_CleanupBoard();

loop:
    while (1);

    return 0;
}
