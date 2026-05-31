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
 * examples/generic/wh_generic_server.c
 *
 * Generic server entry point using the wh_Port_* abstraction API.
 */

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_port.h"

int main(void)
{
    int             err;
    int             isConnected[WOLFHSM_CFG_PORT_SERVER_COUNT] = {0};
    whServerContext serverCtx[WOLFHSM_CFG_PORT_SERVER_COUNT];
    whServerConfig  serverCfg[WOLFHSM_CFG_PORT_SERVER_COUNT];

    WOLFHSM_CFG_PRINTF("Starting generic server...\n");

    err = wh_Port_InitBoard();
    if (err) {
        WOLFHSM_CFG_PRINTF("wh_Port_InitBoard failed: %d\n", err);
        goto loop;
    }

    for (size_t i = 0; i < WOLFHSM_CFG_PORT_SERVER_COUNT; ++i) {
        err = wh_Port_ConfigureServer(i, &serverCfg[i]);
        if (err) {
            WOLFHSM_CFG_PRINTF("wh_Port_ConfigureServer(%zu) failed: %d\n", i,
                               err);
            goto loop;
        }
    }

    WOLFHSM_CFG_PRINTF("Server configured, waiting for connections...\n");

    while (1) {
        for (size_t i = 0; i < WOLFHSM_CFG_PORT_SERVER_COUNT; ++i) {
            if (!isConnected[i]) {
                if (wh_Port_ClientConnected(i)) {
                    err = wh_Port_InitServer(i, &serverCfg[i], &serverCtx[i]);
                    if (err) {
                        WOLFHSM_CFG_PRINTF(
                            "wh_Port_InitServer(%zu) failed: %d\n", i, err);
                        goto loop;
                    }

                    err = wh_Server_SetConnected(&serverCtx[i],
                                                 WH_COMM_CONNECTED);
                    if (err) {
                        WOLFHSM_CFG_PRINTF(
                            "wh_Server_SetConnected(%zu) failed: %d\n", i, err);
                        goto loop;
                    }
                    isConnected[i] = 1;
                    WOLFHSM_CFG_PRINTF("Client connected on instance %zu\n", i);
                }
            }
            else {
                if (wh_Port_ClientDisconnected(i)) {
                    WOLFHSM_CFG_PRINTF("Client disconnected on instance %zu\n",
                                       i);
                    err = wh_Port_CleanupServer(i, &serverCtx[i]);
                    if (err) {
                        WOLFHSM_CFG_PRINTF(
                            "wh_Port_CleanupServer(%zu) failed: %d\n", i, err);
                        goto loop;
                    }
                    isConnected[i] = 0;
                }
                else {
                    err = wh_Server_HandleRequestMessage(&serverCtx[i]);
                    if (err != WH_ERROR_OK && err != WH_ERROR_NOTREADY) {
                        WOLFHSM_CFG_PRINTF(
                            "wh_Server_HandleRequestMessage(%zu) failed: "
                            "%d\n",
                            i, err);
                        goto loop;
                    }
                }
            }
        }
    }

loop:
    while (1)
        ;
}
