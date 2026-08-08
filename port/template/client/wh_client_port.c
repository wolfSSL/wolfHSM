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
 * port/template/client/wh_client_port.c
 *
 * Template client implementation of the wh_Port_* generic port API.
 * Replace the TODO stubs with your platform-specific logic.
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_port.h"

/* TODO: Include your transport header here, e.g.:
 * #include "port/<platform>/<platform>_transport.h"
 */

/* TODO: Declare static transport context and configuration structures.
 * These must persist for the lifetime of the client. Example:
 *
 * static myTransportClientContext transportCtx;
 * static myTransportConfig        transportCfg;
 * static whCommClientConfig       commConfig;
 * static whTransportClientCb      transportCb = MY_CLIENT_CB;
 */


int wh_Port_InitBoard(void)
{
    /* TODO: Initialize any shared platform resources needed by the client.
     * This is called once at startup before any client operations.
     *
     * Examples:
     * - Initialize hardware peripherals
     * - Set up IPC mechanisms for server notifications
     * - Initialize crypto libraries
     */
    return WH_ERROR_OK;
}

int wh_Port_CleanupBoard(void)
{
    /* TODO: Release resources allocated by wh_Port_InitBoard.
     * This is called at shutdown.
     */
    return WH_ERROR_OK;
}

/* TODO: If your transport supports a connect callback, implement it here.
 * The callback is invoked by the transport layer when the connection state
 * changes. It should notify the server side so that wh_Port_ClientConnected
 * and wh_Port_ClientDisconnected work correctly.
 *
 * static int connectCb(void* context, whCommConnected connected)
 * {
 *     (void)context;
 *     if (connected == WH_COMM_CONNECTED) {
 *         // Notify server that client has connected
 *     } else {
 *         // Notify server that client has disconnected
 *     }
 *     return WH_ERROR_OK;
 * }
 */

int wh_Port_ConfigureClient(whClientConfig* clientCfg)
{
    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* TODO: Initialize and populate the comm configuration with your
     * transport callbacks, context, config, client ID, and optionally
     * a connect callback. Then assign it to clientCfg->comm. Example:
     *
     * memset(&transportCtx, 0, sizeof(transportCtx));
     * memset(&commConfig, 0, sizeof(commConfig));
     *
     * transportCfg.server_addr = WOLFHSM_CFG_PORT_SERVER_ADDR;
     *
     * commConfig.transport_cb      = &transportCb;
     * commConfig.transport_context = (void*)&transportCtx;
     * commConfig.transport_config  = (void*)&transportCfg;
     * commConfig.client_id         = WOLFHSM_CFG_PORT_CLIENT_ID;
     * commConfig.connect_cb        = connectCb;
     *
     * clientCfg->comm = &commConfig;
     */

    return WH_ERROR_OK;
}

int wh_Port_InitClient(whClientConfig* clientCfg, whClientContext* clientCtx)
{
    int ret;

    if (clientCfg == NULL || clientCtx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_Init(clientCtx, clientCfg);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Client_CommInit(clientCtx, NULL, NULL);
    if (ret != WH_ERROR_OK) {
        (void)wh_Client_Cleanup(clientCtx);
        return ret;
    }

    return WH_ERROR_OK;
}

int wh_Port_RunClient(whClientContext* clientCtx)
{
    if (clientCtx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* TODO: Implement your client application logic here. For example:
     * - Send echo requests
     * - Perform crypto operations
     * - Store/retrieve NVM objects
     * - Run key management operations
     *
     * Use wh_Client_* APIs. For async operations, poll with a retry loop:
     *
     * do {
     *     ret = wh_Client_EchoRequest(clientCtx, len, data);
     * } while (ret == WH_ERROR_NOTREADY);
     */

    return WH_ERROR_OK;
}

int wh_Port_CleanupClient(whClientContext* clientCtx)
{
    int ret;

    if (clientCtx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_CommClose(clientCtx);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Client_Cleanup(clientCtx);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    return WH_ERROR_OK;
}
