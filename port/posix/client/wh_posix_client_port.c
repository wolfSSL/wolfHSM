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
 * port/posix/client/wh_posix_client_port.c
 *
 * POSIX client implementation of the wh_Port_* generic port API.
 * Uses TCP transport. Configuration is provided through WOLFHSM_CFG_PORT_*
 * defines which must be set by the application (e.g. via a config header).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_port.h"

#include "port/posix/posix_transport_tcp.h"

/* Transport context and configuration - must persist for lifetime of client */
static posixTransportTcpClientContext tcpClientCtx;
static posixTransportTcpConfig        tcpConfig;
static whCommClientConfig             commConfig;
static whTransportClientCb            tcpCb = PTT_CLIENT_CB;

/* Notification FIFO fd — opened once and kept open */
static int notifyFd = -1;

int wh_Port_InitBoard(void)
{
    /* Create the FIFO if it doesn't exist (EEXIST is OK) */
    if (mkfifo(WOLFHSM_CFG_PORT_NOTIFY_PATH, 0666) != 0 && errno != EEXIST) {
        return WH_ERROR_ABORTED;
    }

    /* O_RDWR avoids blocking when no reader is open yet */
    notifyFd = open(WOLFHSM_CFG_PORT_NOTIFY_PATH, O_RDWR | O_NONBLOCK);
    if (notifyFd < 0) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

int wh_Port_CleanupBoard(void)
{
    if (notifyFd >= 0) {
        if (close(notifyFd) != 0) {
            return WH_ERROR_ABORTED;
        }
        notifyFd = -1;
    }

    return WH_ERROR_OK;
}

static int connectCb(void* context, whCommConnected connected)
{
    uint8_t msg;

    (void)context;

    if (notifyFd < 0) {
        return WH_ERROR_ABORTED;
    }

    msg = (connected == WH_COMM_CONNECTED) ? 1 : 0;
    if (write(notifyFd, &msg, 1) != 1) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

int wh_Port_ConfigureClient(whClientConfig* clientCfg)
{
    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(&tcpClientCtx, 0, sizeof(tcpClientCtx));
    memset(&commConfig, 0, sizeof(commConfig));

    tcpConfig.server_ip_string = WOLFHSM_CFG_PORT_TCP_IPSTRING;
    tcpConfig.server_port      = WOLFHSM_CFG_PORT_TCP_PORT;

    commConfig.transport_cb      = &tcpCb;
    commConfig.transport_context = (void*)&tcpClientCtx;
    commConfig.transport_config  = (void*)&tcpConfig;
    commConfig.client_id         = WOLFHSM_CFG_PORT_CLIENT_ID;
    commConfig.connect_cb        = connectCb;

    clientCfg->comm = &commConfig;

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

static void sleepMs(long milliseconds)
{
    struct timespec req;
    req.tv_sec  = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&req, NULL);
}

int wh_Port_RunClient(whClientContext* clientCtx)
{
    int      ret;
    int      counter;
    uint8_t  tx_req[32]  = {0};
    uint16_t tx_req_len  = 0;
    uint8_t  rx_resp[64] = {0};
    uint16_t rx_resp_len = 0;

    if (clientCtx == NULL) {
        return WH_ERROR_BADARGS;
    }

    WOLFHSM_CFG_PRINTF("Client connected, sending echo requests...\n");

    for (counter = 0; counter < 20; counter++) {
        sprintf((char*)tx_req, "Request:%u", counter);
        tx_req_len = strlen((char*)tx_req);

        do {
            ret = wh_Client_EchoRequest(clientCtx, tx_req_len, tx_req);
            if (ret == WH_ERROR_NOTREADY) {
                sleepMs(1);
            }
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF("EchoRequest failed: %d\n", ret);
            break;
        }

        rx_resp_len = 0;
        memset(rx_resp, 0, sizeof(rx_resp));

        do {
            ret = wh_Client_EchoResponse(clientCtx, &rx_resp_len, rx_resp);
            if (ret == WH_ERROR_NOTREADY) {
                sleepMs(1);
            }
        } while (ret == WH_ERROR_NOTREADY);

        if (ret != WH_ERROR_OK) {
            WOLFHSM_CFG_PRINTF("EchoResponse failed: %d\n", ret);
            break;
        }
    }

    return ret;
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
