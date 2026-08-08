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
 * port/posix/server/wh_posix_server_port.c
 *
 * POSIX server implementation of the wh_Port_* generic port API.
 * Uses TCP transport with RamSim flash and NVM. Configuration is provided
 * through WOLFHSM_CFG_PORT_* defines which must be set by the application.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_port.h"

#include "port/posix/posix_transport_tcp.h"

#if WOLFHSM_CFG_PORT_SERVER_COUNT > 1
#error "POSIX port only supports WOLFHSM_CFG_PORT_SERVER_COUNT == 1"
#endif

/* Transport context and configuration - must persist for lifetime of server */
static posixTransportTcpServerContext tcpServerCtx;
static posixTransportTcpConfig        tcpConfig;
static whCommServerConfig             commConfig;
static whTransportServerCb            tcpCb = PTT_SERVER_CB;

/* NVM and flash state */
static uint8_t           flashMemory[WOLFHSM_CFG_PORT_FLASH_RAM_SIZE];
static whFlashRamsimCfg  flashCfg;
static whFlashRamsimCtx  flashCtx;
static const whFlashCb   flashCb = WH_FLASH_RAMSIM_CB;
static whNvmFlashConfig  nvmFlashCfg;
static whNvmFlashContext nvmFlashCtx;
static whNvmCb           nvmCb[1] = {WH_NVM_FLASH_CB};
static whNvmConfig       nvmConfig;
static whNvmContext      nvmCtx;

#ifndef WOLFHSM_CFG_NO_CRYPTO
static whServerCryptoContext cryptoCtx;
#endif

/* Notification FIFO fd — opened once and kept open */
static int notifyFd = -1;

static void cleanupHandler(int sig)
{
    wh_Port_CleanupBoard();
    _exit(128 + sig);
}

int wh_Port_InitBoard(void)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    wolfCrypt_Init();
#endif

    /* Register signal handler to clean up FIFO on exit */
    signal(SIGINT, cleanupHandler);
    signal(SIGTERM, cleanupHandler);

    /* Create the FIFO if it doesn't exist (EEXIST is OK) */
    if (mkfifo(WOLFHSM_CFG_PORT_NOTIFY_PATH, 0666) != 0 && errno != EEXIST) {
        return WH_ERROR_ABORTED;
    }
    /* O_RDWR prevents EOF when no writer is connected yet */
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
    if (unlink(WOLFHSM_CFG_PORT_NOTIFY_PATH) != 0 && errno != ENOENT) {
        return WH_ERROR_ABORTED;
    }

    return WH_ERROR_OK;
}

int wh_Port_ConfigureServer(size_t instance, whServerConfig* serverCfg)
{
    int ret;

    if (serverCfg == NULL || instance >= WOLFHSM_CFG_PORT_SERVER_COUNT) {
        return WH_ERROR_BADARGS;
    }

    memset(serverCfg, 0, sizeof(*serverCfg));
    memset(&tcpServerCtx, 0, sizeof(tcpServerCtx));
    memset(&commConfig, 0, sizeof(commConfig));
    memset(flashMemory, 0, sizeof(flashMemory));

    /* TCP transport configuration */
    tcpConfig.server_ip_string = WOLFHSM_CFG_PORT_TCP_IPSTRING;
    tcpConfig.server_port      = WOLFHSM_CFG_PORT_TCP_PORT;

    commConfig.transport_cb      = &tcpCb;
    commConfig.transport_context = (void*)&tcpServerCtx;
    commConfig.transport_config  = (void*)&tcpConfig;
    commConfig.server_id         = WOLFHSM_CFG_PORT_SERVER_ID;

    serverCfg->comm_config = &commConfig;

    /* Flash simulation configuration */
    flashCfg.size       = WOLFHSM_CFG_PORT_FLASH_RAM_SIZE;
    flashCfg.sectorSize = WOLFHSM_CFG_PORT_FLASH_RAM_SIZE / 2;
    flashCfg.pageSize   = 8;
    flashCfg.erasedByte = (uint8_t)0;
    flashCfg.memory     = flashMemory;

    /* NVM configuration */
    memset(&flashCtx, 0, sizeof(flashCtx));
    memset(&nvmFlashCtx, 0, sizeof(nvmFlashCtx));
    nvmFlashCfg.cb      = &flashCb;
    nvmFlashCfg.context = &flashCtx;
    nvmFlashCfg.config  = &flashCfg;

    nvmConfig.cb      = nvmCb;
    nvmConfig.context = &nvmFlashCtx;
    nvmConfig.config  = &nvmFlashCfg;

    ret = wh_Nvm_Init(&nvmCtx, &nvmConfig);
    if (ret != WH_ERROR_OK) {
        WOLFHSM_CFG_PRINTF("Failed to initialize NVM: %d\n", ret);
        return ret;
    }

    serverCfg->nvm = &nvmCtx;

#ifndef WOLFHSM_CFG_NO_CRYPTO
    memset(&cryptoCtx, 0, sizeof(cryptoCtx));
    serverCfg->crypto = &cryptoCtx;
    serverCfg->devId  = INVALID_DEVID;

    ret = wc_InitRng_ex(cryptoCtx.rng, NULL, INVALID_DEVID);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to initialize RNG: %d\n", ret);
        return ret;
    }
#endif

    (void)instance;
    return WH_ERROR_OK;
}

int wh_Port_InitServer(size_t instance, whServerConfig* serverCfg,
                       whServerContext* serverCtx)
{
    if (serverCfg == NULL || serverCtx == NULL ||
        instance >= WOLFHSM_CFG_PORT_SERVER_COUNT) {
        return WH_ERROR_BADARGS;
    }

    return wh_Server_Init(serverCtx, serverCfg);
}

int wh_Port_CleanupServer(size_t instance, whServerContext* serverCtx)
{
    if (serverCtx == NULL || instance >= WOLFHSM_CFG_PORT_SERVER_COUNT) {
        return WH_ERROR_BADARGS;
    }

    return wh_Server_Cleanup(serverCtx);
}

int wh_Port_ClientConnected(size_t instance)
{
    uint8_t msg;
    ssize_t rc;

    (void)instance;

    if (notifyFd < 0) {
        return 0;
    }

    rc = read(notifyFd, &msg, 1);
    if (rc == 1 && msg == 1) {
        return 1;
    }

    return 0;
}

int wh_Port_ClientDisconnected(size_t instance)
{
    uint8_t msg;
    ssize_t rc;

    (void)instance;

    if (notifyFd < 0) {
        return 0;
    }

    rc = read(notifyFd, &msg, 1);
    if (rc == 1 && msg == 0) {
        return 1;
    }

    return 0;
}
