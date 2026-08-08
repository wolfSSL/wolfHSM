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
 * port/template/server/wh_server_port.c
 *
 * Template server implementation of the wh_Port_* generic port API.
 * Replace the TODO stubs with your platform-specific logic.
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_port.h"

/* TODO: Include your transport header here, e.g.:
 * #include "port/<platform>/<platform>_transport.h"
 */

/* TODO: Declare static transport context and configuration structures.
 * These must persist for the lifetime of the server. Example:
 *
 * static myTransportServerContext transportCtx;
 * static myTransportConfig        transportCfg;
 * static whCommServerConfig       commConfig;
 * static whTransportServerCb      transportCb = MY_SERVER_CB;
 */

/* TODO: Declare NVM and flash state. You can use wh_flash_ramsim for
 * development or provide your own flash callbacks. Example using ramsim:
 *
 * static uint8_t           flashMemory[WOLFHSM_CFG_PORT_FLASH_RAM_SIZE];
 * static whFlashRamsimCfg  flashCfg;
 * static whFlashRamsimCtx  flashCtx;
 * static const whFlashCb   flashCb = WH_FLASH_RAMSIM_CB;
 * static whNvmFlashConfig  nvmFlashCfg;
 * static whNvmFlashContext nvmFlashCtx;
 * static whNvmCb           nvmCb[1] = {WH_NVM_FLASH_CB};
 * static whNvmConfig       nvmConfig;
 * static whNvmContext      nvmCtx;
 */

/* TODO: If crypto is enabled, declare crypto context:
 *
 * #ifndef WOLFHSM_CFG_NO_CRYPTO
 * static whServerCryptoContext cryptoCtx;
 * #endif
 */


int wh_Port_InitBoard(void)
{
    /* TODO: Initialize shared platform resources for the server.
     * This is called once at startup.
     *
     * Examples:
     * - Initialize crypto libraries (e.g. wolfCrypt_Init())
     * - Set up signal handlers for graceful shutdown
     * - Create IPC mechanisms for client connection notifications
     * - Initialize hardware peripherals
     */
    return WH_ERROR_OK;
}

int wh_Port_CleanupBoard(void)
{
    /* TODO: Release resources allocated by wh_Port_InitBoard.
     *
     * Examples:
     * - Close file descriptors or IPC handles
     * - Remove temporary files
     * - Deinitialize hardware
     */
    return WH_ERROR_OK;
}

int wh_Port_ConfigureServer(size_t instance, whServerConfig* serverCfg)
{
    if (serverCfg == NULL || instance >= WOLFHSM_CFG_PORT_SERVER_COUNT) {
        return WH_ERROR_BADARGS;
    }

    /* TODO: Populate serverCfg with transport, NVM, and crypto configuration.
     *
     * 1. Set up transport:
     *    commConfig.transport_cb      = &transportCb;
     *    commConfig.transport_context = (void*)&transportCtx;
     *    commConfig.transport_config  = (void*)&transportCfg;
     *    commConfig.server_id         = WOLFHSM_CFG_PORT_SERVER_ID;
     *    serverCfg->comm_config       = &commConfig;
     *
     * 2. Set up flash and NVM:
     *    - Configure flash backend (ramsim or hardware flash)
     *    - Initialize NVM with wh_Nvm_Init()
     *    - Assign: serverCfg->nvm = &nvmCtx;
     *
     * 3. Set up crypto (if not WOLFHSM_CFG_NO_CRYPTO):
     *    - Initialize RNG with wc_InitRng_ex()
     *    - Assign: serverCfg->crypto = &cryptoCtx;
     *    - Assign: serverCfg->devId = INVALID_DEVID;
     */

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
    (void)instance;

    /* TODO: Check if a client has connected to this server instance.
     * Return 1 exactly once per connection event, 0 otherwise.
     *
     * The mechanism is platform-specific. Examples:
     * - Read from a FIFO/pipe for a connect notification byte
     * - Check a shared memory flag and clear it
     * - Poll a hardware mailbox register
     */

    return 0;
}

int wh_Port_ClientDisconnected(size_t instance)
{
    (void)instance;

    /* TODO: Check if a client has disconnected from this server instance.
     * Return 1 exactly once per disconnection event, 0 otherwise.
     *
     * Uses the same mechanism as wh_Port_ClientConnected but checks for
     * the disconnect notification.
     */

    return 0;
}
