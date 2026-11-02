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
 * wolfhsm/wh_port.h
 *
 * Abstract port API for wolfHSM generic examples. Each port (e.g. POSIX,
 * bare-metal) provides its own implementation of these functions.
 */

#ifndef WOLFHSM_WH_PORT_H_
#define WOLFHSM_WH_PORT_H_

#include <stddef.h>
#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

/** @defgroup Port Port API
 *  @brief Platform-specific board, client, and server initialization functions.
 *  @{
 */

/* Common API */

/**
 * @brief Initialize the board and any shared platform resources.
 *
 * Called once at startup before any client or server operations. Performs
 * platform-specific initialization.
 *
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_InitBoard(void);

/**
 * @brief Clean up board resources allocated by wh_Port_InitBoard.
 *
 * Called at shutdown to release any shared platform resources.
 *
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_CleanupBoard(void);

/* Client API */

/**
 * @brief Populate a client configuration structure with port-specific settings.
 *
 * Sets up transport, communication, and callback configuration for the client.
 * The resulting configuration can be passed to wh_Port_InitClient.
 *
 * @param[out] clientCfg Pointer to the client configuration to populate.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_ConfigureClient(whClientConfig* clientCfg);

/**
 * @brief Initialize and connect a client using the given configuration.
 *
 * Initializes the client context and establishes communication with the server.
 *
 * @param[in]  clientCfg Pointer to the client configuration.
 * @param[out] clientCtx Pointer to the client context to initialize.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_InitClient(whClientConfig* clientCfg, whClientContext* clientCtx);

/**
 * @brief Run the main client application logic.
 *
 * Executes the client workload (e.g. echo requests, tests, benchmarks).
 *
 * @param[in] clientCtx Pointer to an initialized client context.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_RunClient(whClientContext* clientCtx);

/**
 * @brief Clean up a client and release its resources.
 *
 * Closes the communication channel and cleans up the client context.
 *
 * @param[in] clientCtx Pointer to the client context to clean up.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_CleanupClient(whClientContext* clientCtx);

/* Server API */

/**
 * @brief Populate a server configuration structure for a given instance.
 *
 * Sets up transport, NVM, flash, and crypto configuration for the specified
 * server instance.
 *
 * @param[in]  instance  Server instance index.
 * @param[out] serverCfg Pointer to the server configuration to populate.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_ConfigureServer(size_t instance, whServerConfig* serverCfg);

/**
 * @brief Initialize a server instance using the given configuration.
 *
 * @param[in]  instance  Server instance index.
 * @param[in]  serverCfg Pointer to the server configuration.
 * @param[out] serverCtx Pointer to the server context to initialize.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_InitServer(size_t instance, whServerConfig* serverCfg,
                       whServerContext* serverCtx);

/**
 * @brief Clean up a server instance and release its resources.
 *
 * @param[in] instance  Server instance index.
 * @param[in] serverCtx Pointer to the server context to clean up.
 * @return 0 on success, negative error code on failure.
 */
int wh_Port_CleanupServer(size_t instance, whServerContext* serverCtx);

/**
 * @brief Check if a new client connection notification has been received.
 *
 * Returns true once when a client has connected to the given server instance.
 * Subsequent calls will return 0 until the next client connects.
 *
 * @param[in] instance Server instance index.
 * @return 1 if a client connected notification was received, 0 otherwise.
 */
int wh_Port_ClientConnected(size_t instance);

/**
 * @brief Check if a client disconnection notification has been received.
 *
 * Returns true once when a client has disconnected from the given server
 * instance. Subsequent calls will return 0 until the next client disconnects.
 *
 * @param[in] instance Server instance index.
 * @return 1 if a client disconnected notification was received, 0 otherwise.
 */
int wh_Port_ClientDisconnected(size_t instance);

/** @} */ /* end Port */

#endif /* WOLFHSM_WH_PORT_H_ */
