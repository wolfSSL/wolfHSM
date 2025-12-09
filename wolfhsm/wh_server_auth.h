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
/*
 * wolfhsm/wh_server_auth.h
 *
 * Server-side Auth Manager API
 */

#ifndef WOLFHSM_WH_SERVER_AUTH_H_
#define WOLFHSM_WH_SERVER_AUTH_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_server.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER

/**
 * @brief Handles incoming authentication and authorization requests.
 *
 * This function processes incoming auth request messages from the communication
 * server and dispatches them to the appropriate auth manager functions.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] magic The magic number for the request.
 * @param[in] action The action ID of the request.
 * @param[in] seq The sequence number of the request.
 * @param[in] req_size The size of the request packet.
 * @param[in] req_packet Pointer to the request packet data.
 * @param[out] out_resp_size Pointer to store the size of the response packet.
 * @param[out] resp_packet Pointer to store the response packet data.
 * @return int Returns 0 on success, or a negative error code on failure.
 */
int wh_Server_HandleAuthRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);

#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#endif /* !WOLFHSM_WH_SERVER_AUTH_H_ */
