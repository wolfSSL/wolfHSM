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
 * src/wh_server_auth.c
 *
 * Server-side Auth Manager request handler
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER

/* System libraries */
#include <stdint.h>
#include <stddef.h>  /* For NULL */

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_auth.h"

#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_auth.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_auth.h"

int wh_Server_HandleAuthRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet)
{
    /* TODO: Handle auth manager requests
     * This would be used for an admin on the client side to add users, set
     * permissions and manage sessions.
     *
     * A non admin could use this for Auth Manager API's that require less
     * permissions or for messages to authenticate and open a session. */

    (void)server;
    (void)magic;
    (void)action;
    (void)seq;
    (void)req_size;
    (void)req_packet;
    (void)out_resp_size;
    (void)resp_packet;
    
    *out_resp_size = 0;
    return WH_ERROR_NOTIMPL;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
