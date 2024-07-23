/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * src/wh_server_customcb.c
 *
 */

/* Pick up server config */
#include "wolfhsm/wh_server.h"

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_customcb.h"

#include "wolfhsm/wh_server.h"


int wh_Server_RegisterCustomCb(whServerContext* server, uint16_t action,
                               whServerCustomCb handler)
{
    if (NULL == server || NULL == handler ||
        action >= WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT) {
        return WH_ERROR_BADARGS;
    }

    server->customHandlerTable[action] = handler;

    return WH_ERROR_OK;
}


int wh_Server_HandleCustomCbRequest(whServerContext* server, uint16_t magic,
                                    uint16_t action, uint16_t seq,
                                    uint16_t req_size, const void* req_packet,
                                    uint16_t* out_resp_size, void* resp_packet)
{
    int                        rc   = 0;
    whMessageCustomCb_Request  req  = {0};
    whMessageCustomCb_Response resp = {0};

    if (NULL == server || NULL == req_packet || NULL == resp_packet ||
        out_resp_size == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (action >= WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT) {
        /* Invalid callback index  */
        /* TODO: is this the appropriate error to return? */
        return WH_ERROR_BADARGS;
    }

    if (req_size != sizeof(whMessageCustomCb_Request)) {
        /* Request is malformed */
        return WH_ERROR_ABORTED;
    }

    /* Translate the request */
    if ((rc = wh_MessageCustomCb_TranslateRequest(magic, req_packet, &req)) !=
        WH_ERROR_OK) {
        return rc;
    }

    if (server->customHandlerTable[action] != NULL) {
        /* If this isn't a query to check if the callback exists, invoke the
         * registered callback, storing the return value in the reponse  */
        if (req.type != WH_MESSAGE_CUSTOM_CB_TYPE_QUERY) {
            resp.rc = server->customHandlerTable[action](server, &req, &resp);
        }
        /* TODO: propagate other wolfHSM error codes (requires modifiying caller
         * function) once generic server code supports it */
        resp.err = WH_ERROR_OK;
    }
    else {
        /* No callback was registered, populate response error. We must
         * return success to ensure the "error" response is sent  */
        resp.err = WH_ERROR_NOHANDLER;
    }

    /* tag response with requested callback ID for client-side bookkeeping*/
    resp.id = req.id;

    /* Translate the response */
    if ((rc = wh_MessageCustomCb_TranslateResponse(
             magic, &resp, resp_packet)) != WH_ERROR_OK) {
        return rc;
    }

    *out_resp_size = sizeof(resp);

    return WH_ERROR_OK;
}
