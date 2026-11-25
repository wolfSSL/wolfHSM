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

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER

#include <stdint.h>
#include <stddef.h>
#include <string.h>

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

/* Write the reply into the packet and set its size */
static int _FormatResponse(uint16_t                          magic,
                           const whMessageCustomCb_Response* resp,
                           uint16_t* out_resp_size, void* resp_packet)
{
    int rc;

    /* Clear the packet first. The translation does not write every byte, and
     * old bytes in the buffer must not go back to the client */
    memset(resp_packet, 0, sizeof(*resp));

    rc = wh_MessageCustomCb_TranslateResponse(magic, resp, resp_packet);
    if (rc == WH_ERROR_OK) {
        *out_resp_size = sizeof(*resp);
    }
    return rc;
}

int wh_Server_HandleCustomCbRequest(whServerContext* server, uint16_t magic,
                                    uint16_t action, uint16_t seq,
                                    uint16_t req_size, const void* req_packet,
                                    uint16_t* out_resp_size, void* resp_packet)
{
    (void)seq;

    int                        rc   = 0;
    whMessageCustomCb_Request  req  = {0};
    whMessageCustomCb_Response resp = {0};

    if (NULL == server || NULL == req_packet || NULL == resp_packet ||
        out_resp_size == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (req_size != sizeof(whMessageCustomCb_Request)) {
        /* Request is malformed, so only the callback ID in the message header
         * is known. Reply with that and the error */
        resp.id  = action;
        resp.err = WH_ERROR_ABORTED;
        return _FormatResponse(magic, &resp, out_resp_size, resp_packet);
    }

    /* Translate the request */
    if ((rc = wh_MessageCustomCb_TranslateRequest(magic, req_packet, &req)) !=
        WH_ERROR_OK) {
        return rc;
    }

    /* Reply type defaults to the request type. The callback may change it. */
    resp.type = req.type;

    if ((action < WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT) &&
        (server->customHandlerTable[action] != NULL)) {
        /* If this isn't a query to check if the callback exists, invoke the
         * registered callback, storing the return value in the response  */
        if (req.type != WH_MESSAGE_CUSTOM_CB_TYPE_QUERY) {
            resp.rc = server->customHandlerTable[action](server, &req, &resp);
        }
        /* err is wolfHSM's own result. The callback reports errors through its
         * return value, so this replaces anything it wrote to err */
        resp.err = WH_ERROR_OK;
    }
    else {
        /* No callback at this ID, or the ID is past the end of the table */
        resp.err = WH_ERROR_NOHANDLER;
    }

    /* tag response with requested callback ID for client-side bookkeeping*/
    resp.id = req.id;

    return _FormatResponse(magic, &resp, out_resp_size, resp_packet);
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
