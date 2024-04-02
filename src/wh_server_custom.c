#include "wolfhsm/wh_server_custom.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_custom.h"


/* Statically allocated callback table holding user callbacks */
static whServerCustomCb customHandlerTable[WH_MESSAGE_ACTION_MAX] = {NULL};


int wh_Server_RegisterCustomCb(uint16_t action, whServerCustomCb handler)
{
    if (NULL == handler || action >= WH_MESSAGE_ACTION_MAX) {
        return WH_ERROR_BADARGS;
    }

    customHandlerTable[action] = handler;

    return WH_ERROR_OK;
}


int wh_Server_HandleCustomRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet)
{
    int                      rc   = 0;
    whMessageCustom_Request  req  = {0};
    whMessageCustom_Response resp = {0};


    if (action >= WH_MESSAGE_ACTION_MAX) {
        /* Invalid callback index  */
        return WH_ERROR_BADARGS;
    }

    if (req_size != sizeof(whMessageCustom_Request)) {
        /* Request is malformed */
        return WH_ERROR_ABORTED;
    }

    /* Translate the request */
    if ((rc = wh_MessageCustom_TranslateRequest(magic, req_packet, &req)) !=
        WH_ERROR_OK) {
        return rc;
    }

    if (customHandlerTable[action] != NULL) {
        /* Invoke the registered callback, storing the return value in the
         * reponse  */
        resp.rc = customHandlerTable[action](server, &req, &resp);
        /* TODO: propagate wolfHSM error codes (requires modifiying caller
         * function)*/
        resp.err = WH_ERROR_OK;
    }
    else {
        /* No callback was registered, populate response errors, but we must
         * return success to ensure the "error" response is sent  */
        /* TODO: what should we set resp.rc to? */
        resp.err = WH_ERROR_NO_HANDLER;
    }

    /* Translate the response and set output size */
    if ((rc = wh_MessageCustom_TranslateResponse(magic, &resp, resp_packet)) !=
        WH_ERROR_OK) {
        return rc;
    }
    *out_resp_size = sizeof(resp);

    return WH_ERROR_OK;
}
