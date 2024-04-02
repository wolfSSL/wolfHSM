#ifndef WH_SERVER_CUSTOM_H_
#define WH_SERVER_CUSTOM_H_

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_message_custom.h"


typedef int (*whServerCustomCb)(
    whServerContext*               server, /* TODO: should this be const? */
    const whMessageCustom_Request* req, whMessageCustom_Response* resp);

int wh_Server_RegisterCustomCb(uint16_t actionId, whServerCustomCb cb);

int wh_Server_HandleCustomRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet);

#endif /* WH_SERVER_CUSTOM_H_ */