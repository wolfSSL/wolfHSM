#ifndef WOLFHSM_WH_SERVER_WRAPKEY_H_
#define WOLFHSM_WH_SERVER_WRAPKEY_H_

#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_server.h"

int wh_Server_HandleWrapKeyRequest(whServerContext* server, uint16_t magic,
                                   uint16_t action, uint16_t req_size,
                                   const void* req_packet,
                                   uint16_t* out_resp_size, void* resp_packet);
#endif
