#ifndef WOLFHSM_WH_SERVER_INTERNAL_H_
#define WOLFHSM_WH_SERVER_INTERNAL_H_

/*
 * WolfHSM Internal Server API
 *
 */

#include <stdint.h>

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"

/* Handle an NVM request and generate a response
 * Defined in server_nvm.c */
int wh_Server_HandleNvmRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint16_t req_size, const void* req_packet,
        uint16_t *out_resp_size, void* resp_packet);

#endif /* WOLFHSM_WH_SERVER_INTERNAL_H_ */
