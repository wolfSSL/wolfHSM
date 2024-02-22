#ifndef WOLFHSM_WH_SERVER_H_
#define WOLFHSM_WH_SERVER_H_

#include "wolfhsm/wh_comm.h"

#if 0
#include "wolfhsm/nvm.h"
#include "wolfhsm/nvm_remote.h"
#endif

/* Context structure to maintain the state of an HSM server */
typedef struct whServerContext_t {
    whCommServer comm[1];
#if 0
    whNvmContext* nvm_device;
    whNvmServer* nvm;
#endif
} whServer;

typedef struct whServerConfig_t {
    whCommServerConfig* comm;
#if 0
    whNvmConfig* nvm_device;
    whNvmServerConfig* nvm;
#endif
} whServerConfig;

/* Initialize the crypto, nvm, comms, and message handlers.
 */
int wh_Server_Init(whServer* server, whServerConfig* config);

/* Receive and handle an incoming request message if present.
 */
int wh_Server_HandleRequestMessage(whServer* server);

/* Stop all active and pending work, disconnect, and close all used resources.
 */
int wh_Server_Cleanup(whServer* server);

#endif /* WOLFHSM_WH_SERVER_H_ */
