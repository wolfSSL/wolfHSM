#ifndef WOLFHSM_WH_SERVER_H_
#define WOLFHSM_WH_SERVER_H_

/*
 * WolfHSM Public Server API
 *
 */

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/curve25519.h"

typedef struct CacheSlot {
    uint8_t commited;
    whNvmMetadata meta[1];
    uint8_t buffer[WOLFHSM_KEYCACHE_BUFSIZE];
} CacheSlot;

typedef struct {
    curve25519_key curve25519Private[1];
    curve25519_key curve25519Public[1];
    WC_RNG rng[1];
} crypto_context;

/* Context structure to maintain the state of an HSM server */
typedef struct whServerContext_t {
    whCommServer comm[1];
    whNvmContext nvm[1];
    crypto_context crypto[1];
    CacheSlot cache[WOLFHSM_NUM_RAMKEYS];
} whServerContext;

typedef struct whServerConfig_t {
    whCommServerConfig* comm_config;
    whNvmConfig* nvm_config;
} whServerConfig;

/* Initialize the nvm, crypto, and comms, components.
 */
int wh_Server_Init(whServerContext* server, whServerConfig* config);

/* Receive and handle an incoming request message if present.
 */
int wh_Server_HandleRequestMessage(whServerContext* server);

/* Stop all active and pending work, disconnect, and close all used resources.
 */
int wh_Server_Cleanup(whServerContext* server);

#endif /* WOLFHSM_WH_SERVER_H_ */
