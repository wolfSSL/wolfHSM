#ifndef WOLFHSM_WH_SERVER_H_
#define WOLFHSM_WH_SERVER_H_

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_common.h"

#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/curve25519.h"

#if 0
#include "wolfhsm/nvm.h"
#include "wolfhsm/nvm_remote.h"
#endif

typedef struct CacheSlot {
    uint8_t commited;
    whNvmMetadata meta[1];
    uint8_t buffer[WOLFHSM_NVM_MAX_OBJECT_SIZE];
} CacheSlot;

typedef struct {
    curve25519_key curve25519Private[1];
    curve25519_key curve25519Public[1];
    WC_RNG rng[1]; 
} crypto_context;

/* Context structure to maintain the state of an HSM server */
typedef struct whServerContext_t {
    whCommServer comm[1];
    crypto_context crypto[1];
    CacheSlot cache[WOLFHSM_NUM_RAMKEYS];
#if 0
    whNvmFlashContext nvm[1];
#endif
} whServerContext;

typedef struct whServerConfig_t {
    whCommServerConfig* comm;
#if 0
    whNvmConfig* nvm_device;
    whNvmServerConfig* nvm;
#endif
} whServerConfig;

/* Initialize the crypto, nvm, comms, and message handlers.
 */
int wh_Server_Init(whServerContext* server, whServerConfig* config);

/* Receive and handle an incoming request message if present.
 */
int wh_Server_HandleRequestMessage(whServerContext* server);

/* Stop all active and pending work, disconnect, and close all used resources.
 */
int wh_Server_Cleanup(whServerContext* server);

#endif /* WOLFHSM_WH_SERVER_H_ */
