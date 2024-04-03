#ifndef WOLFHSM_WH_SERVER_H_
#define WOLFHSM_WH_SERVER_H_

/*
 * WolfHSM Public Server API
 *
 */

#include <stdint.h>
#include <stdbool.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_message_custom.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

typedef struct CacheSlot {
    uint8_t commited;
    whNvmMetadata meta[1];
    uint8_t buffer[WOLFHSM_KEYCACHE_BUFSIZE];
} CacheSlot;

typedef struct {
    int devId;
    curve25519_key curve25519Private[1];
    curve25519_key curve25519Public[1];
    WC_RNG rng[1];
} crypto_context;

typedef struct {
    bool wcInitFlag: 1;
    bool wcRngInitFlag: 1;
    bool wcDevIdInitFlag: 1;
} whServerFlags;

/* Forward declaration of the server structure so its elements can reference
 * itself  (e.g. server argument to custom callback) */
struct whServerContext_t;

/* Type definition for a custom server callback  */
typedef int (*whServerCustomCb)(
    struct whServerContext_t* server,   /* points to dispatching server ctx */
    const whMessageCustom_Request* req, /* request from client to callback */
    whMessageCustom_Response*      resp /* response from callback to client */
);

/* Context structure to maintain the state of an HSM server */
typedef struct whServerContext_t {
    whServerFlags flags;
    whCommServer comm[1];
    whNvmContext nvm[1];
    crypto_context crypto[1];
    CacheSlot cache[WOLFHSM_NUM_RAMKEYS];
    whServerCustomCb customHandlerTable[WH_CUSTOM_RQST_NUM_CALLBACKS];
} whServerContext;

typedef struct whServerConfig_t {
    whCommServerConfig* comm_config;
    whNvmConfig* nvm_config;
#if defined WOLF_CRYPTO_CB /* TODO: should we be relying on wolfSSL defines? */
    int devId;
    CryptoDevCallbackFunc cryptocb;
#endif
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

/* Registers a custom callback with the server
*/
int wh_Server_RegisterCustomCb(whServerContext* server, uint16_t actionId, whServerCustomCb cb);

/* Receive and handle an incoming custom callback request
*/
int wh_Server_HandleCustomRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet);

#endif /* WOLFHSM_WH_SERVER_H_ */
