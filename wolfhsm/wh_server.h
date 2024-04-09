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
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_server_dma.h"

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


/* Forward declaration of the server structure so its elements can reference
 * itself  (e.g. server argument to custom callback) */
struct whServerContext_t;

/* Type definition for a custom server callback  */
typedef int (*whServerCustomCb)(
    struct whServerContext_t* server,   /* points to dispatching server ctx */
    const whMessageCustomCb_Request* req, /* request from client to callback */
    whMessageCustomCb_Response*      resp /* response from callback to client */
);

#if 0
typedef int (*whDmaClientMem32Cb)(struct whServerContext_t* server,
                                  uint32_t clientAddr, void** serverPtr,
                                  uint32_t len, whDmaOper oper,
                                  whDmaFlags flags);
typedef int (*whDmaClientMem64Cb)(struct whServerContext_t* server,
                                  uint64_t clientAddr, void** serverPtr,
                                  uint64_t len, whDmaOper oper,
                                  whDmaFlags flags);

typedef struct {
    whDmaClientMem32Cb cb32;
    whDmaClientMem64Cb cb64;
} whDmaCb;

/* Indicates to the callback the type of operation the callback should handle */
typedef enum {
    WH_DMA_OPER_CLIENT_READ_PRE = 0, /* Descriptive comment: address validation/Map/unmap/prefetch/cache/etc*/
    WH_DMA_OPER_CLIENT_READ_POST = 1,
    WH_DMA_OPER_CLIENT_WRITE_PRE  = 2,
    WH_DMA_OPER_CLIENT_WRITE_POST = 3,
} whDmaOper;

/* Flags embedded in request/response structs provided by client */
typedef struct {
    uint8_t cacheForceInvalidate : 1;
} whDmaFlags;
#endif

/* Context structure to maintain the state of an HSM server */
typedef struct whServerContext_t {
    whCommServer comm[1];
    whNvmContext* nvm;
    crypto_context* crypto;
    CacheSlot cache[WOLFHSM_NUM_RAMKEYS];
    whServerCustomCb customHandlerTable[WH_CUSTOM_CB_NUM_CALLBACKS];
    whDmaCb dmaCb; 
} whServerContext;

typedef struct whServerConfig_t {
    whCommServerConfig* comm_config;
    whNvmContext* nvm;
    crypto_context* crypto;
#if defined WOLF_CRYPTO_CB /* TODO: should we be relying on wolfSSL defines? */
    int devId;
#endif
} whServerConfig;

/* Initialize the comms and crypto cache components.
 * Note: NVM and Crypto must be initialized prior to Server Init
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
int wh_Server_HandleCustomCbRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet);

/* Registers custom client DMA callbacs to handle platform specific restrictions
 * on accessing the client address space such as caching and address translation */
int wh_Server_DmaRegisterCb(whServerContext* server, whDmaCb cb);

/* Helper functions to invoke user supplied client address DMA callbacks */
int wh_Server_DmaProcessClientAddress32(whServerContext* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whDmaOper oper,
                                        whDmaFlags flags);
int wh_Server_DmaProcessClientAddress64(whServerContext* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whDmaOper oper,
                                        whDmaFlags flags);

#endif /* WOLFHSM_WH_SERVER_H_ */
