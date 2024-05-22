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
#ifndef WOLFHSM_WH_SERVER_H_
#define WOLFHSM_WH_SERVER_H_

/*
 * WolfHSM Public Server API
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_message_customcb.h"

#ifndef WOLFHSM_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#endif  /* WOLFHSM_NO_CRYPTO */

/* Forward declaration of the server structure so its elements can reference
 * itself  (e.g. server argument to custom callback) */
typedef struct whServerContext_t whServerContext;

#ifndef WOLFHSM_NO_CRYPTO
/** Server crypto context and resource allocation */
typedef struct CacheSlot {
    uint8_t commited;
    whNvmMetadata meta[1];
    uint8_t buffer[WOLFHSM_KEYCACHE_BUFSIZE];
} CacheSlot;

typedef struct {
    int devId;
    Aes aes[1];
    RsaKey rsa[1];
    ecc_key eccPrivate[1];
    ecc_key eccPublic[1];
    curve25519_key curve25519Private[1];
    curve25519_key curve25519Public[1];
    WC_RNG rng[1];
} crypto_context;

#ifdef WOLFHSM_SHE_EXTENSION
typedef struct {
    uint8_t sbState;
    uint8_t cmacKeyFound;
    uint8_t ramKeyPlain;
    uint8_t uidSet;
    uint32_t blSize;
    uint32_t blSizeReceived;
    uint32_t rndInited;
    uint8_t prngState[WOLFHSM_SHE_KEY_SZ];
    uint8_t prngKey[WOLFHSM_SHE_KEY_SZ];
    uint8_t uid[WOLFHSM_SHE_UID_SZ];
} she_context;
#endif
#endif  /* WOLFHSM_NO_CRYPTO */

/** Server custom callback */

/* Type definition for a custom server callback  */
typedef int (*whServerCustomCb)(
    whServerContext* server,   /* points to dispatching server ctx */
    const whMessageCustomCb_Request* req, /* request from client to callback */
    whMessageCustomCb_Response*      resp /* response from callback to client */
);


/** Server DMA address translation and validation */

#define WH_DMA_ADDR_ALLOWLIST_COUNT (10)

/* Indicates to a DMA callback the type of memory operation the callback must
 * act on. Common use cases are remapping client addresses into server address
 * space (map in READ_PRE/WRITE_PRE, unmap in READ_POST/WRITE_POST), or
 * invalidating a cache block before reading from or after writing to client
 * memory */
typedef enum {
    /* Indicates server is about to read from client memory */
    WH_DMA_OPER_CLIENT_READ_PRE = 0,
    /* Indicates server has just read from client memory */
    WH_DMA_OPER_CLIENT_READ_POST = 1,
    /* Indicates server is about to write to client memory */
    WH_DMA_OPER_CLIENT_WRITE_PRE  = 2,
    /* Indicates server has just written from client memory */
    WH_DMA_OPER_CLIENT_WRITE_POST = 3,
} whServerDmaOper;

/* Flags embedded in request/response structs provided by client */
typedef struct {
    uint8_t cacheForceInvalidate : 1;
    uint8_t :7;
} whServerDmaFlags;

/* DMA callbacks invoked internally by wolfHSM before and after every client
 * memory operation. There are separate callbacks for processing 32-bit and
 * 64-bit client addresses */
typedef int (*whServerDmaClientMem32Cb)(struct whServerContext_t* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
typedef int (*whServerDmaClientMem64Cb)(struct whServerContext_t* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);

/* DMA address entry within the allowed tables. */
/* Note: These are translated addresses from the Server's perspective*/
typedef struct {
    void*  addr;
    size_t size;
} whServerDmaAddr;

typedef whServerDmaAddr whServerDmaAddrList[WH_DMA_ADDR_ALLOWLIST_COUNT];

/* Holds allowable client read/write addresses */
typedef struct {
    whServerDmaAddrList readList;  /* Allowed client read addresses */
    whServerDmaAddrList writeList; /* Allowed client write addresses */
} whServerDmaAddrAllowList;

/* Server DMA configuration struct for initializing a server */
typedef struct {
    whServerDmaClientMem32Cb        cb32; /* DMA callback for 32-bit system */
    whServerDmaClientMem64Cb        cb64; /* DMA callback for 64-bit system */
    const whServerDmaAddrAllowList* dmaAddrAllowList; /* allowed addresses */
} whServerDmaConfig;

typedef struct {
    whServerDmaClientMem32Cb        cb32; /* DMA callback for 32-bit system */
    whServerDmaClientMem64Cb        cb64; /* DMA callback for 64-bit system */
    const whServerDmaAddrAllowList* dmaAddrAllowList; /* allowed addresses */
} whServerDmaContext;


/** Server config and context */

typedef struct whServerConfig_t {
    whCommServerConfig* comm_config;
    whNvmContext* nvm;

#ifndef WOLFHSM_NO_CRYPTO
    crypto_context* crypto;
#ifdef WOLFHSM_SHE_EXTENSION
    she_context* she;
#endif
#if defined WOLF_CRYPTO_CB /* TODO: should we be relying on wolfSSL defines? */
    int devId;
#endif
#endif  /* WOLFHSM_NO_CRYPTO */
    whServerDmaConfig* dmaConfig;
} whServerConfig;


/* Context structure to maintain the state of an HSM server */
struct whServerContext_t {
    whCommServer comm[1];
    whNvmContext* nvm;
#ifndef WOLFHSM_NO_CRYPTO
    crypto_context* crypto;
    CacheSlot cache[WOLFHSM_NUM_RAMKEYS];
#ifdef WOLFHSM_SHE_EXTENSION
    she_context* she;
#endif
#endif  /* WOLFHSM_NO_CRYPTO */
    whServerCustomCb customHandlerTable[WH_CUSTOM_CB_NUM_CALLBACKS];
    whServerDmaContext dma;
    int connected;
#ifdef WOLFHSM_SHE_EXTENSION
#endif
    uint8_t padding[4];
};


/** Public server context functions */

/* Initialize the comms and crypto cache components.
 * Note: NVM and Crypto components must be initialized prior to Server Init
 */
int wh_Server_Init(whServerContext* server, whServerConfig* config);

/* Allow an external input to set the connected state. */
int wh_Server_SetConnected(whServerContext *server, whCommConnected connected);

/* Invoke SetConnected but using an untyped context pointer, suitable for a
 * CommServer callback */
int wh_Server_SetConnectedCb(void* s, whCommConnected connected);

/* Return the connected state. */
int wh_Server_GetConnected(whServerContext *server,
                            whCommConnected *out_connected);

/*
 * Receive and handle an incoming request message if present.
 */
int wh_Server_HandleRequestMessage(whServerContext* server);

/*
 * Stop all active and pending work, disconnect, and close all used resources.
 */
int wh_Server_Cleanup(whServerContext* server);

/** Server custom callback functions */

/* Registers a custom callback with the server
*/
int wh_Server_RegisterCustomCb( whServerContext* server,
                                uint16_t actionId,
                                whServerCustomCb cb);

/* Receive and handle an incoming custom callback request
*/
int wh_Server_HandleCustomCbRequest(whServerContext* server, uint16_t magic,
                                  uint16_t action, uint16_t seq,
                                  uint16_t req_size, const void* req_packet,
                                  uint16_t* out_resp_size, void* resp_packet);

/** Server DMA functions */

/* Registers custom client DMA callbacks to handle platform specific
 * restrictions on accessing the client address space such as caching and
 * address translation */
int wh_Server_DmaRegisterCb32(struct whServerContext_t* server,
                              whServerDmaClientMem32Cb  cb);
int wh_Server_DmaRegisterCb64(struct whServerContext_t* server,
                              whServerDmaClientMem64Cb  cb);
int wh_Server_DmaRegisterAllowList(struct whServerContext_t*       server,
                                   const whServerDmaAddrAllowList* allowlist);

/* Checks a desired memory operation against the server allowlist */
int wh_Server_DmaCheckMemOperAllowed(const struct whServerContext_t* server,
                                     whServerDmaOper oper, void* addr,
                                     size_t size);

/* Helper functions to invoke user supplied client address DMA callbacks */
int wh_Server_DmaProcessClientAddress32(struct whServerContext_t* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);
int wh_Server_DmaProcessClientAddress64(struct whServerContext_t* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whServerDmaOper oper,
                                        whServerDmaFlags flags);

/* Helper functions to copy data to/from client addresses that invoke the
 * appropriate callbacks and allowlist checks */
int whServerDma_CopyFromClient32(struct whServerContext_t* server,
                                 void* serverPtr, uint32_t clientAddr,
                                 size_t len, whServerDmaFlags flags);
int whServerDma_CopyFromClient64(struct whServerContext_t* server,
                                 void* serverPtr, uint64_t clientAddr,
                                 size_t len, whServerDmaFlags flags);

int whServerDma_CopyToClient32(struct whServerContext_t* server,
                               uint32_t clientAddr, void* serverPtr, size_t len,
                               whServerDmaFlags flags);
int whServerDma_CopyToClient64(struct whServerContext_t* server,
                               uint64_t clientAddr, void* serverPtr, size_t len,
                               whServerDmaFlags flags);

#endif /* WOLFHSM_WH_SERVER_H_ */
