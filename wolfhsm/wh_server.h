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
/*
 * wolfhsm/wh_server.h
 *
*
 */

#ifndef WOLFHSM_WH_SERVER_H_
#define WOLFHSM_WH_SERVER_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declaration of the server structure so its elements can reference
 * itself  (e.g. server argument to custom callback) */
typedef struct whServerContext_t whServerContext;

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_message_customcb.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/sha256.h"
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#ifdef WOLFHSM_CFG_SHE_EXTENSION
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_server_she.h"
#endif


#ifndef WOLFHSM_CFG_NO_CRYPTO
/** Server crypto context and resource allocation */
typedef struct whServerCacheSlot {
    uint8_t        commited;
    whNvmMetadata   meta[1];
    uint8_t         buffer[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE];
} whServerCacheSlot;

typedef struct whServerBigCacheSlot {
    uint8_t       commited;
    whNvmMetadata meta[1];
    uint8_t       buffer[WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE];
} whServerBigCacheSlot;

typedef struct whServerCryptoContext {
    int devId;
#ifndef WC_NO_RNG
    WC_RNG rng[1];
#endif
    union {
#if 0
#ifndef NO_AES
        Aes aes[1];
#endif
#ifndef NO_RSA
        RsaKey rsa[1];
#endif
#ifdef HAVE_CURVE25519
        curve25519_key curve25519Private[1];
#endif
#endif /* 0 */
#ifdef WOLFSSL_CMAC
        Cmac cmac[1];
#endif
    } algoCtx;
} whServerCryptoContext;


#endif /* !WOLFHSM_CFG_NO_CRYPTO */

/** Server custom callback */

/* Type definition for a custom server callback  */
typedef int (*whServerCustomCb)(
    whServerContext* server,              /* points to dispatching server ctx */
    const whMessageCustomCb_Request* req, /* request from client to callback */
    whMessageCustomCb_Response*      resp /* response from callback to client */
);


/** Server DMA address translation and validation */

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
    WH_DMA_OPER_CLIENT_WRITE_PRE = 2,
    /* Indicates server has just written from client memory */
    WH_DMA_OPER_CLIENT_WRITE_POST = 3,
} whServerDmaOper;

#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
typedef enum {
    WH_DMA_COPY_OPER_CLIENT_READ = 0,
    WH_DMA_COPY_OPER_CLIENT_WRITE = 1,
} whServerDmaCopyOper;
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */

/* Flags embedded in request/response structs provided by client */
typedef struct {
    uint8_t cacheForceInvalidate : 1;
    uint8_t : 7;
} whServerDmaFlags;

/* DMA callbacks invoked internally by wolfHSM before and after every client
 * memory operation. */
typedef int (*whServerDmaClientMemCb)(struct whServerContext_t* server,
                                      uintptr_t clientAddr, void** serverPtr,
                                      size_t len, whServerDmaOper oper,
                                      whServerDmaFlags flags);

#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
/* DMA callback invoked to copy from the client */
typedef int (*whServerDmaMemCopyCb)(struct whServerContext_t* server,
                                      uintptr_t clientAddr, uintptr_t serverPtr,
                                      size_t len, whServerDmaCopyOper oper,
                                      whServerDmaFlags flags);
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */

/* DMA address entry within the allowed tables. */
/* Note: These are translated addresses from the Server's perspective*/
typedef struct {
    void*  addr;
    size_t size;
} whServerDmaAddr;

typedef whServerDmaAddr whServerDmaAddrList[WOLFHSM_CFG_SERVER_DMAADDR_COUNT];

/* Holds allowable client read/write addresses */
typedef struct {
    whServerDmaAddrList readList;  /* Allowed client read addresses */
    whServerDmaAddrList writeList; /* Allowed client write addresses */
} whServerDmaAddrAllowList;

/* Server DMA configuration struct for initializing a server */
typedef struct {
    whServerDmaClientMemCb          cb;               /* DMA callback */
#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
    whServerDmaMemCopyCb            memCopyCb;       /* DMA memory copy callback */
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */
    const whServerDmaAddrAllowList* dmaAddrAllowList; /* allowed addresses */
} whServerDmaConfig;

typedef struct {
    whServerDmaClientMemCb          cb;               /* DMA callback */
#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
    whServerDmaMemCopyCb            memCopyCb;       /* DMA memory copy callback */
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */
    const whServerDmaAddrAllowList* dmaAddrAllowList; /* allowed addresses */
} whServerDmaContext;


/** Server config and context */

typedef struct whServerConfig_t {
    whCommServerConfig* comm_config;
    whNvmContext*       nvm;

#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext* crypto;
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    whServerSheContext* she;
#endif /* WOLFHSM_CFG_SHE_EXTENSION */
#if defined WOLF_CRYPTO_CB
    int devId;
#endif /* WOLF_CRYPTO_CB */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */
    whServerDmaConfig* dmaConfig;
} whServerConfig;


/* Context structure to maintain the state of an HSM server */
struct whServerContext_t {
    whNvmContext* nvm;
    whCommServer  comm[1];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext* crypto;
    whServerCacheSlot      cache[WOLFHSM_CFG_SERVER_KEYCACHE_COUNT];
    whServerBigCacheSlot   bigCache[WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT];
#ifdef WOLFHSM_CFG_SHE_EXTENSION
    whServerSheContext* she;
#endif
#endif /* !WOLFHSM_CFG_NO_CRYPTO */
    whServerCustomCb   customHandlerTable[WOLFHSM_CFG_SERVER_CUSTOMCB_COUNT];
    whServerDmaContext dma;
    int                connected;
    uint16_t           cancelSeq;
};


/** Public server context functions */

/* Initialize the comms and crypto cache components.
 * Note: NVM and Crypto components must be initialized prior to Server Init
 */

/**
 * @brief Initializes the server context with the provided configuration.
 *
 * This function must be called before any other server functions are used on
 * the supplied context. Note that the NVM and Crypto components of the config
 * structure MUST be initialized before calling this function.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] config Pointer to the server configuration.
 * @return int Returns 0 on success, WH_ERROR_BADARGS if the arguments are
 * invalid, or WH_ERROR_ABORTED if initialization fails.
 */
int wh_Server_Init(whServerContext* server, whServerConfig* config);

/**
 * @brief Sets the connection state of the server.
 *
 * The connection state indicates whether the server is ready to handle incoming
 * requests. This function should be invoked when the underlying transport is
 * ready for use.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] connected The connection state to set.
 * @return int Returns 0 on success, or WH_ERROR_BADARGS if the arguments are
 * invalid.
 */
int wh_Server_SetConnected(whServerContext* server, whCommConnected connected);

/**
 * @brief Sets a callback function that should be invoked by the underlying
 * transport after it is initialized
 *
 * The connection state indicates whether the server is ready to handle incoming
 * requests. This function should be invoked when the underlying transport
 * is ready for use.
 *
 * @param[in] s Pointer to the server context.
 * @param[in] connected The connection state to set.
 * @return int Returns 0 on success.
 */
int wh_Server_SetConnectedCb(void* s, whCommConnected connected);

/**
 * @brief Gets the connection state of the server.
 *
 * @param[in] server Pointer to the server context.
 * @param[out] out_connected Pointer to store the connection state.
 * @return int Returns 0 on success, or WH_ERROR_BADARGS if the arguments are
 * invalid.
 */
int wh_Server_GetConnected(whServerContext* server,
                           whCommConnected* out_connected);

/**
 * @brief Gets the canceled sequence number of the server.
 *
 * The canceled sequence number is the comms layer sequence number of the last
 * canceled request. This number is set by the server port in response to an
 * out-of-band signal from the client when the client wishes to cancel a
 * request.
 *
 * @param[in] server Pointer to the server context.
 * @param[out] outSeq Pointer to store the canceled sequence number.
 * @return int Returns 0 on success, or WH_ERROR_BADARGS if the arguments are
 * invalid
 *
 */
int wh_Server_GetCanceledSequence(whServerContext* server, uint16_t* outSeq);


/**
 * @brief Sets the canceled sequence number of the server.
 *
 * The canceled sequence number is the comms layer sequence number of the last
 * canceled request. This function should be used by the server port to set the
 * canceled sequence number in response to an out-of-band signal from the
 * client.
 *
 */
int wh_Server_SetCanceledSequence(whServerContext* server, uint16_t cancelSeq);

/**
 * @brief Handles incoming request messages and dispatches them to the
 * appropriate handlers.
 *
 * This function processes incoming request messages from the communication
 * server in a non-blocking fashion. It determines the message group and action,
 * and dispatches the request to the appropriate handler. The function also
 * sends a response back to the client.
 *
 * @param[in] server Pointer to the server context.
 * @return int Returns 0 on success, WH_ERROR_BADARGS if the arguments are
 * invalid, WH_ERROR_NOTREADY if the server is not connected or no data is
 * available, or a negative error code on failure.
 */
int wh_Server_HandleRequestMessage(whServerContext* server);

/**
 * @brief Cleans up the server context and associated resources.
 *
 * This function releases any resources associated with the server context,
 * including communication server resources. It resets the server context
 * to its initial state.
 *
 * @param[in] server Pointer to the server context.
 * @return int Returns WH_ERROR_OK on success, or WH_ERROR_BADARGS if the
 * arguments are invalid.
 */
int wh_Server_Cleanup(whServerContext* server);

/**
 * @brief Checks if the communication transport is a DMA transport.
 *
 * This function determines whether the communication server is using a DMA
 * transport by checking for the presence of a heap hint, which is specific
 * to DMA-enabled transports.
 *
 * @param[in] comm Pointer to the communication server context.
 * @return int Returns 1 if this is a DMA transport, 0 otherwise.
 */
int wh_Server_IsDmaTransport(whCommServer* comm);

/** Server custom callback functions */

/**
 * @brief Registers a custom callback handler for a specific action.
 *
 * This function allows the server to register a custom callback handler
 * for a specific action ID. The callback will be invoked when a request
 * with the corresponding action ID is received.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] actionId The action ID for which the callback is being registered.
 * @param[in] cb The custom callback handler to register.
 * @return int Returns WH_ERROR_OK on success, or WH_ERROR_BADARGS if the
 * arguments are invalid.
 */
int wh_Server_RegisterCustomCb(whServerContext* server, uint16_t action,
                               whServerCustomCb handler);

/**
 * @brief Handles incoming custom callback requests.
 *
 * This function processes incoming custom callback requests by invoking
 * the registered custom callback handler for the specified action. It
 * translates the request and response messages and sends the appropriate
 * response back to the client.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] magic The magic number for the request.
 * @param[in] action The action ID of the request.
 * @param[in] seq The sequence number of the request.
 * @param[in] req_size The size of the request packet.
 * @param[in] req_packet Pointer to the request packet data.
 * @param[out] out_resp_size Pointer to store the size of the response packet.
 * @param[out] resp_packet Pointer to store the response packet data.
 * @return int Returns WH_ERROR_OK on success, WH_ERROR_BADARGS if the arguments
 * are invalid, WH_ERROR_ABORTED if the request is malformed, or a negative
 * error code on failure.
 */
int wh_Server_HandleCustomCbRequest(whServerContext* server, uint16_t magic,
                                    uint16_t action, uint16_t seq,
                                    uint16_t req_size, const void* req_packet,
                                    uint16_t* out_resp_size, void* resp_packet);

/** Server DMA functions */
#ifdef WOLFHSM_CFG_DMA

/**
 * @brief Registers a custom client DMA callback
 *
 * This function allows the server to register a custom callback handler
 * for processing client memory operations. The callback will be invoked during
 * DMA operations to transform client addresses, manipulate caches, etc.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] cb The custom DMA callback handler to register.
 * @return int Returns WH_ERROR_OK on success, or WH_ERROR_BADARGS if the
 * arguments are invalid.
 */
int wh_Server_DmaRegisterCb(struct whServerContext_t* server,
                            whServerDmaClientMemCb    cb);


#ifdef WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY
/**
 * @brief Registers a custom memory copy callback for DMA operations.
 * This function allows the server to register a callback that will be invoked
 * during DMA memory copy operations. The callback overrides the use of
 * memcpy when copying to and from client memory. This is useful if standard
 * memcpy cannot be used to copy data back and forth between the client, even
 * after client addresses are transformed through the standard DMA callbacks
 * (e.g. if client memory can only be accessed though a hardware FIFO or register
 * interface)
 * @param[in] server Pointer to the server context.
 * @param[in] cb The custom memory copy callback handler to register.
 * @return int Returns WH_ERROR_OK on success, or WH_ERROR_BADARGS if the
 * arguments are invalid.
 */
int wh_Server_DmaRegisterMemCopyCb(whServerContext*     server,
                                   whServerDmaMemCopyCb cb);
#endif /* WOLFHSM_CFG_DMA_CUSTOM_CLIENT_COPY */

/**
 * @brief Registers the allowable client read/write addresses for DMA.
 *
 * This function allows the server to register a list of allowable client
 * addresses for DMA read and write operations. The server will check
 * these addresses during DMA operations to ensure they are within the
 * allowed range for the client
 *
 * @param[in] server Pointer to the server context.
 * @param[in] allowlist Pointer to the list of allowable client addresses.
 * @return int Returns WH_ERROR_OK on success, or WH_ERROR_BADARGS if the
 * arguments are invalid.
 */
int wh_Server_DmaRegisterAllowList(struct whServerContext_t*       server,
                                   const whServerDmaAddrAllowList* allowlist);

/**
 * @brief Checks if a DMA memory operation is allowed based on the server's
 * allowlist.
 *
 * This function verifies whether a specified DMA memory operation is permitted
 * by checking the operation type and the address range against the server's
 * registered allowlist. If no allowlist is registered, the operation is
 * allowed.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] oper The DMA operation type (e.g., read or write).
 * @param[in] addr The address to be checked.
 * @param[in] size The size of the memory operation.
 * @return int Returns WH_ERROR_OK if the operation is allowed, WH_ERROR_BADARGS
 * if the arguments are invalid, or WH_ERROR_ACCESS if the operation is not
 * allowed.
 */
int wh_Server_DmaCheckMemOperAllowed(const struct whServerContext_t* server,
                                     whServerDmaOper oper, void* addr,
                                     size_t size);

/**
 * @brief Processes a client address for DMA operations, using the native
 * pointer size of the system
 *
 * This function transforms a client address for DMA operations. It performs
 * user-supplied address transformations, cache manipulations, and checks the
 * transformed address against the server's allowlist if registered.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] clientAddr The client address to be processed.
 * @param[out] serverPtr Pointer to store the transformed server address.
 * @param[in] len The length of the memory operation.
 * @param[in] oper The DMA operation type (e.g., read or write).
 * @param[in] flags Flags for the DMA operation.
 * @return int Returns WH_ERROR_OK on success, WH_ERROR_BADARGS if the arguments
 * are invalid, or a negative error code on failure.
 */
int wh_Server_DmaProcessClientAddress(struct whServerContext_t* server,
                                      uintptr_t clientAddr, void** serverPtr,
                                      size_t len, whServerDmaOper oper,
                                      whServerDmaFlags flags);

/**
 * @brief Copies data from a client address to a server address using the
 * native pointer size of the system.
 *
 * This function performs a DMA read operation, copying data from a client
 * address to a server address. It processes the client address, checks the
 * server address against the allowlist, and performs the actual memory copy.
 *
 * @param[in] server Pointer to the server context.
 * @param[out] serverPtr Pointer to the server memory where data will be copied.
 * @param[in] clientAddr The client address from which data will be copied.
 * @param[in] len The length of the data to be copied.
 * @param[in] flags Flags for the DMA operation.
 * @return int Returns WH_ERROR_OK on success, WH_ERROR_BADARGS if the arguments
 * are invalid, or a negative error code on failure.
 */
int whServerDma_CopyFromClient(struct whServerContext_t* server,
                               void* serverPtr, uintptr_t clientAddr,
                               size_t len, whServerDmaFlags flags);

/**
 * @brief Copies data from a server address to a client address using the
 * native pointer size of the system.
 *
 * This function performs a DMA write operation, copying data from a server
 * address to a client address. It processes the client
 * address, checks the server address against the allowlist, and performs the
 * actual memory copy.
 *
 * @param[in] server Pointer to the server context.
 * @param[in] clientAddr The client address to which data will be copied.
 * @param[in] serverPtr Pointer to the server memory from which data will be
 * copied.
 * @param[in] len The length of the data to be copied.
 * @param[in] flags Flags for the DMA operation.
 * @return int Returns WH_ERROR_OK on success, WH_ERROR_BADARGS if the arguments
 * are invalid, or a negative error code on failure.
 */
int whServerDma_CopyToClient(struct whServerContext_t* server,
                             uintptr_t clientAddr, void* serverPtr, size_t len,
                             whServerDmaFlags flags);
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_WH_SERVER_H_ */
