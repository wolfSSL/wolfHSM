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
 * wolfhsm/wh_comm.h
 *
 * Library to provide client to server requests and server to client responses.
 * Fundamentally, communications are reliable, bidirectional, and packet-based
 * with a fixed MTU.  Packets are delivered in-order without any intrinsic
 * queuing nor OOB support.  Transports deliver complete packets up to the MTU
 * size and provide the number of bytes received.
 *
 * Note: Multibyte data will be passed in native order, which means clients and
 * servers must be the SAME endianess or will be required to translate data
 * elements in messages.  Translate helper functions are provided here and used
 * to interpret header fields.
 *
 * All functions return an integer value with 0 meaning success and !=0 an error
 * enumerated either within wolfhsm/wh_error.h.  Unless otherwise noted, all
 * functions are non-blocking and each may update the context state or perform
 * other bookkeeping actions as necessary.
 *
 */

#ifndef WOLFHSM_WH_COMM_H_
#define WOLFHSM_WH_COMM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>  /* For sized ints */

/** Packet content types */
/* Request/response packets are composed of a single fixed-length header
 * (whCommHeader) followed immediately by variable-length data between 0 and
 * WOLFHSM_CFG_COMM_DATA_LEN bytes.
 */
#define WH_COMM_MTU (8 + WOLFHSM_CFG_COMM_DATA_LEN)
#define WH_COMM_MTU_U64_COUNT ((WH_COMM_MTU + 7) / 8)

/* Support for endian and version differences */
/* Version is BCD to avoid conflict with endian marker */
#define WH_COMM_VERSION (0x01u)
#define WH_COMM_ENDIAN (0xA5u)

#define WH_COMM_MAGIC_ENDIAN_MASK 0xFF00u
#define WH_COMM_MAGIC_VERSION_MASK 0x00FFu

#define WH_COMM_MAGIC_NATIVE    ((WH_COMM_ENDIAN << 8) | WH_COMM_VERSION)
#define WH_COMM_MAGIC_SWAP      (WH_COMM_ENDIAN | (WH_COMM_VERSION << 8))

#define WH_COMM_FLAGS_SWAPTEST(_magic) \
    (_magic                 & WH_COMM_MAGIC_ENDIAN_MASK) ==  \
    (WH_COMM_MAGIC_NATIVE   & WH_COMM_MAGIC_ENDIAN_MASK)

/* 8 byte Header for a packet, request or response. On-the-wire format */
typedef struct {
    uint16_t magic;     /* Endian marker with version */
    uint16_t kind;      /* Kind of packet.  Enumerated in message.h */
    uint16_t seq;       /* Sequence number. Incremented on request, copied for
                         * response. */
    uint16_t aux;       /* Session identifier for request or error indicator
                         * for response. */
} whCommHeader;

enum WH_COMM_AUX_ENUM {
    WH_COMM_AUX_REQ_NORMAL      = 0x0000, /* Normal request. No session */
    /* Request Aux values 1-0xFFFE are session ids */
    WH_COMM_AUX_REQ_NORESP      = 0xFFFF, /* Async request without response*/

    WH_COMM_AUX_RESP_OK         = 0x0000, /* Response is valid */
    WH_COMM_AUX_RESP_ERROR      = 0x0001, /* Request failed with error */
    WH_COMM_AUX_RESP_FATAL      = 0xFFFE, /* Server condition is fatal */
    WH_COMM_AUX_RESP_UNSUPP     = 0xFFFF, /* Request is not supported */
};


/** Translation utilities */

/* Byteswap val if magic doesn't have the same endianness as native */
uint8_t wh_Translate8(uint16_t magic, uint8_t val);
uint16_t wh_Translate16(uint16_t magic, uint16_t val);
uint32_t wh_Translate32(uint16_t magic, uint32_t val);
uint64_t wh_Translate64(uint16_t magic, uint64_t val);

/* Helper macros for struct members */
#define WH_T16(_m, _d, _s, _f) _d->_f = wh_Translate16(_m, _s->_f)
#define WH_T32(_m, _d, _s, _f) _d->_f = wh_Translate32(_m, _s->_f)
#define WH_T64(_m, _d, _s, _f) _d->_f = wh_Translate64(_m, _s->_f)


/** Common client/server functions */

/* Status of whether a client is connected or not */
typedef enum {
    WH_COMM_DISCONNECTED = 0,
    WH_COMM_CONNECTED = 1,
} whCommConnected;

/* Provide a callback to invoke when the transport can detect a connect or a
 * disconnect */
typedef int (*whCommSetConnectedCb)(void* context, whCommConnected connected);



/** CommClient component types */

/* Client transport interface */
typedef struct {
    /* Reset the state of the transport and establish communications.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context or config, or invalid config
     *          WH_ERROR_ABORTED if fatal error occurred.
     */
    int (*Init)(void* context, const void* config,
            whCommSetConnectedCb connectcb, void* connectcb_arg);

    /* Send a new request to the server.  This may also reconnect as necessary.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context, or invalid size
     *          WH_ERROR_NOTREADY if send buffer is not free. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Send)(void* context, uint16_t size, const void* data);

    /* Receive a new response from the server.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context
     *          WH_ERROR_NOTREADY if recv buffer is not filled. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Recv)(void* context, uint16_t *out_size, void* data);

    /* Close the connection.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context
     */
    int (*Cleanup)(void* context);
} whTransportClientCb;

typedef struct {
    const whTransportClientCb* transport_cb;
    void* transport_context;
    const void* transport_config;
    whCommSetConnectedCb connect_cb;
    uint8_t client_id;
    uint8_t WH_PAD[7];
} whCommClientConfig;

/* Context structure for a client.  Note the client context will track the
 * request sequence number and provide a buffer for at least 1 packet.
 */
typedef struct {
    uint64_t WH_ALIGN; /* Ensure following is 64-bit aligned */
    uint64_t packet[WH_COMM_MTU_U64_COUNT];
    void* transport_context;
    const whTransportClientCb* transport_cb;
    whCommSetConnectedCb connect_cb;
    whCommHeader* hdr;
    uint8_t* data;
    int initialized;
    uint16_t reqid;
    uint16_t seq;
    uint16_t size;
    uint8_t client_id;
    uint8_t server_id;
    uint8_t WH_PAD[4];
} whCommClient;


/* Reset the state of the client context and begin the connection to a server
 * using the config data specified.  On success, the Status of the context will
 * be greater than UNINITIALIZED, depending on the transport specifics.
 */
int wh_CommClient_Init(whCommClient* context, const whCommClientConfig* config);

/* If a request buffer is available, send a new request to the server.  The
 * transport will update the sequence number on success.
 */
int wh_CommClient_SendRequest(whCommClient* context, uint16_t magic,
    uint16_t kind, uint16_t *out_seq, uint16_t data_size, const void* data);

/* If a response packet has been buffered, get the header and copy the data out
 * of the buffer.
 */
int wh_CommClient_RecvResponse(whCommClient* context,
        uint16_t* out_magic, uint16_t* out_kind, uint16_t* out_seq,
        uint16_t* out_size, void* data);

/* Get a pointer to the data portion of the internal buffer that is
 * HW_COMM_DATA_LEN bytes.
 */
uint8_t* wh_CommClient_GetDataPtr(whCommClient* context);

/* Inform the server that no further communications are necessary and any
 * unfinished requests can be ignored.
 */
int wh_CommClient_Cleanup(whCommClient* context);


/** CommServer component types */

/* Server transport interface */
typedef struct {
    /* Reset the state of the transport and be ready for communications.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context or config, or invalid config
     *          WH_ERROR_ABORTED if fatal error occurred.
     */
    int (*Init)(void* context, const void* config,
                  whCommSetConnectedCb connectcb, void* connectcb_arg);

    /* Receive a new request from the client. This may also accept a connection.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context
     *          WH_ERROR_NOTREADY if recv buffer is not filled. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Recv)(void* context, uint16_t* inout_size, void* data);

    /* Send a new request to the server.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL data or context, or invalid size
     *          WH_ERROR_NOTREADY if send buffer is not free. Retry.
     *          WH_ERROR_ABORTED if fatal error occurred. Cleanup.
     */
    int (*Send)(void* context, uint16_t data_size, const void* data);

    /* Close the connection.
     * Returns: 0 on success,
     *          WH_ERROR_BADARGS if NULL context
     */
    int (*Cleanup)(void* context);
} whTransportServerCb;

typedef struct {
    void* transport_context;
    const whTransportServerCb* transport_cb;
    const void* transport_config;
    uint8_t server_id;
    uint8_t WH_PAD[7];
} whCommServerConfig;

/* Context structure for a server.  Note the client context will track the
 * request sequence number and provide a buffer for at least 1 request packet.
 */
typedef struct {
    uint64_t WH_ALIGN; /* Ensure following is 64-bit aligned */
    uint64_t packet[WH_COMM_MTU_U64_COUNT];
    void* transport_context;
    const whTransportServerCb* transport_cb;
    whCommHeader* hdr;
    uint8_t* data;
    int initialized;
    uint16_t reqid;
    uint8_t client_id;
    uint8_t server_id;
} whCommServer;

/* Reset the state of the server context and begin the connection to a client
 * using the config data specified.  On success, the Status of the context will
 * be greater than UNINITIALIZED, depending on the transport specifics.
 */
int wh_CommServer_Init(whCommServer* context, const whCommServerConfig* config,
                whCommSetConnectedCb connectcb, void* connectcb_arg);

/* If a request packet has been buffered, get the header and copy the data out
 * of the buffer.
 */
int wh_CommServer_RecvRequest(whCommServer* context,
        uint16_t* out_magic, uint16_t* out_kind, uint16_t* out_seq,
        uint16_t* out_size, void* data);

/* Upon completion of the request, send the response packet using the same seq
 * as the incoming request.  Note that overriding the seq number should only be
 * used for asynchronous notifications, such as keep-alive or close.
 */
int wh_CommServer_SendResponse(whCommServer* context,
        uint16_t magic, uint16_t kind, uint16_t seq,
        uint16_t data_size, const void* data);

/* Get a pointer to the data portion of the internal buffer that is
 * WOLFHSM_CFG_COMM_DATA_LEN bytes long.
 */
uint8_t* wh_CommServer_GetDataPtr(whCommServer* context);


int wh_CommServer_Cleanup(whCommServer* context);

#endif /* WOLFHSM_WH_COMM_H_ */
