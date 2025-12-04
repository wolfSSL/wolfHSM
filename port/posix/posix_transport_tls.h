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
 * port/posix/posix_transport_tls.h
 *
 * wolfHSM Transport binding using TLS sockets with wolfSSL
 *
 * This transport extends the TCP transport with TLS encryption using
 * wolfSSL's embedded certificate buffers for authentication.
 *
 */

#ifndef PORT_POSIX_POSIX_TRANSPORT_TLS_H_
#define PORT_POSIX_POSIX_TRANSPORT_TLS_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "wolfhsm/wh_comm.h"

/* Adds TLS on top of the existing TCP transport */
#include "port/posix/posix_transport_tcp.h"

#ifdef WOLFHSM_CFG_TLS
#ifndef WOLFSSL_USER_SETTINGS
#include "wolfssl/options.h"
#endif
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/memory.h"

#define PTTLS_PACKET_MAX_SIZE WH_COMM_MTU
#define PTTLS_BUFFER_SIZE (sizeof(uint32_t) + PTTLS_PACKET_MAX_SIZE)

/** TLS configuration structure */
typedef struct {
    char* server_ip_string;
    int   server_port;
    bool  disable_peer_verification; /* Whether to verify certificates,
                                  defaults to verifying peer certificates */
    /* Certificate configuration - can be provided as buffers or filenames */
    const unsigned char* ca_cert;     /* CA certificate buffer (DER format) */
    int                  ca_cert_len; /* Length of CA certificate buffer */
    const unsigned char* cert;        /* Certificate buffer (DER format) */
    int                  cert_len;    /* Length of certificate buffer */
    const unsigned char* key;         /* Private key buffer (DER format) */
    int                  key_len;     /* Length of private key buffer */
#ifndef NO_PSK
    /* PSK configuration */
    /* Client PSK callback: unsigned int (*)(WOLFSSL* ssl, const char* hint,
     *                                      char* identity, unsigned int
     * id_max_len, unsigned char* key, unsigned int key_max_len) */
    unsigned int (*psk_client_cb)(WOLFSSL* ssl, const char* hint,
                                  char* identity, unsigned int id_max_len,
                                  unsigned char* key, unsigned int key_max_len);
    /* Server PSK callback for TLS 1.2: unsigned int (*)(WOLFSSL* ssl,
     *                                                   const char* identity,
     *                                                   unsigned char* key,
     *                                                   unsigned int
     * key_max_len) */
    unsigned int (*psk_server_cb)(WOLFSSL* ssl, const char* identity,
                                  unsigned char* key, unsigned int key_max_len);
#ifdef WOLFSSL_TLS13
    /* Server PSK callback for TLS 1.3: unsigned int (*)(WOLFSSL* ssl,
     *                                                    const char* identity,
     *                                                    unsigned char* key,
     *                                                    unsigned int
     * key_max_len, const char** ciphersuite) */
    unsigned int (*psk_server_tls13_cb)(WOLFSSL* ssl, const char* identity,
                                        unsigned char* key,
                                        unsigned int   key_max_len,
                                        const char**   ciphersuite);
#endif                             /* WOLFSSL_TLS13 */
    const char* psk_identity_hint; /* Server PSK identity hint */
#endif                             /* NO_PSK */
    void* heap_hint; /* A pointer to a WOLFSSL_HEAP_HINT structure for static
                      * memory allocation */
} posixTransportTlsConfig;

/** Client context and functions */
typedef enum {
    PTTLS_STATE_UNCONNECTED = 0, /* Not initialized */
    PTTLS_STATE_CONNECT_WAIT,    /* Async connect called */
    PTTLS_STATE_TLS_HANDSHAKE,   /* TLS handshake in progress */
    PTTLS_STATE_CONNECTED,       /* Connected and able to handle traffic */
    PTTLS_STATE_DONE             /* Was connected, now not */
} pttlsClientState;

typedef struct {
    whCommSetConnectedCb connectcb;
    void*                connectcb_arg;
    struct sockaddr_in   server_addr;
    pttlsClientState     state;
    int                  connect_fd_p1; /* fd plus 1 so 0 is invalid */
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WOLFSSL_CTX* ssl_ctx;
    WOLFSSL*     ssl;
#endif
    posixTransportTcpClientContext tcpCtx;
} posixTransportTlsClientContext;

int posixTransportTls_InitConnect(void* context, const void* config,
                                  whCommSetConnectedCb connectcb,
                                  void*                connectcb_arg);
int posixTransportTls_SendRequest(void* context, uint16_t size,
                                  const void* data);
int posixTransportTls_RecvResponse(void* context, uint16_t* out_size,
                                   void* data);
int posixTransportTls_CleanupConnect(void* context);

#define PTTLS_CLIENT_CB                              \
    {                                                \
        .Init    = posixTransportTls_InitConnect,    \
        .Send    = posixTransportTls_SendRequest,    \
        .Recv    = posixTransportTls_RecvResponse,   \
        .Cleanup = posixTransportTls_CleanupConnect, \
    }

/* Return the file descriptor of the connected socket to support poll/select */
int posixTransportTls_GetConnectFd(posixTransportTlsClientContext* context,
                                   int*                            out_fd);

/** Server context and functions */

typedef struct {
    whCommSetConnectedCb connectcb;
    void*                connectcb_arg;
    struct sockaddr_in   server_addr;
    struct sockaddr_in   client_addr;
    int                  listen_fd_p1; /* fd plus 1 so 0 is invalid */
    int                  accept_fd_p1; /* fd plus 1 so 0 is invalid */
    int                  request_recv;
    uint16_t             buffer_offset;
    uint8_t              buffer[PTTLS_BUFFER_SIZE];
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WOLFSSL_CTX* ssl_ctx;
    WOLFSSL*     ssl;
#endif
    posixTransportTcpServerContext tcpCtx;
} posixTransportTlsServerContext;

int posixTransportTls_InitListen(void* context, const void* config,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg);
int posixTransportTls_RecvRequest(void* context, uint16_t* out_size,
                                  void* data);
int posixTransportTls_SendResponse(void* context, uint16_t size,
                                   const void* data);
int posixTransportTls_CleanupListen(void* context);

#define PTTLS_SERVER_CB                             \
    {                                               \
        .Init    = posixTransportTls_InitListen,    \
        .Recv    = posixTransportTls_RecvRequest,   \
        .Send    = posixTransportTls_SendResponse,  \
        .Cleanup = posixTransportTls_CleanupListen, \
    }

/* Return the file descriptor of the listen socket to support poll/select */
int posixTransportTls_GetListenFd(posixTransportTlsServerContext* context,
                                  int*                            out_fd);

/* Return the file descriptor of the accepted socket to support poll/select */
int posixTransportTls_GetAcceptFd(posixTransportTlsServerContext* context,
                                  int*                            out_fd);

#endif /* WOLFHSM_CFG_TLS */
#endif /* !PORT_POSIX_POSIX_TRANSPORT_TLS_H_ */
