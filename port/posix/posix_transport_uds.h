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
 * port/posix/posix_transport_uds.h
 *
 * wolfHSM transport binding using Unix domain sockets (AF_UNIX / SOCK_STREAM).
 *
 * Behavioural contract — identical to posix_transport_tcp:
 *   - All functions are non-blocking; they return WH_ERROR_NOTREADY when an
 *     operation is still in progress and the caller must retry.
 *   - Client connect is asynchronous.  InitConnect starts the connection;
 *     subsequent Send/Recv calls complete it transparently.
 *   - Server accept is implicit inside RecvRequest.
 *
 * Key differences from posix_transport_tcp:
 *   - Address is a filesystem path, not an IP string + port number.
 *   - Server unlinks the path before bind() to clear any stale socket file
 *     left by a previous crash.  This replaces the SO_REUSEADDR idiom used
 *     for TCP (SO_REUSEADDR has no effect on AF_UNIX paths).
 *   - Server chmod(path, 0660) after bind so only the owning user and group
 *     may connect.  Wider permissions would let any local process reach the
 *     HSM server.
 *   - POSIX limits sun_path to 108 bytes including the null terminator.
 *     POSIX_TRANSPORT_UDS_PATH_MAX (107) is the maximum usable path length.
 *   - TCP_NODELAY is not applicable to AF_UNIX and is omitted.
 *
 * Example usage:
 *
 *   posixTransportUdsConfig cfg = { .server_path = "/run/wolfhsm/wolfhsm.sock" };
 *
 *   // Server side:
 *   whTransportServerCb  ptu_scb  = PTU_SERVER_CB;
 *   posixTransportUdsServerContext ptu_sc = {0};
 *   whCommServerConfig sc_conf = {
 *       .transport_cb      = &ptu_scb,
 *       .transport_context = &ptu_sc,
 *       .transport_config  = &cfg,
 *   };
 *
 *   // Client side:
 *   whTransportClientCb  ptu_ccb  = PTU_CLIENT_CB;
 *   posixTransportUdsClientContext ptu_cc = {0};
 *   whCommClientConfig cc_conf = {
 *       .transport_cb      = &ptu_ccb,
 *       .transport_context = &ptu_cc,
 *       .transport_config  = &cfg,
 *       .client_id         = 1,
 *   };
 */

#ifndef PORT_POSIX_POSIX_TRANSPORT_UDS_H_
#define PORT_POSIX_POSIX_TRANSPORT_UDS_H_

#include <stdint.h>
#include <sys/un.h>      /* struct sockaddr_un, AF_UNIX */

#include "wolfhsm/wh_comm.h"

/*
 * AF_UNIX sun_path is 108 bytes on Linux (including the null terminator).
 * We define the max usable path as 107 so a properly terminated string always
 * fits.  Callers that supply a longer path receive WH_ERROR_BADARGS.
 *
 * Decision: use the POSIX-mandated struct sockaddr_un sun_path size minus one
 * rather than hard-coding 107, so this stays correct on platforms where the
 * kernel field is larger.
 */
#define POSIX_TRANSPORT_UDS_PATH_MAX ((int)(sizeof(((struct sockaddr_un*)0)->sun_path) - 1))

/* Packet framing is identical to TCP: uint32_t big-endian length prefix
 * followed by the payload.  The MTU is shared with all other transports. */
#define PTU_PACKET_MAX_SIZE WH_COMM_MTU
#define PTU_BUFFER_SIZE     ((int)(sizeof(uint32_t) + PTU_PACKET_MAX_SIZE))


/* ── Common configuration ──────────────────────────────────────────────────── */

typedef struct {
    /* Null-terminated filesystem path for the Unix domain socket.
     * Must be <= POSIX_TRANSPORT_UDS_PATH_MAX characters (107). */
    const char* server_path;
} posixTransportUdsConfig;


/* ── Client ────────────────────────────────────────────────────────────────── */

/*
 * State machine mirrors the TCP client exactly.  UDS connect() on a
 * non-blocking socket still returns EINPROGRESS; we poll for POLLOUT to
 * confirm the connection is established.
 *
 * Additional UDS-specific errno handling in HandleConnect:
 *   ENOENT  — socket file does not exist yet (server not started); treated
 *             like TCP's ECONNREFUSED: close socket, return to UNCONNECTED,
 *             let the caller retry later.
 */
typedef enum {
    PTU_STATE_UNCONNECTED = 0,
    PTU_STATE_CONNECT_WAIT,
    PTU_STATE_CONNECTED,
    PTU_STATE_DONE
} ptuClientState;

typedef struct {
    whCommSetConnectedCb connectcb;
    void*                connectcb_arg;
    struct sockaddr_un   server_addr;   /* Populated from config path */
    ptuClientState       state;
    int                  connect_fd_p1; /* Actual fd + 1; 0 == invalid */
    int                  request_sent;
    uint16_t             buffer_offset;
    uint8_t              buffer[PTU_BUFFER_SIZE];
} posixTransportUdsClientContext;

int posixTransportUds_InitConnect(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg);
int posixTransportUds_SendRequest(void* context, uint16_t size,
        const void* data);
int posixTransportUds_RecvResponse(void* context, uint16_t* out_size,
        void* data);
int posixTransportUds_CleanupConnect(void* context);

/* Macro to populate a whTransportClientCb at compile time. */
#define PTU_CLIENT_CB                                   \
{                                                       \
    .Init    = posixTransportUds_InitConnect,           \
    .Send    = posixTransportUds_SendRequest,           \
    .Recv    = posixTransportUds_RecvResponse,          \
    .Cleanup = posixTransportUds_CleanupConnect,        \
}

/* Return the connected fd for use with poll()/select(). */
int posixTransportUds_GetConnectFd(posixTransportUdsClientContext* context,
        int* out_fd);


/* ── Server ────────────────────────────────────────────────────────────────── */

typedef struct {
    whCommSetConnectedCb connectcb;
    void*                connectcb_arg;
    /* server_addr.sun_path holds the bound path so CleanupListen can unlink
     * the socket file even without access to the original config. */
    struct sockaddr_un   server_addr;
    int                  listen_fd_p1; /* Actual fd + 1; 0 == invalid */
    int                  accept_fd_p1; /* Actual fd + 1; 0 == invalid */
    int                  request_recv;
    uint16_t             buffer_offset;
    uint8_t              buffer[PTU_BUFFER_SIZE];
} posixTransportUdsServerContext;

int posixTransportUds_InitListen(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg);
int posixTransportUds_RecvRequest(void* context, uint16_t* out_size,
        void* data);
int posixTransportUds_SendResponse(void* context, uint16_t size,
        const void* data);
int posixTransportUds_CleanupListen(void* context);

/* Macro to populate a whTransportServerCb at compile time. */
#define PTU_SERVER_CB                                   \
{                                                       \
    .Init    = posixTransportUds_InitListen,            \
    .Recv    = posixTransportUds_RecvRequest,           \
    .Send    = posixTransportUds_SendResponse,          \
    .Cleanup = posixTransportUds_CleanupListen,         \
}

/* Return the listen fd for use with poll()/select(). */
int posixTransportUds_GetListenFd(posixTransportUdsServerContext* context,
        int* out_fd);

/* Return the accepted client fd for use with poll()/select(). */
int posixTransportUds_GetAcceptFd(posixTransportUdsServerContext* context,
        int* out_fd);

#endif /* PORT_POSIX_POSIX_TRANSPORT_UDS_H_ */
