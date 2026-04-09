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
 * port/posix/posix_transport_uds.c
 *
 * wolfHSM transport using Unix domain sockets (AF_UNIX / SOCK_STREAM).
 *
 * Design notes — read before modifying:
 *
 * Structure mirrors posix_transport_tcp.c exactly.  Where the two files
 * differ, comments call out the reason.  When in doubt about a decision,
 * grep for the same pattern in posix_transport_tcp.c to see the TCP
 * precedent.
 *
 * Packet framing:
 *   [uint32_t big-endian length][payload bytes]
 *   Identical to TCP.  UDS is a reliable, ordered byte stream, so the same
 *   framing works without any changes.
 *
 * Non-blocking I/O:
 *   All sockets are set O_NONBLOCK immediately after creation.  Every
 *   send/recv returns WH_ERROR_NOTREADY on EAGAIN/EINTR so the caller can
 *   retry without blocking the server dispatch loop.
 *
 * fd + 1 sentinel:
 *   connect_fd_p1, listen_fd_p1, accept_fd_p1 store the real fd + 1.
 *   Zero therefore means "no valid fd", avoiding the ambiguity of fd == 0
 *   (which is a valid file descriptor — stdin — in some edge cases).
 *
 * Server socket lifecycle:
 *   unlink(path) → socket() → bind() → chmod() → listen() → accept() → ...
 *   The unlink before bind clears any stale socket file from a previous
 *   crash.  chmod(0660) after bind restricts access to owner + group; the
 *   daemon should run as a dedicated user/group pair.
 *   CleanupListen unlinks the path again so no stale file remains after a
 *   clean shutdown.
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/un.h>      /* struct sockaddr_un */
#include <sys/stat.h>    /* chmod */
#include <unistd.h>      /* close, unlink */
#include <fcntl.h>       /* fcntl, O_NONBLOCK */
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>  /* htonl, ntohl — byte-order for packet length prefix */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "port/posix/posix_transport_uds.h"


/* ── Local declarations ────────────────────────────────────────────────────── */

static int posixTransportUds_MakeNonBlocking(int fd);

static int posixTransportUds_Send(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t size, const void* data);

static int posixTransportUds_Recv(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t* out_size, void* data);

static int posixTransportUds_HandleConnect(
        posixTransportUdsClientContext* c);

static int posixTransportUds_Close(posixTransportUdsClientContext* c);


/* ── Local implementations ─────────────────────────────────────────────────── */

static int posixTransportUds_MakeNonBlocking(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return WH_ERROR_ABORTED;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/*
 * posixTransportUds_Send — write a framed packet to fd.
 *
 * First call: copies size-prefixed data into buffer[].  Subsequent calls
 * (when a previous send was partial) resume from buffer_offset.
 * Returns 0 when the full packet has been sent, WH_ERROR_NOTREADY when
 * only part was sent (caller must retry), WH_ERROR_ABORTED on fatal error.
 *
 * MSG_NOSIGNAL: prevents SIGPIPE if the peer has closed the connection.
 * Without it the process would receive SIGPIPE (default: terminate), which
 * is the wrong behaviour for a server handling multiple clients.
 */
static int posixTransportUds_Send(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t size, const void* data)
{
    int      rc;
    int      send_size;
    int      remaining;
    uint32_t* packet_len;
    void*    packet_data;

    if (    (fd < 0)            ||
            (buffer_offset == NULL) ||
            (buffer == NULL)    ||
            (size == 0)         ||
            (size > PTU_PACKET_MAX_SIZE) ||
            (data == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    packet_len  = (uint32_t*)&buffer[0];
    packet_data = &buffer[sizeof(uint32_t)];
    send_size   = (int)(sizeof(uint32_t) + size);

    if (*buffer_offset == 0) {
        /* First call: serialise the packet into the staging buffer. */
        *packet_len = htonl((uint32_t)size);
        memcpy(packet_data, data, size);
    }

    remaining = send_size - (int)*buffer_offset;

    rc = (int)send(fd, &buffer[*buffer_offset], (size_t)remaining,
                   MSG_NOSIGNAL);
    if (rc < 0) {
        switch (errno) {
        case EAGAIN:
        case EINTR:
            return WH_ERROR_NOTREADY;
        default:
            *buffer_offset = 0;
            return WH_ERROR_ABORTED;
        }
    }

    if (rc != remaining) {
        /* Partial write — advance offset and ask caller to retry. */
        *buffer_offset = (uint16_t)(*buffer_offset + rc);
        return WH_ERROR_NOTREADY;
    }

    *buffer_offset = 0;
    return WH_ERROR_OK;
}

/*
 * posixTransportUds_Recv — read a framed packet from fd.
 *
 * Reads the 4-byte length prefix first, then the payload.  Both reads may
 * be partial (EAGAIN on a non-blocking socket), so buffer_offset tracks how
 * many bytes have been accumulated.  Returns 0 only when the complete
 * packet has been received.
 *
 * Paranoia: the received length field is range-checked before reading the
 * payload.  A zero length or a length exceeding PTU_PACKET_MAX_SIZE is
 * treated as a fatal framing error — the peer is either misbehaving or the
 * connection is corrupt.
 */
static int posixTransportUds_Recv(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t* out_size, void* data)
{
    int      rc;
    uint32_t* packet_len;
    void*    packet_data;
    uint32_t packet_size;
    uint32_t size_remaining;

    if (    (fd < 0)                    ||
            (buffer_offset == NULL)     ||
            ((int)*buffer_offset > PTU_BUFFER_SIZE) ||
            (buffer == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    packet_len  = (uint32_t*)&buffer[0];
    packet_data = &buffer[sizeof(uint32_t)];

    /* Phase 1: read the 4-byte length prefix. */
    if (*buffer_offset < sizeof(uint32_t)) {
        rc = (int)read(fd, &buffer[*buffer_offset],
                       sizeof(uint32_t) - *buffer_offset);
        if (rc < 0) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                return WH_ERROR_NOTREADY;
            default:
                *buffer_offset = 0;
                return WH_ERROR_ABORTED;
            }
        }
        if (rc == 0) {
            /* EOF: peer closed connection. */
            *buffer_offset = 0;
            return WH_ERROR_ABORTED;
        }
        *buffer_offset = (uint16_t)(*buffer_offset + rc);
    }

    if (*buffer_offset < sizeof(uint32_t)) {
        return WH_ERROR_NOTREADY;
    }

    /* Validate the length before using it as a read size. */
    packet_size = ntohl(*packet_len);
    if (packet_size == 0 || packet_size > PTU_PACKET_MAX_SIZE) {
        /* Framing error — discard and abort. */
        *buffer_offset = 0;
        return WH_ERROR_ABORTED;
    }

    /* Phase 2: read the payload. */
    size_remaining = packet_size - ((uint32_t)*buffer_offset
                                    - (uint32_t)sizeof(uint32_t));

    rc = (int)read(fd, &buffer[*buffer_offset], size_remaining);
    if (rc < 0) {
        switch (errno) {
        case EAGAIN:
        case EINPROGRESS:
        case EINTR:
            return WH_ERROR_NOTREADY;
        default:
            *buffer_offset = 0;
            return WH_ERROR_ABORTED;
        }
    }
    if (rc == 0) {
        /* EOF mid-packet. */
        *buffer_offset = 0;
        return WH_ERROR_ABORTED;
    }

    *buffer_offset = (uint16_t)(*buffer_offset + rc);
    size_remaining -= (uint32_t)rc;

    if (size_remaining > 0) {
        return WH_ERROR_NOTREADY;
    }

    /* Complete packet received. Copy out to caller. */
    if (data != NULL) {
        memcpy(data, packet_data, packet_size);
    }
    if (out_size != NULL) {
        *out_size = (uint16_t)packet_size;
    }
    *buffer_offset = 0;
    return WH_ERROR_OK;
}


/* ── Client implementation ─────────────────────────────────────────────────── */

/*
 * posixTransportUds_HandleConnect — drive the non-blocking connect state
 * machine one step forward.
 *
 * UDS-specific errno handling on top of the TCP state machine:
 *   ENOENT: the socket file does not exist yet (server not started).
 *           Treated identically to TCP's ECONNREFUSED: close the socket,
 *           return to UNCONNECTED so InitConnect/SendRequest will retry.
 *   ECONNREFUSED: server is not listening (socket exists but no accept).
 *           Same handling as ENOENT.
 */
static int posixTransportUds_HandleConnect(posixTransportUdsClientContext* c)
{
    int ret;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (c->state) {
    case PTU_STATE_UNCONNECTED:
        ret = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ret < 0) {
            c->state = PTU_STATE_DONE;
            return WH_ERROR_ABORTED;
        }
        if (ret <= 2) {
            /* fd 0/1/2 conflict with stdin/stdout/stderr — close and bail. */
            close(ret);
            c->state = PTU_STATE_DONE;
            return WH_ERROR_ABORTED;
        }
        c->connect_fd_p1 = ret + 1;

        ret = posixTransportUds_MakeNonBlocking(c->connect_fd_p1 - 1);
        if (ret != WH_ERROR_OK) {
            (void)posixTransportUds_Close(c);
            c->state = PTU_STATE_DONE;
            return WH_ERROR_ABORTED;
        }

        ret = connect(c->connect_fd_p1 - 1,
                      (struct sockaddr*)&c->server_addr,
                      sizeof(c->server_addr));
        if (ret == 0) {
            /* Immediate success (unusual for non-blocking, but valid). */
            c->state = PTU_STATE_CONNECTED;
            return WH_ERROR_OK;
        }

        switch (errno) {
        case EINPROGRESS:
        case EINTR:
            c->state = PTU_STATE_CONNECT_WAIT;
            return WH_ERROR_NOTREADY;

        case ENOENT:
            /* Socket file does not exist yet — server not started. */
            /* Fall through to ECONNREFUSED handling. */
        case ECONNREFUSED:
            /* Server not listening.  Close socket; caller may retry. */
            (void)posixTransportUds_Close(c);
            c->state = PTU_STATE_UNCONNECTED;
            return WH_ERROR_NOTFOUND;

        default:
            (void)posixTransportUds_Close(c);
            c->state = PTU_STATE_DONE;
            return WH_ERROR_ABORTED;
        }

    case PTU_STATE_CONNECT_WAIT:
    {
        struct pollfd pfd;
        int pollret;

        pfd.fd      = c->connect_fd_p1 - 1;
        pfd.events  = POLLOUT;
        pfd.revents = 0;

        pollret = poll(&pfd, 1, 0);
        if (pollret < 0) {
            (void)posixTransportUds_Close(c);
            c->state = PTU_STATE_DONE;
            return WH_ERROR_ABORTED;
        }
        if (pollret == 0) {
            /* Not connected yet. */
            return WH_ERROR_NOTREADY;
        }

        /* pollret > 0 — check which events fired. */
        if ((pfd.revents & POLLHUP) != 0) {
            /* HUP without OUT usually means server is not listening. */
            (void)posixTransportUds_Close(c);
            c->state = PTU_STATE_UNCONNECTED;
            return WH_ERROR_NOTFOUND;
        }
        if (((pfd.revents & POLLNVAL) != 0) || ((pfd.revents & POLLERR) != 0)) {
            (void)posixTransportUds_Close(c);
            c->state = PTU_STATE_DONE;
            return WH_ERROR_ABORTED;
        }
        if ((pfd.revents & POLLOUT) != 0) {
            c->state = PTU_STATE_CONNECTED;
            return WH_ERROR_OK;
        }
        return WH_ERROR_NOTREADY;
    }

    case PTU_STATE_CONNECTED:
        return WH_ERROR_OK;

    case PTU_STATE_DONE:
        return WH_ERROR_ABORTED;

    default:
        c->state = PTU_STATE_DONE;
        return WH_ERROR_ABORTED;
    }
}

static int posixTransportUds_Close(posixTransportUdsClientContext* c)
{
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (c->connect_fd_p1 != 0) {
        close(c->connect_fd_p1 - 1);
        c->connect_fd_p1 = 0;
    }
    return WH_ERROR_OK;
}

int posixTransportUds_InitConnect(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    int rc;
    posixTransportUdsClientContext* c  = context;
    const posixTransportUdsConfig*  cf = config;
    size_t path_len;

    if (c == NULL || cf == NULL || cf->server_path == NULL) {
        return WH_ERROR_BADARGS;
    }

    path_len = strlen(cf->server_path);
    if (path_len == 0 || (int)path_len > POSIX_TRANSPORT_UDS_PATH_MAX) {
        /* Empty path or path too long for sun_path. */
        return WH_ERROR_BADARGS;
    }

    memset(c, 0, sizeof(*c));

    c->server_addr.sun_family = AF_UNIX;
    /* strncpy is intentional: sun_path is a fixed char array; we validated
     * path_len above so this is always null-terminated. */
    strncpy(c->server_addr.sun_path, cf->server_path,
            sizeof(c->server_addr.sun_path) - 1);
    c->server_addr.sun_path[sizeof(c->server_addr.sun_path) - 1] = '\0';

    rc = posixTransportUds_HandleConnect(c);

    /* Accept NOTREADY (async connect) and NOTFOUND (server not up yet)
     * as non-fatal startup conditions — the caller will retry via Send. */
    if (    rc == WH_ERROR_OK       ||
            rc == WH_ERROR_NOTFOUND ||
            rc == WH_ERROR_NOTREADY ) {
        c->connectcb     = connectcb;
        c->connectcb_arg = connectcb_arg;
        if (c->connectcb != NULL) {
            c->connectcb(connectcb_arg, WH_COMM_CONNECTED);
        }
        rc = WH_ERROR_OK;
    }
    return rc;
}

int posixTransportUds_GetConnectFd(posixTransportUdsClientContext* context,
        int* out_fd)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (context->state) {
    case PTU_STATE_UNCONNECTED:
        return WH_ERROR_NOTREADY;

    case PTU_STATE_CONNECT_WAIT:
    case PTU_STATE_CONNECTED:
        if (out_fd != NULL) {
            *out_fd = context->connect_fd_p1 - 1;
        }
        return WH_ERROR_OK;

    case PTU_STATE_DONE:
    default:
        return WH_ERROR_ABORTED;
    }
}

int posixTransportUds_SendRequest(void* context,
        uint16_t size, const void* data)
{
    int rc;
    posixTransportUdsClientContext* c = context;

    if (    c == NULL           ||
            size == 0           ||
            size > PTU_PACKET_MAX_SIZE ||
            data == NULL ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_sent == 1) {
        /* A request is already in flight; cannot send another. */
        return WH_ERROR_NOTREADY;
    }

    /* Complete a pending async connect if necessary. */
    rc = posixTransportUds_HandleConnect(c);
    if (rc == WH_ERROR_OK) {
        rc = posixTransportUds_Send(
                c->connect_fd_p1 - 1,
                &c->buffer_offset,
                c->buffer,
                size, data);

        if (rc != WH_ERROR_NOTREADY) {
            c->buffer_offset = 0;
            if (rc == WH_ERROR_OK) {
                c->request_sent = 1;
            } else {
                /* Fatal send error: notify upper layer of disconnect. */
                if (c->connectcb != NULL) {
                    c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
                }
            }
        }
    } else if (rc == WH_ERROR_NOTFOUND) {
        /* Server still not up; squash to NOTREADY so caller retries. */
        rc = WH_ERROR_NOTREADY;
    }
    return rc;
}

int posixTransportUds_RecvResponse(void* context,
        uint16_t* out_size, void* data)
{
    int rc;
    posixTransportUdsClientContext* c = context;

    if (c == NULL || c->connect_fd_p1 == 0) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_sent != 1) {
        /* Cannot receive before sending a request. */
        return WH_ERROR_NOTREADY;
    }

    rc = posixTransportUds_Recv(
            c->connect_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            out_size,
            data);

    if (rc != WH_ERROR_NOTREADY) {
        c->buffer_offset = 0;
        c->request_sent  = 0;
        if (rc != WH_ERROR_OK) {
            if (c->connectcb != NULL) {
                c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
            }
        }
    }
    return rc;
}

int posixTransportUds_CleanupConnect(void* context)
{
    posixTransportUdsClientContext* c = context;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (c->connectcb != NULL) {
        c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
    }
    if (c->connect_fd_p1 != 0) {
        close(c->connect_fd_p1 - 1);
        c->connect_fd_p1 = 0;
    }
    return WH_ERROR_OK;
}


/* ── Server implementation ─────────────────────────────────────────────────── */

int posixTransportUds_GetListenFd(posixTransportUdsServerContext* context,
        int* out_fd)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (context->listen_fd_p1 == 0) {
        return WH_ERROR_NOTREADY;
    }
    if (out_fd != NULL) {
        *out_fd = context->listen_fd_p1 - 1;
    }
    return WH_ERROR_OK;
}

int posixTransportUds_GetAcceptFd(posixTransportUdsServerContext* context,
        int* out_fd)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (context->listen_fd_p1 == 0 || context->accept_fd_p1 == 0) {
        return WH_ERROR_NOTREADY;
    }
    if (out_fd != NULL) {
        *out_fd = context->accept_fd_p1 - 1;
    }
    return WH_ERROR_OK;
}

/*
 * posixTransportUds_InitListen — create and bind the listening socket.
 *
 * Sequence:
 *   1. Validate path length.
 *   2. unlink(path) to remove any stale socket from a prior crash.
 *      We ignore ENOENT (no prior socket) but fail on any other unlink error
 *      because it may indicate a permissions problem that would also cause
 *      bind to fail.
 *   3. socket() + MakeNonBlocking().
 *   4. bind().
 *   5. chmod(0660) — restrict to owner and group.  A mode of 0666 would let
 *      any local user connect to the HSM server, which is too permissive.
 *   6. listen().
 *
 * Note: SO_REUSEADDR is a TCP concept (TIME_WAIT state reuse) and has no
 * useful effect on AF_UNIX sockets.  The unlink() above is the correct
 * idiom for UDS "address reuse".
 */
int posixTransportUds_InitListen(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    int rc;
    posixTransportUdsServerContext* c  = context;
    const posixTransportUdsConfig*  cf = config;
    size_t path_len;

    if (c == NULL || cf == NULL || cf->server_path == NULL) {
        return WH_ERROR_BADARGS;
    }

    path_len = strlen(cf->server_path);
    if (path_len == 0 || (int)path_len > POSIX_TRANSPORT_UDS_PATH_MAX) {
        return WH_ERROR_BADARGS;
    }

    memset(c, 0, sizeof(*c));

    /* Populate the bound address now; sun_path is used later in Cleanup. */
    c->server_addr.sun_family = AF_UNIX;
    strncpy(c->server_addr.sun_path, cf->server_path,
            sizeof(c->server_addr.sun_path) - 1);
    c->server_addr.sun_path[sizeof(c->server_addr.sun_path) - 1] = '\0';

    /* Remove stale socket.  ENOENT is fine (no previous run). Any other
     * error is unexpected and probably means we cannot bind either. */
    if (unlink(c->server_addr.sun_path) < 0 && errno != ENOENT) {
        return WH_ERROR_ABORTED;
    }

    rc = socket(AF_UNIX, SOCK_STREAM, 0);
    if (rc < 0) {
        return WH_ERROR_ABORTED;
    }
    if (rc <= 2) {
        /* Refuse to use fd 0/1/2. */
        close(rc);
        return WH_ERROR_ABORTED;
    }
    c->listen_fd_p1 = rc + 1;

    if (posixTransportUds_MakeNonBlocking(c->listen_fd_p1 - 1) != WH_ERROR_OK) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    if (bind(c->listen_fd_p1 - 1,
             (struct sockaddr*)&c->server_addr,
             sizeof(c->server_addr)) < 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    /* Restrict socket permissions.  0660: owner rw, group rw, other none.
     * The daemon should run as a dedicated user; clients should be in the
     * same group. */
    if (chmod(c->server_addr.sun_path, 0660) < 0) {
        /* chmod failure is non-fatal operationally but is a security issue.
         * Fail loudly rather than silently run with too-open permissions. */
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        (void)unlink(c->server_addr.sun_path);
        return WH_ERROR_ABORTED;
    }

    if (listen(c->listen_fd_p1 - 1, 1) < 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        (void)unlink(c->server_addr.sun_path);
        return WH_ERROR_ABORTED;
    }

    c->connectcb     = connectcb;
    c->connectcb_arg = connectcb_arg;

    /* Signal upper layers that the server is ready to handle traffic.
     * AcceptFd is not yet open; the connection is completed inside
     * RecvRequest on the first call. */
    if (c->connectcb != NULL) {
        c->connectcb(c->connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
}

int posixTransportUds_RecvRequest(void* context,
        uint16_t* out_size, void* data)
{
    int rc;
    posixTransportUdsServerContext* c = context;

    if (c == NULL || c->listen_fd_p1 == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Accept a client connection if we do not already have one. */
    if (c->accept_fd_p1 == 0) {
        rc = accept(c->listen_fd_p1 - 1, NULL, NULL);
        if (rc < 0) {
            switch (errno) {
            case EAGAIN:
            case EINPROGRESS:
            case EINTR:
                return WH_ERROR_NOTREADY;
            default:
                close(c->listen_fd_p1 - 1);
                c->listen_fd_p1 = 0;
                return WH_ERROR_ABORTED;
            }
        }
        c->accept_fd_p1 = rc + 1;
    }

    if (c->request_recv == 1) {
        /* Still processing the previous request; refuse to overwrite. */
        return WH_ERROR_NOTREADY;
    }

    rc = posixTransportUds_Recv(
            c->accept_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            out_size,
            data);

    if (rc != WH_ERROR_NOTREADY) {
        c->buffer_offset = 0;
        if (rc == WH_ERROR_OK) {
            c->request_recv = 1;
        } else {
            /* Client disconnected or fatal receive error.  Close the accepted
             * socket so RecvRequest can accept a new client on the next call.
             * The listen socket stays open. */
            close(c->accept_fd_p1 - 1);
            c->accept_fd_p1 = 0;
            if (c->connectcb != NULL) {
                c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
            }
        }
    }
    return rc;
}

int posixTransportUds_SendResponse(void* context,
        uint16_t size, const void* data)
{
    int rc;
    posixTransportUdsServerContext* c = context;

    if (    c == NULL               ||
            c->listen_fd_p1 == 0    ||
            c->accept_fd_p1 == 0    ||
            size == 0               ||
            size > PTU_PACKET_MAX_SIZE ||
            data == NULL ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_recv == 0) {
        /* No request was received; cannot send a response. */
        return WH_ERROR_NOTREADY;
    }

    rc = posixTransportUds_Send(
            c->accept_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            size, data);

    if (rc != WH_ERROR_NOTREADY) {
        c->buffer_offset = 0;
        if (rc == WH_ERROR_OK) {
            c->request_recv = 0;
        } else {
            close(c->accept_fd_p1 - 1);
            c->accept_fd_p1 = 0;
            if (c->connectcb != NULL) {
                c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
            }
        }
    }
    return rc;
}

/*
 * posixTransportUds_CleanupListen — shut down and remove the socket.
 *
 * Closes both the accept fd (if any) and the listen fd, then unlinks the
 * socket path so no stale file remains.  The unlink here mirrors the one in
 * InitListen: together they ensure the filesystem is clean whether the
 * daemon exits cleanly or crashes (the next InitListen handles the crash
 * case).
 */
int posixTransportUds_CleanupListen(void* context)
{
    posixTransportUdsServerContext* c = context;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (c->connectcb != NULL) {
        c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
    }
    if (c->accept_fd_p1 != 0) {
        close(c->accept_fd_p1 - 1);
        c->accept_fd_p1 = 0;
    }
    if (c->listen_fd_p1 != 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
    }

    /* Remove the socket file.  Ignore errors: if the path is empty (e.g.
     * Init was never called successfully) unlink is a harmless no-op. */
    if (c->server_addr.sun_path[0] != '\0') {
        (void)unlink(c->server_addr.sun_path);
    }

    return WH_ERROR_OK;
}
