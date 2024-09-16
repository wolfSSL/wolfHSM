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
 * port/posix/transport_shm.c
 *
 * Implementation of transport callbacks using tcp
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "port/posix/posix_transport_tcp.h"


/** Local declarations */

/* Common utility function to make a fd non-blocking */
static int posixTransportTcp_MakeNonBlocking(int fd);

/* Server utility function to make a socket no linger and reuse addr */
static int posixTransportTcp_MakeNoLinger(int sock);

/* Common send/write function with a byte buffer */
static int posixTransportTcp_Send(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t size, const void* data);

/* Common recv/read function with a byte buffer */
static int posixTransportTcp_Recv(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t *out_size, void* data);

/* Start a non-blocking connect */
static int posixTransportTcp_HandleConnect(posixTransportTcpClientContext* c);

/* CLose connection and reset state */
static int posixTransportTcp_Close(posixTransportTcpClientContext* c);



/** Local implementations */
static int posixTransportTcp_MakeNonBlocking(int fd)
{
    int rc = 0;
    rc = fcntl(fd, F_GETFL, 0);
    if (rc == -1) {
        /* Error getting flags */
        return WH_ERROR_ABORTED;
    }
    /* Set the nonblocking flag */
    rc = fcntl(fd, F_SETFL, rc | O_NONBLOCK);
    if (rc == -1) {
        /* Error setting flags */
        return WH_ERROR_ABORTED;
    }
    return 0;
}


static int posixTransportTcp_MakeNoLinger(int sock)
{
    struct linger ls = {
            .l_onoff = 0,
            .l_linger = 0,
    };
    int enable = 1;
    int rc = 0;

    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }
    rc = setsockopt(sock, SOL_SOCKET, SO_LINGER, &ls, sizeof(ls));
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }
    return 0;
}

static int posixTransportTcp_Send(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t size, const void* data)
{
    int rc = 0;
    int send_size = 0;
    uint32_t* packet_len = (uint32_t*)&(buffer[0]);
    void* packet_data = &(buffer[sizeof(uint32_t)]);

    if (    (fd < 0) ||
            (buffer_offset == NULL) ||
            (buffer == NULL) ||
            (size == 0) ||
            (size > PTT_PACKET_MAX_SIZE) ||
            (data == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if(*buffer_offset == 0) {
        /* Initial write.  Copy data to buffer */
        /* Prepend packet data with the size in network order */
        *packet_len = htonl((uint32_t)size);
        memcpy(packet_data, data, size);
        send_size = sizeof(uint32_t) + size;
    }
    int remaining_size = send_size - *buffer_offset;


    rc = send(fd, &(buffer[*buffer_offset]), remaining_size, MSG_NOSIGNAL);

    if (rc < 0) {
        switch (errno) {
        case EAGAIN:
        case EINTR:
            /* Not connected yet or not enough buffer space */
            return WH_ERROR_NOTREADY;

        default:
            /* Other error. Assume fatal. */
            *buffer_offset = 0;
            return WH_ERROR_ABORTED;
        }
    }

    if(rc != remaining_size) {
        /* Incomplete write */
        *buffer_offset += rc;
        return WH_ERROR_NOTREADY;
    }

    /* All good. Reset state */
    *buffer_offset = 0;
    return 0;
}

static int posixTransportTcp_Recv(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t *out_size, void* data)
{
    int rc = 0;
    uint32_t* packet_len = (uint32_t*)&(buffer[0]);
    void* packet_data = &(buffer[sizeof(uint32_t)]);
    uint32_t packet_size = 0;
    uint32_t size_remaining = 0;

    if (    (fd < 0) ||
            (buffer_offset == NULL) ||
            (*buffer_offset > PTT_BUFFER_SIZE) ||
            (buffer == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if(*buffer_offset < sizeof(uint32_t)) {
        /* Try to read the size */
        rc = read(fd,
                &(buffer[*buffer_offset]),
                sizeof(uint32_t) - *buffer_offset);
        if (rc < 0) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                /* Not connected yet or no recv data */
                return WH_ERROR_NOTREADY;

            default:
                /* Other error. Assume fatal. */
                *buffer_offset = 0;
                return WH_ERROR_ABORTED;
            }
        }
        *buffer_offset += rc;
    }
    if(*buffer_offset < sizeof(uint32_t)) {
        return WH_ERROR_NOTREADY;
    }
    /* Have the size */
    packet_size = ntohl(*packet_len);
    size_remaining = packet_size - (*buffer_offset - sizeof(uint32_t));
    if ( (packet_size == 0) || (packet_size > PTT_PACKET_MAX_SIZE)) {
        /* Bad recv'ed size.  Assume fatal */
        *buffer_offset = 0;
        return WH_ERROR_ABORTED;
    }
    /* Read the rest of the packet */
    rc = read(fd,
            &(buffer[*buffer_offset]),
            size_remaining);
    if (rc < 0) {
        switch (errno) {
        case EAGAIN:
        case EINPROGRESS:
        case EINTR:
            /* No recv data */
            return WH_ERROR_NOTREADY;

        default:
            /* Other error. Assume fatal. */
            *buffer_offset = 0;
            return WH_ERROR_ABORTED;
        }
    }
    *buffer_offset += rc;
    size_remaining -= rc;
    if (size_remaining > 0) {
        return WH_ERROR_NOTREADY;
    }

    /* Got complete packet. */
    if (data != NULL) {
        memcpy(data, packet_data, packet_size);
    }
    if (out_size != NULL) {
        *out_size = packet_size;
    }
    *buffer_offset = 0;
    return 0;
}

/** Client functions */

static int posixTransportTcp_HandleConnect(posixTransportTcpClientContext* c)
{
    int ret = WH_ERROR_OK;

    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (c->state) {
    case PTT_STATE_UNCONNECTED:
        /* Create a non-block socket and start async connect */
        ret = socket(AF_INET, SOCK_STREAM, 0);
        if (ret >= 0) {
            c->connect_fd_p1 = ret + 1;
            /* Make socket non-blocking */
            ret = posixTransportTcp_MakeNonBlocking(c->connect_fd_p1 - 1);
            if(ret == 0) {
                ret = connect(c->connect_fd_p1 - 1,
                        (struct sockaddr*)&c->server_addr,
                        sizeof(c->server_addr));
                if (ret == 0) {
                    /* Success! */
                    /* III This is unlikely since we are non-blocking */
                    c->state = PTT_STATE_CONNECTED;
                    ret = WH_ERROR_OK;
                } else {
                    /* Not connected yet.  Interpret errno */
                    switch (errno) {
                    case ECONNREFUSED:
                        /* Server not listening yet. Rebuild socket on retry. */
                        /* III This is unlikely since we are non-blocking */
                        (void)posixTransportTcp_Close(c);
                        c->state = PTT_STATE_UNCONNECTED;
                        ret = WH_ERROR_NOTFOUND;
                        break;

                    case EINPROGRESS:
                    case EINTR:
                        /* Connecting async */
                        c->state = PTT_STATE_CONNECT_WAIT;
                        ret = WH_ERROR_NOTREADY;
                        break;

                    default:
                        /* Some other error. Assume fatal. */
                        (void)posixTransportTcp_Close(c);
                        c->state = PTT_STATE_DONE;
                        ret = WH_ERROR_ABORTED;
                    }
                }
            } else {
                /* Problem making this non-blocking */
                (void)posixTransportTcp_Close(c);
                c->state = PTT_STATE_DONE;
                ret = WH_ERROR_ABORTED;
            }
        } else {
            /* Problem creating a socket */
            c->state = PTT_STATE_DONE;
            ret = WH_ERROR_ABORTED;
        }
        break;

    case PTT_STATE_CONNECT_WAIT:
    {
        /* Poll for writeable (connected) socket or error */
        /* Check if writable */
        struct pollfd pfd = {
                .fd = c->connect_fd_p1 - 1,
                .events = POLLOUT,
                .revents = 0,
        };

        /* Check for writeable with no timeout */
        int pollret = poll(&pfd, 1, 0);
        ret = WH_ERROR_OK;
        if (pollret > 0) {
            /* Either connected or error */
            /* Check for nonmaskable flags: POLLERR, POLLHUP, POLLNVAL */
            if ((pfd.revents & POLLHUP) != 0) {
                /* HUP is set when server isn't listening yet */
                (void)posixTransportTcp_Close(c);
                c->state = PTT_STATE_UNCONNECTED;
                ret = WH_ERROR_NOTFOUND;
            } else {
                /* Not HUP.  Might be error or connected */
                if (
                        ((pfd.revents & POLLNVAL) != 0) ||
                        ((pfd.revents & POLLERR) != 0) ) {
                    /* Invalid FD.  Fatal error */
                    (void)posixTransportTcp_Close(c);
                    c->state = PTT_STATE_DONE;
                    ret = WH_ERROR_ABORTED;
                } else {
                    /* Likely connected */
                    if ((pfd.revents & POLLOUT) != 0) {
                        /* Connected */
                        c->state = PTT_STATE_CONNECTED;
                        ret = WH_ERROR_OK;
                    } else {
                        /* Not connected yet, but somehow readable? */
                        ret = WH_ERROR_NOTREADY;
                    }
                }
            }
        }
        if (pollret == 0) {
            /* Poll timeout, not connected yet */
            ret = WH_ERROR_NOTREADY;
        }
        if (pollret < 0) {
            /* Error polling.  Fatal */
            (void)posixTransportTcp_Close(c);
            c->state = PTT_STATE_DONE;
            ret = WH_ERROR_ABORTED;
        }
    } break;

    case PTT_STATE_CONNECTED:
        ret = WH_ERROR_OK;
        break;

    case PTT_STATE_DONE:
        ret = WH_ERROR_ABORTED;
        break;

    default:
        c->state = PTT_STATE_DONE;
        ret = WH_ERROR_ABORTED;
    }
    return ret;
}

static int posixTransportTcp_Close(posixTransportTcpClientContext* c)
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


int posixTransportTcp_InitConnect(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    int rc;
    posixTransportTcpClientContext* c = context;
    const posixTransportTcpConfig* cf = config;

    if ( (c == NULL) || (cf == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(c, 0, sizeof(*c));

    rc = inet_pton(AF_INET, cf->server_ip_string, &c->server_addr.sin_addr);
    if (rc != 1) {
        /* rc == -1 means errno set. rc == 0 means string is not understood. */
        return WH_ERROR_BADARGS;
    }
    c->server_addr.sin_port = htons(cf->server_port);
    c->server_addr.sin_family = AF_INET;

    /* Start the connect process */
    rc = posixTransportTcp_HandleConnect(c);
    if (    (rc == WH_ERROR_OK) ||          /* Connected.  Unlikely */
            (rc == WH_ERROR_NOTFOUND) ||    /* Server not listening */
            (rc == WH_ERROR_NOTREADY) ) {   /* Async connect. Likely */
        c->connectcb = connectcb;
        c->connectcb_arg = connectcb_arg;

        /* Since we have started connecting already, invoke the connectcb so that
         * we can continue to monitor connect status during recv.
         */
        if (c->connectcb != NULL) {
            c->connectcb(connectcb_arg, WH_COMM_CONNECTED);
        }
        /* Override to indicate the connection was good enough */
        rc = WH_ERROR_OK;
    }
    return rc;
}

/* Return the file descriptor of the connected socket to support poll/select */
int posixTransportTcp_GetConnectFd(posixTransportTcpClientContext *context,
        int *out_fd)
{
    int ret = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch(context->state) {
    case PTT_STATE_UNCONNECTED:
        ret = WH_ERROR_NOTREADY;
        break;

    case PTT_STATE_CONNECT_WAIT:
    case PTT_STATE_CONNECTED:
        ret = WH_ERROR_OK;
        if (*out_fd) {
            *out_fd = context->connect_fd_p1 - 1;
        }
        break;

    case PTT_STATE_DONE:
    default:
        ret = WH_ERROR_ABORTED;
        break;
    }

    return ret;
}


int posixTransportTcp_SendRequest(void* context,
        uint16_t size, const void* data)
{
    int rc;
    posixTransportTcpClientContext* c = context;
    if (    (c == NULL) ||
            (size == 0) ||
            (size > PTT_PACKET_MAX_SIZE) ||
            (data == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_sent == 1) {
        return WH_ERROR_NOTREADY;
    }

    /* Handle late/slow connect */
    rc = posixTransportTcp_HandleConnect(c);
    if (rc == WH_ERROR_OK) {

        rc = posixTransportTcp_Send(
                c->connect_fd_p1 - 1,
                &c->buffer_offset,
                c->buffer,
                size, data);

        if (rc != WH_ERROR_NOTREADY) {
            /* Reset state */
            c->buffer_offset = 0;
            if (rc == 0) {
                c->request_sent = 1;
            } else {
                /* Assume fatal error and trigger disconnect */
                if (c->connectcb != NULL) {
                    c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
                }
            }
        }
    } else {
        if (rc == WH_ERROR_NOTFOUND) {
            /* Squash to not ready */
            rc = WH_ERROR_NOTREADY;
        }
    }
    return rc;
}

int posixTransportTcp_RecvResponse(void* context,
        uint16_t* out_size, void* data)
{
    int rc;
    posixTransportTcpClientContext* c = context;
    if (    (c == NULL) ||
            (c->connect_fd_p1 == 0) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_sent != 1) {
        return WH_ERROR_NOTREADY;
    }

    rc = posixTransportTcp_Recv(
            c->connect_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            out_size,
            data);

    if (rc != WH_ERROR_NOTREADY) {
        /* Success or fatal.  Reset state either way */
        c->buffer_offset = 0;
        c->request_sent = 0;
        if (rc != 0) {
            /* Assume fatal error and trigger disconnect */
            if (c->connectcb != NULL) {
                c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
            }
        }
    }
    return rc;
}

int posixTransportTcp_CleanupConnect(void* context)
{
     posixTransportTcpClientContext* c = context;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Trigger disconnect */
    if (c->connectcb != NULL) {
        c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
    }

    if (c->connect_fd_p1 != 0) {
        close(c->connect_fd_p1 -1);
        c->connect_fd_p1 = 0;
    }

    return 0;
}


/** Server Functions */

int posixTransportTcp_GetListenFd(posixTransportTcpServerContext *context,
        int *out_fd)
{
    int ret = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->listen_fd_p1 != 0) {
        if (out_fd != NULL) {
            *out_fd = context->listen_fd_p1 - 1;
        }
    } else {
        ret = WH_ERROR_NOTREADY;
    }
    return ret;
}

int posixTransportTcp_GetAcceptFd(posixTransportTcpServerContext *context,
        int *out_fd)
{
    int ret = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (    (context->listen_fd_p1 != 0) &&
            (context->accept_fd_p1 != 0) ) {
        if (out_fd != NULL) {
            *out_fd = context->accept_fd_p1 - 1;
        }
    } else {
        ret = WH_ERROR_NOTREADY;
    }
    return ret;
}


int posixTransportTcp_InitListen(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    int rc;
    posixTransportTcpServerContext* c = context;
    const posixTransportTcpConfig* cf = config;

    if ( (c == NULL) || (cf == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(c, 0, sizeof(*c));

    rc = inet_pton(AF_INET, cf->server_ip_string, &c->server_addr.sin_addr);
    if (rc != 1) {
        /* rc == -1 means errno set. rc == 0 means string is not understood. */
        return WH_ERROR_BADARGS;
    }
    c->server_addr.sin_port = htons(cf->server_port);
    c->server_addr.sin_family = AF_INET;

    rc = socket(AF_INET, SOCK_STREAM, 0);
    if (rc < 0) {
        return WH_ERROR_ABORTED;
    }
    c->listen_fd_p1 = rc + 1;

    /* Make socket non-blocking */
    rc = posixTransportTcp_MakeNonBlocking(c->listen_fd_p1 - 1);
    if (rc != 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    /* Ensure listen port does not linger */
    (void)posixTransportTcp_MakeNoLinger(c->listen_fd_p1 - 1);
    /* Ok to fail to linger.  Annoying, but ok. */

    rc = bind(c->listen_fd_p1 - 1,
            (struct sockaddr*)&c->server_addr,
            sizeof(c->server_addr));
    if (rc < 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    rc = listen(c->listen_fd_p1 - 1, 1);
    if (rc < 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    c->connectcb = connectcb;
    c->connectcb_arg = connectcb_arg;

    /* Connecting is handled internally so we need server to call recv */
    if (c->connectcb != NULL) {
        c->connectcb(c->connectcb_arg, WH_COMM_CONNECTED);
    }
    /* All good */
    return 0;
}

int posixTransportTcp_RecvRequest(void* context,
        uint16_t* out_size, void* data)
{
    int rc = 0;
    posixTransportTcpServerContext* c = context;
    if (    (c == NULL) ||
            (c->listen_fd_p1 == 0) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->accept_fd_p1 == 0) {
        socklen_t client_len = sizeof(c->client_addr);
        rc = accept(c->listen_fd_p1 - 1,
                (struct sockaddr*)&c->client_addr,
                &client_len);
        if (rc < 0) {
            switch (errno) {
            case EAGAIN:
            case EINPROGRESS:
            case EINTR:
                /* Not connected yet or no client */
                return WH_ERROR_NOTREADY;

            default:
                /* Other error. Assume fatal. */
                close(c->listen_fd_p1 - 1);
                c->listen_fd_p1 = 0;
                return WH_ERROR_ABORTED;
            }
        }
        c->accept_fd_p1 = rc + 1;
    }

    if (c->request_recv == 1) {
        /* Already working on a request. */
        return WH_ERROR_NOTREADY;
    }

    rc = posixTransportTcp_Recv(
            c->accept_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            out_size,
            data);

    if (rc != WH_ERROR_NOTREADY) {
        /* Success or fatal.  Reset state either way */
        c->buffer_offset = 0;
        if (rc == 0) {
            c->request_recv = 1;
        } else {
            /* Assume fatal error and trigger disconnect */
            if (c->connectcb != NULL) {
                c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
            }
        }
    }
    return rc;
}

int posixTransportTcp_SendResponse(void* context,
        uint16_t size, const void* data)
{
    int rc = 0;
    posixTransportTcpServerContext* c = context;
    if (    (c == NULL) ||
            (c->listen_fd_p1 == 0) ||
            (c->accept_fd_p1 == 0) ||
            (size == 0) ||
            (size > PTT_PACKET_MAX_SIZE) ||
            (data == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_recv == 0) {
        return WH_ERROR_NOTREADY;
    }

    rc = posixTransportTcp_Send(
            c->accept_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            size, data);

    if (rc != WH_ERROR_NOTREADY) {
        /* Reset state */
        c->buffer_offset = 0;
        if (rc == 0) {
            c->request_recv = 0;
        } else {
            /* Assume fatal error and trigger disconnect */
            if (c->connectcb != NULL) {
                c->connectcb(c->connectcb_arg, WH_COMM_DISCONNECTED);
            }
        }
    }
    return rc;
}

int posixTransportTcp_CleanupListen(void* context)
{
    posixTransportTcpServerContext* c = context;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Trigger disconnect */
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

    return 0;
}
