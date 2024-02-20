/*
 * transport_shm.c
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

#include "wolfhsm/error.h"
#include "wolfhsm/transport.h"
#include "port/posix/transport_tcp.h"

/* Define and declare callbacks that match wolfhsm/transport.h */

/* Common buffer management functions */

/** Local declarations */

/* Common utility function to make a fd non-blocking */
static int _wh_TransportTcp_MakeNonBlocking(int fd);

/* Common send/write function with a byte buffer */
static int _wh_TransportTcp_Send(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t size, const void* data);

/* Common recv/read function with a byte buffer */
static int _wh_TransportTcp_Recv(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t *out_size, void* data);

/** Local implementations */
static int _wh_TransportTcp_MakeNonBlocking(int fd)
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

static int _wh_TransportTcp_Send(int fd, uint16_t* buffer_offset,
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
            (size > WH_TRANSPORT_TCP_PACKET_MAX_SIZE) ||
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
    rc = write(fd, &(buffer[*buffer_offset]), remaining_size);

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

static int _wh_TransportTcp_Recv(int fd, uint16_t* buffer_offset,
        uint8_t* buffer, uint16_t *out_size, void* data)
{
    int rc = 0;
    uint32_t* packet_len = (uint32_t*)&(buffer[0]);
    void* packet_data = &(buffer[sizeof(uint32_t)]);
    uint32_t packet_size = 0;
    uint32_t size_remaining = 0;

    if (    (fd < 0) ||
            (buffer_offset == NULL) ||
            (*buffer_offset > WH_TRANSPORT_TCP_BUFFER_SIZE) ||
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
    if ( (packet_size == 0) || (packet_size > WOLFHSM_COMM_MTU)) {
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

static int _wh_TransportTcp_InitConnect(void* context, const void* config);
static int _wh_TransportTcp_SendRequest(void* context, uint16_t size,
        const void* data);
static int _wh_TransportTcp_RecvResponse(void* context, uint16_t *out_size,
        void* data);
static int _wh_TransportTcp_CleanupConnect(void* context);


static int _wh_TransportTcp_InitConnect(void* context, const void* config)
{
    int rc = 0;
    whTransportTcpClientContext* c = context;
    const whTransportTcpConfig* cf = config;

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
    rc = socket(AF_INET, SOCK_STREAM, 0);
    if (rc < 0) {
        return WH_ERROR_ABORTED;
    }
    c->connect_fd_p1 = rc + 1;

    /* Make socket non-blocking */
    rc = _wh_TransportTcp_MakeNonBlocking(c->connect_fd_p1 - 1);

    if(rc != 0) {
        close(c->connect_fd_p1 - 1);
        c->connect_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    /* Start the connect process */
    rc = connect(c->connect_fd_p1 - 1,
            (struct sockaddr*)&c->server_addr,
            sizeof(c->server_addr));
    if (rc < 0) {
        switch (errno) {
        case EAGAIN:
        case EINPROGRESS:
        case EINTR:
            /* Ok.  Not ready yet. */
            break;

        default:
            /* Some other error. Assume fatal. */
            close(c->connect_fd_p1 - 1);
            c->connect_fd_p1 = 0;
            return WH_ERROR_ABORTED;
        }
    }

    /* All good */
    return 0;
}

static int _wh_TransportTcp_SendRequest(void* context,
        uint16_t size, const void* data)
{
    int rc = 0;
    whTransportTcpClientContext* c = context;
    if (    (c == NULL) ||
            (c->connect_fd_p1 == 0) ||
            (size == 0) ||
            (size > WH_TRANSPORT_TCP_PACKET_MAX_SIZE) ||
            (data == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_sent == 1) {
        return WH_ERROR_NOTREADY;
    }

    /* Handle late/slow connect */
    if (c->connected == 0) {
        /* Ensure writeable */
        struct pollfd pfd = {
                .fd = c->connect_fd_p1 - 1,
                .events = POLLOUT,
                .revents = 0,
        };
        /* Check for writeable with no timeout */
        rc = poll(&pfd, 1, 0);
        if (rc < 0) {
            /* Error.  */
            return WH_ERROR_ABORTED;
        }
        if (rc == 0) {
            /* Poll timeout, not connected yet */
            return WH_ERROR_NOTREADY;
        }
        if ((pfd.revents & POLLOUT) == 0) {
            /* Not connected yet */
            return WH_ERROR_NOTREADY;
        }
        c->connected = 1;
    }

    rc = _wh_TransportTcp_Send(
            c->connect_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            size, data);

    if (rc != WH_ERROR_NOTREADY) {
        /* Reset state */
        c->buffer_offset = 0;
        if (rc == 0) {
            c->request_sent = 1;
        }
    }
    return rc;
}

static int _wh_TransportTcp_RecvResponse(void* context,
        uint16_t* out_size, void* data)
{
    int rc = 0;
    whTransportTcpClientContext* c = context;
    if (    (c == NULL) ||
            (c->connect_fd_p1 == 0) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_sent != 1) {
        return WH_ERROR_NOTREADY;
    }

    rc = _wh_TransportTcp_Recv(
            c->connect_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            out_size,
            data);

    if (rc != WH_ERROR_NOTREADY) {
        /* Success or fatal.  Reset state either way */
        c->buffer_offset = 0;
        c->request_sent = 0;
    }
    return rc;
}

static int _wh_TransportTcp_CleanupConnect(void* context)
{
     whTransportTcpClientContext* c = context;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (c->connect_fd_p1 != 0) {
        close(c->connect_fd_p1 -1);
        c->connect_fd_p1 = 0;
    }

    return 0;
}

/** TransportClient Implementation */
static const wh_TransportClient_Cb _whTransportTcpClient_Cb = {
        .Init =     _wh_TransportTcp_InitConnect,
        .Send =     _wh_TransportTcp_SendRequest,
        .Recv =     _wh_TransportTcp_RecvResponse,
        .Cleanup =  _wh_TransportTcp_CleanupConnect,
};
const wh_TransportClient_Cb* whTransportTcpClient_Cb =
        &_whTransportTcpClient_Cb;

/** Server Functions */

static int _wh_TransportTcp_MakeNoLinger(int sock);

static int _wh_TransportTcp_InitListen(void* context, const void* config);
static int _wh_TransportTcp_RecvRequest(void* context, uint16_t *out_size,
        void* data);
static int _wh_TransportTcp_SendResponse(void* context, uint16_t size,
        const void* data);
static int _wh_TransportTcp_CleanupListen(void* context);


static int _wh_TransportTcp_MakeNoLinger(int sock)
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

static int _wh_TransportTcp_InitListen(void* context, const void* config)
{
    int rc = 0;
    whTransportTcpServerContext* c = context;
    const whTransportTcpConfig* cf = config;

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
    rc = socket(AF_INET, SOCK_STREAM, 0);
    if (rc < 0) {
        return WH_ERROR_ABORTED;
    }
    c->listen_fd_p1 = rc + 1;

    /* Make socket non-blocking */
    rc = _wh_TransportTcp_MakeNonBlocking(c->listen_fd_p1 - 1);
    if (rc != 0) {
        close(c->listen_fd_p1 - 1);
        c->listen_fd_p1 = 0;
        return WH_ERROR_ABORTED;
    }

    /* Ensure listen port does not linger */
    rc = _wh_TransportTcp_MakeNoLinger(c->listen_fd_p1 -1);
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

    /* All good */
    return 0;
}

static int _wh_TransportTcp_RecvRequest(void* context,
        uint16_t* out_size, void* data)
{
    int rc = 0;
    whTransportTcpServerContext* c = context;
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

    rc = _wh_TransportTcp_Recv(
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
        }
    }
    return rc;
}

static int _wh_TransportTcp_SendResponse(void* context,
        uint16_t size, const void* data)
{
    int rc = 0;
    whTransportTcpServerContext* c = context;
    if (    (c == NULL) ||
            (c->listen_fd_p1 == 0) ||
            (c->accept_fd_p1 == 0) ||
            (size == 0) ||
            (size > WH_TRANSPORT_TCP_PACKET_MAX_SIZE) ||
            (data == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    if (c->request_recv == 0) {
        return WH_ERROR_NOTREADY;
    }

    rc = _wh_TransportTcp_Send(
            c->accept_fd_p1 - 1,
            &c->buffer_offset,
            c->buffer,
            size, data);

    if (rc != WH_ERROR_NOTREADY) {
        /* Reset state */
        c->buffer_offset = 0;
        if (rc == 0) {
            c->request_recv = 0;
        }
    }
    return rc;
}

static int _wh_TransportTcp_CleanupListen(void* context)
{
    whTransportTcpServerContext* c = context;
    if (c == NULL) {
        return WH_ERROR_BADARGS;
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

/** TransportServer Implementation */
static const wh_TransportServer_Cb _whTransportTcpServer_Cb = {
        .Init =     _wh_TransportTcp_InitListen,
        .Recv =     _wh_TransportTcp_RecvRequest,
        .Send =     _wh_TransportTcp_SendResponse,
        .Cleanup =  _wh_TransportTcp_CleanupListen,
};
const wh_TransportServer_Cb* whTransportTcpServer_Cb =
        &_whTransportTcpServer_Cb;

