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
 * port/posix/posix_transport_tcp.h
 *
 * wolfHSM Transport binding using TCP sockets
 */

#ifndef PORT_POSIX_POSIX_TRANSPORT_TCP_H_
#define PORT_POSIX_POSIX_TRANSPORT_TCP_H_

/* Example usage:
 *
 * posixTransportTcpConfig pttcfg[1] = {{
 *      .server_ip_string = "127.0.0.1",
 *      .server_port = 2345,
 * }};
 *
 * wh_TransportClient_Cb pttccb[1] = {PTT_CLIENT_CB};
 * posixTransportTcpClientContext pttcc[1] = {0};
 * whCommClientConfig ccc[1] = {{
 *      .transport_cb = pttccb,
 *      .transport_context = pttcc,
 *      .transport_config = pttcfg,
 *      .client_id = 1234,
 * }}
 * whCommClient cc[1] ={0};
 * wh_CommClient_Init(cc, ccc);
 *
 * wh_TransportServer_Cb pttscb[1] = {PTT_SERVER_CB};
 * posixTransportTcpServerContext pttsc[1] = {0};
 * whCommServerConfig csc[1] = {{
 *      .transport_cb = pttscb,
 *      .transport_context = pttsc,
 *      .transport_config = pttcfg,
 *      .server_id = 5678,
 * }}
 * whCommServer cs[1] = {0};
 * wh_CommServer_Init(cs, csc);
 *
 */

#include <stdint.h>
#include <netinet/in.h>

#include "wolfhsm/wh_comm.h"

#define PTT_PACKET_MAX_SIZE WH_COMM_MTU
#define PTT_BUFFER_SIZE (sizeof(uint32_t) + PTT_PACKET_MAX_SIZE)

/** Common configuration structure */
typedef struct {
    char* server_ip_string;
    short int server_port;
    uint8_t WH_PAD[6];
} posixTransportTcpConfig;


/** Client context and functions */

typedef struct {
    whCommSetConnectedCb connectcb;
    void* connectcb_arg;
    struct sockaddr_in server_addr;
    int connect_fd_p1;      /* fd plus 1 so 0 is invalid */
    int connected;
    int request_sent;
    uint16_t buffer_offset;
    uint8_t buffer[PTT_BUFFER_SIZE];
    uint8_t WH_PAD[6];
} posixTransportTcpClientContext;

int posixTransportTcp_InitConnect(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg);
int posixTransportTcp_SendRequest(void* context, uint16_t size,
        const void* data);
int posixTransportTcp_RecvResponse(void* context, uint16_t *out_size,
        void* data);
int posixTransportTcp_CleanupConnect(void* context);

#define PTT_CLIENT_CB                               \
{                                                   \
    .Init =     posixTransportTcp_InitConnect,      \
    .Send =     posixTransportTcp_SendRequest,      \
    .Recv =     posixTransportTcp_RecvResponse,     \
    .Cleanup =  posixTransportTcp_CleanupConnect,   \
}


/** Server context and functions */

typedef struct {
    whCommSetConnectedCb connectcb;
    void* connectcb_arg;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int listen_fd_p1;       /* fd plus 1 so 0 is invalid */
    int accept_fd_p1;       /* fd plus 1 so 0 is invalid */
    int request_recv;
    uint16_t buffer_offset;
    uint8_t buffer[PTT_BUFFER_SIZE];
    uint8_t WH_PAD[6];
} posixTransportTcpServerContext;

int posixTransportTcp_InitListen(void* context, const void* config,
        whCommSetConnectedCb connectcb, void* connectcb_arg);
int posixTransportTcp_RecvRequest(void* context, uint16_t *out_size,
        void* data);
int posixTransportTcp_SendResponse(void* context, uint16_t size,
        const void* data);
int posixTransportTcp_CleanupListen(void* context);

#define PTT_SERVER_CB                               \
{                                                   \
    .Init =     posixTransportTcp_InitListen,       \
    .Recv =     posixTransportTcp_RecvRequest,      \
    .Send =     posixTransportTcp_SendResponse,     \
    .Cleanup =  posixTransportTcp_CleanupListen,    \
}

#endif /* WH_TRANSPORT_TCP_H_ */
