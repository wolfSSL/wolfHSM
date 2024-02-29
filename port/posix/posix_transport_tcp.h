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

#include "wolfhsm/wh_comm.h"        /* For WH_COMM_MTU */
#include "wolfhsm/wh_transport.h"


#define PTT_PACKET_MAX_SIZE WH_COMM_MTU
#define PTT_BUFFER_SIZE (sizeof(uint32_t) + PTT_PACKET_MAX_SIZE)

/** Common configuration structure */
typedef struct {
    char* server_ip_string;
    short int server_port;
} posixTransportTcpConfig;


/** Client context and functions */

typedef struct {
    struct sockaddr_in server_addr;
    int connect_fd_p1;      /* fd plus 1 so 0 is invalid */
    int connected;
    int request_sent;
    uint16_t buffer_offset;
    uint8_t buffer[PTT_BUFFER_SIZE];
} posixTransportTcpClientContext;

int posixTransportTcp_InitConnect(void* context, const void* config);
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
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int listen_fd_p1;       /* fd plus 1 so 0 is invalid */
    int accept_fd_p1;       /* fd plus 1 so 0 is invalid */
    int request_recv;
    uint16_t buffer_offset;
    uint8_t buffer[PTT_BUFFER_SIZE];
} posixTransportTcpServerContext;

int posixTransportTcp_InitListen(void* context, const void* config);
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
