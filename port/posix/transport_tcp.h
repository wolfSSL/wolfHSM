/*
 * wolfhsm/transport_tcp.h
 *
 * wolfHSM Transport binding using TCP sockets
 */

#ifndef WH_TRANSPORT_TCP_H_
#define WH_TRANSPORT_TCP_H_

/* Example usage:
 *
 * whTransportTcpConfig tcp_config[1] = {{
 *      .server_ip_string = "127.0.0.1",
 *      .server_port = 2345,
 * }};
 *
 * whTransportTcpClientContext tcc[1];
 * whCommClientConfig ccc[1] = {{
 *      .transport_cb = wh_TransportTcp_Cb,
 *      .transport_context = tcc,
 *      .transport_config = tcp_config,
 *      .client_id = 1234,
 * }}
 * whCommClient cc[1];
 * wh_CommClient_Init(cc, ccc);
 *
 * whTransportTcpServerContext tsc[1];
 * whCommServerConfig csc[1] = {{
 *      .transport_cb = wh_TransportTcp_Cb,
 *      .transport_context = tsc,
 *      .transport_config = tcp_config,
 *      .server_id = 5678,
 * }}
 * whCommServer cs[1];
 * wh_CommServer_Init(cs, csc);
 *
 */

#include <stdint.h>

#include <netinet/in.h>

#include "wolfhsm/comm.h"
#include "wolfhsm/transport.h"

#define WH_TRANSPORT_TCP_PACKET_MAX_SIZE WOLFHSM_COMM_MTU
#define WH_TRANSPORT_TCP_BUFFER_SIZE (sizeof(uint32_t) + \
                                        WH_TRANSPORT_TCP_PACKET_MAX_SIZE)

/* Common configuration structure */
typedef struct {
    char* server_ip_string;
    short int server_port;
} whTransportTcpConfig;

typedef struct {
    struct sockaddr_in server_addr;
    int connect_fd_p1;      /* fd plus 1 so 0 is invalid */
    int connected;
    int request_sent;
    uint16_t buffer_offset;
    uint8_t buffer[WH_TRANSPORT_TCP_BUFFER_SIZE];
} whTransportTcpClientContext;

/* wh_TranportClient compliant callbacks */
extern const wh_TransportClient_Cb* whTransportTcpClient_Cb;

typedef struct {
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int listen_fd_p1;       /* fd plus 1 so 0 is invalid */
    int accept_fd_p1;       /* fd plus 1 so 0 is invalid */
    int request_recv;
    uint16_t buffer_offset;
    uint8_t buffer[WH_TRANSPORT_TCP_BUFFER_SIZE];
} whTransportTcpServerContext;

/* wh_TranportServer compliant callbacks */
extern const wh_TransportServer_Cb* whTransportTcpServer_Cb;

#endif /* WH_TRANSPORT_TCP_H_ */
