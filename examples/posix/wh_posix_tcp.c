#include <stdint.h>
#include <string.h> /* For memset, memcpy, strcmp */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_utils.h"

#include "wh_example_posix.h"
#include "port/posix/posix_transport_tcp.h"


#define WH_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_SERVER_TCP_PORT 23456
#define WH_CLIENT_ID 12
#define WH_SERVER_ID 57


/* client configuration structures */
whTransportClientCb            pttcClientTcpCb = PTT_CLIENT_CB;
posixTransportTcpClientContext tcc;
posixTransportTcpConfig        mytcpconfig;
whCommClientConfig             cc_conf;

/* client configuration setup example for transport */
int wh_Client_ExampleTCPConfig(whClientConfig* c_conf)
{
    memset(&tcc, 0, sizeof(posixTransportTcpClientContext));

    mytcpconfig.server_ip_string = WH_SERVER_TCP_IPSTRING;
    mytcpconfig.server_port      = WH_SERVER_TCP_PORT;

    cc_conf.transport_cb      = &pttcClientTcpCb;
    cc_conf.transport_context = (void*)&tcc;
    cc_conf.transport_config  = (void*)&mytcpconfig;
    cc_conf.client_id         = WH_CLIENT_ID;
    c_conf->comm              = &cc_conf;

    return WH_ERROR_OK;
}

/* server configuration structures */
whTransportServerCb            pttServerTcpCb = PTT_SERVER_CB;
posixTransportTcpServerContext tsc;
posixTransportTcpConfig        mytcpconfig;
whCommServerConfig             cs_conf;

/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int wh_Server_ExampleTCPConfig(whServerConfig* s_conf)
{
    /* Server configuration/context */
    memset(&tsc, 0, sizeof(posixTransportTcpServerContext));

    mytcpconfig.server_ip_string = WH_SERVER_TCP_IPSTRING;
    mytcpconfig.server_port      = WH_SERVER_TCP_PORT;

    cs_conf.transport_cb      = &pttServerTcpCb;
    cs_conf.transport_context = (void*)&tsc;
    cs_conf.transport_config  = (void*)&mytcpconfig;
    cs_conf.server_id         = WH_SERVER_ID;

    s_conf->comm_config = &cs_conf;

    return WH_ERROR_OK;
}
