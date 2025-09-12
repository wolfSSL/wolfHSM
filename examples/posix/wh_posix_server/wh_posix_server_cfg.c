#include "wh_posix_cfg.h"
#include "wh_posix_server_cfg.h"

#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"

#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"
#include "port/posix/posix_transport_dma.h"

posixTransportShmConfig shmConfig;
posixTransportTcpConfig tcpConfig;

whCommServerConfig s_comm;

whTransportServerCb tcpCb = PTT_SERVER_CB;
whTransportServerCb shmCb = POSIX_TRANSPORT_SHM_SERVER_CB;
posixTransportShmServerContext tscShm;
posixTransportTcpServerContext tscTcp;

#ifdef WOLFSSL_STATIC_MEMORY
whTransportServerCb dmaCb = POSIX_TRANSPORT_DMA_SERVER_CB;
posixTransportShmServerContext tscDma;


/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int Server_ExampleDMAConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    memset(&tscDma, 0, sizeof(posixTransportShmServerContext));
    memset(&s_comm, 0, sizeof(whCommServerConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    s_comm.transport_cb      = &dmaCb;
    s_comm.transport_context = (void*)&tscDma;
    s_comm.transport_config  = (void*)&shmConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}
#endif


/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int Server_ExampleSHMConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    memset(&tscShm, 0, sizeof(posixTransportShmServerContext));
    memset(&s_comm, 0, sizeof(whCommServerConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    s_comm.transport_cb      = &shmCb;
    s_comm.transport_context = (void*)&tscShm;
    s_comm.transport_config  = (void*)&shmConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}


/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int Server_ExampleTCPConfig(void* conf)
{
    whServerConfig* s_conf = (whServerConfig*)conf;

    /* Server configuration/context */
    memset(&tscTcp, 0, sizeof(posixTransportTcpServerContext));

    tcpConfig.server_ip_string = WH_POSIX_SERVER_TCP_IPSTRING;
    tcpConfig.server_port      = WH_POSIX_SERVER_TCP_PORT;

    s_comm.transport_cb      = &tcpCb;
    s_comm.transport_context = (void*)&tscTcp;
    s_comm.transport_config  = (void*)&tcpConfig;
    s_comm.server_id         = WH_POSIX_SERVER_ID;

    s_conf->comm_config = &s_comm;

    return WH_ERROR_OK;
}
