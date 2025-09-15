/*
 * wolfHSM Client POSIX Example
 */

#include "wh_posix_cfg.h"
#include "wh_posix_client_cfg.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"

#include "port/posix/posix_transport_dma.h"
#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"


posixTransportShmClientContext tccShm;
posixTransportTcpClientContext tccTcp;

posixTransportShmConfig shmConfig;
posixTransportTcpConfig tcpConfig;

whCommClientConfig c_comm;

whTransportClientCb shmCb = POSIX_TRANSPORT_SHM_CLIENT_CB;
whTransportClientCb tcpCb = PTT_CLIENT_CB;

#ifdef WOLFSSL_STATIC_MEMORY
whTransportClientCb dmaCb = POSIX_TRANSPORT_SHM_CLIENT_CB;
whClientDmaConfig   dmaConfig;

const word32 sizeList[] = {
    WH_POSIX_STATIC_MEM_SIZE_1, WH_POSIX_STATIC_MEM_SIZE_2,
    WH_POSIX_STATIC_MEM_SIZE_3, WH_POSIX_STATIC_MEM_SIZE_4,
    WH_POSIX_STATIC_MEM_SIZE_5, WH_POSIX_STATIC_MEM_SIZE_6,
    WH_POSIX_STATIC_MEM_SIZE_7, WH_POSIX_STATIC_MEM_SIZE_8,
    WH_POSIX_STATIC_MEM_SIZE_9};
const word32 distList[] = {
    WH_POSIX_STATIC_MEM_DIST_1, WH_POSIX_STATIC_MEM_DIST_2,
    WH_POSIX_STATIC_MEM_DIST_3, WH_POSIX_STATIC_MEM_DIST_4,
    WH_POSIX_STATIC_MEM_DIST_5, WH_POSIX_STATIC_MEM_DIST_6,
    WH_POSIX_STATIC_MEM_DIST_7, WH_POSIX_STATIC_MEM_DIST_8,
    WH_POSIX_STATIC_MEM_DIST_9};


int Client_ExampleSetupDmaMemory(void* ctx, void* conf)
{
    void*                     dma;
    size_t                    dmaSz;
    WOLFSSL_HEAP_HINT*        hint = NULL;
    int                       ret;
    whClientContext*          client = (whClientContext*)ctx;
    whClientConfig*           c_conf = (whClientConfig*)conf;
    posixTransportShmContext* shmCtx;

    shmCtx = (posixTransportShmContext*)c_conf->comm->transport_context;
    ret    = posixTransportShm_GetDma(shmCtx, &dma, &dmaSz);
    if (ret != 0) {
        printf("Failed to get DMA\n");
        return -1;
    }

    ret = wc_LoadStaticMemory_ex(&hint, WH_POSIX_STATIC_MEM_LIST_SIZE, sizeList,
                                 distList, dma, dmaSz, 0, 0);
    if (ret != 0) {
        printf("Failed to load static memory\n");
        return -1;
    }
    void* test = XMALLOC(1, hint, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(test, hint, DYNAMIC_TYPE_TMP_BUFFER);

    ret = wh_Client_SetHeap(client, (void*)hint);
    if (ret != 0) {
        printf("Failed to set heap\n");
        return -1;
    }

    return 0;
}


/* client configuration setup example for transport */
int Client_ExampleDMAConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccShm, 0, sizeof(posixTransportShmClientContext));
    memset(&c_comm, 0, sizeof(whCommClientConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    dmaConfig.cb               = wh_Client_PosixStaticMemoryDMA;
    dmaConfig.dmaAddrAllowList = NULL;

    c_comm.transport_cb      = &dmaCb;
    c_comm.transport_context = (void*)&tccShm;
    c_comm.transport_config  = (void*)&shmConfig;
    c_comm.client_id         = WH_POSIX_CLIENT_ID;

    c_conf->dmaConfig = &dmaConfig;
    c_conf->comm      = &c_comm;

    return WH_ERROR_OK;
}
#endif

/* client configuration setup example for transport */
int Client_ExampleTCPConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccTcp, 0, sizeof(posixTransportTcpClientContext));

    tcpConfig.server_ip_string = WH_POSIX_SERVER_TCP_IPSTRING;
    tcpConfig.server_port      = WH_POSIX_SERVER_TCP_PORT;

    c_comm.transport_cb      = &tcpCb;
    c_comm.transport_context = (void*)&tccTcp;
    c_comm.transport_config  = (void*)&tcpConfig;
    c_comm.client_id         = WH_POSIX_CLIENT_ID;
    c_conf->comm             = &c_comm;

    return WH_ERROR_OK;
}


/* client configuration setup example for transport */
int Client_ExampleSHMConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccShm, 0, sizeof(posixTransportShmClientContext));
    memset(&c_comm, 0, sizeof(whCommClientConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    c_comm.transport_cb      = &shmCb;
    c_comm.transport_context = (void*)&tccShm;
    c_comm.transport_config  = (void*)&shmConfig;
    c_comm.client_id         = WH_POSIX_CLIENT_ID;
    c_conf->comm             = &c_comm;

    return WH_ERROR_OK;
}
