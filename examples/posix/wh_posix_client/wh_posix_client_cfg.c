/*
 * wolfHSM Client POSIX Example
 */

#include "wh_posix_cfg.h"
#include "wh_posix_client_cfg.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_error.h"

#include "port/posix/posix_transport_shm.h"
#include "port/posix/posix_transport_tcp.h"
#ifdef WOLFHSM_CFG_TLS
#include "port/posix/posix_transport_tls.h"
#endif

#include <string.h>

posixTransportShmClientContext tccShm;
posixTransportTcpClientContext tccTcp;
#ifdef WOLFHSM_CFG_TLS
posixTransportTlsClientContext tccTls;
#endif

posixTransportShmConfig shmConfig;
posixTransportTcpConfig tcpConfig;
#ifdef WOLFHSM_CFG_TLS
posixTransportTlsConfig tlsConfig;
#endif

whCommClientConfig c_comm;

whTransportClientCb shmCb = POSIX_TRANSPORT_SHM_CLIENT_CB;
whTransportClientCb tcpCb = PTT_CLIENT_CB;
#ifdef WOLFHSM_CFG_TLS
whTransportClientCb tlsCb = PTTLS_CLIENT_CB;
#endif

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


int wh_PosixClient_ExampleSetupDmaMemory(void* ctx, void* conf)
{
    void*                     dma;
    size_t                    dmaSz;
    WOLFSSL_HEAP_HINT*        hint = NULL;
    int                       ret;
    whClientConfig*           c_conf = (whClientConfig*)conf;
    posixTransportShmContext* shmCtx;

    shmCtx = (posixTransportShmContext*)c_conf->comm->transport_context;
    ret    = posixTransportShm_GetDma(shmCtx, &dma, &dmaSz);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to get DMA\n");
        return -1;
    }

    ret = wc_LoadStaticMemory_ex(&hint, WH_POSIX_STATIC_MEM_LIST_SIZE, sizeList,
                                 distList, dma, dmaSz, 0, 0);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to load static memory\n");
        return -1;
    }

    ret = posixTransportShm_SetDmaHeap(shmCtx, (void*)hint);
    if (ret != 0) {
        WOLFHSM_CFG_PRINTF("Failed to set heap\n");
        return -1;
    }

    (void)ctx;
    return 0;
}


/* client configuration setup example for transport */
int wh_PosixClient_ExampleShmDmaConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccShm, 0, sizeof(posixTransportShmClientContext));
    memset(&c_comm, 0, sizeof(whCommClientConfig));

    shmConfig.name      = WH_POSIX_SHARED_MEMORY_NAME;
    shmConfig.req_size  = WH_POSIX_REQ_SIZE;
    shmConfig.resp_size = WH_POSIX_RESP_SIZE;
    shmConfig.dma_size  = WH_POSIX_DMA_SIZE;

    dmaConfig.cb               = posixTransportShm_ClientStaticMemDmaCallback;
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
int wh_PosixClient_ExampleTcpConfig(void* conf)
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

#if defined(WOLFHSM_CFG_TLS)
/* client configuration setup example for TLS transport */
#undef USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#include "wolfssl/certs_test.h"

int wh_PosixClient_ExampleTlsConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccTls, 0, sizeof(posixTransportTlsClientContext));

    /* Initialize TLS context fields that need specific values */
    tccTls.state         = 0;
    tccTls.connect_fd_p1 = 0; /* Invalid fd */

    tlsConfig.server_ip_string = WH_POSIX_SERVER_TCP_IPSTRING;
    tlsConfig.server_port      = WH_POSIX_SERVER_TCP_PORT;
    tlsConfig.disable_peer_verification = false;

    tlsConfig.ca_cert = ca_cert_der_2048;
    tlsConfig.ca_cert_len = sizeof_ca_cert_der_2048;
    tlsConfig.cert = client_cert_der_2048;
    tlsConfig.cert_len = sizeof_client_cert_der_2048;
    tlsConfig.key = client_key_der_2048;
    tlsConfig.key_len = sizeof_client_key_der_2048;
    tlsConfig.heap_hint = NULL;

    c_comm.transport_cb      = &tlsCb;
    c_comm.transport_context = (void*)&tccTls;
    c_comm.transport_config  = (void*)&tlsConfig;
    c_comm.client_id         = WH_POSIX_CLIENT_ID;
    c_conf->comm             = &c_comm;

    return WH_ERROR_OK;
}


#ifndef NO_PSK
/* Simple PSK example callback */
static unsigned int psk_tls12_client_cb(WOLFSSL* ssl, const char* hint,
                                        char* identity, unsigned int id_max_len,
                                        unsigned char* key,
                                        unsigned int   key_max_len)
{
    size_t len;

    memset(key, 0, key_max_len);
    const char* exampleIdentity = "PSK_EXAMPLE_CLIENT_IDENTITY";

    printf("PSK server identity hint: %s\n", hint);
    printf("PSK using identity: %s\n", exampleIdentity);
    strncpy(identity, exampleIdentity, id_max_len);

    printf("Enter PSK password: ");
    if (fgets((char*)key, key_max_len - 1, stdin) == NULL) {
        memset(key, 0, key_max_len);
        return 0U;
    }

    (void)ssl;
    len = strcspn((char*)key, "\n");
    ((char*)key)[len] = '\0';
    return (unsigned int)len;
}


int wh_PosixClient_ExamplePskConfig(void* conf)
{
    if (wh_PosixClient_ExampleTlsConfig(conf) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }
    tlsConfig.psk_client_cb = psk_tls12_client_cb;

    return WH_ERROR_OK;
}
#endif /* NO_PSK */
#endif /* WOLFHSM_CFG_TLS */


/* client configuration setup example for transport */
int wh_PosixClient_ExampleShmConfig(void* conf)
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
