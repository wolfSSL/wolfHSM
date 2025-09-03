#include <stdint.h>
#include <string.h> /* For memset, memcpy, strcmp */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_utils.h"

#include "wh_example_posix.h"
#include "port/posix/posix_transport_shm.h"


#define WH_SHARED_MEMORY_NAME "wh_example_shm"
#define WH_CLIENT_ID 12
#define WH_SERVER_ID 57


/* client configuration structures */
whTransportClientCb            pttcClientShmCb[1] =
    {POSIX_TRANSPORT_SHM_CLIENT_CB};
posixTransportShmClientContext tcc;
posixTransportShmConfig        myshmconfig;
whCommClientConfig             cc_conf;

/* client configuration setup example for transport */
int wh_Client_ExampleSHMConfig(whClientConfig* c_conf)
{
    memset(&tcc, 0, sizeof(posixTransportShmClientContext));

    myshmconfig.name = WH_SHARED_MEMORY_NAME;
    myshmconfig.req_size  = 1024;
    myshmconfig.resp_size = 1024;
    myshmconfig.dma_size  = 4096;

    cc_conf.transport_cb      = pttcClientShmCb;
    cc_conf.transport_context = (void*)&tcc;
    cc_conf.transport_config  = (void*)&myshmconfig,
    cc_conf.client_id         = WH_CLIENT_ID,
    c_conf->comm              = &cc_conf;

    return WH_ERROR_OK;
}

/* server configuration structures */
whTransportServerCb            pttServerShmCb[1] =
    {POSIX_TRANSPORT_SHM_SERVER_CB};
posixTransportShmServerContext tsc;
posixTransportShmConfig        myshmconfig;
whCommServerConfig             cs_conf;

/* Server configuration setup example for transport
 * Does not setup flash, nvm, crypto, she, etc. */
int wh_Server_ExampleSHMConfig(whServerConfig* s_conf)
{
    memset(&tsc, 0, sizeof(posixTransportShmServerContext));

    myshmconfig.name = WH_SHARED_MEMORY_NAME;
    myshmconfig.req_size  = 1024;
    myshmconfig.resp_size = 1024;
    myshmconfig.dma_size  = 4096;

    cs_conf.transport_cb      = pttServerShmCb;
    cs_conf.transport_context = (void*)&tsc;
    cs_conf.transport_config  = (void*)&myshmconfig;
    cs_conf.server_id         = WH_SERVER_ID;

    s_conf->comm_config = &cs_conf;

    return WH_ERROR_OK;
}
