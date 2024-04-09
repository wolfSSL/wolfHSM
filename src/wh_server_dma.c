#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server_dma.h"

int wh_Server_DmaRegisterCb(whServerContext* server, whDmaCb cb)
{
    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    server->dmaCb = cb;

    return WH_ERROR_OK;
}


int wh_Server_DmaProcessClientAddress32(whServerContext* server,
                                        uint32_t clientAddr, void** serverPtr,
                                        uint32_t len, whDmaOper oper,
                                        whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    if (NULL != server->dmaCb.cb32) {
        rc =
            server->dmaCb.cb32(server, clientAddr, serverPtr, len, oper, flags);
    }

    /* TODO: other stuff besides invoking client DMA callback? */

    return rc;
}


int wh_Server_DmaProcessClientAddress64(whServerContext* server,
                                        uint64_t clientAddr, void** serverPtr,
                                        uint64_t len, whDmaOper oper,
                                        whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    if (NULL != server->dmaCb.cb64) {
        rc =
            server->dmaCb.cb64(server, clientAddr, serverPtr, len, oper, flags);
    }

    /* TODO: other stuff besides invoking client DMA callback? */

    return rc;
}