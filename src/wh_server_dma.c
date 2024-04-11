#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server_dma.h"

/* TODO: if the Address allowlist ever gets large, we should consider a more
 * efficient representation (requiring sorted array and binary search, or
 * building a binary tree, etc.) */


static int _checkAddrAgainstAllowList(const whDmaAddrList allowList, void* addr,
                                      size_t size)
{
    uintptr_t startAddr = (uintptr_t)addr;
    uintptr_t endAddr   = startAddr + size;

    /* Check if the address range is fully within a allowlist entry */
    for (int i = 0; i < WH_DMA_ADDR_ALLOWLIST_SIZE; i++) {
        uintptr_t allowlistStartAddr = (uintptr_t)allowList[i].addr;
        uintptr_t allowlistEndAddr   = allowlistStartAddr + allowList[i].size;

        if (startAddr >= allowlistStartAddr && endAddr <= allowlistEndAddr) {
            return WH_ERROR_OK;
        }
    }

    return WH_ERROR_ACCESS;
}

static int _checkMemOperAgainstAllowList(const whDmaAddrAllowList* allowList,
                                         whDmaOper oper, void* addr,
                                         size_t size)
{
    int rc = WH_ERROR_OK;

    /* If a read/write operation is requested, check the transformed address
     * against the appropriate allowlist
     *
     * TODO: do we need to allowlist check on POST in case there are subsequent
     * memory operations for some reason?
     */
    if (oper == WH_DMA_OPER_CLIENT_READ_PRE) {
        rc = _checkAddrAgainstAllowList(allowList->readList, addr, size);
    }
    else if (oper == WH_DMA_OPER_CLIENT_WRITE_PRE) {
        rc = _checkAddrAgainstAllowList(allowList->writeList, addr, size);
    }

    return rc;
}

int wh_Server_DmaRegisterCb(whServerContext* server, whDmaCb cb)
{
    if (NULL == server) {
        return WH_ERROR_BADARGS;
    }

    server->dmaCb = cb;

    return WH_ERROR_OK;
}


int wh_Server_DmaRegisterAllowList(whServerContext*          server,
                                   const whDmaAddrAllowList* allowlist)
{
    if (NULL == server || NULL == allowlist) {
        return WH_ERROR_BADARGS;
    }

    server->dmaAddrAllowList = allowlist;

    return WH_ERROR_OK;
}


int wh_Server_DmaProcessClientAddress32(whServerContext* server,
                                        uint32_t         clientAddr,
                                        void** xformedCliAddr, uint32_t len,
                                        whDmaOper oper, whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == server || NULL == xformedCliAddr) {
        return WH_ERROR_BADARGS;
    }

    /* Transformed address defaults to raw client address */
    *xformedCliAddr = (void*)((uintptr_t)clientAddr);

    /* Perform user-supplied address transformation, cache manipulation, etc */
    if (NULL != server->dmaCb.cb32) {
        rc = server->dmaCb.cb32(server, clientAddr, xformedCliAddr, len, oper,
                                flags);
    }

    /* if the server has a allowlist registered, check transformed address
     * against it */
    if (server->dmaAddrAllowList != NULL) {
        rc = _checkMemOperAgainstAllowList(server->dmaAddrAllowList, oper,
                                           *xformedCliAddr, len);
    }

    return rc;
}


int wh_Server_DmaProcessClientAddress64(whServerContext* server,
                                        uint64_t         clientAddr,
                                        void** xformedCliAddr, uint64_t len,
                                        whDmaOper oper, whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    if (NULL == server || NULL == xformedCliAddr) {
        return WH_ERROR_BADARGS;
    }

    /* Transformed address defaults to raw client address */
    *xformedCliAddr = (void*)((uintptr_t)clientAddr);

    /* Perform user-supplied address transformation, cache manipulation, etc */
    if (NULL != server->dmaCb.cb64) {
        rc = server->dmaCb.cb64(server, clientAddr, xformedCliAddr, len, oper,
                                flags);
    }

    /* if the server has a allowlist registered, check address against it */
    if (server->dmaAddrAllowList != NULL) {
        rc = _checkMemOperAgainstAllowList(server->dmaAddrAllowList, oper,
                                           *xformedCliAddr, len);
    }

    return rc;
}


int whServerDma_CopyFromClient32(struct whServerContext_t* server,
                                 void* serverPtr, uint32_t clientAddr,
                                 size_t len, whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be checked against UINT32Max? Should it be uint32_t? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(
        server->dmaAddrAllowList, WH_DMA_OPER_CLIENT_READ_PRE, serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-read */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(serverPtr, transformedAddr, len);

    /* Process the client address post-read */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_POST,
        flags);

    return rc;
}


int whServerDma_CopyFromClient64(struct whServerContext_t* server,
                                 void* serverPtr, uint64_t clientAddr,
                                 size_t len, whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be be uint64_t? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(
        server->dmaAddrAllowList, WH_DMA_OPER_CLIENT_READ_PRE, serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-read */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(serverPtr, transformedAddr, len);

    /* process the client address post-read */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_READ_POST,
        flags);

    return rc;
}

int whServerDma_CopyToClient32(struct whServerContext_t* server,
                               uint32_t clientAddr, void* serverPtr, size_t len,
                               whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be checked against UINT32Max? Should it be uint32_t ? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(
        server->dmaAddrAllowList, WH_DMA_OPER_CLIENT_WRITE_PRE, serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-write */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_WRITE_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(transformedAddr, serverPtr, len);

    /* Process the client address post-write */
    rc = wh_Server_DmaProcessClientAddress32(
        server, clientAddr, &transformedAddr, len,
        WH_DMA_OPER_CLIENT_WRITE_POST, flags);

    return rc;
}


int whServerDma_CopyToClient64(struct whServerContext_t* server,
                               uint64_t clientAddr, void* serverPtr, size_t len,
                               whDmaFlags flags)
{
    int rc = WH_ERROR_OK;

    void* transformedAddr = NULL;

    /* TODO: should len be uint64_t? */
    if (NULL == server || NULL == serverPtr || 0 == len) {
        return WH_ERROR_BADARGS;
    }

    /* Check the server address against the allow list */
    rc = _checkMemOperAgainstAllowList(
        server->dmaAddrAllowList, WH_DMA_OPER_CLIENT_WRITE_PRE, serverPtr, len);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Process the client address pre-write */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len, WH_DMA_OPER_CLIENT_WRITE_PRE,
        flags);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* Perform the actual copy */
    /* TODO: should we add a flag to force client word-sized reads? */
    memcpy(transformedAddr, serverPtr, len);

    /* Process the client address post-write */
    rc = wh_Server_DmaProcessClientAddress64(
        server, clientAddr, &transformedAddr, len,
        WH_DMA_OPER_CLIENT_WRITE_POST, flags);

    return rc;
}
