/*
 * src/wh_transport_mem.c
 *
 * Implementation of transport callbacks using 2 memory blocks
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_transport.h"
#include "wolfhsm/wh_transport_mem.h"

int wh_TransportMem_Init(void* c, const void* cf)
{
    whTransportMemContext* context = c;
    const whTransportMemConfig* config = cf;
    if (    (context == NULL) ||
            (config == NULL) ||
            (config->req == NULL) ||
            (config->req_size == 0) ||
            (config->resp == NULL) ||
            (config->resp_size == 0)) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->req        = (whTransportMemCsr*)config->req;
    context->req_size   = config->req_size;
    context->req_data   = (void*)(context->req + 1);

    context->resp       = (whTransportMemCsr*)config->resp;
    context->resp_size  = config->resp_size;
    context->resp_data  = (void*)(context->resp + 1);

    context->initialized = 1;
    return 0;
}

int wh_TransportMem_InitClear(void* c, const void* cf)
{
    whTransportMemContext* context = c;
    int rc = wh_TransportMem_Init(c, cf);
    if (rc == 0) {
        /* Zero the buffers */
        memset((void*)context->req, 0, context->req_size);
        memset((void*)context->resp, 0, context->resp_size);
    }
    return rc;
}

int wh_TransportMem_Cleanup(void* c)
{
    whTransportMemContext* context = c;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    context->initialized = 0;

    return 0;
}

int wh_TransportMem_SendRequest(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* context = c;
    whTransportMemCsr resp;
    whTransportMemCsr req;

    if (    (context == NULL) ||
            (context->initialized == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Read current CSR's */
    resp.u64 = context->resp->u64;
    req.u64 = context->req->u64;

    /* Has server completed with previous request */
    if (req.s.notify != resp.s.notify) {
        return WH_ERROR_NOTREADY;
    }

    if ((data != NULL) && (len != 0)) {
        memcpy((void*)context->req_data, data, len);
    }
    req.s.len = len;
    req.s.notify++;

    /* Write the new CSR's */
    context->req->u64 = req.u64;

    return 0;
}

int wh_TransportMem_RecvRequest(void* c, uint16_t *out_len, void* data)
{
    whTransportMemContext* context = c;
    whTransportMemCsr req;
    whTransportMemCsr resp;

    if (    (context == NULL) ||
            (context->initialized == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Read current request CSR's */
    req.u64 = context->req->u64;
    resp.u64 = context->resp->u64;

    /* Check to see if a new request has arrived */
    if(req.s.notify == resp.s.notify) {
        return WH_ERROR_NOTREADY;
    }

    if ((data != NULL) && (req.s.len != 0)) {
        memcpy(data, context->req_data, req.s.len);
    }
    if (out_len != NULL) {
        *out_len = req.s.len;
    }

    return 0;
}

int wh_TransportMem_SendResponse(void* c, uint16_t len, const void* data)
{
    whTransportMemContext* context = c;
    whTransportMemCsr req;
    whTransportMemCsr resp;

    if (    (context == NULL) ||
            (context->initialized == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Read both CSR's */
    req.u64 = context->req->u64;
    resp.u64 = context->resp->u64;

    if ((data != NULL) && (len != 0)) {
        memcpy(context->resp_data, data, len);
        /* TODO: Cache flush resp_data for len bytes */
    }
    resp.s.len = len;
    resp.s.notify = req.s.notify;

    /* Write the new CSR's */
    context->resp->u64 = resp.u64;

    return 0;
}

int wh_TransportMem_RecvResponse(void* c, uint16_t *out_len, void* data)
{
    whTransportMemContext* context = c;
    whTransportMemCsr req;
    whTransportMemCsr resp;

    if (    (context == NULL) ||
            (context->initialized == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Read both CSR's */
    req.u64 = context->req->u64;
    resp.u64 = context->resp->u64;

    /* Check to see if the current response is the different than the request */
    if(resp.s.notify != req.s.notify) {
        return WH_ERROR_NOTREADY;
    }

    if ((data != NULL) && (resp.s.len != 0)) {
        /* TODO: Cache invalidate resp_data for resp.s.len bytes */
        memcpy(data, context->resp_data, resp.s.len);
    }

    if (out_len != NULL) {
        *out_len = resp.s.len;
    }

    return 0;
}
