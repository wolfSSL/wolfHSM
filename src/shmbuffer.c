/*
 * shmbuffer.c
 *
 * Implementation of comms over a shared memory section
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "wolfhsm/error.h"
#include "wolfhsm/shmbuffer.h"

union whShmbufferCsr_t {
    uint64_t u64;
    struct {
        uint16_t notify;   /* Incremented to notify */
        uint16_t len;      /* Length of data */
        uint16_t ack;      /* Opt: Acknowledge the reverse notify */
        uint16_t wait;     /* Opt: Incremented while waiting*/
    } s;
};

int wh_Shmbuffer_Init(  whShmbufferContext* context,
                        const whShmbufferConfig* config)
{
    if (    (context == NULL) ||
            (config == NULL) ||
            (config->req == NULL) ||
            (config->req_size == 0) ||
            (config->resp == NULL) ||
            (config->resp_size == 0)) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->req        = (whShmbufferCsr*)config->req;
    context->req_size   = config->req_size;
    context->req_data   = (void*)(context->req + 1);

    context->resp       = (whShmbufferCsr*)config->resp;
    context->resp_size  = config->resp_size;
    context->resp_data  = (void*)(context->resp + 1);

    context->initialized = 1;
    return 0;
}

int wh_Shmbuffer_InitClear(whShmbufferContext* context,
        const whShmbufferConfig* config)
{
    int rc = wh_Shmbuffer_Init(context, config);
    if (rc == 0) {
        /* Zero the buffers */
        memset((void*)context->req, 0, context->req_size);
        memset((void*)context->resp, 0, context->resp_size);
    }
    return rc;
}

int wh_Shmbuffer_Cleanup(whShmbufferContext* context)
{
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    context->initialized = 0;

    return 0;
}

int wh_Shmbuffer_SendRequest(whShmbufferContext* context, uint16_t len,
        const uint8_t* data)
{
    whShmbufferCsr resp;
    whShmbufferCsr req;

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
        /* TODO: Cache flush req_data for len bytes */
    }
    req.s.len = len;
    req.s.notify++;

    /* Write the new CSR's */
    context->req->u64 = req.u64;

    return 0;
}

int wh_Shmbuffer_RecvRequest(   whShmbufferContext* context,
                                uint16_t *out_len, uint8_t* data)
{
    whShmbufferCsr req;
    whShmbufferCsr resp;

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
        /* TODO: Cache invalidate req_data for req.s.len bytes */
        memcpy(data, context->req_data, req.s.len);
    }
    if (out_len != NULL) *out_len = req.s.len;

    return 0;
}

int wh_Shmbuffer_SendResponse(  whShmbufferContext* context,
                                uint16_t len, const uint8_t* data)
{
    whShmbufferCsr req;
    whShmbufferCsr resp;

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

int wh_Shmbuffer_RecvResponse(  whShmbufferContext* context,
                                uint16_t *out_len, uint8_t* data)
{
    whShmbufferCsr req;
    whShmbufferCsr resp;

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

    if (out_len != NULL) *out_len = resp.s.len;

    return 0;
}
