/*
 * transport_shm.c
 *
 * Implementation of transport callbacks using shmbuffer
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <wolfhsm/wh_error.h>
#include <wolfhsm/wh_transport.h>

#include "wolfhsm/shmbuffer.h"

#include "wolfhsm/transport_shm.h"

/* Define and declare callbacks that match wolfhsm/transport.h */
static int _wh_TransportShm_InitClear(void* context, const void* config);
static int _wh_TransportShm_SendRequest(void* context, uint16_t size,
        const void* data);
static int _wh_TransportShm_RecvResponse(void* context, uint16_t *out_size,
        void* data);

static int _wh_TransportShm_Init(void* context, const void* config);
static int _wh_TransportShm_RecvRequest(void* context, uint16_t *out_size,
        void* data);
static int _wh_TransportShm_SendResponse(void* context, uint16_t size,
        const void* data);

static int _wh_TransportShm_Cleanup(void* context);

static int _wh_TransportShm_InitClear(void* context, const void* config)
{
    return wh_Shmbuffer_InitClear(
            (whShmbufferContext*)context,
            (const whShmbufferConfig*)config);
}

static int _wh_TransportShm_SendRequest(void* context,
        uint16_t size, const void* data)
{
    return wh_Shmbuffer_SendRequest(
            (whShmbufferContext*)context,
            size,
            data);
}

static int _wh_TransportShm_RecvResponse(void* context,
        uint16_t* out_size, void* data)
{
    return wh_Shmbuffer_RecvResponse(
            (whShmbufferContext*)context,
            out_size,
            data);
}

static int _wh_TransportShm_Init(void* context, const void* config)
{
    return wh_Shmbuffer_Init(
            (whShmbufferContext*)context,
            (const whShmbufferConfig*)config);
}

static int _wh_TransportShm_RecvRequest(void* context,
        uint16_t* out_size, void* data)
{
    return wh_Shmbuffer_RecvRequest(
            (whShmbufferContext*)context,
            out_size,
            data);
}

static int _wh_TransportShm_SendResponse(void* context,
        uint16_t size, const void* data)
{
    return wh_Shmbuffer_SendResponse(
            (whShmbufferContext*)context,
            size,
            data);
}

static int _wh_TransportShm_Cleanup(void* context)
{
    return wh_Shmbuffer_Cleanup((whShmbufferContext*)context);
}

/** TransportClient Implementation */
static const wh_TransportClient_Cb _whTransportShmClient_Cb = {
        .Init =     _wh_TransportShm_InitClear,
        .Send =     _wh_TransportShm_SendRequest,
        .Recv =     _wh_TransportShm_RecvResponse,
        .Cleanup =  _wh_TransportShm_Cleanup,
};
const wh_TransportClient_Cb* whTransportShmClient_Cb = &_whTransportShmClient_Cb;

/** TransportServer Implementation */
static const wh_TransportServer_Cb _whTransportShmServer_Cb = {
        .Init =     _wh_TransportShm_Init,
        .Recv =     _wh_TransportShm_RecvRequest,
        .Send =     _wh_TransportShm_SendResponse,
        .Cleanup =  _wh_TransportShm_Cleanup,
};
const wh_TransportServer_Cb* whTransportShmServer_Cb = &_whTransportShmServer_Cb;

