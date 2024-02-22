/*
 * src/wh_comm.c
 */


#include <stdint.h>  /* For sized ints */
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "port/posix/posix_transport_tcp.h"

/** Client functions */

int wh_CommClient_Init(whCommClient* context, const whCommClientConfig* config)
{
    int rc = 0;

    if (    (context == NULL) ||
            (config == NULL)     ) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->transport_cb = config->transport_cb;
    context->transport_context = config->transport_context;
    context->client_id = config->client_id;
    if (context->transport_cb->Init != NULL) {
        rc = context->transport_cb->Init(context->transport_context,
                config->transport_config);
    }
    if (rc == 0) {
        context->hdr = (whHeader*)(&context->packet[0]);
        context->data = (void*)(&context->packet[WOLFHSM_COMM_HEADER_LEN]);
        context->initialized = 1;
    }
    return rc;
}

/* If a request buffer is available, send a new request to the server.  The
 * sequence number will be incremented on transport success.
 */
int wh_CommClient_SendRequest(whCommClient* context,
        uint16_t magic, uint16_t type, uint16_t *out_seq,
        uint16_t data_size, const void* data)
{
    int rc = WH_ERROR_NOTREADY;

    if (    (context == NULL) ||
            ((data == NULL) && (data_size != 0)) ) {
        return WH_ERROR_BADARGS;
    }

    if ((context->initialized != 0) &&
        (context->transport_cb != NULL) &&
        (context->transport_cb->Send != NULL)) {

        context->hdr->magic = magic;
        context->hdr->type = wh_Translate16(magic, type);
        context->hdr->seq = wh_Translate16(magic, context->seq + 1);
        if ((data != NULL) && (data_size != 0)) {
            memcpy(context->data, data, data_size);
        }
        rc = context->transport_cb->Send(context->transport_context,
                sizeof(*(context->hdr)) + data_size,
                context->packet);
        if (rc == 0) {
            context->seq++;
            if (out_seq != NULL) *out_seq = context->seq;
        }
    }
    return rc;
}

/* If a response packet has been buffered, get the header and copy the data out
 * of the buffer.
 */
int wh_CommClient_RecvResponse(whCommClient* context,
        uint16_t* out_magic, uint16_t* out_type, uint16_t* out_seq,
        uint16_t* out_size, void* data)
{
    int rc = WH_ERROR_NOTREADY;
    uint16_t magic = 0;
    uint16_t type = 0;
    uint16_t seq = 0;
    uint16_t size = sizeof(context->packet);

    if (    (context == NULL) ||
            (data == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if ((context->initialized != 0) &&
        (context->transport_cb != NULL) &&
        (context->transport_cb->Recv != NULL)) {

        rc = context->transport_cb->Recv(context->transport_context,
                &size,
                context->packet);
        if (rc == 0) {
            if (size >= sizeof(*context->hdr)) {
                size -= sizeof(*context->hdr);
                magic = context->hdr->magic;
                type = wh_Translate16(magic, context->hdr->type);
                seq = wh_Translate16(magic, context->hdr->seq);
                if ((data != NULL) && (size != 0)) {
                    memcpy(data, context->data, size);
                }
                if (out_magic != NULL) *out_magic = magic;
                if (out_type != NULL) *out_type = type;
                if (out_seq != NULL) *out_seq = seq;
                if (out_size != NULL) *out_size = size;
            } else {
                /* Size is too small */
                return WH_ERROR_ABORTED;
            }
        }
    }
    return rc;
}

/* Inform the server that no further communications are necessary and any
 * unfinished requests can be ignored.
 */
int wh_CommClient_Cleanup(whCommClient* context)
{
    int rc = 0;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (    (context->transport_cb != NULL) &&
            (context->transport_cb->Cleanup != NULL)) {
        rc = context->transport_cb->Cleanup(context->transport_context);
    }

    /* Mark as not initialized regardless of cleanup return */
    context->initialized = 0;
    return rc;
}

/** Server Functions */

int wh_CommServer_Init(whCommServer* context, const whCommServerConfig* config)
{
    int rc = 0;

    if (    (context == NULL) ||
            (config == NULL)     ) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->transport_context = config->transport_context;
    context->transport_cb = config->transport_cb;
    context->server_id = config->server_id;
    if (context->transport_cb->Init != NULL) {
        rc = context->transport_cb->Init(context->transport_context,
                config->transport_config);
    }
    if (rc == 0) {
        context->hdr = (whHeader*)(&context->packet[0]);
        context->data = (void*)(&context->packet[WOLFHSM_COMM_HEADER_LEN]);
        context->initialized = 1;
    }
    return rc;
}

int wh_CommServer_RecvRequest(whCommServer* context,
        uint16_t* out_magic, uint16_t* out_type, uint16_t* out_seq,
        uint16_t* out_size, void* data)
{
    int rc = WH_ERROR_NOTREADY;
    uint16_t magic = 0;
    uint16_t type = 0;
    uint16_t seq = 0;
    uint16_t size = sizeof(context->packet);

    if (    (context == NULL) ||
            (data == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if ((context->initialized != 0) &&
        (context->transport_cb != NULL) &&
        (context->transport_cb->Recv != NULL)) {

        rc = context->transport_cb->Recv(context->transport_context,
                &size,
                context->packet);
        if (rc == 0) {
            if (size >= sizeof(*context->hdr)) {

                size -= sizeof(*context->hdr);
                magic = context->hdr->magic;
                type = wh_Translate16(magic, context->hdr->type);
                seq = wh_Translate16(magic, context->hdr->seq);

                if ((data != NULL) && (size != 0)) {
                    memcpy(data, context->data, size);
                }
                if (out_magic != NULL) *out_magic = magic;
                if (out_type != NULL) *out_type = type;
                if (out_seq != NULL) *out_seq = seq;
                if (out_size != NULL) *out_size = size;
            } else {
                /* Size is too small */
                rc = WH_ERROR_ABORTED;
            }
        }
    }
    return rc;
}

int wh_CommServer_SendResponse(whCommServer* context,
        uint16_t magic, uint16_t type, uint16_t seq,
        uint16_t data_size, const void* data)
{
    int rc = WH_ERROR_NOTREADY;
    if (    (context == NULL) ||
            ((data == NULL) && (data_size != 0)) ) {
        return WH_ERROR_BADARGS;
    }

    if ((context->initialized != 0) &&
        (context->transport_cb != NULL) &&
        (context->transport_cb->Send != NULL)) {

        context->hdr->magic = magic;
        context->hdr->type = wh_Translate16(magic, type);
        context->hdr->seq = wh_Translate16(magic, seq);
        if ((data != NULL) && (data_size != 0)) {
            memcpy(context->data, data, data_size);
        }
        rc = context->transport_cb->Send(context->transport_context,
                sizeof(*(context->hdr)) + data_size,
                context->packet);
    }
    return rc;
}

int wh_CommServer_Cleanup(whCommServer* context)
{
    int rc = 0;
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (    (context->transport_cb != NULL) &&
            (context->transport_cb->Cleanup != NULL)) {
        rc = context->transport_cb->Cleanup(context->transport_context);
    }

    /* Mark as not initialized regardless of cleanup return */
    context->initialized = 0;
    return rc;
}
