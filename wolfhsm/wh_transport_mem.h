/*
 * wolfhsm/wh_transport_mem.h
 *
 * wolfHSM Transport binding using 2 memory blocks
 */

#ifndef WH_TRANSPORT_MEM_H_
#define WH_TRANSPORT_MEM_H_

/* Memory block comms
 * Client and server each have access to a shared memory, which is split into
 * request and response buffers.  The top 64-bits of each buffer provide control
 * and status registers that are used to convey flow control.
 *
 * The client generally writes to the request buffer and reads from the response
 * buffer.  The server generally reads from the request buffer and writes to
 * the response buffer.
 *
 * The client sends a request by:
 *  1. Receive the previous response to ensure completion.
 *  2. Writes request data: req->data[] = data[]
 *  3. Increments requestid: req_id = req->notify++
 *  4. Optionally sends notify interrupt to server.
 *
 * The client receives a response to req_id by:
 *  1. Check if the request is complete: resp->notify == req_id
 *  2. Read response data: data[] = resp->data[]
 *
 * The server handles a request by:
 *  1. Check for new request: req->notify != resp->notify
 *  2. Read request data: data[] = req->data[]
 *  3. Save requestid: req_id = req->notify
 *
 * The server sends a response by:
 *  1. Write response data: resp->data[] = data[]
 *  2. Set response id to requestid: resp->notify = req_id
 *  3. Optionally send notify interrupt to client
 *
 *
 * Example usage:
 *
 * uint8_t req_buffer[4096];
 * uint8_t resp_buffer[4096];
 *
 * whTransportMemConfig mem_config[1] = {{
 *      .req = req_buffer,
 *      .req_size = sizeof(req_buffer),
 *      .resp = resp_buffer
 *      .resp_size = sizeof(resp_buffer),
 * }};
 *
 * whTransportMemClientContext memcc[1];
 * whCommClientConfig ccc[1] = {{
 *      .transport_cb = whTransportMemClient_Cb,
 *      .transport_context = memcc,
 *      .transport_config = mem_config,
 *      .client_id = 1234,
 * }};
 * whCommClient cc[1];
 * wh_CommClient_Init(cc, ccc);
 *
 * whTransportMemServerContext memsc[1];
 * whCommServerConfig csc[1] = {{
 *      .transport_cb = whTransportMemServer_Cb,
 *      .transport_context = memsc,
 *      .transport_config = mem_config,
 *      .server_id = 5678,
 * }};
 * whCommServer cs[1];
 * wh_CommServer_Init(cs, csc);
 *
 */

#include <stdint.h>
#include <wolfhsm/wh_transport.h>

typedef struct {
    void* req;
    uint16_t req_size;
    void* resp;
    uint16_t resp_size;
} whTransportMemConfig;

/* Memory buffer control/status layout.  Data buffer follows immediately */
typedef union whTransportMemCsr_t whTransportMemCsr;

typedef struct {
    volatile whTransportMemCsr* req;
    void* req_data;
    uint16_t req_size;
    volatile whTransportMemCsr* resp;
    void* resp_data;
    uint16_t resp_size;
    int initialized;
} whTransportMemContext;

/* Naming conveniences. Reuses the same types. */
typedef whTransportMemContext whTransportMemClientContext;
typedef whTransportMemContext whTransportMemServerContext;

/* Callback function declarations */
int wh_TransportMem_Init(void* c, const void* cf);
int wh_TransportMem_InitClear(void* c, const void* cf);
int wh_TransportMem_Cleanup(void* c);
int wh_TransportMem_SendRequest(void* c, uint16_t len, const uint8_t* data);
int wh_TransportMem_RecvRequest(void* c, uint16_t *out_len, uint8_t* data);
int wh_TransportMem_SendResponse(void* c, uint16_t len, const uint8_t* data);
int wh_TransportMem_RecvResponse(void* c, uint16_t *out_len, uint8_t* data);


/* wh_TranportClient compliant callbacks */
extern const wh_TransportClient_Cb* whTransportMemClient_Cb;

/* wh_TranportServer compliant callbacks */
extern const wh_TransportServer_Cb* whTransportMemServer_Cb;

#endif /* WH_TRANSPORT_MEM_H_ */
