/*
 * wolfhsm/shmbuffer.h
 *
 * Request/response packets over a shared memory
 */

#ifndef WH_SHMBUFFER_H_
#define WH_SHMBUFFER_H_

/* Shared memory comms
 * Client and server each have access to a shared buffer, which is split into
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
 * *
 */

#include <stdint.h>

typedef struct {
    void* req;
    uint16_t req_size;
    void* resp;
    uint16_t resp_size;
} whShmbufferConfig;

/* Shared memory control/status layout.  Data buffer follows immediately */
typedef union whShmbufferCsr_t whShmbufferCsr;

typedef struct {
    volatile whShmbufferCsr* req;
    void* req_data;
    uint16_t req_size;
    volatile whShmbufferCsr* resp;
    void* resp_data;
    uint16_t resp_size;
    int initialized;
} whShmbufferContext;

int wh_Shmbuffer_Init(  whShmbufferContext* context,
                        const whShmbufferConfig* config);

int wh_Shmbuffer_InitClear( whShmbufferContext* context,
                            const whShmbufferConfig* config);

int wh_Shmbuffer_Cleanup(   whShmbufferContext* context);

int wh_Shmbuffer_SendRequest(   whShmbufferContext* context,
                                uint16_t size,
                                const uint8_t* data);

int wh_Shmbuffer_RecvRequest(   whShmbufferContext* context,
                                uint16_t *out_size,
                                uint8_t* data);

int wh_Shmbuffer_SendResponse(  whShmbufferContext* context,
                                uint16_t len,
                                const uint8_t* data);

int wh_Shmbuffer_RecvResponse(  whShmbufferContext* context,
                                uint16_t *out_size,
                                uint8_t* data);

#endif /* WH_SHMBUFFER_H_ */
