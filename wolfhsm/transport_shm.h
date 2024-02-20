/*
 * wolfhsm/transport_shm.h
 *
 * wolfHSM Transport binding using shmbuffer
 */

#ifndef WH_TRANSPORT_SHM_H_
#define WH_TRANSPORT_SHM_H_

/* Example usage:
 *
 * uint8_t req_buffer[4096];
 * uint8_t resp_buffer[4096];
 *
 * whTransportShmConfig shm_config[1] = {{
 *      .req = req_buffer,
 *      .req_size = sizeof(req_buffer),
 *      .resp = resp_buffer
 *      .resp_size = sizeof(resp_buffer),
 * }};
 *
 * whTransportShmClientContext shmcc[1];
 * whCommClientConfig ccc[1] = {{
 *      .transport_cb = whTransportShmClient_Cb,
 *      .transport_context = shmcc,
 *      .transport_config = shm_config,
 *      .client_id = 1234,
 * }};
 * whCommClient cc[1];
 * wh_CommClient_Init(cc, ccc);
 *
 * whTransportShmServerContext shmsc[1];
 * whCommServerConfig csc[1] = {{
 *      .transport_cb = whTransportShmServer_Cb,
 *      .transport_context = shmsc,
 *      .transport_config = shm_config,
 *      .server_id = 5678,
 * }};
 * whCommServer cs[1];
 * wh_CommServer_Init(cs, csc);
 *
 */

#include <stdint.h>
#include <wolfhsm/wh_transport.h>

#include "wolfhsm/shmbuffer.h"

/* Naming conveniences. Reuses the same types. */
typedef whShmbufferConfig whTransportShmConfig;
typedef whShmbufferContext whTransportShmClientContext;
typedef whShmbufferContext whTransportShmServerContext;

/* wh_TranportClient compliant callbacks */
extern const wh_TransportClient_Cb* whTransportShmClient_Cb;

/* wh_TranportServer compliant callbacks */
extern const wh_TransportServer_Cb* whTransportShmServer_Cb;

#endif /* WH_TRANSPORT_SHM_H_ */
