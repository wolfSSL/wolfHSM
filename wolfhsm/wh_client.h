/*
 * wolfhsm/wh_client.h
 *
 * Base WolfHSM Client Library API
 *
 * The WolfHSM Client provides a single context and connection to a
 * WolfHSM Server.  All communications and state are internally managed by
 * registering a crypto callback function to be invoked synchronously when
 * wolfCrypt functions are called.  In order to specify to use the WolfHSM
 * Server for cryptographic operations, the device id WOLFHSM_DEV_ID should be
 * passed into any of the wolfCrypt init functions.
 *
 * In addition to the offload of cryptographic functions, the WolfHSM Client
 * also exposes WolfHSM Server key management, non-volatile memory, and protocol
 * functions.
 */

#ifndef WOLFHSM_WH_CLIENT_H_
#define WOLFHSM_WH_CLIENT_H_

/* System libraries */
#include <stdint.h>

/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"

/* Component includes */
#include "wolfhsm/wh_comm.h"

/* Client context */
struct whClientContext_t {
    whCommClient comm[1];
    uint16_t last_req_id;
    uint16_t last_req_kind;
};
typedef struct whClientContext_t whClientContext;

struct whClientConfig_t {
    whCommClientConfig* comm;
};
typedef struct whClientConfig_t whClientConfig;


/** Context initialization and shutdown functions */
/* Initialize client context and connect to server based on provided
 * configuration */
int wh_Client_Init(whClientContext* c, const whClientConfig* config);

/* Disconnect from server and release any resources */
int wh_Client_Cleanup(whClientContext* c);


/** Generic request/response functions */
/* TODO: Move these to internal API */
int wh_Client_SendRequest(whClientContext* c,
        uint16_t group, uint16_t action,
        uint16_t data_size, const void* data);
int wh_Client_RecvResponse(whClientContext *c,
        uint16_t *out_group, uint16_t *out_action,
        uint16_t *out_size, void* data);


/** Comm component functions */
int wh_Client_EchoRequest(whClientContext* c, uint16_t size, const void* data);
int wh_Client_EchoResponse(whClientContext* c, uint16_t *out_size, void* data);
int wh_Client_Echo(whClientContext* c, uint16_t snd_len, const void* snd_data,
        uint16_t *out_rcv_len, void* rcv_data);


/** NVM functions */
int wh_Client_NvmInitRequest(whClientContext* c);
int wh_Client_NvmInitResponse(whClientContext* c, int32_t *out_rc,
        uint32_t *out_clientnvm_id, uint32_t *out_servernvm_id);
int wh_Client_NvmInit(whClientContext* c, int32_t *out_rc,
        uint32_t *out_clientnvm_id, uint32_t *out_servernvm_id);

int wh_Client_NvmCleanupRequest(whClientContext* c);
int wh_Client_NvmCleanupResponse(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmCleanup(whClientContext* c, int32_t *out_rc);

int wh_Client_NvmGetAvailableRequest(whClientContext* c);
int wh_Client_NvmGetAvailableResponse(whClientContext* c, int32_t *out_rc,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);
int wh_Client_NvmGetAvailable(whClientContext* c, int32_t *out_rc,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects);

int wh_Client_NvmAddObjectRequest(whClientContext* c,
        whNvmId id, whNvmAccess access, whNvmFlags flags,
        whNvmSize label_len, uint8_t* label,
        whNvmSize len, const uint8_t* data);
int wh_Client_NvmAddObjectResponse(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmAddObject(whClientContext* c,
        whNvmId id, whNvmAccess access, whNvmFlags flags,
        whNvmSize label_len, uint8_t* label,
        whNvmSize len, const uint8_t* data, int32_t *out_rc);

int wh_Client_NvmListRequest(whClientContext* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id);
int wh_Client_NvmListResponse(whClientContext* c, int32_t *out_rc,
        whNvmId *out_count, whNvmId *out_id);
int wh_Client_NvmList(whClientContext* c,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        int32_t *out_rc, whNvmId *out_count, whNvmId *out_id);

int wh_Client_NvmGetMetadataRequest(whClientContext* c, whNvmId id);
int wh_Client_NvmGetMetadataResponse(whClientContext* c, int32_t *out_rc,
        whNvmId *out_id, whNvmAccess *out_access, whNvmFlags *out_flags,
        whNvmSize *out_len,
        whNvmSize label_len, uint8_t* label);
int wh_Client_NvmGetMetadata(whClientContext* c, whNvmId id,
        int32_t *out_rc, whNvmId *out_id, whNvmAccess *out_access,
        whNvmFlags *out_flags, whNvmSize *out_len,
        whNvmSize label_len, uint8_t* label);

int wh_Client_NvmDestroyObjectsRequest(whClientContext* c,
        whNvmId list_count, const whNvmId* id_list);
int wh_Client_NvmDestroyObjectsResponse(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmDestroyObjects(whClientContext* c,
        whNvmId list_count, const whNvmId* id_list,
        whNvmSize len, const uint8_t* data, int32_t *out_rc);

int wh_Client_NvmReadRequest(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len);
int wh_Client_NvmReadResponse(whClientContext* c, int32_t *out_rc,
        whNvmSize *out_len, uint8_t* data);
int wh_Client_NvmRead(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        int32_t *out_rc, whNvmSize *out_len, uint8_t* data);

int wh_Client_NvmAddObjectDma32Request(whClientContext* c,
        uint32_t metadata_hostaddr,
        whNvmSize data_len, uint32_t data_hostaddr);
int wh_Client_NvmAddObjectDma32Response(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmAddObjectDma32(whClientContext* c,
        uint32_t metadata_hostaddr, whNvmSize data_len, uint32_t data_hostaddr,
        int32_t *out_rc);

int wh_Client_NvmAddObjectDma64Request(whClientContext* c,
        uint64_t metadata_hostaddr,
        whNvmSize data_len, uint64_t data_hostaddr);
int wh_Client_NvmAddObjectDma64Response(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmAddObjectDma64(whClientContext* c,
        uint64_t metadata_hostaddr, whNvmSize data_len, uint64_t data_hostaddr,
        int32_t *out_rc);

int wh_Client_NvmAddObjectDmaRequest(whClientContext* c,
        whNvmMetadata* metadata,
        whNvmSize data_len, const uint8_t* data);
int wh_Client_NvmAddObjectDmaResponse(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmAddObjectDma(whClientContext* c,
        whNvmMetadata* metadata, whNvmSize data_len, const uint8_t* data,
        int32_t *out_rc);

int wh_Client_NvmReadDma32Request(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint32_t data_hostaddr);
int wh_Client_NvmReadDma32Response(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmReadDma32(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint32_t data_hostaddr, int32_t *out_rc);

int wh_Client_NvmReadDma64Request(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint64_t data_hostaddr);
int wh_Client_NvmReadDma64Response(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmReadDma64(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint64_t data_hostaddr, int32_t *out_rc);

int wh_Client_NvmReadDmaRequest(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len,
        uint8_t* data);
int wh_Client_NvmReadDmaResponse(whClientContext* c, int32_t *out_rc);
int wh_Client_NvmReadDma(whClientContext* c,
        whNvmId id, whNvmSize offset, whNvmSize data_len, uint8_t* data,
        int32_t *out_rc);

#endif /* WOLFHSM_WH_CLIENT_H_ */
