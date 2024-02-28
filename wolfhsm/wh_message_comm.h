/*
 * wolfhsm/wh_message_comm.h
 *
 * Comm component message action enumerations and definitions.
 *
 */

#ifndef WOLFHSM_WH_MESSAGE_COMM_H_
#define WOLFHSM_WH_MESSAGE_COMM_H_

#include <stdint.h>

/* Comm component message kinds */
enum {
    WH_MESSAGE_COMM_ACTION_NONE      = 0x00,
    WH_MESSAGE_COMM_ACTION_INIT      = 0x01,
    WH_MESSAGE_COMM_ACTION_KEEPALIVE = 0x02,
    WH_MESSAGE_COMM_ACTION_CLOSE     = 0x03,
    WH_MESSAGE_COMM_ACTION_INFO      = 0x04,
    WH_MESSAGE_COMM_ACTION_ECHO      = 0x05,
};


/* Generic error response message. */
typedef struct {
    int return_code;
} whMessageComm_ErrorResponse;

int wh_MessageComm_GetErrorResponse(uint16_t magic,
        const void* data,
        int *out_return_code);


/* Generic len/data message that does not require data translation */
typedef struct {
    uint16_t len;
    uint8_t data[WH_COMM_DATA_LEN - sizeof(uint16_t)];
} whMessageCommLenData;

int wh_MessageComm_TranslateLenData(uint16_t magic,
        const whMessageCommLenData* src,
        whMessageCommLenData* dest);

typedef struct {
    uint32_t client_id;
} whMessageCommInitRequest;

int wh_MessageComm_TranslateInitRequest(uint16_t magic,
        const whMessageCommInitRequest* src,
        whMessageCommInitRequest* dest);


typedef struct {
    uint32_t client_id;
    uint32_t server_id;
} whMessageCommInitResponse;

int wh_MessageComm_TranslateInitRequest(uint16_t magic,
        const whMessageCommInitRequest* src,
        whMessageCommInitRequest* dest);

/* Info request/response data */
enum {
    WOLFHSM_INFO_VERSION_LEN = 8,
    WOLFHSM_INFO_BUILD_LEN   = 8,
};

typedef struct {
    uint8_t version[WOLFHSM_INFO_VERSION_LEN];
    uint8_t build[WOLFHSM_INFO_BUILD_LEN];
    uint32_t ramfree;
    uint32_t nvmfree;
    uint8_t debug_state;
    uint8_t boot_state;
    uint8_t lifecycle_state;
    uint8_t nvm_state;
} whMessageCommInfo;

#endif /* WOLFHSM_WH_MESSAGE_COMM_H_ */
