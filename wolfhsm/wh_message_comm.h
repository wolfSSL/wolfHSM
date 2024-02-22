/*
 * wolfhsm/message_comm.h
 *
 */

#ifndef WOLFHSM_WH_MESSAGE_COMM_H_
#define WOLFHSM_WH_MESSAGE_COMM_H_

#include <stdint.h>

#include "wolfhsm/wh_message.h"

enum {
    WOLFHSM_MESSAGE_TYPE_COMM_NONE      = WOLFHSM_MESSAGE_GROUP_COMM + 0x00,
    WOLFHSM_MESSAGE_TYPE_COMM_INIT      = WOLFHSM_MESSAGE_GROUP_COMM + 0x01,
    WOLFHSM_MESSAGE_TYPE_COMM_KEEPALIVE = WOLFHSM_MESSAGE_GROUP_COMM + 0x02,
    WOLFHSM_MESSAGE_TYPE_COMM_CLOSE     = WOLFHSM_MESSAGE_GROUP_COMM + 0x03,
    WOLFHSM_MESSAGE_TYPE_COMM_INFO      = WOLFHSM_MESSAGE_GROUP_COMM + 0x04,
    WOLFHSM_MESSAGE_TYPE_COMM_ECHO      = WOLFHSM_MESSAGE_GROUP_COMM + 0x05,
};

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

/* Generic len/data message that does not require data translation */
typedef struct {
    uint16_t len;
    uint8_t data[WOLFHSM_COMM_DATA_LEN - sizeof(uint16_t)];
} whMessageCommLenData;

int wh_MessageComm_TranslateLenData(uint16_t magic,
        const whMessageCommLenData* src,
        whMessageCommLenData* dest);


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
