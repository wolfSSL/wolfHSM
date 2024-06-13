/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * wolfhsm/wh_message_comm.h
 *
 * Comm component message action enumerations and definitions.
 *
 */

#ifndef WOLFHSM_WH_MESSAGE_COMM_H_
#define WOLFHSM_WH_MESSAGE_COMM_H_

#include <stdint.h>
#include "wolfhsm/wh_comm.h"

/* Comm component message kinds */
enum WH_MESSAGE_COMM_ACTION_ENUM {
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

int wh_MessageComm_TranslateInitResponse(uint16_t magic,
        const whMessageCommInitResponse* src,
        whMessageCommInitResponse* dest);

/* Info request/response data */
enum WOLFHSM_INFO_ENUM {
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
