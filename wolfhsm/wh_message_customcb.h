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
 * wolfhsm/wh_message_customcb.h
 *
 */
#ifndef WOLFHSM_WH_MESSAGE_CUSTOM_CB_H_
#define WOLFHSM_WH_MESSAGE_CUSTOM_CB_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

/* Type indicator for custom request/response messages. Indicates how
 * to interpret whMessageCustomData */
typedef enum {
    /* message types reserved for internal usage*/
    WH_MESSAGE_CUSTOM_CB_TYPE_QUERY      = 0,
    WH_MESSAGE_CUSTOM_CB_TYPE_DMA32      = 1,
    WH_MESSAGE_CUSTOM_CB_TYPE_DMA64      = 2,
    WH_MESSAGE_CUSTOM_CB_TYPE_RESERVED_3 = 3,
    WH_MESSAGE_CUSTOM_CB_TYPE_RESERVED_4 = 4,
    WH_MESSAGE_CUSTOM_CB_TYPE_RESERVED_5 = 5,
    WH_MESSAGE_CUSTOM_CB_TYPE_RESERVED_6 = 6,
    WH_MESSAGE_CUSTOM_CB_TYPE_RESERVED_7 = 7,
    /* User-defined types start from here, up to UINT32_MAX */
    WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START = 8,
} whMessageCustomCb_Type;


/* union providing some helpful abstractions for passing pointers in/out of
 * custom callbacks on top of a raw data buffer */
typedef union {
    /* pointer/size pairs for 32-bit systems */
    struct {
        uint32_t client_addr;
        uint32_t client_sz;
        uint32_t server_addr;
        uint32_t server_sz;
    } dma32;
    /* pointer/size pairs for 64-bit systems */
    struct {
        uint64_t client_addr;
        uint64_t client_sz;
        uint64_t server_addr;
        uint64_t server_sz;
    } dma64;
    /* raw data buffer for user-defined schema */
    struct {
        uint8_t data[WOLFHSM_CFG_CUSTOMCB_LEN];
    } buffer;
} whMessageCustomCb_Data;

/* request message to the custom server callback */
typedef struct {
    uint32_t               id;   /* indentifier of registered callback  */
    uint32_t               type; /* whMessageCustomCb_Type */
    whMessageCustomCb_Data data;
} whMessageCustomCb_Request;

/* response message from the custom server callback */
typedef struct {
    uint32_t id;   /* indentifier of registered callback  */
    uint32_t type; /* whMessageCustomCb_Type */
    int32_t  rc;   /* Return code from custom callback. Invalid if err != 0 */
    int32_t  err;  /* wolfHSM-specific error. If err != 0, rc is invalid */
    whMessageCustomCb_Data data;
} whMessageCustomCb_Response;


/* Translates a custom request message. The whMessageCustomCb_Request.data field
 * will not be translated for whMessageCustomCb_Request.type values greater than
 * WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START */
int wh_MessageCustomCb_TranslateRequest(uint16_t                         magic,
                                        const whMessageCustomCb_Request* src,
                                        whMessageCustomCb_Request*       dst);

/* Translates a custom response message. The whMessageCustomCb_Request.data
 * field will not be translated for whMessageCustomCb_Request.type values
 * greater than WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START */
int wh_MessageCustomCb_TranslateResponse(uint16_t magic,
                                         const whMessageCustomCb_Response* src,
                                         whMessageCustomCb_Response*       dst);

#endif /* !WOLFHSM_WH_MESSAGE_CUSTOM_CB_H_*/
