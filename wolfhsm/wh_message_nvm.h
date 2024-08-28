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
 * wolfhsm/wh_message_nvm.h
 *
 */

#ifndef WOLFHSM_WH_MESSAGE_NVM_H_
#define WOLFHSM_WH_MESSAGE_NVM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_nvm.h"

enum WH_MESSAGE_NVM_ACTION_ENUM {
    WH_MESSAGE_NVM_ACTION_INIT              = 0x1,
    WH_MESSAGE_NVM_ACTION_CLEANUP           = 0x2,
    WH_MESSAGE_NVM_ACTION_GETAVAILABLE      = 0x3,
    WH_MESSAGE_NVM_ACTION_ADDOBJECT         = 0x4,
    WH_MESSAGE_NVM_ACTION_LIST              = 0x5,
    WH_MESSAGE_NVM_ACTION_GETMETADATA       = 0x6,
    WH_MESSAGE_NVM_ACTION_DESTROYOBJECTS    = 0x7,
    WH_MESSAGE_NVM_ACTION_READ              = 0x8,
    WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA32    = 0x14,
    WH_MESSAGE_NVM_ACTION_READDMA32         = 0x18,
    WH_MESSAGE_NVM_ACTION_ADDOBJECTDMA64    = 0x24,
    WH_MESSAGE_NVM_ACTION_READDMA64         = 0x28,
};

enum WH_MESSAGE_NVM_MAX_ENUM {
    /* must be odd for struct whMessageNvm_DestroyObjectsRequest  alignment */
    WH_MESSAGE_NVM_MAX_DESTROY_OBJECTS_COUNT = 19,
    WH_MESSAGE_NVM_MAX_ADDOBJECT_LEN = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(whNvmMetadata),
    WH_MESSAGE_NVM_MAX_READ_LEN = WOLFHSM_CFG_COMM_DATA_LEN - sizeof(int32_t),
};

/* Simple reusable response message */
typedef struct {
    int32_t rc;
} whMessageNvm_SimpleResponse;

int wh_MessageNvm_TranslateSimpleResponse(uint16_t magic,
        const whMessageNvm_SimpleResponse* src,
        whMessageNvm_SimpleResponse* dest);

/** NVM Init Request */
typedef struct {
    uint32_t clientnvm_id;
} whMessageNvm_InitRequest;

int wh_MessageNvm_TranslateInitRequest(uint16_t magic,
        const whMessageNvm_InitRequest* src,
        whMessageNvm_InitRequest* dest);

/** NVM Init Response */
typedef struct {
    int32_t rc;
    uint32_t servernvm_id;
    uint32_t clientnvm_id;
} whMessageNvm_InitResponse;

int wh_MessageNvm_TranslateInitResponse(uint16_t magic,
        const whMessageNvm_InitResponse* src,
        whMessageNvm_InitResponse* dest);

/** NVM Cleanup Request */
/* Empty message */

/** NVM Cleanup Response */
/* Use SimpleResponse */

/** NVM GetAvailable Request */
/* Empty message */

/** NVM GetAvailable Response */
typedef struct {
    int32_t rc;
    uint32_t avail_size;
    uint32_t reclaim_size;
    uint16_t avail_objects;
    uint16_t reclaim_objects;
} whMessageNvm_GetAvailableResponse;

int wh_MessageNvm_TranslateGetAvailableResponse(uint16_t magic,
        const whMessageNvm_GetAvailableResponse* src,
        whMessageNvm_GetAvailableResponse* dest);

/** NVM AddObject Request */
typedef struct {
    uint16_t id;
    uint16_t access;
    uint16_t flags;
    uint16_t len;
    uint8_t label[WH_NVM_LABEL_LEN];
    /* Data up to WH_MESSAGE_NVM_MAX_ADDOBJECT_LEN follows */
} whMessageNvm_AddObjectRequest;

int wh_MessageNvm_TranslateAddObjectRequest(uint16_t magic,
        const whMessageNvm_AddObjectRequest* src,
        whMessageNvm_AddObjectRequest* dest);

/** NVM AddObject Response */
/* Use SimpleResponse */

/** NVM List Request */
typedef struct {
    uint16_t access;
    uint16_t flags;
    uint16_t startId;
} whMessageNvm_ListRequest;

int wh_MessageNvm_TranslateListRequest(uint16_t magic,
        const whMessageNvm_ListRequest* src,
        whMessageNvm_ListRequest* dest);

/** NVM List Response */
typedef struct {
    int32_t rc;
    uint16_t count;
    uint16_t id;
} whMessageNvm_ListResponse;

int wh_MessageNvm_TranslateListResponse(uint16_t magic,
        const whMessageNvm_ListResponse* src,
        whMessageNvm_ListResponse* dest);

/** NVM GetMetadata Request */
typedef struct {
    uint16_t id;
} whMessageNvm_GetMetadataRequest;

int wh_MessageNvm_TranslateGetMetadataRequest(uint16_t magic,
        const whMessageNvm_GetMetadataRequest* src,
        whMessageNvm_GetMetadataRequest* dest);

/** NVM GetMetadata Response */
typedef struct {
    int32_t rc;
    uint16_t id;
    uint16_t access;
    uint16_t flags;
    uint16_t len;
    uint8_t label[WH_NVM_LABEL_LEN];
} whMessageNvm_GetMetadataResponse;

int wh_MessageNvm_TranslateGetMetadataResponse(uint16_t magic,
        const whMessageNvm_GetMetadataResponse* src,
        whMessageNvm_GetMetadataResponse* dest);

/** NVM DestroyObjects Request */
typedef struct {
    uint16_t list_count;
    uint16_t list[WH_MESSAGE_NVM_MAX_DESTROY_OBJECTS_COUNT];
} whMessageNvm_DestroyObjectsRequest;

int wh_MessageNvm_TranslateDestroyObjectsRequest(uint16_t magic,
        const whMessageNvm_DestroyObjectsRequest* src,
        whMessageNvm_DestroyObjectsRequest* dest);

/** NVM DestroyObjects Response */
/* Use SimpleResponse */

/** NVM Read Request */
typedef struct {
    uint16_t id;
    uint16_t offset;
    uint16_t data_len;
} whMessageNvm_ReadRequest;

int wh_MessageNvm_TranslateReadRequest(uint16_t magic,
        const whMessageNvm_ReadRequest* src,
        whMessageNvm_ReadRequest* dest);

/** NVM Read Response */
typedef struct {
    int32_t rc;
    /* Data up to WH_MESSAGE_NVM_MAX_READ_LEN follows */
} whMessageNvm_ReadResponse;

int wh_MessageNvm_TranslateReadResponse(uint16_t magic,
        const whMessageNvm_ReadResponse* src,
        whMessageNvm_ReadResponse* dest);

#ifdef WOLFHSM_CFG_DMA
#if WH_DMA_IS_32BIT
/** NVM AddObjectDma32 Request */
typedef struct {
    uint32_t metadata_hostaddr;
    uint32_t data_hostaddr;
    uint16_t data_len;
    uint8_t WH_PAD[6];
} whMessageNvm_AddObjectDma32Request;

int wh_MessageNvm_TranslateAddObjectDma32Request(uint16_t magic,
        const whMessageNvm_AddObjectDma32Request* src,
        whMessageNvm_AddObjectDma32Request* dest);

/** NVM AddObjectDma32 Response */
/* Use SimpleResponse */

/** NVM ReadDma32 Request */
typedef struct {
    uint32_t data_hostaddr;
    uint16_t id;
    uint16_t offset;
    uint16_t data_len;
    uint8_t WH_PAD[6];
} whMessageNvm_ReadDma32Request;

int wh_MessageNvm_TranslateReadDma32Request(uint16_t magic,
        const whMessageNvm_ReadDma32Request* src,
        whMessageNvm_ReadDma32Request* dest);

/** NVM ReadDma32 Response */
/* Use SimpleResponse */
#endif /* WH_DMA_IS_32BIT */

#if WH_DMA_IS_64BIT
/** NVM AddObjectDma64 Request */
typedef struct {
    uint64_t metadata_hostaddr;
    uint64_t data_hostaddr;
    uint16_t data_len;
    uint8_t WH_PAD[6];
} whMessageNvm_AddObjectDma64Request;

int wh_MessageNvm_TranslateAddObjectDma64Request(uint16_t magic,
        const whMessageNvm_AddObjectDma64Request* src,
        whMessageNvm_AddObjectDma64Request* dest);

/** NVM AddObjectDma64 Response */
/* Use SimpleResponse */

/** NVM ReadDma64 Request */
typedef struct {
    uint64_t data_hostaddr;
    uint16_t id;
    uint16_t offset;
    uint16_t data_len;
    uint8_t WH_PAD[2];
} whMessageNvm_ReadDma64Request;

int wh_MessageNvm_TranslateReadDma64Request(uint16_t magic,
        const whMessageNvm_ReadDma64Request* src,
        whMessageNvm_ReadDma64Request* dest);

/** NVM ReadDma64 Response */
/* Use SimpleResponse */
#endif /* WH_DMA_IS_64BIT */
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_WH_MESSAGE_NVM_H_ */
