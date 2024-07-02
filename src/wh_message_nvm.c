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
 * src/wh_message_nvm.c
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"

#include "wolfhsm/wh_message_nvm.h"


int wh_MessageNvm_TranslateSimpleResponse(uint16_t magic,
        const whMessageNvm_SimpleResponse* src,
        whMessageNvm_SimpleResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

int wh_MessageNvm_TranslateInitRequest(uint16_t magic,
        const whMessageNvm_InitRequest* src,
        whMessageNvm_InitRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, clientnvm_id);
    return 0;
}

int wh_MessageNvm_TranslateInitResponse(uint16_t magic,
        const whMessageNvm_InitResponse* src,
        whMessageNvm_InitResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, clientnvm_id);
    WH_T32(magic, dest, src, servernvm_id);
    return 0;
}

int wh_MessageNvm_TranslateListRequest(uint16_t magic,
        const whMessageNvm_ListRequest* src,
        whMessageNvm_ListRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T16(magic, dest, src, startId);
    return 0;
}

int wh_MessageNvm_TranslateListResponse(uint16_t magic,
        const whMessageNvm_ListResponse* src,
        whMessageNvm_ListResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, count);
    WH_T16(magic, dest, src, id);
    return 0;
}

int wh_MessageNvm_TranslateGetAvailableResponse(uint16_t magic,
        const whMessageNvm_GetAvailableResponse* src,
        whMessageNvm_GetAvailableResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, avail_size);
    WH_T32(magic, dest, src, reclaim_size);
    WH_T16(magic, dest, src, avail_objects);
    WH_T16(magic, dest, src, reclaim_objects);
    return 0;
}

int wh_MessageNvm_TranslateGetMetadataRequest(uint16_t magic,
        const whMessageNvm_GetMetadataRequest* src,
        whMessageNvm_GetMetadataRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    return 0;
}

int wh_MessageNvm_TranslateGetMetadataResponse(uint16_t magic,
        const whMessageNvm_GetMetadataResponse* src,
        whMessageNvm_GetMetadataResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T16(magic, dest, src, len);
    memcpy(dest->label, src->label, sizeof(dest->label));
    return 0;
}

int wh_MessageNvm_TranslateAddObjectRequest(uint16_t magic,
        const whMessageNvm_AddObjectRequest* src,
        whMessageNvm_AddObjectRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, access);
    WH_T16(magic, dest, src, flags);
    WH_T16(magic, dest, src, len);
    memcpy(dest->label, src->label, sizeof(dest->label));
    return 0;
}

int wh_MessageNvm_TranslateDestroyObjectsRequest(uint16_t magic,
        const whMessageNvm_DestroyObjectsRequest* src,
        whMessageNvm_DestroyObjectsRequest* dest)
{
    int counter = 0;
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, list_count);
    for (counter = 0; counter < WH_MESSAGE_NVM_MAX_DESTROY_OBJECTS_COUNT; counter++) {
        WH_T16(magic, dest, src, list[counter]);
    }
    return 0;
}

int wh_MessageNvm_TranslateReadRequest(uint16_t magic,
        const whMessageNvm_ReadRequest* src,
        whMessageNvm_ReadRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, offset);
    WH_T16(magic, dest, src, data_len);
    return 0;
}

int wh_MessageNvm_TranslateReadResponse(uint16_t magic,
        const whMessageNvm_ReadResponse* src,
        whMessageNvm_ReadResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

int wh_MessageNvm_TranslateAddObjectDma32Request(uint16_t magic,
        const whMessageNvm_AddObjectDma32Request* src,
        whMessageNvm_AddObjectDma32Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, metadata_hostaddr);
    WH_T32(magic, dest, src, data_hostaddr);
    WH_T16(magic, dest, src, data_len);
    return 0;
}

int wh_MessageNvm_TranslateReadDma32Request(uint16_t magic,
        const whMessageNvm_ReadDma32Request* src,
        whMessageNvm_ReadDma32Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, data_hostaddr);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, offset);
    WH_T16(magic, dest, src, data_len);
    return 0;
}

int wh_MessageNvm_TranslateAddObjectDma64Request(uint16_t magic,
        const whMessageNvm_AddObjectDma64Request* src,
        whMessageNvm_AddObjectDma64Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, metadata_hostaddr);
    WH_T64(magic, dest, src, data_hostaddr);
    WH_T16(magic, dest, src, data_len);
    return 0;
}

int wh_MessageNvm_TranslateReadDma64Request(uint16_t magic,
        const whMessageNvm_ReadDma64Request* src,
        whMessageNvm_ReadDma64Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, data_hostaddr);
    WH_T16(magic, dest, src, id);
    WH_T16(magic, dest, src, offset);
    WH_T16(magic, dest, src, data_len);
    return 0;
}
