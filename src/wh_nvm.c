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
 * src/wh_nvm.c
 *
 */

#include <stdint.h>
#include <stddef.h>     /* For NULL */
#include <string.h>     /* For memset, memcpy */

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_nvm.h"


int wh_Nvm_Init(whNvmContext* context, const whNvmConfig *config)
{
    int rc = 0;

    if (    (context == NULL) ||
            (config == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    context->cb = config->cb;
    context->context = config->context;

    if (context->cb->Init != NULL) {
        rc = context->cb->Init(context->context, config->config);
        if (rc != 0) {
            context->cb = NULL;
            context->context = NULL;
        }
    }

    return rc;
}

int wh_Nvm_Cleanup(whNvmContext* context)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callback? Return ABORTED */
    if (context->cb->Cleanup == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->Cleanup(context->context);
}

int wh_Nvm_GetAvailable(whNvmContext* context,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callback? Return ABORTED */
    if (context->cb->GetAvailable == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->GetAvailable(context->context,
            out_avail_size, out_avail_objects,
            out_reclaim_size, out_reclaim_objects);
}

int wh_Nvm_AddObjectWithReclaim(whNvmContext* context, whNvmMetadata *meta,
    whNvmSize dataLen, const uint8_t* data)
{
    int ret;
    uint32_t availableSize;
    uint32_t reclaimSize;
    uint16_t availableObjects;
    uint16_t reclaimObjects;

    /* Note that meta and data pointers are validated by AddObject later */
    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* check if we have available object and data space */
    ret = wh_Nvm_GetAvailable(context,
            &availableSize, &availableObjects,
            &reclaimSize, &reclaimObjects);
    if (ret == 0) {
        if (    (availableSize < dataLen) ||
                (availableObjects == 0) ) {
            /* There's no available space, so try to reclaim space, */
            if  (   (availableSize + reclaimSize >= dataLen) &&
                    (availableObjects + reclaimObjects > 0) ) {
                /* Reclaim will make sufficient space available */
                ret = wh_Nvm_DestroyObjects(context, 0, NULL);
            } else {
                /* Reclaim witl not help */
                ret = WH_ERROR_NOSPACE;
            }
        }
    }
    if (ret == 0) {
        ret = wh_Nvm_AddObject(context, meta, dataLen, data);
    }
    return ret;
}

int wh_Nvm_AddObject(whNvmContext* context, whNvmMetadata *meta,
        whNvmSize data_len, const uint8_t* data)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callback? Return ABORTED */
    if (context->cb->AddObject == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->AddObject(context->context, meta, data_len, data);
}

int wh_Nvm_List(whNvmContext* context,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        whNvmId *out_count, whNvmId *out_id)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callback? Return ABORTED */
    if (context->cb->List == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->List(context->context, access, flags, start_id,
            out_count, out_id);
}

int wh_Nvm_GetMetadata(whNvmContext* context, whNvmId id,
        whNvmMetadata* meta)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callback? Return ABORTED */
    if (context->cb->GetMetadata == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->GetMetadata(context->context, id, meta);
}


int wh_Nvm_DestroyObjects(whNvmContext* context, whNvmId list_count,
        const whNvmId* id_list)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callback? Return ABORTED */
    if (context->cb->DestroyObjects == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->DestroyObjects(context->context, list_count, id_list);
}


int wh_Nvm_Read(whNvmContext* context, whNvmId id, whNvmSize offset,
        whNvmSize data_len, uint8_t* data)
{
    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

    /* No callcack? Return ABORTED */
    if (context->cb->Read == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->Read(context->context, id, offset, data_len, data);
}

