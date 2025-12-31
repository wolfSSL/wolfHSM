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

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>     /* For NULL */
#include <string.h>     /* For memset, memcpy */

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"

#include "wolfhsm/wh_nvm.h"

#ifdef WOLFHSM_CFG_THREADSAFE
/* Helper functions for NVM locking */
static int _LockNvm(whNvmContext* context)
{
    return wh_Lock_Acquire(&context->lock);
}

static int _UnlockNvm(whNvmContext* context)
{
    return wh_Lock_Release(&context->lock);
}
#else
#define _LockNvm(context) (WH_ERROR_OK)
#define _UnlockNvm(context) (WH_ERROR_OK)
#endif /* WOLFHSM_CFG_THREADSAFE */

/*
 * Internal unlocked callback helpers.
 * These call the NVM callbacks directly without acquiring locks.
 * Callers MUST hold the NVM lock when using these functions.
 */
static int _GetAvailableUnlocked(whNvmContext* context,
                                 uint32_t*     out_avail_size,
                                 whNvmId*      out_avail_objects,
                                 uint32_t*     out_reclaim_size,
                                 whNvmId*      out_reclaim_objects)
{
    if (context->cb->GetAvailable == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->GetAvailable(context->context, out_avail_size,
                                     out_avail_objects, out_reclaim_size,
                                     out_reclaim_objects);
}

static int _DestroyObjectsUnlocked(whNvmContext* context, whNvmId list_count,
                                   const whNvmId* id_list)
{
    if (context->cb->DestroyObjects == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->DestroyObjects(context->context, list_count, id_list);
}

static int _AddObjectUnlocked(whNvmContext* context, whNvmMetadata* meta,
                              whNvmSize data_len, const uint8_t* data)
{
    if (context->cb->AddObject == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->AddObject(context->context, meta, data_len, data);
}

static int _ListUnlocked(whNvmContext* context, whNvmAccess access,
                         whNvmFlags flags, whNvmId start_id, whNvmId* out_count,
                         whNvmId* out_id)
{
    if (context->cb->List == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->List(context->context, access, flags, start_id,
                             out_count, out_id);
}

static int _GetMetadataUnlocked(whNvmContext* context, whNvmId id,
                                whNvmMetadata* meta)
{
    if (context->cb->GetMetadata == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->GetMetadata(context->context, id, meta);
}

static int _ReadUnlocked(whNvmContext* context, whNvmId id, whNvmSize offset,
                         whNvmSize data_len, uint8_t* data)
{
    if (context->cb->Read == NULL) {
        return WH_ERROR_ABORTED;
    }
    return context->cb->Read(context->context, id, offset, data_len, data);
}

typedef enum {
    WH_NVM_OP_ADD = 0,
    WH_NVM_OP_READ,
    WH_NVM_OP_DESTROY,
} whNvmOp;

static int wh_Nvm_CheckPolicyUnlocked(whNvmContext* context, whNvmOp op,
                                      whNvmId id, whNvmMetadata* existing_meta)
{
    whNvmMetadata meta;
    int           ret;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _GetMetadataUnlocked(context, id, &meta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (existing_meta != NULL) {
        *existing_meta = meta;
    }

    switch (op) {
        case WH_NVM_OP_ADD:
            if (meta.flags & WH_NVM_FLAGS_NONMODIFIABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_NVM_OP_DESTROY:
            if (meta.flags &
                (WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONDESTROYABLE)) {
                return WH_ERROR_ACCESS;
            }
            break;

        case WH_NVM_OP_READ:
            if (meta.flags & WH_NVM_FLAGS_NONEXPORTABLE) {
                return WH_ERROR_ACCESS;
            }
            break;

        default:
            return WH_ERROR_BADARGS;
    }

    return WH_ERROR_OK;
}

static int _Nvm_AddObjectCheckedUnlocked(whNvmContext*  context,
                                         whNvmMetadata* meta,
                                         whNvmSize      data_len,
                                         const uint8_t* data)
{
    int ret;

    ret = wh_Nvm_CheckPolicyUnlocked(context, WH_NVM_OP_ADD, meta->id, NULL);
    if (ret != WH_ERROR_OK && ret != WH_ERROR_NOTFOUND) {
        return ret;
    }

    return _AddObjectUnlocked(context, meta, data_len, data);
}

static int _Nvm_DestroyObjectsCheckedUnlocked(whNvmContext*  context,
                                              whNvmId        list_count,
                                              const whNvmId* id_list)
{
    whNvmId i;
    int     ret;

    if (id_list == NULL && list_count != 0) {
        return WH_ERROR_BADARGS;
    }

    for (i = 0; i < list_count; i++) {
        ret = wh_Nvm_CheckPolicyUnlocked(context, WH_NVM_OP_DESTROY, id_list[i],
                                         NULL);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    return _DestroyObjectsUnlocked(context, list_count, id_list);
}

static int _Nvm_ReadCheckedUnlocked(whNvmContext* context, whNvmId id,
                                    whNvmSize offset, whNvmSize data_len,
                                    uint8_t* data)
{
    int ret;

    ret = wh_Nvm_CheckPolicyUnlocked(context, WH_NVM_OP_READ, id, NULL);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    return _ReadUnlocked(context, id, offset, data_len, data);
}

int wh_Nvm_Init(whNvmContext* context, const whNvmConfig* config)
{
    int rc = 0;

    if ((context == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));

    context->cb      = config->cb;
    context->context = config->context;

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_GLOBAL_KEYS)
    /* Initialize the global key cache */
    memset(&context->globalCache, 0, sizeof(context->globalCache));
#endif

#ifdef WOLFHSM_CFG_THREADSAFE
    /* Initialize lock (NULL lockConfig = no-op locking) */
    rc = wh_Lock_Init(&context->lock, config->lockConfig);
    if (rc != WH_ERROR_OK) {
        context->cb      = NULL;
        context->context = NULL;
        return rc;
    }
#endif

    if (context->cb != NULL && context->cb->Init != NULL) {
        rc = context->cb->Init(context->context, config->config);
        if (rc != 0) {
#ifdef WOLFHSM_CFG_THREADSAFE
            wh_Lock_Cleanup(&context->lock);
#endif
            context->cb = NULL;
            context->context = NULL;
        }
    }

    return rc;
}

int wh_Nvm_Cleanup(whNvmContext* context)
{
    int rc;

    if (    (context == NULL) ||
            (context->cb == NULL) ) {
        return WH_ERROR_BADARGS;
    }

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_GLOBAL_KEYS)
    /* Clear the global key cache */
    memset(&context->globalCache, 0, sizeof(context->globalCache));
#endif

    /* No callback? Return ABORTED */
    if (context->cb->Cleanup == NULL) {
        rc = WH_ERROR_ABORTED;
    }
    else {
        rc = context->cb->Cleanup(context->context);
    }

#ifdef WOLFHSM_CFG_THREADSAFE
    wh_Lock_Cleanup(&context->lock);
#endif

    context->cb      = NULL;
    context->context = NULL;

    return rc;
}

int wh_Nvm_GetAvailable(whNvmContext* context,
        uint32_t *out_avail_size, whNvmId *out_avail_objects,
        uint32_t *out_reclaim_size, whNvmId *out_reclaim_objects)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = _LockNvm(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = _GetAvailableUnlocked(context, out_avail_size, out_avail_objects,
                               out_reclaim_size, out_reclaim_objects);

    (void)_UnlockNvm(context);

    return rc;
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
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockNvm(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* check if we have available object and data space */
    ret = _GetAvailableUnlocked(context, &availableSize, &availableObjects,
                                &reclaimSize, &reclaimObjects);
    if (ret == 0) {
        if (    (availableSize < dataLen) ||
                (availableObjects == 0) ) {
            /* There's no available space, so try to reclaim space, */
            if  (   (availableSize + reclaimSize >= dataLen) &&
                    (availableObjects + reclaimObjects > 0) ) {
                /* Reclaim will make sufficient space available */
                ret = _DestroyObjectsUnlocked(context, 0, NULL);
            } else {
                /* Reclaim will not help */
                ret = WH_ERROR_NOSPACE;
            }
        }
    }
    if (ret == 0) {
        ret = _AddObjectUnlocked(context, meta, dataLen, data);
    }

    (void)_UnlockNvm(context);

    return ret;
}

int wh_Nvm_AddObject(whNvmContext* context, whNvmMetadata *meta,
        whNvmSize data_len, const uint8_t* data)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = _LockNvm(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = _AddObjectUnlocked(context, meta, data_len, data);

    (void)_UnlockNvm(context);

    return rc;
}

int wh_Nvm_AddObjectChecked(whNvmContext* context, whNvmMetadata* meta,
                            whNvmSize data_len, const uint8_t* data)
{
    int ret;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockNvm(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _Nvm_AddObjectCheckedUnlocked(context, meta, data_len, data);

    (void)_UnlockNvm(context);

    return ret;
}

int wh_Nvm_List(whNvmContext* context,
        whNvmAccess access, whNvmFlags flags, whNvmId start_id,
        whNvmId *out_count, whNvmId *out_id)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = _LockNvm(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = _ListUnlocked(context, access, flags, start_id, out_count, out_id);

    (void)_UnlockNvm(context);

    return rc;
}

int wh_Nvm_GetMetadata(whNvmContext* context, whNvmId id,
        whNvmMetadata* meta)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = _LockNvm(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = _GetMetadataUnlocked(context, id, meta);

    (void)_UnlockNvm(context);

    return rc;
}


int wh_Nvm_DestroyObjects(whNvmContext* context, whNvmId list_count,
        const whNvmId* id_list)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = _LockNvm(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = _DestroyObjectsUnlocked(context, list_count, id_list);

    (void)_UnlockNvm(context);

    return rc;
}

int wh_Nvm_DestroyObjectsChecked(whNvmContext* context, whNvmId list_count,
                                 const whNvmId* id_list)
{
    int     ret;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockNvm(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _Nvm_DestroyObjectsCheckedUnlocked(context, list_count, id_list);

    (void)_UnlockNvm(context);

    return ret;
}


int wh_Nvm_Read(whNvmContext* context, whNvmId id, whNvmSize offset,
                whNvmSize data_len, uint8_t* data)
{
    int rc;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    rc = _LockNvm(context);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    rc = _ReadUnlocked(context, id, offset, data_len, data);

    (void)_UnlockNvm(context);

    return rc;
}

int wh_Nvm_ReadChecked(whNvmContext* context, whNvmId id, whNvmSize offset,
                       whNvmSize data_len, uint8_t* data)
{
    int ret;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _LockNvm(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _Nvm_ReadCheckedUnlocked(context, id, offset, data_len, data);

    (void)_UnlockNvm(context);

    return ret;
}


#ifdef WOLFHSM_CFG_THREADSAFE

/*
 * Library internal unlocked NVM functions. Exposes unlocked versions of NVM
 * functionality for consumption elsewhere in compound operations to prevent
 * recursive locking. These assume the caller already holds context->lock.
 *
 * If WOLFHSM_CFG_THREADSAFE is not defined, these functions are redirected
 * to their regular public-facing (locking) counterparts in wh_nvm_internal.h
 */

int wh_Nvm_GetMetadataUnlocked(whNvmContext* context, whNvmId id,
                               whNvmMetadata* meta)
{
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _GetMetadataUnlocked(context, id, meta);
}

int wh_Nvm_ReadUnlocked(whNvmContext* context, whNvmId id, whNvmSize offset,
                        whNvmSize data_len, uint8_t* data)
{
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _ReadUnlocked(context, id, offset, data_len, data);
}

int wh_Nvm_AddObjectWithReclaimUnlocked(whNvmContext*  context,
                                        whNvmMetadata* meta, whNvmSize dataLen,
                                        const uint8_t* data)
{
    int      ret;
    uint32_t availableSize;
    uint32_t reclaimSize;
    uint16_t availableObjects;
    uint16_t reclaimObjects;

    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Check if we have available object and data space */
    ret = _GetAvailableUnlocked(context, &availableSize, &availableObjects,
                                &reclaimSize, &reclaimObjects);
    if (ret == 0) {
        if ((availableSize < dataLen) || (availableObjects == 0)) {
            /* No available space, try to reclaim */
            if ((availableSize + reclaimSize >= dataLen) &&
                (availableObjects + reclaimObjects > 0)) {
                ret = _DestroyObjectsUnlocked(context, 0, NULL);
            }
            else {
                ret = WH_ERROR_NOSPACE;
            }
        }
    }
    if (ret == 0) {
        ret = _AddObjectUnlocked(context, meta, dataLen, data);
    }

    return ret;
}

int wh_Nvm_DestroyObjectsUnlocked(whNvmContext* context, whNvmId list_count,
                                  const whNvmId* id_list)
{
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _DestroyObjectsUnlocked(context, list_count, id_list);
}

int wh_Nvm_AddObjectCheckedUnlocked(whNvmContext* context, whNvmMetadata* meta,
                                    whNvmSize data_len, const uint8_t* data)
{
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _Nvm_AddObjectCheckedUnlocked(context, meta, data_len, data);
}

int wh_Nvm_DestroyObjectsCheckedUnlocked(whNvmContext*  context,
                                         whNvmId        list_count,
                                         const whNvmId* id_list)
{
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _Nvm_DestroyObjectsCheckedUnlocked(context, list_count, id_list);
}

int wh_Nvm_ReadCheckedUnlocked(whNvmContext* context, whNvmId id,
                               whNvmSize offset, whNvmSize data_len,
                               uint8_t* data)
{
    if ((context == NULL) || (context->cb == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _Nvm_ReadCheckedUnlocked(context, id, offset, data_len, data);
}

#endif /* WOLFHSM_CFG_THREADSAFE */
