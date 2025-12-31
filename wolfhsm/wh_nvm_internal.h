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
 * wolfhsm/wh_nvm_internal.h
 *
 * Additional NVM helper API for internal library use only
 *
 */

#ifndef WOLFHSM_WH_NVM_INTERNAL_H_
#define WOLFHSM_WH_NVM_INTERNAL_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_nvm.h"

#include <stdint.h>

#ifdef WOLFHSM_CFG_THREADSAFE
/*
 * Internal unlocked NVM functions. Same functionality as their public
 * counterparts but assume the caller already holds context->lock and do NOT
 * attempt to aquire the lock. For use by server keystore internals when
 * performing atomic multi-step operations.
 */

int wh_Nvm_GetMetadataUnlocked(whNvmContext* context, whNvmId id,
                               whNvmMetadata* meta);

int wh_Nvm_ReadUnlocked(whNvmContext* context, whNvmId id, whNvmSize offset,
                        whNvmSize data_len, uint8_t* data);

int wh_Nvm_AddObjectWithReclaimUnlocked(whNvmContext*  context,
                                        whNvmMetadata* meta, whNvmSize dataLen,
                                        const uint8_t* data);

int wh_Nvm_DestroyObjectsUnlocked(whNvmContext* context, whNvmId list_count,
                                  const whNvmId* id_list);

int wh_Nvm_AddObjectCheckedUnlocked(whNvmContext* context, whNvmMetadata* meta,
                                    whNvmSize data_len, const uint8_t* data);

int wh_Nvm_DestroyObjectsCheckedUnlocked(whNvmContext*  context,
                                         whNvmId        list_count,
                                         const whNvmId* id_list);

int wh_Nvm_ReadCheckedUnlocked(whNvmContext* context, whNvmId id,
                               whNvmSize offset, whNvmSize data_len,
                               uint8_t* data);
#else

/*
 * When THREADSAFE is not defined, unlocked functions map to regular ones.
 * This allows keystore code to always use unlocked variants without
 * conditional compilation.
 */
#define wh_Nvm_GetMetadataUnlocked(ctx, id, meta) \
    wh_Nvm_GetMetadata((ctx), (id), (meta))
#define wh_Nvm_ReadUnlocked(ctx, id, off, len, data) \
    wh_Nvm_Read((ctx), (id), (off), (len), (data))
#define wh_Nvm_AddObjectWithReclaimUnlocked(ctx, meta, len, data) \
    wh_Nvm_AddObjectWithReclaim((ctx), (meta), (len), (data))
#define wh_Nvm_DestroyObjectsUnlocked(ctx, cnt, list) \
    wh_Nvm_DestroyObjects((ctx), (cnt), (list))
#define wh_Nvm_AddObjectCheckedUnlocked(ctx, meta, len, data) \
    wh_Nvm_AddObjectChecked((ctx), (meta), (len), (data))
#define wh_Nvm_DestroyObjectsCheckedUnlocked(ctx, cnt, list) \
    wh_Nvm_DestroyObjectsChecked((ctx), (cnt), (list))
#define wh_Nvm_ReadCheckedUnlocked(ctx, id, off, len, data) \
    wh_Nvm_ReadChecked((ctx), (id), (off), (len), (data))

#endif


#endif /* !WOLFHSM_WH_NVM_INTERNAL_H_ */
