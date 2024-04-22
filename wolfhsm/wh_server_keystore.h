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
#ifndef WOLFHSM_WH_SERVER_KEYSTORE_H
#define WOLFHSM_WH_SERVER_KEYSTORE_H

#include "wolfhsm/wh_server.h"

int hsmGetUniqueId(whServerContext* server);
int hsmCacheFindSlot(whServerContext* server);
int hsmCacheKey(whServerContext* server, whNvmMetadata* meta, uint8_t* in);
int hsmFreshenKey(whServerContext* server, whKeyId keyId);
int hsmReadKey(whServerContext* server, whKeyId keyId, whNvmMetadata* meta,
    uint8_t* out, uint32_t* outSz);
int hsmEvictKey(whServerContext* server, uint16_t keyId);
int hsmCommitKey(whServerContext* server, uint16_t keyId);
int hsmEraseKey(whServerContext* server, whNvmId keyId);
int wh_Server_HandleKeyRequest(whServerContext* server,
        uint16_t magic, uint16_t action, uint16_t seq,
        uint8_t* data, uint16_t* size);

#endif
