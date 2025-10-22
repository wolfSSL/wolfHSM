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
 * wolfhsm/wh_server_cache.h
 *
 * Exists as a separate header so it can be consumed by server, server keystore, and NVM
 * layer without creating circular dependencies
 */

#ifndef WOLFHSM_WH_SERVER_CACHE_H_
#define WOLFHSM_WH_SERVER_CACHE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_common.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/** Server cache slot structures */
typedef struct whServerCacheSlot {
    uint8_t       committed;
    whNvmMetadata meta[1];
    uint8_t       buffer[WOLFHSM_CFG_SERVER_KEYCACHE_BUFSIZE];
} whServerCacheSlot;

typedef struct whServerBigCacheSlot {
    uint8_t       committed;
    whNvmMetadata meta[1];
    uint8_t       buffer[WOLFHSM_CFG_SERVER_KEYCACHE_BIG_BUFSIZE];
} whServerBigCacheSlot;

/**
 * @brief Unified key cache context
 *
 * Holds both regular and big cache arrays. Used for client-local caches
 * (embedded in whServerContext) and global caches (embedded in whNvmContext
 * when WOLFHSM_CFG_GLOBAL_KEYS is enabled).
 */
typedef struct whKeyCacheContext_t {
    whServerCacheSlot    cache[WOLFHSM_CFG_SERVER_KEYCACHE_COUNT];
    whServerBigCacheSlot bigCache[WOLFHSM_CFG_SERVER_KEYCACHE_BIG_COUNT];
} whKeyCacheContext;

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* !WOLFHSM_WH_SERVER_CACHE_H_ */
