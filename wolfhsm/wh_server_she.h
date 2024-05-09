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
#ifndef WOLFHSM_WH_SERVER_SHE_H
#define WOLFHSM_WH_SERVER_SHE_H
#include "wolfhsm/wh_server.h"

enum WOLFHSM_SHE_SUBTYPE {
    WOLFHSM_SHE_SECURE_BOOT_INIT,
    WOLFHSM_SHE_SECURE_BOOT_UPDATE,
    WOLFHSM_SHE_SECURE_BOOT_FINISH,
    WOLFHSM_SHE_GET_STATUS,
    WOLFHSM_SHE_LOAD_KEY,
    WOLFHSM_SHE_EXPORT_RAM_KEY,
    WOLFHSM_SHE_INIT_RNG,
    WOLFHSM_SHE_RND,
    WOLFHSM_SHE_EXTEND_SEED,
};

typedef struct {
    uint32_t count;
    uint32_t flags;
} whSheMetadata;

int wh_Server_HandleSheRequest(whServerContext* server,
    uint16_t action, uint8_t* data, uint16_t* size);
#endif
