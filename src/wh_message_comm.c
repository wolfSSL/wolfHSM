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
 * src/wh_message_comm.c
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"

#include "wolfhsm/wh_message_comm.h"

int wh_MessageComm_TranslateInitRequest(uint16_t magic,
        const whMessageCommInitRequest* src,
        whMessageCommInitRequest* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, client_id);
    return 0;
}

int wh_MessageComm_TranslateInitResponse(uint16_t magic,
        const whMessageCommInitResponse* src,
        whMessageCommInitResponse* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, client_id);
    WH_T32(magic, dest, src, server_id);
    return 0;
}

int wh_MessageComm_TranslateInfoResponse(uint16_t magic,
        const whMessageCommInfoResponse* src,
        whMessageCommInfoResponse* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    memcpy(dest->version, src->version, sizeof(dest->version));
    memcpy(dest->build, src->build, sizeof(dest->build));
    WH_T32(magic, dest, src, cfg_comm_data_len);
    WH_T32(magic, dest, src, cfg_nvm_object_count);
    WH_T32(magic, dest, src, cfg_server_keycache_count);
    WH_T32(magic, dest, src, cfg_server_keycache_bufsize);
    WH_T32(magic, dest, src, cfg_server_keycache_bigcount);
    WH_T32(magic, dest, src, cfg_server_keycache_bigbufsize);
    WH_T32(magic, dest, src, cfg_server_customcb_count);
    WH_T32(magic, dest, src, cfg_server_dmaaddr_count);
    WH_T32(magic, dest, src, debug_state);
    WH_T32(magic, dest, src, boot_state);
    WH_T32(magic, dest, src, lifecycle_state);
    WH_T32(magic, dest, src, nvm_state);
    return 0;
}
