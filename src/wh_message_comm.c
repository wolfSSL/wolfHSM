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
    dest->client_id = wh_Translate32(magic, src->client_id);
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
    dest->client_id = wh_Translate32(magic, src->client_id);
    dest->server_id = wh_Translate32(magic, src->server_id);
    return 0;
}

int wh_MessageComm_TranslateLenData(uint16_t magic,
        const whMessageCommLenData* src,
        whMessageCommLenData* dest)
{
    if (    (src == NULL) ||
            (dest == NULL)  ) {
        return WH_ERROR_BADARGS;
    }
    dest->len = wh_Translate16(magic, src->len);
    /* III Note that we can't use src->len to minimize this copy */
    memcpy(dest->data, src->data, sizeof(dest->data));
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
    dest->cfg_comm_data_len = wh_Translate32(magic, src->cfg_comm_data_len);
    dest->cfg_nvm_object_count = wh_Translate32(magic, src->cfg_nvm_object_count);
    dest->cfg_server_keycache_count = wh_Translate32(magic, src->cfg_server_keycache_count);
    dest->cfg_server_keycache_bufsize = wh_Translate32(magic, src->cfg_server_keycache_bufsize);
    dest->cfg_server_customcb_count = wh_Translate32(magic, src->cfg_server_customcb_count);
    dest->cfg_server_dmaaddr_count = wh_Translate32(magic, src->cfg_server_dmaaddr_count);
    dest->debug_state = wh_Translate32(magic, src->debug_state);
    dest->boot_state = wh_Translate32(magic, src->boot_state);
    dest->lifecycle_state = wh_Translate32(magic, src->lifecycle_state);
    dest->nvm_state = wh_Translate32(magic, src->nvm_state);
    return 0;
}


