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
 * src/wh_message_customcb.c
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"

#include "wolfhsm/wh_message_customcb.h"

static void _translateCustomData(uint16_t magic, uint32_t translatedType,
                                 const whMessageCustomCb_Data* src,
                                 whMessageCustomCb_Data*       dst)
{
    if (translatedType < WH_MESSAGE_CUSTOM_CB_TYPE_USER_DEFINED_START) {
        switch (translatedType) {
            case WH_MESSAGE_CUSTOM_CB_TYPE_QUERY: {
                /* right now, no further translations required */
            } break;
            case WH_MESSAGE_CUSTOM_CB_TYPE_DMA32: {
                dst->dma32.client_addr =
                    wh_Translate32(magic, src->dma32.client_addr);
                dst->dma32.client_sz =
                    wh_Translate32(magic, src->dma32.client_sz);
                dst->dma32.server_addr =
                    wh_Translate32(magic, src->dma32.server_addr);
                dst->dma32.server_sz =
                    wh_Translate32(magic, src->dma32.server_sz);
            } break;
            case WH_MESSAGE_CUSTOM_CB_TYPE_DMA64: {
                dst->dma64.client_addr =
                    wh_Translate64(magic, src->dma64.client_addr);
                dst->dma64.client_sz =
                    wh_Translate64(magic, src->dma64.client_sz);
                dst->dma64.server_addr =
                    wh_Translate64(magic, src->dma64.server_addr);
                dst->dma64.server_sz =
                    wh_Translate64(magic, src->dma64.server_sz);
            } break;
            default: {
                /* reserved message types - no translation for now */
            } break;
        }
    }
    else {
        /* use memmove in case data is translated "in place" */
        memmove(dst->buffer.data, src->buffer.data, sizeof(dst->buffer.data));
    }
}


int wh_MessageCustomCb_TranslateRequest(uint16_t                         magic,
                                        const whMessageCustomCb_Request* src,
                                        whMessageCustomCb_Request*       dst)
{
    if ((src == NULL) || (dst == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dst->id   = wh_Translate32(magic, src->id);
    dst->type = wh_Translate32(magic, src->type);
    _translateCustomData(magic, dst->type, &src->data, &dst->data);

    return WH_ERROR_OK;
}


int wh_MessageCustomCb_TranslateResponse(uint16_t magic,
                                         const whMessageCustomCb_Response* src,
                                         whMessageCustomCb_Response*       dst)
{
    if ((src == NULL) || (dst == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dst->rc  = wh_Translate32(magic, src->rc);
    dst->err = wh_Translate32(magic, src->err);

    /* TODO: should we continue to translate responses for err != 0?
     * Probably still should...*/
    dst->id   = wh_Translate32(magic, src->id);
    dst->type = wh_Translate32(magic, src->type);
    _translateCustomData(magic, dst->type, &src->data, &dst->data);

    return WH_ERROR_OK;
}
