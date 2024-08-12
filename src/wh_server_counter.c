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
 * src/wh_server_counter.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <string.h>
#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_server.h"

#include "wolfhsm/wh_server_counter.h"

int wh_Server_HandleCounter(whServerContext* server, uint16_t action,
    uint8_t* data, uint16_t* size)
{
    whKeyId counterId = 0;
    int ret = 0;
    whPacket* packet = (whPacket*)data;
    whNvmMetadata meta[1] = {{0}};
    uint32_t* counter = (uint32_t*)(&meta->label);

    if (server == NULL || server->nvm == NULL || data == NULL || size == NULL)
        return WH_ERROR_BADARGS;

    switch (action)
    {
    case WH_COUNTER_INIT:
        /* write 0 to nvm with the supplied id and user_id */
        meta->id = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER,
            server->comm->client_id, packet->counterInitReq.counterId);
        /* use the label buffer to hold the counter value */
        *counter = packet->counterInitReq.counter;
        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, meta, 0, NULL);
        if (ret == 0) {
            packet->counterInitRes.counter = *counter;
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->counterInitRes);
        }
        break;
    case WH_COUNTER_INCREMENT:
        /* read the counter, stored in the metadata label */
        ret = wh_Nvm_GetMetadata(server->nvm, WH_MAKE_KEYID(
            WH_KEYTYPE_COUNTER, server->comm->client_id,
            packet->counterIncrementReq.counterId), meta);
        /* increment and write the counter back */
        if (ret == 0) {
            *counter = *counter + 1;
            /* set counter to uint32_t max if it rolled over */
            if (*counter == 0) {
                *counter = UINT32_MAX;
            }
            /* only update if we didn't saturate */
            else {
                ret = wh_Nvm_AddObjectWithReclaim(server->nvm, meta, 0, NULL);
            }
        }
        /* return counter to the caller */
        if (ret == 0) {
            packet->counterIncrementRes.counter = *counter;
            *size = WH_PACKET_STUB_SIZE +
                sizeof(packet->counterIncrementRes);
        }
        break;
    case WH_COUNTER_READ:
        /* read the counter, stored in the metadata label */
        ret = wh_Nvm_GetMetadata(server->nvm, WH_MAKE_KEYID(
            WH_KEYTYPE_COUNTER, server->comm->client_id,
            packet->counterReadReq.counterId), meta);
        /* return counter to the caller */
        if (ret == 0) {

            packet->counterReadRes.counter = *counter;
            *size = WH_PACKET_STUB_SIZE + sizeof(packet->counterReadRes);
        }
        break;
    case WH_COUNTER_DESTROY:
        counterId = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER,
            server->comm->client_id, packet->counterDestroyReq.counterId);
        ret = wh_Nvm_DestroyObjects(server->nvm, 1, &counterId);
        if (ret == 0)
            *size = WH_PACKET_STUB_SIZE;
        break;
    default:
        ret = WH_ERROR_BADARGS;
        break;
    }
    packet->rc = ret;
    if (ret != 0)
        *size = WH_PACKET_STUB_SIZE + sizeof(packet->rc);
    return 0;
}
