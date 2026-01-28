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

#ifdef WOLFHSM_CFG_ENABLE_SERVER

#include <string.h>
#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_counter.h"
#include "wolfhsm/wh_server.h"

#include "wolfhsm/wh_server_counter.h"

int wh_Server_HandleCounter(whServerContext* server, uint16_t magic,
                            uint16_t action, uint16_t req_size,
                            const void* req_packet, uint16_t* out_resp_size,
                            void* resp_packet)
{
    whKeyId       counterId = 0;
    int           ret       = 0;
    whNvmMetadata meta[1]   = {{0}};
    uint32_t*     counter   = (uint32_t*)(&meta->label);

    if (server == NULL || server->nvm == NULL || req_packet == NULL ||
        out_resp_size == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (action) {
        case WH_COUNTER_INIT: {
            whMessageCounter_InitRequest  req  = {0};
            whMessageCounter_InitResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_InitRequest)) {
                resp.rc = WH_ERROR_BADARGS;
                (void)wh_MessageCounter_TranslateInitResponse(
                    magic, &resp, (whMessageCounter_InitResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                return WH_ERROR_OK;
            }

            /* translate request */
            (void)wh_MessageCounter_TranslateInitRequest(
                magic, (whMessageCounter_InitRequest*)req_packet, &req);

            /* write 0 to nvm with the supplied id and user_id */
            meta->id = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER,
                                     (uint16_t)server->comm->client_id,
                                     (uint16_t)req.counterId);
            /* use the label buffer to hold the counter value */
            *counter = req.counter;

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Nvm_AddObjectWithReclaim(server->nvm, meta, 0, NULL);
                if (ret == WH_ERROR_OK) {
                    resp.counter = *counter;
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() == WH_ERROR_OK */
            resp.rc = ret;

            (void)wh_MessageCounter_TranslateInitResponse(
                magic, &resp, (whMessageCounter_InitResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_COUNTER_INCREMENT: {
            whMessageCounter_IncrementRequest  req  = {0};
            whMessageCounter_IncrementResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_IncrementRequest)) {
                resp.rc = WH_ERROR_BADARGS;
                (void)wh_MessageCounter_TranslateIncrementResponse(
                    magic, &resp,
                    (whMessageCounter_IncrementResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                return WH_ERROR_OK;
            }

            /* translate request */
            (void)wh_MessageCounter_TranslateIncrementRequest(
                magic, (whMessageCounter_IncrementRequest*)req_packet, &req);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* read the counter, stored in the metadata label */
                ret = wh_Nvm_GetMetadata(
                    server->nvm,
                    WH_MAKE_KEYID(WH_KEYTYPE_COUNTER,
                                  (uint16_t)server->comm->client_id,
                                  (uint16_t)req.counterId),
                    meta);

                /* increment and write the counter back */
                if (ret == WH_ERROR_OK) {
                    *counter = *counter + 1;
                    /* set counter to uint32_t max if it rolled over */
                    if (*counter == 0) {
                        *counter = UINT32_MAX;
                    }
                    /* only update if we didn't saturate */
                    else {
                        ret = wh_Nvm_AddObjectWithReclaim(server->nvm, meta, 0,
                                                          NULL);
                    }
                }

                /* return counter to the caller */
                if (ret == WH_ERROR_OK) {
                    resp.counter = *counter;
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() == WH_ERROR_OK */
            resp.rc = ret;

            (void)wh_MessageCounter_TranslateIncrementResponse(
                magic, &resp, (whMessageCounter_IncrementResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_COUNTER_READ: {
            whMessageCounter_ReadRequest  req  = {0};
            whMessageCounter_ReadResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_ReadRequest)) {
                resp.rc = WH_ERROR_BADARGS;
                (void)wh_MessageCounter_TranslateReadResponse(
                    magic, &resp, (whMessageCounter_ReadResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                return WH_ERROR_OK;
            }

            /* translate request */
            (void)wh_MessageCounter_TranslateReadRequest(
                magic, (whMessageCounter_ReadRequest*)req_packet, &req);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                /* read the counter, stored in the metadata label */
                ret = wh_Nvm_GetMetadata(
                    server->nvm,
                    WH_MAKE_KEYID(WH_KEYTYPE_COUNTER,
                                  (uint16_t)server->comm->client_id,
                                  (uint16_t)req.counterId),
                    meta);

                /* return counter to the caller */
                if (ret == WH_ERROR_OK) {
                    resp.counter = *counter;
                }

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() == WH_ERROR_OK */
            resp.rc = ret;

            (void)wh_MessageCounter_TranslateReadResponse(
                magic, &resp, (whMessageCounter_ReadResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        case WH_COUNTER_DESTROY: {
            whMessageCounter_DestroyRequest  req  = {0};
            whMessageCounter_DestroyResponse resp = {0};

            if (req_size < sizeof(whMessageCounter_DestroyRequest)) {
                resp.rc = WH_ERROR_BADARGS;
                (void)wh_MessageCounter_TranslateDestroyResponse(
                    magic, &resp,
                    (whMessageCounter_DestroyResponse*)resp_packet);
                *out_resp_size = sizeof(resp);
                return WH_ERROR_OK;
            }

            /* translate request */
            (void)wh_MessageCounter_TranslateDestroyRequest(
                magic, (whMessageCounter_DestroyRequest*)req_packet, &req);

            counterId = WH_MAKE_KEYID(WH_KEYTYPE_COUNTER,
                                      (uint16_t)server->comm->client_id,
                                      (uint16_t)req.counterId);

            ret = WH_SERVER_NVM_LOCK(server);
            if (ret == WH_ERROR_OK) {
                ret = wh_Nvm_DestroyObjects(server->nvm, 1, &counterId);

                (void)WH_SERVER_NVM_UNLOCK(server);
            } /* WH_SERVER_NVM_LOCK() == WH_ERROR_OK */
            resp.rc = ret;

            (void)wh_MessageCounter_TranslateDestroyResponse(
                magic, &resp, (whMessageCounter_DestroyResponse*)resp_packet);

            *out_resp_size = sizeof(resp);
        } break;

        default:
            ret = WH_ERROR_BADARGS;
            break;
    }

    return ret;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER */
