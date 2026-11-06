/*
 * Copyright (C) 2026 wolfSSL Inc.
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
 * test-refactor/misc/wh_test_transport_mem_autopoll.c
 *
 * Client mem transport that has the server handle each request while the
 * client waits for the reply. See wh_test_transport_mem_autopoll.h
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <stddef.h> /* For NULL */

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_transport_mem_autopoll.h"

int whTransportMemAutopoll_Init(void* c, const void* cf,
                                whCommSetConnectedCb connectcb,
                                void*                connectcb_arg)
{
    whTransportMemAutopollClientContext* ctx =
        (whTransportMemAutopollClientContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_TransportMem_InitClear(ctx->mem, cf, connectcb, connectcb_arg);
}

int whTransportMemAutopoll_Send(void* c, uint16_t len, const void* data)
{
    whTransportMemAutopollClientContext* ctx =
        (whTransportMemAutopollClientContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_TransportMem_SendRequest(ctx->mem, len, data);
}

int whTransportMemAutopoll_Recv(void* c, uint16_t* out_len, void* data)
{
    whTransportMemAutopollClientContext* ctx =
        (whTransportMemAutopollClientContext*)c;
    int ret;
    int serverRet;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_TransportMem_RecvResponse(ctx->mem, out_len, data);
    if ((ret == WH_ERROR_NOTREADY) && (ctx->server != NULL)) {
        serverRet = wh_Server_HandleRequestMessage(ctx->server);
        ret       = wh_TransportMem_RecvResponse(ctx->mem, out_len, data);
        /* The server replies to a request at once, so no reply means it failed
         * or had no request to handle. Stop instead of waiting forever */
        if (ret == WH_ERROR_NOTREADY) {
            ret =
                ((serverRet != WH_ERROR_OK) && (serverRet != WH_ERROR_NOTREADY))
                    ? serverRet
                    : WH_ERROR_ABORTED;
        }
    }
    return ret;
}

int whTransportMemAutopoll_Cleanup(void* c)
{
    whTransportMemAutopollClientContext* ctx =
        (whTransportMemAutopollClientContext*)c;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    return wh_TransportMem_Cleanup(ctx->mem);
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
