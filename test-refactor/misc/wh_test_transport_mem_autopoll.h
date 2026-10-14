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
 * test-refactor/misc/wh_test_transport_mem_autopoll.h
 *
 * Client mem transport for misc tests that run a client and its server in one
 * thread. While the client waits for a reply, the transport has the server
 * handle the request, so blocking client APIs work without a server thread.
 */
#ifndef WH_TEST_TRANSPORT_MEM_AUTOPOLL_H_
#define WH_TEST_TRANSPORT_MEM_AUTOPOLL_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>

#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_transport_mem.h"

typedef struct {
    whTransportMemClientContext mem[1];
    /* Server to run while waiting for a reply. Set it before the client's
     * first request. NULL makes this a plain mem transport */
    whServerContext* server;
} whTransportMemAutopollClientContext;

int whTransportMemAutopoll_Init(void* c, const void* cf,
                                whCommSetConnectedCb connectcb,
                                void*                connectcb_arg);
int whTransportMemAutopoll_Send(void* c, uint16_t len, const void* data);
int whTransportMemAutopoll_Recv(void* c, uint16_t* out_len, void* data);
int whTransportMemAutopoll_Cleanup(void* c);

/* clang-format off */
#define WH_TRANSPORT_MEM_AUTOPOLL_CLIENT_CB             \
    {                                                   \
        .Init    = whTransportMemAutopoll_Init,         \
        .Send    = whTransportMemAutopoll_Send,         \
        .Recv    = whTransportMemAutopoll_Recv,         \
        .Cleanup = whTransportMemAutopoll_Cleanup,      \
    }
/* clang-format on */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

#endif /* !WH_TEST_TRANSPORT_MEM_AUTOPOLL_H_ */
