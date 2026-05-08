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
 * test-refactor/wh_test_posix_client.c
 *
 * POSIX client-side init. Wires the client onto the shared
 * mem-transport buffers published by the POSIX server side;
 * the port's server thread is responsible for pumping requests.
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_posix_server.h"
#include "wh_test_posix_client.h"


/* Client-side transport state (buffers are shared with the
 * server via whTestPosix_Server_GetTransportConfig) */
static whTransportMemClientContext _tmClientCtx;
static whCommClientConfig          _commCfg;

static const whTransportClientCb _tcCb = {
    .Init    = wh_TransportMem_InitClear,
    .Send    = wh_TransportMem_SendRequest,
    .Recv    = wh_TransportMem_RecvResponse,
    .Cleanup = wh_TransportMem_Cleanup,
};


int whTestPosix_Client_Init(whClientContext* client)
{
    whClientConfig         cCfg;
    whTransportMemConfig*  tmCfg;
    uint32_t               clientId = 0;
    uint32_t               serverId = 0;

    if (client == NULL) {
        return WH_ERROR_BADARGS;
    }

    tmCfg = whTestPosix_Server_GetTransportConfig();
    if (tmCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    memset(&_commCfg, 0, sizeof(_commCfg));
    _commCfg.transport_cb      = &_tcCb;
    _commCfg.transport_context = (void*)&_tmClientCtx;
    _commCfg.transport_config  = (void*)tmCfg;
    _commCfg.client_id         = 1;

    memset(&cCfg, 0, sizeof(cCfg));
    cCfg.comm = &_commCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, &cCfg));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CommInit(client, &clientId, &serverId));

    return 0;
}


int whTestPosix_Client_Cleanup(whClientContext* client)
{
    if (client == NULL) {
        return 0;
    }
    wh_Client_Cleanup(client);
    return 0;
}
