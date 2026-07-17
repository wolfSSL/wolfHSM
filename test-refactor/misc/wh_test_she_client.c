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
 * test-refactor/misc/wh_test_she_client.c
 *
 * SHE client tests needing raw control of both transport ends, so they cannot
 * use the client-server group's live server: a raw comm server returns the
 * expected kind and seq with a malformed payload size. Counterpart to
 * server/wh_test_she_server.c.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_SHE_EXTENSION) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_she.h"
#include "wolfhsm/wh_she_common.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_she.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define BUFFER_SIZE 4096

/* The four variable-length SHE crypt helpers share a response signature */
typedef int (*whSheCryptRespFn)(whClientContext* c, uint8_t* out, uint32_t sz);

typedef struct {
    uint16_t         action;
    whSheCryptRespFn respFn;
} whSheCryptCase;

typedef struct {
    whClientContext client[1];
    whCommServer    server[1];
    /* Mem transport shared by the client and the raw comm server */
    uint8_t                     reqBuf[BUFFER_SIZE];
    uint8_t                     respBuf[BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportClientCb         tccb[1];
    whTransportMemClientContext tmcc[1];
    whCommClientConfig          cc_conf[1];
    whClientConfig              c_conf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];
} TestCtx;

static const whSheCryptCase _cryptCase[] = {
    {WH_SHE_ENC_ECB, wh_Client_SheEncEcbResponse},
    {WH_SHE_ENC_CBC, wh_Client_SheEncCbcResponse},
    {WH_SHE_DEC_ECB, wh_Client_SheDecEcbResponse},
    {WH_SHE_DEC_CBC, wh_Client_SheDecCbcResponse},
};

static int _SetupClientServer(TestCtx* t)
{
    memset(t, 0, sizeof(*t));

    t->tmcf[0] = (whTransportMemConfig){
        .req       = (whTransportMemCsr*)t->reqBuf,
        .req_size  = sizeof(t->reqBuf),
        .resp      = (whTransportMemCsr*)t->respBuf,
        .resp_size = sizeof(t->respBuf),
    };

    t->tccb[0]    = (whTransportClientCb)WH_TRANSPORT_MEM_CLIENT_CB;
    t->cc_conf[0] = (whCommClientConfig){
        .transport_cb      = t->tccb,
        .transport_context = (void*)t->tmcc,
        .transport_config  = (void*)t->tmcf,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    };
    t->c_conf[0] = (whClientConfig){
        .comm = t->cc_conf,
    };

    t->tscb[0]    = (whTransportServerCb)WH_TRANSPORT_MEM_SERVER_CB;
    t->cs_conf[0] = (whCommServerConfig){
        .transport_cb      = t->tscb,
        .transport_context = (void*)t->tmsc,
        .transport_config  = (void*)t->tmcf,
        .server_id         = 124,
    };

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(t->client, t->c_conf));
    WH_TEST_RETURN_ON_FAIL(
        wh_CommServer_Init(t->server, t->cs_conf, NULL, NULL));
    return WH_ERROR_OK;
}

static void _CleanupClientServer(TestCtx* t)
{
    (void)wh_CommServer_Cleanup(t->server);
    (void)wh_Client_Cleanup(t->client);
}

/* Issue the request for action so the reply's kind and seq line up */
static int _SheCryptRequest(whClientContext* c, uint16_t action, uint8_t* iv,
                            uint8_t* in, uint32_t sz)
{
    int ret;

    switch (action) {
        case WH_SHE_ENC_ECB:
            ret = wh_Client_SheEncEcbRequest(c, 0, in, sz);
            break;
        case WH_SHE_ENC_CBC:
            ret = wh_Client_SheEncCbcRequest(c, 0, iv, WH_SHE_KEY_SZ, in, sz);
            break;
        case WH_SHE_DEC_ECB:
            ret = wh_Client_SheDecEcbRequest(c, 0, in, sz);
            break;
        case WH_SHE_DEC_CBC:
            ret = wh_Client_SheDecCbcRequest(c, 0, iv, WH_SHE_KEY_SZ, in, sz);
            break;
        default:
            ret = WH_ERROR_BADARGS;
            break;
    }
    return ret;
}

/* A fixed-size response one byte short of its own struct must be rejected
 * rather than read out of the stale tail of the shared comm buffer. */
static int _whTest_SheRespSizeFixed(TestCtx* t)
{
    int      ret   = 0;
    uint16_t magic = 0;
    uint16_t kind  = 0;
    uint16_t seq   = 0;
    uint16_t len   = 0;

    uint8_t in[WH_SHE_KEY_SZ * 2];
    uint8_t out[WH_SHE_KEY_SZ * 4];
    uint8_t rxReq[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t txResp[WOLFHSM_CFG_COMM_DATA_LEN];

    whMessageShe_GenMacResponse* macResp = NULL;

    memset(in, 0xA5, sizeof(in));
    memset(out, 0, sizeof(out));

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_SheGenerateMacRequest(t->client, 0, in, sizeof(in)));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_RecvRequest(
        t->server, &magic, &kind, &seq, &len, sizeof(rxReq), rxReq));

    memset(txResp, 0, sizeof(txResp));
    macResp     = (whMessageShe_GenMacResponse*)txResp;
    macResp->rc = WH_SHE_ERC_NO_ERROR;
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendResponse(
        t->server, magic, kind, seq, (uint16_t)(sizeof(*macResp) - 1), txResp));

    ret = wh_Client_SheGenerateMacResponse(t->client, out, sizeof(out));
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    return WH_ERROR_OK;
}

/* Every variable-length helper, at the exact bound: reject a declared sz one
 * past the payload received, accept one sitting exactly on it. */
static int _whTest_SheRespSizeCryptBound(TestCtx* t)
{
    int      ret       = 0;
    int      i         = 0;
    int      j         = 0;
    int      caseCount = 0;
    uint16_t magic     = 0;
    uint16_t kind      = 0;
    uint16_t seq       = 0;
    uint16_t len       = 0;
    uint32_t payloadSz = 0;
    uint32_t claimSz   = 0;

    uint8_t in[WH_SHE_KEY_SZ * 2];
    uint8_t iv[WH_SHE_KEY_SZ];
    uint8_t out[WH_SHE_KEY_SZ * 4];
    uint8_t rxReq[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t txResp[WOLFHSM_CFG_COMM_DATA_LEN];

    /* All four crypt responses share the rc/sz layout, so one type covers
     * them. Asserted below. */
    whMessageShe_EncEcbResponse* cryptResp = NULL;

    memset(in, 0xA5, sizeof(in));
    memset(iv, 0x5A, sizeof(iv));
    memset(out, 0, sizeof(out));

    WH_TEST_ASSERT_RETURN(sizeof(whMessageShe_EncEcbResponse) ==
                          sizeof(whMessageShe_EncCbcResponse));
    WH_TEST_ASSERT_RETURN(sizeof(whMessageShe_EncEcbResponse) ==
                          sizeof(whMessageShe_DecEcbResponse));
    WH_TEST_ASSERT_RETURN(sizeof(whMessageShe_EncEcbResponse) ==
                          sizeof(whMessageShe_DecCbcResponse));

    caseCount = (int)(sizeof(_cryptCase) / sizeof(_cryptCase[0]));
    payloadSz = WH_SHE_KEY_SZ;

    for (i = 0; i < caseCount; i++) {
        for (j = 0; j < 2; j++) {
            claimSz = (j == 0) ? (payloadSz + 1) : payloadSz;

            WH_TEST_RETURN_ON_FAIL(_SheCryptRequest(
                t->client, _cryptCase[i].action, iv, in, sizeof(in)));
            WH_TEST_RETURN_ON_FAIL(wh_CommServer_RecvRequest(
                t->server, &magic, &kind, &seq, &len, sizeof(rxReq), rxReq));

            /* Row's request and response helper must be the same action */
            WH_TEST_ASSERT_RETURN(WH_MESSAGE_ACTION(kind) ==
                                  _cryptCase[i].action);

            memset(txResp, 0, sizeof(txResp));
            cryptResp     = (whMessageShe_EncEcbResponse*)txResp;
            cryptResp->rc = WH_SHE_ERC_NO_ERROR;
            cryptResp->sz = claimSz;
            WH_TEST_RETURN_ON_FAIL(wh_CommServer_SendResponse(
                t->server, magic, kind, seq,
                (uint16_t)(sizeof(*cryptResp) + payloadSz), txResp));

            ret = _cryptCase[i].respFn(t->client, out, sizeof(out));
            if (j == 0) {
                WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
            }
            else {
                WH_TEST_ASSERT_RETURN(ret == WH_ERROR_OK);
            }
        }
    }

    return WH_ERROR_OK;
}

/* A crypt reply too short for even its fixed fields. All-ones payload makes rc
 * read nonzero, so a missing size gate surfaces as a stale rc. */
static int _whTest_SheRespSizeCryptShort(TestCtx* t)
{
    int      ret   = 0;
    uint16_t magic = 0;
    uint16_t kind  = 0;
    uint16_t seq   = 0;
    uint16_t len   = 0;

    uint8_t in[WH_SHE_KEY_SZ * 2];
    uint8_t iv[WH_SHE_KEY_SZ];
    uint8_t out[WH_SHE_KEY_SZ * 4];
    uint8_t rxReq[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t txResp[WOLFHSM_CFG_COMM_DATA_LEN];

    memset(in, 0xA5, sizeof(in));
    memset(iv, 0x5A, sizeof(iv));
    memset(out, 0, sizeof(out));

    WH_TEST_RETURN_ON_FAIL(
        _SheCryptRequest(t->client, WH_SHE_ENC_ECB, iv, in, sizeof(in)));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_RecvRequest(
        t->server, &magic, &kind, &seq, &len, sizeof(rxReq), rxReq));

    memset(txResp, 0xFF, sizeof(txResp));
    WH_TEST_RETURN_ON_FAIL(
        wh_CommServer_SendResponse(t->server, magic, kind, seq, 2, txResp));

    ret = wh_Client_SheEncEcbResponse(t->client, out, sizeof(out));
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    return WH_ERROR_OK;
}

int whTest_SheClient(void* ctx)
{
    TestCtx t[1];

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));

    WH_TEST_PRINT("Testing SHE client response size validation...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_SheRespSizeFixed(t));
    WH_TEST_RETURN_ON_FAIL(_whTest_SheRespSizeCryptBound(t));
    WH_TEST_RETURN_ON_FAIL(_whTest_SheRespSizeCryptShort(t));

    _CleanupClientServer(t);

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION && WOLFHSM_CFG_ENABLE_CLIENT && \
          WOLFHSM_CFG_ENABLE_SERVER */
