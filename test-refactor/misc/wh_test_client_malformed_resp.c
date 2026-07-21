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
 * test-refactor/misc/wh_test_client_malformed_resp.c
 *
 * Client-side hardening against malformed server responses. The test drives a
 * raw comm server so it can emit frames a real server never would.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define WH_TEST_MR_BUFFER_SIZE 4096
#define WH_TEST_MR_RNG_SZ 64
#define WH_TEST_MR_POISON 0xA5

/* Bytes an RNG response spends on the crypto headers before the payload */
#define WH_TEST_MR_HDR_SZ                                       \
    ((uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
                sizeof(whMessageCrypto_RngResponse)))

#define WH_TEST_MR_RESP_SZ (WH_TEST_MR_HDR_SZ + WH_TEST_MR_RNG_SZ)

/* Consumes the pending request and answers it with an RNG response claiming
 * claimedSz bytes, filling payloadSz bytes after the headers but handing only
 * frameLen bytes to the transport so the frame can be cut short. */
static int _sendCraftedRngResponse(whCommServer* server, uint32_t claimedSz,
                                   uint32_t payloadSz, uint8_t fill,
                                   uint16_t frameLen)
{
    uint8_t  rx_req[WH_TEST_MR_RESP_SZ] = {0};
    uint16_t rx_req_len                 = 0;
    uint16_t rx_req_flags               = 0;
    uint16_t rx_req_type                = 0;
    uint16_t rx_req_seq                 = 0;

    uint8_t tx_resp[WH_TEST_MR_RESP_SZ] = {0};

    whMessageCrypto_GenericResponseHeader* hdr =
        (whMessageCrypto_GenericResponseHeader*)tx_resp;
    whMessageCrypto_RngResponse* res =
        (whMessageCrypto_RngResponse*)(tx_resp + sizeof(*hdr));

    int rc = wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                       &rx_req_seq, &rx_req_len, sizeof(rx_req),
                                       rx_req);
    if (rc == WH_ERROR_OK) {
        hdr->algoType = WC_ALGO_TYPE_RNG;
        hdr->rc       = WH_ERROR_OK;
        hdr->reserved = 0;
        res->sz       = claimedSz;
        memset((uint8_t*)(res + 1), fill, payloadSz);

        rc = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                        rx_req_seq, frameLen, tx_resp);
    }
    return rc;
}

/* A response claiming more inline random bytes than the frame actually carried
 * must be rejected instead of copying whatever trails the payload. */
static int _whTest_ClientRngTruncatedResponse(void)
{
    uint8_t              req[WH_TEST_MR_BUFFER_SIZE]  = {0};
    uint8_t              resp[WH_TEST_MR_BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]                      = {{
                             .req       = (whTransportMemCsr*)req,
                             .req_size  = sizeof(req),
                             .resp      = (whTransportMemCsr*)resp,
                             .resp_size = sizeof(resp),
    }};

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientContext             client[1]  = {0};
    whClientConfig              c_conf[1]  = {{
                     .comm = cc_conf,
    }};

    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          s_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};
    whCommServer                server[1] = {0};

    uint8_t  out[WH_TEST_MR_RNG_SZ];
    uint32_t got = 0;
    uint32_t i   = 0;
    int      rc  = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Init(server, s_conf, NULL, NULL));

    /* Well-formed exchange first, so the client packet buffer holds a known
     * pattern past the headers for the malformed exchanges to expose. */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_RngGenerateRequest(client, WH_TEST_MR_RNG_SZ));
    WH_TEST_RETURN_ON_FAIL(_sendCraftedRngResponse(
        server, WH_TEST_MR_RNG_SZ, WH_TEST_MR_RNG_SZ, WH_TEST_MR_POISON,
        WH_TEST_MR_RESP_SZ));

    got = sizeof(out);
    WH_TEST_RETURN_ON_FAIL(wh_Client_RngGenerateResponse(client, out, &got));
    WH_TEST_ASSERT_RETURN(got == WH_TEST_MR_RNG_SZ);
    for (i = 0; i < sizeof(out); i++) {
        WH_TEST_ASSERT_RETURN(out[i] == WH_TEST_MR_POISON);
    }

    /* Headers arrive intact but the claimed payload is left out of the frame */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_RngGenerateRequest(client, WH_TEST_MR_RNG_SZ));
    WH_TEST_RETURN_ON_FAIL(_sendCraftedRngResponse(server, WH_TEST_MR_RNG_SZ, 0,
                                                   0, WH_TEST_MR_HDR_SZ));

    got = sizeof(out);
    rc  = wh_Client_RngGenerateResponse(client, out, &got);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    /* Nothing may have been copied out of the comm buffer */
    for (i = 0; i < sizeof(out); i++) {
        WH_TEST_ASSERT_RETURN(out[i] == 0);
    }

    /* Frame shorter than the headers themselves: the size field the client
     * would read is stale data from the previous exchanges. */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_RngGenerateRequest(client, WH_TEST_MR_RNG_SZ));
    WH_TEST_RETURN_ON_FAIL(_sendCraftedRngResponse(
        server, WH_TEST_MR_RNG_SZ, 0, 0,
        (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader)));

    got = sizeof(out);
    rc  = wh_Client_RngGenerateResponse(client, out, &got);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < sizeof(out); i++) {
        WH_TEST_ASSERT_RETURN(out[i] == 0);
    }

    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA

/* Bytes a DMA RNG response spends on the headers. The payload goes straight to
 * client memory, so this is the whole success reply. */
#define WH_TEST_MR_DMA_RESP_SZ                                  \
    ((uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
                sizeof(whMessageCrypto_RngDmaResponse)))

/* Consumes the pending request and answers it with a DMA RNG response carrying
 * rc, handing the transport only frameLen bytes of it. */
static int _sendCraftedRngDmaResponse(whCommServer* server, int32_t rc,
                                      uint16_t frameLen)
{
    uint8_t  rx_req[WH_TEST_MR_RESP_SZ] = {0};
    uint16_t rx_req_len                 = 0;
    uint16_t rx_req_flags               = 0;
    uint16_t rx_req_type                = 0;
    uint16_t rx_req_seq                 = 0;

    uint8_t tx_resp[WH_TEST_MR_DMA_RESP_SZ] = {0};

    whMessageCrypto_GenericResponseHeader* hdr =
        (whMessageCrypto_GenericResponseHeader*)tx_resp;

    int ret = wh_CommServer_RecvRequest(server, &rx_req_flags, &rx_req_type,
                                        &rx_req_seq, &rx_req_len,
                                        sizeof(rx_req), rx_req);
    if (ret == WH_ERROR_OK) {
        hdr->algoType = WC_ALGO_TYPE_RNG;
        hdr->rc       = rc;
        hdr->reserved = 0;

        ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                         rx_req_seq, frameLen, tx_resp);
    }
    return ret;
}

/* The DMA reply carries no inline payload to read, so this pins the frame to
 * the protocol contract: a success reply must deliver the whole response. */
static int _whTest_ClientRngDmaTruncatedResponse(void)
{
    uint8_t              req[WH_TEST_MR_BUFFER_SIZE]  = {0};
    uint8_t              resp[WH_TEST_MR_BUFFER_SIZE] = {0};
    whTransportMemConfig tmcf[1]                      = {{
                             .req       = (whTransportMemCsr*)req,
                             .req_size  = sizeof(req),
                             .resp      = (whTransportMemCsr*)resp,
                             .resp_size = sizeof(resp),
    }};

    whTransportClientCb         tccb[1]    = {WH_TRANSPORT_MEM_CLIENT_CB};
    whTransportMemClientContext tmcc[1]    = {0};
    whCommClientConfig          cc_conf[1] = {{
                 .transport_cb      = tccb,
                 .transport_context = (void*)tmcc,
                 .transport_config  = (void*)tmcf,
                 .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientContext             client[1]  = {0};
    whClientConfig              c_conf[1]  = {{
                     .comm = cc_conf,
    }};

    whTransportServerCb         tscb[1]   = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]   = {0};
    whCommServerConfig          s_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};
    whCommServer                server[1] = {0};

    uint8_t out[WH_TEST_MR_RNG_SZ];
    int     rc = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));
    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Init(server, s_conf, NULL, NULL));

    /* A complete success reply is accepted */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_RngGenerateDmaRequest(client, out, sizeof(out)));
    WH_TEST_RETURN_ON_FAIL(_sendCraftedRngDmaResponse(server, WH_ERROR_OK,
                                                      WH_TEST_MR_DMA_RESP_SZ));
    WH_TEST_RETURN_ON_FAIL(wh_Client_RngGenerateDmaResponse(client));

    /* One byte short of the response the success rc promised */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_RngGenerateDmaRequest(client, out, sizeof(out)));
    WH_TEST_RETURN_ON_FAIL(_sendCraftedRngDmaResponse(
        server, WH_ERROR_OK, (uint16_t)(WH_TEST_MR_DMA_RESP_SZ - 1)));
    rc = wh_Client_RngGenerateDmaResponse(client);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    /* An error reply legitimately carries only the generic header, so the
     * server's rc must still reach the caller */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_RngGenerateDmaRequest(client, out, sizeof(out)));
    WH_TEST_RETURN_ON_FAIL(_sendCraftedRngDmaResponse(
        server, WH_ERROR_ACCESS,
        (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader)));
    rc = wh_Client_RngGenerateDmaResponse(client);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(wh_CommServer_Cleanup(server));
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_ClientMalformedResp(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client handling of malformed responses...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientRngTruncatedResponse());
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientRngDmaTruncatedResponse());
#endif

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER &&
        * !WOLFHSM_CFG_NO_CRYPTO */
