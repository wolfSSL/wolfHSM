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
 * test-refactor/server/wh_test_cert_readtrusted.c
 *
 * READTRUSTED response sizing over the comm buffer. Drives the
 * request handler directly against the shared server context.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message_cert.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_cert.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* wh_test_cert_data.h defines rather than declares, so it can only be
 * included once across the suite */
extern const unsigned char ROOT_A_CERT[];
extern const size_t        ROOT_A_CERT_len;

/* Mirrors the staging clamp in the non-DMA READTRUSTED handler. Reading at
 * both STAGED_LEN and STAGED_LEN + 1 pins the clamp from either side */
#define WH_TEST_CERT_TRANSPORT_LEN \
    (WOLFHSM_CFG_COMM_DATA_LEN - sizeof(whMessageCert_ReadTrustedResponse))
#define WH_TEST_CERT_STAGED_LEN                               \
    ((WOLFHSM_CFG_MAX_CERT_SIZE > WH_TEST_CERT_TRANSPORT_LEN) \
         ? WH_TEST_CERT_TRANSPORT_LEN                         \
         : WOLFHSM_CFG_MAX_CERT_SIZE)

/* An unstageable certificate must report the stored size and no payload */
static int _whTest_CertReadTrustedOversized(whServerContext* server)
{
    whMessageCert_ReadTrustedRequest req[1] = {{0}};
    union {
        whMessageCert_ReadTrustedResponse resp;
        uint8_t                           bytes[WOLFHSM_CFG_COMM_DATA_LEN];
    } respPkt;
    /* Static filler: an automatic copy would double this stack frame on the
     * embedded targets these suites also run on */
    static uint8_t oversized_cert[WH_TEST_CERT_STAGED_LEN + 1];
    const whNvmId  certId        = 20;
    const uint32_t oversized_len = (uint32_t)WH_TEST_CERT_STAGED_LEN + 1;
    uint16_t       resp_size     = 0;
    int            handler_rc;
    uint32_t       i;

    /* One byte too large to stage */
    memset(oversized_cert, 0x5A, sizeof(oversized_cert));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, certId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, NULL, 0,
        oversized_cert, oversized_len));

    /* Poison makes bytes the handler never staged detectable */
    memset(respPkt.bytes, 0xA5, sizeof(respPkt.bytes));
    req->id = certId;

    /* The server transmits regardless of this return, so out_resp_size is
     * what actually reaches the client */
    handler_rc = wh_Server_HandleCertRequest(
        server, WH_COMM_MAGIC_NATIVE, WH_MESSAGE_CERT_ACTION_READTRUSTED, 0,
        (uint16_t)sizeof(*req), req, &resp_size, respPkt.bytes);

    WH_TEST_ASSERT_RETURN(handler_rc == WH_ERROR_BUFFER_SIZE);
    WH_TEST_ASSERT_RETURN(respPkt.resp.rc == WH_ERROR_BUFFER_SIZE);
    /* Reports the true size, which no non-DMA response can carry */
    WH_TEST_ASSERT_RETURN(respPkt.resp.cert_len == oversized_len);
    WH_TEST_ASSERT_RETURN(resp_size == sizeof(respPkt.resp));

    for (i = sizeof(respPkt.resp); i < sizeof(respPkt.bytes); i++) {
        WH_TEST_ASSERT_RETURN(respPkt.bytes[i] == 0xA5);
    }

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, certId));

    /* The largest stageable certificate must still read back whole */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, certId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, NULL, 0,
        oversized_cert, oversized_len - 1));

    memset(respPkt.bytes, 0xA5, sizeof(respPkt.bytes));
    req->id = certId;

    WH_TEST_RETURN_ON_FAIL(wh_Server_HandleCertRequest(
        server, WH_COMM_MAGIC_NATIVE, WH_MESSAGE_CERT_ACTION_READTRUSTED, 0,
        (uint16_t)sizeof(*req), req, &resp_size, respPkt.bytes));

    WH_TEST_ASSERT_RETURN(respPkt.resp.rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(respPkt.resp.cert_len == oversized_len - 1);
    WH_TEST_ASSERT_RETURN(resp_size == sizeof(respPkt.resp) + oversized_len - 1);

    for (i = 0; i < oversized_len - 1; i++) {
        WH_TEST_ASSERT_RETURN(respPkt.bytes[sizeof(respPkt.resp) + i] == 0x5A);
    }

    return wh_Server_CertEraseTrusted(server, certId);
}

/* A rejected read stages no certificate, so the response must carry no length
 * and no payload */
static int _whTest_CertReadTrustedDenied(whServerContext* server)
{
    whMessageCert_ReadTrustedRequest req[1] = {{0}};
    union {
        whMessageCert_ReadTrustedResponse resp;
        uint8_t                           bytes[WOLFHSM_CFG_COMM_DATA_LEN];
    } respPkt;
    const whNvmId certId    = 21;
    uint16_t      resp_size = 0;
    int           handler_rc;

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, certId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONEXPORTABLE, NULL, 0,
        ROOT_A_CERT, ROOT_A_CERT_len));

    memset(respPkt.bytes, 0xA5, sizeof(respPkt.bytes));
    req->id = certId;

    handler_rc = wh_Server_HandleCertRequest(
        server, WH_COMM_MAGIC_NATIVE, WH_MESSAGE_CERT_ACTION_READTRUSTED, 0,
        (uint16_t)sizeof(*req), req, &resp_size, respPkt.bytes);

    WH_TEST_ASSERT_RETURN(handler_rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(respPkt.resp.rc == WH_ERROR_ACCESS);
    WH_TEST_ASSERT_RETURN(respPkt.resp.cert_len == 0);
    WH_TEST_ASSERT_RETURN(resp_size == sizeof(respPkt.resp));

    return wh_Server_CertEraseTrusted(server, certId);
}

/* READTRUSTED response sizing over the comm buffer */
int whTest_CertReadTrusted(whServerContext* ctx)
{
    whServerContext* server = (whServerContext*)ctx;

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));
    WH_TEST_RETURN_ON_FAIL(_whTest_CertReadTrustedOversized(server));
    WH_TEST_RETURN_ON_FAIL(_whTest_CertReadTrustedDenied(server));

    return 0;
}


#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
