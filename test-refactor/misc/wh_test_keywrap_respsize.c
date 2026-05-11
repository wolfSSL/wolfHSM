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
 * test-refactor/misc/wh_test_keywrap_respsize.c
 *
 * Client-side response size validation for the keywrap family.
 *
 * Each of the four keywrap response handlers
 * (wh_Client_KeyWrapResponse, wh_Client_KeyUnwrapAndExportResponse,
 *  wh_Client_DataWrapResponse, wh_Client_DataUnwrapResponse) parses a
 * response that carries a fixed header plus a variable-length payload
 * whose length is declared inside the header. A correct implementation
 * must verify the bytes actually received cover that declared length
 * before memcpy'ing the payload into the caller's output buffer.
 *
 * The test wires the client to a one-shot fake transport whose Recv
 * delivers a canned malformed response: the declared trailing length
 * is non-zero but no trailing bytes are actually delivered. Each
 * handler must return WH_ERROR_ABORTED rather than over-read the
 * comm buffer.
 *
 * Pure unit test of the client-side parser; no server, no fixture
 * context is consumed.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_KEYWRAP) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_nvm.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define TEST_CIPHER_TYPE WC_CIPHER_AES_GCM
/* Trailing length the malformed response claims. Zero bytes are
 * actually delivered, so any positive value triggers the bug. */
#define MALFORMED_TRAILING_SZ 64
/* Caller output buffers sized large enough that the *Sz > outSz
 * short-circuit doesn't preempt the bounds check we want to hit. */
#define OUT_BUF_SZ 1024
/* Arbitrary non-zero seq the test pretends a request was sent with. */
#define FAKE_SEQ 0x1234

/* Data wrap/unwrap response entry points are not in the public header
 * but have external linkage in wh_client_keywrap.c. */
int wh_Client_DataWrapResponse(whClientContext* ctx,
                               enum wc_CipherType cipherType,
                               void* wrappedDataOut, uint32_t* wrappedDataSz);
int wh_Client_DataUnwrapResponse(whClientContext* ctx,
                                 enum wc_CipherType cipherType, void* dataOut,
                                 uint32_t* dataSz);

/* One-shot fake transport: swallows Send, returns whatever the caller
 * has stashed in `pkt` from Recv. */
typedef struct {
    uint8_t  pkt[WH_COMM_MTU];
    uint16_t pkt_len;
} FakeTransport;

static int Fake_Init(void* c, const void* cf, whCommSetConnectedCb connectcb,
                     void* connectcb_arg)
{
    (void)c; (void)cf; (void)connectcb; (void)connectcb_arg;
    return WH_ERROR_OK;
}
static int Fake_Cleanup(void* c) { (void)c; return WH_ERROR_OK; }
static int Fake_Send(void* c, uint16_t size, const void* data)
{
    (void)c; (void)size; (void)data;
    return WH_ERROR_OK;
}
static int Fake_Recv(void* c, uint16_t* out_size, void* data)
{
    FakeTransport* t = (FakeTransport*)c;
    memcpy(data, t->pkt, t->pkt_len);
    *out_size = t->pkt_len;
    return WH_ERROR_OK;
}

static const whTransportClientCb fakeCb = {
    Fake_Init, Fake_Send, Fake_Recv, Fake_Cleanup,
};

/* Stand up a client wired to the fake transport, with state primed so
 * a single wh_Client_*Response call sees a pending request matching
 * `action`, and the staged comm buffer holds (hdr + resp_struct) with
 * resp_struct declaring trailing bytes that are not actually sent. */
static int _RunCase(uint16_t action, const void* resp_struct,
                    uint16_t resp_sz,
                    int (*invokeResp)(whClientContext*))
{
    FakeTransport      transport;
    whCommClientConfig commCfg;
    whClientConfig     clientCfg;
    whClientContext    client;
    whCommHeader       hdr;
    uint16_t           kind = WH_MESSAGE_KIND(WH_MESSAGE_GROUP_KEY, action);
    int                ret;

    memset(&transport, 0, sizeof(transport));
    memset(&commCfg, 0, sizeof(commCfg));
    memset(&clientCfg, 0, sizeof(clientCfg));
    memset(&client, 0, sizeof(client));

    commCfg.transport_cb      = &fakeCb;
    commCfg.transport_context = &transport;
    commCfg.client_id         = WH_TEST_DEFAULT_CLIENT_ID;
    clientCfg.comm            = &commCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(&client, &clientCfg));

    /* Pretend a request was sent: pending + matching seq/kind so
     * RecvResponse won't bail early. */
    client.comm->pending  = 1;
    client.comm->seq      = FAKE_SEQ;
    client.last_req_id    = FAKE_SEQ;
    client.last_req_kind  = kind;

    /* Pack hdr + malformed response into the fake transport buffer. */
    hdr.magic = WH_COMM_MAGIC_NATIVE;
    hdr.kind  = kind;
    hdr.seq   = FAKE_SEQ;
    hdr.aux   = WH_COMM_AUX_RESP_OK;
    memcpy(transport.pkt, &hdr, sizeof(hdr));
    memcpy(transport.pkt + sizeof(hdr), resp_struct, resp_sz);
    transport.pkt_len = (uint16_t)(sizeof(hdr) + resp_sz);

    ret = invokeResp(&client);
    (void)wh_Client_Cleanup(&client);

    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
    return WH_ERROR_OK;
}

/* Per-handler thunks: each wires up the output buffers the response
 * handler writes into. */
static int _InvokeKeyWrap(whClientContext* c)
{
    uint8_t  out[OUT_BUF_SZ];
    uint16_t outSz = sizeof(out);
    return wh_Client_KeyWrapResponse(c, TEST_CIPHER_TYPE, out, &outSz);
}
static int _InvokeKeyUnwrapAndExport(whClientContext* c)
{
    whNvmMetadata meta;
    uint8_t       out[OUT_BUF_SZ];
    uint16_t      outSz = sizeof(out);
    return wh_Client_KeyUnwrapAndExportResponse(c, TEST_CIPHER_TYPE, &meta,
                                                out, &outSz);
}
static int _InvokeDataWrap(whClientContext* c)
{
    uint8_t  out[OUT_BUF_SZ];
    uint32_t outSz = sizeof(out);
    return wh_Client_DataWrapResponse(c, TEST_CIPHER_TYPE, out, &outSz);
}
static int _InvokeDataUnwrap(whClientContext* c)
{
    uint8_t  out[OUT_BUF_SZ];
    uint32_t outSz = sizeof(out);
    return wh_Client_DataUnwrapResponse(c, TEST_CIPHER_TYPE, out, &outSz);
}

int whTest_KeyWrapRespSize(void* ctx)
{
    whMessageKeystore_KeyWrapResponse            keyWrapResp;
    whMessageKeystore_KeyUnwrapAndExportResponse keyUnwrapResp;
    whMessageKeystore_DataWrapResponse           dataWrapResp;
    whMessageKeystore_DataUnwrapResponse         dataUnwrapResp;

    (void)ctx;

    memset(&keyWrapResp, 0, sizeof(keyWrapResp));
    keyWrapResp.cipherType   = TEST_CIPHER_TYPE;
    keyWrapResp.wrappedKeySz = MALFORMED_TRAILING_SZ;

    memset(&keyUnwrapResp, 0, sizeof(keyUnwrapResp));
    keyUnwrapResp.cipherType = TEST_CIPHER_TYPE;
    keyUnwrapResp.keySz      = MALFORMED_TRAILING_SZ;

    memset(&dataWrapResp, 0, sizeof(dataWrapResp));
    dataWrapResp.cipherType    = TEST_CIPHER_TYPE;
    dataWrapResp.wrappedDataSz = MALFORMED_TRAILING_SZ;

    memset(&dataUnwrapResp, 0, sizeof(dataUnwrapResp));
    dataUnwrapResp.cipherType = TEST_CIPHER_TYPE;
    dataUnwrapResp.dataSz     = MALFORMED_TRAILING_SZ;

    WH_TEST_RETURN_ON_FAIL(_RunCase(WH_KEY_KEYWRAP, &keyWrapResp,
                                    (uint16_t)sizeof(keyWrapResp),
                                    _InvokeKeyWrap));
    WH_TEST_RETURN_ON_FAIL(_RunCase(WH_KEY_KEYUNWRAPEXPORT, &keyUnwrapResp,
                                    (uint16_t)sizeof(keyUnwrapResp),
                                    _InvokeKeyUnwrapAndExport));
    WH_TEST_RETURN_ON_FAIL(_RunCase(WH_KEY_DATAWRAP, &dataWrapResp,
                                    (uint16_t)sizeof(dataWrapResp),
                                    _InvokeDataWrap));
    WH_TEST_RETURN_ON_FAIL(_RunCase(WH_KEY_DATAUNWRAP, &dataUnwrapResp,
                                    (uint16_t)sizeof(dataUnwrapResp),
                                    _InvokeDataUnwrap));
    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_KEYWRAP && CLIENT && !NO_CRYPTO */
