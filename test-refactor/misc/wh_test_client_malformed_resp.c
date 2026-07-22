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
 * Client-side hardening against malformed server responses. Driven by a raw
 * comm server, so a reply can carry the correct kind and sequence while
 * declaring a bogus payload size.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_counter.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_message_keystore.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_transport_mem.h"
#include "wolfhsm/wh_utils.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#define WH_TEST_MR_BUFFER_SIZE 4096
/* Largest frame both ends carry: the transport buffer less its CSR and the
 * comm header, capped by the comm payload limit */
#define WH_TEST_MR_TRANSPORT_MAX                                    \
    (WH_TEST_MR_BUFFER_SIZE - sizeof(whTransportMemCsr) -           \
     sizeof(whCommHeader))
#define WH_TEST_MR_OVERSIZED_SZ                                \
    ((WOLFHSM_CFG_COMM_DATA_LEN < WH_TEST_MR_TRANSPORT_MAX)    \
         ? (size_t)WOLFHSM_CFG_COMM_DATA_LEN                   \
         : WH_TEST_MR_TRANSPORT_MAX)
#define WH_TEST_MR_KEY_SZ 32
#define WH_TEST_MR_POISON 0xA5
#define WH_TEST_MR_KEY_ID 1
#define WH_TEST_MR_COUNTER_ID 1

/* The oversized frame must outgrow every response struct it is sent to, or
 * those handlers never see an over-long reply */
WH_UTILS_STATIC_ASSERT(WH_TEST_MR_OVERSIZED_SZ >
                           sizeof(whMessageCustomCb_Response),
                       "oversized frame too small to overrun the responses");
WH_UTILS_STATIC_ASSERT(WH_TEST_MR_OVERSIZED_SZ >
                           sizeof(whMessageCommInfoResponse),
                       "oversized frame too small to overrun the responses");

/* The fixed-size response handlers, dispatched by index */
enum {
    WH_TEST_MR_KEY_CACHE = 0,
    WH_TEST_MR_KEY_CACHE_RANDOM,
    WH_TEST_MR_KEY_EVICT,
    WH_TEST_MR_KEY_COMMIT,
    WH_TEST_MR_KEY_ERASE,
    WH_TEST_MR_KEY_REVOKE,
    WH_TEST_MR_COUNTER_INIT,
    WH_TEST_MR_COUNTER_INCREMENT,
    WH_TEST_MR_COUNTER_READ,
    WH_TEST_MR_COUNTER_DESTROY,
    WH_TEST_MR_FIXED_COUNT
};

typedef struct {
    const char* name;
    uint16_t    respSz;
} whFixedCase;

static const whFixedCase _fixedCase[] = {
    {"KeyCache", (uint16_t)sizeof(whMessageKeystore_CacheResponse)},
    {"KeyCacheRandom", (uint16_t)sizeof(whMessageKeystore_CacheRandomResponse)},
    {"KeyEvict", (uint16_t)sizeof(whMessageKeystore_EvictResponse)},
    {"KeyCommit", (uint16_t)sizeof(whMessageKeystore_CommitResponse)},
    {"KeyErase", (uint16_t)sizeof(whMessageKeystore_EraseResponse)},
    {"KeyRevoke", (uint16_t)sizeof(whMessageKeystore_RevokeResponse)},
    {"CounterInit", (uint16_t)sizeof(whMessageCounter_InitResponse)},
    {"CounterIncrement",
     (uint16_t)sizeof(whMessageCounter_IncrementResponse)},
    {"CounterRead", (uint16_t)sizeof(whMessageCounter_ReadResponse)},
    {"CounterDestroy", (uint16_t)sizeof(whMessageCounter_DestroyResponse)},
};

typedef struct {
    whClientContext client[1];
    whCommServer    server[1];
    /* Mem transport shared by the client and the raw comm server */
    uint8_t                     reqBuf[WH_TEST_MR_BUFFER_SIZE];
    uint8_t                     respBuf[WH_TEST_MR_BUFFER_SIZE];
    whTransportMemConfig        tmcf[1];
    whTransportClientCb         tccb[1];
    whTransportMemClientContext tmcc[1];
    whCommClientConfig          cc_conf[1];
    whClientConfig              c_conf[1];
    whTransportServerCb         tscb[1];
    whTransportMemServerContext tmsc[1];
    whCommServerConfig          cs_conf[1];
} TestCtx;

/* Frame buffers are static to keep WOLFHSM_CFG_COMM_DATA_LEN off the stack */
static uint8_t _rxReq[WOLFHSM_CFG_COMM_DATA_LEN];
static uint8_t _txResp[WOLFHSM_CFG_COMM_DATA_LEN];

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

/* Consume the pending request and answer it from _txResp, declaring frameLen
 * bytes regardless of what the message actually needs */
static int _ReplyWith(TestCtx* t, uint16_t frameLen)
{
    int      ret   = 0;
    uint16_t magic = 0;
    uint16_t kind  = 0;
    uint16_t seq   = 0;
    uint16_t len   = 0;

    ret = wh_CommServer_RecvRequest(t->server, &magic, &kind, &seq, &len,
                                    sizeof(_rxReq), _rxReq);
    if (ret == WH_ERROR_OK) {
        ret = wh_CommServer_SendResponse(t->server, magic, kind, seq, frameLen,
                                         _txResp);
    }
    return ret;
}

/* Issue the request for a fixed-size case so the reply's kind and seq line up */
static int _FixedRequest(TestCtx* t, int idx)
{
    int     ret = WH_ERROR_BADARGS;
    uint8_t key[WH_TEST_MR_KEY_SZ];

    memset(key, WH_TEST_MR_POISON, sizeof(key));

    switch (idx) {
        case WH_TEST_MR_KEY_CACHE:
            ret = wh_Client_KeyCacheRequest(t->client, 0, NULL, 0, key,
                                            sizeof(key));
            break;
        case WH_TEST_MR_KEY_CACHE_RANDOM:
            ret = wh_Client_KeyCacheRandomRequest(t->client, 0, NULL, 0,
                                                  sizeof(key),
                                                  WH_TEST_MR_KEY_ID);
            break;
        case WH_TEST_MR_KEY_EVICT:
            ret = wh_Client_KeyEvictRequest(t->client, WH_TEST_MR_KEY_ID);
            break;
        case WH_TEST_MR_KEY_COMMIT:
            ret = wh_Client_KeyCommitRequest(t->client, WH_TEST_MR_KEY_ID);
            break;
        case WH_TEST_MR_KEY_ERASE:
            ret = wh_Client_KeyEraseRequest(t->client, WH_TEST_MR_KEY_ID);
            break;
        case WH_TEST_MR_KEY_REVOKE:
            ret = wh_Client_KeyRevokeRequest(t->client, WH_TEST_MR_KEY_ID);
            break;
        case WH_TEST_MR_COUNTER_INIT:
            ret = wh_Client_CounterInitRequest(t->client,
                                               WH_TEST_MR_COUNTER_ID, 0);
            break;
        case WH_TEST_MR_COUNTER_INCREMENT:
            ret = wh_Client_CounterIncrementRequest(t->client,
                                                    WH_TEST_MR_COUNTER_ID);
            break;
        case WH_TEST_MR_COUNTER_READ:
            ret = wh_Client_CounterReadRequest(t->client,
                                               WH_TEST_MR_COUNTER_ID);
            break;
        case WH_TEST_MR_COUNTER_DESTROY:
            ret = wh_Client_CounterDestroyRequest(t->client,
                                                  WH_TEST_MR_COUNTER_ID);
            break;
        default:
            break;
    }
    return ret;
}

static int _FixedResponse(TestCtx* t, int idx)
{
    int      ret     = WH_ERROR_BADARGS;
    uint16_t keyId   = 0;
    uint32_t counter = 0;

    switch (idx) {
        case WH_TEST_MR_KEY_CACHE:
            ret = wh_Client_KeyCacheResponse(t->client, &keyId);
            break;
        case WH_TEST_MR_KEY_CACHE_RANDOM:
            ret = wh_Client_KeyCacheRandomResponse(t->client, &keyId);
            break;
        case WH_TEST_MR_KEY_EVICT:
            ret = wh_Client_KeyEvictResponse(t->client);
            break;
        case WH_TEST_MR_KEY_COMMIT:
            ret = wh_Client_KeyCommitResponse(t->client);
            break;
        case WH_TEST_MR_KEY_ERASE:
            ret = wh_Client_KeyEraseResponse(t->client);
            break;
        case WH_TEST_MR_KEY_REVOKE:
            ret = wh_Client_KeyRevokeResponse(t->client);
            break;
        case WH_TEST_MR_COUNTER_INIT:
            ret = wh_Client_CounterInitResponse(t->client, &counter);
            break;
        case WH_TEST_MR_COUNTER_INCREMENT:
            ret = wh_Client_CounterIncrementResponse(t->client, &counter);
            break;
        case WH_TEST_MR_COUNTER_READ:
            ret = wh_Client_CounterReadResponse(t->client, &counter);
            break;
        case WH_TEST_MR_COUNTER_DESTROY:
            ret = wh_Client_CounterDestroyResponse(t->client);
            break;
        default:
            break;
    }
    return ret;
}

/* Every fixed-size handler, at the exact bound: reject a frame one byte short
 * of the response struct, accept one sitting exactly on it. The short frame is
 * all-ones so a missing size gate surfaces as a stale nonzero rc. */
static int _whTest_MalformedRespFixed(TestCtx* t)
{
    int ret = 0;
    int i   = 0;

    for (i = 0; i < WH_TEST_MR_FIXED_COUNT; i++) {
        memset(_txResp, 0xFF, sizeof(_txResp));
        WH_TEST_RETURN_ON_FAIL(_FixedRequest(t, i));
        WH_TEST_RETURN_ON_FAIL(
            _ReplyWith(t, (uint16_t)(_fixedCase[i].respSz - 1)));

        ret = _FixedResponse(t, i);
        if (ret != WH_ERROR_ABORTED) {
            WH_ERROR_PRINT("%s accepted a short response: %d\n",
                           _fixedCase[i].name, ret);
            return WH_ERROR_ABORTED;
        }

        /* rc of zero, so only the size can decide the outcome */
        memset(_txResp, 0, sizeof(_txResp));
        WH_TEST_RETURN_ON_FAIL(_FixedRequest(t, i));
        WH_TEST_RETURN_ON_FAIL(_ReplyWith(t, _fixedCase[i].respSz));

        ret = _FixedResponse(t, i);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("%s rejected a well-formed response: %d\n",
                           _fixedCase[i].name, ret);
            return WH_ERROR_ABORTED;
        }
    }

    return WH_ERROR_OK;
}

/* Craft a key export reply declaring claimedLen bytes of key material while
 * handing the transport only payloadSz bytes of it */
static int _ReplyWithExport(TestCtx* t, uint32_t claimedLen, uint16_t payloadSz,
                            uint16_t frameLen)
{
    whMessageKeystore_ExportResponse* resp =
        (whMessageKeystore_ExportResponse*)_txResp;

    memset(_txResp, 0, sizeof(_txResp));
    resp->rc  = 0;
    resp->len = claimedLen;
    memset((uint8_t*)(resp + 1), WH_TEST_MR_POISON, payloadSz);

    return _ReplyWith(t, frameLen);
}

/* A response claiming more key material than the frame carried must be
 * rejected instead of copying whatever trails the payload - which, on a
 * request/response buffer, is the client's own outbound request. */
static int _whTest_MalformedRespKeyExport(TestCtx* t)
{
    int      ret    = 0;
    int      i      = 0;
    uint16_t hdrSz  = (uint16_t)sizeof(whMessageKeystore_ExportResponse);
    uint16_t outSz  = 0;
    uint8_t  out[WH_TEST_MR_KEY_SZ * 2];
    uint8_t  label[WH_NVM_LABEL_LEN];

    /* Well-formed exchange first, so the comm buffer holds a known pattern
     * past the header for the malformed exchanges to expose */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportRequest(t->client, WH_TEST_MR_KEY_ID));
    WH_TEST_RETURN_ON_FAIL(_ReplyWithExport(t, WH_TEST_MR_KEY_SZ,
                                            WH_TEST_MR_KEY_SZ,
                                            (uint16_t)(hdrSz +
                                                       WH_TEST_MR_KEY_SZ)));
    outSz = sizeof(out);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportResponse(
        t->client, label, sizeof(label), out, &outSz));
    WH_TEST_ASSERT_RETURN(outSz == WH_TEST_MR_KEY_SZ);
    for (i = 0; i < WH_TEST_MR_KEY_SZ; i++) {
        WH_TEST_ASSERT_RETURN(out[i] == WH_TEST_MR_POISON);
    }

    /* One byte past the payload the frame actually carried */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportRequest(t->client, WH_TEST_MR_KEY_ID));
    WH_TEST_RETURN_ON_FAIL(_ReplyWithExport(
        t, WH_TEST_MR_KEY_SZ + 1, WH_TEST_MR_KEY_SZ,
        (uint16_t)(hdrSz + WH_TEST_MR_KEY_SZ)));
    outSz = sizeof(out);
    ret   = wh_Client_KeyExportResponse(t->client, label, sizeof(label), out,
                                        &outSz);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
    /* Nothing may have been copied out of the comm buffer */
    for (i = 0; i < (int)sizeof(out); i++) {
        WH_TEST_ASSERT_RETURN(out[i] == 0);
    }

    /* A frame too short for even the fixed fields */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportRequest(t->client, WH_TEST_MR_KEY_ID));
    WH_TEST_RETURN_ON_FAIL(
        _ReplyWithExport(t, WH_TEST_MR_KEY_SZ, 0, (uint16_t)(hdrSz - 1)));
    outSz = sizeof(out);
    ret   = wh_Client_KeyExportResponse(t->client, label, sizeof(label), out,
                                        &outSz);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
    for (i = 0; i < (int)sizeof(out); i++) {
        WH_TEST_ASSERT_RETURN(out[i] == 0);
    }

    return WH_ERROR_OK;
}

/* Same bound, on the public-key export path */
static int _whTest_MalformedRespKeyExportPublic(TestCtx* t)
{
    int      ret   = 0;
    int      i     = 0;
    uint16_t hdrSz = (uint16_t)sizeof(whMessageKeystore_ExportPublicResponse);
    uint16_t outSz = 0;
    uint8_t  out[WH_TEST_MR_KEY_SZ * 2];
    uint8_t  label[WH_NVM_LABEL_LEN];

    WH_TEST_ASSERT_RETURN(sizeof(whMessageKeystore_ExportPublicResponse) ==
                          sizeof(whMessageKeystore_ExportResponse));

    /* Declared length one past the payload received */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportPublicRequest(t->client, WH_TEST_MR_KEY_ID, 0));
    WH_TEST_RETURN_ON_FAIL(_ReplyWithExport(
        t, WH_TEST_MR_KEY_SZ + 1, WH_TEST_MR_KEY_SZ,
        (uint16_t)(hdrSz + WH_TEST_MR_KEY_SZ)));
    outSz = sizeof(out);
    ret = wh_Client_KeyExportPublicResponse(t->client, label, sizeof(label),
                                            out, &outSz);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
    for (i = 0; i < (int)sizeof(out); i++) {
        WH_TEST_ASSERT_RETURN(out[i] == 0);
    }

    /* Exactly on the bound is accepted */
    memset(out, 0, sizeof(out));
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyExportPublicRequest(t->client, WH_TEST_MR_KEY_ID, 0));
    WH_TEST_RETURN_ON_FAIL(_ReplyWithExport(t, WH_TEST_MR_KEY_SZ,
                                            WH_TEST_MR_KEY_SZ,
                                            (uint16_t)(hdrSz +
                                                       WH_TEST_MR_KEY_SZ)));
    outSz = sizeof(out);
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyExportPublicResponse(
        t->client, label, sizeof(label), out, &outSz));
    WH_TEST_ASSERT_RETURN(outSz == WH_TEST_MR_KEY_SZ);
    for (i = 0; i < WH_TEST_MR_KEY_SZ; i++) {
        WH_TEST_ASSERT_RETURN(out[i] == WH_TEST_MR_POISON);
    }

    return WH_ERROR_OK;
}

/* A reply far larger than the response struct. The comm layer copies the whole
 * payload into the buffer it is handed, so these handlers must not hand it a
 * buffer smaller than a maximum-size frame. */
static int _whTest_MalformedRespOversized(TestCtx* t)
{
    int                        ret = 0;
    whMessageCustomCb_Response customResp;

    memset(_txResp, 0, sizeof(_txResp));

    /* Fixed-size keystore handler: the frame is oversized but well-formed up
     * front, so the crafted rc of zero comes back */
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_KeyEvictRequest(t->client, WH_TEST_MR_KEY_ID));
    WH_TEST_RETURN_ON_FAIL(_ReplyWith(t, (uint16_t)WH_TEST_MR_OVERSIZED_SZ));
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvictResponse(t->client));

    /* Handlers validating an exact size reject the frame outright */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInitRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(_ReplyWith(t, (uint16_t)WH_TEST_MR_OVERSIZED_SZ));
    ret = wh_Client_CommInitResponse(t->client, NULL, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CommInfoRequest(t->client));
    WH_TEST_RETURN_ON_FAIL(_ReplyWith(t, (uint16_t)WH_TEST_MR_OVERSIZED_SZ));
    ret = wh_Client_CommInfoResponse(t->client, NULL, NULL, NULL, NULL, NULL,
                                     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                     NULL, NULL);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    memset(&customResp, 0, sizeof(customResp));
    WH_TEST_RETURN_ON_FAIL(wh_Client_CustomCheckRegisteredRequest(
        t->client, WH_MESSAGE_CUSTOM_CB_TYPE_QUERY));
    WH_TEST_RETURN_ON_FAIL(_ReplyWith(t, (uint16_t)WH_TEST_MR_OVERSIZED_SZ));
    ret = wh_Client_CustomCbResponse(t->client, &customResp);
    WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);

    return WH_ERROR_OK;
}

int whTest_ClientMalformedResp(void* ctx)
{
    TestCtx t[1];

    (void)ctx;

    WH_TEST_RETURN_ON_FAIL(_SetupClientServer(t));

    WH_TEST_PRINT("Testing client handling of malformed responses...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_MalformedRespFixed(t));
    WH_TEST_RETURN_ON_FAIL(_whTest_MalformedRespKeyExport(t));
    WH_TEST_RETURN_ON_FAIL(_whTest_MalformedRespKeyExportPublic(t));
    WH_TEST_RETURN_ON_FAIL(_whTest_MalformedRespOversized(t));

    _CleanupClientServer(t);

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */
