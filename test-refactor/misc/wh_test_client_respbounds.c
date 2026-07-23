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
/* test-refactor/misc/wh_test_client_respbounds.c
 *
 * Verify the client bounds response data against the received frame. */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/hash.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(HAVE_HKDF) || defined(HAVE_CMAC_KDF)

/* Output buffer the caller offers, and the size the stub server claims to
 * have derived. Large enough that the declared size passes the client's
 * caller-buffer check and only a frame-length check can reject it. */
#define WH_TEST_RESPBOUNDS_OUT_SIZE 256
#define WH_TEST_RESPBOUNDS_BODY_MAX 128
#define WH_TEST_RESPBOUNDS_POISON 0xA5
#define WH_TEST_RESPBOUNDS_CASE_COUNT 2

/* Body lengths to reply with: a full response header carrying no key material,
 * then a frame too short to even hold the response header */
#define WH_TEST_RESPBOUNDS_LEN_NODATA                     \
    (uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
               sizeof(whMessageCrypto_HkdfResponse))
#define WH_TEST_RESPBOUNDS_LEN_SHORT                      \
    (uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
               sizeof(uint32_t))

/* Stub transport state: the request header to echo and the canned reply */
typedef struct {
    whCommHeader reqHdr;
    uint8_t      body[WH_TEST_RESPBOUNDS_BODY_MAX];
    uint16_t     bodyLen;
    int          pending;
} whTestRespBoundsCtx;

static int _stubInit(void* context, const void* config,
                     whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    (void)config;
    (void)connectcb;
    (void)connectcb_arg;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }
    ((whTestRespBoundsCtx*)context)->pending = 0;
    return WH_ERROR_OK;
}

/* Capture the request header so the reply can echo its kind and sequence */
static int _stubSend(void* context, uint16_t size, const void* data)
{
    whTestRespBoundsCtx* ctx = (whTestRespBoundsCtx*)context;

    if ((ctx == NULL) || (data == NULL) || (size < sizeof(whCommHeader))) {
        return WH_ERROR_BADARGS;
    }

    memcpy(&ctx->reqHdr, data, sizeof(ctx->reqHdr));
    ctx->pending = 1;
    return WH_ERROR_OK;
}

/* Reply with the canned body, reporting only the bytes the test staged */
static int _stubRecv(void* context, uint16_t* out_size, void* data)
{
    whTestRespBoundsCtx* ctx = (whTestRespBoundsCtx*)context;
    whCommHeader*        hdr = (whCommHeader*)data;

    if ((ctx == NULL) || (out_size == NULL) || (data == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->pending == 0) {
        return WH_ERROR_NOTREADY;
    }

    memcpy(hdr, &ctx->reqHdr, sizeof(*hdr));
    hdr->aux = WH_COMM_AUX_RESP_OK;
    memcpy((uint8_t*)data + sizeof(*hdr), ctx->body, ctx->bodyLen);

    *out_size    = (uint16_t)(sizeof(*hdr) + ctx->bodyLen);
    ctx->pending = 0;
    return WH_ERROR_OK;
}

static int _stubCleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static const whTransportClientCb _stubCb = {
    _stubInit,
    _stubSend,
    _stubRecv,
    _stubCleanup,
};

/* Stage a KDF response declaring outSz bytes of key material while reporting
 * only bodyLen bytes. Both KDF response structs share the same layout. */
static void _stageKdfResponse(whTestRespBoundsCtx* ctx, uint32_t outSz,
                              uint16_t bodyLen)
{
    whMessageCrypto_GenericResponseHeader* genHdr =
        (whMessageCrypto_GenericResponseHeader*)ctx->body;
    whMessageCrypto_HkdfResponse* res =
        (whMessageCrypto_HkdfResponse*)(genHdr + 1);

    memset(ctx->body, 0, sizeof(ctx->body));
    genHdr->algoType = WC_ALGO_TYPE_KDF;
    genHdr->rc       = WH_ERROR_OK;
    res->keyIdOut    = WH_KEYID_ERASED;
    res->outSz       = outSz;
    ctx->bodyLen     = bodyLen;
}

/* Confirm the client left the caller's buffer alone */
static int _outputUntouched(const uint8_t* out, uint32_t outSz)
{
    uint32_t i;

    for (i = 0; i < outSz; i++) {
        if (out[i] != WH_TEST_RESPBOUNDS_POISON) {
            return 0;
        }
    }
    return 1;
}

#ifdef HAVE_HKDF
static int _whTest_ClientRespBoundsHkdf(void)
{
    const uint16_t bodyLens[WH_TEST_RESPBOUNDS_CASE_COUNT] = {
        WH_TEST_RESPBOUNDS_LEN_NODATA, WH_TEST_RESPBOUNDS_LEN_SHORT};
    whTestRespBoundsCtx stub[1]    = {{{0, 0, 0, 0}, {0}, 0, 0}};
    whCommClientConfig  cc_conf[1] = {{0}};
    whClientConfig      c_conf[1]  = {{0}};
    whClientContext     client[1]  = {{0}};
    uint8_t             ikm[32];
    uint8_t             out[WH_TEST_RESPBOUNDS_OUT_SIZE];
    int                 ret;
    int                 i;

    cc_conf->transport_cb      = &_stubCb;
    cc_conf->transport_context = (void*)stub;
    cc_conf->client_id         = WH_TEST_DEFAULT_CLIENT_ID;
    c_conf->comm               = cc_conf;

    memset(ikm, 0x0b, sizeof(ikm));

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    for (i = 0; i < WH_TEST_RESPBOUNDS_CASE_COUNT; i++) {
        WH_TEST_PRINT("  HKDF response body length %u\n",
                      (unsigned int)bodyLens[i]);
        memset(out, WH_TEST_RESPBOUNDS_POISON, sizeof(out));
        _stageKdfResponse(stub, WH_TEST_RESPBOUNDS_OUT_SIZE, bodyLens[i]);

        ret = wh_Client_HkdfMakeExportKey(client, WC_SHA256, WH_KEYID_ERASED,
                                          ikm, (uint32_t)sizeof(ikm), NULL, 0,
                                          NULL, 0, out, (uint32_t)sizeof(out));

        WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
        WH_TEST_ASSERT_RETURN(_outputUntouched(out, (uint32_t)sizeof(out)));
    }

    (void)wh_Client_Cleanup(client);

    return WH_ERROR_OK;
}
#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
static int _whTest_ClientRespBoundsCmacKdf(void)
{
    const uint16_t bodyLens[WH_TEST_RESPBOUNDS_CASE_COUNT] = {
        WH_TEST_RESPBOUNDS_LEN_NODATA, WH_TEST_RESPBOUNDS_LEN_SHORT};
    whTestRespBoundsCtx stub[1]    = {{{0, 0, 0, 0}, {0}, 0, 0}};
    whCommClientConfig  cc_conf[1] = {{0}};
    whClientConfig      c_conf[1]  = {{0}};
    whClientContext     client[1]  = {{0}};
    uint8_t             z[32];
    uint8_t             out[WH_TEST_RESPBOUNDS_OUT_SIZE];
    int                 ret;
    int                 i;

    cc_conf->transport_cb      = &_stubCb;
    cc_conf->transport_context = (void*)stub;
    cc_conf->client_id         = WH_TEST_DEFAULT_CLIENT_ID;
    c_conf->comm               = cc_conf;

    memset(z, 0x5c, sizeof(z));

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    for (i = 0; i < WH_TEST_RESPBOUNDS_CASE_COUNT; i++) {
        WH_TEST_PRINT("  CMAC-KDF response body length %u\n",
                      (unsigned int)bodyLens[i]);
        memset(out, WH_TEST_RESPBOUNDS_POISON, sizeof(out));
        _stageKdfResponse(stub, WH_TEST_RESPBOUNDS_OUT_SIZE, bodyLens[i]);

        ret = wh_Client_CmacKdfMakeExportKey(
            client, WH_KEYID_ERASED, NULL, 0, WH_KEYID_ERASED, z,
            (uint32_t)sizeof(z), NULL, 0, out, (uint32_t)sizeof(out));

        WH_TEST_ASSERT_RETURN(ret == WH_ERROR_ABORTED);
        WH_TEST_ASSERT_RETURN(_outputUntouched(out, (uint32_t)sizeof(out)));
    }

    (void)wh_Client_Cleanup(client);

    return WH_ERROR_OK;
}
#endif /* HAVE_CMAC_KDF */

int whTest_ClientRespBounds(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client response bounds checking...\n");

#ifdef HAVE_HKDF
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientRespBoundsHkdf());
#endif
#ifdef HAVE_CMAC_KDF
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientRespBoundsCmacKdf());
#endif

    return WH_ERROR_OK;
}

#endif /* HAVE_HKDF || HAVE_CMAC_KDF */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && !WOLFHSM_CFG_NO_CRYPTO */
