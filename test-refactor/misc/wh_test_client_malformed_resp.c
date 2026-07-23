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
 * Client-side hardening against malformed server responses. The client APIs
 * exercised here send and receive within one blocking call, so the test
 * installs a scripted transport that answers each request with a frame a real
 * server would never emit.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#ifdef WOLFSSL_CMAC

#include "wolfssl/wolfcrypt/cmac.h"

#define WH_TEST_MR_POISON 0xA5
#define WH_TEST_MR_TAG_SZ 16

/* Bytes a CMAC response spends on headers before the MAC payload */
#define WH_TEST_MR_CMAC_HDR_SZ                                  \
    ((uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
                sizeof(whMessageCrypto_CmacAesResponse)))

#ifdef WOLFHSM_CFG_DMA
#define WH_TEST_MR_CMAC_DMA_HDR_SZ                              \
    ((uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
                sizeof(whMessageCrypto_CmacAesDmaResponse)))
#endif

/* Scripted transport state. Each exchange is described before the client call
 * that triggers it, so a response can advertise a MAC the frame does not
 * actually carry. */
typedef struct {
    uint8_t  request[WH_COMM_MTU];
    uint32_t claimedOutSz; /* value written to res->outSz */
    int32_t  rc;           /* crypto response header rc */
    uint16_t payloadLen;   /* MAC bytes actually written after the response */
    uint16_t frameLen;     /* crypto bytes handed back to the client */
    uint8_t  dma;          /* selects the DMA response layout */
    uint8_t  fill;
    uint8_t  pending;
} whTestMrTransport;

static int _mrTransportInit(void* context, const void* config,
                            whCommSetConnectedCb connectcb, void* connectcb_arg)
{
    whTestMrTransport* xport = (whTestMrTransport*)context;

    (void)config;
    (void)connectcb;
    (void)connectcb_arg;

    if (xport == NULL) {
        return WH_ERROR_BADARGS;
    }
    xport->pending = 0;
    return WH_ERROR_OK;
}

static int _mrTransportSend(void* context, uint16_t size, const void* data)
{
    whTestMrTransport* xport = (whTestMrTransport*)context;

    if ((xport == NULL) || (data == NULL) || (size > sizeof(xport->request))) {
        return WH_ERROR_BADARGS;
    }
    memcpy(xport->request, data, size);
    xport->pending = 1;
    return WH_ERROR_OK;
}

/* Answers the pending request with the scripted frame. The body is always
 * written whatever frameLen says: under-reporting what was written is what
 * makes the frame malformed, and it keeps the two bounds separable. */
static int _mrTransportRecv(void* context, uint16_t* out_size, void* data)
{
    whTestMrTransport*                     xport = (whTestMrTransport*)context;
    whCommHeader*                          hdr;
    whMessageCrypto_GenericResponseHeader* res_hdr;
    whMessageCrypto_CmacAesResponse*       res;
    uint8_t*                               mac;
#ifdef WOLFHSM_CFG_DMA
    whMessageCrypto_CmacAesDmaResponse* dma_res;
#endif

    if ((xport == NULL) || (out_size == NULL) || (data == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (xport->pending == 0) {
        return WH_ERROR_NOTREADY;
    }
    xport->pending = 0;

    /* Echo the request header so magic, kind and sequence all match */
    memcpy(data, xport->request, sizeof(whCommHeader));
    hdr      = (whCommHeader*)data;
    hdr->aux = 0;

    res_hdr = (whMessageCrypto_GenericResponseHeader*)((uint8_t*)data +
                                                       sizeof(*hdr));
    res_hdr->algoType = WC_ALGO_TYPE_CMAC;
    res_hdr->rc       = xport->rc;
    res_hdr->reserved = 0;

    mac = NULL;
#ifdef WOLFHSM_CFG_DMA
    if (xport->dma != 0) {
        dma_res = (whMessageCrypto_CmacAesDmaResponse*)(res_hdr + 1);
        memset(dma_res, 0, sizeof(*dma_res));
        dma_res->outSz = xport->claimedOutSz;
        dma_res->keyId = WH_KEYID_ERASED;
        mac            = (uint8_t*)(dma_res + 1);
    }
    else
#endif
    {
        res = (whMessageCrypto_CmacAesResponse*)(res_hdr + 1);
        memset(res, 0, sizeof(*res));
        res->outSz = xport->claimedOutSz;
        res->keyId = WH_KEYID_ERASED;
        mac        = (uint8_t*)(res + 1);
    }

    if (xport->payloadLen > 0) {
        memset(mac, xport->fill, xport->payloadLen);
    }

    *out_size = (uint16_t)(sizeof(*hdr) + xport->frameLen);
    return WH_ERROR_OK;
}

static int _mrTransportCleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

/* A CMAC response claiming more MAC bytes than the frame carried must be
 * rejected instead of handing the caller whatever trails the response body. */
static int _whTest_ClientCmacTruncatedResponse(void)
{
    whTestMrTransport         xport[1] = {0};
    const whTransportClientCb tccb[1]  = {{
         .Init    = _mrTransportInit,
         .Send    = _mrTransportSend,
         .Recv    = _mrTransportRecv,
         .Cleanup = _mrTransportCleanup,
    }};
    whCommClientConfig        cc_conf[1] = {{
               .transport_cb      = tccb,
               .transport_context = (void*)xport,
               .transport_config  = NULL,
               .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientContext           client[1]  = {0};
    whClientConfig            c_conf[1]  = {{
                   .comm = cc_conf,
    }};

    Cmac     cmac[1];
    uint8_t  key[WH_TEST_MR_TAG_SZ];
    uint8_t  in[WH_TEST_MR_TAG_SZ];
    uint8_t  mac[WH_TEST_MR_TAG_SZ];
    uint32_t macLen = 0;
    bool     sent   = false;
    int      i      = 0;
    int      rc     = 0;

    memset(key, 0x0B, sizeof(key));
    memset(in, 0x0C, sizeof(in));

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Well-formed oneshot first. The frame carries the MAC it claims, so it
     * must be accepted, and it leaves a known pattern in the client packet
     * buffer for the malformed exchanges to expose. */
    memset(cmac, 0, sizeof(cmac));
    memset(mac, 0, sizeof(mac));
    xport->dma          = 0;
    xport->rc           = WH_ERROR_OK;
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ;
    xport->fill         = WH_TEST_MR_POISON;
    xport->frameLen     = WH_TEST_MR_CMAC_HDR_SZ + WH_TEST_MR_TAG_SZ;
    macLen              = sizeof(mac);

    rc = wh_Client_CmacGenerateRequest(client, cmac, WC_CMAC_AES, key,
                                       sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(macLen == WH_TEST_MR_TAG_SZ);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == WH_TEST_MR_POISON);
    }

    /* One MAC byte short of the claim: the last byte the client would copy was
     * never delivered. The caller's buffer is big enough for the claim, so
     * only the frame bound can reject this. */
    memset(cmac, 0, sizeof(cmac));
    memset(mac, 0, sizeof(mac));
    xport->frameLen = WH_TEST_MR_CMAC_HDR_SZ + WH_TEST_MR_TAG_SZ - 1;
    macLen          = sizeof(mac);

    rc = wh_Client_CmacGenerateRequest(client, cmac, WC_CMAC_AES, key,
                                       sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* Exactly the claim is still accepted, so the bound cannot be off by one */
    memset(cmac, 0, sizeof(cmac));
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ - 1;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ - 1;
    xport->frameLen     = WH_TEST_MR_CMAC_HDR_SZ + WH_TEST_MR_TAG_SZ - 1;
    macLen              = sizeof(mac);

    rc = wh_Client_CmacGenerateRequest(client, cmac, WC_CMAC_AES, key,
                                       sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(macLen == WH_TEST_MR_TAG_SZ - 1);

    /* A header-only reply carrying a server error must still surface that
     * error rather than the new frame bound */
    memset(cmac, 0, sizeof(cmac));
    xport->rc         = WH_ERROR_ACCESS;
    xport->payloadLen = 0;
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);
    macLen          = sizeof(mac);

    rc = wh_Client_CmacGenerateRequest(client, cmac, WC_CMAC_AES, key,
                                       sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);

    /* A success reply too short for the response struct: every field the
     * client would read, the MAC length included, is stale */
    memset(cmac, 0, sizeof(cmac));
    memset(mac, 0, sizeof(mac));
    xport->rc           = WH_ERROR_OK;
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ;
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);
    macLen          = sizeof(mac);

    rc = wh_Client_CmacGenerateRequest(client, cmac, WC_CMAC_AES, key,
                                       sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* Update carries no MAC, but the state it restores must be in the frame.
     * One byte short of the response struct is a stale-state read. */
    memset(cmac, 0, sizeof(cmac));
    xport->rc           = WH_ERROR_OK;
    xport->claimedOutSz = 0;
    xport->payloadLen   = 0;
    xport->frameLen     = WH_TEST_MR_CMAC_HDR_SZ - 1;

    rc = wh_Client_CmacUpdateRequest(client, cmac, WC_CMAC_AES, key,
                                     sizeof(key), in, sizeof(in), &sent);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sent);
    rc = wh_Client_CmacUpdateResponse(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    /* The whole response struct is accepted */
    xport->frameLen = WH_TEST_MR_CMAC_HDR_SZ;

    rc = wh_Client_CmacUpdateRequest(client, cmac, WC_CMAC_AES, key,
                                     sizeof(key), in, sizeof(in), &sent);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sent);
    rc = wh_Client_CmacUpdateResponse(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Final claims a MAC the frame never carried */
    memset(mac, 0, sizeof(mac));
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ;
    xport->frameLen     = WH_TEST_MR_CMAC_HDR_SZ + WH_TEST_MR_TAG_SZ - 1;
    macLen              = sizeof(mac);

    rc = wh_Client_CmacFinalRequest(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacFinalResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* Final on a success reply too short for the response struct */
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);
    macLen          = sizeof(mac);

    rc = wh_Client_CmacFinalRequest(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacFinalResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* ...and is accepted once the frame carries it */
    xport->frameLen = WH_TEST_MR_CMAC_HDR_SZ + WH_TEST_MR_TAG_SZ;
    macLen          = sizeof(mac);

    rc = wh_Client_CmacFinalRequest(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacFinalResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(macLen == WH_TEST_MR_TAG_SZ);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA

/* The DMA responses return the MAC inline just like the non-DMA ones, so they
 * carry the same exposure and the same bound. */
static int _whTest_ClientCmacDmaTruncatedResponse(void)
{
    whTestMrTransport         xport[1] = {0};
    const whTransportClientCb tccb[1]  = {{
         .Init    = _mrTransportInit,
         .Send    = _mrTransportSend,
         .Recv    = _mrTransportRecv,
         .Cleanup = _mrTransportCleanup,
    }};
    whCommClientConfig        cc_conf[1] = {{
               .transport_cb      = tccb,
               .transport_context = (void*)xport,
               .transport_config  = NULL,
               .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientContext           client[1]  = {0};
    whClientConfig            c_conf[1]  = {{
                   .comm = cc_conf,
    }};

    Cmac     cmac[1];
    uint8_t  key[WH_TEST_MR_TAG_SZ];
    uint8_t  in[WH_TEST_MR_TAG_SZ];
    uint8_t  mac[WH_TEST_MR_TAG_SZ];
    uint32_t macLen = 0;
    bool     sent   = false;
    int      i      = 0;
    int      rc     = 0;

    memset(key, 0x0B, sizeof(key));
    memset(in, 0x0C, sizeof(in));

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Well-formed oneshot leaves the poison pattern behind the response */
    memset(cmac, 0, sizeof(cmac));
    memset(mac, 0, sizeof(mac));
    xport->dma          = 1;
    xport->rc           = WH_ERROR_OK;
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ;
    xport->fill         = WH_TEST_MR_POISON;
    xport->frameLen     = WH_TEST_MR_CMAC_DMA_HDR_SZ + WH_TEST_MR_TAG_SZ;
    macLen              = sizeof(mac);

    rc = wh_Client_CmacGenerateDmaRequest(client, cmac, WC_CMAC_AES, key,
                                          sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateDmaResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(macLen == WH_TEST_MR_TAG_SZ);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == WH_TEST_MR_POISON);
    }

    /* One MAC byte short of the claim */
    memset(cmac, 0, sizeof(cmac));
    memset(mac, 0, sizeof(mac));
    xport->frameLen = WH_TEST_MR_CMAC_DMA_HDR_SZ + WH_TEST_MR_TAG_SZ - 1;
    macLen          = sizeof(mac);

    rc = wh_Client_CmacGenerateDmaRequest(client, cmac, WC_CMAC_AES, key,
                                          sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateDmaResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* Exactly the claim is accepted */
    memset(cmac, 0, sizeof(cmac));
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ - 1;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ - 1;
    xport->frameLen     = WH_TEST_MR_CMAC_DMA_HDR_SZ + WH_TEST_MR_TAG_SZ - 1;
    macLen              = sizeof(mac);

    rc = wh_Client_CmacGenerateDmaRequest(client, cmac, WC_CMAC_AES, key,
                                          sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateDmaResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(macLen == WH_TEST_MR_TAG_SZ - 1);

    /* The DMA dispatcher replies with the generic header alone when a handler
     * fails, so that reply must keep returning the server's error */
    memset(cmac, 0, sizeof(cmac));
    xport->rc         = WH_ERROR_ACCESS;
    xport->payloadLen = 0;
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);
    macLen          = sizeof(mac);

    rc = wh_Client_CmacGenerateDmaRequest(client, cmac, WC_CMAC_AES, key,
                                          sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateDmaResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ACCESS);

    /* A success reply too short for the response struct */
    memset(cmac, 0, sizeof(cmac));
    memset(mac, 0, sizeof(mac));
    xport->rc           = WH_ERROR_OK;
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ;
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);
    macLen          = sizeof(mac);

    rc = wh_Client_CmacGenerateDmaRequest(client, cmac, WC_CMAC_AES, key,
                                          sizeof(key), in, sizeof(in), macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacGenerateDmaResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* DMA update: state restored from a frame too short to hold it */
    memset(cmac, 0, sizeof(cmac));
    xport->rc           = WH_ERROR_OK;
    xport->claimedOutSz = 0;
    xport->payloadLen   = 0;
    xport->frameLen     = WH_TEST_MR_CMAC_DMA_HDR_SZ - 1;

    rc = wh_Client_CmacDmaUpdateRequest(client, cmac, WC_CMAC_AES, key,
                                        sizeof(key), in, sizeof(in), &sent);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sent);
    rc = wh_Client_CmacDmaUpdateResponse(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    xport->frameLen = WH_TEST_MR_CMAC_DMA_HDR_SZ;

    rc = wh_Client_CmacDmaUpdateRequest(client, cmac, WC_CMAC_AES, key,
                                        sizeof(key), in, sizeof(in), &sent);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sent);
    rc = wh_Client_CmacDmaUpdateResponse(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* DMA final claims a MAC the frame never carried */
    memset(mac, 0, sizeof(mac));
    xport->claimedOutSz = WH_TEST_MR_TAG_SZ;
    xport->payloadLen   = WH_TEST_MR_TAG_SZ;
    xport->frameLen     = WH_TEST_MR_CMAC_DMA_HDR_SZ + WH_TEST_MR_TAG_SZ - 1;
    macLen              = sizeof(mac);

    rc = wh_Client_CmacDmaFinalRequest(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacDmaFinalResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    /* DMA final on a success reply too short for the response struct */
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);
    macLen          = sizeof(mac);

    rc = wh_Client_CmacDmaFinalRequest(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacDmaFinalResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    for (i = 0; i < WH_TEST_MR_TAG_SZ; i++) {
        WH_TEST_ASSERT_RETURN(mac[i] == 0);
    }

    xport->frameLen = WH_TEST_MR_CMAC_DMA_HDR_SZ + WH_TEST_MR_TAG_SZ;
    macLen          = sizeof(mac);

    rc = wh_Client_CmacDmaFinalRequest(client, cmac);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    rc = wh_Client_CmacDmaFinalResponse(client, cmac, mac, &macLen);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(macLen == WH_TEST_MR_TAG_SZ);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_ClientMalformedResp(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client handling of malformed responses...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientCmacTruncatedResponse());
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientCmacDmaTruncatedResponse());
#endif

    return WH_ERROR_OK;
}

#endif /* WOLFSSL_CMAC */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && !WOLFHSM_CFG_NO_CRYPTO */
