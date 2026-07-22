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
 * Client-side hardening against malformed server responses, driven by a
 * scripted transport that replies with frames a real server never emits.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_DMA) && !defined(NO_AES)

/* Pattern a well-formed reply leaves in the caller's output */
#define WH_TEST_MR_POISON 0xA5
/* Pattern a rejected reply must never propagate */
#define WH_TEST_MR_STALE 0x5A
#define WH_TEST_MR_KEY_ID 1
#define WH_TEST_MR_IN_SZ AES_BLOCK_SIZE
#define WH_TEST_MR_IV_SZ 12

/* Bytes every crypto response spends before the per-algorithm struct */
#define WH_TEST_MR_HDR_SZ \
    ((uint16_t)sizeof(whMessageCrypto_GenericResponseHeader))

/* Scripted transport state. Each exchange is described before the client call
 * that triggers it, so a response can advertise a payload the frame does not
 * actually carry. */
typedef struct {
    uint8_t  request[WH_COMM_MTU];
    int32_t  rc;        /* crypto response header rc */
    uint32_t claimedSz; /* value written to res->authTagSz */
    uint16_t structSz;  /* size of the algorithm response struct */
    uint16_t bodyLen;   /* trailing bytes actually written after the struct */
    uint16_t frameLen;  /* crypto bytes reported to the client */
    uint16_t algoType;  /* crypto response header algoType */
    uint8_t  fill;      /* pattern written into the trailing bytes */
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

/* Answers the pending request with the currently scripted frame. The body is
 * always written and frameLen alone decides what is reported, so anything the
 * client reads past the frame is data left over from an earlier exchange. */
static int _mrTransportRecv(void* context, uint16_t* out_size, void* data)
{
    whTestMrTransport*                     xport = (whTestMrTransport*)context;
    whCommHeader*                          hdr;
    whMessageCrypto_GenericResponseHeader* res_hdr;
    uint8_t*                               body;
#ifdef HAVE_AESGCM
    whMessageCrypto_AesGcmDmaResponse* gcm_res;
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

    res_hdr =
        (whMessageCrypto_GenericResponseHeader*)((uint8_t*)data + sizeof(*hdr));
    res_hdr->algoType = xport->algoType;
    res_hdr->rc       = xport->rc;
    res_hdr->reserved = 0;

    body = (uint8_t*)(res_hdr + 1);
    if (xport->structSz > 0) {
        memset(body, 0, xport->structSz);
    }
#ifdef HAVE_AESGCM
    if (xport->algoType == WC_CIPHER_AES_GCM) {
        gcm_res            = (whMessageCrypto_AesGcmDmaResponse*)body;
        gcm_res->authTagSz = xport->claimedSz;
    }
#endif
    if (xport->bodyLen > 0) {
        memset(body + xport->structSz, xport->fill, xport->bodyLen);
    }

    *out_size = (uint16_t)(sizeof(*hdr) + xport->frameLen);
    return WH_ERROR_OK;
}

static int _mrTransportCleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

static const whTransportClientCb _mrTransportCb = {
    _mrTransportInit, _mrTransportSend, _mrTransportRecv, _mrTransportCleanup};

/* Brings up a client talking to the scripted transport. The configs are
 * caller-owned so they outlive the client context. */
static int _mrClientInit(whClientContext* client, whClientConfig* c_conf,
                         whCommClientConfig* cc_conf, whTestMrTransport* xport)
{
    cc_conf->transport_cb      = &_mrTransportCb;
    cc_conf->transport_context = (void*)xport;
    cc_conf->transport_config  = NULL;
    cc_conf->client_id         = WH_TEST_DEFAULT_CLIENT_ID;
    c_conf->comm               = cc_conf;

    return wh_Client_Init(client, c_conf);
}

static int _mrAllBytesAre(const uint8_t* buf, uint32_t len, uint8_t val)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != val) {
            return 0;
        }
    }
    return 1;
}

/* Preps an Aes for a DMA request that carries a key id instead of key bytes */
static int _mrAesInit(Aes* aes)
{
    int rc;

    rc = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (rc != 0) {
        return WH_ERROR_ABORTED;
    }
    return wh_Client_AesSetKeyId(aes, WH_TEST_MR_KEY_ID);
}

#ifdef WOLFSSL_AES_COUNTER
/* The CTR DMA response carries the updated counter register and partial block
 * after its struct, so a frame that stops short would restore both from the
 * client's own request bytes. */
static int _whTest_ClientAesCtrDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    Aes                aes[1];
    uint8_t            in[WH_TEST_MR_IN_SZ];
    uint8_t            out[WH_TEST_MR_IN_SZ];
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ +
                       sizeof(whMessageCrypto_AesCtrDmaResponse) + AES_IV_SIZE +
                       AES_BLOCK_SIZE);
    int rc;

    memset(in, WH_TEST_MR_POISON, sizeof(in));
    memset(out, 0, sizeof(out));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_RETURN_ON_FAIL(_mrAesInit(aes));

    xport->algoType = WC_CIPHER_AES_CTR;
    xport->structSz = (uint16_t)sizeof(whMessageCrypto_AesCtrDmaResponse);
    xport->bodyLen  = AES_IV_SIZE + AES_BLOCK_SIZE;
    xport->fill     = WH_TEST_MR_POISON;
    xport->rc       = WH_ERROR_OK;

    /* A frame carrying the counter state it claims is accepted, and leaves a
     * known pattern behind for the rejections below to check against */
    xport->frameLen = fullSz;
    rc = wh_Client_AesCtrDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_mrAllBytesAre((const uint8_t*)aes->reg, AES_IV_SIZE,
                                         WH_TEST_MR_POISON));
    WH_TEST_ASSERT_RETURN(_mrAllBytesAre((const uint8_t*)aes->tmp,
                                         AES_BLOCK_SIZE, WH_TEST_MR_POISON));

    /* One byte short of the state it must carry: reject, counter untouched */
    xport->fill     = WH_TEST_MR_STALE;
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_AesCtrDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(_mrAllBytesAre((const uint8_t*)aes->reg, AES_IV_SIZE,
                                         WH_TEST_MR_POISON));
    WH_TEST_ASSERT_RETURN(_mrAllBytesAre((const uint8_t*)aes->tmp,
                                         AES_BLOCK_SIZE, WH_TEST_MR_POISON));

    /* A header-only reply is what the server sends on failure, so it must
     * still surface the server's error rather than the frame rejection */
    xport->rc       = WH_ERROR_BADARGS;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_AesCtrDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
/* The ECB DMA response is struct-only, but the client still overlays it, so a
 * frame shorter than the struct must not be parsed. */
static int _whTest_ClientAesEcbDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    Aes                aes[1];
    uint8_t            in[WH_TEST_MR_IN_SZ];
    uint8_t            out[WH_TEST_MR_IN_SZ];
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ +
                       sizeof(whMessageCrypto_AesEcbDmaResponse));
    int rc;

    memset(in, WH_TEST_MR_POISON, sizeof(in));
    memset(out, 0, sizeof(out));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_RETURN_ON_FAIL(_mrAesInit(aes));

    xport->algoType = WC_CIPHER_AES_ECB;
    xport->structSz = (uint16_t)sizeof(whMessageCrypto_AesEcbDmaResponse);
    xport->bodyLen  = 0;
    xport->fill     = WH_TEST_MR_STALE;
    xport->rc       = WH_ERROR_OK;

    xport->frameLen = fullSz;
    rc = wh_Client_AesEcbDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_AesEcbDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    xport->rc       = WH_ERROR_BADARGS;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_AesEcbDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
/* The CBC DMA response carries the updated IV after its struct, and that IV
 * chains into the next block, so a short frame must not update it. */
static int _whTest_ClientAesCbcDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    Aes                aes[1];
    uint8_t            in[WH_TEST_MR_IN_SZ];
    uint8_t            out[WH_TEST_MR_IN_SZ];
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ +
                       sizeof(whMessageCrypto_AesCbcDmaResponse) + AES_IV_SIZE);
    int rc;

    memset(in, WH_TEST_MR_POISON, sizeof(in));
    memset(out, 0, sizeof(out));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_RETURN_ON_FAIL(_mrAesInit(aes));

    xport->algoType = WC_CIPHER_AES_CBC;
    xport->structSz = (uint16_t)sizeof(whMessageCrypto_AesCbcDmaResponse);
    xport->bodyLen  = AES_IV_SIZE;
    xport->fill     = WH_TEST_MR_POISON;
    xport->rc       = WH_ERROR_OK;

    xport->frameLen = fullSz;
    rc = wh_Client_AesCbcDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_mrAllBytesAre((const uint8_t*)aes->reg, AES_IV_SIZE,
                                         WH_TEST_MR_POISON));

    xport->fill     = WH_TEST_MR_STALE;
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_AesCbcDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(_mrAllBytesAre((const uint8_t*)aes->reg, AES_IV_SIZE,
                                         WH_TEST_MR_POISON));

    xport->rc       = WH_ERROR_BADARGS;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_AesCbcDma(client, aes, 1, in, sizeof(in), out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
/* The GCM DMA response reports an auth tag length and the tag trails the
 * struct, so the length has to be backed by the frame as well as fit the
 * caller's tag buffer. The two bounds are exercised separately. */
static int _whTest_ClientAesGcmDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    Aes                aes[1];
    uint8_t            in[WH_TEST_MR_IN_SZ];
    uint8_t            out[WH_TEST_MR_IN_SZ];
    uint8_t            iv[WH_TEST_MR_IV_SZ];
    uint8_t            tag[2 * AES_BLOCK_SIZE];
    const uint16_t     structSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ +
                       sizeof(whMessageCrypto_AesGcmDmaResponse));
    int rc;

    memset(in, WH_TEST_MR_POISON, sizeof(in));
    memset(out, 0, sizeof(out));
    memset(iv, 0, sizeof(iv));
    memset(tag, 0, sizeof(tag));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_RETURN_ON_FAIL(_mrAesInit(aes));

    xport->algoType  = WC_CIPHER_AES_GCM;
    xport->structSz  = (uint16_t)sizeof(whMessageCrypto_AesGcmDmaResponse);
    xport->claimedSz = AES_BLOCK_SIZE;
    xport->bodyLen   = AES_BLOCK_SIZE;
    xport->fill      = WH_TEST_MR_POISON;
    xport->rc        = WH_ERROR_OK;

    /* A frame carrying the tag it claims is accepted, and copies exactly
     * authTagSz bytes into the caller's buffer */
    xport->frameLen = (uint16_t)(structSz + AES_BLOCK_SIZE);
    rc = wh_Client_AesGcmDma(client, aes, 1, in, sizeof(in), iv, sizeof(iv),
                             NULL, 0, NULL, tag, AES_BLOCK_SIZE, out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(
        _mrAllBytesAre(tag, AES_BLOCK_SIZE, WH_TEST_MR_POISON));
    WH_TEST_ASSERT_RETURN(
        _mrAllBytesAre(tag + AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0));

    /* Claims a tag one byte longer than the frame carries. The claim still
     * fits the caller's buffer, so only the frame bound can reject it. */
    xport->fill     = WH_TEST_MR_STALE;
    xport->frameLen = (uint16_t)(structSz + AES_BLOCK_SIZE - 1);
    rc = wh_Client_AesGcmDma(client, aes, 1, in, sizeof(in), iv, sizeof(iv),
                             NULL, 0, NULL, tag, AES_BLOCK_SIZE, out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(
        _mrAllBytesAre(tag, AES_BLOCK_SIZE, WH_TEST_MR_POISON));

    /* Frame shorter than the response struct itself */
    xport->frameLen = (uint16_t)(structSz - 1);
    rc = wh_Client_AesGcmDma(client, aes, 1, in, sizeof(in), iv, sizeof(iv),
                             NULL, 0, NULL, tag, AES_BLOCK_SIZE, out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    /* A tag the frame does carry but the caller's buffer cannot hold is
     * rejected by the pre-existing capacity check, without touching the tail
     * of the caller's buffer */
    xport->claimedSz = 2 * AES_BLOCK_SIZE;
    xport->bodyLen   = 2 * AES_BLOCK_SIZE;
    xport->frameLen  = (uint16_t)(structSz + (2 * AES_BLOCK_SIZE));
    rc = wh_Client_AesGcmDma(client, aes, 1, in, sizeof(in), iv, sizeof(iv),
                             NULL, 0, NULL, tag, AES_BLOCK_SIZE, out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(
        _mrAllBytesAre(tag + AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0));

    xport->rc       = WH_ERROR_BADARGS;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_AesGcmDma(client, aes, 1, in, sizeof(in), iv, sizeof(iv),
                             NULL, 0, NULL, tag, AES_BLOCK_SIZE, out);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    wc_AesFree(aes);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* HAVE_AESGCM */

int whTest_ClientMalformedResp(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client handling of malformed responses...\n");
#ifdef WOLFSSL_AES_COUNTER
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientAesCtrDmaTruncatedResponse());
#endif
#ifdef HAVE_AES_ECB
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientAesEcbDmaTruncatedResponse());
#endif
#ifdef HAVE_AES_CBC
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientAesCbcDmaTruncatedResponse());
#endif
#ifdef HAVE_AESGCM
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientAesGcmDmaTruncatedResponse());
#endif

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_DMA && !NO_AES */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && !WOLFHSM_CFG_NO_CRYPTO */
