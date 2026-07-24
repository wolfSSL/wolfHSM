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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#if defined(WOLFSSL_HAVE_LMS)
#include "wolfssl/wolfcrypt/wc_lms.h"
#endif
#if defined(WOLFSSL_HAVE_XMSS)
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif
#if defined(WOLFSSL_HAVE_MLKEM)
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#endif

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Keygen, sign and signatures-left are private-key operations, so a
 * verify-only build has no client API for this file to drive. */
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_VERIFY_ONLY)
#define WH_TEST_MR_LMS
#endif
#if defined(WOLFSSL_HAVE_XMSS) && !defined(WOLFSSL_XMSS_VERIFY_ONLY)
#define WH_TEST_MR_XMSS
#endif

#if defined(WOLFHSM_CFG_DMA) &&                             \
    (defined(WH_TEST_MR_LMS) || defined(WH_TEST_MR_XMSS) || \
     defined(WOLFSSL_HAVE_MLKEM))

/* Pattern a well-formed reply leaves in the caller's output */
#define WH_TEST_MR_POISON 0xA5
#define WH_TEST_MR_KEY_ID 1
/* Distinct from WH_ERROR_ABORTED and WH_ERROR_BADARGS so the error-reply case
 * cannot be confused with a rejection */
#define WH_TEST_MR_SERVER_RC WH_ERROR_NOTFOUND

/* Bytes every crypto response spends before the per-algorithm struct */
#define WH_TEST_MR_HDR_SZ \
    ((uint16_t)sizeof(whMessageCrypto_GenericResponseHeader))

/* Shorthand for the stateful signature response structs, which are otherwise
 * too long to keep the call sites inside 80 columns */
typedef whMessageCrypto_PqcStatefulSigKeyGenDmaResponse   whTestMrKeyGenResp;
typedef whMessageCrypto_PqcStatefulSigSignDmaResponse     whTestMrSignResp;
typedef whMessageCrypto_PqcStatefulSigVerifyDmaResponse   whTestMrVerifyResp;
typedef whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse whTestMrSigsLeftResp;
typedef whMessageCrypto_MlKemKeyGenDmaResponse            whTestMrKemKeyGenResp;

/* Scripted transport state. Each exchange is described before the client call
 * that triggers it, so a response can advertise a payload the frame does not
 * actually carry. */
typedef struct {
    uint8_t  request[WH_COMM_MTU];
    int32_t  rc;       /* crypto response header rc */
    uint32_t claimVal; /* value stamped into the response struct */
    uint16_t claimOff; /* offset of that field within the struct */
    uint16_t structSz; /* size of the algorithm response struct */
    uint16_t bodyLen;  /* trailing bytes actually written after the struct */
    uint16_t frameLen; /* crypto bytes reported to the client */
    uint16_t algoType; /* crypto response header algoType */
    uint8_t  fill;     /* pattern written into the trailing bytes */
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
    if (xport->structSz >= xport->claimOff + sizeof(xport->claimVal)) {
        memcpy(body + xport->claimOff, &xport->claimVal,
               sizeof(xport->claimVal));
    }
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

/* Describes the well-formed reply for one algorithm. Sub-tests then vary
 * frameLen, claimVal and rc around it. */
static void _mrScript(whTestMrTransport* xport, uint16_t algoType,
                      uint16_t structSz, uint16_t claimOff, uint32_t claimVal)
{
    xport->algoType = algoType;
    xport->structSz = structSz;
    xport->claimOff = claimOff;
    xport->claimVal = claimVal;
    xport->bodyLen  = 0;
    xport->fill     = WH_TEST_MR_POISON;
    xport->rc       = WH_ERROR_OK;
    xport->frameLen = (uint16_t)(WH_TEST_MR_HDR_SZ + structSz);
}

#ifdef WH_TEST_MR_LMS

/* L=1, H=5, W=8 matches the LMS parameters the client-server tests use */
#define WH_TEST_MR_LMS_LEVELS (1)
#define WH_TEST_MR_LMS_HEIGHT (5)
#define WH_TEST_MR_LMS_WNTZ (8)

/* The keygen response carries the id the server assigned, and the client
 * stores it in both the caller's out-param and the key. A short frame would
 * take that id from the request bytes still sitting in the comm buffer. */
static int _whTest_ClientLmsMakeKeyDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    LmsKey             key[1];
    whKeyId            keyId = WH_KEYID_ERASED;
    whKeyId            gotId = WH_KEYID_ERASED;
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrKeyGenResp));
    int rc;

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_LmsKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wc_LmsKey_SetParameters(key, WH_TEST_MR_LMS_LEVELS,
                                                  WH_TEST_MR_LMS_HEIGHT,
                                                  WH_TEST_MR_LMS_WNTZ) == 0);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN,
              (uint16_t)sizeof(whTestMrKeyGenResp),
              (uint16_t)offsetof(whTestMrKeyGenResp, keyId), WH_TEST_MR_KEY_ID);

    /* A frame carrying the struct it claims is accepted, and leaves a known
     * key id behind for the rejection below to check against */
    rc = wh_Client_LmsMakeKeyDma(client, key, &keyId, WH_NVM_FLAGS_NONE, 0,
                                 NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(keyId == WH_TEST_MR_KEY_ID);

    /* One byte short of the struct: reject, key id untouched */
    xport->claimVal = WH_TEST_MR_KEY_ID + 1;
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_LmsMakeKeyDma(client, key, &keyId, WH_NVM_FLAGS_NONE, 0,
                                 NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(keyId == WH_TEST_MR_KEY_ID);
    WH_TEST_ASSERT_RETURN(wh_Client_LmsGetKeyId(key, &gotId) == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(gotId == WH_TEST_MR_KEY_ID);

    /* A header-only reply is what the server sends on failure, so it must
     * still surface the server's error rather than the frame rejection */
    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_LmsMakeKeyDma(client, key, &keyId, WH_NVM_FLAGS_NONE, 0,
                                 NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_LmsKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

/* The signature travels by DMA, so the response frame carries only its length.
 * That length must be backed by the frame as well as fit the caller's
 * buffer, and the two bounds are exercised separately. */
static int _whTest_ClientLmsSignDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    LmsKey             key[1];
    const byte         msg[] = "wolfHSM LMS malformed response test";
    byte               sig[128];
    word32             sigSz = 0;
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrSignResp));
    int rc;

    memset(sig, 0, sizeof(sig));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_LmsKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wh_Client_LmsSetKeyId(key, WH_TEST_MR_KEY_ID) ==
                          WH_ERROR_OK);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN,
              (uint16_t)sizeof(whTestMrSignResp),
              (uint16_t)offsetof(whTestMrSignResp, sigLen),
              (uint32_t)sizeof(sig) / 2);

    sigSz = (word32)sizeof(sig);
    rc = wh_Client_LmsSignDma(client, msg, (word32)sizeof(msg) - 1, sig, &sigSz,
                              key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sigSz == (word32)sizeof(sig) / 2);

    /* The claim still fits the caller's buffer, so only the frame bound can
     * reject this one, and the reported length must not move */
    xport->frameLen = (uint16_t)(fullSz - 1);
    sigSz           = (word32)sizeof(sig);
    rc = wh_Client_LmsSignDma(client, msg, (word32)sizeof(msg) - 1, sig, &sigSz,
                              key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(sigSz == (word32)sizeof(sig));

    /* A length the frame does carry but the caller's buffer cannot hold is
     * rejected by the pre-existing capacity check */
    xport->claimVal = (uint32_t)sizeof(sig) + 1;
    xport->frameLen = fullSz;
    sigSz           = (word32)sizeof(sig);
    rc = wh_Client_LmsSignDma(client, msg, (word32)sizeof(msg) - 1, sig, &sigSz,
                              key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    sigSz           = (word32)sizeof(sig);
    rc = wh_Client_LmsSignDma(client, msg, (word32)sizeof(msg) - 1, sig, &sigSz,
                              key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_LmsKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

/* The verify result is the whole point of the exchange, so a short frame must
 * not be allowed to answer "valid" out of the request bytes. */
static int _whTest_ClientLmsVerifyDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    LmsKey             key[1];
    const byte         msg[] = "wolfHSM LMS malformed response test";
    byte               sig[128];
    int                res = 0;
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrVerifyResp));
    int rc;

    memset(sig, WH_TEST_MR_POISON, sizeof(sig));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_LmsKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wh_Client_LmsSetKeyId(key, WH_TEST_MR_KEY_ID) ==
                          WH_ERROR_OK);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY,
              (uint16_t)sizeof(whTestMrVerifyResp),
              (uint16_t)offsetof(whTestMrVerifyResp, res), 1);

    rc = wh_Client_LmsVerifyDma(client, sig, (word32)sizeof(sig), msg,
                                (word32)sizeof(msg) - 1, &res, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(res == 1);

    /* Claims the signature verified, in a frame too short to say so */
    res             = 0;
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_LmsVerifyDma(client, sig, (word32)sizeof(sig), msg,
                                (word32)sizeof(msg) - 1, &res, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(res == 0);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_LmsVerifyDma(client, sig, (word32)sizeof(sig), msg,
                                (word32)sizeof(msg) - 1, &res, key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_LmsKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

/* SigsLeft returns the remaining-signature flag as its own return value, so a
 * short frame would report a one-time key as still usable. */
static int _whTest_ClientLmsSigsLeftDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    LmsKey             key[1];
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrSigsLeftResp));
    int rc;

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_LmsKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wh_Client_LmsSetKeyId(key, WH_TEST_MR_KEY_ID) ==
                          WH_ERROR_OK);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT,
              (uint16_t)sizeof(whTestMrSigsLeftResp),
              (uint16_t)offsetof(whTestMrSigsLeftResp, sigsLeft), 1);

    rc = wh_Client_LmsSigsLeftDma(client, key);
    WH_TEST_ASSERT_RETURN(rc == 1);

    xport->frameLen = (uint16_t)(fullSz - 1);
    rc              = wh_Client_LmsSigsLeftDma(client, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc              = wh_Client_LmsSigsLeftDma(client, key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_LmsKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WH_TEST_MR_LMS */

#ifdef WH_TEST_MR_XMSS

#define WH_TEST_MR_XMSS_PARAM_STR "XMSS-SHA2_10_256"

/* XMSS mirrors the LMS keygen response exactly, so the same short frame would
 * hand back a key id the server never assigned. */
static int _whTest_ClientXmssMakeKeyDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    XmssKey            key[1];
    whKeyId            keyId = WH_KEYID_ERASED;
    whKeyId            gotId = WH_KEYID_ERASED;
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrKeyGenResp));
    int rc;

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_XmssKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(
        wc_XmssKey_SetParamStr(key, WH_TEST_MR_XMSS_PARAM_STR) == 0);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN,
              (uint16_t)sizeof(whTestMrKeyGenResp),
              (uint16_t)offsetof(whTestMrKeyGenResp, keyId), WH_TEST_MR_KEY_ID);

    rc = wh_Client_XmssMakeKeyDma(client, key, &keyId, WH_NVM_FLAGS_NONE, 0,
                                  NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(keyId == WH_TEST_MR_KEY_ID);

    xport->claimVal = WH_TEST_MR_KEY_ID + 1;
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_XmssMakeKeyDma(client, key, &keyId, WH_NVM_FLAGS_NONE, 0,
                                  NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(keyId == WH_TEST_MR_KEY_ID);
    WH_TEST_ASSERT_RETURN(wh_Client_XmssGetKeyId(key, &gotId) == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(gotId == WH_TEST_MR_KEY_ID);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_XmssMakeKeyDma(client, key, &keyId, WH_NVM_FLAGS_NONE, 0,
                                  NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_XmssKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

static int _whTest_ClientXmssSignDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    XmssKey            key[1];
    const byte         msg[] = "wolfHSM XMSS malformed response test";
    byte               sig[128];
    word32             sigSz = 0;
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrSignResp));
    int rc;

    memset(sig, 0, sizeof(sig));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_XmssKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wh_Client_XmssSetKeyId(key, WH_TEST_MR_KEY_ID) ==
                          WH_ERROR_OK);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN,
              (uint16_t)sizeof(whTestMrSignResp),
              (uint16_t)offsetof(whTestMrSignResp, sigLen),
              (uint32_t)sizeof(sig) / 2);

    sigSz = (word32)sizeof(sig);
    rc    = wh_Client_XmssSignDma(client, msg, (word32)sizeof(msg) - 1, sig,
                                  &sigSz, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sigSz == (word32)sizeof(sig) / 2);

    xport->frameLen = (uint16_t)(fullSz - 1);
    sigSz           = (word32)sizeof(sig);
    rc = wh_Client_XmssSignDma(client, msg, (word32)sizeof(msg) - 1, sig,
                               &sigSz, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(sigSz == (word32)sizeof(sig));

    xport->claimVal = (uint32_t)sizeof(sig) + 1;
    xport->frameLen = fullSz;
    sigSz           = (word32)sizeof(sig);
    rc = wh_Client_XmssSignDma(client, msg, (word32)sizeof(msg) - 1, sig,
                               &sigSz, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    sigSz           = (word32)sizeof(sig);
    rc = wh_Client_XmssSignDma(client, msg, (word32)sizeof(msg) - 1, sig,
                               &sigSz, key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_XmssKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

static int _whTest_ClientXmssVerifyDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    XmssKey            key[1];
    const byte         msg[] = "wolfHSM XMSS malformed response test";
    byte               sig[128];
    int                res = 0;
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrVerifyResp));
    int rc;

    memset(sig, WH_TEST_MR_POISON, sizeof(sig));

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_XmssKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wh_Client_XmssSetKeyId(key, WH_TEST_MR_KEY_ID) ==
                          WH_ERROR_OK);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY,
              (uint16_t)sizeof(whTestMrVerifyResp),
              (uint16_t)offsetof(whTestMrVerifyResp, res), 1);

    rc = wh_Client_XmssVerifyDma(client, sig, (word32)sizeof(sig), msg,
                                 (word32)sizeof(msg) - 1, &res, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(res == 1);

    res             = 0;
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_XmssVerifyDma(client, sig, (word32)sizeof(sig), msg,
                                 (word32)sizeof(msg) - 1, &res, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);
    WH_TEST_ASSERT_RETURN(res == 0);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_XmssVerifyDma(client, sig, (word32)sizeof(sig), msg,
                                 (word32)sizeof(msg) - 1, &res, key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_XmssKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

static int _whTest_ClientXmssSigsLeftDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    XmssKey            key[1];
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrSigsLeftResp));
    int rc;

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(wc_XmssKey_Init(key, NULL, INVALID_DEVID) == 0);
    WH_TEST_ASSERT_RETURN(wh_Client_XmssSetKeyId(key, WH_TEST_MR_KEY_ID) ==
                          WH_ERROR_OK);

    _mrScript(xport, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT,
              (uint16_t)sizeof(whTestMrSigsLeftResp),
              (uint16_t)offsetof(whTestMrSigsLeftResp, sigsLeft), 1);

    rc = wh_Client_XmssSigsLeftDma(client, key);
    WH_TEST_ASSERT_RETURN(rc == 1);

    xport->frameLen = (uint16_t)(fullSz - 1);
    rc              = wh_Client_XmssSigsLeftDma(client, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc              = wh_Client_XmssSigsLeftDma(client, key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_XmssKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WH_TEST_MR_XMSS */

#ifdef WOLFSSL_HAVE_MLKEM

/* Every reply here claims a key length the client's staging buffer cannot
 * hold, so an accepted frame yields WH_ERROR_BADARGS from the pre-existing
 * capacity check and only a frame rejection yields WH_ERROR_ABORTED. */
static int _whTest_ClientMlKemMakeKeyDmaTruncatedResponse(void)
{
    whTestMrTransport  xport[1]   = {0};
    whCommClientConfig cc_conf[1] = {0};
    whClientConfig     c_conf[1]  = {0};
    whClientContext    client[1]  = {0};
    MlKemKey           key[1];
    const uint16_t     fullSz =
        (uint16_t)(WH_TEST_MR_HDR_SZ + sizeof(whTestMrKemKeyGenResp));
    int rc;

    WH_TEST_RETURN_ON_FAIL(_mrClientInit(client, c_conf, cc_conf, xport));
    WH_TEST_ASSERT_RETURN(
        wc_MlKemKey_Init(key, WC_ML_KEM_512, NULL, INVALID_DEVID) == 0);

    _mrScript(xport, WC_PK_TYPE_PQC_KEM_KEYGEN,
              (uint16_t)sizeof(whTestMrKemKeyGenResp),
              (uint16_t)offsetof(whTestMrKemKeyGenResp, keySize),
              (uint32_t)WC_ML_KEM_MAX_PRIVATE_KEY_SIZE + 1);

    rc = wh_Client_MlKemMakeExportKeyDma(client, WC_ML_KEM_512, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_BADARGS);

    /* One byte short of the struct: the frame bound now rejects first */
    xport->frameLen = (uint16_t)(fullSz - 1);
    rc = wh_Client_MlKemMakeExportKeyDma(client, WC_ML_KEM_512, key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    xport->rc       = WH_TEST_MR_SERVER_RC;
    xport->frameLen = WH_TEST_MR_HDR_SZ;
    rc = wh_Client_MlKemMakeExportKeyDma(client, WC_ML_KEM_512, key);
    WH_TEST_ASSERT_RETURN(rc == WH_TEST_MR_SERVER_RC);

    wc_MlKemKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WOLFSSL_HAVE_MLKEM */

int whTest_ClientMalformedResp(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client handling of malformed responses...\n");
#ifdef WH_TEST_MR_LMS
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientLmsMakeKeyDmaTruncatedResponse());
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientLmsSignDmaTruncatedResponse());
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientLmsVerifyDmaTruncatedResponse());
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientLmsSigsLeftDmaTruncatedResponse());
#endif
#ifdef WH_TEST_MR_XMSS
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientXmssMakeKeyDmaTruncatedResponse());
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientXmssSignDmaTruncatedResponse());
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientXmssVerifyDmaTruncatedResponse());
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientXmssSigsLeftDmaTruncatedResponse());
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientMlKemMakeKeyDmaTruncatedResponse());
#endif

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_DMA && (LMS || XMSS || WOLFSSL_HAVE_MLKEM) */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && !WOLFHSM_CFG_NO_CRYPTO */
