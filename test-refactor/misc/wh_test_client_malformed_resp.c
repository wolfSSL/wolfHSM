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

#ifdef WOLFSSL_HAVE_MLDSA

#include "wolfssl/wolfcrypt/dilithium.h"

#define WH_TEST_MR_POISON 0xA5
#define WH_TEST_MR_DER_SZ 256

/* Bytes an ML-DSA keygen response spends on headers before the DER payload */
#define WH_TEST_MR_MLDSA_HDR_SZ                                 \
    ((uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
                sizeof(whMessageCrypto_MlDsaKeyGenResponse)))

#ifdef WOLFHSM_CFG_DMA
/* A DMA sign response is headers only; the signature goes to client memory */
#define WH_TEST_MR_MLDSA_SIGN_SZ                                \
    ((uint16_t)(sizeof(whMessageCrypto_GenericResponseHeader) + \
                sizeof(whMessageCrypto_MlDsaSignDmaResponse)))
#endif

/* Scripted transport state. Each exchange is described before the client call
 * that triggers it, so a response can advertise a payload the frame does not
 * actually carry. */
typedef struct {
    uint8_t  request[WH_COMM_MTU];
    uint32_t claimedLen; /* value written to res->len, or to res->sigLen */
    uint16_t payloadLen; /* payload bytes actually written after the headers */
    uint16_t frameLen;   /* crypto bytes handed back to the client */
    uint16_t algoType;   /* crypto response header algoType */
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

/* Answers the pending request with the currently scripted frame. Only frameLen
 * crypto bytes are reported, so anything the client reads past that is data
 * left over from an earlier exchange. */
static int _mrTransportRecv(void* context, uint16_t* out_size, void* data)
{
    whTestMrTransport*                     xport = (whTestMrTransport*)context;
    whCommHeader*                          hdr;
    whMessageCrypto_GenericResponseHeader* res_hdr;
    whMessageCrypto_MlDsaKeyGenResponse*   res;
#ifdef WOLFHSM_CFG_DMA
    whMessageCrypto_MlDsaSignDmaResponse* sig_res;
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
    res_hdr->algoType = xport->algoType;
    res_hdr->rc       = WH_ERROR_OK;
    res_hdr->reserved = 0;

#ifdef WOLFHSM_CFG_DMA
    if (xport->algoType == WC_PK_TYPE_PQC_SIG_SIGN) {
        /* Body is written whatever frameLen says: reporting fewer bytes than
         * were written is what makes the frame malformed, and it keeps the
         * frame bound separable from the caller-buffer bound. */
        sig_res = (whMessageCrypto_MlDsaSignDmaResponse*)(res_hdr + 1);
        memset(sig_res, 0, sizeof(*sig_res));
        sig_res->sigLen = xport->claimedLen;
    }
    else
#endif
    if (xport->frameLen >= WH_TEST_MR_MLDSA_HDR_SZ) {
        res        = (whMessageCrypto_MlDsaKeyGenResponse*)(res_hdr + 1);
        res->keyId = WH_KEYID_ERASED;
        res->len   = xport->claimedLen;
        if (xport->payloadLen > 0) {
            memset((uint8_t*)(res + 1), xport->fill, xport->payloadLen);
        }
    }

    *out_size = (uint16_t)(sizeof(*hdr) + xport->frameLen);
    return WH_ERROR_OK;
}

static int _mrTransportCleanup(void* context)
{
    (void)context;
    return WH_ERROR_OK;
}

/* An ML-DSA keygen response claiming a DER blob the frame never carried must
 * be rejected instead of deserializing whatever trails the response body. */
static int _whTest_ClientMlDsaKeyGenTruncatedResponse(void)
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

    MlDsaKey key[1];
    whKeyId  key_id = WH_KEYID_ERASED;
    int      rc     = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    /* Well-formed cache keygen first. The frame carries the payload it claims,
     * so it must be accepted, and it leaves a known pattern in the client
     * packet buffer for the malformed exchanges to expose. */
    xport->algoType   = WC_PK_TYPE_PQC_SIG_KEYGEN;
    xport->claimedLen = WH_TEST_MR_DER_SZ;
    xport->payloadLen = WH_TEST_MR_DER_SZ;
    xport->fill       = WH_TEST_MR_POISON;
    xport->frameLen   = WH_TEST_MR_MLDSA_HDR_SZ + WH_TEST_MR_DER_SZ;

    rc = wh_Client_MlDsaMakeCacheKey(client, 0, WC_ML_DSA_44, &key_id,
                                     WH_NVM_FLAGS_NONE, 0, NULL);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    /* Headers arrive intact but the claimed DER is left out of the frame */
    rc = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(rc == 0);

    xport->claimedLen = WH_TEST_MR_DER_SZ;
    xport->payloadLen = 0;
    xport->frameLen   = WH_TEST_MR_MLDSA_HDR_SZ;

    rc = wh_Client_MlDsaMakeExportKey(client, WC_ML_DSA_44, 0, key);
    wc_MlDsaKey_Free(key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    /* Frame shorter than the headers themselves: the keyId and length the
     * client would read are stale bytes from the previous exchange. */
    rc = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(rc == 0);

    xport->claimedLen = 0;
    xport->payloadLen = 0;
    xport->frameLen = (uint16_t)sizeof(whMessageCrypto_GenericResponseHeader);

    rc = wh_Client_MlDsaMakeExportKey(client, WC_ML_DSA_44, 0, key);
    wc_MlDsaKey_Free(key);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA

#define WH_TEST_MR_SIG_SZ 128
#define WH_TEST_MR_SIGN_KEY_ID 1

/* The DMA sign response carries no inline payload, but the signature length it
 * reports still lands in the caller's out_len, so it has to be backed by the
 * frame and fit the buffer the server was given. */
static int _whTest_ClientMlDsaSignDmaTruncatedResponse(void)
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

    MlDsaKey key[1];
    uint8_t  msg[32];
    uint8_t  sig[WH_TEST_MR_SIG_SZ];
    word32   sigLen = 0;
    int      rc     = 0;

    memset(msg, WH_TEST_MR_POISON, sizeof(msg));
    memset(sig, 0, sizeof(sig));

    WH_TEST_RETURN_ON_FAIL(wh_Client_Init(client, c_conf));

    rc = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
    WH_TEST_ASSERT_RETURN(rc == 0);
    /* Pin a cached key id so signing does not import the key first */
    rc = wh_Client_MlDsaSetKeyId(key, WH_TEST_MR_SIGN_KEY_ID);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

    xport->algoType   = WC_PK_TYPE_PQC_SIG_SIGN;
    xport->payloadLen = 0;
    xport->fill       = 0;

    /* A complete reply reporting a signature that fits is accepted */
    xport->claimedLen = WH_TEST_MR_SIG_SZ;
    xport->frameLen   = WH_TEST_MR_MLDSA_SIGN_SZ;

    sigLen = sizeof(sig);
    rc = wh_Client_MlDsaSignDma(client, msg, sizeof(msg), sig, &sigLen, key,
                                NULL, 0, 0);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(sigLen == WH_TEST_MR_SIG_SZ);

    /* Frame one byte short of the response: sigLen would be read from bytes
     * the frame never delivered */
    xport->claimedLen = WH_TEST_MR_SIG_SZ;
    xport->frameLen   = (uint16_t)(WH_TEST_MR_MLDSA_SIGN_SZ - 1);

    sigLen = sizeof(sig);
    rc = wh_Client_MlDsaSignDma(client, msg, sizeof(msg), sig, &sigLen, key,
                                NULL, 0, 0);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    /* Complete frame, but a signature longer than the caller's buffer */
    xport->claimedLen = WH_TEST_MR_SIG_SZ + 1;
    xport->frameLen   = WH_TEST_MR_MLDSA_SIGN_SZ;

    sigLen = sizeof(sig);
    rc = wh_Client_MlDsaSignDma(client, msg, sizeof(msg), sig, &sigLen, key,
                                NULL, 0, 0);
    WH_TEST_ASSERT_RETURN(rc == WH_ERROR_ABORTED);

    wc_MlDsaKey_Free(key);
    WH_TEST_RETURN_ON_FAIL(wh_Client_Cleanup(client));

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_ClientMalformedResp(void* ctx)
{
    (void)ctx;

    WH_TEST_PRINT("Testing client handling of malformed responses...\n");
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientMlDsaKeyGenTruncatedResponse());
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_ClientMlDsaSignDmaTruncatedResponse());
#endif

    return WH_ERROR_OK;
}

#endif /* WOLFSSL_HAVE_MLDSA */

#endif /* WOLFHSM_CFG_ENABLE_CLIENT && !WOLFHSM_CFG_NO_CRYPTO */
