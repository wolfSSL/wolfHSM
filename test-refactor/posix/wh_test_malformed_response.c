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
 * test-refactor/posix/wh_test_malformed_response.c
 *
 * Negative-path coverage for the client-side response frame bounds
 * checks, driven by a fake server that declares a payload length its
 * frame does not carry. POSIX/pthread only, and port-owned rather than
 * in the common list, which runs against a real server process.
 */

#include <pthread.h>
#include <string.h>
#include <time.h>

#include "wolfhsm/wh_settings.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT) && \
    !defined(WOLFHSM_CFG_NO_CRYPTO)

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/rsa.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_transport_mem.h"

#define WH_TEST_MALFORMED_BUFFER_SIZE 4096

/* Inside WOLFHSM_CFG_COMM_DATA_LEN, so only a frame-length check rejects it */
#define WH_TEST_MALFORMED_CLAIMED_SZ 64

typedef enum {
    WH_TEST_MALFORMED_TRUNCATED = 0,
    WH_TEST_MALFORMED_OVERSIZED,
    WH_TEST_MALFORMED_SHAPE_COUNT
} whTestMalformedShape;

typedef int (*whTestMalformedFn)(whClientContext* client);

typedef struct {
    const char*       name;
    whTestMalformedFn call;
    uint16_t          resSize; /* size of the algorithm's response struct */
} whTestMalformedCase;

/* Every keygen response opens with this pair */
typedef struct {
    uint32_t keyId;
    uint32_t len;
} whTestMalformedKeyGenBody;


static int _callEd25519MakeKey(whClientContext* client)
{
    ed25519_key key[1];
    int         ret;

    ret = wc_ed25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wh_Client_Ed25519MakeExportKey(client, key);
    wc_ed25519_free(key);
    return ret;
}

static int _callEccMakeKey(whClientContext* client)
{
    ecc_key key[1];
    int     ret;

    ret = wc_ecc_init_ex(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wh_Client_EccMakeExportKey(client, 32, ECC_SECP256R1, key);
    wc_ecc_free(key);
    return ret;
}

static int _callRsaMakeKey(whClientContext* client)
{
    RsaKey key[1];
    int    ret;

    ret = wc_InitRsaKey_ex(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wh_Client_RsaMakeExportKey(client, 2048, 65537, key);
    wc_FreeRsaKey(key);
    return ret;
}

static int _callCurve25519MakeKey(whClientContext* client)
{
    curve25519_key key[1];
    int            ret;

    ret = wc_curve25519_init_ex(key, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wh_Client_Curve25519MakeExportKey(client, CURVE25519_KEYSIZE, key);
    wc_curve25519_free(key);
    return ret;
}

static const whTestMalformedCase _malformedCases[] = {
    {"Ed25519 keygen", _callEd25519MakeKey,
     (uint16_t)sizeof(whMessageCrypto_Ed25519KeyGenResponse)},
    {"ECC keygen", _callEccMakeKey,
     (uint16_t)sizeof(whMessageCrypto_EccKeyGenResponse)},
    {"RSA keygen", _callRsaMakeKey,
     (uint16_t)sizeof(whMessageCrypto_RsaKeyGenResponse)},
    {"Curve25519 keygen", _callCurve25519MakeKey,
     (uint16_t)sizeof(whMessageCrypto_Curve25519KeyGenResponse)},
};

#define WH_TEST_MALFORMED_CASE_COUNT \
    (sizeof(_malformedCases) / sizeof(_malformedCases[0]))

static const struct timespec WH_TEST_MALFORMED_ONE_MS = {0, 1000000};

/* Bounds the 1 ms retry loops so a stalled peer fails the suite, not hangs it */
#define WH_TEST_MALFORMED_MAX_TRIES 5000

static int _malformedClientRc = WH_TEST_SUCCESS;
static int _malformedServerRc = WH_TEST_SUCCESS;


/* Echoes the request kind and seq so the client accepts the reply */
static void* _malformedServerThread(void* cf)
{
    whCommServerConfig* config = (whCommServerConfig*)cf;
    whCommServer        server[1];
    uint8_t             rx_req[WH_TEST_MALFORMED_BUFFER_SIZE];
    uint8_t             tx_resp[WH_TEST_MALFORMED_BUFFER_SIZE];
    uint16_t            rx_req_len   = 0;
    uint16_t            rx_req_flags = 0;
    uint16_t            rx_req_type  = 0;
    uint16_t            rx_req_seq   = 0;
    uint16_t            tx_resp_len  = 0;
    size_t              step;
    size_t              shape;
    size_t              idx;
    int                 tries;
    int                 ret;

    whMessageCrypto_GenericResponseHeader* hdr =
        (whMessageCrypto_GenericResponseHeader*)tx_resp;
    whTestMalformedKeyGenBody* body =
        (whTestMalformedKeyGenBody*)(tx_resp + sizeof(*hdr));

    ret = wh_CommServer_Init(server, config, NULL, NULL);
    WH_TEST_ASSERT_MSG(0 == ret, "Fake server Init: ret=%d", ret);

    /* Flattened so a timeout exits the exchange in one break */
    for (step = 0; step < (size_t)WH_TEST_MALFORMED_SHAPE_COUNT *
                              WH_TEST_MALFORMED_CASE_COUNT;
         step++) {
        shape = step / WH_TEST_MALFORMED_CASE_COUNT;
        idx   = step % WH_TEST_MALFORMED_CASE_COUNT;

        tries = 0;
        do {
            ret = wh_CommServer_RecvRequest(server, &rx_req_flags,
                                            &rx_req_type, &rx_req_seq,
                                            &rx_req_len, sizeof(rx_req),
                                            rx_req);
            if (ret != WH_ERROR_NOTREADY) {
                break;
            }
            /* Ignored: ending the loop on an interrupted sleep would
             * strand the client waiting for a response. */
            (void)nanosleep(&WH_TEST_MALFORMED_ONE_MS, NULL);
            tries++;
        } while (tries < WH_TEST_MALFORMED_MAX_TRIES);

        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Fake server RecvRequest for %s: ret=%d\n",
                           _malformedCases[idx].name, ret);
            _malformedServerRc = WH_TEST_FAIL;
            break;
        }

        memset(tx_resp, 0, sizeof(tx_resp));
        /* From the request header, not the comm kind, or the client
         * rejects the reply before reaching the bounds check. */
        hdr->rc = WH_ERROR_OK;
        hdr->algoType =
            ((whMessageCrypto_GenericRequestHeader*)rx_req)->algoType;

        if (shape == (size_t)WH_TEST_MALFORMED_TRUNCATED) {
            /* Stop short of the response struct the client reads */
            tx_resp_len = (uint16_t)sizeof(*hdr);
        }
        else {
            body->keyId = 0;
            body->len   = WH_TEST_MALFORMED_CLAIMED_SZ;
            tx_resp_len =
                (uint16_t)(sizeof(*hdr) + _malformedCases[idx].resSize);
        }

        tries = 0;
        do {
            ret = wh_CommServer_SendResponse(server, rx_req_flags, rx_req_type,
                                             rx_req_seq, tx_resp_len, tx_resp);
            if (ret != WH_ERROR_NOTREADY) {
                break;
            }
            (void)nanosleep(&WH_TEST_MALFORMED_ONE_MS, NULL);
            tries++;
        } while (tries < WH_TEST_MALFORMED_MAX_TRIES);

        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("Fake server SendResponse for %s: ret=%d\n",
                           _malformedCases[idx].name, ret);
            _malformedServerRc = WH_TEST_FAIL;
            break;
        }
    }

    ret = wh_CommServer_Cleanup(server);
    WH_TEST_ASSERT_MSG(0 == ret, "Fake server Cleanup: ret=%d", ret);
    return NULL;
}


static void* _malformedClientThread(void* cf)
{
    whClientConfig* config = (whClientConfig*)cf;
    whClientContext client[1];
    size_t          shape;
    size_t          idx;
    int             ret;

    ret = wh_Client_Init(client, config);
    WH_TEST_ASSERT_MSG(0 == ret, "Fake client Init: ret=%d", ret);
    if (ret != 0) {
        _malformedClientRc = ret;
        return NULL;
    }

    for (shape = 0; shape < (size_t)WH_TEST_MALFORMED_SHAPE_COUNT; shape++) {
        for (idx = 0; idx < WH_TEST_MALFORMED_CASE_COUNT; idx++) {
            ret = _malformedCases[idx].call(client);
            if (ret != WH_ERROR_ABORTED) {
                WH_ERROR_PRINT("%s shape %u: expected WH_ERROR_ABORTED, "
                               "got %d\n",
                               _malformedCases[idx].name, (unsigned)shape, ret);
                _malformedClientRc = WH_TEST_FAIL;
            }
        }
    }

    (void)wh_Client_Cleanup(client);
    return NULL;
}


int whTest_MalformedCryptoResponse(void* ctx)
{
    uint8_t req[WH_TEST_MALFORMED_BUFFER_SIZE]  = {0};
    uint8_t resp[WH_TEST_MALFORMED_BUFFER_SIZE] = {0};

    whTransportMemConfig tmcf[1] = {{
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
    whClientConfig              c_conf[1]  = {{
                     .comm = cc_conf,
    }};

    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 1,
    }};

    pthread_t sthread;
    pthread_t cthread;
    int       rc;

    (void)ctx;

    _malformedClientRc = WH_TEST_SUCCESS;
    _malformedServerRc = WH_TEST_SUCCESS;

    rc = pthread_create(&sthread, NULL, _malformedServerThread, cs_conf);
    if (rc != 0) {
        WH_ERROR_PRINT("Fake server thread create: rc=%d\n", rc);
        return WH_TEST_FAIL;
    }

    rc = pthread_create(&cthread, NULL, _malformedClientThread, c_conf);
    if (rc != 0) {
        WH_ERROR_PRINT("Fake client thread create: rc=%d\n", rc);
        (void)pthread_cancel(sthread);
        (void)pthread_join(sthread, NULL);
        return WH_TEST_FAIL;
    }

    (void)pthread_join(cthread, NULL);
    (void)pthread_join(sthread, NULL);

    if (_malformedClientRc != WH_TEST_SUCCESS) {
        return _malformedClientRc;
    }
    return _malformedServerRc;
}

#else /* !WOLFHSM_CFG_TEST_POSIX || !WOLFHSM_CFG_ENABLE_CLIENT ||
       * WOLFHSM_CFG_NO_CRYPTO */

int whTest_MalformedCryptoResponse(void* ctx)
{
    (void)ctx;
    return WH_TEST_SKIPPED;
}

#endif
