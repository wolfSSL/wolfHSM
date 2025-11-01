/*
 * Copyright (C) 2024 wolfSSL Inc.
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
 * test/wh_test.c
 *
 */

#include <assert.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"
#include "wolfhsm/wh_error.h"

#include "wh_test_common.h"

/* Individual unit test drivers */
#include "wh_test_comm.h"
#include "wh_test_flash_ramsim.h"
#include "wh_test_nvm_flash.h"
#include "wh_test_crypto.h"
#include "wh_test_she.h"
#include "wh_test_clientserver.h"
#include "wh_test_keywrap.h"
#include "wh_test_multiclient.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER)
#include "wh_test_cert.h"
#endif

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
#include "wh_test_wolfcrypt_test.h"
#endif

#if defined(WOLFHSM_CFG_SERVER_IMG_MGR)
#include "wh_test_server_img_mgr.h"
#endif

#if defined(WOLFHSM_CFG_TEST_POSIX) && defined(WOLFHSM_CFG_ENABLE_CLIENT)
#include "port/posix/posix_transport_tcp.h"
#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "port/posix/posix_transport_tls.h"
#endif /* WOLFHSM_CFG_NO_CRYPTO */
#endif

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_server.h"

#if defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)
int whTest_Unit(void)
{
    printf("Enter unit tests\n");

    /* Component Tests */
    WH_TEST_ASSERT(0 == whTest_Flash_RamSim());
    WH_TEST_ASSERT(0 == whTest_NvmFlash());
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)
    WH_TEST_ASSERT(0 == whTest_CertRamSim(WH_NVM_TEST_BACKEND_FLASH));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    WH_TEST_ASSERT(0 == whTest_CertRamSim(WH_NVM_TEST_BACKEND_FLASH_LOG));
#endif /* WOLFHSM_CFG_SERVER_NVM_FLASH_LOG */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */


    /* Comm tests */
    WH_TEST_ASSERT(0 == whTest_Comm());
    WH_TEST_ASSERT(0 == whTest_ClientServer());

#ifndef WOLFHSM_CFG_NO_CRYPTO
    /* Crypto Tests */
    WH_TEST_ASSERT(0 == whTest_Crypto());

#if defined(WOLFHSM_CFG_SERVER_IMG_MGR) && !defined(WOLFHSM_CFG_NO_CRYPTO)
    /* Image Manager Tests */
    WH_TEST_ASSERT(0 == whTest_ServerImgMgr(WH_NVM_TEST_BACKEND_FLASH));

#if defined(WOLFHSM_CFG_SERVER_NVM_FLASH_LOG)
    WH_TEST_ASSERT(0 == whTest_ServerImgMgr(WH_NVM_TEST_BACKEND_FLASH_LOG));
#endif

#endif /* WOLFHSM_CFG_SERVER_IMG_MGR && !WOLFHSM_CFG_NO_CRYPTO */

    /* Multi-Client Tests (includes Global Keys when enabled) */
    WH_TEST_ASSERT(0 == whTest_MultiClient());

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    WH_TEST_ASSERT(0 == whTest_She());
#endif /* WOLFHSM_SHE_EXTENTION */

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
    WH_TEST_ASSERT(0 == whTest_WolfCryptTest());
#endif

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

    return 0;
}
#endif /* WOLFHSM_CFG_ENABLE_CLIENT && WOLFHSM_CFG_ENABLE_SERVER */

#if defined(WOLFHSM_CFG_ENABLE_CLIENT)
/*
 * Run all the client-only tests on the specified client configuration
 */
int whTest_ClientConfig(whClientConfig* clientCfg)
{
    if (clientCfg == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_RETURN_ON_FAIL(whTest_ClientServerClientConfig(clientCfg));

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
    WH_TEST_RETURN_ON_FAIL(whTest_CryptoClientConfig(clientCfg));

#if defined(WOLFHSM_CFG_KEYWRAP)
    WH_TEST_RETURN_ON_FAIL(whTest_KeyWrapClientConfig(clientCfg));
#endif /*WOLFHSM_CFG_KEYWRAP */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#if defined(WOLFHSM_CFG_SHE_EXTENSION)
    WH_TEST_RETURN_ON_FAIL(whTest_SheClientConfig(clientCfg));
#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#if defined(WOLFHSM_CFG_TEST_WOLFCRYPTTEST)
    WH_TEST_RETURN_ON_FAIL(whTest_WolfCryptTestCfg(clientCfg));
#endif /* WOLFHSM_CFG_TEST_WOLFCRYPTTEST */

    return WH_ERROR_OK;
}

#if defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP) && defined(WOLFHSM_CFG_TEST_POSIX)
/*
 * Run all the client-only tests on a default client configuration matching the
 * example server TCP configuration.
 */
int whTest_ClientTcp(void)
{
    /* Client configuration/contexts */
    whTransportClientCb            pttccb[1]      = {PTT_CLIENT_CB};
    posixTransportTcpClientContext tcc[1]         = {0};
    posixTransportTcpConfig        mytcpconfig[1] = {{
               .server_ip_string = "127.0.0.1",
               .server_port      = 23456,
    }};

    whCommClientConfig cc_conf[1] = {{
        .transport_cb      = pttccb,
        .transport_context = (void*)tcc,
        .transport_config  = (void*)mytcpconfig,
        .client_id         = WH_TEST_DEFAULT_CLIENT_ID,
    }};
    whClientConfig     c_conf[1]  = {{
             .comm = cc_conf,
    }};

    return whTest_ClientConfig(c_conf);
}
#endif /* WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP && WOLFHSM_CFG_TEST_POSIX */
#if defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TLS) && defined(WOLFHSM_CFG_TEST_POSIX)
/* client configuration setup example for TLS transport */

#define WH_POSIX_SERVER_TCP_PORT 23456
#define WH_POSIX_SERVER_TCP_IPSTRING "127.0.0.1"
#define WH_POSIX_CLIENT_ID 12

#undef USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048
#include "wolfssl/certs_test.h"

posixTransportTlsClientContext tccTls;
posixTransportTlsConfig tlsConfig;
whCommClientConfig c_comm;
whTransportClientCb tlsCb = PTTLS_CLIENT_CB;

static int
whPosixClient_ExampleTlsContextSetup(posixTransportTlsClientContext* ctx)
{
    int rc;

    /* uncomment and compile with DEBUG_WOLFSSL for debugging  */
    /* wolfSSL_Debugging_ON(); */

    /* Create a new wolfSSL context to use with this connection */
    ctx->ssl_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!ctx->ssl_ctx) {
        return WH_ERROR_ABORTED;
    }

    /* don't use wolfHSM for TLS crypto when communicating with wolfHSM */
    wolfSSL_CTX_SetDevId(ctx->ssl_ctx, INVALID_DEVID);

    /* Load CA certificate for server verification */
    rc = wolfSSL_CTX_load_verify_buffer(ctx->ssl_ctx, ca_cert_der_2048,
                                        sizeof_ca_cert_der_2048,
                                        CTC_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
        return WH_ERROR_ABORTED;
    }

    rc = wolfSSL_CTX_use_certificate_buffer(ctx->ssl_ctx, client_cert_der_2048,
                                            sizeof(client_cert_der_2048),
                                            CTC_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
        return WH_ERROR_ABORTED;
    }

    /* load private key for TLS connection */
    rc = wolfSSL_CTX_use_PrivateKey_buffer(ctx->ssl_ctx, client_key_der_2048,
                                           sizeof(client_key_der_2048),
                                           CTC_FILETYPE_ASN1);
    if (rc != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
        return WH_ERROR_ABORTED;
    }
    /* Set verification mode */
    wolfSSL_CTX_set_verify(ctx->ssl_ctx, WOLFSSL_VERIFY_PEER, NULL);

    return WH_ERROR_OK;
}

static int whPosixClient_ExampleTlsCommonConfig(void* conf)
{
    whClientConfig* c_conf = (whClientConfig*)conf;

    memset(&tccTls, 0, sizeof(posixTransportTlsClientContext));

    /* Initialize TCP context fields that need specific values */
    tccTls.state         = 0;
    tccTls.connect_fd_p1 = 0; /* Invalid fd */
    tccTls.request_sent  = 0;
    tccTls.buffer_offset = 0;

    tlsConfig.server_ip_string = WH_POSIX_SERVER_TCP_IPSTRING;
    tlsConfig.server_port      = WH_POSIX_SERVER_TCP_PORT;
    tlsConfig.verify_peer      = true;

    c_comm.transport_cb      = &tlsCb;
    c_comm.transport_context = (void*)&tccTls;
    c_comm.transport_config  = (void*)&tlsConfig;
    c_comm.client_id         = WH_POSIX_CLIENT_ID;
    c_conf->comm             = &c_comm;

    return WH_ERROR_OK;
}

int whPosixClient_ExampleTlsConfig(void* conf)
{
    if (whPosixClient_ExampleTlsCommonConfig(conf) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }

    if (whPosixClient_ExampleTlsContextSetup(&tccTls) != WH_ERROR_OK) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/*
 * Run all the client-only tests on a default client configuration matching the
 * example server TLS configuration.
 */
int whTest_ClientTls(void)
{
    int ret;
    whClientConfig c_conf[1];

    if (whPosixClient_ExampleTlsConfig(c_conf) != WH_ERROR_OK) {
       ret = -1;
    }
    else {
        ret = whTest_ClientConfig(c_conf);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_TEST_CLIENT_ONLY_TLS && WOLFHSM_CFG_TEST_POSIX */
#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#if !defined(WOLFHSM_CFG_TEST_UNIT_NO_MAIN)

int main(void)
{
    int ret = 0;

#if defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TCP) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_TEST_POSIX)
    /* Test driver should run TCP client tests against the example server */
    ret = whTest_ClientTcp();
#elif defined(WOLFHSM_CFG_TEST_CLIENT_ONLY_TLS) && \
    defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_TEST_POSIX)
    /* Test driver should run TLS client tests against the example server */
    ret = whTest_ClientTls();
#elif defined(WOLFHSM_CFG_ENABLE_CLIENT) && defined(WOLFHSM_CFG_ENABLE_SERVER)
    /* Default case: Test driver should run all the unit tests locally */
    ret = whTest_Unit();
#else
#error "No client or server enabled in build, one or both must be enabled"
#endif

    return ret;
}

#endif /* WOLFHSM_CFG_TEST_UNIT_NO_MAIN */
