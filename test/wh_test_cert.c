/*
 * Copyright (C) 2025 wolfSSL Inc.
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
 * test/wh_test_cert.c
 */

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_nvm_flash.h"
#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"
#include "wh_test_cert.h"
#include "wh_test_cert_data.h"


/* Run certificate configuration tests */
int whTest_CertServerCfg(whServerConfig* serverCfg)
{
    int rc = WH_ERROR_OK;
    whServerContext server[1] = {0};
    const whNvmId rootCertA = 1;
    const whNvmId rootCertB = 2;

    /* Initialize server */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_DEBUG_PRINT("Server initialized successfully\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Add trusted root certificate for chain A */
    WH_DEBUG_PRINT("Adding trusted root certificate for chain A...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(server, rootCertA,
                                                   ROOT_A_CERT, ROOT_A_CERT_len));

    /* Add trusted root certificate for chain B */
    WH_DEBUG_PRINT("Adding trusted root certificate for chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertB, ROOT_B_CERT, ROOT_B_CERT_len));

    /* Verify valid single cert (intermediate) */
    WH_DEBUG_PRINT(
        "Verifying valid single certificate...using intermediate cert\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, INTERMEDIATE_A_CERT, INTERMEDIATE_A_CERT_len, rootCertA));

    /* attempt to verify invalid cert (leaf w/o intermediate), should fail */
    WH_DEBUG_PRINT(
        "Attempting to verify invalid single certificate...using leaf cert "
        "without intermediate\n");
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                         wh_Server_CertVerify(server, LEAF_A_CERT, LEAF_A_CERT_len,
                                              rootCertA));

    /* attempt to verify invalid cert (intermediate with different root),
     * should fail */
    WH_DEBUG_PRINT("Attempting to verify invalid single certificate...using "
                   "intermediate cert with different root\n");
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, INTERMEDIATE_B_CERT,
                                               INTERMEDIATE_B_CERT_len,
                                               rootCertA));

    /* Verify valid chain */
    WH_DEBUG_PRINT("Verifying valid certificate chain...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA));

    /* Verify valid chain B */
    WH_DEBUG_PRINT("Verifying valid certificate chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootCertB));

    /* attempt to verify invalid chains, should fail */
    WH_DEBUG_PRINT("Attempting to verify invalid certificate chains...\n");
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                         wh_Server_CertVerify(server, RAW_CERT_CHAIN_A,
                                              RAW_CERT_CHAIN_A_len, rootCertB));
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                         wh_Server_CertVerify(server, RAW_CERT_CHAIN_B,
                                              RAW_CERT_CHAIN_B_len, rootCertA));

    /* remove trusted root certificate for chain A */
    WH_DEBUG_PRINT("Removing trusted root certificates...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertB));

    WH_DEBUG_PRINT("Test completed successfully\n");
    return rc;
}

int whTest_CertClient(whClientContext* client)
{
    int rc = WH_ERROR_OK;
    int32_t out_rc;
    whNvmId rootCertA_id = 1;
    whNvmId rootCertB_id = 2;

    WH_DEBUG_PRINT("Starting certificate client test...\n");

    /* Initialize certificate manager */
    WH_DEBUG_PRINT("Initializing certificate manager...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(client, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add root certificates to NVM */
    WH_DEBUG_PRINT("Adding root certificate A to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(client, rootCertA_id,
                                                   ROOT_A_CERT, ROOT_A_CERT_len,
                                                   &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_DEBUG_PRINT("Adding root certificate B to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(client, rootCertB_id,
                                                   ROOT_B_CERT, ROOT_B_CERT_len,
                                                   &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid single cert (intermediate) */
    WH_DEBUG_PRINT(
        "Verifying valid single certificate...using intermediate cert\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, INTERMEDIATE_A_CERT,
                                               INTERMEDIATE_A_CERT_len,
                                               rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid cert (leaf w/o intermediate), should fail */
    WH_DEBUG_PRINT(
        "Attempting to verify invalid single certificate...using leaf cert "
        "without intermediate\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, LEAF_A_CERT,
                                               LEAF_A_CERT_len,
                                               rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* attempt to verify invalid cert (intermediate with different root),
     * should fail */
    WH_DEBUG_PRINT("Attempting to verify invalid single certificate...using "
                   "intermediate cert with different root\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, INTERMEDIATE_B_CERT,
                                               INTERMEDIATE_B_CERT_len,
                                               rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Verify valid chain */
    WH_DEBUG_PRINT("Verifying valid certificate chain...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len,
                                               rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid chain B */
    WH_DEBUG_PRINT("Verifying valid certificate chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_B,
                                               RAW_CERT_CHAIN_B_len,
                                               rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid chains, should fail */
    WH_DEBUG_PRINT("Attempting to verify invalid certificate chains...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len,
                                               rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_B,
                                               RAW_CERT_CHAIN_B_len,
                                               rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Clean up - delete the root certificates */
    WH_DEBUG_PRINT("Deleting root certificates...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertEraseTrusted(client, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertEraseTrusted(client, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_DEBUG_PRINT("Certificate client test completed successfully\n");

    return rc;
}

#if defined(WOLFHSM_CFG_DMA)
/* Run certificate client DMA tests
 *
 * Only suitable for internal use in wolfHSM test harness, as it requires
 * the client and server to have direct access to each others process memory
 * and assumes the server has the appropriate DMA translation configured */
int whTest_CertClientDma_ClientServerTestInternal(whClientContext* client)
{
    int rc = WH_ERROR_OK;
    int32_t out_rc;
    whNvmId rootCertA_id = 1;
    whNvmId rootCertB_id = 2;

    WH_DEBUG_PRINT("Starting certificate client DMA test...\n");

    /* Initialize certificate manager */
    WH_DEBUG_PRINT("Initializing certificate manager...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(client, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add root certificates to NVM */
    WH_DEBUG_PRINT("Adding root certificate A to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrustedDma(client, rootCertA_id,
                                                      ROOT_A_CERT, ROOT_A_CERT_len,
                                                      &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_DEBUG_PRINT("Adding root certificate B to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrustedDma(client, rootCertB_id,
                                                      ROOT_B_CERT, ROOT_B_CERT_len,
                                                      &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid single cert (intermediate) */
    WH_DEBUG_PRINT(
        "Verifying valid single certificate...using intermediate cert\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, INTERMEDIATE_A_CERT,
                                                  INTERMEDIATE_A_CERT_len,
                                                  rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid cert (leaf w/o intermediate), should fail */
    WH_DEBUG_PRINT(
        "Attempting to verify invalid single certificate...using leaf cert "
        "without intermediate\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, LEAF_A_CERT,
                                                  LEAF_A_CERT_len,
                                                  rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* attempt to verify invalid cert (intermediate with different root),
     * should fail */
    WH_DEBUG_PRINT("Attempting to verify invalid single certificate...using "
                   "intermediate cert with different root\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, INTERMEDIATE_B_CERT,
                                                  INTERMEDIATE_B_CERT_len,
                                                  rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Verify valid chain */
    WH_DEBUG_PRINT("Verifying valid certificate chain...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, RAW_CERT_CHAIN_A,
                                                  RAW_CERT_CHAIN_A_len,
                                                  rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid chain B */
    WH_DEBUG_PRINT("Verifying valid certificate chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, RAW_CERT_CHAIN_B,
                                                  RAW_CERT_CHAIN_B_len,
                                                  rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid chains, should fail */
    WH_DEBUG_PRINT("Attempting to verify invalid certificate chains...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, RAW_CERT_CHAIN_A,
                                                  RAW_CERT_CHAIN_A_len,
                                                  rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, RAW_CERT_CHAIN_B,
                                                  RAW_CERT_CHAIN_B_len,
                                                  rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Clean up - delete the root certificates */
    WH_DEBUG_PRINT("Deleting root certificates...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertEraseTrusted(client, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertEraseTrusted(client, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_DEBUG_PRINT("Certificate client DMA test completed successfully\n");

    return rc;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_CertRamSim(void)
{
    int rc = WH_ERROR_OK;
    const uint32_t BUFFER_SIZE = 1024;

    /* Transport memory configuration */
    uint8_t              req[BUFFER_SIZE];
    uint8_t              resp[BUFFER_SIZE];
    whTransportMemConfig tmcf[1] = {{
        .req       = (whTransportMemCsr*)req,
        .req_size  = sizeof(req),
        .resp      = (whTransportMemCsr*)resp,
        .resp_size = sizeof(resp),
    }};

    /* Server configuration/contexts */
    whTransportServerCb         tscb[1]    = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmsc[1]    = {0};
    whCommServerConfig          cs_conf[1] = {{
                 .transport_cb      = tscb,
                 .transport_context = (void*)tmsc,
                 .transport_config  = (void*)tmcf,
                 .server_id         = 124,
    }};
    /* RamSim Flash state and configuration */
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = 1024 * 1024, /* 1MB  Flash */
        .sectorSize = 128 * 1024,  /* 128KB  Sector Size */
        .pageSize   = 8,           /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    /* NVM Flash Configuration using RamSim HAL Flash */
    whNvmFlashConfig  nf_conf[1] = {{
         .cb      = fcb,
         .context = fc,
         .config  = fc_conf,
    }};
    whNvmFlashContext nfc[1]     = {0};
    whNvmCb           nfcb[1]    = {WH_NVM_FLASH_CB};

    whNvmConfig  n_conf[1] = {{
         .cb      = nfcb,
         .context = nfc,
         .config  = nf_conf,
    }};
    whNvmContext nvm[1]    = {{0}};
#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1] = {{
        .devId = INVALID_DEVID,
    }};
#endif

    whServerConfig  s_conf[1] = {{
         .comm_config = cs_conf,
         .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
         .crypto      = crypto,
#endif
    }};

    /* Initialize NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, crypto->devId));
#endif

    /* Run certificate configuration tests */
    rc = whTest_CertServerCfg(s_conf);
    if (rc != WH_ERROR_OK) {
        printf("Certificate server config tests failed: %d\n", rc);
    }

    /* Cleanup NVM */
    wh_Nvm_Cleanup(nvm);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return rc;
}

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
