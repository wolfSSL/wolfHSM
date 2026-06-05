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
 * test-refactor/wh_test_cert.c
 *
 * Server-side certificate test suite. Exercises the cert
 * manager through direct server API calls. Uses the shared
 * server context for setup/cleanup.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_message_cert.h"

#include "wh_test_common.h"
#include "wh_test_list.h"
#include "wh_test_cert_data.h"


/*
 * Add trusted roots, verify valid and invalid certs/chains,
 * then remove roots.
 */
int whTest_CertVerify(whServerContext* ctx)
{
    whServerContext* server = (whServerContext*)ctx;
    const whNvmId rootA = 1;
    const whNvmId rootB = 2;

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Add trusted roots */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootA, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootB, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_B_CERT, ROOT_B_CERT_len));

    /* Valid single cert (intermediate against its root) */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, INTERMEDIATE_A_CERT, INTERMEDIATE_A_CERT_len,
        rootA, WH_CERT_FLAGS_NONE,
        WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Invalid: leaf without intermediate -- must fail */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_CERT_VERIFY == wh_Server_CertVerify(
            server, LEAF_A_CERT, LEAF_A_CERT_len,
            rootA, WH_CERT_FLAGS_NONE,
            WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Invalid: intermediate against wrong root */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_CERT_VERIFY == wh_Server_CertVerify(
            server, INTERMEDIATE_B_CERT,
            INTERMEDIATE_B_CERT_len,
            rootA, WH_CERT_FLAGS_NONE,
            WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Valid chains */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len,
        rootA, WH_CERT_FLAGS_NONE,
        WH_NVM_FLAGS_USAGE_ANY, NULL));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len,
        rootB, WH_CERT_FLAGS_NONE,
        WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Cross-chain: must fail */
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_CERT_VERIFY == wh_Server_CertVerify(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len,
            rootB, WH_CERT_FLAGS_NONE,
            WH_NVM_FLAGS_USAGE_ANY, NULL));

    WH_TEST_ASSERT_RETURN(
        WH_ERROR_CERT_VERIFY == wh_Server_CertVerify(
            server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len,
            rootA, WH_CERT_FLAGS_NONE,
            WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Remove trusted roots */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertEraseTrusted(server, rootA));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertEraseTrusted(server, rootB));

    return 0;
}

/*
 * Cert add/erase are client-driven, so they must respect NVM
 * flag policy: server-only flags are stripped on add, a
 * server-only (KEK) object can be neither overwritten nor
 * destroyed, and a NONDESTROYABLE cert survives erase.
 */
int whTest_CertNvmPolicy(whServerContext* ctx)
{
    whServerContext* server  = (whServerContext*)ctx;
    whNvmMetadata    meta    = {0};
    whNvmMetadata    check   = {0};
    const uint8_t    kek[16] = {0xA5};
    const whNvmId    stripId = 0x55;
    const whNvmId    certId  = 0x58;

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Server-only flags must be stripped from a client add. */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertAddTrusted(server, stripId, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP,
                                 NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_GetMetadata(server->nvm, stripId, &check));
    WH_TEST_ASSERT_RETURN((check.flags & WH_NVM_FLAGS_TRUSTED) == 0);
    WH_TEST_ASSERT_RETURN((check.flags & WH_NVM_FLAGS_USAGE_WRAP) != 0);
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, stripId));

    /* Provision a KEK-flagged key directly, as trusted
     * provisioning would. */
    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 0x57);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_NONEXPORTABLE;
    meta.len    = sizeof(kek);
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, sizeof(kek), kek));

    /* Cert erase must not destroy it. */
    WH_TEST_ASSERT_RETURN(wh_Server_CertEraseTrusted(server, meta.id) ==
                          WH_ERROR_ACCESS);

    /* Cert add must not overwrite it. */
    WH_TEST_ASSERT_RETURN(
        wh_Server_CertAddTrusted(server, meta.id, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_NONE, NULL, 0, ROOT_A_CERT,
                                 ROOT_A_CERT_len) == WH_ERROR_ACCESS);

    /* The KEK must be untouched. */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_GetMetadata(server->nvm, meta.id, &check));
    WH_TEST_ASSERT_RETURN((check.flags & WH_NVM_FLAGS_TRUSTED) != 0);
    WH_TEST_ASSERT_RETURN(check.len == sizeof(kek));

    /* Server-internal unchecked destroy still works; clean up. */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    /* A NONDESTROYABLE cert must also survive cert erase. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, certId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONDESTROYABLE, NULL, 0,
        ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_ASSERT_RETURN(wh_Server_CertEraseTrusted(server, certId) ==
                          WH_ERROR_ACCESS);
    meta.id = certId;
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    return 0;
}

/*
 * Keys and certs share the NVM id space, so a client that passes a
 * trusted KEK's id to a cert read handler must be refused. The KEK
 * flag alone (no NONEXPORTABLE) must be enough: the dispatcher is
 * the only gate, since wh_Server_CertReadTrusted() does an unchecked
 * NVM read. Driven through wh_Server_HandleCertRequest() because the
 * check lives in the dispatcher, not the server cert API.
 */
int whTest_CertReadRejectsServerOnly(whServerContext* ctx)
{
    whServerContext* server  = (whServerContext*)ctx;
    whNvmMetadata    meta    = {0};
    const uint8_t    kek[32] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    const uint16_t   magic   = WH_COMM_MAGIC_NATIVE;
    uint8_t          req_packet[WOLFHSM_CFG_COMM_DATA_LEN]  = {0};
    uint8_t          resp_packet[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t         resp_size                              = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Provision a trusted KEK the way whnvmtool would, deliberately
     * WITHOUT NONEXPORTABLE, to prove the trusted flag alone gates the
     * read. */
    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 0x5A);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP;
    meta.len    = sizeof(kek);
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, sizeof(kek), kek));

    /* READTRUSTED must refuse the KEK id and return no cert bytes.
     * The handler formats resp.rc and also returns it; resp.rc is the
     * client-visible signal, so assert on that. */
    {
        whMessageCert_ReadTrustedRequest  req  = {0};
        whMessageCert_ReadTrustedResponse resp = {0};

        req.id = meta.id;
        wh_MessageCert_TranslateReadTrustedRequest(
            magic, &req, (whMessageCert_ReadTrustedRequest*)req_packet);

        (void)wh_Server_HandleCertRequest(
            server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED, 0, sizeof(req),
            req_packet, &resp_size, resp_packet);

        wh_MessageCert_TranslateReadTrustedResponse(
            magic, (whMessageCert_ReadTrustedResponse*)resp_packet, &resp);

        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_ACCESS);
        WH_TEST_ASSERT_RETURN(resp.cert_len == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(resp));
    }

#ifdef WOLFHSM_CFG_DMA
    /* READTRUSTED_DMA must refuse it too and write nothing. */
    {
        whMessageCert_ReadTrustedDmaRequest req  = {0};
        whMessageCert_SimpleResponse        resp = {0};
        uint8_t                             out_buf[64];
        size_t                              i;

        memset(out_buf, 0, sizeof(out_buf));
        req.id        = meta.id;
        req.cert_addr = (uint64_t)(uintptr_t)out_buf;
        req.cert_len  = sizeof(out_buf);
        wh_MessageCert_TranslateReadTrustedDmaRequest(
            magic, &req, (whMessageCert_ReadTrustedDmaRequest*)req_packet);

        resp_size = 0;
        (void)wh_Server_HandleCertRequest(
            server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA, 0,
            sizeof(req), req_packet, &resp_size, resp_packet);

        wh_MessageCert_TranslateSimpleResponse(
            magic, (whMessageCert_SimpleResponse*)resp_packet, &resp);

        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_ACCESS);
        for (i = 0; i < sizeof(out_buf); i++) {
            WH_TEST_ASSERT_RETURN(out_buf[i] == 0);
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    /* Server-internal unchecked destroy still works; clean up. */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    return 0;
}

#endif
