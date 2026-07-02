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
                                 WH_NVM_FLAGS_KEK | WH_NVM_FLAGS_USAGE_WRAP,
                                 NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_GetMetadata(server->nvm, stripId, &check));
    WH_TEST_ASSERT_RETURN((check.flags & WH_NVM_FLAGS_KEK) == 0);
    WH_TEST_ASSERT_RETURN((check.flags & WH_NVM_FLAGS_USAGE_WRAP) != 0);
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, stripId));

    /* Provision a KEK-flagged key directly, as trusted
     * provisioning would. */
    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 0x57);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_KEK | WH_NVM_FLAGS_NONEXPORTABLE;
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
    WH_TEST_ASSERT_RETURN((check.flags & WH_NVM_FLAGS_KEK) != 0);
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

#endif
