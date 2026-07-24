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
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_cert.h"

#ifdef WOLFHSM_CFG_ENABLE_SERVER
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_message_cert.h"
#include "wolfhsm/wh_flash_ramsim.h"
#include "wolfhsm/wh_nvm_flash.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
#include "wolfhsm/wh_client.h"
#endif

#include "wolfhsm/wh_transport_mem.h"

#include "wh_test_common.h"
#include "wh_test_cert.h"
#include "wh_test_cert_data.h"
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
#include "wh_test_cert_data_acert.h"
#endif

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
static int whTest_CertNonExportable(whClientContext* client);
#endif

#define FLASH_RAM_SIZE (1024 * 1024) /* 1MB */
#define FLASH_SECTOR_SIZE (128 * 1024) /* 128KB */
#define FLASH_PAGE_SIZE (8) /* 8B */

#ifdef WOLFHSM_CFG_ENABLE_SERVER
/* Run certificate configuration tests */
int whTest_CertServerCfg(whServerConfig* serverCfg)
{
    int             rc        = WH_ERROR_OK;
    whServerContext server[1] = {0};
    const whNvmId   rootCertA = 1;
    const whNvmId   rootCertB = 2;

    /* Initialize server */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_PRINT("Server initialized successfully\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Add trusted root certificate for chain A */
    WH_TEST_PRINT("Adding trusted root certificate for chain A...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));

    /* Add trusted root certificate for chain B */
    WH_TEST_PRINT("Adding trusted root certificate for chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertB, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_B_CERT, ROOT_B_CERT_len));

    /* Verify valid single cert (intermediate) */
    WH_TEST_PRINT(
        "Verifying valid single certificate...using intermediate cert\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, INTERMEDIATE_A_CERT, INTERMEDIATE_A_CERT_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* attempt to verify invalid cert (leaf w/o intermediate), should fail */
    WH_TEST_PRINT(
        "Attempting to verify invalid single certificate...using leaf cert "
        "without intermediate\n");
    WH_TEST_ASSERT_RETURN(
        WH_ERROR_CERT_VERIFY ==
        wh_Server_CertVerify(server, LEAF_A_CERT, LEAF_A_CERT_len, rootCertA,
                             WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* attempt to verify invalid cert (intermediate with different root),
     * should fail */
    WH_TEST_PRINT("Attempting to verify invalid single certificate...using "
                   "intermediate cert with different root\n");
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, INTERMEDIATE_B_CERT,
                                               INTERMEDIATE_B_CERT_len,
                                               rootCertA, WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Verify valid chain */
    WH_TEST_PRINT("Verifying valid certificate chain...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* Verify valid chain B */
    WH_TEST_PRINT("Verifying valid certificate chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootCertB,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* attempt to verify invalid chains, should fail. Cache entries are scoped
     * to the trusted root NVM ID, so prior positive verifies under the true
     * root cannot bypass these cross-root checks. */
    WH_TEST_PRINT("Attempting to verify invalid certificate chains...\n");
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len, rootCertB,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, RAW_CERT_CHAIN_B,
                                               RAW_CERT_CHAIN_B_len, rootCertA,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* ===== Multi-root verification tests ===== */
    {
        const whNvmId rootCertC_absent     = 99;
        whNvmId       roots_AB[2]          = {rootCertA, rootCertB};
        whNvmId       roots_BA[2]          = {rootCertB, rootCertA};
        whNvmId       roots_A_absent[2]    = {rootCertA, rootCertC_absent};
        whNvmId       roots_only_absent[2] = {rootCertC_absent, 100};
        whNvmId       roots_max[WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS];
        uint16_t      i;

        /* (1) Single root via multi-root path */
        WH_TEST_PRINT("Multi-root: single-element array, chain matches...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertA, 1,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        WH_TEST_PRINT("Multi-root: single-element array, chain mismatch...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_CERT_VERIFY ==
            wh_Server_CertVerifyMultiRoot(
                server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertB, 1,
                WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* (2) Two roots, chain matches first */
        WH_TEST_PRINT("Multi-root: two roots [A,B], chain anchors to A...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* (3) Two roots, chain matches second */
        WH_TEST_PRINT("Multi-root: two roots [A,B], chain anchors to B...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
            server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_AB, 2,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* (4) Two roots, chain matches neither (incomplete chain: leaf
         * without its intermediate cannot be anchored to A or B) */
        WH_TEST_PRINT(
            "Multi-root: two roots [A,B], chain matches neither...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_CERT_VERIFY ==
            wh_Server_CertVerifyMultiRoot(server, LEAF_A_CERT, LEAF_A_CERT_len,
                                          roots_AB, 2, WH_CERT_FLAGS_NONE,
                                          WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* (5) One present root, one absent root */
        WH_TEST_PRINT("Multi-root: roots [A, absent], chain anchors to A "
                      "succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_A_absent, 2,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        WH_TEST_PRINT("Multi-root: roots [A, absent], chain B fails with "
                      "CERT_VERIFY...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_CERT_VERIFY ==
            wh_Server_CertVerifyMultiRoot(
                server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_A_absent,
                2, WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* (6) All supplied roots absent */
        WH_TEST_PRINT("Multi-root: all supplied roots absent → NOTFOUND...\n");
        WH_TEST_ASSERT_RETURN(WH_ERROR_NOTFOUND ==
                              wh_Server_CertVerifyMultiRoot(
                                  server, RAW_CERT_CHAIN_A,
                                  RAW_CERT_CHAIN_A_len, roots_only_absent, 2,
                                  WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY,
                                  NULL));

        /* (7) Boundary on numRoots */
        WH_TEST_PRINT("Multi-root: numRoots == 0 → BADARGS...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_BADARGS ==
            wh_Server_CertVerifyMultiRoot(
                server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertA, 0,
                WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        WH_TEST_PRINT("Multi-root: numRoots > MAX → BADARGS...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_BADARGS ==
            wh_Server_CertVerifyMultiRoot(
                server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_max,
                WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1, WH_CERT_FLAGS_NONE,
                WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* numRoots == MAX, mostly absent ids plus rootCertA, succeeds */
        roots_max[0] = rootCertA;
        for (i = 1; i < WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS; i++) {
            roots_max[i] = (whNvmId)(200 + i); /* nonexistent */
        }
        WH_TEST_PRINT(
            "Multi-root: numRoots == MAX with mostly-absent succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_max,
            WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS, WH_CERT_FLAGS_NONE,
            WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* (12) Order independence: [A,B] and [B,A] both succeed for chain B */
        WH_TEST_PRINT("Multi-root: order independence [B,A] for chain B...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
            server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_BA, 2,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

        /* Equivalence with single-root entry point */
        WH_TEST_PRINT(
            "Multi-root: equivalence with single-root entry point...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    }

    /* remove trusted root certificate for chain A */
    WH_TEST_PRINT("Removing trusted root certificates...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertB));

    WH_TEST_PRINT("Test completed successfully\n");
    return rc;
}

/* AddTrusted is a client-driven path, so it must strip server-only flags.
 * Confirm the trusted flag is dropped while a normal client-settable flag
 * survives. */
static int
whTest_CertServerAddTrustedStripsServerFlags(whServerConfig* serverCfg)
{
    int             rc        = WH_ERROR_OK;
    whServerContext server[1] = {0};
    const whNvmId   kekCertId = 0x55;
    whNvmMetadata   meta      = {0};

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_PRINT("Cert AddTrusted strips server-only flags...\n");

    /* Ask for the server-only trusted flag plus a normal usage flag. */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertAddTrusted(server, kekCertId, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP,
                                 NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len));

    /* Read back what was actually stored. */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_GetMetadata(server->nvm, kekCertId, &meta));

    /* Trusted flag must be gone; the normal flag must remain. */
    WH_TEST_ASSERT_RETURN((meta.flags & WH_NVM_FLAGS_TRUSTED) == 0);
    WH_TEST_ASSERT_RETURN((meta.flags & WH_NVM_FLAGS_USAGE_WRAP) != 0);

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, kekCertId));

    WH_TEST_PRINT("Cert AddTrusted server-only flag strip PASSED\n");
    return rc;
}

/* Keys and certs share the NVM id space, and AddTrusted/EraseTrusted are
 * client-driven, so both must respect NVM flag policy: a client must not be
 * able to overwrite or destroy a protected object (e.g. a trusted KEK)
 * through the cert API. */
static int whTest_CertServerTrustedRespectsNvmPolicy(whServerConfig* serverCfg)
{
    int             rc        = WH_ERROR_OK;
    whServerContext server[1] = {0};
    whNvmMetadata   meta      = {0};
    whNvmMetadata   check     = {0};
    const uint8_t   kek[16]   = {0xA5};

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_PRINT("Cert AddTrusted/EraseTrusted respect NVM policy...\n");

    /* Provision a KEK-flagged key directly, as trusted provisioning would. */
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

    /* Server-internal unchecked destroy still works; clean up with it. */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    /* A NONDESTROYABLE cert must also survive cert erase. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, 0x58, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONDESTROYABLE, NULL, 0,
        ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_ASSERT_RETURN(wh_Server_CertEraseTrusted(server, 0x58) ==
                          WH_ERROR_ACCESS);
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_GetMetadata(server->nvm, 0x58, &check));
    meta.id = 0x58;
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    WH_TEST_PRINT("Cert NVM policy test PASSED\n");
    return rc;
}

/* Keys and certs share the NVM id space, so a client that passes a trusted
 * KEK's id to a cert read handler must be refused. The trusted flag alone (no
 * NONEXPORTABLE) must be enough: the dispatcher is the only gate, since
 * wh_Server_CertReadTrusted() does an unchecked NVM read. Provision a
 * KEK-flagged object without NONEXPORTABLE and confirm both READTRUSTED and
 * READTRUSTED_DMA return WH_ERROR_ACCESS and leak no bytes. Driven through
 * wh_Server_HandleCertRequest() because the check lives in the dispatcher,
 * not in the server cert API. */
static int
whTest_CertServerReadTrustedRejectsServerOnly(whServerConfig* serverCfg)
{
    int             rc        = WH_ERROR_OK;
    whServerContext server[1] = {0};
    whNvmMetadata   meta      = {0};
    /* Recognizable KEK bytes so any leak into the response is obvious. */
    const uint8_t  kek[32] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                              0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                              0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                              0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    const uint16_t magic   = WH_COMM_MAGIC_NATIVE;
    uint8_t        req_packet[WOLFHSM_CFG_COMM_DATA_LEN]  = {0};
    uint8_t        resp_packet[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t       resp_size                              = 0;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_PRINT("Cert ReadTrusted rejects server-only KEK...\n");

    /* Provision a trusted KEK the way whnvmtool would, deliberately WITHOUT
     * NONEXPORTABLE, to prove the trusted flag alone gates the read. */
    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 0x5A);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP;
    meta.len    = sizeof(kek);
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, sizeof(kek), kek));

    /* READTRUSTED must refuse the KEK id and return no cert bytes. */
    {
        whMessageCert_ReadTrustedRequest  req  = {0};
        whMessageCert_ReadTrustedResponse resp = {0};

        req.id = meta.id;
        wh_MessageCert_TranslateReadTrustedRequest(
            magic, &req, (whMessageCert_ReadTrustedRequest*)req_packet);

        /* The handler formats resp.rc and also returns it; resp.rc is the
         * client-visible signal, so assert on that rather than the return. */
        (void)wh_Server_HandleCertRequest(
            server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED, /*seq=*/0,
            sizeof(req), req_packet, &resp_size, resp_packet);

        wh_MessageCert_TranslateReadTrustedResponse(
            magic, (whMessageCert_ReadTrustedResponse*)resp_packet, &resp);

        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_ACCESS);
        WH_TEST_ASSERT_RETURN(resp.cert_len == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(resp));
    }

#ifdef WOLFHSM_CFG_DMA
    /* READTRUSTED_DMA must refuse it too and write nothing to the buffer. */
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
            server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED_DMA, /*seq=*/0,
            sizeof(req), req_packet, &resp_size, resp_packet);

        wh_MessageCert_TranslateSimpleResponse(
            magic, (whMessageCert_SimpleResponse*)resp_packet, &resp);

        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_ACCESS);
        for (i = 0; i < sizeof(out_buf); i++) {
            WH_TEST_ASSERT_RETURN(out_buf[i] == 0);
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    /* Server-internal unchecked destroy still works; clean up with it. */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    WH_TEST_PRINT("Cert ReadTrusted server-only rejection PASSED\n");
    return rc;
}

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
/* Exercises the trusted-cert verify cache directly through the server API:
 *  - repeat-verify of the same chain under the same root stays successful
 *  - cache entries are bound to the trusted root NVM ID: chain A under root B
 *    must fail even after chain A has been cached by a verify under root A
 *    (regression test against cross-root cache bypass)
 *  - clearing the cache leaves the cross-root case still failing */
static int whTest_CertServerVerifyCache(whServerConfig* serverCfg)
{
    whServerContext server[1] = {0};
    const whNvmId   rootCertA = 1;
    const whNvmId   rootCertB = 2;

    WH_TEST_PRINT("=== Server cert verify-cache test ===\n");

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertB, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_B_CERT, ROOT_B_CERT_len));

    /* 1. Repeat-verify hit: verify chain A twice under root A; both succeed. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* 2. Cache is bound to root NVM ID: chain A under root B must fail even
     * though every cert in chain A was cached under root A by step 1. The
     * cache hit must not let an unsigned-by-rootB chain through. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len, rootCertB,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* 3. Clear: the same cross-root verify still fails cold. */
    wh_Server_CertVerifyCache_Clear(server);
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len, rootCertB,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertB));
    WH_TEST_PRINT("Server cert verify-cache test PASSED\n");
    return WH_ERROR_OK;
}

/* Counts verify-callback invocations for the eviction-on-re-add test. A cache
 * hit short-circuits wolfSSL's verify path and bypasses the callback, so the
 * counter distinguishes cold verifies (callback fires per cert) from warm
 * verifies (callback skipped on CA hits). */
static int s_evictReAddCb_count = 0;
static int whTest_evictReAddVerifyCb(int                     preverify,
                                     WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    s_evictReAddCb_count++;
    return preverify;
}

/* Exercises the cache-eviction hook in wh_Server_CertAddTrusted on re-add:
 *  - warm the cache by verifying chain A under root A at NVM id N
 *  - re-add a DIFFERENT root (root B) at the SAME id N
 *  - assert: re-verify of chain A under id N must fail. If the eviction hook
 *    failed to drop the slots bound to id N, the cached CAs from chain A
 *    would short-circuit the signature checks and let chain A through under
 *    root B — exactly the staleness window EvictRoot exists to close.
 *
 * Regression target: a refactor that drops the EvictRoot call from the
 * AddTrusted success path, moves it under the wrong branch, or removes the
 * `if (rc == WH_ERROR_OK)` guard. No existing test exercises re-add at the
 * same id, so such a regression would slip through the suite. */
static int whTest_CertServerVerifyCacheEvictOnReAdd(whServerConfig* serverCfg)
{
    whServerContext     server[1] = {0};
    whServerCertConfig  certCfg   = {.verifyCb = whTest_evictReAddVerifyCb};
    whServerCertConfig* savedCertConfig;
    const whNvmId       rootId = 1;
    int                 coldCount;
    int                 warmCount;

    WH_TEST_PRINT("=== Server cert verify-cache evict-on-re-add test ===\n");

    /* Inject the counting callback so we can detect cache hits by absence of
     * callback fires. Restore on exit. */
    savedCertConfig       = serverCfg->certConfig;
    serverCfg->certConfig = &certCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Add root A at the target id. Use NONE (not NONMODIFIABLE) so the re-add
     * below passes the NVM add policy check and exercises the success path
     * that fires EvictRoot. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, NULL, 0,
        ROOT_A_CERT, ROOT_A_CERT_len));

    /* Start cold under the global-shared cache mode where prior tests may
     * have populated entries. Per-client mode is already clean. */
    wh_Server_CertVerifyCache_Clear(server);

    /* 1. Cold verify under root A at id N. Callback fires for every cert. */
    s_evictReAddCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootId,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    coldCount = s_evictReAddCb_count;
    WH_TEST_ASSERT_RETURN(coldCount > 0);

    /* 2. Re-verify confirms the cache actually warmed: CA hits skip the
     * callback, so the count must drop below cold. */
    s_evictReAddCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootId,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    warmCount = s_evictReAddCb_count;
    WH_TEST_ASSERT_RETURN(warmCount > 0);
    WH_TEST_ASSERT_RETURN(warmCount < coldCount);

    /* 3. Re-add root B at the SAME id. The eviction hook must drop every
     * slot whose stored root set contains id N. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONE, NULL, 0,
        ROOT_B_CERT, ROOT_B_CERT_len));

    /* 4. Re-verify chain A under id N. Root B does not sign chain A, so a
     * sound trust store rejects it with WH_ERROR_CERT_VERIFY. If eviction
     * failed, the cached intermediate from step 1 would hit, get loaded
     * into the cert manager as a trusted CA via wolfSSL_CertManagerLoad-
     * CABuffer, and the leaf would then verify against it — masking the
     * failure that the no-cache build would produce. */
    s_evictReAddCb_count = 0;
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len, rootId,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));
    /* Callback must have fired on the failing path. Zero would mean every
     * cert short-circuited via cache hit — the regression. */
    WH_TEST_ASSERT_RETURN(s_evictReAddCb_count > 0);

    /* 5. Verify chain B under id N succeeds (root B is now the anchor) and
     * runs cold — sanity check that the swap actually replaced the root and
     * that no stale entries survived from the chain-A warm. */
    s_evictReAddCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootId,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_evictReAddCb_count > 0);

    /* Cleanup */
    wh_Server_CertVerifyCache_Clear(server);
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootId));
    serverCfg->certConfig = savedCertConfig;
    WH_TEST_PRINT("Server cert verify-cache evict-on-re-add test PASSED\n");
    return WH_ERROR_OK;
}

/* Counts verify-callback invocations for the multi-root subset rule test. */
static int s_subsetRuleCb_count = 0;
static int whTest_subsetRuleVerifyCb(int                     preverify,
                                     WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    s_subsetRuleCb_count++;
    return preverify;
}

/* Exercises both directions of the cache subset rule against
 * wh_Server_CertVerifyMultiRoot with cache-hit observability:
 *  - SOUND HIT: a stored {R} entry must hit a future verify whose loaded
 *    set is a superset {R, R2}. A single-root verify warms the cache;
 *    the subsequent multi-root verify sees CA hits and runs warm.
 *  - SOUND MISS: a stored {R, R2} entry must NOT hit a future verify whose
 *    loaded set is only {R}. A multi-root verify warms a wider entry; the
 *    subsequent single-root verify with only one root loaded must re-verify
 *    cold (no hits).
 *
 * Regression target: a swapped _IsSubsetOf argument direction would let
 * wider cache entries hit narrower lookups — the cross-root bypass class.
 * Existing multi-root tests run with the cache enabled but only assert
 * verify success/failure, so they cannot tell a cache hit from a cold
 * verify and would not catch this regression. */
static int
whTest_CertServerVerifyCacheMultiRootSubset(whServerConfig* serverCfg)
{
    whServerContext     server[1] = {0};
    whServerCertConfig  certCfg   = {.verifyCb = whTest_subsetRuleVerifyCb};
    whServerCertConfig* savedCertConfig;
    const whNvmId       rootCertA   = 1;
    const whNvmId       rootCertB   = 2;
    whNvmId             roots_AB[2] = {rootCertA, rootCertB};
    int                 coldSingle;
    int                 warmMulti;
    int                 coldMulti;

    WH_TEST_PRINT(
        "=== Server cert verify-cache multi-root subset rule test ===\n");

    savedCertConfig       = serverCfg->certConfig;
    serverCfg->certConfig = &certCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertB, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_B_CERT, ROOT_B_CERT_len));

    /* Start cold in case a prior test populated entries (relevant under
     * global mode where the cache survives server (re)init). */
    wh_Server_CertVerifyCache_Clear(server);

    /* === Direction 1: stored {A} HITS lookup against superset {A, B} === */

    /* 1a. Cold single-root verify under {A} inserts {A}-bound entries. */
    s_subsetRuleCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    coldSingle = s_subsetRuleCb_count;
    WH_TEST_ASSERT_RETURN(coldSingle > 0);

    /* 1b. Multi-root verify against {A, B}: stored {A} is a subset of
     * {A, B}, so CA cache hits short-circuit the callback. Warm count must
     * be strictly less than the cold single-root baseline. A bug that
     * widened the recorded set or swapped the subset direction would
     * make this MISS and re-verify cold. */
    s_subsetRuleCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    warmMulti = s_subsetRuleCb_count;
    WH_TEST_ASSERT_RETURN(warmMulti > 0);
    WH_TEST_ASSERT_RETURN(warmMulti < coldSingle);

    /* === Direction 2: stored {A, B} does NOT hit lookup against {A} === */

    /* Wipe so direction 2 is unambiguous. */
    wh_Server_CertVerifyCache_Clear(server);

    /* 2a. Cold multi-root verify under {A, B} inserts {A, B}-bound entries.
     * Both roots are present so the slot records the full two-element set
     * (cf. §7.1: "the loaded set is recorded, not the caller-supplied set"). */
    s_subsetRuleCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyMultiRoot(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    coldMulti = s_subsetRuleCb_count;
    WH_TEST_ASSERT_RETURN(coldMulti > 0);

    /* 2b. Single-root verify under {A}: stored {A, B} is NOT a subset of
     * {A}, so the lookup must MISS and the verify must run cold. A bug
     * that swapped the subset direction would make this HIT and short-
     * circuit the signature check — the cross-root bypass we are guarding
     * against. Equality with coldMulti confirms zero hits on the CA. */
    s_subsetRuleCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_subsetRuleCb_count == coldMulti);

    /* Cleanup */
    wh_Server_CertVerifyCache_Clear(server);
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertB));
    serverCfg->certConfig = savedCertConfig;
    WH_TEST_PRINT(
        "Server cert verify-cache multi-root subset rule test PASSED\n");
    return WH_ERROR_OK;
}

/* Counts verify-callback invocations so we can tell a cold verify (callback
 * fires for every cert) from a warm verify (callback skipped on cache hits).
 * Used by the SetEnabled test below to confirm that disabling actually
 * suppresses cache hits. */
static int s_setEnabledCb_count = 0;
static int whTest_setEnabledVerifyCb(int                     preverify,
                                     WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    s_setEnabledCb_count++;
    return preverify;
}

/* Exercises wh_Server_CertVerifyCache_SetEnabled:
 *  - disable flushes existing entries and suppresses subsequent cache hits
 *    (a re-verify after disable runs cold, callback fires the full count)
 *  - re-enable resumes caching (a verify after re-enable populates, the next
 *    re-verify warms — callback count drops back down)
 *  - default state is enabled (covered implicitly by the cold/warm counts) */
static int whTest_CertServerVerifyCacheSetEnabled(whServerConfig* serverCfg)
{
    whServerContext     server[1] = {0};
    whServerCertConfig  certCfg   = {.verifyCb = whTest_setEnabledVerifyCb};
    whServerCertConfig* savedCertConfig;
    const whNvmId       rootCertA = 1;
    int                 coldCount;
    int                 warmCount;
    int                 afterDisableCount;

    WH_TEST_PRINT("=== Server cert verify-cache set-enabled test ===\n");

    /* Inject the counting callback so we can detect cache hits by absence of
     * callback fires. Restore on exit. */
    savedCertConfig       = serverCfg->certConfig;
    serverCfg->certConfig = &certCfg;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));

    /* Start cold under the global-shared cache mode where prior tests may
     * have populated entries. Per-client mode is already clean. */
    wh_Server_CertVerifyCache_Clear(server);

    /* 1. Cold verify under default-enabled cache: callback fires for every
     * cert in the chain. */
    s_setEnabledCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    coldCount = s_setEnabledCb_count;
    WH_TEST_ASSERT_RETURN(coldCount > 0);

    /* 2. Re-verify with cache still enabled: CA cache hits skip the callback,
     * so the count is strictly less than cold. */
    s_setEnabledCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    warmCount = s_setEnabledCb_count;
    WH_TEST_ASSERT_RETURN(warmCount > 0);
    WH_TEST_ASSERT_RETURN(warmCount < coldCount);

    /* 3. Disable the cache. Entries from steps 1-2 must be flushed and new
     * inserts suppressed: the next verify should be cold again (count back
     * up to coldCount). */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyCache_SetEnabled(server, 0));
    s_setEnabledCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    afterDisableCount = s_setEnabledCb_count;
    WH_TEST_ASSERT_RETURN(afterDisableCount == coldCount);

    /* 4. Second verify while still disabled — also cold (no caching). */
    s_setEnabledCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_setEnabledCb_count == coldCount);

    /* 5. Re-enable. The post-disable verify did not populate the cache, so
     * the first re-enabled verify is still cold (and populates). */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyCache_SetEnabled(server, 1));
    s_setEnabledCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_setEnabledCb_count == coldCount);

    /* 6. Subsequent verify warms, matching step 2's warmCount. */
    s_setEnabledCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_setEnabledCb_count == warmCount);

    /* Clean up: leave the cache empty for downstream tests. */
    wh_Server_CertVerifyCache_Clear(server);
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    serverCfg->certConfig = savedCertConfig;
    WH_TEST_PRINT("Server cert verify-cache set-enabled test PASSED\n");
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

#if defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE) && \
    defined(WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL)
/* Counts callback invocations to detect cross-client cache hits. The verify
 * callback fires only on a cold verify; a global-cache hit short-circuits the
 * wolfSSL verify path and bypasses the callback. Two server contexts that
 * share the same NVM context must share the cache, so the second context's
 * verify of an already-cached chain must NOT increment this counter. */
static int s_globalCacheCb_count = 0;
static int whTest_globalCacheVerifyCb(int                     preverify,
                                      WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    s_globalCacheCb_count++;
    /* Mirror wolfSSL's verdict so cross-root verifies still fail. Returning a
     * hard 1 would mask signature mismatches and break the cross-root
     * regression check below. */
    return preverify;
}

/* Cross-client cache hit test. Two whServerContext instances, both backed by
 * the single whNvmContext owned by the test driver, must share the trusted
 * cert verify cache: a chain verified on serverA must short-circuit when
 * verified again on serverB. */
static int whTest_CertServerVerifyCacheGlobalShared(whServerConfig* serverCfg)
{
    whServerContext serverA[1] = {0};
    whServerContext serverB[1] = {0};
    const whNvmId   rootCertA  = 1;
    const whNvmId   rootCertB  = 2;
    int             beforeCount;
    int             rc;

    /* Each server needs its own transport/comm state so wh_CommServer_Init
     * doesn't share buffers across them; only the NVM context (and thus the
     * global cache, which lives on it) is shared. The buffers themselves are
     * never used because this test bypasses the comm channel — but giving
     * each server its own keeps wh_Server_Init/Cleanup well-defined. */
    enum { COMM_BUF_SIZE = 1024 };
    uint8_t                     reqA[COMM_BUF_SIZE]  = {0};
    uint8_t                     respA[COMM_BUF_SIZE] = {0};
    uint8_t                     reqB[COMM_BUF_SIZE]  = {0};
    uint8_t                     respB[COMM_BUF_SIZE] = {0};
    whTransportMemConfig        tmcfA[1]             = {{
                           .req       = (whTransportMemCsr*)reqA,
                           .req_size  = sizeof(reqA),
                           .resp      = (whTransportMemCsr*)respA,
                           .resp_size = sizeof(respA),
    }};
    whTransportMemConfig        tmcfB[1]             = {{
                           .req       = (whTransportMemCsr*)reqB,
                           .req_size  = sizeof(reqB),
                           .resp      = (whTransportMemCsr*)respB,
                           .resp_size = sizeof(respB),
    }};
    whTransportServerCb         tscb[1]  = {WH_TRANSPORT_MEM_SERVER_CB};
    whTransportMemServerContext tmscA[1] = {{0}};
    whTransportMemServerContext tmscB[1] = {{0}};
    whCommServerConfig          csA[1]   = {{
                   .transport_cb      = tscb,
                   .transport_context = (void*)tmscA,
                   .transport_config  = (void*)tmcfA,
                   .server_id         = 200,
    }};
    whCommServerConfig          csB[1]   = {{
                   .transport_cb      = tscb,
                   .transport_context = (void*)tmscB,
                   .transport_config  = (void*)tmcfB,
                   .server_id         = 201,
    }};
    whServerConfig              cfgA     = *serverCfg;
    whServerConfig              cfgB     = *serverCfg;
    cfgA.comm_config                     = csA;
    cfgB.comm_config                     = csB;

    WH_TEST_PRINT(
        "=== Server cert verify-cache global cross-client test ===\n");

    /* Two independent server contexts, both pointing at the same NVM
     * context via serverCfg. The cache lives on the NVM context in global
     * mode, so both servers see the same slots. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(serverA, &cfgA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(serverA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(serverB, &cfgB));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(serverB));

    /* Register the same counting callback on both servers so we can detect
     * which verify path actually executed wolfSSL's signature check vs.
     * which one short-circuited via the global cache. */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertSetVerifyCb(serverA, whTest_globalCacheVerifyCb));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertSetVerifyCb(serverB, whTest_globalCacheVerifyCb));

    /* Trust both roots so the cross-root regression below has somewhere to
     * land. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        serverA, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        serverA, rootCertB, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_B_CERT, ROOT_B_CERT_len));

    /* Make sure we start cold even if a prior test populated the global
     * cache. wh_Server_CertInit no longer clears under _GLOBAL. */
    wh_Server_CertVerifyCache_Clear(serverA);

    /* 1. Cold verify on A populates the global cache. */
    s_globalCacheCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        serverA, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_globalCacheCb_count > 0);

    /* 2. Same chain re-verified on B hits the cache populated by A for the
     * CA certs — those callback invocations are skipped. The leaf is not
     * cached (caching it would let an isolated "leaf alone" verify falsely
     * succeed via cache hit), so the leaf's callback still fires. The
     * re-verify therefore invokes the callback fewer times than the cold
     * verify but still at least once. */
    beforeCount = s_globalCacheCb_count;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        serverB, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_globalCacheCb_count > beforeCount);
    WH_TEST_ASSERT_RETURN(s_globalCacheCb_count - beforeCount < beforeCount);

    /* 3. Cross-root: chain A under rootB must still fail on B even though
     * chain A was cached under rootA. The cache is keyed on (root, hash);
     * a hit under one root must not satisfy a verify under another. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(serverB, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len, rootCertB,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));

    /* 4. Clear via serverA wipes the shared cache; serverB now cold-verifies
     * again and the callback fires. */
    wh_Server_CertVerifyCache_Clear(serverA);
    beforeCount = s_globalCacheCb_count;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        serverB, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_globalCacheCb_count > beforeCount);

    /* Reset cache so subsequent tests in the driver get a clean slate. */
    wh_Server_CertVerifyCache_Clear(serverA);
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(serverA, rootCertA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(serverA, rootCertB));

    /* Tear down both servers so their transport state doesn't leak into
     * subsequent tests in the driver. */
    rc = wh_Server_Cleanup(serverA);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
    rc = wh_Server_Cleanup(serverB);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    WH_TEST_PRINT("Server cert verify-cache global cross-client test PASSED\n");
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE && \
          WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL */

/* State for the user-injectable verify callback test */
static int s_verifyCb_count         = 0;
static int s_verifyCb_lastPreverify = -1;
static int s_verifyCb_returnVal     = 1;

static int whTest_recordingVerifyCb(int                     preverify,
                                    WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    s_verifyCb_count++;
    s_verifyCb_lastPreverify = preverify;
    return s_verifyCb_returnVal;
}

/* Exercises the user-injectable verify callback configured through
 * whServerCertConfig. Confirms:
 *  - the callback is invoked during chain verification with preverify=1
 *  - returning zero from the callback fails the verify
 *  - cache hits on CA certs bypass the callback (when the verify cache
 *    is enabled). Leaf certs are intentionally not cached, so the leaf's
 *    signature is re-verified (and the callback re-invoked) on every
 *    verify call. */
static int whTest_CertServerVerifyCallback(whServerConfig* serverCfg)
{
    int                 rc;
    whServerContext     server[1] = {0};
    whServerCertConfig  certCfg   = {.verifyCb = whTest_recordingVerifyCb};
    whServerCertConfig* savedCertConfig;
    const whNvmId       rootCertA = 1;

    WH_TEST_PRINT("=== Server cert verify-callback test ===\n");

    /* Inject our cert config; restore on exit. */
    savedCertConfig       = serverCfg->certConfig;
    serverCfg->certConfig = &certCfg;

    s_verifyCb_count         = 0;
    s_verifyCb_lastPreverify = -1;
    s_verifyCb_returnVal     = 1;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));

    /* 1. Callback is invoked on a successful verify with preverify=1. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_verifyCb_count > 0);
    WH_TEST_ASSERT_RETURN(s_verifyCb_lastPreverify == 1);

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
    {
        /* 2. Cache hits on CA certs bypass the callback. Leaves are not
         * cached (caching them would let an isolated "leaf alone" verify
         * falsely succeed via cache hit), so the leaf's callback fires on
         * every re-verify. The re-verify therefore invokes the callback
         * fewer times than the cold verify but still at least once. */
        int firstRunCount = s_verifyCb_count;
        WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
            server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
            WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
        WH_TEST_ASSERT_RETURN(s_verifyCb_count > firstRunCount);
        WH_TEST_ASSERT_RETURN(s_verifyCb_count - firstRunCount < firstRunCount);

        /* Clear cache so the next verify re-enters wolfSSL and the cb. */
        wh_Server_CertVerifyCache_Clear(server);
    }
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

    /* 3. Returning zero from the callback forces verify failure. */
    s_verifyCb_returnVal = 0;
    s_verifyCb_count     = 0;
    WH_TEST_ASSERT_RETURN(WH_ERROR_CERT_VERIFY ==
                          wh_Server_CertVerify(server, RAW_CERT_CHAIN_A,
                                               RAW_CERT_CHAIN_A_len, rootCertA,
                                               WH_CERT_FLAGS_NONE,
                                               WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_verifyCb_count > 0);

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    serverCfg->certConfig = savedCertConfig;
    rc                    = WH_ERROR_OK;
    WH_TEST_PRINT("Server cert verify-callback test PASSED\n");
    return rc;
}

/* Exercises wh_Server_CertSetVerifyCb: register, replace, and unregister the
 * verify callback after the server is already initialized (i.e. without
 * supplying it via whServerCertConfig). */
static int whTest_CertServerVerifyCallbackRuntime(whServerConfig* serverCfg)
{
    int                 rc;
    whServerContext     server[1] = {0};
    whServerCertConfig* savedCertConfig;
    const whNvmId       rootCertA = 1;

    WH_TEST_PRINT("=== Server cert verify-callback runtime test ===\n");

    /* Force NULL certConfig so registration must come from the runtime API. */
    savedCertConfig       = serverCfg->certConfig;
    serverCfg->certConfig = NULL;

    s_verifyCb_count         = 0;
    s_verifyCb_lastPreverify = -1;
    s_verifyCb_returnVal     = 1;

    WH_TEST_RETURN_ON_FAIL(wh_Server_Init(server, serverCfg));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootCertA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL,
        0, ROOT_A_CERT, ROOT_A_CERT_len));

    /* 1. No callback registered: verify succeeds, counter stays 0. */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_verifyCb_count == 0);

    /* 2. Register at runtime; cb must fire on the next cold verify. */
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertSetVerifyCb(server, whTest_recordingVerifyCb));
#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
    wh_Server_CertVerifyCache_Clear(server);
#endif
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_verifyCb_count > 0);
    WH_TEST_ASSERT_RETURN(s_verifyCb_lastPreverify == 1);

    /* 3. Unregister at runtime; verify still succeeds, counter stays 0. */
    s_verifyCb_count = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertSetVerifyCb(server, NULL));
#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
    wh_Server_CertVerifyCache_Clear(server);
#endif
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(s_verifyCb_count == 0);

    /* 4. NULL server is rejected. */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          wh_Server_CertSetVerifyCb(NULL, NULL));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootCertA));
    serverCfg->certConfig = savedCertConfig;
    rc                    = WH_ERROR_OK;
    WH_TEST_PRINT("Server cert verify-callback runtime test PASSED\n");
    return rc;
}
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#ifdef WOLFHSM_CFG_ENABLE_CLIENT
int whTest_CertClient(whClientContext* client)
{
    int      rc = WH_ERROR_OK;
    int32_t  out_rc;
    whNvmId  rootCertA_id = 1;
    whNvmId  rootCertB_id = 2;
    whKeyId  out_keyId    = WH_KEYID_ERASED;
    uint8_t  exportedPubKey[LEAF_A_PUBKEY_len];
    uint16_t exportedPubKeyLen = sizeof(exportedPubKey);

    WH_TEST_PRINT("Starting certificate client test...\n");

    /* Initialize certificate manager */
    WH_TEST_PRINT("Initializing certificate manager...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(client, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add root certificates to NVM */
    WH_TEST_PRINT("Adding root certificate A to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        client, rootCertA_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("Adding root certificate B to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        client, rootCertB_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_B_CERT, ROOT_B_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid single cert (intermediate) */
    WH_TEST_PRINT(
        "Verifying valid single certificate...using intermediate cert\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, INTERMEDIATE_A_CERT,
                                                INTERMEDIATE_A_CERT_len,
                                                rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* out_rc is mandatory; a NULL verdict pointer must be rejected so the
     * verification result can never be silently discarded */
    WH_TEST_ASSERT_RETURN(wh_Client_CertVerify(client, INTERMEDIATE_A_CERT,
                                               INTERMEDIATE_A_CERT_len,
                                               rootCertA_id,
                                               NULL) == WH_ERROR_BADARGS);

    /* attempt to verify invalid cert (leaf w/o intermediate), should fail */
    WH_TEST_PRINT(
        "Attempting to verify invalid single certificate...using leaf cert "
        "without intermediate\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(
        client, LEAF_A_CERT, LEAF_A_CERT_len, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* attempt to verify invalid cert (intermediate with different root),
     * should fail */
    WH_TEST_PRINT("Attempting to verify invalid single certificate...using "
                   "intermediate cert with different root\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, INTERMEDIATE_B_CERT,
                                                INTERMEDIATE_B_CERT_len,
                                                rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Verify valid chain */
    WH_TEST_PRINT("Verifying valid certificate chain...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(
        client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid chain B */
    WH_TEST_PRINT("Verifying valid certificate chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(
        client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid chains, should fail. Cache entries are scoped
     * to the trusted root NVM ID, so prior positive verifies under the true
     * root cannot bypass these cross-root checks. */
    WH_TEST_PRINT("Attempting to verify invalid certificate chains...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(
        client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(
        client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Test verify with cached leaf public key */
    WH_TEST_PRINT("Testing verify with cached leaf public key...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyAndCacheLeafPubKey(
        client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA_id,
        WH_NVM_FLAGS_USAGE_ANY, &out_keyId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Export the cached public key so we can verify it matches the expected
     * leaf public key. Don't assert on the result as we must evict the key
     * first */
    rc = wh_Client_KeyExport(client, out_keyId, NULL, 0, exportedPubKey,
                             &exportedPubKeyLen);

    /* Evict the cached key before any further assertions so it doesn't leak
     * cache slots */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, out_keyId));

    /* Now that we have ecicted the key, check that the export and leaf key
     * caching worked as expected */
    WH_TEST_ASSERT(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(exportedPubKeyLen == LEAF_A_PUBKEY_len);
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(exportedPubKey, LEAF_A_PUBKEY, LEAF_A_PUBKEY_len));

    /* ===== Multi-root client tests ===== */
    {
        whNvmId rootC_absent         = 99;
        whNvmId roots_AB[2]          = {rootCertA_id, rootCertB_id};
        whNvmId roots_BA[2]          = {rootCertB_id, rootCertA_id};
        whNvmId roots_A_absent[2]    = {rootCertA_id, rootC_absent};
        whNvmId roots_only_absent[2] = {rootC_absent, 100};
        whKeyId mr_keyId             = WH_KEYID_ERASED;

        /* (1) Single-root via multi-root path */
        WH_TEST_PRINT("Client multi-root: single root, chain matches...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertA_id, 1,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        WH_TEST_PRINT("Client multi-root: single root, chain mismatch...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertB_id, 1,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* (2-3) Two roots, chain matches first / second */
        WH_TEST_PRINT("Client multi-root: [A,B] anchors to A...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        WH_TEST_PRINT("Client multi-root: [A,B] anchors to B...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_AB, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* (4) Two roots, neither matches (incomplete chain: leaf without
         * its intermediate cannot be anchored to A or B) */
        WH_TEST_PRINT("Client multi-root: [A,B] mismatch (leaf without "
                      "intermediate)...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, LEAF_A_CERT, LEAF_A_CERT_len, roots_AB, 2, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* (5) One present root + absent: success when chain matches present */
        WH_TEST_PRINT("Client multi-root: [A, absent] chain A succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_A_absent, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        WH_TEST_PRINT(
            "Client multi-root: [A, absent] chain B → CERT_VERIFY...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_A_absent, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* (6) All supplied roots absent */
        WH_TEST_PRINT("Client multi-root: all absent → NOTFOUND...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_only_absent,
            2, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_NOTFOUND);

        /* (7) Boundary numRoots == 0 rejected client-side */
        WH_TEST_PRINT("Client multi-root: numRoots == 0 → BADARGS...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_BADARGS ==
            wh_Client_CertVerifyMultiRoot(client, RAW_CERT_CHAIN_A,
                                          RAW_CERT_CHAIN_A_len, &rootCertA_id,
                                          0, &out_rc));

        /* (7b) Boundary numRoots > MAX_VERIFY_ROOTS rejected client-side */
        {
            whNvmId  oversized[WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1] = {0};
            uint16_t over = (uint16_t)(WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1);
            WH_TEST_PRINT("Client multi-root: numRoots > MAX → BADARGS...\n");
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_BADARGS ==
                wh_Client_CertVerifyMultiRoot(client, RAW_CERT_CHAIN_A,
                                              RAW_CERT_CHAIN_A_len, oversized,
                                              over, &out_rc));
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_BADARGS ==
                wh_Client_CertVerifyMultiRootAndCacheLeafPubKey(
                    client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, oversized,
                    over, WH_NVM_FLAGS_USAGE_ANY, &mr_keyId, &out_rc));
        }

        /* (12) Order independence */
        WH_TEST_PRINT("Client multi-root: [B,A] for chain B succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRoot(
            client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_BA, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* (11) Async split with case (3) */
        WH_TEST_PRINT(
            "Client multi-root: async split, [A,B] chain B succeeds...\n");
        do {
            rc = wh_Client_CertVerifyMultiRootRequest(
                client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_AB, 2);
        } while (rc == WH_ERROR_NOTREADY);
        WH_TEST_RETURN_ON_FAIL(rc);
        do {
            rc = wh_Client_CertVerifyMultiRootResponse(client, &out_rc);
        } while (rc == WH_ERROR_NOTREADY);
        WH_TEST_RETURN_ON_FAIL(rc);
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* (9) Leaf key caching variant: succeed on chain A and pull pubkey */
        WH_TEST_PRINT(
            "Client multi-root: leaf cache [A,B] chain A succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootAndCacheLeafPubKey(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
            WH_NVM_FLAGS_USAGE_ANY, &mr_keyId, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        exportedPubKeyLen = sizeof(exportedPubKey);
        rc = wh_Client_KeyExport(client, mr_keyId, NULL, 0, exportedPubKey,
                                 &exportedPubKeyLen);
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, mr_keyId));
        WH_TEST_ASSERT(rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(exportedPubKeyLen == LEAF_A_PUBKEY_len);
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(exportedPubKey, LEAF_A_PUBKEY, LEAF_A_PUBKEY_len));
    }

    /* Clean up - delete the root certificates */
    WH_TEST_PRINT("Deleting root certificates...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Test non-exportable flag enforcement */
    WH_TEST_RETURN_ON_FAIL(whTest_CertNonExportable(client));

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
    /* Verify-cache scenarios over the full client/server RPC: cross-root
     * recognition, the clear RPC, and re-verify behavior after clear. */
    {
        whNvmId rootCertA_id_c = 1;
        whNvmId rootCertB_id_c = 2;

        WH_TEST_PRINT("=== Client cert verify-cache test ===\n");

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertAddTrusted(client, rootCertA_id_c, WH_NVM_ACCESS_ANY,
                                     WH_NVM_FLAGS_NONMODIFIABLE, NULL, 0,
                                     ROOT_A_CERT, ROOT_A_CERT_len, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertAddTrusted(client, rootCertB_id_c, WH_NVM_ACCESS_ANY,
                                     WH_NVM_FLAGS_NONMODIFIABLE, NULL, 0,
                                     ROOT_B_CERT, ROOT_B_CERT_len, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* Start from a known-empty cache. */
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyCacheClear(client, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* Warm the cache by verifying chain A under its true root. */
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                                    RAW_CERT_CHAIN_A_len,
                                                    rootCertA_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* Cache entries are bound to the trusted root NVM ID: chain A under
         * root B fails even though every cert in chain A is cached under
         * root A. The cache hit must not bypass the cross-root check. */
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                                    RAW_CERT_CHAIN_A_len,
                                                    rootCertB_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* After clear, the cross-root verify still fails cold. Exercises the
         * clear RPC path. */
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyCacheClear(client, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                                    RAW_CERT_CHAIN_A_len,
                                                    rootCertB_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* Exercise the SetEnabled RPC path. The cross-root-must-fail
         * invariant has to hold regardless of cache state, so re-run it
         * after disable and after re-enable to confirm the RPC neither
         * crashes nor breaks correctness. Behavioral observation (cache
         * hits vs misses) is covered by whTest_CertServerVerifyCacheSetEnabled;
         * here we just confirm the wire path round-trips. */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertVerifyCacheSetEnabled(client, 0, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                                    RAW_CERT_CHAIN_A_len,
                                                    rootCertA_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                                    RAW_CERT_CHAIN_A_len,
                                                    rootCertB_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertVerifyCacheSetEnabled(client, 1, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerify(client, RAW_CERT_CHAIN_A,
                                                    RAW_CERT_CHAIN_A_len,
                                                    rootCertA_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* Cleanup */
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertEraseTrusted(client, rootCertA_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertEraseTrusted(client, rootCertB_id_c, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_PRINT("Client cert verify-cache test PASSED\n");
    }
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

    WH_TEST_PRINT("Certificate client test completed successfully\n");

    return rc;
}

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
/* Run attribute certificate client tests */
int whTest_CertClientAcert(whClientContext* client)
{
    int     rc = WH_ERROR_OK;
    int32_t out_rc;
    whNvmId trustedCertId = 1;
    whNvmId rootCertB_id  = 2;

    WH_TEST_PRINT("Starting attribute certificate client test...\n");

    /* Initialize certificate manager */
    WH_TEST_PRINT("Initializing certificate manager...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(client, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add trusted certificate to NVM */
    WH_TEST_PRINT("Adding trusted certificate to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        client, trustedCertId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, caCert_der, caCert_der_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("Adding root certificate B to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        client, rootCertB_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_B_CERT, ROOT_B_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify attribute certificate */
    WH_TEST_PRINT("Verifying attribute certificate...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyAcert(
        client, attrCert_der, attrCert_der_len, trustedCertId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Attempt to verify attribute certificate with different root, should fail
     */
    WH_TEST_PRINT(
        "Attempting to verify attribute certificate with different root...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyAcert(
        client, attrCert_der, attrCert_der_len, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Clean up - delete the trusted certificates */
    WH_TEST_PRINT("Deleting trusted certificates...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, trustedCertId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT(
        "Attribute certificate client test completed successfully\n");

    return rc;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

#if defined(WOLFHSM_CFG_DMA)
/* Run certificate client DMA tests
 *
 * Only suitable for internal use in wolfHSM test harness, as it requires
 * the client and server to have direct access to each others process memory
 * and assumes the server has the appropriate DMA translation configured */
int whTest_CertClientDma_ClientServerTestInternal(whClientContext* client)
{
    int     rc = WH_ERROR_OK;
    int32_t out_rc;
    whNvmId rootCertA_id = 1;
    whNvmId rootCertB_id = 2;
    whKeyId  out_keyId    = WH_KEYID_ERASED;
    uint8_t  exportedPubKey[LEAF_A_PUBKEY_len];
    uint16_t exportedPubKeyLen = sizeof(exportedPubKey);

    WH_TEST_PRINT("Starting certificate client DMA test...\n");

    /* Initialize certificate manager */
    WH_TEST_PRINT("Initializing certificate manager...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(client, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add root certificates to NVM */
    WH_TEST_PRINT("Adding root certificate A to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrustedDma(
        client, rootCertA_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("Adding root certificate B to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrustedDma(
        client, rootCertB_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_B_CERT, ROOT_B_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid single cert (intermediate) */
    WH_TEST_PRINT(
        "Verifying valid single certificate...using intermediate cert\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, INTERMEDIATE_A_CERT,
                                                   INTERMEDIATE_A_CERT_len,
                                                   rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid cert (leaf w/o intermediate), should fail */
    WH_TEST_PRINT(
        "Attempting to verify invalid single certificate...using leaf cert "
        "without intermediate\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(
        client, LEAF_A_CERT, LEAF_A_CERT_len, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* attempt to verify invalid cert (intermediate with different root),
     * should fail */
    WH_TEST_PRINT("Attempting to verify invalid single certificate...using "
                   "intermediate cert with different root\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(client, INTERMEDIATE_B_CERT,
                                                   INTERMEDIATE_B_CERT_len,
                                                   rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Verify valid chain */
    WH_TEST_PRINT("Verifying valid certificate chain...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(
        client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify valid chain B */
    WH_TEST_PRINT("Verifying valid certificate chain B...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(
        client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* attempt to verify invalid chains, should fail. Cache entries are scoped
     * to the trusted root NVM ID, so prior positive verifies under the true
     * root cannot bypass these cross-root checks. */
    WH_TEST_PRINT("Attempting to verify invalid certificate chains...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(
        client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDma(
        client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Test verify with cached leaf public key */
    WH_TEST_PRINT("Testing verify with cached leaf public key using DMA...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyDmaAndCacheLeafPubKey(
        client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootCertA_id,
        WH_NVM_FLAGS_USAGE_ANY, &out_keyId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Export the cached public key so we can verify it matches the expected
     * leaf public key. Don't assert on the result as we must evict the key
     * first */
    rc = wh_Client_KeyExportDma(
        client, out_keyId, exportedPubKey, sizeof(exportedPubKey), NULL, 0,
        &exportedPubKeyLen);

    /* Evict the cached key before any further assertions so it doesn't leak
     * cache slots */
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, out_keyId));

    /* Now that we have ecicted the key, check that the export and leaf key
     * caching worked as expected */
    WH_TEST_ASSERT(rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(exportedPubKeyLen == LEAF_A_PUBKEY_len);
    WH_TEST_ASSERT_RETURN(
        0 == memcmp(exportedPubKey, LEAF_A_PUBKEY, LEAF_A_PUBKEY_len));

    /* ===== Multi-root DMA client tests ===== */
    {
        whNvmId rootC_absent         = 99;
        whNvmId roots_AB[2]          = {rootCertA_id, rootCertB_id};
        whNvmId roots_BA[2]          = {rootCertB_id, rootCertA_id};
        whNvmId roots_A_absent[2]    = {rootCertA_id, rootC_absent};
        whNvmId roots_only_absent[2] = {rootC_absent, 100};
        whKeyId mr_keyId             = WH_KEYID_ERASED;

        /* (1) Single root via multi-root DMA path */
        WH_TEST_PRINT("Client multi-root DMA: single root, matches...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertA_id, 1,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        WH_TEST_PRINT("Client multi-root DMA: single root, mismatch...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, &rootCertB_id, 1,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* (2-3) Two roots, chain matches first / second */
        WH_TEST_PRINT("Client multi-root DMA: [A,B] chain A succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        WH_TEST_PRINT("Client multi-root DMA: [A,B] chain B succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_AB, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* (5) Present + absent: success when chain matches present */
        WH_TEST_PRINT(
            "Client multi-root DMA: [A, absent] chain A succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_A_absent, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        WH_TEST_PRINT(
            "Client multi-root DMA: [A, absent] chain B → CERT_VERIFY...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_A_absent, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

        /* (6) All absent → NOTFOUND */
        WH_TEST_PRINT("Client multi-root DMA: all absent → NOTFOUND...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_only_absent,
            2, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_NOTFOUND);

        /* (12) Order independence */
        WH_TEST_PRINT("Client multi-root DMA: [B,A] chain B succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyMultiRootDma(
            client, RAW_CERT_CHAIN_B, RAW_CERT_CHAIN_B_len, roots_BA, 2,
            &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

        /* (7) Boundary numRoots == 0 rejected client-side */
        WH_TEST_PRINT("Client multi-root DMA: numRoots == 0 → BADARGS...\n");
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_BADARGS ==
            wh_Client_CertVerifyMultiRootDma(client, RAW_CERT_CHAIN_A,
                                             RAW_CERT_CHAIN_A_len,
                                             &rootCertA_id, 0, &out_rc));

        /* (7b) Boundary numRoots > MAX_VERIFY_ROOTS rejected client-side */
        {
            whNvmId  oversized[WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1] = {0};
            uint16_t over = (uint16_t)(WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1);
            WH_TEST_PRINT(
                "Client multi-root DMA: numRoots > MAX → BADARGS...\n");
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_BADARGS ==
                wh_Client_CertVerifyMultiRootDma(client, RAW_CERT_CHAIN_A,
                                                 RAW_CERT_CHAIN_A_len,
                                                 oversized, over, &out_rc));
            WH_TEST_ASSERT_RETURN(
                WH_ERROR_BADARGS ==
                wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKey(
                    client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, oversized,
                    over, WH_NVM_FLAGS_USAGE_ANY, &mr_keyId, &out_rc));
        }

        /* (9) Leaf key caching variant: succeed on chain A and pull pubkey */
        WH_TEST_PRINT(
            "Client multi-root DMA: leaf cache [A,B] chain A succeeds...\n");
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKey(
                client, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, roots_AB, 2,
                WH_NVM_FLAGS_USAGE_ANY, &mr_keyId, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        exportedPubKeyLen = sizeof(exportedPubKey);
        rc = wh_Client_KeyExportDma(client, mr_keyId, exportedPubKey,
                                    sizeof(exportedPubKey), NULL, 0,
                                    &exportedPubKeyLen);
        WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(client, mr_keyId));
        WH_TEST_ASSERT(rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(exportedPubKeyLen == LEAF_A_PUBKEY_len);
        WH_TEST_ASSERT_RETURN(
            0 == memcmp(exportedPubKey, LEAF_A_PUBKEY, LEAF_A_PUBKEY_len));
    }

    /* Clean up - delete the root certificates */
    WH_TEST_PRINT("Deleting root certificates...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, rootCertA_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("Certificate client DMA test completed successfully\n");

    return rc;
}

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
/* Run attribute certificate client DMA tests
 *
 * Only suitable for internal use in wolfHSM test harness, as it requires
 * the client and server to have direct access to each others process memory
 * and assumes the server has the appropriate DMA translation configured */
int whTest_CertClientAcertDma_ClientServerTestInternal(whClientContext* client)
{
    int     rc = WH_ERROR_OK;
    int32_t out_rc;
    whNvmId trustedCertId = 1;
    whNvmId rootCertB_id  = 2;

    WH_TEST_PRINT("Starting attribute certificate client test...\n");

    /* Initialize certificate manager */
    WH_TEST_PRINT("Initializing certificate manager...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(client, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add trusted certificate to NVM */
    WH_TEST_PRINT("Adding trusted certificate to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrustedDma(
        client, trustedCertId, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, caCert_der, caCert_der_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("Adding root certificate B to NVM...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrustedDma(
        client, rootCertB_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_B_CERT, ROOT_B_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Verify attribute certificate */
    WH_TEST_PRINT("Verifying attribute certificate...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyAcertDma(
        client, attrCert_der, attrCert_der_len, trustedCertId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Attempt to verify attribute certificate with different root, should fail
     */
    WH_TEST_PRINT(
        "Attempting to verify attribute certificate with different root...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyAcertDma(
        client, attrCert_der, attrCert_der_len, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    /* Regression test for finding 4235. A malformed (undersized) ACERT_DMA
     * request must report an error on the wire, not a false success. Send a
     * raw 1 byte request with the low level API and confirm resp.rc is not OK.
     */
    WH_TEST_PRINT("Sending malformed ACERT_DMA request...\n");
    {
        uint8_t                      badReq = 0;
        uint16_t                     rgroup, raction, rsize;
        whMessageCert_SimpleResponse badResp = {0};

        do {
            rc = wh_Client_SendRequest(
                client, WH_MESSAGE_GROUP_CERT,
                WH_MESSAGE_CERT_ACTION_VERIFY_ACERT_DMA, sizeof(badReq),
                &badReq);
        } while (rc == WH_ERROR_NOTREADY);
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);

        do {
            rc = wh_Client_RecvResponse(client, &rgroup, &raction, &rsize,
                                        &badResp);
        } while (rc == WH_ERROR_NOTREADY);
        WH_TEST_ASSERT_RETURN(rc == WH_ERROR_OK);
        WH_TEST_ASSERT_RETURN(badResp.rc != WH_ERROR_OK);
    }

    /* Clean up - delete the trusted certificates */
    WH_TEST_PRINT("Deleting trusted certificates...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, trustedCertId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, rootCertB_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT(
        "Attribute certificate client test completed successfully\n");

    return rc;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

#endif /* WOLFHSM_CFG_DMA */

static int whTest_CertNonExportable(whClientContext* client)
{
    int      rc                    = WH_ERROR_OK;
    int32_t  out_rc                = 0;
    whNvmId  exportable_cert_id    = 101;
    whNvmId  nonexportable_cert_id = 102;
    uint8_t  cert_buffer[2048]     = {0};
    uint32_t cert_len              = sizeof(cert_buffer);

    WH_TEST_PRINT("Testing non-exportable certificate functionality...\n");

    /* Add exportable certificate */
    WH_TEST_PRINT("Adding exportable certificate...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertAddTrusted(client, exportable_cert_id, WH_NVM_ACCESS_ANY,
                                 WH_NVM_FLAGS_NONMODIFIABLE, NULL, 0,
                                 ROOT_A_CERT, ROOT_A_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Add non-exportable certificate */
    WH_TEST_PRINT("Adding non-exportable certificate...\n");
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        client, nonexportable_cert_id, WH_NVM_ACCESS_ANY,
        WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONEXPORTABLE, NULL, 0,
        ROOT_B_CERT, ROOT_B_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Test reading exportable certificate - should succeed */
    WH_TEST_PRINT("Reading exportable certificate (should succeed)...\n");
    cert_len = sizeof(cert_buffer);
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrusted(
        client, exportable_cert_id, cert_buffer, &cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Test reading non-exportable certificate - should fail */
    WH_TEST_PRINT("Reading non-exportable certificate (should fail)...\n");
    cert_len = sizeof(cert_buffer);
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrusted(
        client, nonexportable_cert_id, cert_buffer, &cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_ACCESS);

#ifdef WOLFHSM_CFG_DMA
    /* Test DMA variant with non-exportable certificate */
    WH_TEST_PRINT(
        "Reading non-exportable certificate via DMA (should fail)...\n");
    cert_len = sizeof(cert_buffer);
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrustedDma(
        client, nonexportable_cert_id, cert_buffer, cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_ACCESS);
#endif

    /* Clean up - delete the certificates */
    WH_TEST_PRINT("Cleaning up certificates...\n");
    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, exportable_cert_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(client, nonexportable_cert_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_PRINT("Non-exportable certificate test completed successfully\n");
    return rc;
}

#endif /* WOLFHSM_CFG_ENABLE_CLIENT */

#ifdef WOLFHSM_CFG_ENABLE_SERVER
int whTest_CertRamSim(whTestNvmBackendType nvmType)
{
    int            rc          = WH_ERROR_OK;
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
    uint8_t memory[FLASH_RAM_SIZE] = {0};
    whFlashRamsimCtx fc[1]      = {0};
    whFlashRamsimCfg fc_conf[1] = {{
        .size       = FLASH_RAM_SIZE,    /* 1MB  Flash */
        .sectorSize = FLASH_SECTOR_SIZE, /* 128KB  Sector Size */
        .pageSize   = FLASH_PAGE_SIZE,   /* 8B   Page Size */
        .erasedByte = ~(uint8_t)0,
        .memory     = memory,
    }};
    const whFlashCb  fcb[1]     = {WH_FLASH_RAMSIM_CB};

    whTestNvmBackendUnion nvm_setup;
    whNvmConfig           n_conf[1] = {0};
    whNvmContext nvm[1]    = {{0}};

    WH_TEST_RETURN_ON_FAIL(
        whTest_NvmCfgBackend(nvmType, &nvm_setup, n_conf, fc_conf, fc, fcb));

#ifndef WOLFHSM_CFG_NO_CRYPTO
    whServerCryptoContext crypto[1] = {0};
#endif

    whServerConfig s_conf[1] = {{
        .comm_config = cs_conf,
        .nvm         = nvm,
#ifndef WOLFHSM_CFG_NO_CRYPTO
        .crypto = crypto,
#endif
    }};

    WH_TEST_PRINT("Testing Server Certificate with RAM sim...\n");

    /* Initialize NVM */
    WH_TEST_RETURN_ON_FAIL(wh_Nvm_Init(nvm, n_conf));
#ifndef WOLFHSM_CFG_NO_CRYPTO
    WH_TEST_RETURN_ON_FAIL(wolfCrypt_Init());
    WH_TEST_RETURN_ON_FAIL(wc_InitRng_ex(crypto->rng, NULL, INVALID_DEVID));
#endif

    /* Run certificate configuration tests */
    rc = whTest_CertServerCfg(s_conf);
    if (rc != WH_ERROR_OK) {
        WH_ERROR_PRINT("Certificate server config tests failed: %d\n", rc);
    }

    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerAddTrustedStripsServerFlags(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT(
                "Cert AddTrusted server-only flag strip test failed: %d\n", rc);
        }
    }

    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerTrustedRespectsNvmPolicy(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert NVM policy test failed: %d\n", rc);
        }
    }

    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerReadTrustedRejectsServerOnly(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert ReadTrusted server-only rejection test "
                           "failed: %d\n",
                           rc);
        }
    }

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCache(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert verify-cache tests failed: %d\n", rc);
        }
    }
    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCacheEvictOnReAdd(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT(
                "Cert verify-cache evict-on-re-add tests failed: %d\n", rc);
        }
    }
    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCacheMultiRootSubset(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT(
                "Cert verify-cache multi-root subset tests failed: %d\n", rc);
        }
    }
    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCacheSetEnabled(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert verify-cache set-enabled tests failed: %d\n",
                           rc);
        }
    }
#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_GLOBAL
    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCacheGlobalShared(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert verify-cache global cross-client tests "
                           "failed: %d\n",
                           rc);
        }
    }
#endif
#endif

    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCallback(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert verify-callback tests failed: %d\n", rc);
        }
    }

    if (rc == WH_ERROR_OK) {
        rc = whTest_CertServerVerifyCallbackRuntime(s_conf);
        if (rc != WH_ERROR_OK) {
            WH_ERROR_PRINT("Cert verify-callback runtime tests failed: %d\n",
                           rc);
        }
    }

    /* Cleanup NVM */
    wh_Nvm_Cleanup(nvm);
#ifndef WOLFHSM_CFG_NO_CRYPTO
    wc_FreeRng(crypto->rng);
    wolfCrypt_Cleanup();
#endif

    return rc;
}
#endif /* WOLFHSM_CFG_ENABLE_SERVER */

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
