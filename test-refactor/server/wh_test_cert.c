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
#include "wolfhsm/wh_server_keystore.h"
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

/* Verify cert read handler rejects non-cert IDs and SERVER_ONLY objects. */
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

    /* Provision a trusted KEK at a crypto-typed ID. */
    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CRYPTO, 0, 0x5A);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_TRUSTED | WH_NVM_FLAGS_USAGE_WRAP;
    meta.len    = sizeof(kek);
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, sizeof(kek), kek));

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
        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_BADARGS);
        WH_TEST_ASSERT_RETURN(resp.cert_len == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(resp));

        memset(&resp, 0, sizeof(resp));
        req.id = WH_KEYID_ID(meta.id);
        wh_MessageCert_TranslateReadTrustedRequest(
            magic, &req, (whMessageCert_ReadTrustedRequest*)req_packet);
        (void)wh_Server_HandleCertRequest(
            server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED, 0, sizeof(req),
            req_packet, &resp_size, resp_packet);
        wh_MessageCert_TranslateReadTrustedResponse(
            magic, (whMessageCert_ReadTrustedResponse*)resp_packet, &resp);
        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_NOTFOUND);
        WH_TEST_ASSERT_RETURN(resp.cert_len == 0);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(resp));
    }

    /* Verify SERVER_ONLY object in cert namespace cannot be read. */
    {
        whMessageCert_ReadTrustedRequest  req  = {0};
        whMessageCert_ReadTrustedResponse resp = {0};
        whNvmMetadata                     srv  = {0};

        srv.id = WH_MAKE_KEYID(WH_KEYTYPE_CERT, server->comm->client_id, 0x5B);
        srv.access = WH_NVM_ACCESS_ANY;
        srv.flags  = WH_NVM_FLAGS_SERVER_ONLY;
        srv.len    = sizeof(kek);
        WH_TEST_RETURN_ON_FAIL(
            wh_Nvm_AddObject(server->nvm, &srv, sizeof(kek), kek));

        req.id = 0x5B;
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

        WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &srv.id));
    }

#ifdef WOLFHSM_CFG_DMA
    {
        whMessageCert_ReadTrustedDmaRequest req  = {0};
        whMessageCert_SimpleResponse        resp = {0};
        uint8_t                             out_buf[64];
        size_t                              i;

        memset(out_buf, 0, sizeof(out_buf));
        req.id        = WH_KEYID_ID(meta.id);
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

        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_NOTFOUND);
        for (i = 0; i < sizeof(out_buf); i++) {
            WH_TEST_ASSERT_RETURN(out_buf[i] == 0);
        }
    }
#endif /* WOLFHSM_CFG_DMA */

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &meta.id));

    return 0;
}

/* Verify EraseTrusted cannot destroy non-certificate objects. */
int whTest_CertEraseCannotReachNonCert(whServerContext* ctx)
{
    whServerContext* server  = (whServerContext*)ctx;
    whNvmMetadata    meta    = {0};
    whNvmMetadata    check   = {0};
    const uint8_t  secret[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    const uint16_t magic     = WH_COMM_MAGIC_NATIVE;
    uint8_t        req_packet[WOLFHSM_CFG_COMM_DATA_LEN]  = {0};
    uint8_t        resp_packet[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t       resp_size                              = 0;
    /* Protected ID that no client translation can produce */
    const whNvmId protectedId = WH_MAKE_KEYID(0xF, 0xE, 0x00);

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    meta.id     = protectedId;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONMODIFIABLE;
    meta.len    = sizeof(secret);
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, sizeof(secret), secret));

    {
        whMessageCert_EraseTrustedRequest req  = {0};
        whMessageCert_SimpleResponse      resp = {0};

        req.id = protectedId;
        wh_MessageCert_TranslateEraseTrustedRequest(
            magic, &req, (whMessageCert_EraseTrustedRequest*)req_packet);

        (void)wh_Server_HandleCertRequest(
            server, magic, WH_MESSAGE_CERT_ACTION_ERASETRUSTED, 0, sizeof(req),
            req_packet, &resp_size, resp_packet);

        wh_MessageCert_TranslateSimpleResponse(
            magic, (whMessageCert_SimpleResponse*)resp_packet, &resp);
        WH_TEST_ASSERT_RETURN(resp.rc == WH_ERROR_BADARGS);
        WH_TEST_ASSERT_RETURN(resp_size == sizeof(resp));
    }

    WH_TEST_ASSERT_RETURN(
        wh_Nvm_GetMetadata(server->nvm, protectedId, &check) == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(check.len == sizeof(secret));

    WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &protectedId));

    return 0;
}

/* Issue a client READTRUSTED request for `id` and return the response rc. */
static int32_t _certReadRc(whServerContext* server, uint16_t magic, whNvmId id,
                           uint8_t* req_packet, uint8_t* resp_packet)
{
    whMessageCert_ReadTrustedRequest  req       = {0};
    whMessageCert_ReadTrustedResponse resp      = {0};
    uint16_t                          resp_size = 0;

    req.id = id;
    wh_MessageCert_TranslateReadTrustedRequest(
        magic, &req, (whMessageCert_ReadTrustedRequest*)req_packet);
    (void)wh_Server_HandleCertRequest(
        server, magic, WH_MESSAGE_CERT_ACTION_READTRUSTED, 0, sizeof(req),
        req_packet, &resp_size, resp_packet);
    wh_MessageCert_TranslateReadTrustedResponse(
        magic, (whMessageCert_ReadTrustedResponse*)resp_packet, &resp);
    return resp.rc;
}

/* Verify certificate ID isolation between clients and shared global access. */
int whTest_CertPerClientIsolation(whServerContext* ctx)
{
    whServerContext* server = (whServerContext*)ctx;
    whNvmMetadata    meta   = {0};
    const uint16_t   magic  = WH_COMM_MAGIC_NATIVE;
    uint8_t          req_packet[WOLFHSM_CFG_COMM_DATA_LEN]  = {0};
    uint8_t          resp_packet[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    const whNvmId    client1Cert = WH_MAKE_KEYID(WH_KEYTYPE_CERT, 1, 5);

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));

    /* Add cert to client 1 namespace */
    meta.id     = client1Cert;
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONE;
    meta.len    = ROOT_A_CERT_len;
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, ROOT_A_CERT_len, ROOT_A_CERT));

    /* Client 2 cannot see client 1 cert */
    server->comm->client_id = 2;
    WH_TEST_ASSERT_RETURN(_certReadRc(server, magic, 5, req_packet,
                                      resp_packet) == WH_ERROR_NOTFOUND);

    /* Client 1 can read its own cert */
    server->comm->client_id = 1;
    WH_TEST_ASSERT_RETURN(
        _certReadRc(server, magic, 5, req_packet, resp_packet) == WH_ERROR_OK);

#ifdef WOLFHSM_CFG_GLOBAL_KEYS
    /* Verify global cert access */
    memset(&meta, 0, sizeof(meta));
    meta.id     = WH_MAKE_KEYID(WH_KEYTYPE_CERT, WH_KEYUSER_GLOBAL, 6);
    meta.access = WH_NVM_ACCESS_ANY;
    meta.flags  = WH_NVM_FLAGS_NONE;
    meta.len    = ROOT_B_CERT_len;
    WH_TEST_RETURN_ON_FAIL(
        wh_Nvm_AddObject(server->nvm, &meta, ROOT_B_CERT_len, ROOT_B_CERT));

    server->comm->client_id = 2;
    WH_TEST_ASSERT_RETURN(_certReadRc(server, magic,
                                      6 | WH_KEYID_CLIENT_GLOBAL_FLAG,
                                      req_packet, resp_packet) == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(_certReadRc(server, magic, 6, req_packet,
                                      resp_packet) == WH_ERROR_NOTFOUND);

    {
        whNvmId g = WH_MAKE_KEYID(WH_KEYTYPE_CERT, WH_KEYUSER_GLOBAL, 6);
        WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &g));
    }
#else
    /* The global flag is rejected, not mapped to client 1's own cert */
    WH_TEST_ASSERT_RETURN(
        _certReadRc(server, magic, 5 | WH_KEYID_CLIENT_GLOBAL_FLAG, req_packet,
                    resp_packet) == WH_ERROR_BADARGS);
#endif

    /* Clean up and restore client ID */
    {
        whNvmId c1 = client1Cert;
        WH_TEST_RETURN_ON_FAIL(wh_Nvm_DestroyObjects(server->nvm, 1, &c1));
    }
    server->comm->client_id = 0;

    return 0;
}

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_FULLCHAIN
/* Counts verify-callback invocations for the full-chain cache test */
static int _fullChainCacheCbCount = 0;
static int _fullChainCacheVerifyCb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)store;
    _fullChainCacheCbCount++;
    return preverify;
}

/*
 * Full-chain caching: a repeat verify of a chain skips every check, leaf
 * included. The leaf alone, or after another chain's intermediate, still
 * fails, a failed verify is not cached, and asking for the leaf public key
 * on a cached chain still caches it.
 */
int whTest_CertVerifyCacheFullChain(whServerContext* ctx)
{
    whServerContext* server     = (whServerContext*)ctx;
    VerifyCallback   savedCb    = server->cert.verifyCb;
    const whNvmId    rootA      = 1;
    const whNvmId    rootB      = 2;
    whNvmId          rootsAB[2] = {rootA, rootB};
    static uint8_t   otherChain[4096];
    uint32_t         otherChainLen;
    whKeyId          keyId = WH_KEYID_ERASED;
    whNvmMetadata    meta;
    uint8_t          pubKey[512];
    uint32_t         pubKeyLen = sizeof(pubKey);
    int              i;

    /* Leaf A after chain B's intermediate, which did not sign it */
    WH_TEST_ASSERT_RETURN(INTERMEDIATE_B_CERT_len + LEAF_A_CERT_len <=
                          sizeof(otherChain));
    memcpy(otherChain, INTERMEDIATE_B_CERT, INTERMEDIATE_B_CERT_len);
    memcpy(otherChain + INTERMEDIATE_B_CERT_len, LEAF_A_CERT, LEAF_A_CERT_len);
    otherChainLen = (uint32_t)(INTERMEDIATE_B_CERT_len + LEAF_A_CERT_len);

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertInit(server));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_CertSetVerifyCb(server, _fullChainCacheVerifyCb));
    /* Start cold: in global mode the cache outlives CertInit */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyCache_Clear(server));

    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootA, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL, 0,
        ROOT_A_CERT, ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertAddTrusted(
        server, rootB, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE, NULL, 0,
        ROOT_B_CERT, ROOT_B_CERT_len));

    /* Cold verify of chain A checks every cert */
    _fullChainCacheCbCount = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(_fullChainCacheCbCount > 0);

    /* Repeat verify hits the whole-chain entry: nothing is checked */
    _fullChainCacheCbCount = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootA,
        WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY, NULL));
    WH_TEST_ASSERT_RETURN(_fullChainCacheCbCount == 0);

    /* The leaf alone, and the leaf after chain B's intermediate, are
     * checked the normal way and fail. Both roots are loaded for the second
     * so that intermediate itself verifies. Try twice: a failed verify must
     * not be cached. */
    for (i = 0; i < 2; i++) {
        _fullChainCacheCbCount = 0;
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_CERT_VERIFY ==
            wh_Server_CertVerify(server, LEAF_A_CERT, LEAF_A_CERT_len, rootA,
                                 WH_CERT_FLAGS_NONE, WH_NVM_FLAGS_USAGE_ANY,
                                 NULL));
        WH_TEST_ASSERT_RETURN(_fullChainCacheCbCount > 0);

        _fullChainCacheCbCount = 0;
        WH_TEST_ASSERT_RETURN(
            WH_ERROR_CERT_VERIFY ==
            wh_Server_CertVerifyMultiRoot(server, otherChain, otherChainLen,
                                          rootsAB, 2, WH_CERT_FLAGS_NONE,
                                          WH_NVM_FLAGS_USAGE_ANY, NULL));
        WH_TEST_ASSERT_RETURN(_fullChainCacheCbCount > 0);
    }

    /* A cached chain still caches the leaf public key when asked */
    _fullChainCacheCbCount = 0;
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerify(
        server, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, rootA,
        WH_CERT_FLAGS_CACHE_LEAF_PUBKEY, WH_NVM_FLAGS_USAGE_VERIFY, &keyId));
    WH_TEST_ASSERT_RETURN(_fullChainCacheCbCount == 0);
    WH_TEST_ASSERT_RETURN(!WH_KEYID_ISERASED(keyId));
    WH_TEST_RETURN_ON_FAIL(
        wh_Server_KeystoreReadKey(server, keyId, &meta, pubKey, &pubKeyLen));
    WH_TEST_ASSERT_RETURN(pubKeyLen == LEAF_A_PUBKEY_len);
    WH_TEST_ASSERT_RETURN(0 == memcmp(pubKey, LEAF_A_PUBKEY, pubKeyLen));
    WH_TEST_RETURN_ON_FAIL(wh_Server_KeystoreEvictKey(server, keyId));

    /* Cleanup */
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertVerifyCache_Clear(server));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootA));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertEraseTrusted(server, rootB));
    WH_TEST_RETURN_ON_FAIL(wh_Server_CertSetVerifyCb(server, savedCb));

    return 0;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE_FULLCHAIN */

#endif
