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
 * test-refactor/client-server/wh_test_client_certs.c
 *
 * Client-side certificate test suite. Exercises the cert
 * manager through the client request/response API, with
 * and without DMA.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER) \
    && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include "wh_test_common.h"
#include "wh_test_list.h"
#include "wh_test_cert_data_extern.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/* Client cert ids. The ABSENT ids are never added. */
#define CERT_ID_READ 103
#define CERT_ID_ROOT_A 104
#define CERT_ID_ROOT_B 105
#define CERT_ID_ABSENT 106
#define CERT_ID_ABSENT2 107
#define CERT_ID_EXPORTABLE 108
#define CERT_ID_NONEXPORTABLE 109
#define CERT_ID_ACERT_CA 110

typedef struct {
    const unsigned char* cert;
    const size_t*        certLen;
    const whNvmId*       roots;
    uint16_t             numRoots;
    int32_t              expected;
} whTestCertVerifyCase;

typedef int (*whTestCertSubtest)(whClientContext* ctx, int useDma);

static const whNvmId _rootsA[]       = {CERT_ID_ROOT_A};
static const whNvmId _rootsB[]       = {CERT_ID_ROOT_B};
static const whNvmId _rootsAB[]      = {CERT_ID_ROOT_A, CERT_ID_ROOT_B};
static const whNvmId _rootsBA[]      = {CERT_ID_ROOT_B, CERT_ID_ROOT_A};
static const whNvmId _rootsAAbsent[] = {CERT_ID_ROOT_A, CERT_ID_ABSENT};
static const whNvmId _rootsAbsent[]  = {CERT_ID_ABSENT, CERT_ID_ABSENT2};

/* Single-root cases also run through the single-root API */
static const whTestCertVerifyCase _verifyCases[] = {
    {INTERMEDIATE_A_CERT, &INTERMEDIATE_A_CERT_len, _rootsA, 1, WH_ERROR_OK},
    {LEAF_A_CERT, &LEAF_A_CERT_len, _rootsA, 1, WH_ERROR_CERT_VERIFY},
    {INTERMEDIATE_B_CERT, &INTERMEDIATE_B_CERT_len, _rootsA, 1,
     WH_ERROR_CERT_VERIFY},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsA, 1, WH_ERROR_OK},
    {RAW_CERT_CHAIN_B, &RAW_CERT_CHAIN_B_len, _rootsB, 1, WH_ERROR_OK},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsB, 1, WH_ERROR_CERT_VERIFY},
    {RAW_CERT_CHAIN_B, &RAW_CERT_CHAIN_B_len, _rootsA, 1, WH_ERROR_CERT_VERIFY},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsAB, 2, WH_ERROR_OK},
    {RAW_CERT_CHAIN_B, &RAW_CERT_CHAIN_B_len, _rootsAB, 2, WH_ERROR_OK},
    {RAW_CERT_CHAIN_B, &RAW_CERT_CHAIN_B_len, _rootsBA, 2, WH_ERROR_OK},
    {LEAF_A_CERT, &LEAF_A_CERT_len, _rootsAB, 2, WH_ERROR_CERT_VERIFY},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsAAbsent, 2, WH_ERROR_OK},
    {RAW_CERT_CHAIN_B, &RAW_CERT_CHAIN_B_len, _rootsAAbsent, 2,
     WH_ERROR_CERT_VERIFY},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsAbsent, 2,
     WH_ERROR_NOTFOUND},
};


static int _certAdd(whClientContext* ctx, int useDma, whNvmId id,
                    whNvmFlags flags, const uint8_t* cert, uint32_t certLen)
{
    int32_t out_rc = 0;
    int     rc;

    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        rc = wh_Client_CertAddTrustedDma(ctx, id, WH_NVM_ACCESS_ANY, flags,
                                         NULL, 0, cert, certLen, &out_rc);
    }
    else
#endif
    {
        rc = wh_Client_CertAddTrusted(ctx, id, WH_NVM_ACCESS_ANY, flags, NULL,
                                      0, cert, certLen, &out_rc);
    }
    return (rc != WH_ERROR_OK) ? rc : out_rc;
}

static int _certErase(whClientContext* ctx, whNvmId id)
{
    int32_t out_rc = 0;
    int     rc     = wh_Client_CertEraseTrusted(ctx, id, &out_rc);

    return (rc != WH_ERROR_OK) ? rc : out_rc;
}

static int _certRead(whClientContext* ctx, int useDma, whNvmId id,
                     uint8_t* cert, uint32_t* certLen, int32_t* out_rc)
{
    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        return wh_Client_CertReadTrustedDma(ctx, id, cert, *certLen, out_rc);
    }
#endif
    return wh_Client_CertReadTrusted(ctx, id, cert, certLen, out_rc);
}

static int _certVerify(whClientContext* ctx, int useDma, const uint8_t* cert,
                       uint32_t certLen, whNvmId root, int32_t* out_rc)
{
    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        return wh_Client_CertVerifyDma(ctx, cert, certLen, root, out_rc);
    }
#endif
    return wh_Client_CertVerify(ctx, cert, certLen, root, out_rc);
}

static int _certVerifyMultiRoot(whClientContext* ctx, int useDma,
                                const uint8_t* cert, uint32_t certLen,
                                const whNvmId* roots, uint16_t numRoots,
                                int32_t* out_rc)
{
    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        return wh_Client_CertVerifyMultiRootDma(ctx, cert, certLen, roots,
                                                numRoots, out_rc);
    }
#endif
    return wh_Client_CertVerifyMultiRoot(ctx, cert, certLen, roots, numRoots,
                                         out_rc);
}

static int _certVerifyMultiRootSplit(whClientContext* ctx, int useDma,
                                     const uint8_t* cert, uint32_t certLen,
                                     const whNvmId* roots, uint16_t numRoots,
                                     int32_t* out_rc)
{
    int rc;

    (void)useDma;
    do {
#ifdef WOLFHSM_CFG_DMA
        if (useDma) {
            rc = wh_Client_CertVerifyMultiRootDmaRequest(ctx, cert, certLen,
                                                         roots, numRoots);
        }
        else
#endif
        {
            rc = wh_Client_CertVerifyMultiRootRequest(ctx, cert, certLen, roots,
                                                      numRoots);
        }
    } while (rc == WH_ERROR_NOTREADY);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    do {
#ifdef WOLFHSM_CFG_DMA
        if (useDma) {
            rc = wh_Client_CertVerifyMultiRootDmaResponse(ctx, out_rc);
        }
        else
#endif
        {
            rc = wh_Client_CertVerifyMultiRootResponse(ctx, out_rc);
        }
    } while (rc == WH_ERROR_NOTREADY);
    return rc;
}

static int _certVerifyAndCacheLeafPubKey(whClientContext* ctx, int useDma,
                                         const uint8_t* cert, uint32_t certLen,
                                         whNvmId root, whKeyId* keyId,
                                         int32_t* out_rc)
{
    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        return wh_Client_CertVerifyDmaAndCacheLeafPubKey(
            ctx, cert, certLen, root, WH_NVM_FLAGS_USAGE_ANY, keyId, out_rc);
    }
#endif
    return wh_Client_CertVerifyAndCacheLeafPubKey(
        ctx, cert, certLen, root, WH_NVM_FLAGS_USAGE_ANY, keyId, out_rc);
}

static int _certVerifyMultiRootAndCacheLeafPubKey(
    whClientContext* ctx, int useDma, const uint8_t* cert, uint32_t certLen,
    const whNvmId* roots, uint16_t numRoots, whKeyId* keyId, int32_t* out_rc)
{
    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        return wh_Client_CertVerifyMultiRootDmaAndCacheLeafPubKey(
            ctx, cert, certLen, roots, numRoots, WH_NVM_FLAGS_USAGE_ANY, keyId,
            out_rc);
    }
#endif
    return wh_Client_CertVerifyMultiRootAndCacheLeafPubKey(
        ctx, cert, certLen, roots, numRoots, WH_NVM_FLAGS_USAGE_ANY, keyId,
        out_rc);
}

static int _addRoots(whClientContext* ctx, int useDma)
{
    WH_TEST_RETURN_ON_FAIL(_certAdd(ctx, useDma, CERT_ID_ROOT_A,
                                    WH_NVM_FLAGS_NONMODIFIABLE, ROOT_A_CERT,
                                    ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(_certAdd(ctx, useDma, CERT_ID_ROOT_B,
                                    WH_NVM_FLAGS_NONMODIFIABLE, ROOT_B_CERT,
                                    ROOT_B_CERT_len));
    return WH_ERROR_OK;
}

static int _eraseRoots(whClientContext* ctx)
{
    WH_TEST_RETURN_ON_FAIL(_certErase(ctx, CERT_ID_ROOT_A));
    WH_TEST_RETURN_ON_FAIL(_certErase(ctx, CERT_ID_ROOT_B));
    return WH_ERROR_OK;
}

static int _runVerifyCase(whClientContext* ctx, int useDma,
                          const whTestCertVerifyCase* tc)
{
    const uint32_t certLen = (uint32_t)*tc->certLen;
    int32_t        out_rc  = 0;

    if (tc->numRoots == 1) {
        WH_TEST_RETURN_ON_FAIL(
            _certVerify(ctx, useDma, tc->cert, certLen, tc->roots[0], &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == tc->expected);
    }
    WH_TEST_RETURN_ON_FAIL(_certVerifyMultiRoot(
        ctx, useDma, tc->cert, certLen, tc->roots, tc->numRoots, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == tc->expected);
    WH_TEST_RETURN_ON_FAIL(_certVerifyMultiRootSplit(
        ctx, useDma, tc->cert, certLen, tc->roots, tc->numRoots, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == tc->expected);
    return WH_ERROR_OK;
}

static int _runVerifyCases(whClientContext* ctx, int useDma,
                           const whTestCertVerifyCase* cases, size_t count)
{
    size_t i;
    int    ret;

    for (i = 0; i < count; i++) {
        ret = _runVerifyCase(ctx, useDma, &cases[i]);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("verify case %u failed\n", (unsigned)i);
            return ret;
        }
    }
    return WH_ERROR_OK;
}

/* Evict before checking so a failure does not leak a cache slot */
static int _checkLeafPubKey(whClientContext* ctx, int useDma, whKeyId keyId)
{
    uint8_t  pubKey[512] = {0};
    uint16_t pubKeyLen   = sizeof(pubKey);
    int      rc;

    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        rc = wh_Client_KeyExportDma(ctx, keyId, pubKey, sizeof(pubKey), NULL, 0,
                                    &pubKeyLen);
    }
    else
#endif
    {
        rc = wh_Client_KeyExport(ctx, keyId, NULL, 0, pubKey, &pubKeyLen);
    }
    WH_TEST_RETURN_ON_FAIL(wh_Client_KeyEvict(ctx, keyId));
    WH_TEST_RETURN_ON_FAIL(rc);
    WH_TEST_ASSERT_RETURN(pubKeyLen == LEAF_A_PUBKEY_len);
    WH_TEST_ASSERT_RETURN(0 ==
                          memcmp(pubKey, LEAF_A_PUBKEY, LEAF_A_PUBKEY_len));
    return WH_ERROR_OK;
}


/*
 * Verify that wh_Client_CertReadTrusted reports WH_ERROR_BUFFER_SIZE
 * and updates the cert_len out-param when the caller buffer is too
 * small to hold the returned certificate.
 */
static int _whTest_CertReadTrustedSmallBuffer(whClientContext* ctx)
{
    int32_t       out_rc          = 0;
    const whNvmId cert_id         = CERT_ID_READ;
    uint8_t       small_buf[16]   = {0};
    uint8_t       full_buf[2048]  = {0};
    uint32_t      cert_len        = 0;

    /* Sanity: the test cert must actually exceed the small buffer. */
    WH_TEST_ASSERT_RETURN(ROOT_A_CERT_len > sizeof(small_buf));
    WH_TEST_ASSERT_RETURN(ROOT_A_CERT_len <= sizeof(full_buf));

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertAddTrusted(
        ctx, cert_id, WH_NVM_ACCESS_ANY, WH_NVM_FLAGS_NONMODIFIABLE,
        NULL, 0, ROOT_A_CERT, ROOT_A_CERT_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    /* Undersized buffer. */
    cert_len = sizeof(small_buf);
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrusted(
        ctx, cert_id, small_buf, &cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_BUFFER_SIZE);
    WH_TEST_ASSERT_RETURN(cert_len == ROOT_A_CERT_len);

    /* Retry with a properly sized buffer using the reported length. */
    WH_TEST_RETURN_ON_FAIL(wh_Client_CertReadTrusted(
        ctx, cert_id, full_buf, &cert_len, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(cert_len == ROOT_A_CERT_len);

    WH_TEST_RETURN_ON_FAIL(
        wh_Client_CertEraseTrusted(ctx, cert_id, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    return WH_ERROR_OK;
}

/* Single and multi-root verify of certs and chains against roots A and B */
static int _whTest_CertVerifyChains(whClientContext* ctx, int useDma)
{
    WH_TEST_RETURN_ON_FAIL(_addRoots(ctx, useDma));
    WH_TEST_RETURN_ON_FAIL(
        _runVerifyCases(ctx, useDma, _verifyCases, ARRAY_SIZE(_verifyCases)));
    WH_TEST_RETURN_ON_FAIL(_eraseRoots(ctx));
    return WH_ERROR_OK;
}

/* Verify chain A and cache its leaf public key, with one root and with two */
static int _whTest_CertCacheLeafPubKey(whClientContext* ctx, int useDma)
{
    whKeyId keyId  = WH_KEYID_ERASED;
    int32_t out_rc = 0;

    WH_TEST_RETURN_ON_FAIL(_addRoots(ctx, useDma));

    WH_TEST_RETURN_ON_FAIL(_certVerifyAndCacheLeafPubKey(
        ctx, useDma, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, CERT_ID_ROOT_A,
        &keyId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(_checkLeafPubKey(ctx, useDma, keyId));

    keyId = WH_KEYID_ERASED;
    WH_TEST_RETURN_ON_FAIL(_certVerifyMultiRootAndCacheLeafPubKey(
        ctx, useDma, RAW_CERT_CHAIN_A, RAW_CERT_CHAIN_A_len, _rootsAB, 2,
        &keyId, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(_checkLeafPubKey(ctx, useDma, keyId));

    WH_TEST_RETURN_ON_FAIL(_eraseRoots(ctx));
    return WH_ERROR_OK;
}

/* Argument errors are caught on the client before any request is sent */
static int _whTest_CertVerifyBadArgs(whClientContext* ctx, int useDma)
{
    const whNvmId  roots[WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1] = {0};
    const uint16_t over    = WOLFHSM_CFG_CERT_MAX_VERIFY_ROOTS + 1;
    const uint32_t certLen = (uint32_t)RAW_CERT_CHAIN_A_len;
    whKeyId        keyId   = WH_KEYID_ERASED;
    int32_t        out_rc  = 0;

    /* out_rc is required so a verify result can never be dropped */
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _certVerify(ctx, useDma, RAW_CERT_CHAIN_A, certLen,
                                      CERT_ID_ROOT_A, NULL));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _certVerifyMultiRoot(ctx, useDma, RAW_CERT_CHAIN_A,
                                               certLen, roots, 0, &out_rc));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _certVerifyMultiRoot(ctx, useDma, RAW_CERT_CHAIN_A,
                                               certLen, roots, over, &out_rc));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _certVerifyMultiRootSplit(ctx, useDma,
                                                    RAW_CERT_CHAIN_A, certLen,
                                                    roots, over, &out_rc));
    WH_TEST_ASSERT_RETURN(WH_ERROR_BADARGS ==
                          _certVerifyMultiRootAndCacheLeafPubKey(
                              ctx, useDma, RAW_CERT_CHAIN_A, certLen, roots,
                              over, &keyId, &out_rc));
    return WH_ERROR_OK;
}

/* A NONEXPORTABLE cert is stored but cannot be read back */
static int _whTest_CertNonExportable(whClientContext* ctx, int useDma)
{
    uint8_t  cert[2048] = {0};
    uint32_t certLen    = sizeof(cert);
    int32_t  out_rc     = 0;

    WH_TEST_ASSERT_RETURN(ROOT_A_CERT_len <= sizeof(cert));

    WH_TEST_RETURN_ON_FAIL(_certAdd(ctx, useDma, CERT_ID_EXPORTABLE,
                                    WH_NVM_FLAGS_NONMODIFIABLE, ROOT_A_CERT,
                                    ROOT_A_CERT_len));
    WH_TEST_RETURN_ON_FAIL(
        _certAdd(ctx, useDma, CERT_ID_NONEXPORTABLE,
                 WH_NVM_FLAGS_NONMODIFIABLE | WH_NVM_FLAGS_NONEXPORTABLE,
                 ROOT_B_CERT, ROOT_B_CERT_len));

    WH_TEST_RETURN_ON_FAIL(
        _certRead(ctx, useDma, CERT_ID_EXPORTABLE, cert, &certLen, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_ASSERT_RETURN(0 == memcmp(cert, ROOT_A_CERT, ROOT_A_CERT_len));

    certLen = sizeof(cert);
    WH_TEST_RETURN_ON_FAIL(
        _certRead(ctx, useDma, CERT_ID_NONEXPORTABLE, cert, &certLen, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_ACCESS);

    WH_TEST_RETURN_ON_FAIL(_certErase(ctx, CERT_ID_EXPORTABLE));
    WH_TEST_RETURN_ON_FAIL(_certErase(ctx, CERT_ID_NONEXPORTABLE));
    return WH_ERROR_OK;
}

#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
static int _certVerifyAcert(whClientContext* ctx, int useDma,
                            const uint8_t* cert, uint32_t certLen, whNvmId root,
                            int32_t* out_rc)
{
    (void)useDma;
#ifdef WOLFHSM_CFG_DMA
    if (useDma) {
        return wh_Client_CertVerifyAcertDma(ctx, cert, certLen, root, out_rc);
    }
#endif
    return wh_Client_CertVerifyAcert(ctx, cert, certLen, root, out_rc);
}

/* An attribute cert verifies against its issuer only */
static int _whTest_CertVerifyAcert(whClientContext* ctx, int useDma)
{
    int32_t out_rc = 0;

    WH_TEST_RETURN_ON_FAIL(_certAdd(ctx, useDma, CERT_ID_ACERT_CA,
                                    WH_NVM_FLAGS_NONMODIFIABLE, caCert_der,
                                    caCert_der_len));
    WH_TEST_RETURN_ON_FAIL(_certAdd(ctx, useDma, CERT_ID_ROOT_B,
                                    WH_NVM_FLAGS_NONMODIFIABLE, ROOT_B_CERT,
                                    ROOT_B_CERT_len));

    WH_TEST_RETURN_ON_FAIL(_certVerifyAcert(ctx, useDma, attrCert_der,
                                            attrCert_der_len, CERT_ID_ACERT_CA,
                                            &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(_certVerifyAcert(
        ctx, useDma, attrCert_der, attrCert_der_len, CERT_ID_ROOT_B, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_CERT_VERIFY);

    WH_TEST_RETURN_ON_FAIL(_certErase(ctx, CERT_ID_ACERT_CA));
    WH_TEST_RETURN_ON_FAIL(_certErase(ctx, CERT_ID_ROOT_B));
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT */

#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
/* Chain A fails under root B both before and after it is cached under A */
static const whTestCertVerifyCase _crossRootCases[] = {
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsB, 1, WH_ERROR_CERT_VERIFY},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsA, 1, WH_ERROR_OK},
    {RAW_CERT_CHAIN_A, &RAW_CERT_CHAIN_A_len, _rootsB, 1, WH_ERROR_CERT_VERIFY},
};

/* Cache entries stay bound to their root across clear, disable and enable */
static int _whTest_CertVerifyCache(whClientContext* ctx, int useDma)
{
    int32_t out_rc = 0;
    uint8_t enable;

    WH_TEST_RETURN_ON_FAIL(_addRoots(ctx, useDma));

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertVerifyCacheClear(ctx, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
    WH_TEST_RETURN_ON_FAIL(_runVerifyCases(ctx, useDma, _crossRootCases,
                                           ARRAY_SIZE(_crossRootCases)));

    for (enable = 0; enable <= 1; enable++) {
        WH_TEST_RETURN_ON_FAIL(
            wh_Client_CertVerifyCacheSetEnabled(ctx, enable, &out_rc));
        WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);
        WH_TEST_RETURN_ON_FAIL(_runVerifyCases(ctx, useDma, _crossRootCases,
                                               ARRAY_SIZE(_crossRootCases)));
    }

    WH_TEST_RETURN_ON_FAIL(_eraseRoots(ctx));
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE */

/* Run once per DMA mode */
static const whTestCertSubtest _subtests[] = {
    _whTest_CertVerifyChains,  _whTest_CertCacheLeafPubKey,
    _whTest_CertVerifyBadArgs, _whTest_CertNonExportable,
#if defined(WOLFHSM_CFG_CERTIFICATE_MANAGER_ACERT)
    _whTest_CertVerifyAcert,
#endif
#ifdef WOLFHSM_CFG_CERTIFICATE_VERIFY_CACHE
    _whTest_CertVerifyCache,
#endif
};


int whTest_ClientCerts(whClientContext* ctx)
{
    int32_t out_rc = 0;
    int     useDma;
    size_t  i;
    int     ret;

    WH_TEST_RETURN_ON_FAIL(wh_Client_CertInit(ctx, &out_rc));
    WH_TEST_ASSERT_RETURN(out_rc == WH_ERROR_OK);

    WH_TEST_RETURN_ON_FAIL(_whTest_CertReadTrustedSmallBuffer(ctx));

    for (useDma = 0; useDma < WH_TEST_DMA_MODE_CNT; useDma++) {
        for (i = 0; i < ARRAY_SIZE(_subtests); i++) {
            ret = _subtests[i](ctx, useDma);
            if (ret != WH_ERROR_OK) {
                WH_ERROR_PRINT("subtest %u failed, useDma=%d\n", (unsigned)i,
                               useDma);
                return ret;
            }
        }
    }

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER && !WOLFHSM_CFG_NO_CRYPTO */
