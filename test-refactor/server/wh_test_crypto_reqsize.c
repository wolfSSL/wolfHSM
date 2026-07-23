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
/* Tests that wh_Server_HandleCryptoRequest rejects crypto requests too
 * short to hold the fixed request struct the handler reads. */

#include "wolfhsm/wh_settings.h"

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#ifdef HAVE_ECC
#include "wolfssl/wolfcrypt/ecc.h"
#endif
#ifdef HAVE_CURVE25519
#include "wolfssl/wolfcrypt/curve25519.h"
#endif
#ifdef WOLFSSL_HAVE_MLDSA
#include "wolfssl/wolfcrypt/dilithium.h"
#endif
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#include "wh_test_common.h"
#include "wh_test_list.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

/* Without a covered algorithm nothing below is built, so the weak stub in
 * wh_test_list.c reports the test as skipped. */
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_ED25519) || \
    (defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
     !defined(WOLFSSL_NO_ML_DSA_44))

#define WH_TEST_CRYPTO_REQSIZE_HDR_LEN \
    ((uint16_t)sizeof(whMessageCrypto_GenericRequestHeader))
#define WH_TEST_CRYPTO_REQSIZE_RESP_HDR_LEN \
    ((uint16_t)sizeof(whMessageCrypto_GenericResponseHeader))

/* Request and response packets, static to keep them off the stack */
static uint8_t _reqPacket[WOLFHSM_CFG_COMM_DATA_LEN];
static uint8_t _respPacket[WOLFHSM_CFG_COMM_DATA_LEN];

/* Build a crypto request packet: generic header, fixed request struct, then
 * any variable-length payload the request declares. */
static void _BuildRequest(uint32_t algoType, uint32_t algoSubType,
                          const void* reqStruct, uint16_t reqStructLen,
                          const void* payload, uint16_t payloadLen)
{
    whMessageCrypto_GenericRequestHeader* hdr =
        (whMessageCrypto_GenericRequestHeader*)_reqPacket;

    memset(_reqPacket, 0, sizeof(_reqPacket));
    memset(_respPacket, 0, sizeof(_respPacket));

    hdr->algoType    = algoType;
    hdr->algoSubType = algoSubType;
    hdr->affinity    = WH_CRYPTO_AFFINITY_SW;

    memcpy(_reqPacket + WH_TEST_CRYPTO_REQSIZE_HDR_LEN, reqStruct,
           reqStructLen);
    if ((payload != NULL) && (payloadLen > 0)) {
        memcpy(_reqPacket + WH_TEST_CRYPTO_REQSIZE_HDR_LEN + reqStructLen,
               payload, payloadLen);
    }
}

/* Dispatch whatever is currently in _reqPacket at the given req_size */
static int _SendRequest(whServerContext* server, uint16_t reqSize)
{
    uint16_t respSize = 0;

    return wh_Server_HandleCryptoRequest(server, WH_COMM_MAGIC_NATIVE,
                                         WC_ALGO_TYPE_PK, 0, reqSize,
                                         _reqPacket, &respSize, _respPacket);
}

/* Reissue the request already in _reqPacket at two lengths too short to hold
 * the fixed struct. Both must be rejected, stale request bytes and all. */
static int _CheckTruncated(whServerContext* server, const char* name,
                           uint16_t reqStructLen)
{
    int      ret;
    uint16_t i;
    uint16_t shortSizes[2];

    /* Header only (zero payload), and one byte short of the fixed struct */
    shortSizes[0] = WH_TEST_CRYPTO_REQSIZE_HDR_LEN;
    shortSizes[1] =
        (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN + reqStructLen - 1);

    /* The size guard is the only thing that should reject these, so require
     * its error rather than accepting any failure. */
    for (i = 0; i < 2; i++) {
        ret = _SendRequest(server, shortSizes[i]);
        if (ret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("%s truncated to %u bytes: expected %d, got %d\n",
                           name, (unsigned)shortSizes[i], WH_ERROR_BADARGS,
                           ret);
            return WH_TEST_FAIL;
        }
    }

    return WH_TEST_SUCCESS;
}

/* Run the positive control at full length, then the truncated cases */
static int _CheckFixedRequest(whServerContext* server, const char* name,
                              uint32_t algoType, uint32_t algoSubType,
                              const void* reqStruct, uint16_t reqStructLen)
{
    int ret;

    _BuildRequest(algoType, algoSubType, reqStruct, reqStructLen, NULL, 0);

    ret = _SendRequest(
        server, (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN + reqStructLen));
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("%s full-length request failed: ret=%d\n", name, ret);
        return WH_TEST_FAIL;
    }

    return _CheckTruncated(server, name, reqStructLen);
}

#ifdef HAVE_ECC
static int _whTest_CryptoReqSizeEcc(whServerContext* server)
{
    whMessageCrypto_EccKeyGenRequest req;

    memset(&req, 0, sizeof(req));
    req.sz      = 32;
    req.curveId = ECC_SECP256R1;
    req.keyId   = WH_KEYID_ERASED;
    req.flags   = WH_NVM_FLAGS_EPHEMERAL;

    return _CheckFixedRequest(server, "ECC keygen", WC_PK_TYPE_EC_KEYGEN,
                              WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE, &req,
                              (uint16_t)sizeof(req));
}
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
static int _whTest_CryptoReqSizeCurve25519(whServerContext* server)
{
    whMessageCrypto_Curve25519KeyGenRequest req;

    memset(&req, 0, sizeof(req));
    req.sz    = CURVE25519_KEYSIZE;
    req.keyId = WH_KEYID_ERASED;
    req.flags = WH_NVM_FLAGS_EPHEMERAL;

    return _CheckFixedRequest(server, "Curve25519 keygen",
                              WC_PK_TYPE_CURVE25519_KEYGEN,
                              WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE, &req,
                              (uint16_t)sizeof(req));
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
static int _whTest_CryptoReqSizeEd25519(whServerContext* server)
{
    whMessageCrypto_Ed25519KeyGenRequest req;

    memset(&req, 0, sizeof(req));
    req.keyId = WH_KEYID_ERASED;
    req.flags = WH_NVM_FLAGS_EPHEMERAL;

    return _CheckFixedRequest(server, "Ed25519 keygen",
                              WC_PK_TYPE_ED25519_KEYGEN,
                              WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE, &req,
                              (uint16_t)sizeof(req));
}
#endif /* HAVE_ED25519 */

#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_NO_ML_DSA_44)
static int _whTest_CryptoReqSizeMlDsa(whServerContext* server)
{
    whMessageCrypto_MlDsaKeyGenRequest req;

    memset(&req, 0, sizeof(req));
    req.level = WC_ML_DSA_44;
    req.keyId = WH_KEYID_ERASED;
    req.flags = WH_NVM_FLAGS_EPHEMERAL;

    return _CheckFixedRequest(server, "ML-DSA keygen",
                              WC_PK_TYPE_PQC_SIG_KEYGEN, WC_PQC_SIG_TYPE_MLDSA,
                              &req, (uint16_t)sizeof(req));
}
#endif /* WOLFSSL_HAVE_MLDSA && !NO_MAKE_KEY && !NO_ML_DSA_44 */

/* Sign and verify need keygen to produce the key they operate on */
#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_NO_ML_DSA_44) && !defined(WOLFSSL_MLDSA_NO_SIGN) && \
    !defined(WOLFSSL_MLDSA_NO_VERIFY)

#define WH_TEST_CRYPTO_REQSIZE_MSG_LEN 32
#define WH_TEST_CRYPTO_REQSIZE_SIG_MAX DILITHIUM_MAX_SIG_SIZE

/* Captured ML-DSA signature and the verify request payload built from it */
static uint8_t _sig[WH_TEST_CRYPTO_REQSIZE_SIG_MAX];
static uint8_t _payload[WH_TEST_CRYPTO_REQSIZE_SIG_MAX +
                        WH_TEST_CRYPTO_REQSIZE_MSG_LEN];

/* Cache an ML-DSA key and return the client-visible key id */
static int _MlDsaCacheKey(whServerContext* server, uint32_t* outKeyId)
{
    whMessageCrypto_MlDsaKeyGenRequest  req;
    whMessageCrypto_MlDsaKeyGenResponse res;
    int                                 ret;

    memset(&req, 0, sizeof(req));
    req.level = WC_ML_DSA_44;
    req.keyId = WH_KEYID_ERASED;
    req.flags = WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY;

    _BuildRequest(WC_PK_TYPE_PQC_SIG_KEYGEN, WC_PQC_SIG_TYPE_MLDSA, &req,
                  (uint16_t)sizeof(req), NULL, 0);

    ret = _SendRequest(
        server, (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN + sizeof(req)));
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("ML-DSA keygen for sign/verify failed: ret=%d\n", ret);
        return WH_TEST_FAIL;
    }

    memcpy(&res, _respPacket + WH_TEST_CRYPTO_REQSIZE_RESP_HDR_LEN,
           sizeof(res));
    *outKeyId = res.keyId;

    return WH_TEST_SUCCESS;
}

/* Sign the message, keep the signature, then run the truncated cases */
static int _MlDsaSignPhase(whServerContext* server, uint32_t keyId,
                           const uint8_t* msg, uint16_t msgLen,
                           uint16_t* outSigLen)
{
    whMessageCrypto_MlDsaSignRequest  req;
    whMessageCrypto_MlDsaSignResponse res;
    int                               ret;

    memset(&req, 0, sizeof(req));
    req.level       = WC_ML_DSA_44;
    req.keyId       = keyId;
    req.sz          = msgLen;
    req.preHashType = WC_HASH_TYPE_NONE;

    _BuildRequest(WC_PK_TYPE_PQC_SIG_SIGN, WC_PQC_SIG_TYPE_MLDSA, &req,
                  (uint16_t)sizeof(req), msg, msgLen);

    ret = _SendRequest(server, (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN +
                                          sizeof(req) + msgLen));
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("ML-DSA sign full-length request failed: ret=%d\n", ret);
        return WH_TEST_FAIL;
    }

    memcpy(&res, _respPacket + WH_TEST_CRYPTO_REQSIZE_RESP_HDR_LEN,
           sizeof(res));
    if ((res.sz == 0) || (res.sz > sizeof(_sig))) {
        WH_ERROR_PRINT("ML-DSA signature length %u out of range\n",
                       (unsigned)res.sz);
        return WH_TEST_FAIL;
    }
    *outSigLen = (uint16_t)res.sz;
    memcpy(_sig, _respPacket + WH_TEST_CRYPTO_REQSIZE_RESP_HDR_LEN +
                     sizeof(res),
           *outSigLen);

    return _CheckTruncated(server, "ML-DSA sign", (uint16_t)sizeof(req));
}

/* Verify the signature just produced, then run the truncated cases */
static int _MlDsaVerifyPhase(whServerContext* server, uint32_t keyId,
                             uint16_t sigLen, const uint8_t* msg,
                             uint16_t msgLen)
{
    whMessageCrypto_MlDsaVerifyRequest  req;
    whMessageCrypto_MlDsaVerifyResponse res;
    int                                 ret;

    memset(&req, 0, sizeof(req));
    req.level       = WC_ML_DSA_44;
    req.keyId       = keyId;
    req.sigSz       = sigLen;
    req.hashSz      = msgLen;
    req.preHashType = WC_HASH_TYPE_NONE;

    memcpy(_payload, _sig, sigLen);
    memcpy(_payload + sigLen, msg, msgLen);

    _BuildRequest(WC_PK_TYPE_PQC_SIG_VERIFY, WC_PQC_SIG_TYPE_MLDSA, &req,
                  (uint16_t)sizeof(req), _payload, (uint16_t)(sigLen + msgLen));

    ret = _SendRequest(server, (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN +
                                          sizeof(req) + sigLen + msgLen));
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("ML-DSA verify full-length request failed: ret=%d\n",
                       ret);
        return WH_TEST_FAIL;
    }

    memcpy(&res, _respPacket + WH_TEST_CRYPTO_REQSIZE_RESP_HDR_LEN,
           sizeof(res));
    if (res.res != 1) {
        WH_ERROR_PRINT("ML-DSA verify control did not verify: res=%u\n",
                       (unsigned)res.res);
        return WH_TEST_FAIL;
    }

    return _CheckTruncated(server, "ML-DSA verify", (uint16_t)sizeof(req));
}

/* Drop the cached key so the shared server context is left as it was found.
 * A sign request carrying the evict option needs no signature, so this works
 * on every path where the key was cached. */
static int _MlDsaEvictKey(whServerContext* server, uint32_t keyId,
                          const uint8_t* msg, uint16_t msgLen)
{
    whMessageCrypto_MlDsaSignRequest req;
    int                              ret;

    memset(&req, 0, sizeof(req));
    req.options     = WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT;
    req.level       = WC_ML_DSA_44;
    req.keyId       = keyId;
    req.sz          = msgLen;
    req.preHashType = WC_HASH_TYPE_NONE;

    _BuildRequest(WC_PK_TYPE_PQC_SIG_SIGN, WC_PQC_SIG_TYPE_MLDSA, &req,
                  (uint16_t)sizeof(req), msg, msgLen);

    ret = _SendRequest(server, (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN +
                                          sizeof(req) + msgLen));
    if (ret != WH_ERROR_OK) {
        WH_ERROR_PRINT("ML-DSA evict failed: ret=%d\n", ret);
        return WH_TEST_FAIL;
    }

    /* Reissuing the same request must now fail, proving the key is gone */
    req.options = 0;
    _BuildRequest(WC_PK_TYPE_PQC_SIG_SIGN, WC_PQC_SIG_TYPE_MLDSA, &req,
                  (uint16_t)sizeof(req), msg, msgLen);

    ret = _SendRequest(server, (uint16_t)(WH_TEST_CRYPTO_REQSIZE_HDR_LEN +
                                          sizeof(req) + msgLen));
    if (ret == WH_ERROR_OK) {
        WH_ERROR_PRINT("ML-DSA key still cached after evict\n");
        return WH_TEST_FAIL;
    }

    return WH_TEST_SUCCESS;
}

/* Sign and verify carry a variable-length payload, so their fixed struct is
 * checked against a request that is otherwise complete and valid. */
static int _whTest_CryptoReqSizeMlDsaSignVerify(whServerContext* server)
{
    uint8_t  msg[WH_TEST_CRYPTO_REQSIZE_MSG_LEN];
    uint32_t keyId     = 0;
    uint16_t sigLen    = 0;
    int      keyCached = 0;
    int      evictRc;
    int      rc;

    memset(msg, 0x5A, sizeof(msg));

    rc = _MlDsaCacheKey(server, &keyId);
    if (rc == WH_TEST_SUCCESS) {
        keyCached = 1;
        rc = _MlDsaSignPhase(server, keyId, msg, (uint16_t)sizeof(msg),
                             &sigLen);
    }
    if (rc == WH_TEST_SUCCESS) {
        rc = _MlDsaVerifyPhase(server, keyId, sigLen, msg,
                               (uint16_t)sizeof(msg));
    }

    /* Evict on every path, so a failing subtest does not leave the key
     * behind for whatever runs next against this server. */
    if (keyCached != 0) {
        evictRc = _MlDsaEvictKey(server, keyId, msg, (uint16_t)sizeof(msg));
        if (rc == WH_TEST_SUCCESS) {
            rc = evictRc;
        }
    }

    return rc;
}
#endif /* ML-DSA keygen && !NO_SIGN && !NO_VERIFY */

int whTest_CryptoReqSize(whServerContext* server)
{
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_PRINT("Testing crypto handler request size validation...\n");

#ifdef HAVE_ECC
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoReqSizeEcc(server));
#endif
#ifdef HAVE_CURVE25519
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoReqSizeCurve25519(server));
#endif
#ifdef HAVE_ED25519
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoReqSizeEd25519(server));
#endif
#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && \
    !defined(WOLFSSL_NO_ML_DSA_44)
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoReqSizeMlDsa(server));
#if !defined(WOLFSSL_MLDSA_NO_SIGN) && !defined(WOLFSSL_MLDSA_NO_VERIFY)
    WH_TEST_RETURN_ON_FAIL(_whTest_CryptoReqSizeMlDsaSignVerify(server));
#endif
#endif

    return WH_ERROR_OK;
}

#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_ED25519 || ML-DSA keygen */
#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO */
