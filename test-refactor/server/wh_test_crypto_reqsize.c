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
 * test-refactor/server/wh_test_crypto_reqsize.c
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    !defined(NO_AES)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* Populate the generic request header and dispatch a non-DMA cipher request.
 * req_size is inSize plus the header the dispatcher strips. */
static int _dispatchCipher(whServerContext* server, int algoType,
                           uint16_t inSize, void* req_packet, void* resp_packet)
{
    whMessageCrypto_GenericRequestHeader* hdr =
        (whMessageCrypto_GenericRequestHeader*)req_packet;
    uint16_t resp_size = 0;
    uint16_t req_size =
        (uint16_t)(inSize + sizeof(whMessageCrypto_GenericRequestHeader));

    hdr->algoType    = (whMessageCrypto_AlgoType)algoType;
    hdr->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    hdr->affinity    = 0;

    return wh_Server_HandleCryptoRequest(server, WH_COMM_MAGIC_NATIVE,
                                         WC_ALGO_TYPE_CIPHER, 0, req_size,
                                         req_packet, &resp_size, resp_packet);
}

/* Each request sets sz so the 32-bit sum wraps back to a header-only inSize;
 * a 32-bit server with the unfixed guard would accept it. */
static int _whTest_AesReqSizeRejects(whServerContext* server)
{
    uint8_t  req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t  resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t* cin = req_packet + sizeof(whMessageCrypto_GenericRequestHeader);
    int      ret;
    uint16_t inSize;
#ifdef WOLFSSL_AES_COUNTER
    whMessageCrypto_AesCtrRequest* ctr = (whMessageCrypto_AesCtrRequest*)cin;
#endif
#ifdef HAVE_AES_ECB
    whMessageCrypto_AesEcbRequest* ecb = (whMessageCrypto_AesEcbRequest*)cin;
#endif
#ifdef HAVE_AES_CBC
    whMessageCrypto_AesCbcRequest* cbc = (whMessageCrypto_AesCbcRequest*)cin;
#endif
#ifdef HAVE_AESGCM
    whMessageCrypto_AesGcmRequest* gcm = (whMessageCrypto_AesGcmRequest*)cin;
#endif

#ifdef WOLFSSL_AES_COUNTER
    memset(req_packet, 0, sizeof(req_packet));
    ctr->enc    = 1;
    ctr->keyLen = 32;
    ctr->sz     = (uint32_t)(0u - 32u);
    inSize = (uint16_t)(sizeof(whMessageCrypto_AesCtrRequest) + AES_IV_SIZE +
                        AES_BLOCK_SIZE);
    ret    = _dispatchCipher(server, WC_CIPHER_AES_CTR, inSize, req_packet,
                             resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

#ifdef HAVE_AES_ECB
    memset(req_packet, 0, sizeof(req_packet));
    ecb->enc    = 1;
    ecb->keyLen = 32;
    ecb->sz     = (uint32_t)(0u - 32u);
    inSize      = (uint16_t)sizeof(whMessageCrypto_AesEcbRequest);
    ret         = _dispatchCipher(server, WC_CIPHER_AES_ECB, inSize, req_packet,
                                  resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

#ifdef HAVE_AES_CBC
    memset(req_packet, 0, sizeof(req_packet));
    cbc->enc    = 1;
    cbc->keyLen = 32;
    cbc->sz     = (uint32_t)(0u - 32u);
    inSize = (uint16_t)(sizeof(whMessageCrypto_AesCbcRequest) + AES_BLOCK_SIZE);
    ret    = _dispatchCipher(server, WC_CIPHER_AES_CBC, inSize, req_packet,
                             resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

#ifdef HAVE_AESGCM
    memset(req_packet, 0, sizeof(req_packet));
    gcm->enc       = 0;
    gcm->keyLen    = 32;
    gcm->sz        = (uint32_t)(0u - 32u);
    gcm->ivSz      = 0;
    gcm->authInSz  = 0;
    gcm->authTagSz = 0;
    inSize         = (uint16_t)sizeof(whMessageCrypto_AesGcmRequest);
    ret = _dispatchCipher(server, WC_CIPHER_AES_GCM, inSize, req_packet,
                          resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

    return WH_ERROR_OK;
}

/* Width-independent proof the vectors alias a header-only inSize in 32-bit; a
 * request struct size change fails here instead of making the tests vacuous. */
static int _whTest_ReqSizeVectorsWrap(whServerContext* server)
{
    (void)server;

#ifdef WOLFSSL_AES_COUNTER
    WH_TEST_ASSERT_RETURN((uint32_t)(sizeof(whMessageCrypto_AesCtrRequest) +
                                     (uint32_t)(0u - 32u) + 32u + AES_IV_SIZE +
                                     AES_BLOCK_SIZE) ==
                          (uint32_t)(sizeof(whMessageCrypto_AesCtrRequest) +
                                     AES_IV_SIZE + AES_BLOCK_SIZE));
#endif
#ifdef HAVE_AES_ECB
    WH_TEST_ASSERT_RETURN((uint32_t)(sizeof(whMessageCrypto_AesEcbRequest) +
                                     (uint32_t)(0u - 32u) + 32u) ==
                          (uint32_t)sizeof(whMessageCrypto_AesEcbRequest));
#endif
#ifdef HAVE_AES_CBC
    WH_TEST_ASSERT_RETURN(
        (uint32_t)(sizeof(whMessageCrypto_AesCbcRequest) +
                   (uint32_t)(0u - 32u) + 32u + AES_BLOCK_SIZE) ==
        (uint32_t)(sizeof(whMessageCrypto_AesCbcRequest) + AES_BLOCK_SIZE));
#endif
#ifdef HAVE_AESGCM
    WH_TEST_ASSERT_RETURN((uint32_t)(sizeof(whMessageCrypto_AesGcmRequest) +
                                     (uint32_t)(0u - 32u) + 32u) ==
                          (uint32_t)sizeof(whMessageCrypto_AesGcmRequest));
#endif

    return WH_ERROR_OK;
}

#ifdef WOLFHSM_CFG_DMA
/* Dispatch a DMA cipher request; same header stripping as the non-DMA path. */
static int _dispatchCipherDma(whServerContext* server, int algoType,
                              uint16_t inSize, void* req_packet,
                              void* resp_packet)
{
    whMessageCrypto_GenericRequestHeader* hdr =
        (whMessageCrypto_GenericRequestHeader*)req_packet;
    uint16_t resp_size = 0;
    uint16_t req_size =
        (uint16_t)(inSize + sizeof(whMessageCrypto_GenericRequestHeader));

    hdr->algoType    = (whMessageCrypto_AlgoType)algoType;
    hdr->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;
    hdr->affinity    = 0;

    return wh_Server_HandleCryptoDmaRequest(
        server, WH_COMM_MAGIC_NATIVE, WC_ALGO_TYPE_CIPHER, 0, req_size,
        req_packet, &resp_size, resp_packet);
}

/* GcmDma has several wrappable addends so an alias-craft reaches the guarded
 * sum; Ctr/Ecb/CbcDma wrap only through keySz (caught by the header-size
 * check either way) and are exercised for uniformity. */
static int _whTest_AesDmaReqSizeRejects(whServerContext* server)
{
    uint8_t  req_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t  resp_packet[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t* cin = req_packet + sizeof(whMessageCrypto_GenericRequestHeader);
    int      ret;
    uint16_t inSize;
    whMessageCrypto_AesGcmDmaRequest* gcm =
        (whMessageCrypto_AesGcmDmaRequest*)cin;
#ifdef WOLFSSL_AES_COUNTER
    whMessageCrypto_AesCtrDmaRequest* ctr =
        (whMessageCrypto_AesCtrDmaRequest*)cin;
#endif
#ifdef HAVE_AES_ECB
    whMessageCrypto_AesEcbDmaRequest* ecb =
        (whMessageCrypto_AesEcbDmaRequest*)cin;
#endif
#ifdef HAVE_AES_CBC
    whMessageCrypto_AesCbcDmaRequest* cbc =
        (whMessageCrypto_AesCbcDmaRequest*)cin;
#endif

#ifdef HAVE_AESGCM
    memset(req_packet, 0, sizeof(req_packet));
    gcm->enc       = 0;
    gcm->keySz     = 32;
    gcm->ivSz      = (uint32_t)(0u - 32u);
    gcm->authTagSz = 0;
    inSize         = (uint16_t)sizeof(whMessageCrypto_AesGcmDmaRequest);
    ret = _dispatchCipherDma(server, WC_CIPHER_AES_GCM, inSize, req_packet,
                             resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#else
    (void)gcm;
#endif

#ifdef WOLFSSL_AES_COUNTER
    memset(req_packet, 0, sizeof(req_packet));
    ctr->keySz = 0xFFFFFFF0u;
    inSize     = (uint16_t)sizeof(whMessageCrypto_AesCtrDmaRequest);
    ret = _dispatchCipherDma(server, WC_CIPHER_AES_CTR, inSize, req_packet,
                             resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

#ifdef HAVE_AES_ECB
    memset(req_packet, 0, sizeof(req_packet));
    ecb->keySz = 0xFFFFFFF0u;
    inSize     = (uint16_t)sizeof(whMessageCrypto_AesEcbDmaRequest);
    ret = _dispatchCipherDma(server, WC_CIPHER_AES_ECB, inSize, req_packet,
                             resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

#ifdef HAVE_AES_CBC
    memset(req_packet, 0, sizeof(req_packet));
    cbc->keySz = 0xFFFFFFF0u;
    inSize     = (uint16_t)sizeof(whMessageCrypto_AesCbcDmaRequest);
    ret = _dispatchCipherDma(server, WC_CIPHER_AES_CBC, inSize, req_packet,
                             resp_packet);
    WH_TEST_ASSERT_RETURN(ret != WH_ERROR_OK);
#endif

    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */

int whTest_CryptoReqSize(whServerContext* server)
{
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    WH_TEST_PRINT("Testing AES crypto handler req_size validation...\n");

    WH_TEST_RETURN_ON_FAIL(_whTest_ReqSizeVectorsWrap(server));
    WH_TEST_RETURN_ON_FAIL(_whTest_AesReqSizeRejects(server));
#ifdef WOLFHSM_CFG_DMA
    WH_TEST_RETURN_ON_FAIL(_whTest_AesDmaReqSizeRejects(server));
#endif

    WH_TEST_PRINT("AES crypto req_size validation test SUCCESS\n");

    return WH_ERROR_OK;
}

#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO && !NO_AES */
