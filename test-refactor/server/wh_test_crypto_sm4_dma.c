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
 * test-refactor/server/wh_test_crypto_sm4_dma.c
 *
 * SM4 DMA handlers must reject payload and AAD sizes that do not fit in 32
 * bits. Each case first sends a well-formed one-block request, then the same
 * request with one size raised past 32 bits.
 */

#include "wolfhsm/wh_settings.h"

#if defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO) && \
    defined(WOLFHSM_CFG_DMA)

#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"

#if defined(WOLFSSL_SM4) &&                                  \
    (defined(WOLFSSL_SM4_ECB) || defined(WOLFSSL_SM4_CBC) || \
     defined(WOLFSSL_SM4_CTR) || defined(WOLFSSL_SM4_GCM) || \
     defined(WOLFSSL_SM4_CCM))

#include "wolfssl/wolfcrypt/sm4.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_crypto.h"

#include "wh_test_common.h"
#include "wh_test_list.h"

/* The low 32 bits are one block, so a truncated size looks valid */
#define WH_TEST_SM4_BIG_SZ (((uint64_t)1 << 32) + SM4_BLOCK_SIZE)
#define WH_TEST_SM4_NONCE_SZ 12
#define WH_TEST_SM4_TAG_SZ SM4_BLOCK_SIZE

typedef struct {
    int      type;
    uint64_t sz;
    uint64_t aadSz;
} whTestSm4DmaCase;

static const whTestSm4DmaCase whTestSm4DmaCases[] = {
#ifdef WOLFSSL_SM4_ECB
    {WC_CIPHER_SM4_ECB, WH_TEST_SM4_BIG_SZ, 0},
#endif
#ifdef WOLFSSL_SM4_CBC
    {WC_CIPHER_SM4_CBC, WH_TEST_SM4_BIG_SZ, 0},
#endif
#ifdef WOLFSSL_SM4_CTR
    {WC_CIPHER_SM4_CTR, WH_TEST_SM4_BIG_SZ, 0},
#endif
#ifdef WOLFSSL_SM4_GCM
    {WC_CIPHER_SM4_GCM, WH_TEST_SM4_BIG_SZ, SM4_BLOCK_SIZE},
    {WC_CIPHER_SM4_GCM, SM4_BLOCK_SIZE, WH_TEST_SM4_BIG_SZ},
#endif
#ifdef WOLFSSL_SM4_CCM
    {WC_CIPHER_SM4_CCM, WH_TEST_SM4_BIG_SZ, SM4_BLOCK_SIZE},
    {WC_CIPHER_SM4_CCM, SM4_BLOCK_SIZE, WH_TEST_SM4_BIG_SZ},
#endif
};

/* Lay out an encrypt request with an all-zero inline key */
static uint16_t _BuildRequest(uint8_t* packet, int type, uint64_t sz,
                              uint64_t aadSz, const uint8_t* in, uint8_t* out,
                              const uint8_t* aad)
{
    whMessageCrypto_GenericRequestHeader* hdr =
        (whMessageCrypto_GenericRequestHeader*)packet;
    uint8_t*                   body   = packet + sizeof(*hdr);
    whMessageCrypto_DmaBuffer* input  = NULL;
    whMessageCrypto_DmaBuffer* output = NULL;
    uint32_t*                  keySz  = NULL;
    size_t                     len    = 0;

    memset(packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);
    hdr->algoType    = (uint32_t)type;
    hdr->algoSubType = WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE;

    switch (type) {
        case WC_CIPHER_SM4_ECB: {
            whMessageCrypto_Sm4EcbDmaRequest* req =
                (whMessageCrypto_Sm4EcbDmaRequest*)body;
            req->enc = 1;
            input    = &req->input;
            output   = &req->output;
            keySz    = &req->keySz;
            len      = sizeof(*req);
        } break;
        case WC_CIPHER_SM4_CBC: {
            whMessageCrypto_Sm4CbcDmaRequest* req =
                (whMessageCrypto_Sm4CbcDmaRequest*)body;
            req->enc = 1;
            input    = &req->input;
            output   = &req->output;
            keySz    = &req->keySz;
            len      = sizeof(*req) + SM4_IV_SIZE;
        } break;
        case WC_CIPHER_SM4_CTR: {
            whMessageCrypto_Sm4CtrDmaRequest* req =
                (whMessageCrypto_Sm4CtrDmaRequest*)body;
            input  = &req->input;
            output = &req->output;
            keySz  = &req->keySz;
            len    = sizeof(*req) + SM4_IV_SIZE + SM4_BLOCK_SIZE;
        } break;
        default: {
            whMessageCrypto_Sm4AuthDmaRequest* req =
                (whMessageCrypto_Sm4AuthDmaRequest*)body;
            req->enc       = 1;
            req->ivSz      = WH_TEST_SM4_NONCE_SZ;
            req->authTagSz = WH_TEST_SM4_TAG_SZ;
            req->aad.addr  = (uint64_t)(uintptr_t)aad;
            req->aad.sz    = aadSz;
            input          = &req->input;
            output         = &req->output;
            keySz          = &req->keySz;
            len = sizeof(*req) + WH_TEST_SM4_NONCE_SZ + WH_TEST_SM4_TAG_SZ;
        } break;
    }

    input->addr  = (uint64_t)(uintptr_t)in;
    input->sz    = sz;
    output->addr = (uint64_t)(uintptr_t)out;
    output->sz   = sz;
    *keySz       = SM4_KEY_SIZE;

    return (uint16_t)(sizeof(*hdr) + len + SM4_KEY_SIZE);
}

static int _Dispatch(whServerContext* server, const whTestSm4DmaCase* c,
                     uint64_t sz, uint64_t aadSz)
{
    uint8_t  req[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t  res[WOLFHSM_CFG_COMM_DATA_LEN];
    uint8_t  in[SM4_BLOCK_SIZE]  = {0};
    uint8_t  out[SM4_BLOCK_SIZE] = {0};
    uint8_t  aad[SM4_BLOCK_SIZE] = {0};
    uint16_t resSz               = 0;
    uint16_t reqSz = _BuildRequest(req, c->type, sz, aadSz, in, out, aad);

    return wh_Server_HandleCryptoDmaRequest(server, WH_COMM_MAGIC_NATIVE,
                                            WC_ALGO_TYPE_CIPHER, 0, reqSz, req,
                                            &resSz, res);
}

int whTest_CryptoSm4DmaLength(whServerContext* server)
{
    size_t i;

    for (i = 0; i < sizeof(whTestSm4DmaCases) / sizeof(whTestSm4DmaCases[0]);
         i++) {
        const whTestSm4DmaCase* c     = &whTestSm4DmaCases[i];
        uint64_t                aadSz = (c->aadSz != 0) ? SM4_BLOCK_SIZE : 0;
        int                     ret;

        ret = _Dispatch(server, c, SM4_BLOCK_SIZE, aadSz);
        if (ret != WH_ERROR_OK) {
            WH_ERROR_PRINT("SM4 type %d one-block DMA request failed: %d\n",
                           c->type, ret);
            return WH_TEST_FAIL;
        }

        ret = _Dispatch(server, c, c->sz, c->aadSz);
        if (ret != WH_ERROR_BADARGS) {
            WH_ERROR_PRINT("SM4 type %d accepted a size above 32 bits: %d\n",
                           c->type, ret);
            return WH_TEST_FAIL;
        }
    }

    return WH_ERROR_OK;
}

#endif /* WOLFSSL_SM4 && (any SM4 mode) */

#endif /* WOLFHSM_CFG_ENABLE_SERVER && !WOLFHSM_CFG_NO_CRYPTO && \
          WOLFHSM_CFG_DMA */
