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
 * src/wh_client_crypto.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_ENABLE_CLIENT)

/* System libraries */
#include <stdint.h>
#include <stddef.h> /* For NULL */
#include <string.h> /* For memset, memcpy */


/* Common WolfHSM types and defines shared with the server */
#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_utils.h"


/* Components */
#include "wolfhsm/wh_comm.h"
#if !defined(WOLFHSM_CFG_NO_CRYPTO)
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/wc_port.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/wc_mldsa.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"
#if defined(WOLFSSL_HAVE_LMS)
#include "wolfssl/wolfcrypt/wc_lms.h"
#endif
#if defined(WOLFSSL_HAVE_XMSS)
#include "wolfssl/wolfcrypt/wc_xmss.h"
#endif
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#endif

/* Message definitions */
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_message_comm.h"
#include "wolfhsm/wh_message_customcb.h"
#include "wolfhsm/wh_message_crypto.h"

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"

/** Forward declarations */
#ifdef HAVE_ECC
/* Async halves of the keygen path used by the public Request/Response APIs
 * and the blocking wrappers wh_Client_EccMakeCacheKey/EccMakeExportKey. */
static int _EccMakeKeyRequest(whClientContext* ctx, int size, int curveId,
                              whKeyId key_id, whNvmFlags flags,
                              uint16_t label_len, const uint8_t* label);
static int _EccMakeKeyResponse(whClientContext* ctx, whKeyId* out_key_id,
                               ecc_key* out_key);
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Server creates a key based on incoming flags */
static int _Curve25519MakeKey(whClientContext* ctx, uint16_t size,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              const uint8_t* label, uint16_t label_len,
                              curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifndef NO_RSA
/* Shared async halves used by the RsaMakeCacheKey/RsaMakeExportKey wrappers. */
static int _RsaMakeKeyRequest(whClientContext* ctx, uint32_t size, uint32_t e,
                              whKeyId key_id, whNvmFlags flags,
                              uint32_t label_len, const uint8_t* label);
static int _RsaMakeKeyResponse(whClientContext* ctx, whKeyId* out_key_id,
                               RsaKey* out_rsa);
#endif

#ifdef HAVE_HKDF
/* Generate HKDF output on the server based on the flags */
static int _HkdfMakeKey(whClientContext* ctx, int hashType, whKeyId keyIdIn,
                        const uint8_t* inKey, uint32_t inKeySz,
                        const uint8_t* salt, uint32_t saltSz,
                        const uint8_t* info, uint32_t infoSz, whNvmFlags flags,
                        uint32_t label_len, const uint8_t* label,
                        whKeyId* inout_key_id, uint8_t* out, uint32_t outSz);
#endif

#if defined(HAVE_CMAC_KDF)
static int _CmacKdfMakeKey(whClientContext* ctx, whKeyId saltKeyId,
                           const uint8_t* salt, uint32_t saltSz, whKeyId zKeyId,
                           const uint8_t* z, uint32_t zSz,
                           const uint8_t* fixedInfo, uint32_t fixedInfoSz,
                           whNvmFlags flags, uint32_t label_len,
                           const uint8_t* label, whKeyId* inout_key_id,
                           uint8_t* out, uint32_t outSz);
#endif

#ifdef WOLFSSL_HAVE_MLDSA
/* Make a ML-DSA key on the server based on the flags */
static int _MlDsaMakeKey(whClientContext* ctx, int size, int level,
                         whKeyId* inout_key_id, whNvmFlags flags,
                         uint16_t label_len, const uint8_t* label, wc_MlDsaKey* key);

#ifdef WOLFHSM_CFG_DMA
static int _MlDsaMakeKeyDma(whClientContext* ctx, int level,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, const uint8_t* label, wc_MlDsaKey* key);
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM
static int _MlKemMakeKey(whClientContext* ctx, int level,
                         whKeyId* inout_key_id, whNvmFlags flags,
                         uint16_t label_len, const uint8_t* label, MlKemKey* key);
#ifdef WOLFHSM_CFG_DMA
static int _MlKemMakeKeyDma(whClientContext* ctx, int level,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, const uint8_t* label, MlKemKey* key);
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_HAVE_MLKEM */

static uint8_t* _createCryptoRequest(uint8_t* reqBuf, uint16_t type,
                                     uint32_t affinity);
static uint8_t* _createCryptoRequestWithSubtype(uint8_t* reqBuf, uint16_t type,
                                                uint16_t algoSubType,
                                                uint32_t affinity);
static int      _getCryptoResponse(uint8_t* respBuf, uint16_t type,
                                   uint8_t** outResponse);


/* Helper function to prepare a crypto request buffer with generic header */
static uint8_t* _createCryptoRequest(uint8_t* reqBuf, uint16_t type,
                                     uint32_t affinity)
{
    return _createCryptoRequestWithSubtype(
        reqBuf, type, WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE, affinity);
}

/* Helper function to prepare a crypto request buffer with generic header and
 * subtype */
static uint8_t* _createCryptoRequestWithSubtype(uint8_t* reqBuf, uint16_t type,
                                                uint16_t algoSubType,
                                                uint32_t affinity)
{
    whMessageCrypto_GenericRequestHeader* header =
        (whMessageCrypto_GenericRequestHeader*)reqBuf;
    header->algoType    = type;
    header->algoSubType = algoSubType;
    header->affinity    = affinity;
    return reqBuf + sizeof(whMessageCrypto_GenericRequestHeader);
}

/* Helper function to validate and extract crypto response */
/* TODO: add algoSubType checking */
static int _getCryptoResponse(uint8_t* respBuf, uint16_t type,
                              uint8_t** outResponse)
{
    whMessageCrypto_GenericResponseHeader* header =
        (whMessageCrypto_GenericResponseHeader*)respBuf;

    if (header->algoType != type) {
        return WH_ERROR_ABORTED;
    }

    if (outResponse != NULL) {
        *outResponse = respBuf + sizeof(whMessageCrypto_GenericResponseHeader);
    }

    return header->rc;
}

/** Implementations */
int wh_Client_RngGenerateRequest(whClientContext* ctx, uint32_t size)
{
    whMessageCrypto_RngRequest* req;
    uint8_t*                    dataPtr;
    uint16_t                    req_len;

    if (ctx == NULL || size == 0) {
        return WH_ERROR_BADARGS;
    }
    if (size > WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_RngRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_RNG, ctx->cryptoAffinity);
    req->sz = size;

    req_len =
        (uint16_t)(sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req));

    WH_DEBUG_CLIENT_VERBOSE("RNG req: size=%u\n", (unsigned int)size);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_RNG,
                                 req_len, dataPtr);
}

int wh_Client_RngGenerateResponse(whClientContext* ctx, uint8_t* out,
                                  uint32_t* inout_size)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     res_len = 0;
    uint8_t*                     dataPtr;
    whMessageCrypto_RngResponse* res = NULL;

    if (ctx == NULL || inout_size == NULL ||
        (out == NULL && *inout_size != 0)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_RNG, (uint8_t**)&res);
    if (ret == WH_ERROR_OK) {
        const uint32_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        /* Reject a size the received message does not actually carry, or that
         * exceeds the inline cap or the caller's buffer. */
        if (res_len < hdr_sz || res->sz > (res_len - hdr_sz) ||
            res->sz > WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ ||
            res->sz > *inout_size) {
            ret = WH_ERROR_ABORTED;
        }
        else {
            if (res->sz > 0 && out != NULL) {
                memcpy(out, (uint8_t*)(res + 1), res->sz);
            }
            *inout_size = res->sz;
            WH_DEBUG_CLIENT_VERBOSE("RNG resp: size=%u\n",
                                    (unsigned int)res->sz);
        }
    }
    return ret;
}

int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size)
{
    int            ret = WH_ERROR_OK;
    uint32_t       remaining;
    const uint32_t cap = (uint32_t)WH_MESSAGE_CRYPTO_RNG_MAX_INLINE_SZ;

    if (ctx == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    remaining = size;
    while (ret == WH_ERROR_OK && remaining > 0) {
        uint32_t chunk = (remaining < cap) ? remaining : cap;
        uint32_t got   = chunk;

        ret = wh_Client_RngGenerateRequest(ctx, chunk);
        if (ret != WH_ERROR_OK) {
            break;
        }
        do {
            ret = wh_Client_RngGenerateResponse(ctx, out, &got);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret != WH_ERROR_OK) {
            break;
        }
        if (got == 0) {
            /* Server returned nothing for a non-zero request — guard against
             * infinite loop. */
            ret = WH_ERROR_ABORTED;
            break;
        }
        out += got;
        remaining -= got;
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_RngGenerateDmaRequest(whClientContext* ctx, uint8_t* out,
                                    uint32_t size)
{
    int                            ret             = WH_ERROR_OK;
    uint8_t*                       dataPtr         = NULL;
    whMessageCrypto_RngDmaRequest* req             = NULL;
    uintptr_t                      outAddr         = 0;
    bool                           outAddrAcquired = false;

    if (ctx == NULL || out == NULL || size == 0) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to avoid acquiring a DMA mapping that
     * would be leaked if SendRequest later rejects the request. */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_RngDmaRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_RNG, ctx->cryptoAffinity);

    req->output.sz   = size;
    req->output.addr = 0;

    /* PRE address translation for the output buffer */
    ret = wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)out, (void**)&outAddr, size,
        WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
    if (ret == WH_ERROR_OK) {
        outAddrAcquired  = true;
        req->output.addr = outAddr;
    }

    if (ret == WH_ERROR_OK) {
        /* Stash for POST cleanup in the matching Response */
        ctx->dma.asyncCtx.rng.outAddr    = outAddr;
        ctx->dma.asyncCtx.rng.clientAddr = (uintptr_t)out;
        ctx->dma.asyncCtx.rng.outSz      = size;

        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_RNG,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            dataPtr);
    }

    if (ret != WH_ERROR_OK && outAddrAcquired) {
        /* Release the mapping if SendRequest failed; the Response will not run
         * and the stash is meaningless. */
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, size,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        ctx->dma.asyncCtx.rng.outSz = 0;
    }
    return ret;
}

int wh_Client_RngGenerateDmaResponse(whClientContext* ctx)
{
    int                             ret     = WH_ERROR_OK;
    uint8_t*                        dataPtr = NULL;
    whMessageCrypto_RngDmaResponse* resp    = NULL;
    uint16_t                        respSz  = 0;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_RNG, (uint8_t**)&resp);
        /* On success, server has written random bytes directly to client
         * memory — nothing else to copy. */
        if (ret == WH_ERROR_OK) {
            const uint32_t hdr_sz =
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*resp);
            /* Nothing here is read inline; the bound just holds a success rc
             * to a full response (an error reply carries only the header). */
            if (respSz < hdr_sz) {
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    /* POST DMA cleanup using stashed addresses (runs on every non-NOTREADY
     * exit so the client buffer is safe to read regardless of error). */
    if (ctx->dma.asyncCtx.rng.outSz > 0) {
        uintptr_t outAddr = ctx->dma.asyncCtx.rng.outAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.rng.clientAddr, (void**)&outAddr,
            ctx->dma.asyncCtx.rng.outSz, WH_DMA_OPER_CLIENT_WRITE_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.rng.outSz = 0;
    }
    return ret;
}

int wh_Client_RngGenerateDma(whClientContext* ctx, uint8_t* out, uint32_t size)
{
    int ret;

    ret = wh_Client_RngGenerateDmaRequest(ctx, out, size);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RngGenerateDmaResponse(ctx);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#ifndef NO_AES

#ifdef WOLFSSL_AES_COUNTER
int wh_Client_AesCtrRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len)
{
    whMessageCrypto_AesCtrRequest* req;
    uint8_t*                       dataPtr;
    uint8_t*                       req_in;
    uint8_t*                       req_key;
    uint8_t*                       req_iv;
    uint8_t*                       req_tmp;
    uint32_t                       req_len;
    uint32_t                       key_len;
    whKeyId                        key_id;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0))) {
        return WH_ERROR_BADARGS;
    }

    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    key_len = aes->keylen;
    key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesCtrRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_CTR, ctx->cryptoAffinity);
    req_in  = (uint8_t*)(req + 1);
    req_key = req_in + len;
    req_iv  = req_key + key_len;
    req_tmp = req_iv + AES_IV_SIZE;
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              len + key_len + AES_IV_SIZE + AES_BLOCK_SIZE;

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req->enc    = enc;
    req->keyLen = key_len;
    req->sz     = len;
    req->keyId  = key_id;
    req->left   = aes->left;

    if ((in != NULL) && (len > 0)) {
        memcpy(req_in, in, len);
    }
    if (key_len > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), key_len);
    }
    memcpy(req_iv, (uint8_t*)aes->reg, AES_IV_SIZE);
    memcpy(req_tmp, (uint8_t*)aes->tmp, AES_BLOCK_SIZE);

    WH_DEBUG_CLIENT_VERBOSE("AesCtr req: enc=%d keylen=%u insz=%u reqsz=%u\n",
                            enc, (unsigned int)key_len, (unsigned int)len,
                            (unsigned int)req_len);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO,
                                 WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
}

int wh_Client_AesCtrResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t* out_size)
{
    int                             ret;
    uint8_t*                        dataPtr;
    uint16_t                        group   = 0;
    uint16_t                        action  = 0;
    uint16_t                        res_len = 0;
    whMessageCrypto_AesCtrResponse* res;

    if ((ctx == NULL) || (aes == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_CTR, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            const uint32_t hdr_sz =
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res) +
                (2 * AES_BLOCK_SIZE);
            /* Trailing payload is: output (res->sz) + reg (AES_BLOCK_SIZE)
             * + tmp (AES_BLOCK_SIZE) */
            if (res_len < hdr_sz || res->sz > (res_len - hdr_sz)) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                uint8_t* res_out = (uint8_t*)(res + 1);
                uint8_t* res_reg = res_out + res->sz;
                uint8_t* res_tmp = res_reg + AES_BLOCK_SIZE;

                memcpy(out, res_out, res->sz);
                aes->left = res->left;
                memcpy((uint8_t*)aes->reg, res_reg, AES_BLOCK_SIZE);
                memcpy((uint8_t*)aes->tmp, res_tmp, AES_BLOCK_SIZE);
                if (out_size != NULL) {
                    *out_size = res->sz;
                }
                WH_DEBUG_CLIENT_VERBOSE("AesCtr res: outsz=%u left=%u\n",
                                        (unsigned int)res->sz,
                                        (unsigned int)res->left);
            }
        }
    }
    return ret;
}

int wh_Client_AesCtr(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out)
{
    int ret;

    if ((ctx == NULL) || (aes == NULL) || (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_AesCtrRequest(ctx, aes, enc, in, len);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesCtrResponse(ctx, aes, out, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_AesCtrDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out)
{
    int                               ret     = WH_ERROR_OK;
    whMessageCrypto_AesCtrDmaRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    uintptr_t                         inAddr  = 0;
    uintptr_t                         outAddr = 0;
    bool                              inAcq   = false;
    bool                              outAcq  = false;
    uint8_t*                          req_iv;
    uint8_t*                          req_tmp;
    uint8_t*                          req_key;
    uint32_t                          req_len;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0)) ||
        ((out == NULL) && (len > 0))) {
        return WH_ERROR_BADARGS;
    }

    /* Fail-fast on occupied transport before acquiring DMA mappings */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesCtrDmaRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_CTR, ctx->cryptoAffinity);
    req_iv  = (uint8_t*)req + sizeof(whMessageCrypto_AesCtrDmaRequest);
    req_tmp = req_iv + AES_IV_SIZE;
    req_key = req_tmp + AES_BLOCK_SIZE;
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              AES_IV_SIZE + AES_BLOCK_SIZE;

    memset(req, 0, sizeof(*req));
    req->enc  = enc;
    req->left = aes->left;

    req->keyId = WH_DEVCTX_TO_KEYID(aes->devCtx);
    if (req->keyId != WH_KEYID_ERASED) {
        req->keySz = 0;
    }
    else {
        req->keySz = aes->keylen;
        req_len += req->keySz;
    }

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    memcpy(req_iv, (uint8_t*)aes->reg, AES_IV_SIZE);
    memcpy(req_tmp, (uint8_t*)aes->tmp, AES_BLOCK_SIZE);
    if (req->keySz > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), req->keySz);
    }

    if (in != NULL && len > 0) {
        req->input.sz = len;
        ret           = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAcq           = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK && out != NULL && len > 0) {
        req->output.sz = len;
        ret            = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            outAcq           = true;
            req->output.addr = outAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Stash addresses for POST cleanup in matching Response */
        ctx->dma.asyncCtx.aes.inAddr        = inAddr;
        ctx->dma.asyncCtx.aes.inClientAddr  = (uintptr_t)in;
        ctx->dma.asyncCtx.aes.inSz          = inAcq ? len : 0;
        ctx->dma.asyncCtx.aes.outAddr       = outAddr;
        ctx->dma.asyncCtx.aes.outClientAddr = (uintptr_t)out;
        ctx->dma.asyncCtx.aes.outSz         = outAcq ? len : 0;
        ctx->dma.asyncCtx.aes.aadSz         = 0;

        WH_DEBUG_CLIENT_VERBOSE(
            "AesCtr DMA req: enc=%d keysz=%u insz=%u reqsz=%u\n", enc,
            (unsigned int)req->keySz, (unsigned int)len, (unsigned int)req_len);

        ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                    WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
    }

    if (ret != WH_ERROR_OK) {
        if (inAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        if (outAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.aes, 0, sizeof(ctx->dma.asyncCtx.aes));
    }
    return ret;
}

int wh_Client_AesCtrDmaResponse(whClientContext* ctx, Aes* aes)
{
    int                                ret;
    uint8_t*                           dataPtr;
    uint16_t                           res_len = 0;
    whMessageCrypto_AesCtrDmaResponse* res;

    if ((ctx == NULL) || (aes == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_CTR, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            uint8_t* res_iv =
                (uint8_t*)res + sizeof(whMessageCrypto_AesCtrDmaResponse);
            uint8_t* res_tmp = res_iv + AES_IV_SIZE;
            aes->left        = res->left;
            memcpy((uint8_t*)aes->reg, res_iv, AES_IV_SIZE);
            memcpy((uint8_t*)aes->tmp, res_tmp, AES_BLOCK_SIZE);
            WH_DEBUG_CLIENT_VERBOSE("AesCtr DMA res: left=%u\n",
                                    (unsigned int)res->left);
        }
    }

    /* POST cleanup on every non-NOTREADY return so caller buffers are safe */
    if (ctx->dma.asyncCtx.aes.inSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.inAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.inClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.inSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.inSz = 0;
    }
    if (ctx->dma.asyncCtx.aes.outSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.outAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.outClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.outSz, WH_DMA_OPER_CLIENT_WRITE_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.outSz = 0;
    }
    return ret;
}

int wh_Client_AesCtrDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, uint8_t* out)
{
    int ret;

    if ((ctx == NULL) || (aes == NULL) || (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_AesCtrDmaRequest(ctx, aes, enc, in, len, out);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesCtrDmaResponse(ctx, aes);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
int wh_Client_AesEcbRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len)
{
    whMessageCrypto_AesEcbRequest* req;
    uint8_t*                       dataPtr;
    uint8_t*                       req_in;
    uint8_t*                       req_key;
    uint32_t                       req_len;
    uint32_t                       key_len;
    whKeyId                        key_id;
    uint16_t                       blocks = len / AES_BLOCK_SIZE;

    if ((ctx == NULL) || (aes == NULL) || ((len % AES_BLOCK_SIZE) != 0) ||
        ((in == NULL) && (len > 0))) {
        return WH_ERROR_BADARGS;
    }
    if (blocks == 0) {
        return WH_ERROR_OK;
    }

    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    key_len = aes->keylen;
    key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesEcbRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_ECB, ctx->cryptoAffinity);
    req_in  = (uint8_t*)(req + 1);
    req_key = req_in + len;
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              len + key_len;

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req->enc    = enc;
    req->keyLen = key_len;
    req->sz     = len;
    req->keyId  = key_id;

    if ((in != NULL) && (len > 0)) {
        memcpy(req_in, in, len);
    }
    if (key_len > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), key_len);
    }

    WH_DEBUG_CLIENT_VERBOSE(
        "AesEcb req: enc=%d keylen=%u insz=%u blocks=%u reqsz=%u\n", enc,
        (unsigned int)key_len, (unsigned int)len, (unsigned int)blocks,
        (unsigned int)req_len);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO,
                                 WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
}

int wh_Client_AesEcbResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t* out_size)
{
    int                             ret;
    uint8_t*                        dataPtr;
    uint16_t                        group   = 0;
    uint16_t                        action  = 0;
    uint16_t                        res_len = 0;
    whMessageCrypto_AesEcbResponse* res;

    (void)aes;

    if ((ctx == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_ECB, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            const uint32_t hdr_sz =
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
            if (res_len < hdr_sz || res->sz > (res_len - hdr_sz)) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                uint8_t* res_out = (uint8_t*)(res + 1);
                memcpy(out, res_out, res->sz);
                if (out_size != NULL) {
                    *out_size = res->sz;
                }
                WH_DEBUG_CLIENT_VERBOSE("AesEcb res: outsz=%u\n",
                                        (unsigned int)res->sz);
            }
        }
    }
    return ret;
}

int wh_Client_AesEcb(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out)
{
    int ret;

    if ((ctx == NULL) || (aes == NULL) || ((len % AES_BLOCK_SIZE) != 0) ||
        (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (len == 0) {
        return WH_ERROR_OK;
    }

    ret = wh_Client_AesEcbRequest(ctx, aes, enc, in, len);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesEcbResponse(ctx, aes, out, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_AesEcbDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out)
{
    int                               ret     = WH_ERROR_OK;
    whMessageCrypto_AesEcbDmaRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    uintptr_t                         inAddr  = 0;
    uintptr_t                         outAddr = 0;
    bool                              inAcq   = false;
    bool                              outAcq  = false;
    uint8_t*                          req_key;
    uint32_t                          req_len;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0)) ||
        ((out == NULL) && (len > 0)) || ((len % AES_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }

    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesEcbDmaRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_ECB, ctx->cryptoAffinity);
    req_key = (uint8_t*)req + sizeof(whMessageCrypto_AesEcbDmaRequest);
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    memset(req, 0, sizeof(*req));
    req->enc = enc;

    req->keyId = WH_DEVCTX_TO_KEYID(aes->devCtx);
    if (req->keyId != WH_KEYID_ERASED) {
        req->keySz = 0;
    }
    else {
        req->keySz = aes->keylen;
        req_len += req->keySz;
    }

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    if (req->keySz > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), req->keySz);
    }

    if (in != NULL && len > 0) {
        req->input.sz = len;
        ret           = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAcq           = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK && out != NULL && len > 0) {
        req->output.sz = len;
        ret            = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            outAcq           = true;
            req->output.addr = outAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.aes.inAddr        = inAddr;
        ctx->dma.asyncCtx.aes.inClientAddr  = (uintptr_t)in;
        ctx->dma.asyncCtx.aes.inSz          = inAcq ? len : 0;
        ctx->dma.asyncCtx.aes.outAddr       = outAddr;
        ctx->dma.asyncCtx.aes.outClientAddr = (uintptr_t)out;
        ctx->dma.asyncCtx.aes.outSz         = outAcq ? len : 0;
        ctx->dma.asyncCtx.aes.aadSz         = 0;

        WH_DEBUG_CLIENT_VERBOSE(
            "AesEcb DMA req: enc=%d keysz=%u insz=%u reqsz=%u\n", enc,
            (unsigned int)req->keySz, (unsigned int)len, (unsigned int)req_len);

        ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                    WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
    }

    if (ret != WH_ERROR_OK) {
        if (inAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        if (outAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.aes, 0, sizeof(ctx->dma.asyncCtx.aes));
    }
    return ret;
}

int wh_Client_AesEcbDmaResponse(whClientContext* ctx, Aes* aes)
{
    int                                ret;
    uint8_t*                           dataPtr;
    uint16_t                           res_len = 0;
    whMessageCrypto_AesEcbDmaResponse* res;

    (void)aes;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_ECB, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            WH_DEBUG_CLIENT_VERBOSE("AesEcb DMA res: ok\n");
        }
    }

    if (ctx->dma.asyncCtx.aes.inSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.inAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.inClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.inSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.inSz = 0;
    }
    if (ctx->dma.asyncCtx.aes.outSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.outAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.outClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.outSz, WH_DMA_OPER_CLIENT_WRITE_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.outSz = 0;
    }
    return ret;
}

int wh_Client_AesEcbDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, uint8_t* out)
{
    int ret;

    if ((ctx == NULL) || (aes == NULL) || (in == NULL) || (out == NULL) ||
        ((len % AES_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }
    if (len == 0) {
        return WH_ERROR_OK;
    }

    ret = wh_Client_AesEcbDmaRequest(ctx, aes, enc, in, len, out);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesEcbDmaResponse(ctx, aes);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wh_Client_AesCbcRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len)
{
    whMessageCrypto_AesCbcRequest* req;
    uint8_t*                       dataPtr;
    uint16_t                       blocks;
    uint32_t                       key_len;
    const uint8_t*                 key;
    whKeyId                        key_id;
    uint8_t*                       iv;
    uint32_t                       iv_len;
    uint8_t*                       req_in;
    uint8_t*                       req_key;
    uint8_t*                       req_iv;
    uint32_t                       req_len;

    if ((ctx == NULL) || (aes == NULL) || ((len % AES_BLOCK_SIZE) != 0) ||
        (in == NULL)) {
        return WH_ERROR_BADARGS;
    }

    blocks = len / AES_BLOCK_SIZE;

    if (blocks == 0) {
        return WH_ERROR_OK;
    }

    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    key_len = aes->keylen;
    key     = (const uint8_t*)(aes->devKey);
    key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);
    iv      = (uint8_t*)aes->reg;
    iv_len  = AES_IV_SIZE;

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesCbcRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_CBC, ctx->cryptoAffinity);
    req_in  = (uint8_t*)(req + 1);
    req_key = req_in + len;
    req_iv  = req_key + key_len;
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              len + key_len + iv_len;

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req->enc    = enc;
    req->keyLen = key_len;
    req->sz     = len;
    req->keyId  = key_id;
    if ((in != NULL) && (len > 0)) {
        memcpy(req_in, in, len);
    }
    if ((key != NULL) && (key_len > 0)) {
        memcpy(req_key, key, key_len);
    }
    if ((iv != NULL) && (iv_len > 0)) {
        memcpy(req_iv, iv, iv_len);
    }

    WH_DEBUG_CLIENT_VERBOSE(
        "AesCbc req: enc=%d keylen=%u ivsz=%u insz=%u reqsz=%u\n", enc,
        (unsigned int)key_len, (unsigned int)iv_len, (unsigned int)len,
        (unsigned int)req_len);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO,
                                 WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
}

int wh_Client_AesCbcResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t* out_size)
{
    int                             ret;
    uint8_t*                        dataPtr;
    uint16_t                        group   = 0;
    uint16_t                        action  = 0;
    uint16_t                        res_len = 0;
    whMessageCrypto_AesCbcResponse* res;

    if ((ctx == NULL) || (aes == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_CBC, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            const uint32_t hdr_sz =
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res) +
                AES_IV_SIZE;
            /* Trailing payload is: output (res->sz) + updated IV
             * (AES_IV_SIZE) */
            if (res_len < hdr_sz || res->sz > (res_len - hdr_sz)) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                uint8_t* res_out = (uint8_t*)(res + 1);
                uint8_t* res_iv  = res_out + res->sz;
                memcpy(out, res_out, res->sz);
                /* Update the IV from the server response for CBC chaining.
                 * The server provides the updated IV after the output data. */
                memcpy((uint8_t*)aes->reg, res_iv, AES_IV_SIZE);
                if (out_size != NULL) {
                    *out_size = res->sz;
                }
                WH_DEBUG_CLIENT_VERBOSE("AesCbc res: outsz=%u\n",
                                        (unsigned int)res->sz);
            }
        }
    }

    return ret;
}

int wh_Client_AesCbc(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out)
{
    int ret;

    if ((ctx == NULL) || (aes == NULL) || ((len % AES_BLOCK_SIZE) != 0) ||
        (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (len == 0) {
        return WH_ERROR_OK;
    }

    ret = wh_Client_AesCbcRequest(ctx, aes, enc, in, len);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesCbcResponse(ctx, aes, out, NULL);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_AesCbcDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out)
{
    int                               ret     = WH_ERROR_OK;
    whMessageCrypto_AesCbcDmaRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    uintptr_t                         inAddr  = 0;
    uintptr_t                         outAddr = 0;
    bool                              inAcq   = false;
    bool                              outAcq  = false;
    uint8_t*                          req_iv;
    uint8_t*                          req_key;
    uint32_t                          req_len;
    uint8_t*                          iv;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0)) ||
        ((out == NULL) && (len > 0)) || ((len % AES_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }

    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    iv      = (uint8_t*)aes->reg;
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesCbcDmaRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_CBC, ctx->cryptoAffinity);
    req_iv  = (uint8_t*)req + sizeof(whMessageCrypto_AesCbcDmaRequest);
    req_key = req_iv + AES_IV_SIZE;
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              AES_IV_SIZE;

    memset(req, 0, sizeof(*req));
    req->enc = enc;

    req->keyId = WH_DEVCTX_TO_KEYID(aes->devCtx);
    if (req->keyId != WH_KEYID_ERASED) {
        req->keySz = 0;
    }
    else {
        req->keySz = aes->keylen;
        req_len += req->keySz;
    }

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    memcpy(req_iv, iv, AES_IV_SIZE);
    if (req->keySz > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), req->keySz);
    }

    if (in != NULL && len > 0) {
        req->input.sz = len;
        ret           = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAcq           = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK && out != NULL && len > 0) {
        req->output.sz = len;
        ret            = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            outAcq           = true;
            req->output.addr = outAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.aes.inAddr        = inAddr;
        ctx->dma.asyncCtx.aes.inClientAddr  = (uintptr_t)in;
        ctx->dma.asyncCtx.aes.inSz          = inAcq ? len : 0;
        ctx->dma.asyncCtx.aes.outAddr       = outAddr;
        ctx->dma.asyncCtx.aes.outClientAddr = (uintptr_t)out;
        ctx->dma.asyncCtx.aes.outSz         = outAcq ? len : 0;
        ctx->dma.asyncCtx.aes.aadSz         = 0;

        WH_DEBUG_CLIENT_VERBOSE(
            "AesCbc DMA req: enc=%d keysz=%u insz=%u reqsz=%u\n", enc,
            (unsigned int)req->keySz, (unsigned int)len, (unsigned int)req_len);

        ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                    WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
    }

    if (ret != WH_ERROR_OK) {
        if (inAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        if (outAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.aes, 0, sizeof(ctx->dma.asyncCtx.aes));
    }
    return ret;
}

int wh_Client_AesCbcDmaResponse(whClientContext* ctx, Aes* aes)
{
    int                                ret;
    uint8_t*                           dataPtr;
    uint16_t                           res_len = 0;
    whMessageCrypto_AesCbcDmaResponse* res;

    if ((ctx == NULL) || (aes == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_CBC, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            uint8_t* res_iv =
                (uint8_t*)res + sizeof(whMessageCrypto_AesCbcDmaResponse);
            memcpy((uint8_t*)aes->reg, res_iv, AES_IV_SIZE);
            WH_DEBUG_CLIENT_VERBOSE("AesCbc DMA res: ok\n");
        }
    }

    if (ctx->dma.asyncCtx.aes.inSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.inAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.inClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.inSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.inSz = 0;
    }
    if (ctx->dma.asyncCtx.aes.outSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.outAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.outClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.outSz, WH_DMA_OPER_CLIENT_WRITE_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.outSz = 0;
    }
    return ret;
}

int wh_Client_AesCbcDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, uint8_t* out)
{
    int ret;

    if ((ctx == NULL) || (aes == NULL) || (in == NULL) || (out == NULL) ||
        ((len % AES_BLOCK_SIZE) != 0)) {
        return WH_ERROR_BADARGS;
    }
    if (len == 0) {
        return WH_ERROR_OK;
    }

    ret = wh_Client_AesCbcDmaRequest(ctx, aes, enc, in, len, out);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesCbcDmaResponse(ctx, aes);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
int wh_Client_AesGcmRequest(whClientContext* ctx, Aes* aes, int enc,
                            const uint8_t* in, uint32_t len, const uint8_t* iv,
                            uint32_t iv_len, const uint8_t* authin,
                            uint32_t authin_len, const uint8_t* dec_tag,
                            uint32_t tag_len)
{
    whMessageCrypto_AesGcmRequest* req;
    uint8_t*                       dataPtr;
    uint8_t*                       req_in;
    uint8_t*                       req_key;
    uint8_t*                       req_iv;
    uint8_t*                       req_authin;
    uint8_t*                       req_tag;
    uint32_t                       req_len;
    uint32_t                       key_len;
    whKeyId                        key_id;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0)) ||
        ((iv == NULL) && (iv_len > 0)) ||
        ((authin == NULL) && (authin_len > 0)) ||
        ((enc == 0) && (dec_tag == NULL))) {
        return WH_ERROR_BADARGS;
    }

    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    key_len = aes->keylen;
    key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesGcmRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_GCM, ctx->cryptoAffinity);

    req_in     = (uint8_t*)(req + 1);
    req_key    = req_in + len;
    req_iv     = req_key + key_len;
    req_authin = req_iv + iv_len;
    req_tag    = req_authin + authin_len;

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              len + key_len + iv_len + authin_len + ((enc == 0) ? tag_len : 0);

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    req->enc       = enc;
    req->keyLen    = key_len;
    req->sz        = len;
    req->ivSz      = iv_len;
    req->authInSz  = authin_len;
    req->authTagSz = tag_len;
    req->keyId     = key_id;

    if (in != NULL && len > 0) {
        memcpy(req_in, in, len);
    }
    if (key_len > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), key_len);
    }
    if (iv != NULL && iv_len > 0) {
        memcpy(req_iv, iv, iv_len);
    }
    if (authin != NULL && authin_len > 0) {
        memcpy(req_authin, authin, authin_len);
    }
    if (enc == 0 && dec_tag != NULL && tag_len > 0) {
        memcpy(req_tag, dec_tag, tag_len);
    }

    WH_DEBUG_CLIENT_VERBOSE(
        "AesGcm req: enc=%d keylen=%u ivsz=%u insz=%u authinsz=%u tagsz=%u "
        "reqsz=%u\n",
        enc, (unsigned int)key_len, (unsigned int)iv_len, (unsigned int)len,
        (unsigned int)authin_len, (unsigned int)tag_len, (unsigned int)req_len);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO,
                                 WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
}

int wh_Client_AesGcmResponse(whClientContext* ctx, Aes* aes, uint8_t* out,
                             uint32_t out_capacity, uint32_t* out_size,
                             uint8_t* enc_tag, uint32_t tag_len)
{
    int                             ret;
    uint8_t*                        dataPtr;
    uint16_t                        group   = 0;
    uint16_t                        action  = 0;
    uint16_t                        res_len = 0;
    whMessageCrypto_AesGcmResponse* res;

    (void)aes;

    /* out may be NULL (e.g. GMAC: tag-only, no plaintext). The downstream
     * copy guards on `out != NULL && res->sz > 0`, so out_capacity is
     * checked only when out is actually used. Rejecting `out == NULL &&
     * out_capacity > 0` here would leave a stale response in the comm
     * queue after Request already sent. */
    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_GCM, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            const uint32_t hdr_sz =
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
            uint8_t* res_out = (uint8_t*)(res + 1);
            uint8_t* res_tag = res_out + res->sz;
            uint32_t trailing = (uint32_t)res->sz + (uint32_t)res->authTagSz;
            if (res_len < hdr_sz || trailing < res->sz ||
                trailing > (res_len - hdr_sz)) {
                return WH_ERROR_ABORTED;
            }

            if (out != NULL && res->sz > 0) {
                if (res->sz > out_capacity) {
                    return WH_ERROR_ABORTED;
                }
                memcpy(out, res_out, res->sz);
            }
            if (out_size != NULL) {
                *out_size = res->sz;
            }
            if (enc_tag != NULL && res->authTagSz > 0) {
                if (res->authTagSz > tag_len) {
                    return WH_ERROR_ABORTED;
                }
                memcpy(enc_tag, res_tag, res->authTagSz);
            }
            WH_DEBUG_CLIENT_VERBOSE("AesGcm res: outsz=%u tagsz=%u\n",
                                    (unsigned int)res->sz,
                                    (unsigned int)res->authTagSz);
        }
    }
    return ret;
}

int wh_Client_AesGcm(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, const uint8_t* iv, uint32_t iv_len,
                     const uint8_t* authin, uint32_t authin_len,
                     const uint8_t* dec_tag, uint8_t* enc_tag, uint32_t tag_len,
                     uint8_t* out)
{
    int ret;

    ret = wh_Client_AesGcmRequest(ctx, aes, enc, in, len, iv, iv_len, authin,
                                  authin_len, dec_tag, tag_len);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesGcmResponse(ctx, aes, out, len, NULL, enc_tag,
                                           tag_len);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_AesGcmDmaRequest(whClientContext* ctx, Aes* aes, int enc,
                               const uint8_t* in, uint32_t len, uint8_t* out,
                               const uint8_t* iv, uint32_t iv_len,
                               const uint8_t* authin, uint32_t authin_len,
                               const uint8_t* dec_tag, uint32_t tag_len)
{
    int                               ret     = WH_ERROR_OK;
    whMessageCrypto_AesGcmDmaRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    uintptr_t                         inAddr  = 0;
    uintptr_t                         outAddr = 0;
    uintptr_t                         aadAddr = 0;
    bool                              inAcq   = false;
    bool                              outAcq  = false;
    bool                              aadAcq  = false;
    uint8_t*                          req_iv;
    uint8_t*                          req_tag;
    uint8_t*                          req_key;
    uint32_t                          req_len;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0)) ||
        ((out == NULL) && (len > 0)) || ((iv == NULL) && (iv_len > 0)) ||
        ((authin == NULL) && (authin_len > 0)) ||
        ((enc == 0) && (dec_tag == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_AesGcmDmaRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_GCM, ctx->cryptoAffinity);
    req_iv  = (uint8_t*)req + sizeof(whMessageCrypto_AesGcmDmaRequest);
    req_tag = req_iv + iv_len;
    req_key = req_tag + (enc != 0 ? 0 : tag_len);
    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              iv_len + (enc != 0 ? 0 : tag_len);

    memset(req, 0, sizeof(*req));
    req->enc       = enc;
    req->ivSz      = iv_len;
    req->authTagSz = tag_len;

    req->keyId = WH_DEVCTX_TO_KEYID(aes->devCtx);
    if (req->keyId != WH_KEYID_ERASED) {
        req->keySz = 0;
    }
    else {
        req->keySz = aes->keylen;
        req_len += req->keySz;
    }

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    if (iv_len > 0) {
        memcpy(req_iv, iv, iv_len);
    }
    if (enc == 0 && tag_len > 0) {
        memcpy(req_tag, dec_tag, tag_len);
    }
    if (req->keySz > 0) {
        memcpy(req_key, (const uint8_t*)(aes->devKey), req->keySz);
    }

    if (in != NULL && len > 0) {
        req->input.sz = len;
        ret           = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAcq           = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK && out != NULL && len > 0) {
        req->output.sz = len;
        ret            = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            outAcq           = true;
            req->output.addr = outAddr;
        }
    }

    if (ret == WH_ERROR_OK && authin != NULL && authin_len > 0) {
        req->aad.sz = authin_len;
        ret         = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)authin, (void**)&aadAddr, req->aad.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            aadAcq        = true;
            req->aad.addr = aadAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.aes.inAddr        = inAddr;
        ctx->dma.asyncCtx.aes.inClientAddr  = (uintptr_t)in;
        ctx->dma.asyncCtx.aes.inSz          = inAcq ? len : 0;
        ctx->dma.asyncCtx.aes.outAddr       = outAddr;
        ctx->dma.asyncCtx.aes.outClientAddr = (uintptr_t)out;
        ctx->dma.asyncCtx.aes.outSz         = outAcq ? len : 0;
        ctx->dma.asyncCtx.aes.aadAddr       = aadAddr;
        ctx->dma.asyncCtx.aes.aadClientAddr = (uintptr_t)authin;
        ctx->dma.asyncCtx.aes.aadSz         = aadAcq ? authin_len : 0;

        WH_DEBUG_CLIENT_VERBOSE(
            "AesGcm DMA req: enc=%d keysz=%u ivsz=%u insz=%u authinsz=%u "
            "tagsz=%u reqsz=%u\n",
            enc, (unsigned int)req->keySz, (unsigned int)iv_len,
            (unsigned int)len, (unsigned int)authin_len, (unsigned int)tag_len,
            (unsigned int)req_len);

        ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                    WC_ALGO_TYPE_CIPHER, req_len, dataPtr);
    }

    if (ret != WH_ERROR_OK) {
        if (inAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        if (outAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        }
        if (aadAcq) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)authin, (void**)&aadAddr, authin_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.aes, 0, sizeof(ctx->dma.asyncCtx.aes));
    }
    return ret;
}

int wh_Client_AesGcmDmaResponse(whClientContext* ctx, Aes* aes,
                                uint8_t* enc_tag, uint32_t tag_len)
{
    int                                ret;
    uint8_t*                           dataPtr;
    uint16_t                           res_len = 0;
    whMessageCrypto_AesGcmDmaResponse* res;

    (void)aes;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_CIPHER_AES_GCM, (uint8_t**)&res);
        if (ret == WH_ERROR_OK) {
            if (enc_tag != NULL && res->authTagSz > 0) {
                if (res->authTagSz > tag_len) {
                    ret = WH_ERROR_ABORTED;
                }
                else {
                    uint8_t* res_tag =
                        (uint8_t*)res +
                        sizeof(whMessageCrypto_AesGcmDmaResponse);
                    memcpy(enc_tag, res_tag, res->authTagSz);
                }
            }
            WH_DEBUG_CLIENT_VERBOSE("AesGcm DMA res: tagsz=%u\n",
                                    (unsigned int)res->authTagSz);
        }
    }

    if (ctx->dma.asyncCtx.aes.inSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.inAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.inClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.inSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.inSz = 0;
    }
    if (ctx->dma.asyncCtx.aes.outSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.outAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.outClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.outSz, WH_DMA_OPER_CLIENT_WRITE_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.outSz = 0;
    }
    if (ctx->dma.asyncCtx.aes.aadSz > 0) {
        uintptr_t addr = ctx->dma.asyncCtx.aes.aadAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.aes.aadClientAddr, (void**)&addr,
            ctx->dma.asyncCtx.aes.aadSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.aes.aadSz = 0;
    }
    return ret;
}

int wh_Client_AesGcmDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, const uint8_t* iv,
                        uint32_t iv_len, const uint8_t* authin,
                        uint32_t authin_len, const uint8_t* dec_tag,
                        uint8_t* enc_tag, uint32_t tag_len, uint8_t* out)
{
    int ret;

    ret = wh_Client_AesGcmDmaRequest(ctx, aes, enc, in, len, out, iv, iv_len,
                                     authin, authin_len, dec_tag, tag_len);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_AesGcmDmaResponse(ctx, aes, enc_tag, tag_len);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

#ifdef HAVE_ECC
int wh_Client_EccSetKeyId(ecc_key* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_EccGetKeyId(ecc_key* key, whKeyId* outId)
{
    if ((key == NULL) || (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_EccImportKey(whClientContext* ctx, ecc_key* key,
                           whKeyId* inout_keyId, whNvmFlags flags,
                           uint16_t label_len, uint8_t* label)
{
    int      ret                 = WH_ERROR_OK;
    whKeyId  key_id              = WH_KEYID_ERASED;
    byte     buffer[ECC_BUFSIZE] = {0};
    uint16_t buffer_len          = 0;

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    ret =
        wh_Crypto_EccSerializeKeyDer(key, sizeof(buffer), buffer, &buffer_len);
    WH_DEBUG_CLIENT_VERBOSE("serialize ret:%d, key:%p, max_size:%u, buffer:%p, "
           "outlen:%u\n",
           ret, key, (unsigned int)sizeof(buffer), buffer,
           buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

    WH_DEBUG_CLIENT_VERBOSE("label:%.*s ret:%d keyid:%u\n", label_len,
           label, ret, key_id);
    return ret;
}

int wh_Client_EccExportKey(whClientContext* ctx, whKeyId keyId, ecc_key* key,
                           uint16_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    /* buffer cannot be larger than MTU */
    byte     buffer[ECC_BUFSIZE] = {0};
    uint16_t buffer_len          = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret =
        wh_Client_KeyExport(ctx, keyId, label, label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Update the key structure */
        ret = wh_Crypto_EccDeserializeKeyDer(buffer, buffer_len, key);
    }

    WH_DEBUG_CLIENT_VERBOSE("keyid:%x key:%p ret:%d label:%.*s\n", keyId,
           key, ret, (int)label_len, label);
    return ret;
}

int wh_Client_EccExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                 ecc_key* key, uint16_t label_len,
                                 uint8_t* label)
{
    int      ret;
    byte     buffer[ECC_BUFSIZE] = {0};
    uint16_t buffer_len          = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_ECC, label,
                                    label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_EccDeserializeKeyDer(buffer, buffer_len, key);
    }
    return ret;
}

/* Shared async Request half for ECC keygen.  Builds and sends the keygen
 * request packet.  The caller must arrange the matching async Response (or
 * blocking poll) to consume the reply. */
static int _EccMakeKeyRequest(whClientContext* ctx, int size, int curveId,
                              whKeyId key_id, whNvmFlags flags,
                              uint16_t label_len, const uint8_t* label)
{
    whMessageCrypto_EccKeyGenRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    uint16_t                          req_len;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_EccKeyGenRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_EC_KEYGEN, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->sz      = size;
    req->curveId = curveId;
    req->flags   = flags;
    req->keyId   = key_id;
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }

    WH_DEBUG_CLIENT_VERBOSE("EccMakeKey req: size=%u curveId=%d flags=0x%x\n",
                            (unsigned)size, curveId, (unsigned)flags);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 req_len, dataPtr);
}

/* Shared async Response half for ECC keygen.  Single-shot receive: returns
 * WH_ERROR_NOTREADY if the reply has not arrived yet.  When the request was
 * EPHEMERAL (export), the server-supplied DER is deserialized into out_key;
 * otherwise the assigned keyId is written to *out_key_id (if non-NULL) and
 * also stamped into out_key->devCtx (if non-NULL). */
static int _EccMakeKeyResponse(whClientContext* ctx, whKeyId* out_key_id,
                               ecc_key* out_key)
{
    int                                ret;
    uint16_t                           group;
    uint16_t                           action;
    uint16_t                           res_len = 0;
    uint8_t*                           dataPtr = NULL;
    whMessageCrypto_EccKeyGenResponse* res     = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Get response structure pointer; validates the generic header rc */
    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_EC_KEYGEN, (uint8_t**)&res);
    /* wolfCrypt allows positive error codes on success in some scenarios */
    if (ret >= 0) {
        whKeyId      key_id = (whKeyId)(res->keyId);
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        /* Defensive bound: res->len must fit within the actual received
         * frame */
        if (res_len < hdr_sz || res->len > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }
        WH_DEBUG_CLIENT_VERBOSE("EccMakeKey res: keyid:%u len:%u\n",
                                (unsigned)key_id, (unsigned)res->len);

        if (out_key_id != NULL) {
            *out_key_id = key_id;
        }

        /* A DER blob is present for both ephemeral/export keygen and the
         * cache-and-export path. When key material was requested (out_key !=
         * NULL) but the server returned an empty body, treat it as an error so
         * a caller of ...AndExportPublic never receives an unpopulated key. */
        if (out_key != NULL) {
            if (res->len > 0) {
                uint8_t* key_der  = (uint8_t*)(res + 1);
                uint16_t der_size = (uint16_t)(res->len);
                /* Leave devCtx ERASED here: ephemeral keygen keeps it that way,
                 * and the cache-and-export wrapper overwrites it with the cached
                 * keyId after this returns. */
                wh_Client_EccSetKeyId(out_key, WH_KEYID_ERASED);
                ret =
                    wh_Crypto_EccDeserializeKeyDer(key_der, der_size, out_key);
                WH_DEBUG_VERBOSE_HEXDUMP("[client] KeyGen export:", key_der,
                                         der_size);
            }
            else {
                ret = WH_ERROR_ABORTED;
            }
        }
    }
    return ret;
}

int wh_Client_EccMakeCacheKeyRequest(whClientContext* ctx, int size,
                                     int curveId, whKeyId key_id,
                                     whNvmFlags flags, uint16_t label_len,
                                     uint8_t* label)
{
    /* The export pair owns ephemeral keygen — reject EPHEMERAL here so callers
     * don't accidentally export when they meant to cache. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }
    return _EccMakeKeyRequest(ctx, size, curveId, key_id, flags, label_len,
                              label);
}

int wh_Client_EccMakeCacheKeyResponse(whClientContext* ctx, whKeyId* out_key_id)
{
    if (out_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }
    return _EccMakeKeyResponse(ctx, out_key_id, NULL);
}

int wh_Client_EccMakeExportKeyRequest(whClientContext* ctx, int size,
                                      int curveId)
{
    return _EccMakeKeyRequest(ctx, size, curveId, WH_KEYID_ERASED,
                              WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
}

int wh_Client_EccMakeExportKeyResponse(whClientContext* ctx, ecc_key* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    return _EccMakeKeyResponse(ctx, NULL, key);
}

int wh_Client_EccMakeCacheKey(whClientContext* ctx, int size, int curveId,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              uint16_t label_len, uint8_t* label)
{
    int     ret;
    whKeyId key_id = WH_KEYID_ERASED;

    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_EccMakeCacheKeyRequest(ctx, size, curveId, *inout_key_id,
                                           flags, label_len, label);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_EccMakeCacheKeyResponse(ctx, &key_id);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret >= 0) {
            *inout_key_id = key_id;
        }
    }
    return ret;
}

int wh_Client_EccMakeCacheKeyAndExportPublic(whClientContext* ctx, int size,
                                             int curveId,
                                             whKeyId* inout_key_id,
                                             whNvmFlags flags,
                                             uint16_t label_len,
                                             const uint8_t* label,
                                             ecc_key* pub)
{
    int     ret;
    whKeyId in_keyId;
    whKeyId key_id = WH_KEYID_ERASED;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export pair, not the cache pair. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret      = _EccMakeKeyRequest(ctx, size, curveId, in_keyId, flags,
                                  label_len, label);
    if (ret == WH_ERROR_OK) {
        do {
            ret = _EccMakeKeyResponse(ctx, &key_id, pub);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret >= 0) {
            *inout_key_id = key_id;
            /* Associate the returned key with the cached keyId and stamp the
             * client's HSM devId so pub is immediately usable both as the
             * exported public key and as a handle to the cached private key,
             * without the caller re-initializing it. */
            wh_Client_EccSetKeyId(pub, key_id);
            pub->devId = WH_CLIENT_DEVID(ctx);
        }
        else if (!WH_KEYID_ISERASED(key_id)) {
            /* The server committed a key but the best-effort export returned no
             * usable public key (empty response body when it did not fit, or a
             * client-side deserialize failure). Roll back so the operation is
             * atomic and no cache slot is orphaned. key_id is only set from a
             * parsed server response, so it is non-erased only when a key was
             * actually committed - safe even when the caller supplied an
             * explicit keyId. */
            (void)wh_Client_KeyEvict(ctx, key_id);
            *inout_key_id = WH_KEYID_ERASED;
        }
    }
    return ret;
}

int wh_Client_EccMakeExportKey(whClientContext* ctx, int size, int curveId,
                               ecc_key* key)
{
    int ret;

    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_EccMakeExportKeyRequest(ctx, size, curveId);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_EccMakeExportKeyResponse(ctx, key);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

/* Build and send an ECDH shared-secret request.
 *
 * flags & WH_NVM_FLAGS_EPHEMERAL selects the export mode (secret returned to
 * the client). Otherwise the secret is cached on the server with `flags`
 * and `label`, stored at `out_key_id` (WH_KEYID_ERASED -> server allocates). */
static int _EccSharedSecretRequest(whClientContext* ctx, whKeyId prv_key_id,
                                   whKeyId pub_key_id, uint32_t options,
                                   whNvmFlags flags, whKeyId out_key_id,
                                   const uint8_t* label, uint16_t label_len)
{
    whMessageCrypto_EcdhRequest* req     = NULL;
    uint8_t*                     dataPtr = NULL;
    uint16_t                     req_len;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (WH_KEYID_ISERASED(prv_key_id) || WH_KEYID_ISERASED(pub_key_id)) {
        return WH_ERROR_BADARGS;
    }
    if ((label_len > 0) && (label == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (label_len > WH_NVM_LABEL_LEN) {
        label_len = WH_NVM_LABEL_LEN;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_EcdhRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_ECDH, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->options      = options;
    req->privateKeyId = prv_key_id;
    req->publicKeyId  = pub_key_id;
    req->flags        = flags;
    req->keyId        = out_key_id;
    if ((label != NULL) && (label_len > 0)) {
        memcpy(req->label, label, label_len);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 req_len, dataPtr);
}

/* Receive and parse an ECDH shared-secret response.
 *
 * If `out` is non-NULL the response is treated as export mode: the secret is
 * copied to `out` and `*inout_size` is updated. If `out_key_id` is non-NULL
 * the response is treated as cache mode: the assigned keyId is returned. */
static int _EccSharedSecretResponse(whClientContext* ctx, uint8_t* out,
                                    uint16_t* inout_size, whKeyId* out_key_id)
{
    int                           ret;
    uint16_t                      group;
    uint16_t                      action;
    uint16_t                      res_len = 0;
    uint8_t*                      dataPtr;
    whMessageCrypto_EcdhResponse* res = NULL;

    if ((ctx == NULL) || ((out != NULL) && (inout_size == NULL))) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDH, (uint8_t**)&res);
    if (ret >= 0) {
        uint8_t*     res_out = (uint8_t*)(res + 1);
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        /* Defensive bound: res->sz must fit within the actual received frame */
        if (res_len < hdr_sz || res->sz > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }
        if (out_key_id != NULL) {
            *out_key_id = (whKeyId)res->keyId;
        }
        if (inout_size != NULL) {
            if ((out != NULL) && (res->sz > *inout_size)) {
                /* Output buffer too small. Report required size and fail
                 * rather than silently truncating ECDH key material. */
                *inout_size = res->sz;
                return WH_ERROR_BUFFER_SIZE;
            }
            *inout_size = res->sz;
            if ((out != NULL) && (res->sz > 0)) {
                memcpy(out, res_out, res->sz);
            }
        }
    }
    return ret;
}

int wh_Client_EccSharedSecretRequest(whClientContext* ctx, whKeyId prv_key_id,
                                     whKeyId pub_key_id)
{
    return _EccSharedSecretRequest(ctx, prv_key_id, pub_key_id, 0,
                                   WH_NVM_FLAGS_EPHEMERAL, WH_KEYID_ERASED,
                                   NULL, 0);
}

int wh_Client_EccSharedSecretResponse(whClientContext* ctx, uint8_t* out,
                                      uint16_t* inout_size)
{
    return _EccSharedSecretResponse(ctx, out, inout_size, NULL);
}

int wh_Client_EccSharedSecretCacheKeyRequest(
    whClientContext* ctx, whKeyId prv_key_id, whKeyId pub_key_id,
    whKeyId out_key_id, whNvmFlags flags, const uint8_t* label,
    uint16_t label_len)
{
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }
    return _EccSharedSecretRequest(ctx, prv_key_id, pub_key_id, 0, flags,
                                   out_key_id, label, label_len);
}

int wh_Client_EccSharedSecretCacheKeyResponse(whClientContext* ctx,
                                              whKeyId*         out_key_id)
{
    if ((ctx == NULL) || (out_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return _EccSharedSecretResponse(ctx, NULL, NULL, out_key_id);
}

/* Common path for blocking ECDH shared-secret APIs.
 *
 * Handles auto-importing client-local input keys to the server cache (with
 * EVICT* options on the request so the server cleans them up), sending the
 * request, polling the response, and tearing down on error. */
static int _EccSharedSecretBlocking(whClientContext* ctx, ecc_key* priv_key,
                                    ecc_key* pub_key, whNvmFlags flags,
                                    uint8_t* out, uint16_t* inout_size,
                                    whKeyId* inout_key_id, const uint8_t* label,
                                    uint16_t label_len)
{
    int     ret        = WH_ERROR_OK;
    whKeyId prv_key_id = WH_KEYID_ERASED;
    whKeyId pub_key_id = WH_KEYID_ERASED;
    int     prv_evict  = 0;
    int     pub_evict  = 0;

    pub_key_id = WH_DEVCTX_TO_KEYID(pub_key->devCtx);
    if (WH_KEYID_ISERASED(pub_key_id)) {
        uint8_t    keyLabel[] = "TempEccDh-pub";
        whNvmFlags imp_flags  = WH_NVM_FLAGS_USAGE_DERIVE;

        ret = wh_Client_EccImportKey(ctx, pub_key, &pub_key_id, imp_flags,
                                     sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            pub_evict = 1;
        }
    }

    prv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(prv_key_id)) {
        uint8_t    keyLabel[] = "TempEccDh-prv";
        whNvmFlags imp_flags  = WH_NVM_FLAGS_USAGE_DERIVE;

        ret = wh_Client_EccImportKey(ctx, priv_key, &prv_key_id, imp_flags,
                                     sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint32_t options = 0;
        whKeyId  out_key_id =
            (inout_key_id != NULL) ? *inout_key_id : WH_KEYID_ERASED;

        if (pub_evict != 0) {
            options |= WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPUB;
        }
        if (prv_evict != 0) {
            options |= WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPRV;
        }

        ret = _EccSharedSecretRequest(ctx, prv_key_id, pub_key_id, options,
                                      flags, out_key_id, label, label_len);
        if (ret == WH_ERROR_OK) {
            /* Server will evict the temp-imported input keys */
            pub_evict = prv_evict = 0;

            do {
                ret = _EccSharedSecretResponse(ctx, out, inout_size,
                                               inout_key_id);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    /* Evict the keys manually on error */
    if (pub_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if (prv_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, prv_key_id);
    }
    return ret;
}

int wh_Client_EccSharedSecret(whClientContext* ctx, ecc_key* priv_key,
                              ecc_key* pub_key, uint8_t* out,
                              uint16_t* inout_size)
{
    if ((ctx == NULL) || (pub_key == NULL) || (priv_key == NULL) ||
        ((out != NULL) && (inout_size == NULL))) {
        return WH_ERROR_BADARGS;
    }

    return _EccSharedSecretBlocking(ctx, priv_key, pub_key,
                                    WH_NVM_FLAGS_EPHEMERAL, out, inout_size,
                                    NULL, NULL, 0);
}

int wh_Client_EccSharedSecretCacheKey(whClientContext* ctx, ecc_key* priv_key,
                                      ecc_key* pub_key, whKeyId* inout_key_id,
                                      whNvmFlags flags, const uint8_t* label,
                                      uint16_t label_len)
{
    if ((ctx == NULL) || (pub_key == NULL) || (priv_key == NULL) ||
        (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    return _EccSharedSecretBlocking(ctx, priv_key, pub_key, flags, NULL, NULL,
                                    inout_key_id, label, label_len);
}


int wh_Client_EccSignRequest(whClientContext* ctx, whKeyId keyId,
                             const uint8_t* hash, uint16_t hash_len)
{
    whMessageCrypto_EccSignRequest* req     = NULL;
    uint8_t*                        dataPtr = NULL;
    size_t                          req_len;

    if ((ctx == NULL) || ((hash == NULL) && (hash_len > 0))) {
        return WH_ERROR_BADARGS;
    }
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) + hash_len;
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_EccSignRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_ECDSA_SIGN, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->options = 0;
    req->keyId   = keyId;
    req->sz      = hash_len;
    if ((hash != NULL) && (hash_len > 0)) {
        memcpy((uint8_t*)(req + 1), hash, hash_len);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 (uint16_t)req_len, dataPtr);
}

int wh_Client_EccSignResponse(whClientContext* ctx, uint8_t* sig,
                              uint16_t* inout_sig_len)
{
    int                              ret;
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         res_len = 0;
    uint8_t*                         dataPtr;
    whMessageCrypto_EccSignResponse* res = NULL;

    if ((ctx == NULL) || ((sig != NULL) && (inout_sig_len == NULL))) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDSA_SIGN, (uint8_t**)&res);
    if (ret >= 0) {
        uint8_t*     res_sig = (uint8_t*)(res + 1);
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        /* Defensive bound: res->sz must fit within the actual received frame */
        if (res_len < hdr_sz || res->sz > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }
        if (inout_sig_len != NULL) {
            if ((sig != NULL) && (res->sz > *inout_sig_len)) {
                /* Output buffer too small. Report required size and fail
                 * rather than silently truncating signature bytes. */
                *inout_sig_len = res->sz;
                return WH_ERROR_BUFFER_SIZE;
            }
            *inout_sig_len = res->sz;
            if ((sig != NULL) && (res->sz > 0)) {
                memcpy(sig, res_sig, res->sz);
            }
        }
    }
    return ret;
}

int wh_Client_EccSign(whClientContext* ctx, ecc_key* key, const uint8_t* hash,
                      uint16_t hash_len, uint8_t* sig, uint16_t* inout_sig_len)
{
    int                             ret     = 0;
    whMessageCrypto_EccSignRequest* req     = NULL;
    uint8_t*                        dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    WH_DEBUG_CLIENT_VERBOSE("ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
           ctx, key, hash, (unsigned)hash_len, sig, inout_sig_len);

    if ((ctx == NULL) || (key == NULL) || ((hash == NULL) && (hash_len > 0)) ||
        ((sig != NULL) && (inout_sig_len == NULL))) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    WH_DEBUG_CLIENT_VERBOSE("keyid:%x, in_len:%u, inout_len:%p\n", key_id,
           hash_len, inout_sig_len);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempEccSign";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_SIGN;

        ret = wh_Client_EccImportKey(ctx, key, &key_id, flags, sizeof(keyLabel),
                                     keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;

        uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(*req) + hash_len;
        uint32_t options = 0;

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_EccSignRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ECDSA_SIGN, ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint8_t* req_hash = (uint8_t*)(req + 1);

            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_ECCSIGN_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->keyId   = key_id;
            req->sz      = hash_len;
            if ((hash != NULL) && (hash_len > 0)) {
                memcpy(req_hash, hash, hash_len);
            }
            /* Dump the request and hash for debugging */
            WH_DEBUG_CLIENT_VERBOSE("EccSign: key_id=%x, hash_len=%u, options=%u\n",
                   key_id, (unsigned)hash_len, (unsigned)options);
            WH_DEBUG_VERBOSE_HEXDUMP("[client] EccSign req:", (uint8_t*)req,
                             sizeof(*req));
            if ((hash != NULL) && (hash_len > 0)) {
                WH_DEBUG_VERBOSE_HEXDUMP("[client] EccSign hash:", (uint8_t*)hash,
                                 hash_len);
            }

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Poll shared Response */
                do {
                    ret = wh_Client_EccSignResponse(ctx, sig, inout_sig_len);
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
        else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
    WH_DEBUG_CLIENT_VERBOSE("ret:%d\n", ret);
    return ret;
}

int wh_Client_EccVerifyRequest(whClientContext* ctx, whKeyId keyId,
                               const uint8_t* sig, uint16_t sig_len,
                               const uint8_t* hash, uint16_t hash_len)
{
    whMessageCrypto_EccVerifyRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    size_t                            req_len;

    if ((ctx == NULL) || ((sig == NULL) && (sig_len > 0)) ||
        ((hash == NULL) && (hash_len > 0))) {
        return WH_ERROR_BADARGS;
    }
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
              sig_len + hash_len;
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_EccVerifyRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_ECDSA_VERIFY, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->options = 0;
    req->keyId   = keyId;
    req->sigSz   = sig_len;
    req->hashSz  = hash_len;
    if ((sig != NULL) && (sig_len > 0)) {
        memcpy((uint8_t*)(req + 1), sig, sig_len);
    }
    if ((hash != NULL) && (hash_len > 0)) {
        memcpy((uint8_t*)(req + 1) + sig_len, hash, hash_len);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 (uint16_t)req_len, dataPtr);
}

int wh_Client_EccVerifyResponse(whClientContext* ctx, ecc_key* opt_key,
                                int* out_res)
{
    int                                ret;
    uint16_t                           group;
    uint16_t                           action;
    uint16_t                           res_len = 0;
    uint8_t*                           dataPtr;
    whMessageCrypto_EccVerifyResponse* res = NULL;

    if ((ctx == NULL) || (out_res == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDSA_VERIFY, (uint8_t**)&res);
    if (ret >= 0) {
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        /* Defensive bound: res->pubSz must fit within the actual received
         * frame */
        if (res_len < hdr_sz || res->pubSz > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }
        *out_res = res->res;
        if ((opt_key != NULL) && (res->pubSz > 0)) {
            ret = wh_Crypto_EccUpdatePrivateOnlyKeyDer(opt_key, res->pubSz,
                                                       (uint8_t*)(res + 1));
        }
    }
    return ret;
}

int wh_Client_EccVerify(whClientContext* ctx, ecc_key* key, const uint8_t* sig,
                        uint16_t sig_len, const uint8_t* hash,
                        uint16_t hash_len, int* out_res)
{
    int                               ret     = 0;
    whMessageCrypto_EccVerifyRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict          = 0;
    int     export_pub_key = 0;


    WH_DEBUG_CLIENT_VERBOSE("ctx:%p key:%p, sig:%p sig_len:%u, hash:%p hash_len:%u "
           "out_res:%p\n",
           ctx, key, sig, sig_len, hash, hash_len, out_res);

    /* Validate response-side args upfront so we never send a request that the
     * matching *Response would then reject without consuming the reply. */
    if ((ctx == NULL) || (key == NULL) || ((sig == NULL) && (sig_len > 0)) ||
        ((hash == NULL) && (hash_len > 0)) || (out_res == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (key->type == ECC_PRIVATEKEY_ONLY) {
        export_pub_key = 1;
    }
    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempEccVerify";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_VERIFY;

        ret = wh_Client_EccImportKey(ctx, key, &key_id, flags, sizeof(keyLabel),
                                     keyLabel);
        if (ret == 0) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;

        uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(whMessageCrypto_EccVerifyRequest) + sig_len +
                           hash_len;

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_EccVerifyRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ECDSA_VERIFY, ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint8_t* req_sig  = (uint8_t*)(req + 1);
            uint8_t* req_hash = req_sig + sig_len;

            /* Set request packet members */
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_ECCVERIFY_OPTIONS_EVICT;
            }
            if (export_pub_key != 0) {
                options |= WH_MESSAGE_CRYPTO_ECCVERIFY_OPTIONS_EXPORTPUB;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->keyId   = key_id;
            req->sigSz   = sig_len;
            if ((sig != NULL) && (sig_len > 0)) {
                memcpy(req_sig, sig, sig_len);
            }
            req->hashSz = hash_len;
            if ((hash != NULL) && (hash_len > 0)) {
                memcpy(req_hash, hash, hash_len);
            }

            WH_DEBUG_CLIENT_VERBOSE("EccVerify req: key_id=%x, sig_len=%u, "
                   "hash_len=%u, options=%u\n",
                   key_id, (unsigned int)sig_len, (unsigned int)hash_len,
                   (unsigned int)options);
            WH_DEBUG_VERBOSE_HEXDUMP("[client] EccVerify req:", (uint8_t*)req, req_len);
            if ((sig != NULL) && (sig_len > 0)) {
                WH_DEBUG_VERBOSE_HEXDUMP("[client] EccVerify sig:", sig, sig_len);
            }
            if ((hash != NULL) && (hash_len > 0)) {
                WH_DEBUG_VERBOSE_HEXDUMP("[client] EccVerify hash:", hash, hash_len);
            }

            /* write request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);

            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Poll shared Response. When EXPORTPUB was requested, the
                 * Response updates the caller's key with the server-derived
                 * public half. */
                do {
                    ret = wh_Client_EccVerifyResponse(
                        ctx, (export_pub_key != 0) ? key : NULL, out_res);
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
        else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
    WH_DEBUG_CLIENT_VERBOSE("ret:%d\n", ret);
    return ret;
}

#if 0
int wh_Client_EccCheckPubKey(whClientContext* ctx, ecc_key* key,
        const uint8_t* pub_key, uint16_t pub_key_len)
{
/* TODO: Check if keyid is set on incoming key.
 *      if not, import private key to server
 *      send request with pub key der
 *      server creates new key with private and public.  check
 *      evict temp key
 */
    int ret;

    if (    (ctx == NULL) ||
            (key == NULL) ||
            (pub_key == NULL) ||
            (pub_key_len == 0) ) {
        return WH_ERROR_BADARGS;
    }
    int curve_id = wc_ecc_get_curve_id(key->idx);
    whKeyId key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Request packet */
    wh_Packet_pk_ecc_check_req* req = &packet->pkEccCheckReq;
    uint8_t* req_pub_key = (uint8_t*)(req + 1);

    req->type = WC_PK_TYPE_EC_CHECK_PRIV_KEY;
    req->keyId = key_id;
    req->curveId = curve_id;

    /* Response packet */
    wh_Packet_pk_ecc_check_res* res = &packet->pkEccCheckRes;


    /* write request */
    ret = wh_Client_SendRequest(ctx, group,
        WC_ALGO_TYPE_PK,
        WH_PACKET_STUB_SIZE + sizeof(packet->pkEccCheckReq),
        (uint8_t*)packet);
    /* read response */
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                WOLFHSM_CFG_COMM_DATA_LEN, (uint8_t*)packet);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        if (packet->rc != 0)
            ret = packet->rc;
    }
}
#endif /* 0 */

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
int wh_Client_Curve25519SetKeyId(curve25519_key* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    /* TODO: Eliminate this and handle remote keys cleaner */
    key->pubSet  = 1;
    key->privSet = 1;
    return WH_ERROR_OK;
}

int wh_Client_Curve25519GetKeyId(curve25519_key* key, whKeyId* outId)
{
    if ((key == NULL) || (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_Curve25519ImportKey(whClientContext* ctx, curve25519_key* key,
                                  whKeyId* inout_keyId, whNvmFlags flags,
                                  uint16_t label_len, uint8_t* label)

{
    int      ret                               = 0;
    whKeyId  key_id                            = WH_KEYID_ERASED;
    byte     buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t buffer_len                        = 0;

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    buffer_len = sizeof(buffer);
    ret        = wh_Crypto_Curve25519SerializeKey(key, buffer, &buffer_len);
    if (ret == 0) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if (inout_keyId != NULL) {
            *inout_keyId = key_id;
        }
        WH_DEBUG_CLIENT_VERBOSE("importKey: cached keyid=%u\n", key_id);
        WH_DEBUG_VERBOSE_HEXDUMP("[client] importKey: key=", buffer, buffer_len);
    }
    return ret;
}

int wh_Client_Curve25519ExportKey(whClientContext* ctx, whKeyId keyId,
                                  curve25519_key* key, uint16_t label_len,
                                  uint8_t* label)
{
    int ret = 0;
    /* buffer cannot be larger than MTU */
    byte     buffer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t buffer_len                        = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret =
        wh_Client_KeyExport(ctx, keyId, label, label_len, buffer, &buffer_len);
    if (ret == 0) {
        /* Update the key structure */
        ret = wh_Crypto_Curve25519DeserializeKey(buffer, buffer_len, key);
    }

    return ret;
}

int wh_Client_Curve25519ExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                        curve25519_key* key,
                                        uint16_t label_len, uint8_t* label)
{
    int      ret;
    byte     buffer[CURVE25519_MAX_KEY_TO_DER_SZ] = {0};
    uint16_t buffer_len                           = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_CURVE25519, label,
                                    label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_Curve25519DeserializeKey(buffer, buffer_len, key);
    }
    return ret;
}

static int _Curve25519MakeKey(whClientContext* ctx, uint16_t size,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              const uint8_t* label, uint16_t label_len,
                              curve25519_key* key)
{
    int                                       ret    = 0;
    uint16_t                                  group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                                  action = WC_ALGO_TYPE_PK;
    uint16_t                                  data_len = 0;
    whMessageCrypto_Curve25519KeyGenRequest*  req      = NULL;
    whMessageCrypto_Curve25519KeyGenResponse* res      = NULL;
    uint8_t*                                  dataPtr  = NULL;
    whKeyId                                   key_id   = WH_KEYID_ERASED;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }
    memset((uint8_t*)dataPtr, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Curve25519KeyGenRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_CURVE25519_KEYGEN, ctx->cryptoAffinity);

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Set up the request packet */
    req->sz    = size;
    req->flags = flags;
    req->keyId = key_id;
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }
    data_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    ret =
        wh_Client_SendRequest(ctx, group, action, data_len, (uint8_t*)dataPtr);
    WH_DEBUG_CLIENT_VERBOSE("Curve25519 KeyGen Req sent:size:%u, ret:%d\n",
           (unsigned int)req->sz, ret);
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &data_len,
                                         WOLFHSM_CFG_COMM_DATA_LEN,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }


    if (ret == 0) {
        /* Get response structure pointer, validates generic header */
        ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_CURVE25519_KEYGEN,
                                 (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
            WH_DEBUG_CLIENT_VERBOSE("Curve25519 KeyGen Res recv:keyid:%u, len:%u, "
                   "ret:%d\n",
                   (unsigned int)res->keyId, (unsigned int)res->len, ret);
            /* Key is cached on server or is ephemeral */
            key_id = (whKeyId)(res->keyId);

            /* Update output variable if requested */
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }

            /* Update the context if provided */
            if (key != NULL) {
                uint16_t     der_size = (uint16_t)(res->len);
                uint8_t*     key_der  = (uint8_t*)(res + 1);
                const size_t hdr_sz =
                    sizeof(whMessageCrypto_GenericResponseHeader) +
                    sizeof(*res);
                /* Set the key_id.  ERASED for EPHEMERAL, cached id otherwise. */
                wh_Client_Curve25519SetKeyId(key, key_id);

                /* Response carries the exported key (EPHEMERAL) or the public
                 * key (cached keygen). An empty body means the caller requested
                 * key material the server did not return; also reject a length
                 * that does not fit the received frame before deserializing. */
                if (der_size == 0) {
                    ret = WH_ERROR_ABORTED;
                }
                else if ((data_len < hdr_sz) ||
                         (res->len > (data_len - hdr_sz))) {
                    ret = WH_ERROR_ABORTED;
                }
                else {
                    ret = wh_Crypto_Curve25519DeserializeKey(key_der, der_size,
                                                             key);
                    WH_DEBUG_VERBOSE_HEXDUMP("[client] KeyGen export:", key_der,
                                     der_size);
                }
            }
        }
    }
    return ret;
}

int wh_Client_Curve25519MakeCacheKey(whClientContext* ctx, uint16_t size,
                                     whKeyId* inout_key_id, whNvmFlags flags,
                                     const uint8_t* label, uint16_t label_len)
{
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519MakeKey(ctx, size, inout_key_id, flags, label, label_len,
                              NULL);
}

int wh_Client_Curve25519MakeCacheKeyAndExportPublic(
    whClientContext* ctx, uint16_t size, whKeyId* inout_key_id,
    whNvmFlags flags, const uint8_t* label, uint16_t label_len,
    curve25519_key* pub)
{
    int     ret;
    whKeyId in_keyId;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export path, not the cache path. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret = _Curve25519MakeKey(ctx, size, inout_key_id, flags, label, label_len,
                             pub);
    if (ret >= 0) {
        /* Stamp the cached keyId and the client's HSM devId so pub is
         * immediately usable as a handle to the cached private key. The keyId
         * is set here (not only inside _Curve25519MakeKey) because a public-key
         * deserialize that retries parameter sets can re-init pub and clear
         * it. */
        wh_Client_Curve25519SetKeyId(pub, *inout_key_id);
        pub->devId = WH_CLIENT_DEVID(ctx);
    }
    else if (!WH_KEYID_ISERASED(*inout_key_id) &&
             (WH_KEYID_ISERASED(in_keyId) || (ret == WH_ERROR_ABORTED))) {
        /* The server committed a key but the best-effort export returned no
         * public key (empty response body when it did not fit). Roll back so the
         * operation is atomic and no cache slot is orphaned. A non-DMA keygen
         * only yields WH_ERROR_ABORTED after the server has committed and
         * returned the keyId, so evicting is safe even when the caller supplied
         * an explicit keyId. */
        (void)wh_Client_KeyEvict(ctx, *inout_key_id);
        *inout_key_id = WH_KEYID_ERASED;
    }
    return ret;
}

int wh_Client_Curve25519MakeExportKey(whClientContext* ctx, uint16_t size,
                                      curve25519_key* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519MakeKey(ctx, size, NULL, WH_NVM_FLAGS_EPHEMERAL, NULL, 0,
                              key);
}

/* Build and send a Curve25519 shared-secret request. See
 * _EccSharedSecretRequest for flags/keyId/label semantics — identical contract.
 */
static int
_Curve25519SharedSecretRequest(whClientContext* ctx, whKeyId prv_key_id,
                               whKeyId pub_key_id, int endian, uint32_t options,
                               whNvmFlags flags, whKeyId out_key_id,
                               const uint8_t* label, uint16_t label_len)
{
    whMessageCrypto_Curve25519Request* req     = NULL;
    uint8_t*                           dataPtr = NULL;
    uint16_t                           req_len;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (WH_KEYID_ISERASED(prv_key_id) || WH_KEYID_ISERASED(pub_key_id)) {
        return WH_ERROR_BADARGS;
    }
    if ((label_len > 0) && (label == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (label_len > WH_NVM_LABEL_LEN) {
        label_len = WH_NVM_LABEL_LEN;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Curve25519Request*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_CURVE25519, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->options      = options;
    req->privateKeyId = prv_key_id;
    req->publicKeyId  = pub_key_id;
    req->endian       = endian;
    req->flags        = flags;
    req->keyId        = out_key_id;
    if ((label != NULL) && (label_len > 0)) {
        memcpy(req->label, label, label_len);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 req_len, dataPtr);
}

/* Receive and parse a Curve25519 shared-secret response. See
 * _EccSharedSecretResponse for out/out_key_id semantics. */
static int _Curve25519SharedSecretResponse(whClientContext* ctx, uint8_t* out,
                                           uint16_t* inout_size,
                                           whKeyId*  out_key_id)
{
    int                                 ret;
    uint16_t                            group;
    uint16_t                            action;
    uint16_t                            res_len = 0;
    uint8_t*                            dataPtr;
    whMessageCrypto_Curve25519Response* res = NULL;

    if ((ctx == NULL) || ((out != NULL) && (inout_size == NULL))) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_CURVE25519, (uint8_t**)&res);
    if (ret >= 0) {
        uint8_t*     res_out = (uint8_t*)(res + 1);
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        if (res_len < hdr_sz || res->sz > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }
        if (out_key_id != NULL) {
            *out_key_id = (whKeyId)res->keyId;
        }
        if (inout_size != NULL) {
            if ((out != NULL) && (res->sz > *inout_size)) {
                *inout_size = res->sz;
                return WH_ERROR_BUFFER_SIZE;
            }
            *inout_size = res->sz;
            if ((out != NULL) && (res->sz > 0)) {
                memcpy(out, res_out, res->sz);
                WH_DEBUG_VERBOSE_HEXDUMP("[client] X25519:", res_out, res->sz);
            }
        }
    }
    return ret;
}

int wh_Client_Curve25519SharedSecretRequest(whClientContext* ctx,
                                            whKeyId          prv_key_id,
                                            whKeyId pub_key_id, int endian)
{
    return _Curve25519SharedSecretRequest(ctx, prv_key_id, pub_key_id, endian,
                                          0, WH_NVM_FLAGS_EPHEMERAL,
                                          WH_KEYID_ERASED, NULL, 0);
}

int wh_Client_Curve25519SharedSecretResponse(whClientContext* ctx, uint8_t* out,
                                             uint16_t* out_size)
{
    return _Curve25519SharedSecretResponse(ctx, out, out_size, NULL);
}

int wh_Client_Curve25519SharedSecretCacheKeyRequest(
    whClientContext* ctx, whKeyId prv_key_id, whKeyId pub_key_id, int endian,
    whKeyId out_key_id, whNvmFlags flags, const uint8_t* label,
    uint16_t label_len)
{
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }
    return _Curve25519SharedSecretRequest(ctx, prv_key_id, pub_key_id, endian,
                                          0, flags, out_key_id, label,
                                          label_len);
}

int wh_Client_Curve25519SharedSecretCacheKeyResponse(whClientContext* ctx,
                                                     whKeyId* out_key_id)
{
    if ((ctx == NULL) || (out_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return _Curve25519SharedSecretResponse(ctx, NULL, NULL, out_key_id);
}

static int _Curve25519SharedSecretBlocking(
    whClientContext* ctx, curve25519_key* priv_key, curve25519_key* pub_key,
    int endian, whNvmFlags flags, uint8_t* out, uint16_t* out_size,
    whKeyId* inout_key_id, const uint8_t* label, uint16_t label_len)
{
    int     ret        = WH_ERROR_OK;
    whKeyId prv_key_id = WH_KEYID_ERASED;
    whKeyId pub_key_id = WH_KEYID_ERASED;
    int     prv_evict  = 0;
    int     pub_evict  = 0;

    pub_key_id = WH_DEVCTX_TO_KEYID(pub_key->devCtx);
    if (WH_KEYID_ISERASED(pub_key_id)) {
        uint8_t    keyLabel[] = "TempX25519-pub";
        whNvmFlags imp_flags  = WH_NVM_FLAGS_USAGE_DERIVE;

        ret = wh_Client_Curve25519ImportKey(
            ctx, pub_key, &pub_key_id, imp_flags, sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            pub_evict = 1;
        }
    }

    prv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(prv_key_id)) {
        uint8_t    keyLabel[] = "TempX25519-prv";
        whNvmFlags imp_flags  = WH_NVM_FLAGS_USAGE_DERIVE;

        ret = wh_Client_Curve25519ImportKey(
            ctx, priv_key, &prv_key_id, imp_flags, sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint32_t options = 0;
        whKeyId  out_key_id =
            (inout_key_id != NULL) ? *inout_key_id : WH_KEYID_ERASED;

        if (pub_evict != 0) {
            options |= WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPUB;
        }
        if (prv_evict != 0) {
            options |= WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPRV;
        }

        ret = _Curve25519SharedSecretRequest(ctx, prv_key_id, pub_key_id,
                                             endian, options, flags, out_key_id,
                                             label, label_len);
        if (ret == WH_ERROR_OK) {
            pub_evict = prv_evict = 0;

            do {
                ret = _Curve25519SharedSecretResponse(ctx, out, out_size,
                                                      inout_key_id);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    if (pub_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if (prv_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, prv_key_id);
    }
    return ret;
}

int wh_Client_Curve25519SharedSecret(whClientContext* ctx,
                                     curve25519_key*  priv_key,
                                     curve25519_key* pub_key, int endian,
                                     uint8_t* out, uint16_t* out_size)
{
    if ((ctx == NULL) || (pub_key == NULL) || (priv_key == NULL) ||
        ((out != NULL) && (out_size == NULL))) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519SharedSecretBlocking(ctx, priv_key, pub_key, endian,
                                           WH_NVM_FLAGS_EPHEMERAL, out,
                                           out_size, NULL, NULL, 0);
}

int wh_Client_Curve25519SharedSecretCacheKey(
    whClientContext* ctx, curve25519_key* priv_key, curve25519_key* pub_key,
    int endian, whKeyId* inout_key_id, whNvmFlags flags, const uint8_t* label,
    uint16_t label_len)
{
    if ((ctx == NULL) || (pub_key == NULL) || (priv_key == NULL) ||
        (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519SharedSecretBlocking(ctx, priv_key, pub_key, endian,
                                           flags, NULL, NULL, inout_key_id,
                                           label, label_len);
}
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
int wh_Client_Ed25519SetKeyId(ed25519_key* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_Ed25519GetKeyId(ed25519_key* key, whKeyId* outId)
{
    if ((key == NULL) || (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_Ed25519ImportKey(whClientContext* ctx, ed25519_key* key,
                               whKeyId* inout_keyId, whNvmFlags flags,
                               uint16_t label_len, uint8_t* label)
{
    int      ret         = WH_ERROR_OK;
    whKeyId  key_id      = WH_KEYID_ERASED;
    uint8_t  buffer[128] = {0};
    uint16_t buffer_len  = sizeof(buffer);

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    ret =
        wh_Crypto_Ed25519SerializeKeyDer(key, buffer_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

    return ret;
}

int wh_Client_Ed25519ExportKey(whClientContext* ctx, whKeyId keyId,
                               ed25519_key* key, uint16_t label_len,
                               uint8_t* label)
{
    int      ret         = WH_ERROR_OK;
    uint8_t  buffer[128] = {0};
    uint16_t buffer_len  = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret =
        wh_Client_KeyExport(ctx, keyId, label, label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_Ed25519DeserializeKeyDer(buffer, buffer_len, key);
        if (ret == 0) {
            wh_Client_Ed25519SetKeyId(key, keyId);
        }
    }

    return ret;
}

int wh_Client_Ed25519ExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                     ed25519_key* key, uint16_t label_len,
                                     uint8_t* label)
{
    int      ret;
    uint8_t  buffer[MAX_PUBLIC_KEY_SZ] = {0};
    uint16_t buffer_len  = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_ED25519, label,
                                    label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_Ed25519DeserializeKeyDer(buffer, buffer_len, key);
    }
    return ret;
}

static int _Ed25519MakeKey(whClientContext* ctx, whKeyId* inout_key_id,
                           whNvmFlags flags, uint16_t label_len,
                           const uint8_t* label, ed25519_key* key)
{
    int                                    ret     = WH_ERROR_OK;
    whKeyId                                key_id  = WH_KEYID_ERASED;
    uint8_t*                               dataPtr = NULL;
    whMessageCrypto_Ed25519KeyGenRequest*  req     = NULL;
    whMessageCrypto_Ed25519KeyGenResponse* res     = NULL;

    if (ctx == NULL || ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Ed25519KeyGenRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_ED25519_KEYGEN, ctx->cryptoAffinity);

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    memset(req, 0, sizeof(*req));
    req->flags  = flags;
    req->keyId  = key_id;
    req->access = WH_NVM_ACCESS_ANY;
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }

    ret = wh_Client_SendRequest(ctx, group, action, req_len, (uint8_t*)dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    uint16_t res_len = 0;
    do {
        ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                     WOLFHSM_CFG_COMM_DATA_LEN,
                                     (uint8_t*)dataPtr);
    } while (ret == WH_ERROR_NOTREADY);

    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (group != WH_MESSAGE_GROUP_CRYPTO || action != WC_ALGO_TYPE_PK) {
        return WH_ERROR_ABORTED;
    }

    ret =
        _getCryptoResponse(dataPtr, WC_PK_TYPE_ED25519_KEYGEN, (uint8_t**)&res);
    if (ret >= 0) {
        key_id = (whKeyId)res->keyId;
        if (inout_key_id != NULL) {
            *inout_key_id = key_id;
        }
        if (key != NULL) {
            wh_Client_Ed25519SetKeyId(key, key_id);
            /* Response carries the exported key (EPHEMERAL) or the public key
             * (cached keygen). An empty body means the caller requested key
             * material the server did not return. */
            if (res->outSz > 0) {
                uint8_t* out   = (uint8_t*)(res + 1);
                uint16_t outSz = (uint16_t)res->outSz;
                if (outSz + sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res) >
                    WOLFHSM_CFG_COMM_DATA_LEN) {
                    return WH_ERROR_ABORTED;
                }
                ret = wh_Crypto_Ed25519DeserializeKeyDer(out, outSz, key);
            }
            else {
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    return ret;
}

int wh_Client_Ed25519MakeExportKey(whClientContext* ctx, ed25519_key* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Ed25519MakeKey(ctx, NULL, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, key);
}

int wh_Client_Ed25519MakeCacheKey(whClientContext* ctx, whKeyId* inout_key_id,
                                  whNvmFlags flags, uint16_t label_len,
                                  uint8_t* label)
{
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Ed25519MakeKey(ctx, inout_key_id, flags, label_len, label, NULL);
}

int wh_Client_Ed25519MakeCacheKeyAndExportPublic(whClientContext* ctx,
                                                 whKeyId* inout_key_id,
                                                 whNvmFlags flags,
                                                 uint16_t label_len,
                                                 const uint8_t* label,
                                                 ed25519_key* pub)
{
    int     ret;
    whKeyId in_keyId;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export path, not the cache path. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret = _Ed25519MakeKey(ctx, inout_key_id, flags, label_len, label, pub);
    if (ret >= 0) {
        /* Stamp the cached keyId and the client's HSM devId so pub is
         * immediately usable as a handle to the cached private key. The keyId
         * is set here (not only inside _Ed25519MakeKey) because a public-key
         * deserialize that retries parameter sets can re-init pub and clear
         * it. */
        wh_Client_Ed25519SetKeyId(pub, *inout_key_id);
        pub->devId = WH_CLIENT_DEVID(ctx);
    }
    else if (!WH_KEYID_ISERASED(*inout_key_id) &&
             (WH_KEYID_ISERASED(in_keyId) || (ret == WH_ERROR_ABORTED))) {
        /* The server committed a key but the best-effort export returned no
         * public key (empty response body when it did not fit). Roll back so the
         * operation is atomic and no cache slot is orphaned. A non-DMA keygen
         * only yields WH_ERROR_ABORTED after the server has committed and
         * returned the keyId, so evicting is safe even when the caller supplied
         * an explicit keyId. */
        (void)wh_Client_KeyEvict(ctx, *inout_key_id);
        *inout_key_id = WH_KEYID_ERASED;
    }
    return ret;
}

int wh_Client_Ed25519Sign(whClientContext* ctx, ed25519_key* key,
                          const uint8_t* msg, uint32_t msgLen, uint8_t type,
                          const uint8_t* context, uint32_t contextLen,
                          uint8_t* sig, uint32_t* inout_sig_len)
{
    int                                  ret     = 0;
    whMessageCrypto_Ed25519SignRequest*  req     = NULL;
    whMessageCrypto_Ed25519SignResponse* res     = NULL;
    uint8_t*                             dataPtr = NULL;

    whKeyId key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    int     evict  = 0;

    if ((ctx == NULL) || (key == NULL) || ((msg == NULL) && (msgLen > 0)) ||
        ((sig != NULL) && (inout_sig_len == NULL)) ||
        ((context == NULL) && (contextLen > 0))) {
        return WH_ERROR_BADARGS;
    }

    if ((type != (byte)Ed25519) && (type != (byte)Ed25519ctx) &&
        (type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }
    if ((type == (byte)Ed25519) && (contextLen != 0 || context != NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (contextLen > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }

    uint32_t total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                         sizeof(*req) + msgLen + contextLen;
    if (total_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }
    uint16_t req_len = (uint16_t)total_len;

    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempEd25519Sign";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_SIGN;

        ret = wh_Client_Ed25519ImportKey(ctx, key, &key_id, flags,
                                         sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;

        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_Ed25519SignRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ED25519_SIGN, ctx->cryptoAffinity);

        uint8_t* req_msg = (uint8_t*)(req + 1);
        uint8_t* req_ctx = req_msg + msgLen;

        if (evict != 0) {
            options |= WH_MESSAGE_CRYPTO_ED25519_SIGN_OPTIONS_EVICT;
        }

        memset(req, 0, sizeof(*req));
        req->options = options;
        req->keyId   = key_id;
        req->msgSz   = msgLen;
        req->type    = type;
        req->ctxSz   = contextLen;
        if ((msg != NULL) && (msgLen > 0)) {
            memcpy(req_msg, msg, msgLen);
        }
        if ((context != NULL) && (contextLen > 0)) {
            memcpy(req_ctx, context, contextLen);
        }

        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                    (uint8_t*)dataPtr);
        if (ret == WH_ERROR_OK) {
            /* Server will evict at this point. Reset evict */
            evict = 0;

            uint16_t res_len = 0;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);

            if (group != WH_MESSAGE_GROUP_CRYPTO || action != WC_ALGO_TYPE_PK) {
                ret = WH_ERROR_ABORTED;
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ED25519_SIGN,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    const uint32_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    if (res_len < hdr_sz || res->sigSz > (res_len - hdr_sz)) {
                        ret = WH_ERROR_ABORTED;
                    }
                }
                if (ret >= 0) {
                    uint8_t* res_sig = (uint8_t*)(res + 1);
                    if (sig != NULL) {
                        if (res->sigSz > *inout_sig_len) {
                            ret = WH_ERROR_BUFFER_SIZE;
                        }
                        else {
                            memcpy(sig, res_sig, res->sigSz);
                        }
                    }
                    if (inout_sig_len != NULL) {
                        *inout_sig_len = res->sigSz;
                    }
                }
            }
        }
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    /* map ASN key decoding errors to WH_ERROR_BADARGS */
    if (ret == ASN_PARSE_E)
        ret = WH_ERROR_BADARGS;

    return ret;
}

int wh_Client_Ed25519Verify(whClientContext* ctx, ed25519_key* key,
                            const uint8_t* sig, uint32_t sigLen,
                            const uint8_t* msg, uint32_t msgLen, uint8_t type,
                            const uint8_t* context, uint32_t contextLen,
                            int* out_res)
{
    int                                    ret     = 0;
    whMessageCrypto_Ed25519VerifyRequest*  req     = NULL;
    whMessageCrypto_Ed25519VerifyResponse* res     = NULL;
    uint8_t*                               dataPtr = NULL;
    whKeyId  key_id  = WH_DEVCTX_TO_KEYID(key->devCtx);
    int      evict     = 0;
    uint32_t total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                         sizeof(*req) + sigLen + msgLen + contextLen;

    if ((ctx == NULL) || (key == NULL) || (sig == NULL) || (msg == NULL) ||
        (out_res == NULL) || ((context == NULL) && (contextLen > 0))) {
        return WH_ERROR_BADARGS;
    }

    if ((type != (byte)Ed25519) && (type != (byte)Ed25519ctx) &&
        (type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }
    if ((type == (byte)Ed25519) && (contextLen != 0 || context != NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (contextLen > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }

    if (total_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }
    uint16_t req_len = (uint16_t)total_len;

    *out_res = 0;

    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempEd25519Verify";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_VERIFY;

        ret = wh_Client_Ed25519ImportKey(ctx, key, &key_id, flags,
                                         sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;

        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_Ed25519VerifyRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ED25519_VERIFY, ctx->cryptoAffinity);

        uint8_t* req_sig = (uint8_t*)(req + 1);
        uint8_t* req_msg = req_sig + sigLen;
        uint8_t* req_ctx = req_msg + msgLen;

        if (evict != 0) {
            options |= WH_MESSAGE_CRYPTO_ED25519_VERIFY_OPTIONS_EVICT;
        }

        memset(req, 0, sizeof(*req));
        req->options = options;
        req->keyId   = key_id;
        req->sigSz   = sigLen;
        req->msgSz   = msgLen;
        req->type    = type;
        req->ctxSz   = contextLen;

        memcpy(req_sig, sig, sigLen);
        memcpy(req_msg, msg, msgLen);
        if ((context != NULL) && (contextLen > 0)) {
            memcpy(req_ctx, context, contextLen);
        }

        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                    (uint8_t*)dataPtr);
        if (ret == WH_ERROR_OK) {
            /* Server will evict at this point. Reset evict */
            evict = 0;

            uint16_t res_len = 0;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);

            if (group != WH_MESSAGE_GROUP_CRYPTO || action != WC_ALGO_TYPE_PK) {
                ret = WH_ERROR_ABORTED;
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ED25519_VERIFY,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    const uint32_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    /* Note whMessageCrypto_Ed25519VerifyResponse has no
                     * size field */
                    if (res_len < hdr_sz) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else {
                        *out_res = res->res;
                    }
                }
            }
        }
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    /* map ASN key decoding errors to WH_ERROR_BADARGS */
    if (ret == ASN_PARSE_E)
        ret = WH_ERROR_BADARGS;

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Ed25519SignDma(whClientContext* ctx, ed25519_key* key,
                             const uint8_t* msg, uint32_t msgLen, uint8_t type,
                             const uint8_t* context, uint32_t contextLen,
                             uint8_t* sig, uint32_t* inout_sig_len)
{
    int                                     ret     = 0;
    whMessageCrypto_Ed25519SignDmaRequest*  req     = NULL;
    whMessageCrypto_Ed25519SignDmaResponse* res     = NULL;
    uint8_t*                                dataPtr = NULL;
    uintptr_t                               msgAddr = 0;
    uintptr_t                               sigAddr = 0;

    whKeyId  key_id   = WH_DEVCTX_TO_KEYID(key->devCtx);
    int      evict    = 0;
    uint32_t inSigLen = (inout_sig_len != NULL) ? *inout_sig_len : 0;

    if ((ctx == NULL) || (key == NULL) || ((msg == NULL) && (msgLen > 0)) ||
        (sig == NULL) || (inout_sig_len == NULL) ||
        ((context == NULL) && (contextLen > 0))) {
        return WH_ERROR_BADARGS;
    }

    if ((type != (byte)Ed25519) && (type != (byte)Ed25519ctx) &&
        (type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }
    if ((type == (byte)Ed25519) && (contextLen != 0 || context != NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (contextLen > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }

    uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + contextLen;
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempEd25519SignDma";
        whNvmFlags flags = WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY;

        ret = wh_Client_Ed25519ImportKey(ctx, key, &key_id, flags,
                                         sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;

        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_Ed25519SignDmaRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ED25519_SIGN, ctx->cryptoAffinity);

        uint8_t* req_ctx = (uint8_t*)(req + 1);

        if (evict != 0) {
            options |= WH_MESSAGE_CRYPTO_ED25519_SIGN_OPTIONS_EVICT;
        }

        memset(req, 0, sizeof(*req));
        req->options = options;
        req->keyId   = key_id;
        req->type    = type;
        req->ctxSz   = contextLen;
        req->msg.sz  = msgLen;
        req->sig.sz  = inSigLen;
        if ((context != NULL) && (contextLen > 0)) {
            memcpy(req_ctx, context, contextLen);
        }

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, req->msg.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->msg.addr = msgAddr;
            ret           = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)sig, (void**)&sigAddr, req->sig.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        }
        if (ret == WH_ERROR_OK) {
            req->sig.addr = sigAddr;

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            evict = 0;

            uint16_t res_len = 0;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);

            if (group != WH_MESSAGE_GROUP_CRYPTO_DMA ||
                action != WC_ALGO_TYPE_PK) {
                ret = WH_ERROR_ABORTED;
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ED25519_SIGN,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    const uint32_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    /* DMA mode: signature was written to the caller's
                     * buffer; only sigSz is returned inline */
                    if (res_len < hdr_sz) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else if (inout_sig_len != NULL) {
                        *inout_sig_len = res->sigSz;
                    }
                }
            }
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, inSigLen,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgLen,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    /* map ASN key decoding errors to WH_ERROR_BADARGS */
    if (ret == ASN_PARSE_E)
        ret = WH_ERROR_BADARGS;

    return ret;
}

int wh_Client_Ed25519VerifyDma(whClientContext* ctx, ed25519_key* key,
                               const uint8_t* sig, uint32_t sigLen,
                               const uint8_t* msg, uint32_t msgLen,
                               uint8_t type, const uint8_t* context,
                               uint32_t contextLen, int* out_res)
{
    int                                       ret     = 0;
    whMessageCrypto_Ed25519VerifyDmaRequest*  req     = NULL;
    whMessageCrypto_Ed25519VerifyDmaResponse* res     = NULL;
    uint8_t*                                  dataPtr = NULL;
    uintptr_t                                 sigAddr = 0;
    uintptr_t                                 msgAddr = 0;
    uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + contextLen;
    whKeyId key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    int     evict  = 0;

    if ((ctx == NULL) || (key == NULL) || (sig == NULL) || (msg == NULL) ||
        (out_res == NULL) || ((context == NULL) && (contextLen > 0))) {
        return WH_ERROR_BADARGS;
    }

    if ((type != (byte)Ed25519) && (type != (byte)Ed25519ctx) &&
        (type != (byte)Ed25519ph)) {
        return WH_ERROR_BADARGS;
    }
    if ((type == (byte)Ed25519) && (contextLen != 0 || context != NULL)) {
        return WH_ERROR_BADARGS;
    }
    if (contextLen > WH_CRYPTO_ED25519_MAX_CTX_LEN) {
        return WH_ERROR_BADARGS;
    }

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    *out_res = 0;

    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempEd25519VerifyDma";
        whNvmFlags flags = WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY;

        ret = wh_Client_Ed25519ImportKey(ctx, key, &key_id, flags,
                                         sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;

        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_Ed25519VerifyDmaRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ED25519_VERIFY, ctx->cryptoAffinity);

        uint8_t* req_ctx = (uint8_t*)(req + 1);

        if (evict != 0) {
            options |= WH_MESSAGE_CRYPTO_ED25519_VERIFY_OPTIONS_EVICT;
        }

        memset(req, 0, sizeof(*req));
        req->options = options;
        req->keyId   = key_id;
        req->type    = type;
        req->ctxSz   = contextLen;
        req->sig.sz  = sigLen;
        req->msg.sz  = msgLen;
        if ((context != NULL) && (contextLen > 0)) {
            memcpy(req_ctx, context, contextLen);
        }

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, req->sig.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->sig.addr = sigAddr;
            ret           = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)msg, (void**)&msgAddr, req->msg.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        }
        if (ret == WH_ERROR_OK) {
            req->msg.addr = msgAddr;

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            evict = 0;

            uint16_t res_len = 0;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);

            if (group != WH_MESSAGE_GROUP_CRYPTO_DMA ||
                action != WC_ALGO_TYPE_PK) {
                ret = WH_ERROR_ABORTED;
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ED25519_VERIFY,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    const uint32_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    /* Note whMessageCrypto_Ed25519VerifyDmaResponse has no
                     * size field */
                    if (res_len < hdr_sz) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else {
                        *out_res = res->verifyResult;
                    }
                }
            }
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgLen,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigLen,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    /* map ASN key decoding errors to WH_ERROR_BADARGS */
    if (ret == ASN_PARSE_E)
        ret = WH_ERROR_BADARGS;

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_ED25519 */

#ifndef NO_RSA
int wh_Client_RsaSetKeyId(RsaKey* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_RsaGetKeyId(RsaKey* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}


int wh_Client_RsaImportKey(whClientContext* ctx, const RsaKey* key,
                           whKeyId* inout_keyId, whNvmFlags flags,
                           uint32_t label_len, uint8_t* label)
{
    int      ret                               = 0;
    whKeyId  key_id                            = WH_KEYID_ERASED;
    byte     keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t derSize                           = 0;

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }
    /* Convert RSA key to DER format */
    ret = wh_Crypto_RsaSerializeKeyDer(key, sizeof(keyDer), keyDer, &derSize);
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, keyDer, derSize,
                                 &key_id);
        if (inout_keyId != NULL) {
            *inout_keyId = key_id;
        }
    }
    return ret;
}

int wh_Client_RsaExportKey(whClientContext* ctx, whKeyId keyId, RsaKey* key,
                           uint32_t label_len, uint8_t* label)
{
    int ret = 0;
    /* DER cannot be larger than MTU */
    byte     keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
    uint16_t derSize                           = sizeof(keyDer);
    uint8_t  keyLabel[WH_NVM_LABEL_LEN]        = {0};

    if ((ctx == NULL) || (keyId == WH_KEYID_ERASED) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the key from the server */
    ret = wh_Client_KeyExport(ctx, keyId, keyLabel, sizeof(keyLabel), keyDer,
                              &derSize);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_RsaDeserializeKeyDer(derSize, keyDer, key);
        if (ret == 0) {
            /* Successful parsing of RSA key.  Update the label */
            if ((label_len > 0) && (label != NULL)) {
                if (label_len > WH_NVM_LABEL_LEN) {
                    label_len = WH_NVM_LABEL_LEN;
                }
                memcpy(label, keyLabel, label_len);
            }
        }
    }

    return ret;
}

int wh_Client_RsaExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                 RsaKey* key, uint32_t label_len,
                                 uint8_t* label)
{
    int      ret;
    byte     keyDer[MAX_PUBLIC_KEY_SZ]  = {0};
    uint16_t derSize                    = sizeof(keyDer);
    uint8_t  keyLabel[WH_NVM_LABEL_LEN] = {0};

    if ((ctx == NULL) || (keyId == WH_KEYID_ERASED) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_RSA, keyLabel,
                                    sizeof(keyLabel), keyDer, &derSize);
    if (ret == WH_ERROR_OK) {
        /* wh_Crypto_RsaDeserializeKeyDer falls back to public-key decode
         * when the blob does not parse as a private key. */
        ret = wh_Crypto_RsaDeserializeKeyDer(derSize, keyDer, key);
        if (ret == 0) {
            if ((label_len > 0) && (label != NULL)) {
                if (label_len > WH_NVM_LABEL_LEN) {
                    label_len = WH_NVM_LABEL_LEN;
                }
                memcpy(label, keyLabel, label_len);
            }
        }
    }

    return ret;
}

static int _RsaMakeKeyRequest(whClientContext* ctx, uint32_t size, uint32_t e,
                              whKeyId key_id, whNvmFlags flags,
                              uint32_t label_len, const uint8_t* label)
{
    whMessageCrypto_RsaKeyGenRequest* req     = NULL;
    uint8_t*                          dataPtr = NULL;
    uint16_t                          req_len;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_RsaKeyGenRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_RSA_KEYGEN, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->size  = size;
    req->e     = e;
    req->flags = flags;
    req->keyId = key_id;
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }

    WH_DEBUG_CLIENT_VERBOSE("RSA KeyGen Req: size:%u, e:%u\n", (unsigned)size,
                            (unsigned)e);

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 req_len, dataPtr);
}

/* Receives a keygen reply: deserializes DER into out_rsa for export,
 * or writes the assigned keyId to *out_key_id for cache. */
static int _RsaMakeKeyResponse(whClientContext* ctx, whKeyId* out_key_id,
                               RsaKey* out_rsa)
{
    int                                ret;
    uint16_t                           group;
    uint16_t                           action;
    uint16_t                           res_len = 0;
    uint8_t*                           dataPtr = NULL;
    whMessageCrypto_RsaKeyGenResponse* res     = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_RSA_KEYGEN, (uint8_t**)&res);
    /* wolfCrypt allows positive return codes on success */
    if (ret >= 0) {
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        whKeyId key_id;

        if (res_len < hdr_sz || res->len > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }

        key_id = (whKeyId)(res->keyId);
        WH_DEBUG_CLIENT_VERBOSE("RSA KeyGen Res: keyid:%x len:%u\n", key_id,
                                (unsigned)res->len);

        if (out_key_id != NULL) {
            *out_key_id = key_id;
        }

        /* Export path: server must return a DER blob. Reject empty bodies
         * and stamp ERASED rather than trust the server-reported keyId. */
        if (out_rsa != NULL) {
            if (res->len == 0) {
                return WH_ERROR_ABORTED;
            }
            uint8_t* rsa_der  = (uint8_t*)(res + 1);
            word32   der_size = (word32)(res->len);
            wh_Client_RsaSetKeyId(out_rsa, WH_KEYID_ERASED);
            ret = wh_Crypto_RsaDeserializeKeyDer(der_size, rsa_der, out_rsa);
        }
    }
    return ret;
}

int wh_Client_RsaMakeCacheKeyRequest(whClientContext* ctx, uint32_t size,
                                     uint32_t e, whKeyId key_id,
                                     whNvmFlags flags, uint32_t label_len,
                                     uint8_t* label)
{
    /* Ephemeral keygen belongs to the export pair, not the cache pair. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }
    return _RsaMakeKeyRequest(ctx, size, e, key_id, flags, label_len, label);
}

int wh_Client_RsaMakeCacheKeyResponse(whClientContext* ctx, whKeyId* out_key_id)
{
    if (out_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }
    return _RsaMakeKeyResponse(ctx, out_key_id, NULL);
}

int wh_Client_RsaMakeExportKeyRequest(whClientContext* ctx, uint32_t size,
                                      uint32_t e)
{
    return _RsaMakeKeyRequest(ctx, size, e, WH_KEYID_ERASED,
                              WH_NVM_FLAGS_EPHEMERAL, 0, NULL);
}

int wh_Client_RsaMakeExportKeyResponse(whClientContext* ctx, RsaKey* rsa)
{
    if (rsa == NULL) {
        return WH_ERROR_BADARGS;
    }
    return _RsaMakeKeyResponse(ctx, NULL, rsa);
}

int wh_Client_RsaMakeCacheKey(whClientContext* ctx, uint32_t size, uint32_t e,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              uint32_t label_len, uint8_t* label)
{
    int     ret;
    whKeyId key_id = WH_KEYID_ERASED;

    if ((ctx == NULL) || (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RsaMakeCacheKeyRequest(ctx, size, e, *inout_key_id, flags,
                                           label_len, label);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaMakeCacheKeyResponse(ctx, &key_id);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret >= 0) {
            *inout_key_id = key_id;
        }
    }
    return ret;
}

int wh_Client_RsaMakeCacheKeyAndExportPublic(whClientContext* ctx,
                                             uint32_t size, uint32_t e,
                                             whKeyId* inout_key_id,
                                             whNvmFlags flags,
                                             uint32_t label_len,
                                             const uint8_t* label,
                                             RsaKey* pub)
{
    int     ret;
    whKeyId in_keyId;
    whKeyId key_id = WH_KEYID_ERASED;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export pair, not the cache pair. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret      = _RsaMakeKeyRequest(ctx, size, e, in_keyId, flags, label_len,
                                  label);
    if (ret == WH_ERROR_OK) {
        do {
            ret = _RsaMakeKeyResponse(ctx, &key_id, pub);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret >= 0) {
            *inout_key_id = key_id;
            /* Associate the returned key with the cached keyId and stamp the
             * client's HSM devId so pub is immediately usable both as the
             * exported public key and as a handle to the cached private key,
             * without the caller re-initializing it. */
            wh_Client_RsaSetKeyId(pub, key_id);
            pub->devId = WH_CLIENT_DEVID(ctx);
        }
        else if (!WH_KEYID_ISERASED(key_id)) {
            /* The server committed a key but the best-effort export returned no
             * usable public key (empty response body when it did not fit, or a
             * client-side deserialize failure). Roll back so the operation is
             * atomic and no cache slot is orphaned. key_id is only set from a
             * parsed server response, so it is non-erased only when a key was
             * actually committed - safe even when the caller supplied an
             * explicit keyId. */
            (void)wh_Client_KeyEvict(ctx, key_id);
            *inout_key_id = WH_KEYID_ERASED;
        }
    }
    return ret;
}

int wh_Client_RsaMakeExportKey(whClientContext* ctx, uint32_t size, uint32_t e,
                               RsaKey* rsa)
{
    int ret;

    if ((ctx == NULL) || (rsa == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RsaMakeExportKeyRequest(ctx, size, e);
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RsaMakeExportKeyResponse(ctx, rsa);
        } while (ret == WH_ERROR_NOTREADY);
    }
    return ret;
}

int wh_Client_RsaFunctionRequest(whClientContext* ctx, whKeyId keyId,
                                 int rsa_type, const uint8_t* in,
                                 uint16_t in_len, uint16_t out_capacity)
{
    whMessageCrypto_RsaRequest* req     = NULL;
    uint8_t*                    dataPtr = NULL;
    size_t                      total_len;
    uint16_t                    req_len;

    if ((ctx == NULL) || ((in == NULL) && (in_len > 0))) {
        return WH_ERROR_BADARGS;
    }
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    total_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) + in_len;
    if (total_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }
    req_len = (uint16_t)total_len;

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_RsaRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_RSA, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->opType  = rsa_type;
    req->options = 0;
    req->keyId   = keyId;
    req->inLen   = in_len;
    req->outLen  = out_capacity;
    if ((in != NULL) && (in_len > 0)) {
        memcpy((uint8_t*)(req + 1), in, in_len);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 req_len, dataPtr);
}

int wh_Client_RsaFunctionResponse(whClientContext* ctx, uint8_t* out,
                                  uint16_t* inout_out_len)
{
    int                          ret;
    uint16_t                     group;
    uint16_t                     action;
    uint16_t                     res_len = 0;
    uint8_t*                     dataPtr;
    whMessageCrypto_RsaResponse* res = NULL;

    if ((ctx == NULL) || ((out != NULL) && (inout_out_len == NULL))) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_RSA, (uint8_t**)&res);
    if (ret >= 0) {
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        uint8_t* res_out;

        if (res_len < hdr_sz || res->outLen > (res_len - hdr_sz)) {
            return WH_ERROR_ABORTED;
        }

        res_out = (uint8_t*)(res + 1);
        if (inout_out_len != NULL) {
            if ((out != NULL) && (res->outLen > *inout_out_len)) {
                /* Report required size; never silently truncate. */
                *inout_out_len = (uint16_t)res->outLen;
                return WH_ERROR_BUFFER_SIZE;
            }
            *inout_out_len = (uint16_t)res->outLen;
            if ((out != NULL) && (res->outLen > 0)) {
                memcpy(out, res_out, res->outLen);
            }
        }
    }
    return ret;
}

int wh_Client_RsaFunction(whClientContext* ctx, RsaKey* key, int rsa_type,
                          const uint8_t* in, uint16_t in_len, uint8_t* out,
                          uint16_t* inout_out_len)
{
    int                         ret     = WH_ERROR_OK;
    whMessageCrypto_RsaRequest* req     = NULL;
    uint8_t*                    dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    WH_DEBUG_CLIENT_VERBOSE("ctx:%p key:%p, rsa_type:%d in:%p in_len:%u, out:%p "
           "inout_out_len:%p\n",
           ctx, key, rsa_type, in, (unsigned)in_len, out,
           inout_out_len);

    if ((ctx == NULL) || (key == NULL) || ((in == NULL) && (in_len > 0)) ||
        ((out != NULL) && (inout_out_len == NULL))) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    WH_DEBUG_CLIENT_VERBOSE("key_id:%x\n", key_id);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempRsaFunction";
        /* Set usage flags based on requested RSA operation */
        whNvmFlags flags = WH_NVM_FLAGS_NONE;
        switch (rsa_type) {
            case RSA_PUBLIC_ENCRYPT:
            case RSA_PRIVATE_ENCRYPT:
                flags = WH_NVM_FLAGS_USAGE_ENCRYPT;
                break;
            case RSA_PUBLIC_DECRYPT:
            case RSA_PRIVATE_DECRYPT:
                flags = WH_NVM_FLAGS_USAGE_DECRYPT;
                break;
            default:
                flags = WH_NVM_FLAGS_ANY;
                break;
        }

        ret = wh_Client_RsaImportKey(ctx, key, &key_id, flags, sizeof(keyLabel),
                                     keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group     = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action    = WC_ALGO_TYPE_PK;
        size_t   total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(*req) + in_len;
        uint32_t options = 0;

        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_RsaRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_RSA, ctx->cryptoAffinity);

        if (total_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint16_t req_len = (uint16_t)total_len;
            uint8_t* req_in  = (uint8_t*)(req + 1);

            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_RSA_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->opType  = rsa_type;
            req->options = options;
            req->keyId   = key_id;
            req->inLen   = in_len;
            if ((in != NULL) && (in_len > 0)) {
                memcpy(req_in, in, in_len);
            }
            /* Set output length only when provided to avoid NULL dereference */
            req->outLen = (inout_out_len != NULL) ? *inout_out_len : 0;

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                do {
                    ret =
                        wh_Client_RsaFunctionResponse(ctx, out, inout_out_len);
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
        else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
    WH_DEBUG_CLIENT_VERBOSE("ret:%d\n", ret);
    return ret;
}

int wh_Client_RsaGetSizeRequest(whClientContext* ctx, whKeyId keyId)
{
    whMessageCrypto_RsaGetSizeRequest* req     = NULL;
    uint8_t*                           dataPtr = NULL;
    uint16_t                           req_len;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (WH_KEYID_ISERASED(keyId)) {
        return WH_ERROR_BADARGS;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_RsaGetSizeRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_RSA_GET_SIZE, ctx->cryptoAffinity);

    memset(req, 0, sizeof(*req));
    req->options = 0;
    req->keyId   = keyId;

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_PK,
                                 req_len, dataPtr);
}

int wh_Client_RsaGetSizeResponse(whClientContext* ctx, int* out_size)
{
    int                                 ret;
    uint16_t                            group;
    uint16_t                            action;
    uint16_t                            res_len = 0;
    uint8_t*                            dataPtr;
    whMessageCrypto_RsaGetSizeResponse* res = NULL;

    if ((ctx == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_RSA_GET_SIZE, (uint8_t**)&res);
    if (ret >= 0) {
        const size_t hdr_sz =
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res);
        if (res_len < hdr_sz) {
            return WH_ERROR_ABORTED;
        }
        *out_size = (int)res->keySize;
    }
    return ret;
}

int wh_Client_RsaGetSize(whClientContext* ctx, const RsaKey* key, int* out_size)
{
    int                                ret     = WH_ERROR_OK;
    whMessageCrypto_RsaGetSizeRequest* req     = NULL;
    uint8_t*                           dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    WH_DEBUG_CLIENT_VERBOSE("ctx:%p key:%p, out_size:%p \n", ctx, key,
           out_size);

    if ((ctx == NULL) || (key == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempRsaGetSize";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        WH_DEBUG_CLIENT_VERBOSE("Importing temp key\n");
        ret = wh_Client_RsaImportKey(ctx, key, &key_id, flags, sizeof(keyLabel),
                                     keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
        uint32_t options = 0;

        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_RsaGetSizeRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_RSA_GET_SIZE, ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_RSA_GET_SIZE_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->keyId   = key_id;

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                do {
                    ret = wh_Client_RsaGetSizeResponse(ctx, out_size);
                } while (ret == WH_ERROR_NOTREADY);
            }
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if (evict != 0) {
        WH_DEBUG_CLIENT_VERBOSE("Evicting temp key %x\n", key_id);
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
    WH_DEBUG_CLIENT_VERBOSE("ret:%d\n", ret);
    return ret;
}


#endif /* !NO_RSA */

#ifdef HAVE_HKDF
/* Internal helper function to generate HKDF output on the server */
static int _HkdfMakeKey(whClientContext* ctx, int hashType, whKeyId keyIdIn,
                        const uint8_t* inKey, uint32_t inKeySz,
                        const uint8_t* salt, uint32_t saltSz,
                        const uint8_t* info, uint32_t infoSz, whNvmFlags flags,
                        uint32_t label_len, const uint8_t* label,
                        whKeyId* inout_key_id, uint8_t* out, uint32_t outSz)
{
    int                           ret     = WH_ERROR_OK;
    uint8_t*                      dataPtr = NULL;
    whMessageCrypto_HkdfRequest*  req     = NULL;
    whMessageCrypto_HkdfResponse* res     = NULL;
    uint16_t                      group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action  = WC_ALGO_TYPE_KDF;
    whKeyId                       key_id  = WH_KEYID_ERASED;

    if ((ctx == NULL) || ((inKey == NULL) && (inKeySz != 0))) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_HkdfRequest*)_createCryptoRequestWithSubtype(
        dataPtr, WC_ALGO_TYPE_KDF, WC_KDF_TYPE_HKDF, ctx->cryptoAffinity);

    /* Calculate request length including variable-length data */
    uint32_t total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                         sizeof(*req) + inKeySz + saltSz + infoSz;
    if (total_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }
    uint16_t req_len = (uint16_t)total_len;

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Populate request body */
    req->flags    = flags;
    req->keyIdIn  = keyIdIn;
    req->keyIdOut = key_id;
    req->hashType = hashType;
    req->inKeySz  = inKeySz;
    req->saltSz   = saltSz;
    req->infoSz   = infoSz;
    req->outSz    = outSz;

    /* Copy label if provided */
    memset(req->label, 0, WH_NVM_LABEL_LEN);
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }

    /* Copy variable-length data after the request structure */
    uint8_t* data_ptr = (uint8_t*)(req + 1);

    /* Copy input key material */
    if ((inKey != NULL) && (inKeySz > 0)) {
        memcpy(data_ptr, inKey, inKeySz);
        data_ptr += inKeySz;
    }

    /* Copy salt if provided */
    if (salt != NULL && saltSz > 0) {
        memcpy(data_ptr, salt, saltSz);
        data_ptr += saltSz;
    }

    /* Copy info if provided */
    if (info != NULL && infoSz > 0) {
        memcpy(data_ptr, info, infoSz);
    }

    /* Send Request */
    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);

    WH_DEBUG_CLIENT_VERBOSE("HKDF Req sent: hashType:%d inKeySz:%u saltSz:%u infoSz:%u outSz:%u "
           "ret:%d\n",
           (int)req->hashType, (unsigned int)req->inKeySz,
           (unsigned int)req->saltSz, (unsigned int)req->infoSz,
           (unsigned int)req->outSz, ret);

    if (ret == 0) {
        uint16_t res_len = 0;
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                         WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);

        WH_DEBUG_CLIENT_VERBOSE("HKDF Res recv: ret:%d, res_len: %u\n", ret,
               (unsigned int)res_len);

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header rc */
            ret =
                _getCryptoResponse(dataPtr, WC_ALGO_TYPE_KDF, (uint8_t**)&res);
        }

        if (ret == WH_ERROR_OK) {
            /* Key is cached on server or is ephemeral */
            key_id = (whKeyId)(res->keyIdOut);

            /* Update output variable if requested */
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }

            /* Copy output key material if output buffer provided */
            if (out != NULL) {
                if (res->outSz <= outSz) {
                    uint8_t* hkdf_out = (uint8_t*)(res + 1);
                    memcpy(out, hkdf_out, res->outSz);

                    WH_DEBUG_CLIENT_VERBOSE("Set key_id:%x with flags:%x outSz:%u\n",
                           key_id, flags, (unsigned int)res->outSz);
                }
                else {
                    /* Server returned more than we can handle - error */
                    ret = WH_ERROR_ABORTED;
                }
            }
        }
    }
    return ret;
}

int wh_Client_HkdfMakeCacheKey(whClientContext* ctx, int hashType,
                               whKeyId keyIdIn, const uint8_t* inKey,
                               uint32_t inKeySz, const uint8_t* salt,
                               uint32_t saltSz, const uint8_t* info,
                               uint32_t infoSz, whKeyId* inout_key_id,
                               whNvmFlags flags, const uint8_t* label,
                               uint32_t label_len, uint32_t outSz)
{
    if ((ctx == NULL) || (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _HkdfMakeKey(ctx, hashType, keyIdIn, inKey, inKeySz, salt, saltSz,
                        info, infoSz, flags, label_len, label, inout_key_id,
                        NULL, outSz);
}

int wh_Client_HkdfMakeExportKey(whClientContext* ctx, int hashType,
                                whKeyId keyIdIn, const uint8_t* inKey,
                                uint32_t inKeySz, const uint8_t* salt,
                                uint32_t saltSz, const uint8_t* info,
                                uint32_t infoSz, uint8_t* out, uint32_t outSz)
{
    if ((ctx == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _HkdfMakeKey(ctx, hashType, keyIdIn, inKey, inKeySz, salt, saltSz,
                        info, infoSz, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, NULL,
                        out, outSz);
}

#endif /* HAVE_HKDF */

#ifdef HAVE_CMAC_KDF
static int _CmacKdfMakeKey(whClientContext* ctx, whKeyId saltKeyId,
                           const uint8_t* salt, uint32_t saltSz, whKeyId zKeyId,
                           const uint8_t* z, uint32_t zSz,
                           const uint8_t* fixedInfo, uint32_t fixedInfoSz,
                           whNvmFlags flags, uint32_t label_len,
                           const uint8_t* label, whKeyId* inout_key_id,
                           uint8_t* out, uint32_t outSz)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_CmacKdfRequest*  req     = NULL;
    whMessageCrypto_CmacKdfResponse* res     = NULL;
    uint16_t                         group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                         action  = WC_ALGO_TYPE_KDF;
    whKeyId                          key_id  = WH_KEYID_ERASED;

    if ((ctx == NULL) || (outSz == 0)) {
        return WH_ERROR_BADARGS;
    }

    if ((saltSz > 0 && salt == NULL) || (zSz > 0 && z == NULL) ||
        (fixedInfoSz > 0 && fixedInfo == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Retrieve the shared communication buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Prepare request structure with subtype information */
    req = (whMessageCrypto_CmacKdfRequest*)_createCryptoRequestWithSubtype(
        dataPtr, WC_ALGO_TYPE_KDF, WC_KDF_TYPE_TWOSTEP_CMAC,
        ctx->cryptoAffinity);

    uint32_t total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                         sizeof(*req) + saltSz + zSz + fixedInfoSz;

    if (total_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }
    uint16_t req_len = (uint16_t)total_len;

    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    req->flags       = flags;
    req->keyIdSalt   = saltKeyId;
    req->keyIdZ      = zKeyId;
    req->keyIdOut    = key_id;
    req->saltSz      = saltSz;
    req->zSz         = zSz;
    req->fixedInfoSz = fixedInfoSz;
    req->outSz       = outSz;

    memset(req->label, 0, WH_NVM_LABEL_LEN);
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }

    uint8_t* payload = (uint8_t*)(req + 1);

    if (saltSz > 0 && salt != NULL) {
        memcpy(payload, salt, saltSz);
        payload += saltSz;
    }

    if (zSz > 0 && z != NULL) {
        memcpy(payload, z, zSz);
        payload += zSz;
    }

    if (fixedInfoSz > 0 && fixedInfo != NULL) {
        memcpy(payload, fixedInfo, fixedInfoSz);
        payload += fixedInfoSz;
    }

    /* squash unused warning */
    (void)payload;

    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    uint16_t res_len = 0;
    do {
        ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                     WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    } while (ret == WH_ERROR_NOTREADY);

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_KDF, (uint8_t**)&res);
    }

    if (ret == WH_ERROR_OK) {
        key_id = (whKeyId)(res->keyIdOut);

        if (inout_key_id != NULL) {
            *inout_key_id = key_id;
        }

        if (out != NULL) {
            if (res->outSz <= outSz) {
                uint8_t* out_data = (uint8_t*)(res + 1);
                memcpy(out, out_data, res->outSz);
            }
            else {
                ret = WH_ERROR_ABORTED;
            }
        }
    }

    return ret;
}

int wh_Client_CmacKdfMakeCacheKey(whClientContext* ctx, whKeyId saltKeyId,
                                  const uint8_t* salt, uint32_t saltSz,
                                  whKeyId zKeyId, const uint8_t* z,
                                  uint32_t zSz, const uint8_t* fixedInfo,
                                  uint32_t fixedInfoSz, whKeyId* inout_key_id,
                                  whNvmFlags flags, const uint8_t* label,
                                  uint32_t label_len, uint32_t outSz)
{
    if ((ctx == NULL) || (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _CmacKdfMakeKey(ctx, saltKeyId, salt, saltSz, zKeyId, z, zSz,
                           fixedInfo, fixedInfoSz, flags, label_len, label,
                           inout_key_id, NULL, outSz);
}

int wh_Client_CmacKdfMakeExportKey(whClientContext* ctx, whKeyId saltKeyId,
                                   const uint8_t* salt, uint32_t saltSz,
                                   whKeyId zKeyId, const uint8_t* z,
                                   uint32_t zSz, const uint8_t* fixedInfo,
                                   uint32_t fixedInfoSz, uint8_t* out,
                                   uint32_t outSz)
{
    if ((ctx == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _CmacKdfMakeKey(ctx, saltKeyId, salt, saltSz, zKeyId, z, zSz,
                           fixedInfo, fixedInfoSz, WH_NVM_FLAGS_EPHEMERAL, 0,
                           NULL, NULL, out, outSz);
}
#endif /* HAVE_CMAC_KDF */

#ifndef NO_AES
int wh_Client_AesSetKeyId(Aes* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_AesGetKeyId(Aes* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}
#endif /* !NO_AES */

#ifdef WOLFSSL_CMAC
int wh_Client_CmacSetKeyId(Cmac* key, whNvmId keyId)
{
    if (key == NULL)
        return WH_ERROR_BADARGS;
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_CmacGetKeyId(Cmac* key, whNvmId* outId)
{
    if (key == NULL || outId == NULL)
        return WH_ERROR_BADARGS;
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

#ifndef NO_AES

/* Resolve the key source for a CMAC request: if the caller didn't provide
 * inline bytes and the cmac struct has cached bytes, use those. HSM keys
 * (non-erased keyId) are resolved server-side. */
static void _CmacResolveClientKey(Cmac* cmac, const uint8_t** inout_key,
                                  uint32_t* inout_keyLen, whKeyId* out_key_id)
{
    whKeyId key_id = WH_DEVCTX_TO_KEYID(cmac->devCtx);

    if (*inout_key == NULL && *inout_keyLen == 0 && WH_KEYID_ISERASED(key_id) &&
        cmac->aes.keylen > 0) {
        *inout_key    = (const uint8_t*)cmac->aes.devKey;
        *inout_keyLen = cmac->aes.keylen;
    }
    *out_key_id = key_id;
}

/* Reject keys that would overflow cmac->aes.devKey (32 bytes) when cached
 * client-side, matching the server's own keySz > AES_256_KEY_SIZE check.
 * Must be called after _CmacResolveClientKey and before any state mutation
 * or transport send. */
static int _CmacValidateInlineKeyLen(uint32_t keyLen)
{
    if (keyLen > AES_256_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }
    return WH_ERROR_OK;
}

/* Enforce wolfCrypt's CMAC tag length contract locally to fail fast on a
 * transaction that would return an error from server */
static int _CmacValidateTagLen(uint32_t outMacLen)
{
    if (outMacLen > 0 &&
        (outMacLen < WC_CMAC_TAG_MIN_SZ || outMacLen > WC_CMAC_TAG_MAX_SZ)) {
        return WH_ERROR_BUFFER_SIZE;
    }
    return WH_ERROR_OK;
}

int wh_Client_CmacGenerateRequest(whClientContext* ctx, Cmac* cmac,
                                  CmacType type, const uint8_t* key,
                                  uint32_t keyLen, const uint8_t* in,
                                  uint32_t inLen, uint32_t outMacLen)
{
    whMessageCrypto_CmacAesRequest* req;
    uint8_t*                        dataPtr;
    uint8_t*                        req_in;
    uint8_t*                        req_key;
    uint32_t                        hdr_sz;
    whKeyId                         key_id;
    int                             ret;

    if (ctx == NULL || cmac == NULL || in == NULL || inLen == 0 ||
        outMacLen == 0 || (key == NULL && keyLen != 0)) {
        return WH_ERROR_BADARGS;
    }

    ret = _CmacValidateTagLen(outMacLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    _CmacResolveClientKey(cmac, &key, &keyLen, &key_id);

    ret = _CmacValidateInlineKeyLen(keyLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_CmacAesRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC, ctx->cryptoAffinity);

    hdr_sz  = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    req_in  = (uint8_t*)(req + 1);
    req_key = req_in + inLen;

    if (inLen > WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_GENERATE_SZ ||
        keyLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz - inLen) {
        return WH_ERROR_BADARGS;
    }

    memset(&req->resumeState, 0, sizeof(req->resumeState));
    req->inSz  = inLen;
    req->outSz = outMacLen;
    req->keyId = key_id;
    req->keySz = keyLen;

    memcpy(req_in, in, inLen);
    if (key != NULL && keyLen > 0) {
        memcpy(req_key, key, keyLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_CMAC,
                                (uint16_t)(hdr_sz + inLen + keyLen), dataPtr);
    if (ret == WH_ERROR_OK) {
        cmac->type = type;
        if (key != NULL && keyLen > 0 && WH_KEYID_ISERASED(key_id) &&
            key != (const uint8_t*)cmac->aes.devKey) {
            memcpy((void*)cmac->aes.devKey, key, keyLen);
            cmac->aes.keylen = keyLen;
        }
    }
    return ret;
}

int wh_Client_CmacGenerateResponse(whClientContext* ctx, Cmac* cmac,
                                   uint8_t* outMac, uint32_t* outMacLen)
{
    whMessageCrypto_CmacAesResponse* res = NULL;
    uint8_t*                         dataPtr;
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         res_len = 0;
    int                              ret;

    if (ctx == NULL || cmac == NULL || outMac == NULL || outMacLen == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
    /* wolfCrypt allows positive error codes on success */
    if (ret >= 0) {
        /* Restore state from response (server has finalized; buffer/digest
         * carry the post-finalization state). */
        ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &res->resumeState);
        if (ret >= 0) {
            ret = _CmacValidateTagLen(*outMacLen);
        }
        if (ret >= 0) {
            if (res->outSz < *outMacLen) {
                *outMacLen = res->outSz;
            }
            memcpy(outMac, (uint8_t*)(res + 1), *outMacLen);
        }
    }
    return ret;
}

int wh_Client_CmacUpdateRequest(whClientContext* ctx, Cmac* cmac, CmacType type,
                                const uint8_t* key, uint32_t keyLen,
                                const uint8_t* in, uint32_t inLen,
                                bool* requestSent)
{
    whMessageCrypto_CmacAesRequest* req;
    uint8_t*                        dataPtr;
    uint8_t*                        req_in;
    uint8_t*                        req_key;
    uint32_t                        hdr_sz;
    whKeyId                         key_id;
    int                             ret;

    if (ctx == NULL || cmac == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0) || (key == NULL && keyLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    _CmacResolveClientKey(cmac, &key, &keyLen, &key_id);

    ret = _CmacValidateInlineKeyLen(keyLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Empty update with no key: nothing to send, just record type. */
    if (inLen == 0 && keyLen == 0) {
        cmac->type = type;
        return WH_ERROR_OK;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_CmacAesRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC, ctx->cryptoAffinity);
    hdr_sz  = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    req_in  = (uint8_t*)(req + 1);
    req_key = req_in + inLen;

    if (inLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz ||
        keyLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz - inLen) {
        return WH_ERROR_BADARGS;
    }

    /* Wire request: input + (optional) key + full state round-trip. The
     * server may leave a partial (or whole) block in cmac->buffer after
     * wc_CmacUpdate, so we faithfully round-trip the entire state on every
     * Request/Response pair. */
    req->inSz  = inLen;
    req->outSz = 0;
    req->keyId = key_id;
    req->keySz = keyLen;
    wh_Crypto_CmacAesSaveStateToMsg(&req->resumeState, cmac);

    if (in != NULL && inLen > 0) {
        memcpy(req_in, in, inLen);
    }
    if (key != NULL && keyLen > 0) {
        memcpy(req_key, key, keyLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_CMAC,
                                (uint16_t)(hdr_sz + inLen + keyLen), dataPtr);
    if (ret == WH_ERROR_OK) {
        *requestSent = true;
        cmac->type   = type;
        if (key != NULL && keyLen > 0 && WH_KEYID_ISERASED(key_id) &&
            key != (const uint8_t*)cmac->aes.devKey) {
            memcpy((void*)cmac->aes.devKey, key, keyLen);
            cmac->aes.keylen = keyLen;
        }
    }
    return ret;
}

int wh_Client_CmacUpdateResponse(whClientContext* ctx, Cmac* cmac)
{
    whMessageCrypto_CmacAesResponse* res = NULL;
    uint8_t*                         dataPtr;
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         res_len = 0;
    int                              ret;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
    if (ret >= 0) {
        /* Restore full state from server. The server may leave a partial
         * (or whole) block in its buffer after wc_CmacUpdate (CMAC's last
         * block has special handling), so we round-trip the whole state. */
        ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &res->resumeState);
    }
    return ret;
}

int wh_Client_CmacFinalRequest(whClientContext* ctx, Cmac* cmac)
{
    whMessageCrypto_CmacAesRequest* req;
    uint8_t*                        dataPtr;
    uint8_t*                        req_in;
    uint8_t*                        req_key;
    const uint8_t*                  key    = NULL;
    uint32_t                        keyLen = 0;
    whKeyId                         key_id;
    uint32_t                        hdr_sz;
    int                             ret;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    _CmacResolveClientKey(cmac, &key, &keyLen, &key_id);

    ret = _CmacValidateInlineKeyLen(keyLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_CmacAesRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC, ctx->cryptoAffinity);
    hdr_sz  = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    req_in  = (uint8_t*)(req + 1);
    req_key = req_in;

    if (keyLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz) {
        return WH_ERROR_BADARGS;
    }

    /* Final: no new input — server uses the round-tripped state (which
     * already includes any partial/whole block left in cmac->buffer from
     * the previous Update) and finalizes. */
    req->inSz  = 0;
    req->outSz = AES_BLOCK_SIZE;
    req->keyId = key_id;
    req->keySz = keyLen;
    wh_Crypto_CmacAesSaveStateToMsg(&req->resumeState, cmac);

    if (key != NULL && keyLen > 0) {
        memcpy(req_key, key, keyLen);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO,
                                 WC_ALGO_TYPE_CMAC, (uint16_t)(hdr_sz + keyLen),
                                 dataPtr);
}

int wh_Client_CmacFinalResponse(whClientContext* ctx, Cmac* cmac,
                                uint8_t* outMac, uint32_t* outMacLen)
{
    whMessageCrypto_CmacAesResponse* res = NULL;
    uint8_t*                         dataPtr;
    uint16_t                         group;
    uint16_t                         action;
    uint16_t                         res_len = 0;
    int                              ret;

    if (ctx == NULL || cmac == NULL || outMac == NULL || outMacLen == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
    if (ret >= 0) {
        /* Restore final state from response (server's bufferSz is 0 after
         * Final). */
        ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &res->resumeState);
        if (ret >= 0) {
            ret = _CmacValidateTagLen(*outMacLen);
        }
        if (ret >= 0) {
            if (res->outSz < *outMacLen) {
                *outMacLen = res->outSz;
            }
            memcpy(outMac, (uint8_t*)(res + 1), *outMacLen);
        }
    }
    return ret;
}

int wh_Client_Cmac(whClientContext* ctx, Cmac* cmac, CmacType type,
                   const uint8_t* key, uint32_t keyLen, const uint8_t* in,
                   uint32_t inLen, uint8_t* outMac, uint32_t* outMacLen)
{
    int ret = WH_ERROR_OK;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* No-op init: record type only. */
    if (inLen == 0 && keyLen == 0 && (outMac == NULL || outMacLen == NULL)) {
        cmac->type = type;
        return WH_ERROR_OK;
    }

    if (outMac != NULL && outMacLen != NULL) {
        ret = _CmacValidateTagLen(*outMacLen);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    /* Oneshot fast path: input + output present and the input fits inline,
     * plus either an explicit key (matches wc_AesCmacGenerate_ex semantics —
     * fresh oneshot, prior cmac state is irrelevant and may be uninitialized)
     * or fresh cmac state with a cached HSM keyId. The Generate request
     * resets state server-side. */
    if (in != NULL && inLen > 0 && outMac != NULL && outMacLen != NULL &&
        *outMacLen > 0 &&
        inLen <= WH_MESSAGE_CRYPTO_CMAC_MAX_INLINE_GENERATE_SZ &&
        ((key != NULL && keyLen > 0) ||
         (cmac->bufferSz == 0 && cmac->totalSz == 0))) {
        ret = wh_Client_CmacGenerateRequest(ctx, cmac, type, key, keyLen, in,
                                            inLen, *outMacLen);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_CmacGenerateResponse(ctx, cmac, outMac,
                                                     outMacLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
        return ret;
    }

    /* Streaming path: Update + Final. The existing blocking semantic is
     * a single-shot Update (no chunking), so just one Update call. */
    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret = wh_Client_CmacUpdateRequest(ctx, cmac, type, key, keyLen, in,
                                          inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    else if (key != NULL && keyLen > 0) {
        /* Key-provision only (no input, no output): cache key client-side
         * via Update with no input. Server returns updated state (which
         * is effectively unchanged since no data was processed). */
        bool sent = false;
        ret = wh_Client_CmacUpdateRequest(ctx, cmac, type, key, keyLen, NULL, 0,
                                          &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_CmacUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    if (ret == WH_ERROR_OK && outMac != NULL && outMacLen != NULL) {
        ret = wh_Client_CmacFinalRequest(ctx, cmac);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_CmacFinalResponse(ctx, cmac, outMac, outMacLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    return ret;
}

#endif /* !NO_AES */


#ifdef WOLFHSM_CFG_DMA

/* Stash the DMA input mapping for POST cleanup on the matching Response. */
static void _CmacDmaStashInput(whClientContext* ctx, uintptr_t inAddr,
                               uintptr_t clientAddr, uint64_t inSz)
{
    ctx->dma.asyncCtx.cmac.inAddr     = inAddr;
    ctx->dma.asyncCtx.cmac.clientAddr = clientAddr;
    ctx->dma.asyncCtx.cmac.inSz       = inSz;
}

/* Run POST DMA cleanup if a mapping was stashed, then clear the stash. */
static void _CmacDmaPostCleanup(whClientContext* ctx)
{
    if (ctx->dma.asyncCtx.cmac.inSz > 0) {
        uintptr_t inAddr = ctx->dma.asyncCtx.cmac.inAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.cmac.clientAddr, (void**)&inAddr,
            ctx->dma.asyncCtx.cmac.inSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.cmac.inSz = 0;
    }
}

int wh_Client_CmacGenerateDmaRequest(whClientContext* ctx, Cmac* cmac,
                                     CmacType type, const uint8_t* key,
                                     uint32_t keyLen, const uint8_t* in,
                                     uint32_t inLen, uint32_t outMacLen)
{
    whMessageCrypto_CmacAesDmaRequest* req;
    uint8_t*                           dataPtr;
    uint8_t*                           req_key;
    uint32_t                           hdr_sz;
    uintptr_t                          inAddr         = 0;
    bool                               inAddrAcquired = false;
    whKeyId                            key_id;
    int                                ret;

    if (ctx == NULL || cmac == NULL || in == NULL || inLen == 0 ||
        outMacLen == 0 || (key == NULL && keyLen != 0)) {
        return WH_ERROR_BADARGS;
    }

    ret = _CmacValidateTagLen(outMacLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Fail-fast on occupied transport to avoid leaking the DMA mapping if
     * SendRequest rejects the request. */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    _CmacResolveClientKey(cmac, &key, &keyLen, &key_id);

    ret = _CmacValidateInlineKeyLen(keyLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_CmacAesDmaRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC, ctx->cryptoAffinity);
    memset(req, 0, sizeof(*req));

    hdr_sz  = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    req_key = (uint8_t*)(req + 1);

    if (keyLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz) {
        return WH_ERROR_BADARGS;
    }

    req->outSz      = outMacLen;
    req->keyId      = key_id;
    req->keySz      = keyLen;
    req->inlineInSz = 0;
    req->input.sz   = inLen;

    if (key != NULL && keyLen > 0) {
        memcpy(req_key, key, keyLen);
    }

    ret = wh_Client_DmaProcessClientAddress(ctx, (uintptr_t)in, (void**)&inAddr,
                                            inLen, WH_DMA_OPER_CLIENT_READ_PRE,
                                            (whDmaFlags){0});
    if (ret == WH_ERROR_OK) {
        inAddrAcquired  = true;
        req->input.addr = inAddr;
        _CmacDmaStashInput(ctx, inAddr, (uintptr_t)in, inLen);
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                    WC_ALGO_TYPE_CMAC,
                                    (uint16_t)(hdr_sz + keyLen), dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        cmac->type = type;
        if (key != NULL && keyLen > 0 && WH_KEYID_ISERASED(key_id) &&
            key != (const uint8_t*)cmac->aes.devKey) {
            memcpy((void*)cmac->aes.devKey, key, keyLen);
            cmac->aes.keylen = keyLen;
        }
    }
    else if (inAddrAcquired) {
        _CmacDmaPostCleanup(ctx);
    }
    return ret;
}

int wh_Client_CmacGenerateDmaResponse(whClientContext* ctx, Cmac* cmac,
                                      uint8_t* outMac, uint32_t* outMacLen)
{
    whMessageCrypto_CmacAesDmaResponse* res = NULL;
    uint8_t*                            dataPtr;
    uint16_t                            respSz = 0;
    int                                 ret;

    if (ctx == NULL || cmac == NULL || outMac == NULL || outMacLen == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
        if (ret >= 0) {
            ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &res->resumeState);
            if (ret >= 0) {
                ret = _CmacValidateTagLen(*outMacLen);
            }
            if (ret >= 0) {
                if (res->outSz < *outMacLen) {
                    *outMacLen = res->outSz;
                }
                memcpy(outMac, (uint8_t*)(res + 1), *outMacLen);
            }
        }
    }

    _CmacDmaPostCleanup(ctx);
    return ret;
}

int wh_Client_CmacDmaUpdateRequest(whClientContext* ctx, Cmac* cmac,
                                   CmacType type, const uint8_t* key,
                                   uint32_t keyLen, const uint8_t* in,
                                   uint32_t inLen, bool* requestSent)
{
    whMessageCrypto_CmacAesDmaRequest* req;
    uint8_t*                           dataPtr;
    uint8_t*                           req_key;
    uintptr_t                          inAddr         = 0;
    bool                               inAddrAcquired = false;
    whKeyId                            key_id;
    uint32_t                           hdr_sz;
    int                                ret;

    if (ctx == NULL || cmac == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0) || (key == NULL && keyLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    _CmacResolveClientKey(cmac, &key, &keyLen, &key_id);

    ret = _CmacValidateInlineKeyLen(keyLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Empty update with no key: nothing to send, just record type. */
    if (inLen == 0 && keyLen == 0) {
        cmac->type = type;
        return WH_ERROR_OK;
    }

    /* Fail-fast on occupied transport before acquiring any DMA mapping. */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_CmacAesDmaRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC, ctx->cryptoAffinity);
    memset(req, 0, sizeof(*req));

    hdr_sz  = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    req_key = (uint8_t*)(req + 1);

    if (keyLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz) {
        return WH_ERROR_BADARGS;
    }

    /* Wire request: full state round-trip + (optional) inline key + DMA
     * input. Server may leave a partial/whole block in cmac->buffer after
     * wc_CmacUpdate, so resumeState carries the entire CMAC state. */
    wh_Crypto_CmacAesSaveStateToMsg(&req->resumeState, cmac);
    req->outSz      = 0;
    req->keyId      = key_id;
    req->keySz      = keyLen;
    req->inlineInSz = 0;

    if (key != NULL && keyLen > 0) {
        memcpy(req_key, key, keyLen);
    }

    /* PRE DMA translate for the input (if any). */
    if (inLen > 0) {
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, inLen,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAddrAcquired  = true;
            req->input.sz   = inLen;
            req->input.addr = inAddr;
            _CmacDmaStashInput(ctx, inAddr, (uintptr_t)in, inLen);
        }
    }
    else {
        ret = WH_ERROR_OK;
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                    WC_ALGO_TYPE_CMAC,
                                    (uint16_t)(hdr_sz + keyLen), dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        *requestSent = true;
        cmac->type   = type;
        if (key != NULL && keyLen > 0 && WH_KEYID_ISERASED(key_id) &&
            key != (const uint8_t*)cmac->aes.devKey) {
            memcpy((void*)cmac->aes.devKey, key, keyLen);
            cmac->aes.keylen = keyLen;
        }
    }
    else if (inAddrAcquired) {
        _CmacDmaPostCleanup(ctx);
    }
    return ret;
}

int wh_Client_CmacDmaUpdateResponse(whClientContext* ctx, Cmac* cmac)
{
    whMessageCrypto_CmacAesDmaResponse* res = NULL;
    uint8_t*                            dataPtr;
    uint16_t                            respSz = 0;
    int                                 ret;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
        if (ret >= 0) {
            /* Restore full state from server (includes any partial/whole
             * block left in the server's wc_CmacUpdate buffer). */
            ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &res->resumeState);
        }
    }

    _CmacDmaPostCleanup(ctx);
    return ret;
}

int wh_Client_CmacDmaFinalRequest(whClientContext* ctx, Cmac* cmac)
{
    whMessageCrypto_CmacAesDmaRequest* req;
    uint8_t*                           dataPtr;
    uint8_t*                           req_key;
    const uint8_t*                     key    = NULL;
    uint32_t                           keyLen = 0;
    whKeyId                            key_id;
    uint32_t                           hdr_sz;
    int                                ret;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    _CmacResolveClientKey(cmac, &key, &keyLen, &key_id);

    ret = _CmacValidateInlineKeyLen(keyLen);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_CmacAesDmaRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC, ctx->cryptoAffinity);
    memset(req, 0, sizeof(*req));

    hdr_sz  = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
    req_key = (uint8_t*)(req + 1);

    if (keyLen > (uint32_t)WOLFHSM_CFG_COMM_DATA_LEN - hdr_sz) {
        return WH_ERROR_BADARGS;
    }

    /* Final: no new input — server uses the round-tripped state and
     * finalizes. No DMA addresses are used. */
    wh_Crypto_CmacAesSaveStateToMsg(&req->resumeState, cmac);
    req->outSz      = AES_BLOCK_SIZE;
    req->keyId      = key_id;
    req->keySz      = keyLen;
    req->inlineInSz = 0;

    if (key != NULL && keyLen > 0) {
        memcpy(req_key, key, keyLen);
    }

    return wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                 WC_ALGO_TYPE_CMAC, (uint16_t)(hdr_sz + keyLen),
                                 dataPtr);
}

int wh_Client_CmacDmaFinalResponse(whClientContext* ctx, Cmac* cmac,
                                   uint8_t* outMac, uint32_t* outMacLen)
{
    whMessageCrypto_CmacAesDmaResponse* res = NULL;
    uint8_t*                            dataPtr;
    uint16_t                            respSz = 0;
    int                                 ret;

    if (ctx == NULL || cmac == NULL || outMac == NULL || outMacLen == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
    if (ret >= 0) {
        ret = wh_Crypto_CmacAesRestoreStateFromMsg(cmac, &res->resumeState);
        if (ret >= 0) {
            ret = _CmacValidateTagLen(*outMacLen);
        }
        if (ret >= 0) {
            if (res->outSz < *outMacLen) {
                *outMacLen = res->outSz;
            }
            memcpy(outMac, (uint8_t*)(res + 1), *outMacLen);
        }
    }
    return ret;
}

int wh_Client_CmacDma(whClientContext* ctx, Cmac* cmac, CmacType type,
                      const uint8_t* key, uint32_t keyLen, const uint8_t* in,
                      uint32_t inLen, uint8_t* outMac, uint32_t* outMacLen)
{
    int ret = WH_ERROR_OK;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* No-op init. */
    if (inLen == 0 && keyLen == 0 && (outMac == NULL || outMacLen == NULL)) {
        cmac->type = type;
        return WH_ERROR_OK;
    }

    if (outMac != NULL && outMacLen != NULL) {
        ret = _CmacValidateTagLen(*outMacLen);
        if (ret != WH_ERROR_OK) {
            return ret;
        }
    }

    /* Oneshot fast path: input + output present, plus either an explicit key
     * (matches wc_AesCmacGenerate_ex semantics — fresh oneshot, prior cmac
     * state is irrelevant and may be uninitialized) or fresh cmac state with
     * a cached HSM keyId. The Generate request resets state server-side. */
    if (in != NULL && inLen > 0 && outMac != NULL && outMacLen != NULL &&
        *outMacLen > 0 &&
        ((key != NULL && keyLen > 0) ||
         (cmac->bufferSz == 0 && cmac->totalSz == 0))) {
        ret = wh_Client_CmacGenerateDmaRequest(ctx, cmac, type, key, keyLen, in,
                                               inLen, *outMacLen);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_CmacGenerateDmaResponse(ctx, cmac, outMac,
                                                        outMacLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
        return ret;
    }

    /* Streaming path: DMA Update + DMA Final. The existing blocking semantic
     * is a single-shot Update (no chunking), so just one Update call. */
    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, type, key, keyLen, in,
                                             inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    else if (key != NULL && keyLen > 0) {
        bool sent = false;
        ret = wh_Client_CmacDmaUpdateRequest(ctx, cmac, type, key, keyLen, NULL,
                                             0, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_CmacDmaUpdateResponse(ctx, cmac);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    if (ret == WH_ERROR_OK && outMac != NULL && outMacLen != NULL) {
        ret = wh_Client_CmacDmaFinalRequest(ctx, cmac);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_CmacDmaFinalResponse(ctx, cmac, outMac,
                                                     outMacLen);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_CMAC */

#ifndef NO_SHA256

/* Maximum number of input bytes that wh_Client_Sha256UpdateRequest can absorb
 * in a single call: the inline-data wire capacity, plus whatever room is left
 * in the partial-block buffer (we can stash up to BLOCK_SIZE-1-buffLen tail
 * bytes locally without producing a new full block). */
static uint32_t _Sha256UpdatePerCallCapacity(const wc_Sha256* sha)
{
    return WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ +
           (uint32_t)(WC_SHA256_BLOCK_SIZE - 1u - sha->buffLen);
}

int wh_Client_Sha256UpdateRequest(whClientContext* ctx, wc_Sha256* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent)
{
    int                            ret = 0;
    whMessageCrypto_Sha256Request* req = NULL;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr = NULL;
    uint8_t*                       sha256BufferBytes;
    uint32_t                       capacity;
    uint32_t                       wirePos = 0;
    uint32_t                       i       = 0;
    /* Snapshot of buffer state for rollback if SendRequest fails */
    uint32_t savedBuffLen;
    uint8_t  savedBuffer[WC_SHA256_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA256_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    capacity = _Sha256UpdatePerCallCapacity(sha);
    if (inLen > capacity) {
        return WH_ERROR_BADARGS;
    }

    /* Empty update: nothing to send, no state to mutate. */
    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha256Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA256, ctx->cryptoAffinity);
    inlineData        = (uint8_t*)(req + 1);
    sha256BufferBytes = (uint8_t*)sha->buffer;

    /* Save the buffer state before mutation so we can restore it if
     * SendRequest fails, preventing silent SHA state corruption. */
    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, sha256BufferBytes, sha->buffLen);

    /* If there's a partial block already buffered, top it up from the input.
     * If we manage to fill a full block, copy the completed block into the
     * wire payload as the first inline block. */
    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA256_BLOCK_SIZE) {
            sha256BufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA256_BLOCK_SIZE) {
            memcpy(inlineData + wirePos, sha256BufferBytes,
                   WC_SHA256_BLOCK_SIZE);
            wirePos += WC_SHA256_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    /* Copy as many full blocks from the input as fit in the inline area. */
    while ((inLen - i) >= WC_SHA256_BLOCK_SIZE &&
           (wirePos + WC_SHA256_BLOCK_SIZE) <=
               WH_MESSAGE_CRYPTO_SHA256_MAX_INLINE_UPDATE_SZ) {
        memcpy(inlineData + wirePos, in + i, WC_SHA256_BLOCK_SIZE);
        wirePos += WC_SHA256_BLOCK_SIZE;
        i += WC_SHA256_BLOCK_SIZE;
    }

    /* Stash any remaining tail bytes into the buffer for next time. The
     * capacity check above guarantees this fits without overflow. */
    while (i < inLen) {
        sha256BufferBytes[sha->buffLen++] = in[i++];
    }

    /* Pure-buffer-fill update: nothing to send. */
    if (wirePos == 0) {
        return WH_ERROR_OK;
    }

    /* Populate fixed request fields */
    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + wirePos,
                                dataPtr);

    if (ret == 0) {
        *requestSent = true;
    }
    else {
        /* SendRequest failed — restore buffer state so the caller can retry
         * or continue hashing without data loss. */
        sha->buffLen = savedBuffLen;
        memcpy(sha256BufferBytes, savedBuffer, savedBuffLen);
    }
    return ret;
}

int wh_Client_Sha256UpdateResponse(whClientContext* ctx, wc_Sha256* sha)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret    = 0;
    whMessageCrypto_Sha2Response* res    = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        if (res->hashType != WC_HASH_TYPE_SHA256) {
            return WH_ERROR_ABORTED;
        }
        memcpy(sha->digest, res->hash, WC_SHA256_DIGEST_SIZE);
        sha->hiLen = res->hiLen;
        sha->loLen = res->loLen;
    }
    return ret;
}

int wh_Client_Sha256FinalRequest(whClientContext* ctx, wc_Sha256* sha)
{
    int                            ret;
    whMessageCrypto_Sha256Request* req;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (sha->buffLen >= WC_SHA256_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha256Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA256, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha256FinalResponse(whClientContext* ctx, wc_Sha256* sha,
                                  uint8_t* out)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret;
    whMessageCrypto_Sha2Response* res = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != 0) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        if (res->hashType != WC_HASH_TYPE_SHA256) {
            return WH_ERROR_ABORTED;
        }
        memcpy(out, res->hash, WC_SHA256_DIGEST_SIZE);
        /* Reset state without blowing away devId */
        (void)wc_InitSha256_ex(sha, NULL, sha->devId);
    }
    return ret;
}

int wh_Client_Sha256(whClientContext* ctx, wc_Sha256* sha256, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha256Hash(sha256, data, len, NULL) */
    if (in != NULL && inLen > 0) {
        uint32_t consumed = 0;
        while (ret == WH_ERROR_OK && consumed < inLen) {
            uint32_t capacity  = _Sha256UpdatePerCallCapacity(sha256);
            uint32_t remaining = inLen - consumed;
            uint32_t chunk     = (remaining < capacity) ? remaining : capacity;
            bool     sent      = false;

            ret = wh_Client_Sha256UpdateRequest(ctx, sha256, in + consumed,
                                                chunk, &sent);
            if (ret != WH_ERROR_OK) {
                break;
            }
            if (sent) {
                do {
                    ret = wh_Client_Sha256UpdateResponse(ctx, sha256);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret != WH_ERROR_OK) {
                    break;
                }
            }
            consumed += chunk;
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha256Hash(sha256, NULL, 0, *hash) */
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha256FinalRequest(ctx, sha256);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha256FinalResponse(ctx, sha256, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha256DmaUpdateRequest(whClientContext* ctx, wc_Sha256* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha256DmaRequest* req     = NULL;
    uint8_t*                          inlineData;
    uint8_t*                          sha256BufferBytes;
    uint32_t                          wirePos        = 0;
    uint32_t                          i              = 0;
    uintptr_t                         inAddr         = 0;
    bool                              inAddrAcquired = false;
    const uint8_t*                    dmaBase        = NULL;
    uint32_t                          dmaSz          = 0;
    /* Snapshot of buffer state for rollback if SendRequest fails */
    uint32_t savedBuffLen;
    uint8_t  savedBuffer[WC_SHA256_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA256_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha256DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA256, ctx->cryptoAffinity);
    inlineData        = (uint8_t*)(req + 1);
    sha256BufferBytes = (uint8_t*)sha->buffer;

    /* Save buffer state for rollback */
    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, sha256BufferBytes, sha->buffLen);

    /* If there's a partial block already buffered, top it up from input.
     * If we complete a full block, copy it to the inline trailing area. */
    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA256_BLOCK_SIZE) {
            sha256BufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA256_BLOCK_SIZE) {
            memcpy(inlineData, sha256BufferBytes, WC_SHA256_BLOCK_SIZE);
            wirePos      = WC_SHA256_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    /* Remaining whole blocks from input go via DMA */
    if ((inLen - i) >= WC_SHA256_BLOCK_SIZE) {
        dmaBase = in + i;
        dmaSz   = ((inLen - i) / WC_SHA256_BLOCK_SIZE) * WC_SHA256_BLOCK_SIZE;
        i += dmaSz;
    }

    /* Stash any remaining tail bytes into the buffer */
    while (i < inLen) {
        sha256BufferBytes[sha->buffLen++] = in[i++];
    }

    /* If no blocks to send, nothing to do */
    if (wirePos == 0 && dmaSz == 0) {
        return WH_ERROR_OK;
    }

    /* Populate request fields */
    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;
    req->input.sz          = dmaSz;
    req->input.addr        = 0;

    /* DMA PRE for input data if there are DMA blocks */
    if (dmaSz > 0) {
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAddrAcquired  = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        WH_DEBUG_CLIENT_VERBOSE("SHA256 DMA UPDATE: inlineSz=%u, dmaSz=%u\n",
                                (unsigned int)wirePos, (unsigned int)dmaSz);

        /* Stash DMA info for Response POST cleanup */
        ctx->dma.asyncCtx.sha.ioAddr     = inAddr;
        ctx->dma.asyncCtx.sha.clientAddr = (uintptr_t)dmaBase;
        ctx->dma.asyncCtx.sha.ioSz       = dmaSz;

        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
                wirePos,
            dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        *requestSent = true;
    }
    else {
        /* Rollback buffer state and release DMA on failure */
        sha->buffLen = savedBuffLen;
        memcpy(sha256BufferBytes, savedBuffer, savedBuffLen);
        if (inAddrAcquired) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.sha, 0, sizeof(ctx->dma.asyncCtx.sha));
    }
    return ret;
}

int wh_Client_Sha256DmaUpdateResponse(whClientContext* ctx, wc_Sha256* sha)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                ret = WH_ERROR_ABORTED;
            }
            else if (resp->hashType != WC_HASH_TYPE_SHA256) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(sha->digest, resp->hash, WC_SHA256_DIGEST_SIZE);
                sha->hiLen = resp->hiLen;
                sha->loLen = resp->loLen;
            }
        }
    }

    /* POST-process DMA input using stashed async context */
    if (ctx->dma.asyncCtx.sha.ioSz > 0) {
        uintptr_t ioAddr = ctx->dma.asyncCtx.sha.ioAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.sha.clientAddr, (void**)&ioAddr,
            ctx->dma.asyncCtx.sha.ioSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.sha.ioSz = 0;
    }
    return ret;
}

int wh_Client_Sha256DmaFinalRequest(whClientContext* ctx, wc_Sha256* sha)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha256DmaRequest* req     = NULL;
    uint8_t*                          inlineData;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    if (sha->buffLen >= WC_SHA256_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha256DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA256, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;
    req->input.sz          = 0;
    req->input.addr        = 0;

    /* Copy partial-block tail as inline data */
    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    WH_DEBUG_CLIENT_VERBOSE("SHA256 DMA FINAL: buffLen=%u\n",
                            (unsigned int)sha->buffLen);

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha256DmaFinalResponse(whClientContext* ctx, wc_Sha256* sha,
                                     uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                return WH_ERROR_ABORTED;
            }
            if (resp->hashType != WC_HASH_TYPE_SHA256) {
                return WH_ERROR_ABORTED;
            }
            memcpy(out, resp->hash, WC_SHA256_DIGEST_SIZE);
            /* Reset state without blowing away devId */
            (void)wc_InitSha256_ex(sha, NULL, sha->devId);
        }
    }
    return ret;
}

int wh_Client_Sha256Dma(whClientContext* ctx, wc_Sha256* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret = wh_Client_Sha256DmaUpdateRequest(ctx, sha, in, inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_Sha256DmaUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha256DmaFinalRequest(ctx, sha);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha256DmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224

/* Maximum number of input bytes that wh_Client_Sha224UpdateRequest can absorb
 * in a single call: the inline-data wire capacity, plus whatever room is left
 * in the partial-block buffer (we can stash up to BLOCK_SIZE-1-buffLen tail
 * bytes locally without producing a new full block). */
static uint32_t _Sha224UpdatePerCallCapacity(const wc_Sha224* sha)
{
    return WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ +
           (uint32_t)(WC_SHA224_BLOCK_SIZE - 1u - sha->buffLen);
}

int wh_Client_Sha224UpdateRequest(whClientContext* ctx, wc_Sha224* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent)
{
    int                            ret = 0;
    whMessageCrypto_Sha256Request* req = NULL;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr = NULL;
    uint8_t*                       sha224BufferBytes;
    uint32_t                       capacity;
    uint32_t                       wirePos = 0;
    uint32_t                       i       = 0;
    /* Snapshot of buffer state for rollback if SendRequest fails */
    uint32_t savedBuffLen;
    uint8_t  savedBuffer[WC_SHA224_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA224_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    capacity = _Sha224UpdatePerCallCapacity(sha);
    if (inLen > capacity) {
        return WH_ERROR_BADARGS;
    }

    /* Empty update: nothing to send, no state to mutate. */
    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha256Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA224, ctx->cryptoAffinity);
    inlineData        = (uint8_t*)(req + 1);
    sha224BufferBytes = (uint8_t*)sha->buffer;

    /* Save the buffer state before mutation so we can restore it if
     * SendRequest fails, preventing silent SHA state corruption. */
    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, sha224BufferBytes, sha->buffLen);

    /* If there's a partial block already buffered, top it up from the input.
     * If we manage to fill a full block, copy the completed block into the
     * wire payload as the first inline block. */
    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA224_BLOCK_SIZE) {
            sha224BufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA224_BLOCK_SIZE) {
            memcpy(inlineData + wirePos, sha224BufferBytes,
                   WC_SHA224_BLOCK_SIZE);
            wirePos += WC_SHA224_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    /* Copy as many full blocks from the input as fit in the inline area. */
    while ((inLen - i) >= WC_SHA224_BLOCK_SIZE &&
           (wirePos + WC_SHA224_BLOCK_SIZE) <=
               WH_MESSAGE_CRYPTO_SHA224_MAX_INLINE_UPDATE_SZ) {
        memcpy(inlineData + wirePos, in + i, WC_SHA224_BLOCK_SIZE);
        wirePos += WC_SHA224_BLOCK_SIZE;
        i += WC_SHA224_BLOCK_SIZE;
    }

    /* Stash any remaining tail bytes into the buffer for next time. The
     * capacity check above guarantees this fits without overflow. */
    while (i < inLen) {
        sha224BufferBytes[sha->buffLen++] = in[i++];
    }

    /* Pure-buffer-fill update: nothing to send. */
    if (wirePos == 0) {
        return WH_ERROR_OK;
    }

    /* Populate fixed request fields. Intermediate hash state uses the full
     * SHA256 digest size (32 bytes) on the wire; the final truncation to
     * WC_SHA224_DIGEST_SIZE happens only in FinalResponse. */
    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + wirePos,
                                dataPtr);

    if (ret == 0) {
        *requestSent = true;
    }
    else {
        /* SendRequest failed — restore buffer state so the caller can retry
         * or continue hashing without data loss. */
        sha->buffLen = savedBuffLen;
        memcpy(sha224BufferBytes, savedBuffer, savedBuffLen);
    }
    return ret;
}

int wh_Client_Sha224UpdateResponse(whClientContext* ctx, wc_Sha224* sha)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret    = 0;
    whMessageCrypto_Sha2Response* res    = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        if (res->hashType != WC_HASH_TYPE_SHA224) {
            return WH_ERROR_ABORTED;
        }
        /* Intermediate hash state is stored at full SHA256 digest width */
        memcpy(sha->digest, res->hash, WC_SHA256_DIGEST_SIZE);
        sha->hiLen = res->hiLen;
        sha->loLen = res->loLen;
    }
    return ret;
}

int wh_Client_Sha224FinalRequest(whClientContext* ctx, wc_Sha224* sha)
{
    int                            ret;
    whMessageCrypto_Sha256Request* req;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (sha->buffLen >= WC_SHA224_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha256Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA224, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha224FinalResponse(whClientContext* ctx, wc_Sha224* sha,
                                  uint8_t* out)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret;
    whMessageCrypto_Sha2Response* res = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != 0) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        if (res->hashType != WC_HASH_TYPE_SHA224) {
            return WH_ERROR_ABORTED;
        }
        /* Final output is truncated to WC_SHA224_DIGEST_SIZE */
        memcpy(out, res->hash, WC_SHA224_DIGEST_SIZE);
        /* Reset state without blowing away devId */
        (void)wc_InitSha224_ex(sha, NULL, sha->devId);
    }
    return ret;
}

int wh_Client_Sha224(whClientContext* ctx, wc_Sha224* sha224, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha224Hash(sha224, data, len, NULL) */
    if (in != NULL && inLen > 0) {
        uint32_t consumed = 0;
        while (ret == WH_ERROR_OK && consumed < inLen) {
            uint32_t capacity  = _Sha224UpdatePerCallCapacity(sha224);
            uint32_t remaining = inLen - consumed;
            uint32_t chunk     = (remaining < capacity) ? remaining : capacity;
            bool     sent      = false;

            ret = wh_Client_Sha224UpdateRequest(ctx, sha224, in + consumed,
                                                chunk, &sent);
            if (ret != WH_ERROR_OK) {
                break;
            }
            if (sent) {
                do {
                    ret = wh_Client_Sha224UpdateResponse(ctx, sha224);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret != WH_ERROR_OK) {
                    break;
                }
            }
            consumed += chunk;
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha224Hash(sha224, NULL, 0, *hash) */
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha224FinalRequest(ctx, sha224);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha224FinalResponse(ctx, sha224, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha224DmaUpdateRequest(whClientContext* ctx, wc_Sha224* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha256DmaRequest* req     = NULL;
    uint8_t*                          inlineData;
    uint8_t*                          shaBufferBytes;
    uint32_t                          wirePos        = 0;
    uint32_t                          i              = 0;
    uintptr_t                         inAddr         = 0;
    bool                              inAddrAcquired = false;
    const uint8_t*                    dmaBase        = NULL;
    uint32_t                          dmaSz          = 0;
    uint32_t                          savedBuffLen;
    uint8_t                           savedBuffer[WC_SHA224_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA224_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha256DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA224, ctx->cryptoAffinity);
    inlineData     = (uint8_t*)(req + 1);
    shaBufferBytes = (uint8_t*)sha->buffer;

    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, shaBufferBytes, sha->buffLen);

    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA224_BLOCK_SIZE) {
            shaBufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA224_BLOCK_SIZE) {
            memcpy(inlineData, shaBufferBytes, WC_SHA224_BLOCK_SIZE);
            wirePos      = WC_SHA224_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    if ((inLen - i) >= WC_SHA224_BLOCK_SIZE) {
        dmaBase = in + i;
        dmaSz   = ((inLen - i) / WC_SHA224_BLOCK_SIZE) * WC_SHA224_BLOCK_SIZE;
        i += dmaSz;
    }

    while (i < inLen) {
        shaBufferBytes[sha->buffLen++] = in[i++];
    }

    if (wirePos == 0 && dmaSz == 0) {
        return WH_ERROR_OK;
    }

    req->isLastBlock = 0;
    req->inSz        = wirePos;
    /* SHA224 shares SHA256's internal 32-byte digest state */
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;
    req->input.sz          = dmaSz;
    req->input.addr        = 0;

    if (dmaSz > 0) {
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAddrAcquired  = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.sha.ioAddr     = inAddr;
        ctx->dma.asyncCtx.sha.clientAddr = (uintptr_t)dmaBase;
        ctx->dma.asyncCtx.sha.ioSz       = dmaSz;

        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
                wirePos,
            dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        *requestSent = true;
    }
    else {
        sha->buffLen = savedBuffLen;
        memcpy(shaBufferBytes, savedBuffer, savedBuffLen);
        if (inAddrAcquired) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.sha, 0, sizeof(ctx->dma.asyncCtx.sha));
    }
    return ret;
}

int wh_Client_Sha224DmaUpdateResponse(whClientContext* ctx, wc_Sha224* sha)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                ret = WH_ERROR_ABORTED;
            }
            else if (resp->hashType != WC_HASH_TYPE_SHA224) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(sha->digest, resp->hash, WC_SHA256_DIGEST_SIZE);
                sha->hiLen = resp->hiLen;
                sha->loLen = resp->loLen;
            }
        }
    }

    if (ctx->dma.asyncCtx.sha.ioSz > 0) {
        uintptr_t ioAddr = ctx->dma.asyncCtx.sha.ioAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.sha.clientAddr, (void**)&ioAddr,
            ctx->dma.asyncCtx.sha.ioSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.sha.ioSz = 0;
    }
    return ret;
}

int wh_Client_Sha224DmaFinalRequest(whClientContext* ctx, wc_Sha224* sha)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha256DmaRequest* req     = NULL;
    uint8_t*                          inlineData;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    if (sha->buffLen >= WC_SHA224_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha256DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA224, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    /* SHA224 shares SHA256's internal 32-byte digest state */
    memcpy(req->resumeState.hash, sha->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha->hiLen;
    req->resumeState.loLen = sha->loLen;
    req->input.sz          = 0;
    req->input.addr        = 0;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha224DmaFinalResponse(whClientContext* ctx, wc_Sha224* sha,
                                     uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                return WH_ERROR_ABORTED;
            }
            if (resp->hashType != WC_HASH_TYPE_SHA224) {
                return WH_ERROR_ABORTED;
            }
            memcpy(out, resp->hash, WC_SHA224_DIGEST_SIZE);
            (void)wc_InitSha224_ex(sha, NULL, sha->devId);
        }
    }
    return ret;
}

int wh_Client_Sha224Dma(whClientContext* ctx, wc_Sha224* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret = wh_Client_Sha224DmaUpdateRequest(ctx, sha, in, inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_Sha224DmaUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha224DmaFinalRequest(ctx, sha);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha224DmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384

/* Maximum number of input bytes that wh_Client_Sha384UpdateRequest can absorb
 * in a single call: the inline-data wire capacity, plus whatever room is left
 * in the partial-block buffer (we can stash up to BLOCK_SIZE-1-buffLen tail
 * bytes locally without producing a new full block). */
static uint32_t _Sha384UpdatePerCallCapacity(const wc_Sha384* sha)
{
    return WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ +
           (uint32_t)(WC_SHA384_BLOCK_SIZE - 1u - sha->buffLen);
}

int wh_Client_Sha384UpdateRequest(whClientContext* ctx, wc_Sha384* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent)
{
    int                            ret = 0;
    whMessageCrypto_Sha512Request* req = NULL;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr = NULL;
    uint8_t*                       sha384BufferBytes;
    uint32_t                       capacity;
    uint32_t                       wirePos = 0;
    uint32_t                       i       = 0;
    /* Snapshot of buffer state for rollback if SendRequest fails */
    uint32_t savedBuffLen;
    uint8_t  savedBuffer[WC_SHA384_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA384_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    capacity = _Sha384UpdatePerCallCapacity(sha);
    if (inLen > capacity) {
        return WH_ERROR_BADARGS;
    }

    /* Empty update: nothing to send, no state to mutate. */
    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha512Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA384, ctx->cryptoAffinity);
    inlineData        = (uint8_t*)(req + 1);
    sha384BufferBytes = (uint8_t*)sha->buffer;

    /* Save the buffer state before mutation so we can restore it if
     * SendRequest fails, preventing silent SHA state corruption. */
    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, sha384BufferBytes, sha->buffLen);

    /* If there's a partial block already buffered, top it up from the input.
     * If we manage to fill a full block, copy the completed block into the
     * wire payload as the first inline block. */
    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA384_BLOCK_SIZE) {
            sha384BufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA384_BLOCK_SIZE) {
            memcpy(inlineData + wirePos, sha384BufferBytes,
                   WC_SHA384_BLOCK_SIZE);
            wirePos += WC_SHA384_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    /* Copy as many full blocks from the input as fit in the inline area. */
    while ((inLen - i) >= WC_SHA384_BLOCK_SIZE &&
           (wirePos + WC_SHA384_BLOCK_SIZE) <=
               WH_MESSAGE_CRYPTO_SHA384_MAX_INLINE_UPDATE_SZ) {
        memcpy(inlineData + wirePos, in + i, WC_SHA384_BLOCK_SIZE);
        wirePos += WC_SHA384_BLOCK_SIZE;
        i += WC_SHA384_BLOCK_SIZE;
    }

    /* Stash any remaining tail bytes into the buffer for next time. The
     * capacity check above guarantees this fits without overflow. */
    while (i < inLen) {
        sha384BufferBytes[sha->buffLen++] = in[i++];
    }

    /* Pure-buffer-fill update: nothing to send. */
    if (wirePos == 0) {
        return WH_ERROR_OK;
    }

    /* Populate fixed request fields. Intermediate hash state uses the full
     * SHA512 digest size (64 bytes) on the wire; the final truncation to
     * WC_SHA384_DIGEST_SIZE happens only in FinalResponse. */
    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = WC_HASH_TYPE_SHA384;

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + wirePos,
                                dataPtr);

    if (ret == 0) {
        *requestSent = true;
    }
    else {
        /* SendRequest failed — restore buffer state so the caller can retry
         * or continue hashing without data loss. */
        sha->buffLen = savedBuffLen;
        memcpy(sha384BufferBytes, savedBuffer, savedBuffLen);
    }
    return ret;
}

int wh_Client_Sha384UpdateResponse(whClientContext* ctx, wc_Sha384* sha)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret    = 0;
    whMessageCrypto_Sha2Response* res    = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        if (res->hashType != WC_HASH_TYPE_SHA384) {
            return WH_ERROR_ABORTED;
        }
        /* Intermediate hash state is stored at full SHA512 digest width */
        memcpy(sha->digest, res->hash, WC_SHA512_DIGEST_SIZE);
        sha->hiLen = res->hiLen;
        sha->loLen = res->loLen;
    }
    return ret;
}

int wh_Client_Sha384FinalRequest(whClientContext* ctx, wc_Sha384* sha)
{
    int                            ret;
    whMessageCrypto_Sha512Request* req;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (sha->buffLen >= WC_SHA384_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha512Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA384, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = WC_HASH_TYPE_SHA384;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha384FinalResponse(whClientContext* ctx, wc_Sha384* sha,
                                  uint8_t* out)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret;
    whMessageCrypto_Sha2Response* res = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != 0) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        if (res->hashType != WC_HASH_TYPE_SHA384) {
            return WH_ERROR_ABORTED;
        }
        /* Final output is truncated to WC_SHA384_DIGEST_SIZE */
        memcpy(out, res->hash, WC_SHA384_DIGEST_SIZE);
        /* Reset state without blowing away devId */
        (void)wc_InitSha384_ex(sha, NULL, sha->devId);
    }
    return ret;
}

int wh_Client_Sha384(whClientContext* ctx, wc_Sha384* sha384, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha384Hash(sha384, data, len, NULL) */
    if (in != NULL && inLen > 0) {
        uint32_t consumed = 0;
        while (ret == WH_ERROR_OK && consumed < inLen) {
            uint32_t capacity  = _Sha384UpdatePerCallCapacity(sha384);
            uint32_t remaining = inLen - consumed;
            uint32_t chunk     = (remaining < capacity) ? remaining : capacity;
            bool     sent      = false;

            ret = wh_Client_Sha384UpdateRequest(ctx, sha384, in + consumed,
                                                chunk, &sent);
            if (ret != WH_ERROR_OK) {
                break;
            }
            if (sent) {
                do {
                    ret = wh_Client_Sha384UpdateResponse(ctx, sha384);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret != WH_ERROR_OK) {
                    break;
                }
            }
            consumed += chunk;
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha384Hash(sha384, NULL, 0, *hash) */
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha384FinalRequest(ctx, sha384);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha384FinalResponse(ctx, sha384, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha384DmaUpdateRequest(whClientContext* ctx, wc_Sha384* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha512DmaRequest* req     = NULL;
    uint8_t*                          inlineData;
    uint8_t*                          shaBufferBytes;
    uint32_t                          wirePos        = 0;
    uint32_t                          i              = 0;
    uintptr_t                         inAddr         = 0;
    bool                              inAddrAcquired = false;
    const uint8_t*                    dmaBase        = NULL;
    uint32_t                          dmaSz          = 0;
    uint32_t                          savedBuffLen;
    uint8_t                           savedBuffer[WC_SHA384_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA384_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha512DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA384, ctx->cryptoAffinity);
    inlineData     = (uint8_t*)(req + 1);
    shaBufferBytes = (uint8_t*)sha->buffer;

    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, shaBufferBytes, sha->buffLen);

    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA384_BLOCK_SIZE) {
            shaBufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA384_BLOCK_SIZE) {
            memcpy(inlineData, shaBufferBytes, WC_SHA384_BLOCK_SIZE);
            wirePos      = WC_SHA384_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    if ((inLen - i) >= WC_SHA384_BLOCK_SIZE) {
        dmaBase = in + i;
        dmaSz   = ((inLen - i) / WC_SHA384_BLOCK_SIZE) * WC_SHA384_BLOCK_SIZE;
        i += dmaSz;
    }

    while (i < inLen) {
        shaBufferBytes[sha->buffLen++] = in[i++];
    }

    if (wirePos == 0 && dmaSz == 0) {
        return WH_ERROR_OK;
    }

    req->isLastBlock = 0;
    req->inSz        = wirePos;
    /* SHA384 shares SHA512's internal 64-byte digest state */
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = WC_HASH_TYPE_SHA384;
    req->input.sz             = dmaSz;
    req->input.addr           = 0;

    if (dmaSz > 0) {
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAddrAcquired  = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.sha.ioAddr     = inAddr;
        ctx->dma.asyncCtx.sha.clientAddr = (uintptr_t)dmaBase;
        ctx->dma.asyncCtx.sha.ioSz       = dmaSz;

        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
                wirePos,
            dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        *requestSent = true;
    }
    else {
        sha->buffLen = savedBuffLen;
        memcpy(shaBufferBytes, savedBuffer, savedBuffLen);
        if (inAddrAcquired) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.sha, 0, sizeof(ctx->dma.asyncCtx.sha));
    }
    return ret;
}

int wh_Client_Sha384DmaUpdateResponse(whClientContext* ctx, wc_Sha384* sha)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                ret = WH_ERROR_ABORTED;
            }
            else if (resp->hashType != WC_HASH_TYPE_SHA384) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(sha->digest, resp->hash, WC_SHA512_DIGEST_SIZE);
                sha->hiLen = resp->hiLen;
                sha->loLen = resp->loLen;
            }
        }
    }

    if (ctx->dma.asyncCtx.sha.ioSz > 0) {
        uintptr_t ioAddr = ctx->dma.asyncCtx.sha.ioAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.sha.clientAddr, (void**)&ioAddr,
            ctx->dma.asyncCtx.sha.ioSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.sha.ioSz = 0;
    }
    return ret;
}

int wh_Client_Sha384DmaFinalRequest(whClientContext* ctx, wc_Sha384* sha)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha512DmaRequest* req     = NULL;
    uint8_t*                          inlineData;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    if (sha->buffLen >= WC_SHA384_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha512DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA384, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    /* SHA384 shares SHA512's internal 64-byte digest state */
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = WC_HASH_TYPE_SHA384;
    req->input.sz             = 0;
    req->input.addr           = 0;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha384DmaFinalResponse(whClientContext* ctx, wc_Sha384* sha,
                                     uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                return WH_ERROR_ABORTED;
            }
            if (resp->hashType != WC_HASH_TYPE_SHA384) {
                return WH_ERROR_ABORTED;
            }
            memcpy(out, resp->hash, WC_SHA384_DIGEST_SIZE);
            (void)wc_InitSha384_ex(sha, NULL, sha->devId);
        }
    }
    return ret;
}

int wh_Client_Sha384Dma(whClientContext* ctx, wc_Sha384* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret = wh_Client_Sha384DmaUpdateRequest(ctx, sha, in, inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_Sha384DmaUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha384DmaFinalRequest(ctx, sha);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha384DmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA384 */


#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_SHA512_HASHTYPE)

/* Maximum number of input bytes that wh_Client_Sha512UpdateRequest can absorb
 * in a single call: the inline-data wire capacity, plus whatever room is left
 * in the partial-block buffer (we can stash up to BLOCK_SIZE-1-buffLen tail
 * bytes locally without producing a new full block). */
static uint32_t _Sha512UpdatePerCallCapacity(const wc_Sha512* sha)
{
    return WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ +
           (uint32_t)(WC_SHA512_BLOCK_SIZE - 1u - sha->buffLen);
}

int wh_Client_Sha512UpdateRequest(whClientContext* ctx, wc_Sha512* sha,
                                  const uint8_t* in, uint32_t inLen,
                                  bool* requestSent)
{
    int                            ret = 0;
    whMessageCrypto_Sha512Request* req = NULL;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr = NULL;
    uint8_t*                       sha512BufferBytes;
    uint32_t                       capacity;
    uint32_t                       wirePos = 0;
    uint32_t                       i       = 0;
    /* Snapshot of buffer state for rollback if SendRequest fails */
    uint32_t savedBuffLen;
    uint8_t  savedBuffer[WC_SHA512_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA512_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    capacity = _Sha512UpdatePerCallCapacity(sha);
    if (inLen > capacity) {
        return WH_ERROR_BADARGS;
    }

    /* Empty update: nothing to send, no state to mutate. */
    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha512Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA512, ctx->cryptoAffinity);
    inlineData        = (uint8_t*)(req + 1);
    sha512BufferBytes = (uint8_t*)sha->buffer;

    /* Save the buffer state before mutation so we can restore it if
     * SendRequest fails, preventing silent SHA state corruption. */
    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, sha512BufferBytes, sha->buffLen);

    /* If there's a partial block already buffered, top it up from the input.
     * If we manage to fill a full block, copy the completed block into the
     * wire payload as the first inline block. */
    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA512_BLOCK_SIZE) {
            sha512BufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA512_BLOCK_SIZE) {
            memcpy(inlineData + wirePos, sha512BufferBytes,
                   WC_SHA512_BLOCK_SIZE);
            wirePos += WC_SHA512_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    /* Copy as many full blocks from the input as fit in the inline area. */
    while ((inLen - i) >= WC_SHA512_BLOCK_SIZE &&
           (wirePos + WC_SHA512_BLOCK_SIZE) <=
               WH_MESSAGE_CRYPTO_SHA512_MAX_INLINE_UPDATE_SZ) {
        memcpy(inlineData + wirePos, in + i, WC_SHA512_BLOCK_SIZE);
        wirePos += WC_SHA512_BLOCK_SIZE;
        i += WC_SHA512_BLOCK_SIZE;
    }

    /* Stash any remaining tail bytes into the buffer for next time. The
     * capacity check above guarantees this fits without overflow. */
    while (i < inLen) {
        sha512BufferBytes[sha->buffLen++] = in[i++];
    }

    /* Pure-buffer-fill update: nothing to send. */
    if (wirePos == 0) {
        return WH_ERROR_OK;
    }

    /* Populate fixed request fields */
    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = sha->hashType;

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + wirePos,
                                dataPtr);

    if (ret == 0) {
        *requestSent = true;
    }
    else {
        /* SendRequest failed — restore buffer state so the caller can retry
         * or continue hashing without data loss. */
        sha->buffLen = savedBuffLen;
        memcpy(sha512BufferBytes, savedBuffer, savedBuffLen);
    }
    return ret;
}

int wh_Client_Sha512UpdateResponse(whClientContext* ctx, wc_Sha512* sha)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret    = 0;
    whMessageCrypto_Sha2Response* res    = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        /* Family check, not variant match: SHA-512/t shares block size and
         * compression with SHA-512, and the client supplies the variant IV
         * in resumeState.hash — so a server missing SHA-512/t support still
         * returns a correct intermediate state. */
        if (res->hashType != WC_HASH_TYPE_SHA512 &&
            res->hashType != WC_HASH_TYPE_SHA512_224 &&
            res->hashType != WC_HASH_TYPE_SHA512_256) {
            return WH_ERROR_ABORTED;
        }
        memcpy(sha->digest, res->hash, WC_SHA512_DIGEST_SIZE);
        sha->hiLen = res->hiLen;
        sha->loLen = res->loLen;
    }
    return ret;
}

int wh_Client_Sha512FinalRequest(whClientContext* ctx, wc_Sha512* sha)
{
    int                            ret;
    whMessageCrypto_Sha512Request* req;
    uint8_t*                       inlineData;
    uint8_t*                       dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (sha->buffLen >= WC_SHA512_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha512Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA512, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = sha->hashType;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha512FinalResponse(whClientContext* ctx, wc_Sha512* sha,
                                  uint8_t* out)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret;
    whMessageCrypto_Sha2Response* res = NULL;
    uint8_t*                      dataPtr;
    int                           hashType;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != 0) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                         sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        /* keep hashtype before initialization */
        hashType = sha->hashType;
        /* Family check, not variant match: SHA-512/t shares block size and
         * compression with SHA-512; the client supplies the variant IV in
         * resumeState.hash and the switch below truncates by hashType, so a
         * server missing SHA-512/t support still yields a correct digest. */
        if (res->hashType != WC_HASH_TYPE_SHA512 &&
            res->hashType != WC_HASH_TYPE_SHA512_224 &&
            res->hashType != WC_HASH_TYPE_SHA512_256) {
            return WH_ERROR_ABORTED;
        }
        /* reset the state of the sha context (without blowing away devId and
         *  hashType), and copy only the digest bytes for the active variant */
        switch (hashType) {
#ifndef WOLFSSL_NOSHA512_224
            case WC_HASH_TYPE_SHA512_224:
                memcpy(out, res->hash, WC_SHA512_224_DIGEST_SIZE);
                (void)wc_InitSha512_224_ex(sha, NULL, sha->devId);
                break;
#endif
#ifndef WOLFSSL_NOSHA512_256
            case WC_HASH_TYPE_SHA512_256:
                memcpy(out, res->hash, WC_SHA512_256_DIGEST_SIZE);
                (void)wc_InitSha512_256_ex(sha, NULL, sha->devId);
                break;
#endif
            default:
                memcpy(out, res->hash, WC_SHA512_DIGEST_SIZE);
                (void)wc_InitSha512_ex(sha, NULL, sha->devId);
                break;
        }
    }
    return ret;
}

int wh_Client_Sha512(whClientContext* ctx, wc_Sha512* sha512, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha512Hash(sha512, data, len, NULL) */
    if (in != NULL && inLen > 0) {
        uint32_t consumed = 0;
        while (ret == WH_ERROR_OK && consumed < inLen) {
            uint32_t capacity  = _Sha512UpdatePerCallCapacity(sha512);
            uint32_t remaining = inLen - consumed;
            uint32_t chunk     = (remaining < capacity) ? remaining : capacity;
            bool     sent      = false;

            ret = wh_Client_Sha512UpdateRequest(ctx, sha512, in + consumed,
                                                chunk, &sent);
            if (ret != WH_ERROR_OK) {
                break;
            }
            if (sent) {
                do {
                    ret = wh_Client_Sha512UpdateResponse(ctx, sha512);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret != WH_ERROR_OK) {
                    break;
                }
            }
            consumed += chunk;
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha512Hash(sha512, NULL, 0, *hash) */
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha512FinalRequest(ctx, sha512);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha512FinalResponse(ctx, sha512, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha512DmaUpdateRequest(whClientContext* ctx, wc_Sha512* sha,
                                     const uint8_t* in, uint32_t inLen,
                                     bool* requestSent)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha512DmaRequest* req     = NULL;
    uint8_t*                          inlineData;
    uint8_t*                          shaBufferBytes;
    uint32_t                          wirePos        = 0;
    uint32_t                          i              = 0;
    uintptr_t                         inAddr         = 0;
    bool                              inAddrAcquired = false;
    const uint8_t*                    dmaBase        = NULL;
    uint32_t                          dmaSz          = 0;
    uint32_t                          savedBuffLen;
    uint8_t                           savedBuffer[WC_SHA512_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    *requestSent = false;

    if (sha->buffLen >= WC_SHA512_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha512DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA512, ctx->cryptoAffinity);
    inlineData     = (uint8_t*)(req + 1);
    shaBufferBytes = (uint8_t*)sha->buffer;

    savedBuffLen = sha->buffLen;
    memcpy(savedBuffer, shaBufferBytes, sha->buffLen);

    if (sha->buffLen > 0) {
        while (i < inLen && sha->buffLen < WC_SHA512_BLOCK_SIZE) {
            shaBufferBytes[sha->buffLen++] = in[i++];
        }
        if (sha->buffLen == WC_SHA512_BLOCK_SIZE) {
            memcpy(inlineData, shaBufferBytes, WC_SHA512_BLOCK_SIZE);
            wirePos      = WC_SHA512_BLOCK_SIZE;
            sha->buffLen = 0;
        }
    }

    if ((inLen - i) >= WC_SHA512_BLOCK_SIZE) {
        dmaBase = in + i;
        dmaSz   = ((inLen - i) / WC_SHA512_BLOCK_SIZE) * WC_SHA512_BLOCK_SIZE;
        i += dmaSz;
    }

    while (i < inLen) {
        shaBufferBytes[sha->buffLen++] = in[i++];
    }

    if (wirePos == 0 && dmaSz == 0) {
        return WH_ERROR_OK;
    }

    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = sha->hashType;
    req->input.sz             = dmaSz;
    req->input.addr           = 0;

    if (dmaSz > 0) {
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAddrAcquired  = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.sha.ioAddr     = inAddr;
        ctx->dma.asyncCtx.sha.clientAddr = (uintptr_t)dmaBase;
        ctx->dma.asyncCtx.sha.ioSz       = dmaSz;

        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
                wirePos,
            dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        *requestSent = true;
    }
    else {
        sha->buffLen = savedBuffLen;
        memcpy(shaBufferBytes, savedBuffer, savedBuffLen);
        if (inAddrAcquired) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.sha, 0, sizeof(ctx->dma.asyncCtx.sha));
    }
    return ret;
}

int wh_Client_Sha512DmaUpdateResponse(whClientContext* ctx, wc_Sha512* sha)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                ret = WH_ERROR_ABORTED;
            }
            /* Family check, not variant match: SHA-512/t shares block size and
             * compression with SHA-512, and the client supplies the variant IV
             * in resumeState.hash — so a server missing SHA-512/t support still
             * returns a correct intermediate state. */
            else if (resp->hashType != WC_HASH_TYPE_SHA512 &&
                     resp->hashType != WC_HASH_TYPE_SHA512_224 &&
                     resp->hashType != WC_HASH_TYPE_SHA512_256) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(sha->digest, resp->hash, WC_SHA512_DIGEST_SIZE);
                sha->hiLen = resp->hiLen;
                sha->loLen = resp->loLen;
            }
        }
    }

    if (ctx->dma.asyncCtx.sha.ioSz > 0) {
        uintptr_t ioAddr = ctx->dma.asyncCtx.sha.ioAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.sha.clientAddr, (void**)&ioAddr,
            ctx->dma.asyncCtx.sha.ioSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.sha.ioSz = 0;
    }
    return ret;
}

int wh_Client_Sha512DmaFinalRequest(whClientContext* ctx, wc_Sha512* sha)
{
    int                               ret     = WH_ERROR_OK;
    uint8_t*                          dataPtr = NULL;
    whMessageCrypto_Sha512DmaRequest* req     = NULL;
    uint8_t*                          inlineData;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Fail-fast on occupied transport to prevent modification to local state */
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    if (sha->buffLen >= WC_SHA512_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha512DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA512, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->buffLen;
    memcpy(req->resumeState.hash, sha->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha->hiLen;
    req->resumeState.loLen    = sha->loLen;
    req->resumeState.hashType = sha->hashType;
    req->input.sz             = 0;
    req->input.addr           = 0;

    if (sha->buffLen > 0) {
        memcpy(inlineData, sha->buffer, sha->buffLen);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO_DMA,
                                WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->buffLen,
                                dataPtr);
    return ret;
}

int wh_Client_Sha512DmaFinalResponse(whClientContext* ctx, wc_Sha512* sha,
                                     uint8_t* out)
{
    int                              ret      = WH_ERROR_OK;
    uint8_t*                         dataPtr  = NULL;
    whMessageCrypto_Sha2DmaResponse* resp     = NULL;
    uint16_t                         respSz   = 0;
    int                              hashType = 0;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret =
            _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz < sizeof(whMessageCrypto_GenericResponseHeader) +
                             sizeof(*resp)) {
                return WH_ERROR_ABORTED;
            }
            /* keep hashtype before initialization */
            hashType = sha->hashType;
            /* Family check, not variant match: SHA-512/t shares block size and
             * compression with SHA-512; the client supplies the variant IV in
             * resumeState.hash and the switch below truncates by hashType, so a
             * server missing SHA-512/t support still yields a correct digest.
             */
            if (resp->hashType != WC_HASH_TYPE_SHA512 &&
                resp->hashType != WC_HASH_TYPE_SHA512_224 &&
                resp->hashType != WC_HASH_TYPE_SHA512_256) {
                return WH_ERROR_ABORTED;
            }
            /* reset the state of the sha context (without blowing away devId
             *  and hashType), and copy only the digest bytes for the active
             *  variant */
            switch (hashType) {
#ifndef WOLFSSL_NOSHA512_224
                case WC_HASH_TYPE_SHA512_224:
                    memcpy(out, resp->hash, WC_SHA512_224_DIGEST_SIZE);
                    (void)wc_InitSha512_224_ex(sha, NULL, sha->devId);
                    break;
#endif
#ifndef WOLFSSL_NOSHA512_256
                case WC_HASH_TYPE_SHA512_256:
                    memcpy(out, resp->hash, WC_SHA512_256_DIGEST_SIZE);
                    (void)wc_InitSha512_256_ex(sha, NULL, sha->devId);
                    break;
#endif
                default:
                    memcpy(out, resp->hash, WC_SHA512_DIGEST_SIZE);
                    (void)wc_InitSha512_ex(sha, NULL, sha->devId);
                    break;
            }
        }
    }
    return ret;
}

int wh_Client_Sha512Dma(whClientContext* ctx, wc_Sha512* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int ret = WH_ERROR_OK;

    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret = wh_Client_Sha512DmaUpdateRequest(ctx, sha, in, inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = wh_Client_Sha512DmaUpdateResponse(ctx, sha);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = wh_Client_Sha512DmaFinalRequest(ctx, sha);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_Sha512DmaFinalResponse(ctx, sha, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA  */
#endif /* WOLFSSL_SHA512 */

#if defined(WOLFSSL_SHA3)
/* SHA3 - all four variants (224/256/384/512) share the wc_Sha3 struct and
 * the same wire format. Per-variant differences (block size, digest size,
 * Update/Final functions) are passed via a small dispatch table. */

typedef struct {
    int      hashType; /* WC_HASH_TYPE_SHA3_* (also algoType on the wire) */
    uint32_t blockSize;
    uint32_t digestSize;
    uint32_t maxInlineSz;
    /* Only initFn is used client-side (context reset after Final). Update/Final
     * run on the server, so no update/final pointers are carried here. */
    int (*initFn)(wc_Sha3* sha, void* heap, int devId);
} whSha3Variant;

#ifndef WOLFSSL_NOSHA3_224
static const whSha3Variant whSha3_224 = {
    WC_HASH_TYPE_SHA3_224, WC_SHA3_224_BLOCK_SIZE, WC_SHA3_224_DIGEST_SIZE,
    WH_MESSAGE_CRYPTO_SHA3_224_MAX_INLINE_UPDATE_SZ, wc_InitSha3_224};
#endif
#ifndef WOLFSSL_NOSHA3_256
static const whSha3Variant whSha3_256 = {
    WC_HASH_TYPE_SHA3_256, WC_SHA3_256_BLOCK_SIZE, WC_SHA3_256_DIGEST_SIZE,
    WH_MESSAGE_CRYPTO_SHA3_256_MAX_INLINE_UPDATE_SZ, wc_InitSha3_256};
#endif
#ifndef WOLFSSL_NOSHA3_384
static const whSha3Variant whSha3_384 = {
    WC_HASH_TYPE_SHA3_384, WC_SHA3_384_BLOCK_SIZE, WC_SHA3_384_DIGEST_SIZE,
    WH_MESSAGE_CRYPTO_SHA3_384_MAX_INLINE_UPDATE_SZ, wc_InitSha3_384};
#endif
#ifndef WOLFSSL_NOSHA3_512
static const whSha3Variant whSha3_512 = {
    WC_HASH_TYPE_SHA3_512, WC_SHA3_512_BLOCK_SIZE, WC_SHA3_512_DIGEST_SIZE,
    WH_MESSAGE_CRYPTO_SHA3_512_MAX_INLINE_UPDATE_SZ, wc_InitSha3_512};
#endif

/* Maximum input absorbable by a single UpdateRequest: inline wire capacity
 * plus room left in the local partial-block buffer. */
static uint32_t _Sha3UpdatePerCallCapacity(const wc_Sha3*       sha,
                                           const whSha3Variant* v)
{
    return v->maxInlineSz + (uint32_t)(v->blockSize - 1u - sha->i);
}

/* Reject Keccak-mode contexts. The wire format carries only s[] and the
 * server re-inits the context, applying standard SHA-3 0x06 padding; a
 * Keccak-flagged context would silently produce a wrong digest. The cryptocb
 * path falls back to software for this case; the direct API has no fallback
 * so it must refuse the call. */
static int _Sha3RejectKeccak(const wc_Sha3* sha)
{
#ifdef WOLFSSL_HASH_FLAGS
    if (sha != NULL && (sha->flags & WC_HASH_SHA3_KECCAK256) != 0u) {
        return WH_ERROR_BADARGS;
    }
#else
    (void)sha;
#endif
    return WH_ERROR_OK;
}

static int _Sha3UpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                              const whSha3Variant* v, const uint8_t* in,
                              uint32_t inLen, bool* requestSent)
{
    int                          ret = 0;
    whMessageCrypto_Sha3Request* req = NULL;
    uint8_t*                     inlineData;
    uint8_t*                     dataPtr = NULL;
    uint32_t                     capacity;
    uint32_t                     wirePos = 0;
    uint32_t                     i       = 0;
    /* Snapshot of partial buffer for rollback if SendRequest fails */
    uint32_t savedI;
    uint8_t  savedT[WC_SHA3_224_BLOCK_SIZE]; /* largest block size: 144 */

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    ret = _Sha3RejectKeccak(sha);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (sha->i >= v->blockSize) {
        return WH_ERROR_BADARGS;
    }

    capacity = _Sha3UpdatePerCallCapacity(sha, v);
    if (inLen > capacity) {
        return WH_ERROR_BADARGS;
    }
    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha3Request*)_createCryptoRequest(
        dataPtr, v->hashType, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    savedI = sha->i;
    memcpy(savedT, sha->t, sha->i);

    /* Top up the local partial buffer. If it completes a full block, copy
     * the assembled block as the first inline block. */
    if (sha->i > 0) {
        while (i < inLen && sha->i < v->blockSize) {
            sha->t[sha->i++] = in[i++];
        }
        if (sha->i == v->blockSize) {
            memcpy(inlineData + wirePos, sha->t, v->blockSize);
            wirePos += v->blockSize;
            sha->i = 0;
        }
    }

    /* Pack as many whole input blocks as will fit inline. */
    while ((inLen - i) >= v->blockSize &&
           (wirePos + v->blockSize) <= v->maxInlineSz) {
        memcpy(inlineData + wirePos, in + i, v->blockSize);
        wirePos += v->blockSize;
        i += v->blockSize;
    }

    /* Stash remaining tail bytes locally. */
    while (i < inLen) {
        sha->t[sha->i++] = in[i++];
    }

    /* Pure buffer-fill update: nothing to send. */
    if (wirePos == 0) {
        return WH_ERROR_OK;
    }

    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.s, sha->s, sizeof(req->resumeState.s));

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + wirePos,
                                dataPtr);
    if (ret == 0) {
        *requestSent = true;
    }
    else {
        /* Restore partial buffer on failure so caller can retry. */
        sha->i = savedI;
        memcpy(sha->t, savedT, savedI);
    }
    return ret;
}

static int _Sha3UpdateResponse(whClientContext* ctx, wc_Sha3* sha,
                               const whSha3Variant* v)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret    = 0;
    whMessageCrypto_Sha3Response* res    = NULL;
    uint8_t*                      dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, v->hashType, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz <
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        memcpy(sha->s, res->resumeState.s, sizeof(sha->s));
    }
    return ret;
}

static int _Sha3FinalRequest(whClientContext* ctx, wc_Sha3* sha,
                             const whSha3Variant* v)
{
    int                          ret;
    whMessageCrypto_Sha3Request* req;
    uint8_t*                     inlineData;
    uint8_t*                     dataPtr;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    ret = _Sha3RejectKeccak(sha);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    if (sha->i >= v->blockSize) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha3Request*)_createCryptoRequest(
        dataPtr, v->hashType, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->i;
    memcpy(req->resumeState.s, sha->s, sizeof(req->resumeState.s));
    if (sha->i > 0) {
        memcpy(inlineData, sha->t, sha->i);
    }

    ret = wh_Client_SendRequest(ctx, WH_MESSAGE_GROUP_CRYPTO, WC_ALGO_TYPE_HASH,
                                sizeof(whMessageCrypto_GenericRequestHeader) +
                                    sizeof(*req) + sha->i,
                                dataPtr);
    return ret;
}

static int _Sha3FinalResponse(whClientContext* ctx, wc_Sha3* sha,
                              const whSha3Variant* v, uint8_t* out)
{
    uint16_t                      group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action = WH_MESSAGE_ACTION_NONE;
    uint16_t                      dataSz = 0;
    int                           ret;
    whMessageCrypto_Sha3Response* res = NULL;
    uint8_t*                      dataPtr;
    void*                         savedHeap;
    int                           savedDevId;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret != 0) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, v->hashType, (uint8_t**)&res);
    if (ret >= 0) {
        if (dataSz <
            sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*res)) {
            return WH_ERROR_ABORTED;
        }
        memcpy(out, res->hash, v->digestSize);
        /* Reset state, preserving heap and devId. */
        savedHeap  = sha->heap;
        savedDevId = sha->devId;
        (void)v->initFn(sha, savedHeap, savedDevId);
    }
    return ret;
}

/* Snapshot of the streaming state the offload path mutates: the Keccak
 * state and the locally buffered partial block. */
typedef struct {
    uint64_t s[25];
    uint8_t  t[WC_SHA3_224_BLOCK_SIZE]; /* largest block size: 144 */
    uint32_t i;
} _Sha3SavedState;

static void _Sha3SaveState(const wc_Sha3* sha, _Sha3SavedState* saved)
{
    saved->i = sha->i;
    memcpy(saved->s, sha->s, sizeof(saved->s));
    memcpy(saved->t, sha->t, sizeof(saved->t));
}

static void _Sha3RestoreState(wc_Sha3* sha, const _Sha3SavedState* saved)
{
    sha->i = (uint8_t)saved->i;
    memcpy(sha->s, saved->s, sizeof(saved->s));
    memcpy(sha->t, saved->t, sizeof(saved->t));
}

static int _Sha3Oneshot(whClientContext* ctx, wc_Sha3* sha,
                        const whSha3Variant* v, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int             ret = WH_ERROR_OK;
    _Sha3SavedState saved;

    /* _Sha3UpdatePerCallCapacity (below) reads sha->i, so validate sha here
     * rather than relying on the lower-level helper's NULL check. */
    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Mirror _Sha3UpdateRequest's invariant: skipping the update branch on
     * (in == NULL && inLen != 0) would silently digest the current state. */
    if (in == NULL && inLen != 0) {
        return WH_ERROR_BADARGS;
    }

    /* A server without SHA3 answers NOT_COMPILED_IN, which wolfCrypt maps to
     * CRYPTOCB_UNAVAILABLE and re-hashes the same input in software. Snapshot
     * so that fallback cannot absorb any of it twice. */
    _Sha3SaveState(sha, &saved);

    if (in != NULL && inLen > 0) {
        uint32_t consumed = 0;
        while (ret == WH_ERROR_OK && consumed < inLen) {
            uint32_t capacity  = _Sha3UpdatePerCallCapacity(sha, v);
            uint32_t remaining = inLen - consumed;
            uint32_t chunk     = (remaining < capacity) ? remaining : capacity;
            bool     sent      = false;

            ret = _Sha3UpdateRequest(ctx, sha, v, in + consumed, chunk, &sent);
            if (ret != WH_ERROR_OK) {
                break;
            }
            if (sent) {
                do {
                    ret = _Sha3UpdateResponse(ctx, sha, v);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret != WH_ERROR_OK) {
                    break;
                }
            }
            consumed += chunk;
        }
    }

    if (ret == WH_ERROR_OK && out != NULL) {
        ret = _Sha3FinalRequest(ctx, sha, v);
        if (ret == WH_ERROR_OK) {
            do {
                ret = _Sha3FinalResponse(ctx, sha, v, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    /* Leave sha as the caller passed it so a fallback starts clean. */
    if (ret != WH_ERROR_OK) {
        _Sha3RestoreState(sha, &saved);
    }

    return ret;
}

/* Per-variant public APIs - thin wrappers over the shared helpers. */

#ifndef WOLFSSL_NOSHA3_224
int wh_Client_Sha3_224(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                       uint32_t inLen, uint8_t* out)
{
    return _Sha3Oneshot(ctx, sha, &whSha3_224, in, inLen, out);
}

int wh_Client_Sha3_224UpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                    const uint8_t* in, uint32_t inLen,
                                    bool* requestSent)
{
    return _Sha3UpdateRequest(ctx, sha, &whSha3_224, in, inLen, requestSent);
}

int wh_Client_Sha3_224UpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3UpdateResponse(ctx, sha, &whSha3_224);
}

int wh_Client_Sha3_224FinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3FinalRequest(ctx, sha, &whSha3_224);
}

int wh_Client_Sha3_224FinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                    uint8_t* out)
{
    return _Sha3FinalResponse(ctx, sha, &whSha3_224, out);
}
#endif /* !WOLFSSL_NOSHA3_224 */

#ifndef WOLFSSL_NOSHA3_256
int wh_Client_Sha3_256(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                       uint32_t inLen, uint8_t* out)
{
    return _Sha3Oneshot(ctx, sha, &whSha3_256, in, inLen, out);
}

int wh_Client_Sha3_256UpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                    const uint8_t* in, uint32_t inLen,
                                    bool* requestSent)
{
    return _Sha3UpdateRequest(ctx, sha, &whSha3_256, in, inLen, requestSent);
}

int wh_Client_Sha3_256UpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3UpdateResponse(ctx, sha, &whSha3_256);
}

int wh_Client_Sha3_256FinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3FinalRequest(ctx, sha, &whSha3_256);
}

int wh_Client_Sha3_256FinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                    uint8_t* out)
{
    return _Sha3FinalResponse(ctx, sha, &whSha3_256, out);
}
#endif /* !WOLFSSL_NOSHA3_256 */

#ifndef WOLFSSL_NOSHA3_384
int wh_Client_Sha3_384(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                       uint32_t inLen, uint8_t* out)
{
    return _Sha3Oneshot(ctx, sha, &whSha3_384, in, inLen, out);
}

int wh_Client_Sha3_384UpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                    const uint8_t* in, uint32_t inLen,
                                    bool* requestSent)
{
    return _Sha3UpdateRequest(ctx, sha, &whSha3_384, in, inLen, requestSent);
}

int wh_Client_Sha3_384UpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3UpdateResponse(ctx, sha, &whSha3_384);
}

int wh_Client_Sha3_384FinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3FinalRequest(ctx, sha, &whSha3_384);
}

int wh_Client_Sha3_384FinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                    uint8_t* out)
{
    return _Sha3FinalResponse(ctx, sha, &whSha3_384, out);
}
#endif /* !WOLFSSL_NOSHA3_384 */

#ifndef WOLFSSL_NOSHA3_512
int wh_Client_Sha3_512(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                       uint32_t inLen, uint8_t* out)
{
    return _Sha3Oneshot(ctx, sha, &whSha3_512, in, inLen, out);
}

int wh_Client_Sha3_512UpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                    const uint8_t* in, uint32_t inLen,
                                    bool* requestSent)
{
    return _Sha3UpdateRequest(ctx, sha, &whSha3_512, in, inLen, requestSent);
}

int wh_Client_Sha3_512UpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3UpdateResponse(ctx, sha, &whSha3_512);
}

int wh_Client_Sha3_512FinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3FinalRequest(ctx, sha, &whSha3_512);
}

int wh_Client_Sha3_512FinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                    uint8_t* out)
{
    return _Sha3FinalResponse(ctx, sha, &whSha3_512, out);
}
#endif /* !WOLFSSL_NOSHA3_512 */

#ifdef WOLFHSM_CFG_DMA
/* SHA3 DMA helpers - inline first block (assembled from partial buffer) plus
 * whole-block DMA input. Final goes inline-only. */

static int _Sha3DmaUpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                 const whSha3Variant* v, const uint8_t* in,
                                 uint32_t inLen, bool* requestSent)
{
    int                             ret     = WH_ERROR_OK;
    uint8_t*                        dataPtr = NULL;
    whMessageCrypto_Sha3DmaRequest* req     = NULL;
    uint8_t*                        inlineData;
    uint32_t                        wirePos        = 0;
    uint32_t                        i              = 0;
    uintptr_t                       inAddr         = 0;
    bool                            inAddrAcquired = false;
    const uint8_t*                  dmaBase        = NULL;
    uint32_t                        dmaSz          = 0;
    uint32_t                        savedI;
    uint8_t                         savedT[WC_SHA3_224_BLOCK_SIZE];

    if (ctx == NULL || sha == NULL || requestSent == NULL ||
        (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }
    *requestSent = false;

    ret = _Sha3RejectKeccak(sha);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }

    if (sha->i >= v->blockSize) {
        return WH_ERROR_BADARGS;
    }
    if (inLen == 0) {
        return WH_ERROR_OK;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha3DmaRequest*)_createCryptoRequest(
        dataPtr, v->hashType, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    savedI = sha->i;
    memcpy(savedT, sha->t, sha->i);

    if (sha->i > 0) {
        while (i < inLen && sha->i < v->blockSize) {
            sha->t[sha->i++] = in[i++];
        }
        if (sha->i == v->blockSize) {
            memcpy(inlineData, sha->t, v->blockSize);
            wirePos = v->blockSize;
            sha->i  = 0;
        }
    }

    if ((inLen - i) >= v->blockSize) {
        dmaBase = in + i;
        dmaSz   = ((inLen - i) / v->blockSize) * v->blockSize;
        i += dmaSz;
    }

    while (i < inLen) {
        sha->t[sha->i++] = in[i++];
    }

    if (wirePos == 0 && dmaSz == 0) {
        return WH_ERROR_OK;
    }

    req->isLastBlock = 0;
    req->inSz        = wirePos;
    memcpy(req->resumeState.s, sha->s, sizeof(req->resumeState.s));
    req->input.sz   = dmaSz;
    req->input.addr = 0;

    if (dmaSz > 0) {
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            inAddrAcquired  = true;
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK) {
        ctx->dma.asyncCtx.sha.ioAddr     = inAddr;
        ctx->dma.asyncCtx.sha.clientAddr = (uintptr_t)dmaBase;
        ctx->dma.asyncCtx.sha.ioSz       = dmaSz;

        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
                wirePos,
            dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        *requestSent = true;
    }
    else {
        sha->i = savedI;
        memcpy(sha->t, savedT, savedI);
        if (inAddrAcquired) {
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)dmaBase, (void**)&inAddr, dmaSz,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        memset(&ctx->dma.asyncCtx.sha, 0, sizeof(ctx->dma.asyncCtx.sha));
    }
    return ret;
}

static int _Sha3DmaUpdateResponse(whClientContext* ctx, wc_Sha3* sha,
                                  const whSha3Variant* v)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha3DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, v->hashType, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz <
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*resp)) {
                ret = WH_ERROR_ABORTED;
            }
            else {
                memcpy(sha->s, resp->resumeState.s, sizeof(sha->s));
            }
        }
    }

    if (ctx->dma.asyncCtx.sha.ioSz > 0) {
        uintptr_t ioAddr = ctx->dma.asyncCtx.sha.ioAddr;
        (void)wh_Client_DmaProcessClientAddress(
            ctx, ctx->dma.asyncCtx.sha.clientAddr, (void**)&ioAddr,
            ctx->dma.asyncCtx.sha.ioSz, WH_DMA_OPER_CLIENT_READ_POST,
            (whDmaFlags){0});
        ctx->dma.asyncCtx.sha.ioSz = 0;
    }
    return ret;
}

static int _Sha3DmaFinalRequest(whClientContext* ctx, wc_Sha3* sha,
                                const whSha3Variant* v)
{
    int                             ret     = WH_ERROR_OK;
    uint8_t*                        dataPtr = NULL;
    whMessageCrypto_Sha3DmaRequest* req     = NULL;
    uint8_t*                        inlineData;

    if (ctx == NULL || sha == NULL) {
        return WH_ERROR_BADARGS;
    }
    ret = _Sha3RejectKeccak(sha);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    if (wh_CommClient_IsRequestPending(ctx->comm) == 1) {
        return WH_ERROR_REQUEST_PENDING;
    }
    if (sha->i >= v->blockSize) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_Sha3DmaRequest*)_createCryptoRequest(
        dataPtr, v->hashType, ctx->cryptoAffinity);
    inlineData = (uint8_t*)(req + 1);

    req->isLastBlock = 1;
    req->inSz        = sha->i;
    memcpy(req->resumeState.s, sha->s, sizeof(req->resumeState.s));
    req->input.sz   = 0;
    req->input.addr = 0;

    if (sha->i > 0) {
        memcpy(inlineData, sha->t, sha->i);
    }

    ret = wh_Client_SendRequest(
        ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_HASH,
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) + sha->i,
        dataPtr);
    return ret;
}

static int _Sha3DmaFinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                 const whSha3Variant* v, uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha3DmaResponse* resp    = NULL;
    uint16_t                         respSz  = 0;
    void*                            savedHeap;
    int                              savedDevId;

    if (ctx == NULL || sha == NULL || out == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                 WOLFHSM_CFG_COMM_DATA_LEN, dataPtr);
    if (ret == WH_ERROR_NOTREADY) {
        return ret;
    }

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, v->hashType, (uint8_t**)&resp);
        if (ret >= 0) {
            if (respSz <
                sizeof(whMessageCrypto_GenericResponseHeader) + sizeof(*resp)) {
                return WH_ERROR_ABORTED;
            }
            memcpy(out, resp->hash, v->digestSize);
            savedHeap  = sha->heap;
            savedDevId = sha->devId;
            (void)v->initFn(sha, savedHeap, savedDevId);
        }
    }
    return ret;
}

static int _Sha3DmaOneshot(whClientContext* ctx, wc_Sha3* sha,
                           const whSha3Variant* v, const uint8_t* in,
                           uint32_t inLen, uint8_t* out)
{
    int             ret = WH_ERROR_OK;
    _Sha3SavedState saved;

    /* Mirror _Sha3DmaUpdateRequest's invariant: skipping the update branch on
     * (in == NULL && inLen != 0) would silently digest the current state.
     * sha is validated here since _Sha3SaveState dereferences it below. */
    if (sha == NULL || (in == NULL && inLen != 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Same fallback hazard as _Sha3Oneshot: snapshot before mutating. */
    _Sha3SaveState(sha, &saved);

    if (in != NULL && inLen > 0) {
        bool sent = false;
        ret       = _Sha3DmaUpdateRequest(ctx, sha, v, in, inLen, &sent);
        if (ret == WH_ERROR_OK && sent) {
            do {
                ret = _Sha3DmaUpdateResponse(ctx, sha, v);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }
    if (ret == WH_ERROR_OK && out != NULL) {
        ret = _Sha3DmaFinalRequest(ctx, sha, v);
        if (ret == WH_ERROR_OK) {
            do {
                ret = _Sha3DmaFinalResponse(ctx, sha, v, out);
            } while (ret == WH_ERROR_NOTREADY);
        }
    }

    /* Leave sha as the caller passed it so a fallback starts clean. */
    if (ret != WH_ERROR_OK) {
        _Sha3RestoreState(sha, &saved);
    }

    return ret;
}

/* Per-variant DMA public APIs - thin wrappers over the shared DMA helpers. */

#ifndef WOLFSSL_NOSHA3_224
int wh_Client_Sha3_224Dma(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                          uint32_t inLen, uint8_t* out)
{
    return _Sha3DmaOneshot(ctx, sha, &whSha3_224, in, inLen, out);
}

int wh_Client_Sha3_224DmaUpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                       const uint8_t* in, uint32_t inLen,
                                       bool* requestSent)
{
    return _Sha3DmaUpdateRequest(ctx, sha, &whSha3_224, in, inLen, requestSent);
}

int wh_Client_Sha3_224DmaUpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaUpdateResponse(ctx, sha, &whSha3_224);
}

int wh_Client_Sha3_224DmaFinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaFinalRequest(ctx, sha, &whSha3_224);
}

int wh_Client_Sha3_224DmaFinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                       uint8_t* out)
{
    return _Sha3DmaFinalResponse(ctx, sha, &whSha3_224, out);
}
#endif /* !WOLFSSL_NOSHA3_224 */

#ifndef WOLFSSL_NOSHA3_256
int wh_Client_Sha3_256Dma(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                          uint32_t inLen, uint8_t* out)
{
    return _Sha3DmaOneshot(ctx, sha, &whSha3_256, in, inLen, out);
}

int wh_Client_Sha3_256DmaUpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                       const uint8_t* in, uint32_t inLen,
                                       bool* requestSent)
{
    return _Sha3DmaUpdateRequest(ctx, sha, &whSha3_256, in, inLen, requestSent);
}

int wh_Client_Sha3_256DmaUpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaUpdateResponse(ctx, sha, &whSha3_256);
}

int wh_Client_Sha3_256DmaFinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaFinalRequest(ctx, sha, &whSha3_256);
}

int wh_Client_Sha3_256DmaFinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                       uint8_t* out)
{
    return _Sha3DmaFinalResponse(ctx, sha, &whSha3_256, out);
}
#endif /* !WOLFSSL_NOSHA3_256 */

#ifndef WOLFSSL_NOSHA3_384
int wh_Client_Sha3_384Dma(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                          uint32_t inLen, uint8_t* out)
{
    return _Sha3DmaOneshot(ctx, sha, &whSha3_384, in, inLen, out);
}

int wh_Client_Sha3_384DmaUpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                       const uint8_t* in, uint32_t inLen,
                                       bool* requestSent)
{
    return _Sha3DmaUpdateRequest(ctx, sha, &whSha3_384, in, inLen, requestSent);
}

int wh_Client_Sha3_384DmaUpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaUpdateResponse(ctx, sha, &whSha3_384);
}

int wh_Client_Sha3_384DmaFinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaFinalRequest(ctx, sha, &whSha3_384);
}

int wh_Client_Sha3_384DmaFinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                       uint8_t* out)
{
    return _Sha3DmaFinalResponse(ctx, sha, &whSha3_384, out);
}
#endif /* !WOLFSSL_NOSHA3_384 */

#ifndef WOLFSSL_NOSHA3_512
int wh_Client_Sha3_512Dma(whClientContext* ctx, wc_Sha3* sha, const uint8_t* in,
                          uint32_t inLen, uint8_t* out)
{
    return _Sha3DmaOneshot(ctx, sha, &whSha3_512, in, inLen, out);
}

int wh_Client_Sha3_512DmaUpdateRequest(whClientContext* ctx, wc_Sha3* sha,
                                       const uint8_t* in, uint32_t inLen,
                                       bool* requestSent)
{
    return _Sha3DmaUpdateRequest(ctx, sha, &whSha3_512, in, inLen, requestSent);
}

int wh_Client_Sha3_512DmaUpdateResponse(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaUpdateResponse(ctx, sha, &whSha3_512);
}

int wh_Client_Sha3_512DmaFinalRequest(whClientContext* ctx, wc_Sha3* sha)
{
    return _Sha3DmaFinalRequest(ctx, sha, &whSha3_512);
}

int wh_Client_Sha3_512DmaFinalResponse(whClientContext* ctx, wc_Sha3* sha,
                                       uint8_t* out)
{
    return _Sha3DmaFinalResponse(ctx, sha, &whSha3_512, out);
}
#endif /* !WOLFSSL_NOSHA3_512 */
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_SHA3 */

#ifdef WOLFSSL_HAVE_MLDSA

int wh_Client_MlDsaSetKeyId(wc_MlDsaKey* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);

    return WH_ERROR_OK;
}

int wh_Client_MlDsaGetKeyId(wc_MlDsaKey* key, whKeyId* outId)
{
    if (key == NULL || outId == NULL) {
        return WH_ERROR_BADARGS;
    }

    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);

    return WH_ERROR_OK;
}

int wh_Client_MlDsaImportKey(whClientContext* ctx, wc_MlDsaKey* key,
                             whKeyId* inout_keyId, whNvmFlags flags,
                             uint16_t label_len, uint8_t* label)
{
    int      ret    = WH_ERROR_OK;
    whKeyId  key_id = WH_KEYID_ERASED;
    byte     buffer[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    uint16_t buffer_len = 0;

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    ret = wh_Crypto_MlDsaSerializeKeyDer(key, sizeof(buffer), buffer,
                                         &buffer_len);
    WH_DEBUG_CLIENT_VERBOSE("serialize ret:%d, key:%p, max_size:%u, buffer:%p, "
           "outlen:%u\n",
           ret, key, (unsigned int)sizeof(buffer), buffer,
           buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

    WH_DEBUG_CLIENT_VERBOSE("label:%.*s ret:%d keyid:%u\n", label_len,
           label, ret, key_id);
    return ret;
}

int wh_Client_MlDsaExportKey(whClientContext* ctx, whKeyId keyId, wc_MlDsaKey* key,
                             uint16_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    /* buffer cannot be larger than MTU */
    byte     buffer[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Now export the DER key from the server */
    ret =
        wh_Client_KeyExport(ctx, keyId, label, label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Update the key structure */
        ret = wh_Crypto_MlDsaDeserializeKeyDer(buffer, buffer_len, key);
    }

    WH_DEBUG_CLIENT_VERBOSE("keyid:%x key:%p ret:%d label:%.*s\n", keyId,
           key, ret, (int)label_len, label);
    return ret;
}

int wh_Client_MlDsaExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                   wc_MlDsaKey* key, uint16_t label_len,
                                   uint8_t* label)
{
    int      ret;
    byte     buffer[MAX_PUBLIC_KEY_SZ] = {0};
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_MLDSA, label,
                                    label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlDsaDeserializeKeyDer(buffer, buffer_len, key);
    }
    return ret;
}

static int _MlDsaMakeKey(whClientContext* ctx, int size, int level,
                         whKeyId* inout_key_id, whNvmFlags flags,
                         uint16_t label_len, const uint8_t* label, wc_MlDsaKey* key)
{
    int                                  ret     = WH_ERROR_OK;
    whKeyId                              key_id  = WH_KEYID_ERASED;
    uint8_t*                             dataPtr = NULL;
    whMessageCrypto_MlDsaKeyGenRequest*  req     = NULL;
    whMessageCrypto_MlDsaKeyGenResponse* res     = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_MlDsaKeyGenRequest*)_createCryptoRequestWithSubtype(
        dataPtr, WC_PK_TYPE_PQC_SIG_KEYGEN, WC_PQC_SIG_TYPE_MLDSA,
        ctx->cryptoAffinity);

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* No other calls before here, so this is always true */
    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;

        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            memset(req, 0, sizeof(*req));
            req->level = level;
            req->sz    = size;
            req->flags = flags;
            req->keyId = key_id;
            if ((label != NULL) && (label_len > 0)) {
                if (label_len > WH_NVM_LABEL_LEN) {
                    label_len = WH_NVM_LABEL_LEN;
                }
                memcpy(req->label, label, label_len);
            }

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            WH_DEBUG_CLIENT_VERBOSE("Req sent:size:%u, ret:%d\n",
                   (unsigned int)req->sz, ret);
            if (ret == 0) {
                uint16_t res_len;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_SIG_KEYGEN,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        WH_DEBUG_CLIENT_VERBOSE(
                            "Res recv:keyid:%u, len:%u, ret:%d\n",
                            (unsigned int)res->keyId,
                            (unsigned int)res->len, ret);
                        /* Key is cached on server or is ephemeral */
                        key_id = (whKeyId)(res->keyId);

                        /* Update output variable if requested */
                        if (inout_key_id != NULL) {
                            *inout_key_id = key_id;
                        }

                        /* Update the context if provided */
                        if (key != NULL) {
                            uint16_t     der_size = (uint16_t)(res->len);
                            const size_t hdr_sz =
                                sizeof(whMessageCrypto_GenericResponseHeader) +
                                sizeof(*res);
                            /* Set the key_id. ERASED for EPHEMERAL, cached id
                             * otherwise. */
                            wh_Client_MlDsaSetKeyId(key, key_id);

                            /* Response carries the exported key (EPHEMERAL) or
                             * the public key (cached keygen). An empty body
                             * means the caller requested key material the server
                             * did not return; also reject a length that does not
                             * fit the received frame before deserializing. */
                            if (der_size == 0) {
                                ret = WH_ERROR_ABORTED;
                            }
                            else if ((res_len < hdr_sz) ||
                                     (res->len > (res_len - hdr_sz))) {
                                ret = WH_ERROR_ABORTED;
                            }
                            else {
                                uint8_t* key_der = (uint8_t*)(res + 1);
                                ret = wh_Crypto_MlDsaDeserializeKeyDer(
                                    key_der, der_size, key);
                    WH_DEBUG_VERBOSE_HEXDUMP(
                                    "[client] ML-DSA KeyGen export:", key_der,
                                    der_size);
                            }
                        }
                    }
                }
            }
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }
    return ret;
}

int wh_Client_MlDsaMakeCacheKey(whClientContext* ctx, int size, int level,
                                whKeyId* inout_key_id, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label)
{
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlDsaMakeKey(ctx, size, level, inout_key_id, flags, label_len,
                         label, NULL);
}

int wh_Client_MlDsaMakeCacheKeyAndExportPublic(whClientContext* ctx, int size,
                                               int level,
                                               whKeyId* inout_key_id,
                                               whNvmFlags flags,
                                               uint16_t label_len,
                                               const uint8_t* label,
                                               wc_MlDsaKey* pub)
{
    int     ret;
    whKeyId in_keyId;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export path, not the cache path. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret = _MlDsaMakeKey(ctx, size, level, inout_key_id, flags, label_len, label,
                        pub);
    if (ret >= 0) {
        /* Stamp the cached keyId and the client's HSM devId so pub is
         * immediately usable as a handle to the cached private key. The keyId
         * is set here (not only inside _MlDsaMakeKey) because a public-key
         * deserialize that retries parameter sets can re-init pub and clear
         * it. */
        wh_Client_MlDsaSetKeyId(pub, *inout_key_id);
        pub->devId = WH_CLIENT_DEVID(ctx);
    }
    else if (!WH_KEYID_ISERASED(*inout_key_id) &&
             (WH_KEYID_ISERASED(in_keyId) || (ret == WH_ERROR_ABORTED))) {
        /* The server committed a key but the best-effort export returned no
         * public key (empty response body when it did not fit). Roll back so the
         * operation is atomic and no cache slot is orphaned. A non-DMA keygen
         * only yields WH_ERROR_ABORTED after the server has committed and
         * returned the keyId, so evicting is safe even when the caller supplied
         * an explicit keyId. */
        (void)wh_Client_KeyEvict(ctx, *inout_key_id);
        *inout_key_id = WH_KEYID_ERASED;
    }
    return ret;
}

int wh_Client_MlDsaMakeExportKey(whClientContext* ctx, int level, int size,
                                 wc_MlDsaKey* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlDsaMakeKey(ctx, size, level, NULL, WH_NVM_FLAGS_EPHEMERAL, 0,
                         NULL, key);
}


int wh_Client_MlDsaSign(whClientContext* ctx, const byte* in, word32 in_len,
                      byte* out, word32* inout_len, wc_MlDsaKey* key,
                      const byte* context, byte contextLen,
                      word32 preHashType)
{
    int                                ret     = 0;
    whMessageCrypto_MlDsaSignRequest*  req     = NULL;
    whMessageCrypto_MlDsaSignResponse* res     = NULL;
    uint8_t*                           dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    WH_DEBUG_CLIENT_VERBOSE("ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
           ctx, key, in, (unsigned)in_len, out, inout_len);

    if ((ctx == NULL) || (key == NULL) || ((in == NULL) && (in_len > 0)) ||
        (out == NULL) || (inout_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    WH_DEBUG_CLIENT_VERBOSE("keyid:%x, in_len:%u, inout_len:%p\n", key_id,
           in_len, inout_len);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempMlDsaSign";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_SIGN;

        ret = wh_Client_MlDsaImportKey(ctx, key, &key_id, flags,
                                       sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;

        uint32_t total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                             sizeof(*req) + in_len + contextLen;
        uint32_t options = 0;

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req =
            (whMessageCrypto_MlDsaSignRequest*)_createCryptoRequestWithSubtype(
                dataPtr, WC_PK_TYPE_PQC_SIG_SIGN, WC_PQC_SIG_TYPE_MLDSA,
                ctx->cryptoAffinity);

        if (total_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint16_t req_len = (uint16_t)total_len;
            uint8_t* req_data = (uint8_t*)(req + 1);
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options     = options;
            req->level       = key->level;
            req->keyId       = key_id;
            req->sz          = in_len;
            req->contextSz   = contextLen;
            req->preHashType = preHashType;
            if ((in != NULL) && (in_len > 0)) {
                memcpy(req_data, in, in_len);
            }
            if ((context != NULL) && (contextLen > 0)) {
                memcpy(req_data + in_len, context, contextLen);
            }

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;

                /* Response Message */
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_SIG_SIGN,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        const uint32_t hdr_sz =
                            sizeof(whMessageCrypto_GenericResponseHeader) +
                            sizeof(*res);
                        if (res_len < hdr_sz ||
                            res->sz > (res_len - hdr_sz)) {
                            ret = WH_ERROR_ABORTED;
                        }
                        else {
                            uint8_t* res_sig = (uint8_t*)(res + 1);
                            if (res->sz > *inout_len) {
                                ret = WH_ERROR_BUFFER_SIZE;
                            }
                            else {
                                memcpy(out, res_sig, res->sz);
                            }
                            *inout_len = res->sz;
                        }
                    }
                }
            }
        }
        else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    } /* Evict the key manually on error */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
    WH_DEBUG_CLIENT_VERBOSE("ret:%d\n", ret);
    return ret;
}

int wh_Client_MlDsaVerify(whClientContext* ctx, const byte* sig, word32 sig_len,
                         const byte* msg, word32 msg_len, int* out_res,
                         wc_MlDsaKey* key, const byte* context, byte contextLen,
                         word32 preHashType)
{
    int                                  ret     = WH_ERROR_OK;
    uint8_t*                             dataPtr = NULL;
    whMessageCrypto_MlDsaVerifyRequest*  req     = NULL;
    whMessageCrypto_MlDsaVerifyResponse* res     = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;


    WH_DEBUG_CLIENT_VERBOSE("ctx:%p key:%p, sig:%p sig_len:%u, msg:%p msg_len:%u "
           "out_res:%p\n",
           ctx, key, sig, sig_len, msg, msg_len, out_res);

    if ((ctx == NULL) || (key == NULL) || ((sig == NULL) && (sig_len > 0)) ||
        (out_res == NULL) || ((msg == NULL) && (msg_len > 0))) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempMlDsaVerify";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_VERIFY;

        ret = wh_Client_MlDsaImportKey(ctx, key, &key_id, flags,
                                       sizeof(keyLabel), keyLabel);
        if (ret == 0) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;

        uint32_t total_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                             sizeof(*req) + sig_len + msg_len + contextLen;


        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_MlDsaVerifyRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_SIG_VERIFY,
                                            WC_PQC_SIG_TYPE_MLDSA,
                                            ctx->cryptoAffinity);

        if (total_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint16_t req_len = (uint16_t)total_len;
            uint8_t* req_sig  = (uint8_t*)(req + 1);
            uint8_t* req_hash = req_sig + sig_len;

            /* Set request packet members */
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options     = options;
            req->level       = key->level;
            req->keyId       = key_id;
            req->sigSz       = sig_len;
            if ((sig != NULL) && (sig_len > 0)) {
                memcpy(req_sig, sig, sig_len);
            }
            req->hashSz      = msg_len;
            if ((msg != NULL) && (msg_len > 0)) {
                memcpy(req_hash, msg, msg_len);
            }
            req->contextSz   = contextLen;
            req->preHashType = preHashType;
            if ((context != NULL) && (contextLen > 0)) {
                memcpy(req_hash + msg_len, context, contextLen);
            }

            /* write request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);

            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict = 0;
                /* Response Message */
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret == 0) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_SIG_VERIFY,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        const uint32_t hdr_sz =
                            sizeof(whMessageCrypto_GenericResponseHeader) +
                            sizeof(*res);
                        /* Note whMessageCrypto_MlDsaVerifyResponse has no
                         * size field */
                        if (res_len < hdr_sz) {
                            ret = WH_ERROR_ABORTED;
                        }
                        else {
                            *out_res = res->res;
                        }
                    }
                }
            }
        }
        else {
            /* Request length is too long */
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
    WH_DEBUG_CLIENT_VERBOSE("ret:%d\n", ret);
    return ret;
}

int wh_Client_MlDsaCheckPrivKey(whClientContext* ctx, wc_MlDsaKey* key,
                                const byte* pubKey, word32 pubKeySz)
{
    /* TODO */
    (void)ctx;
    (void)key;
    (void)pubKey;
    (void)pubKeySz;
    return WH_ERROR_NOHANDLER;
}


#ifdef WOLFHSM_CFG_DMA

int wh_Client_MlDsaImportKeyDma(whClientContext* ctx, wc_MlDsaKey* key,
                                whKeyId* inout_keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label)
{
    int      ret    = WH_ERROR_OK;
    whKeyId  key_id = WH_KEYID_ERASED;
    byte     buffer[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    uint16_t buffer_len = 0;

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    /* Serialize the key to a temporary buffer first */
    ret = wh_Crypto_MlDsaSerializeKeyDer(key, sizeof(buffer), buffer,
                                         &buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Cache the key using DMA and get the keyID */
        ret = wh_Client_KeyCacheDma(ctx, flags, label, label_len, buffer,
                                    buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

    return ret;
}

int wh_Client_MlDsaExportKeyDma(whClientContext* ctx, whKeyId keyId,
                                wc_MlDsaKey* key, uint16_t label_len,
                                uint8_t* label)
{
    int      ret                                = WH_ERROR_OK;
    byte     buffer[MLDSA_MAX_BOTH_KEY_DER_SIZE] = {0};
    uint16_t buffer_len                         = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Export the key from server using DMA */
    ret = wh_Client_KeyExportDma(ctx, keyId, buffer, buffer_len, label,
                                 label_len, &buffer_len);
    if (ret == WH_ERROR_OK) {
        /* Deserialize the key */
        ret = wh_Crypto_MlDsaDeserializeKeyDer(buffer, buffer_len, key);
    }

    return ret;
}

int wh_Client_MlDsaExportPublicKeyDma(whClientContext* ctx, whKeyId keyId,
                                      wc_MlDsaKey* key, uint16_t label_len,
                                      uint8_t* label)
{
    int      ret;
    byte     buffer[MLDSA_MAX_BOTH_KEY_DER_SIZE] = {0};
    uint16_t buffer_len                              = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_MLDSA, buffer,
                                       buffer_len, label, label_len,
                                       &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlDsaDeserializeKeyDer(buffer, buffer_len, key);
    }
    return ret;
}

static int _MlDsaMakeKeyDma(whClientContext* ctx, int level,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, const uint8_t* label, wc_MlDsaKey* key)
{
    int                                     ret    = WH_ERROR_OK;
    whKeyId                                 key_id = WH_KEYID_ERASED;
    byte                                    buffer[MLDSA_MAX_BOTH_KEY_DER_SIZE];
    uint8_t*                                dataPtr = NULL;
    whMessageCrypto_MlDsaKeyGenDmaRequest*  req     = NULL;
    whMessageCrypto_MlDsaKeyGenDmaResponse* res     = NULL;
    uintptr_t                               keyAddr   = 0;
    uint64_t                                keyAddrSz = 0;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req =
        (whMessageCrypto_MlDsaKeyGenDmaRequest*)_createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_SIG_KEYGEN, WC_PQC_SIG_TYPE_MLDSA,
            ctx->cryptoAffinity);

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Request Message */
    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint16_t action = WC_ALGO_TYPE_PK;

    uint16_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
        memset(req, 0, sizeof(*req));
        req->level    = level;
        req->flags    = flags;
        req->keyId    = key_id;
        req->key.sz = keyAddrSz = sizeof(buffer);

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)buffer, (void**)&keyAddr, keyAddrSz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->key.addr = (uint64_t)(uintptr_t)keyAddr;
        }

        if ((label != NULL) && (label_len > 0)) {
            if (label_len > WH_NVM_LABEL_LEN) {
                label_len = WH_NVM_LABEL_LEN;
            }
            memcpy(req->label, label, label_len);
            req->labelSize = label_len;
        }

        uint16_t res_len = 0;
        if (ret == WH_ERROR_OK) {
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)buffer, (void**)&keyAddr, keyAddrSz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_SIG_KEYGEN,
                                     (uint8_t**)&res);
            /* wolfCrypt allows positive error codes on success in some
             * scenarios */
            if (ret >= 0) {
                const uint32_t hdr_sz =
                    sizeof(whMessageCrypto_GenericResponseHeader) +
                    sizeof(*res);
                /* Note whMessageCrypto_MlDsaKeyGenDmaResponse has no
                 * trailing payload; keySize bounds the DMA buffer write */
                if (res_len < hdr_sz) {
                    ret = WH_ERROR_ABORTED;
                }
            }
            if (ret >= 0) {
                /* Key is cached on server or is ephemeral */
                key_id = (whKeyId)(res->keyId);

                /* Update output variable if requested */
                if (inout_key_id != NULL) {
                    *inout_key_id = key_id;
                }

                /* Update the context if provided */
                if (key != NULL) {
                    /* Set the key_id. ERASED for EPHEMERAL, cached id
                     * otherwise. */
                    wh_Client_MlDsaSetKeyId(key, key_id);

                    /* buffer holds the exported key (EPHEMERAL) or the public
                     * key (cached keygen); keySize bounds the DMA write. An
                     * empty result means the caller requested key material the
                     * server did not return. */
                    if (res->keySize == 0) {
                        ret = WH_ERROR_ABORTED;
                    }
                    /* Bound the server-reported key size to the DMA buffer
                     * capacity before deserializing */
                    else if (res->keySize > sizeof(buffer)) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else {
                        ret = wh_Crypto_MlDsaDeserializeKeyDer(
                            buffer, res->keySize, key);
                    }
                }
            }
        }
    }
    else {
        ret = WH_ERROR_BADARGS;
    }
    return ret;
}


int wh_Client_MlDsaMakeExportKeyDma(whClientContext* ctx, int level,
                                    wc_MlDsaKey* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlDsaMakeKeyDma(ctx, level, NULL, WH_NVM_FLAGS_EPHEMERAL, 0, NULL,
                            key);
}

int wh_Client_MlDsaMakeCacheKeyDma(whClientContext* ctx, int level,
                                   whKeyId* inout_key_id, whNvmFlags flags,
                                   uint16_t label_len, const uint8_t* label,
                                   wc_MlDsaKey* pub)
{
    int     ret;
    whKeyId in_keyId;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export path, not the cache path. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret = _MlDsaMakeKeyDma(ctx, level, inout_key_id, flags, label_len, label,
                           pub);
    if (ret >= 0) {
        /* Stamp the cached keyId and the client's HSM devId so pub is
         * immediately usable as a handle to the cached private key. The keyId
         * is set here (not only inside _MlDsaMakeKeyDma) because a public-key
         * deserialize that retries parameter sets can re-init pub and clear
         * it. */
        wh_Client_MlDsaSetKeyId(pub, *inout_key_id);
        pub->devId = WH_CLIENT_DEVID(ctx);
    }
    else if (WH_KEYID_ISERASED(in_keyId) && !WH_KEYID_ISERASED(*inout_key_id)) {
        /* The server auto-assigned and committed a key but the export failed.
         * Roll back so the operation is atomic and no cache slot is orphaned.
         * Unlike the non-DMA ...AndExportPublic wrapper, this deliberately does
         * NOT also roll back a caller-supplied explicit keyId via a
         * ret == WH_ERROR_ABORTED check: the DMA keygen handler can itself
         * return WH_ERROR_ABORTED before committing a key, so that discriminator
         * is not safe here. In practice the client DMA buffer is always sized
         * >= the public key and the server self-evicts on its own serialize/DMA
         * failures, so the explicit-keyId orphan case is not reachable. */
        (void)wh_Client_KeyEvict(ctx, *inout_key_id);
        *inout_key_id = WH_KEYID_ERASED;
    }
    return ret;
}


int wh_Client_MlDsaSignDma(whClientContext* ctx, const byte* in, word32 in_len,
                         byte* out, word32* out_len, wc_MlDsaKey* key,
                         const byte* context, byte contextLen,
                         word32 preHashType)
{
    int                                   ret     = 0;
    whMessageCrypto_MlDsaSignDmaRequest*  req     = NULL;
    whMessageCrypto_MlDsaSignDmaResponse* res     = NULL;
    uint8_t*                              dataPtr = NULL;
    uintptr_t                             inAddr  = 0;
    uintptr_t                             outAddr = 0;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    if ((ctx == NULL) || (key == NULL) || ((in == NULL) && (in_len > 0)) ||
        (out == NULL) || (out_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempMlDsaSign";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_SIGN;

        ret = wh_Client_MlDsaImportKeyDma(ctx, key, &key_id, flags,
                                          sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    WH_DEBUG_CLIENT_VERBOSE("keyid:%x, in_len:%u, inout_len:%p\n", key_id,
           in_len, out_len);

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;

        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
            contextLen;
        uint32_t options = 0;

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_MlDsaSignDmaRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_SIG_SIGN,
                                            WC_PQC_SIG_TYPE_MLDSA,
                                            ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options     = options;
            req->level       = key->level;
            req->keyId       = key_id;
            req->contextSz   = contextLen;
            req->preHashType = preHashType;
            if ((context != NULL) && (contextLen > 0)) {
                memcpy((uint8_t*)(req + 1), context, contextLen);
            }

            /* Set up DMA buffers */
            req->msg.sz   = in_len;
            ret           = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, req->msg.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->msg.addr = inAddr;
            }

            if (ret == WH_ERROR_OK) {
                req->sig.sz = *out_len;
                ret         = wh_Client_DmaProcessClientAddress(
                    ctx, (uintptr_t)out, (void**)&outAddr, req->sig.sz,
                    WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
                if (ret == WH_ERROR_OK) {
                    req->sig.addr = outAddr;
                }
            }

            /* Send Request */
            if (ret == WH_ERROR_OK) {
                ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                            (uint8_t*)dataPtr);
            }
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point if requested */
                evict = 0;

                /* Response Message */
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_SIG_SIGN,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        /* Update signature length */
                        *out_len = res->sigLen;
                    }
                }
            }

            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, *out_len,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, in_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }
    /* Evict the key manually on error if needed */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    return ret;
}

int wh_Client_MlDsaVerifyDma(whClientContext* ctx, const byte* sig,
                            word32 sig_len, const byte* msg, word32 msg_len,
                            int* out_res, wc_MlDsaKey* key, const byte* context,
                            byte contextLen, word32 preHashType)
{
    int                                     ret     = 0;
    whMessageCrypto_MlDsaVerifyDmaRequest*  req     = NULL;
    whMessageCrypto_MlDsaVerifyDmaResponse* res     = NULL;
    uint8_t*                                dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

    if ((ctx == NULL) || (key == NULL) || ((sig == NULL) && (sig_len > 0)) ||
        ((msg == NULL) && (msg_len > 0)) || (out_res == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempMlDsaVerify";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_VERIFY;

        ret = wh_Client_MlDsaImportKeyDma(ctx, key, &key_id, flags,
                                          sizeof(keyLabel), keyLabel);
        if (ret == 0) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action  = WC_ALGO_TYPE_PK;
        uint32_t options = 0;
        uintptr_t sigAddr = 0;
        uintptr_t msgAddr = 0;

        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req) +
            contextLen;

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_MlDsaVerifyDmaRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_SIG_VERIFY,
                                            WC_PQC_SIG_TYPE_MLDSA,
                                            ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options     = options;
            req->level       = key->level;
            req->keyId       = key_id;
            req->contextSz   = contextLen;
            req->preHashType = preHashType;
            if ((context != NULL) && (contextLen > 0)) {
                memcpy((uint8_t*)(req + 1), context, contextLen);
            }

            /* Set up DMA buffers */
            req->sig.sz   = sig_len;
            ret           = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)sig, (void**)&sigAddr, sig_len,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->sig.addr = sigAddr;
            }
            if (ret == WH_ERROR_OK) {
                req->msg.sz = msg_len;
                ret         = wh_Client_DmaProcessClientAddress(
                    ctx, (uintptr_t)msg, (void**)&msgAddr, msg_len,
                    WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
                if (ret == WH_ERROR_OK) {
                    req->msg.addr = msgAddr;
                }
            }

            /* Send Request */
            if (ret == WH_ERROR_OK) {
                ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                            (uint8_t*)dataPtr);
            }
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point if requested */
                evict = 0;

                /* Response Message */
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_SIG_VERIFY,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        const uint32_t hdr_sz =
                            sizeof(whMessageCrypto_GenericResponseHeader) +
                            sizeof(*res);
                        /* Note whMessageCrypto_MlDsaVerifyDmaResponse has no
                         * size field */
                        if (res_len < hdr_sz) {
                            ret = WH_ERROR_ABORTED;
                        }
                        else {
                            /* Set verification result */
                            *out_res = res->verifyResult;
                        }
                    }
                }
            }

            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)msg, (void**)&msgAddr, msg_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)sig, (void**)&sigAddr, sig_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    /* Evict the key manually on error if needed */
    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    return ret;
}


int wh_Client_MlDsaCheckPrivKeyDma(whClientContext* ctx, wc_MlDsaKey* key,
                                   const byte* pubKey, word32 pubKeySz)
{
    /* TODO */
    (void)ctx;
    (void)key;
    (void)pubKey;
    (void)pubKeySz;
    return CRYPTOCB_UNAVAILABLE;
}


#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_HAVE_MLDSA */

#ifdef WOLFSSL_HAVE_MLKEM

int wh_Client_MlKemSetKeyId(MlKemKey* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_MlKemGetKeyId(MlKemKey* key, whKeyId* outId)
{
    if ((key == NULL) || (outId == NULL)) {
        return WH_ERROR_BADARGS;
    }

    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_MlKemImportKey(whClientContext* ctx, MlKemKey* key,
                             whKeyId* inout_keyId, whNvmFlags flags,
                             uint16_t label_len, uint8_t* label)
{
    int      ret    = WH_ERROR_OK;
    whKeyId  key_id = WH_KEYID_ERASED;
    uint8_t  buffer[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    ret = wh_Crypto_MlKemSerializeKey(key, (uint16_t)buffer_len, buffer,
                                      &buffer_len);
    WH_DEBUG_CLIENT_VERBOSE("MlKemImportKey: serialize ret:%d, len:%u\n",
                            ret, (unsigned int)buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }
    WH_DEBUG_CLIENT_VERBOSE("MlKemImportKey: ret:%d keyId:%u\n", ret, key_id);

    wc_ForceZero(buffer, buffer_len);
    return ret;
}

int wh_Client_MlKemExportKey(whClientContext* ctx, whKeyId keyId, MlKemKey* key,
                             uint16_t label_len, uint8_t* label)
{
    int      ret = WH_ERROR_OK;
    uint8_t  buffer[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret =
        wh_Client_KeyExport(ctx, keyId, label, label_len, buffer, &buffer_len);
    WH_DEBUG_CLIENT_VERBOSE("MlKemExportKey: export ret:%d, len:%u\n",
                            ret, (unsigned int)buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlKemDeserializeKey(buffer, buffer_len, key);
    }
    WH_DEBUG_CLIENT_VERBOSE("MlKemExportKey: keyId:%x ret:%d\n", keyId, ret);

    wc_ForceZero(buffer, buffer_len);
    return ret;
}

int wh_Client_MlKemExportPublicKey(whClientContext* ctx, whKeyId keyId,
                                   MlKemKey* key, uint16_t label_len,
                                   uint8_t* label)
{
    int      ret;
    uint8_t  buffer[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE] = {0};
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublic(ctx, keyId, WH_KEY_ALGO_MLKEM, label,
                                    label_len, buffer, &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlKemDeserializeKey(buffer, buffer_len, key);
    }
    return ret;
}

static int _MlKemMakeKey(whClientContext* ctx, int level,
                         whKeyId* inout_key_id, whNvmFlags flags,
                         uint16_t label_len, const uint8_t* label, MlKemKey* key)
{
    int                                  ret     = WH_ERROR_OK;
    whKeyId                              key_id  = WH_KEYID_ERASED;
    uint8_t*                             dataPtr = NULL;
    whMessageCrypto_MlKemKeyGenRequest*  req     = NULL;
    whMessageCrypto_MlKemKeyGenResponse* res     = NULL;
    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t req_len;
    uint16_t res_len;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_MlKemKeyGenRequest*)_createCryptoRequestWithSubtype(
        dataPtr, WC_PK_TYPE_PQC_KEM_KEYGEN, WC_PQC_KEM_TYPE_KYBER,
        ctx->cryptoAffinity);

    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    req_len = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    /* Defense in depth: ensure request fits in comm buffer */
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    memset(req, 0, sizeof(*req));
    req->level  = level;
    req->flags  = flags;
    req->keyId  = key_id;
    req->access = WH_NVM_ACCESS_ANY;
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
    }

    ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                (uint8_t*)dataPtr);
    WH_DEBUG_CLIENT_VERBOSE("MlKemMakeKey: Req sent:level:%d, ret:%d\n",
                            level, ret);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    do {
        ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                     WOLFHSM_CFG_COMM_DATA_LEN,
                                     (uint8_t*)dataPtr);
    } while (ret == WH_ERROR_NOTREADY);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_KEM_KEYGEN,
                                (uint8_t**)&res);
    if (ret >= 0) {
        key_id = (whKeyId)res->keyId;
        WH_DEBUG_CLIENT_VERBOSE("MlKemMakeKey: Res recv:"
                                "keyId:%u, len:%u, ret:%d\n",
                                (unsigned int)res->keyId,
                                (unsigned int)res->len, ret);
        if (inout_key_id != NULL) {
            *inout_key_id = key_id;
        }
        if (key != NULL) {
            wh_Client_MlKemSetKeyId(key, key_id);
            /* Response carries the exported key (EPHEMERAL) or the public key
             * (cached keygen). An empty body means the caller requested key
             * material the server did not return. */
            if (res->len > 0) {
                uint8_t*     key_raw = (uint8_t*)(res + 1);
                const size_t hdr_sz  =
                    sizeof(whMessageCrypto_GenericResponseHeader) +
                    sizeof(*res);
                if (res_len < hdr_sz || res->len > (res_len - hdr_sz)) {
                    ret = WH_ERROR_ABORTED;
                }
                else {
                    ret = wh_Crypto_MlKemDeserializeKey(
                        key_raw, (uint16_t)res->len, key);
                }
            }
            else {
                ret = WH_ERROR_ABORTED;
            }
        }
    }
    return ret;
}

int wh_Client_MlKemMakeCacheKey(whClientContext* ctx, int level,
                                whKeyId* inout_key_id, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label)
{
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlKemMakeKey(ctx, level, inout_key_id, flags, label_len,
                         label, NULL);
}

int wh_Client_MlKemMakeCacheKeyAndExportPublic(whClientContext* ctx, int level,
                                               whKeyId* inout_key_id,
                                               whNvmFlags flags,
                                               uint16_t label_len,
                                               const uint8_t* label,
                                               MlKemKey* pub)
{
    int     ret;
    whKeyId in_keyId;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export path, not the cache path. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret = _MlKemMakeKey(ctx, level, inout_key_id, flags, label_len, label, pub);
    if (ret >= 0) {
        /* Stamp the cached keyId and the client's HSM devId so pub is
         * immediately usable as a handle to the cached private key. The keyId
         * is set here (not only inside _MlKemMakeKey) because a public-key
         * deserialize that retries parameter sets can re-init pub and clear
         * it. */
        wh_Client_MlKemSetKeyId(pub, *inout_key_id);
        pub->devId = WH_CLIENT_DEVID(ctx);
    }
    else if (!WH_KEYID_ISERASED(*inout_key_id) &&
             (WH_KEYID_ISERASED(in_keyId) || (ret == WH_ERROR_ABORTED))) {
        /* The server committed a key but the best-effort export returned no
         * public key (empty response body when it did not fit). Roll back so the
         * operation is atomic and no cache slot is orphaned. A non-DMA keygen
         * only yields WH_ERROR_ABORTED after the server has committed and
         * returned the keyId, so evicting is safe even when the caller supplied
         * an explicit keyId. */
        (void)wh_Client_KeyEvict(ctx, *inout_key_id);
        *inout_key_id = WH_KEYID_ERASED;
    }
    return ret;
}

int wh_Client_MlKemMakeExportKey(whClientContext* ctx, int level,
                                 MlKemKey* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlKemMakeKey(ctx, level, NULL, WH_NVM_FLAGS_EPHEMERAL, 0,
                         NULL, key);
}

int wh_Client_MlKemEncapsulate(whClientContext* ctx, MlKemKey* key,
                               uint8_t* ct, uint32_t* inout_ct_len, uint8_t* ss,
                               uint32_t* inout_ss_len)
{
    int                                  ret = WH_ERROR_OK;
    uint8_t*                             dataPtr = NULL;
    whMessageCrypto_MlKemEncapsRequest*  req = NULL;
    whMessageCrypto_MlKemEncapsResponse* res = NULL;

    whKeyId key_id;
    int     evict = 0;

    if ((ctx == NULL) || (key == NULL) || (ct == NULL) || (ss == NULL) ||
        (inout_ct_len == NULL) || (inout_ss_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    if ((*inout_ct_len == 0) || (*inout_ss_len == 0)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempMlKemEncaps";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_DERIVE;
        ret = wh_Client_MlKemImportKey(ctx, key, &key_id, flags,
                                       sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
        uint16_t res_len = 0;
        uint32_t options = 0;

        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            if (evict != 0) {
                (void)wh_Client_KeyEvict(ctx, key_id);
            }
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_MlKemEncapsRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_KEM_ENCAPS,
                                            WC_PQC_KEM_TYPE_KYBER,
                                            ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLKEM_ENCAPS_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->type;
            req->keyId   = key_id;

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            WH_DEBUG_CLIENT_VERBOSE("MlKemEncapsulate: Req sent:keyId:%u, "
                                    "level:%u, ret:%d\n",
                                    (unsigned int)key_id,
                                    (unsigned int)key->type, ret);
            if (ret == WH_ERROR_OK) {
                evict = 0;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_KEM_ENCAPS,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    uint8_t*     resp_data  = (uint8_t*)(res + 1);
                    uint32_t     out_ct_len = res->ctSz;
                    uint32_t     out_ss_len = res->ssSz;
                    const size_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    WH_DEBUG_CLIENT_VERBOSE("MlKemEncapsulate: Res recv:"
                                            "ctSz:%u, ssSz:%u, ret:%d\n",
                                            (unsigned int)out_ct_len,
                                            (unsigned int)out_ss_len, ret);
                    if (res_len < hdr_sz ||
                        out_ct_len > (res_len - hdr_sz) ||
                        out_ss_len > (res_len - hdr_sz - out_ct_len)) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else if (*inout_ct_len < out_ct_len ||
                             *inout_ss_len < out_ss_len) {
                        ret = WH_ERROR_BADARGS;
                    }
                    else {
                        memcpy(ct, resp_data, out_ct_len);
                        memcpy(ss, resp_data + out_ct_len, out_ss_len);
                        *inout_ct_len = out_ct_len;
                        *inout_ss_len = out_ss_len;
                    }
                }
            }
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    if (ret != WH_ERROR_OK) {
        wc_ForceZero(ss, *inout_ss_len);
    }

    return ret;
}

int wh_Client_MlKemDecapsulate(whClientContext* ctx, MlKemKey* key,
                               const uint8_t* ct, uint32_t ct_len, uint8_t* ss,
                               uint32_t* inout_ss_len)
{
    int                                  ret = WH_ERROR_OK;
    uint8_t*                             dataPtr = NULL;
    whMessageCrypto_MlKemDecapsRequest*  req = NULL;
    whMessageCrypto_MlKemDecapsResponse* res = NULL;

    whKeyId key_id;
    int     evict = 0;

    if ((ctx == NULL) || (key == NULL) || ((ct == NULL) && (ct_len > 0)) ||
        (ss == NULL) || (inout_ss_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempMlKemDecaps";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_DERIVE;
        ret = wh_Client_MlKemImportKey(ctx, key, &key_id, flags,
                                       sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint32_t options = 0;
        uint64_t total_len = (uint64_t)sizeof(whMessageCrypto_GenericRequestHeader) +
                             sizeof(*req) + ct_len;

        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            if (evict != 0) {
                (void)wh_Client_KeyEvict(ctx, key_id);
            }
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_MlKemDecapsRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_KEM_DECAPS,
                                            WC_PQC_KEM_TYPE_KYBER,
                                            ctx->cryptoAffinity);

        if (total_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint8_t* req_ct  = (uint8_t*)(req + 1);
            uint16_t req_len = (uint16_t)total_len;
            uint16_t res_len = 0;

            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLKEM_DECAPS_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->type;
            req->keyId   = key_id;
            req->ctSz    = ct_len;
            if ((ct != NULL) && (ct_len > 0)) {
                memcpy(req_ct, ct, ct_len);
            }

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            WH_DEBUG_CLIENT_VERBOSE("MlKemDecapsulate: Req sent:keyId:%u, "
                                    "ctSz:%u, ret:%d\n",
                                    (unsigned int)key_id,
                                    (unsigned int)ct_len, ret);
            if (ret == WH_ERROR_OK) {
                evict = 0;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_KEM_DECAPS,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    uint8_t*     resp_ss    = (uint8_t*)(res + 1);
                    uint32_t     out_ss_len = res->ssSz;
                    const size_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    WH_DEBUG_CLIENT_VERBOSE("MlKemDecapsulate: Res recv:"
                                            "ssSz:%u, ret:%d\n",
                                            (unsigned int)out_ss_len, ret);
                    if (res_len < hdr_sz ||
                        out_ss_len > (res_len - hdr_sz)) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else if (*inout_ss_len < out_ss_len) {
                        ret = WH_ERROR_BADARGS;
                    }
                    else {
                        memcpy(ss, resp_ss, out_ss_len);
                        *inout_ss_len = out_ss_len;
                    }
                }
            }
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    if (ret != WH_ERROR_OK) {
        wc_ForceZero(ss, *inout_ss_len);
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_MlKemImportKeyDma(whClientContext* ctx, MlKemKey* key,
                                whKeyId* inout_keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label)
{
    int      ret = WH_ERROR_OK;
    whKeyId  key_id = WH_KEYID_ERASED;
    uint8_t  buffer[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || (key == NULL) ||
        ((label_len != 0) && (label == NULL))) {
        return WH_ERROR_BADARGS;
    }

    if (inout_keyId != NULL) {
        key_id = *inout_keyId;
    }

    ret = wh_Crypto_MlKemSerializeKey(key, (uint16_t)buffer_len, buffer,
                                      &buffer_len);
    WH_DEBUG_CLIENT_VERBOSE("MlKemImportKeyDma: serialize ret:%d, len:%u\n",
                            ret, (unsigned int)buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_KeyCacheDma(ctx, flags, label, label_len, buffer,
                                    buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }
    WH_DEBUG_CLIENT_VERBOSE("MlKemImportKeyDma: ret:%d keyId:%u\n",
                            ret, key_id);

    wc_ForceZero(buffer, buffer_len);
    return ret;
}

int wh_Client_MlKemExportKeyDma(whClientContext* ctx, whKeyId keyId,
                                MlKemKey* key, uint16_t label_len,
                                uint8_t* label)
{
    int      ret = WH_ERROR_OK;
    uint8_t  buffer[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE] = {0};
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportDma(ctx, keyId, buffer, buffer_len, label,
                                 label_len, &buffer_len);
    WH_DEBUG_CLIENT_VERBOSE("MlKemExportKeyDma: export ret:%d, len:%u\n",
                            ret, (unsigned int)buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlKemDeserializeKey(buffer, buffer_len, key);
    }
    WH_DEBUG_CLIENT_VERBOSE("MlKemExportKeyDma: keyId:%x ret:%d\n",
                            keyId, ret);

    wc_ForceZero(buffer, buffer_len);
    return ret;
}

int wh_Client_MlKemExportPublicKeyDma(whClientContext* ctx, whKeyId keyId,
                                      MlKemKey* key, uint16_t label_len,
                                      uint8_t* label)
{
    int      ret;
    uint8_t  buffer[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE] = {0};
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || WH_KEYID_ISERASED(keyId) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_Client_KeyExportPublicDma(ctx, keyId, WH_KEY_ALGO_MLKEM, buffer,
                                       buffer_len, label, label_len,
                                       &buffer_len);
    if (ret == WH_ERROR_OK) {
        ret = wh_Crypto_MlKemDeserializeKey(buffer, buffer_len, key);
    }
    return ret;
}

static int _MlKemMakeKeyDma(whClientContext* ctx, int level,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, const uint8_t* label, MlKemKey* key)
{
    int                                     ret = WH_ERROR_OK;
    whKeyId                                 key_id = WH_KEYID_ERASED;
    uint8_t*                                dataPtr = NULL;
    whMessageCrypto_MlKemKeyGenDmaRequest*  req = NULL;
    whMessageCrypto_MlKemKeyGenDmaResponse* res = NULL;
    uintptr_t                               keyAddr = 0;

    uint8_t  buffer[WC_ML_KEM_MAX_PRIVATE_KEY_SIZE];
    uint16_t buffer_len = sizeof(buffer);

    if ((ctx == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_MlKemKeyGenDmaRequest*)_createCryptoRequestWithSubtype(
        dataPtr, WC_PK_TYPE_PQC_KEM_KEYGEN, WC_PQC_KEM_TYPE_KYBER,
        ctx->cryptoAffinity);

    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint16_t action = WC_ALGO_TYPE_PK;
    uint16_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    memset(req, 0, sizeof(*req));
    req->level  = level;
    req->flags  = flags;
    req->keyId  = key_id;
    req->access = WH_NVM_ACCESS_ANY;
    req->key.sz = buffer_len;

    ret = wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)buffer, (void**)&keyAddr, buffer_len,
        WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
    if (ret == WH_ERROR_OK) {
        req->key.addr = (uint64_t)(uintptr_t)keyAddr;
    }

    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
        req->labelSize = label_len;
    }

    if (ret == WH_ERROR_OK) {
        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                    (uint8_t*)dataPtr);
    }
    if (ret == WH_ERROR_OK) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                         WOLFHSM_CFG_COMM_DATA_LEN,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }

    (void)wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)buffer, (void**)&keyAddr, buffer_len,
        WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

    if (ret == WH_ERROR_OK) {
        ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_KEM_KEYGEN,
                                 (uint8_t**)&res);
        if (ret >= 0) {
            key_id = (whKeyId)res->keyId;
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }
            if (key != NULL) {
                wh_Client_MlKemSetKeyId(key, key_id);
                /* buffer holds the exported key (EPHEMERAL) or the public key
                 * (cached keygen); keySize bounds the DMA write. An empty result
                 * means the caller requested key material the server did not
                 * return. */
                if (res->keySize == 0) {
                    ret = WH_ERROR_ABORTED;
                }
                else if (res->keySize > buffer_len) {
                    ret = WH_ERROR_BADARGS;
                }
                else {
                    ret = wh_Crypto_MlKemDeserializeKey(
                        buffer, (uint16_t)res->keySize, key);
                }
            }

        }
    }

    wc_ForceZero(buffer, buffer_len);
    return ret;
}

int wh_Client_MlKemMakeExportKeyDma(whClientContext* ctx, int level,
                                    MlKemKey* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlKemMakeKeyDma(ctx, level, NULL, WH_NVM_FLAGS_EPHEMERAL, 0, NULL,
                            key);
}

int wh_Client_MlKemMakeCacheKeyDma(whClientContext* ctx, int level,
                                   whKeyId* inout_key_id, whNvmFlags flags,
                                   uint16_t label_len, const uint8_t* label,
                                   MlKemKey* pub)
{
    int     ret;
    whKeyId in_keyId;

    if ((ctx == NULL) || (inout_key_id == NULL) || (pub == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Ephemeral keygen belongs to the export path, not the cache path. */
    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
        return WH_ERROR_BADARGS;
    }

    in_keyId = *inout_key_id;
    ret = _MlKemMakeKeyDma(ctx, level, inout_key_id, flags, label_len, label,
                           pub);
    if (ret >= 0) {
        /* Stamp the cached keyId and the client's HSM devId so pub is
         * immediately usable as a handle to the cached private key. The keyId
         * is set here (not only inside _MlKemMakeKeyDma) because a public-key
         * deserialize that retries parameter sets can re-init pub and clear
         * it. */
        wh_Client_MlKemSetKeyId(pub, *inout_key_id);
        pub->devId = WH_CLIENT_DEVID(ctx);
    }
    else if (WH_KEYID_ISERASED(in_keyId) && !WH_KEYID_ISERASED(*inout_key_id)) {
        /* The server auto-assigned and committed a key but the export failed.
         * Roll back so the operation is atomic and no cache slot is orphaned.
         * Unlike the non-DMA ...AndExportPublic wrapper, this deliberately does
         * NOT also roll back a caller-supplied explicit keyId via a
         * ret == WH_ERROR_ABORTED check: the DMA keygen handler can itself
         * return WH_ERROR_ABORTED before committing a key, so that discriminator
         * is not safe here. In practice the client DMA buffer is always sized
         * >= the public key and the server self-evicts on its own serialize/DMA
         * failures, so the explicit-keyId orphan case is not reachable. */
        (void)wh_Client_KeyEvict(ctx, *inout_key_id);
        *inout_key_id = WH_KEYID_ERASED;
    }
    return ret;
}

int wh_Client_MlKemEncapsulateDma(whClientContext* ctx, MlKemKey* key,
                                  uint8_t* ct, uint32_t* inout_ct_len,
                                  uint8_t* ss, uint32_t* inout_ss_len)
{
    int                                     ret = WH_ERROR_OK;
    uint8_t*                                dataPtr = NULL;
    whMessageCrypto_MlKemEncapsDmaRequest*  req = NULL;
    whMessageCrypto_MlKemEncapsDmaResponse* res = NULL;
    uintptr_t                               ctAddr = 0;
    whKeyId                                 key_id;
    int                                     evict = 0;
    uint32_t                                options = 0;
    uint32_t                                origCtSz;

    if ((ctx == NULL) || (key == NULL) || (ct == NULL) || (ss == NULL) ||
        (inout_ct_len == NULL) || (inout_ss_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    origCtSz = *inout_ct_len;

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempMlKemEncaps";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_DERIVE;
        ret = wh_Client_MlKemImportKeyDma(ctx, key, &key_id, flags,
                                          sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
        uint16_t res_len = 0;

        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            if (evict != 0) {
                (void)wh_Client_KeyEvict(ctx, key_id);
            }
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_MlKemEncapsDmaRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_KEM_ENCAPS,
                                            WC_PQC_KEM_TYPE_KYBER,
                                            ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLKEM_ENCAPS_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->type;
            req->keyId   = key_id;

            req->ct.sz = origCtSz;
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)ct, (void**)&ctAddr, req->ct.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->ct.addr = ctAddr;
            }

            if (ret == WH_ERROR_OK) {
                ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                            (uint8_t*)dataPtr);
            }
            if (ret == WH_ERROR_OK) {
                evict = 0;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_KEM_ENCAPS,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    /* ct was transferred via DMA, ss is inline in response */
                    uint8_t*     resp_ss = (uint8_t*)(res + 1);
                    const size_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    if (res_len < hdr_sz ||
                        res->ssLen > (res_len - hdr_sz)) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else if (res->ctLen > origCtSz ||
                             res->ssLen > *inout_ss_len) {
                        ret = WH_ERROR_BADARGS;
                    }
                    else {
                        memcpy(ss, resp_ss, res->ssLen);
                        *inout_ct_len = res->ctLen;
                        *inout_ss_len = res->ssLen;
                    }
                }
            }

            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)ct, (void**)&ctAddr, origCtSz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    if (ret != WH_ERROR_OK) {
        wc_ForceZero(ss, *inout_ss_len);
    }

    return ret;
}

int wh_Client_MlKemDecapsulateDma(whClientContext* ctx, MlKemKey* key,
                                  const uint8_t* ct, uint32_t ct_len,
                                  uint8_t* ss, uint32_t* inout_ss_len)
{
    int                                     ret = WH_ERROR_OK;
    uint8_t*                                dataPtr = NULL;
    whMessageCrypto_MlKemDecapsDmaRequest*  req = NULL;
    whMessageCrypto_MlKemDecapsDmaResponse* res = NULL;
    uintptr_t                               ctAddr = 0;
    whKeyId                                 key_id;
    int                                     evict = 0;
    uint32_t                                options = 0;

    if ((ctx == NULL) || (key == NULL) || ((ct == NULL) && (ct_len > 0)) ||
        (ss == NULL) || (inout_ss_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        uint8_t    keyLabel[] = "TempMlKemDecaps";
        whNvmFlags flags      = WH_NVM_FLAGS_USAGE_DERIVE;
        ret = wh_Client_MlKemImportKeyDma(ctx, key, &key_id, flags,
                                          sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
        uint16_t res_len = 0;

        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            if (evict != 0) {
                (void)wh_Client_KeyEvict(ctx, key_id);
            }
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_MlKemDecapsDmaRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_KEM_DECAPS,
                                            WC_PQC_KEM_TYPE_KYBER,
                                            ctx->cryptoAffinity);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLKEM_DECAPS_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->type;
            req->keyId   = key_id;

            req->ct.sz = ct_len;
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)ct, (void**)&ctAddr, req->ct.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->ct.addr = ctAddr;
            }

            if (ret == WH_ERROR_OK) {
                ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                            (uint8_t*)dataPtr);
            }
            if (ret == WH_ERROR_OK) {
                evict = 0;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 WOLFHSM_CFG_COMM_DATA_LEN,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
            }

            if (ret == WH_ERROR_OK) {
                ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_KEM_DECAPS,
                                         (uint8_t**)&res);
                if (ret >= 0) {
                    /* ss is inline in response, not via DMA */
                    uint8_t*     resp_ss = (uint8_t*)(res + 1);
                    const size_t hdr_sz =
                        sizeof(whMessageCrypto_GenericResponseHeader) +
                        sizeof(*res);
                    if (res_len < hdr_sz ||
                        res->ssLen > (res_len - hdr_sz)) {
                        ret = WH_ERROR_ABORTED;
                    }
                    else if (res->ssLen > *inout_ss_len) {
                        ret = WH_ERROR_BADARGS;
                    }
                    else {
                        memcpy(ss, resp_ss, res->ssLen);
                        *inout_ss_len = res->ssLen;
                    }
                }
            }

            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)ct, (void**)&ctAddr, ct_len,
                WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    if (evict != 0) {
        (void)wh_Client_KeyEvict(ctx, key_id);
    }

    if (ret != WH_ERROR_OK) {
        wc_ForceZero(ss, *inout_ss_len);
    }

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_HAVE_MLKEM */

#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
#ifdef WOLFHSM_CFG_DMA

#ifdef WOLFSSL_HAVE_LMS

int wh_Client_LmsSetKeyId(LmsKey* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_LmsGetKeyId(LmsKey* key, whKeyId* outId)
{
    if (key == NULL || outId == NULL) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

int wh_Client_LmsMakeKeyDma(whClientContext* ctx, LmsKey* key,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, uint8_t* label)
{
    int                                              ret = WH_ERROR_OK;
    int                                              postRet = WH_ERROR_OK;
    whKeyId                                          key_id = WH_KEYID_ERASED;
    uint8_t*                                         dataPtr;
    whMessageCrypto_PqcStatefulSigKeyGenDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigKeyGenDmaResponse* res;
    word32                                           pubLen32 = 0;
    uintptr_t                                        pubAddr = 0;

    if ((ctx == NULL) || (key == NULL) || (key->params == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Enforce write-through */
    if ((flags & WH_NVM_FLAGS_EPHEMERAL) != 0) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_LmsKey_GetPubLen(key, &pubLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigKeyGenDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN,
            WC_PQC_STATEFUL_SIG_TYPE_LMS, ctx->cryptoAffinity);

    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->flags         = flags;
        req->keyId         = key_id;
        req->access        = WH_NVM_ACCESS_ANY;
        req->lmsLevels     = key->params->levels;
        req->lmsHeight     = key->params->height;
        req->lmsWinternitz = key->params->width;
        req->pub.sz        = pubLen32;

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key->pub, (void**)&pubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->pub.addr = (uint64_t)(uintptr_t)pubAddr;
        }

        if ((label != NULL) && (label_len > 0)) {
            if (label_len > WH_NVM_LABEL_LEN) {
                label_len = WH_NVM_LABEL_LEN;
            }
            memcpy(req->label, label, label_len);
            req->labelSize = label_len;
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        postRet = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key->pub, (void**)&pubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr,
                                     WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN,
                                     (uint8_t**)&res);
            if (ret >= 0) {
                key_id = (whKeyId)res->keyId;
                if (inout_key_id != NULL) {
                    *inout_key_id = key_id;
                }
                wh_Client_LmsSetKeyId(key, key_id);
            }
        }

        /* Prioritize server errors over POST errors */
        if (ret == WH_ERROR_OK) {
            ret = postRet;
        }
    }

    return ret;
}

int wh_Client_LmsMakeExportKeyDma(whClientContext* ctx, LmsKey* key)
{
    return wh_Client_LmsMakeKeyDma(ctx, key, NULL, WH_NVM_FLAGS_NONE, 0, NULL);
}

int wh_Client_LmsSignDma(whClientContext* ctx, const byte* msg, word32 msgSz,
                         byte* sig, word32* sigSz, LmsKey* key)
{
    int                                            ret = WH_ERROR_OK;
    int                                            postRet = WH_ERROR_OK;
    uint8_t*                                       dataPtr;
    whMessageCrypto_PqcStatefulSigSignDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigSignDmaResponse* res;
    uintptr_t                                      msgAddr = 0;
    uintptr_t                                      sigAddr = 0;
    whKeyId                                        key_id;
    word32                                         sigCap;

    if ((ctx == NULL) || (key == NULL) || (msg == NULL) || (sig == NULL) ||
        (sigSz == NULL)) {
        return WH_ERROR_BADARGS;
    }

    sigCap = *sigSz;
    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigSignDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN,
            WC_PQC_STATEFUL_SIG_TYPE_LMS, ctx->cryptoAffinity);

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->keyId   = key_id;
        req->options = 0;
        req->msg.sz  = msgSz;
        req->sig.sz  = sigCap;

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->msg.addr = (uint64_t)(uintptr_t)msgAddr;
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)sig, (void**)&sigAddr, sigCap,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        }
        if (ret == WH_ERROR_OK) {
            req->sig.addr = (uint64_t)(uintptr_t)sigAddr;
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        postRet = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigCap,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN,
                                     (uint8_t**)&res);
            if (ret >= 0) {
                if (res->sigLen > sigCap) {
                    ret = WH_ERROR_BADARGS;
                }
                else {
                    *sigSz = res->sigLen;
                    ret = WH_ERROR_OK;
                }
            }
        }

        /* Prioritize server errors over POST errors */
        if (ret == WH_ERROR_OK) {
            ret = postRet;
        }
    }

    return ret;
}

int wh_Client_LmsVerifyDma(whClientContext* ctx, const byte* sig, word32 sigSz,
                           const byte* msg, word32 msgSz, int* res, LmsKey* key)
{
    int                                              ret = WH_ERROR_OK;
    uint8_t*                                         dataPtr;
    whMessageCrypto_PqcStatefulSigVerifyDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigVerifyDmaResponse* resp;
    uintptr_t                                        sigAddr = 0;
    uintptr_t                                        msgAddr = 0;
    whKeyId                                          key_id;

    if ((ctx == NULL) || (key == NULL) || (sig == NULL) || (msg == NULL) ||
        (res == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        /* No HSM-resident key; let wolfCrypt fall through to software verify
         * using the client-side public key. */
        return WH_ERROR_NOTIMPL;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigVerifyDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY,
            WC_PQC_STATEFUL_SIG_TYPE_LMS, ctx->cryptoAffinity);

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->keyId  = key_id;
        req->sig.sz = sigSz;
        req->msg.sz = msgSz;

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->sig.addr = (uint64_t)(uintptr_t)sigAddr;
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        }
        if (ret == WH_ERROR_OK) {
            req->msg.addr = (uint64_t)(uintptr_t)msgAddr;
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigSz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr,
                                     WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY,
                                     (uint8_t**)&resp);
            if (ret >= 0) {
                *res = (int)resp->res;
                ret = WH_ERROR_OK;
            }
        }
    }

    return ret;
}

int wh_Client_LmsSigsLeftDma(whClientContext* ctx, LmsKey* key)
{
    int                                                ret = WH_ERROR_OK;
    uint8_t*                                           dataPtr;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse* res;
    whKeyId                                            key_id;

    if ((ctx == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT,
            WC_PQC_STATEFUL_SIG_TYPE_LMS, ctx->cryptoAffinity);

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->keyId = key_id;

        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                    (uint8_t*)dataPtr);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr,
                                     WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT,
                                     (uint8_t**)&res);
            if (ret >= 0) {
                /* The server mirrors wc_LmsKey_SigsLeft(), which is a
                 * boolean. Normalize so the only nonzero return is 1. */
                ret = (res->sigsLeft != 0) ? 1 : 0;
            }
        }
    }

    return ret;
}

int wh_Client_LmsImportPubKey(whClientContext* ctx, LmsKey* key,
                              whKeyId* inout_keyId, whNvmFlags flags,
                              uint16_t label_len, uint8_t* label)
{
    int      ret;
    uint8_t  blob[256];
    uint16_t blobSz = (uint16_t)sizeof(blob);
    uint16_t keyId16;

    if ((ctx == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Build a public-only slot blob from the loaded public key, then provision
     * it via the generic keystore. The server stores no private state, so the
     * key is verify-only. */
    ret = wh_Crypto_LmsSerializePubKey(key, blobSz, blob, &blobSz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId16 = (uint16_t)((inout_keyId != NULL) ? *inout_keyId
                                               : WH_KEYID_ERASED);
    ret = wh_Client_KeyCache(ctx, (uint32_t)flags, label, label_len, blob,
                             blobSz, &keyId16);
    if ((ret == WH_ERROR_OK) && ((flags & WH_NVM_FLAGS_EPHEMERAL) == 0)) {
        ret = wh_Client_KeyCommit(ctx, (whNvmId)keyId16);
    }
    if (ret == WH_ERROR_OK) {
        wh_Client_LmsSetKeyId(key, (whKeyId)keyId16);
        if (inout_keyId != NULL) {
            *inout_keyId = (whKeyId)keyId16;
        }
    }
    return ret;
}

#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS

int wh_Client_XmssSetKeyId(XmssKey* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }
    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);
    return WH_ERROR_OK;
}

int wh_Client_XmssGetKeyId(XmssKey* key, whKeyId* outId)
{
    if (key == NULL || outId == NULL) {
        return WH_ERROR_BADARGS;
    }
    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);
    return WH_ERROR_OK;
}

/* The XMSS implementations mirror the LMS ones; the only differences are the
 * subType passed to _createCryptoRequestWithSubtype and the key field names
 * (key->pk instead of key->pub, key->params is XmssParams). */
int wh_Client_XmssMakeKeyDma(whClientContext* ctx, XmssKey* key,
                             whKeyId* inout_key_id, whNvmFlags flags,
                             uint16_t label_len, uint8_t* label)
{
    int                                              ret = WH_ERROR_OK;
    int                                              postRet = WH_ERROR_OK;
    whKeyId                                          key_id = WH_KEYID_ERASED;
    uint8_t*                                         dataPtr;
    whMessageCrypto_PqcStatefulSigKeyGenDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigKeyGenDmaResponse* res;
    word32                                           pubLen32 = 0;
    uintptr_t                                        pubAddr = 0;

    if ((ctx == NULL) || (key == NULL) || (key->params == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Enforce write-through */
    if ((flags & WH_NVM_FLAGS_EPHEMERAL) != 0) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_XmssKey_GetPubLen(key, &pubLen32);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigKeyGenDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN,
            WC_PQC_STATEFUL_SIG_TYPE_XMSS, ctx->cryptoAffinity);

    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->flags  = flags;
        req->keyId  = key_id;
        req->access = WH_NVM_ACCESS_ANY;
        req->pub.sz = pubLen32;

        {
            const char* paramStr = NULL;
            ret = wc_XmssKey_GetParamStr(key, &paramStr);
            if (ret != 0) {
                return WH_ERROR_BADARGS;
            }
            if (XSTRLEN(paramStr) >= sizeof(req->xmssParamStr)) {
                return WH_ERROR_BADARGS;
            }
            XSTRNCPY(req->xmssParamStr, paramStr, sizeof(req->xmssParamStr));
            req->xmssParamStr[sizeof(req->xmssParamStr) - 1] = '\0';
        }

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key->pk, (void**)&pubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->pub.addr = (uint64_t)(uintptr_t)pubAddr;
        }

        if ((label != NULL) && (label_len > 0)) {
            if (label_len > WH_NVM_LABEL_LEN) {
                label_len = WH_NVM_LABEL_LEN;
            }
            memcpy(req->label, label, label_len);
            req->labelSize = label_len;
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        postRet = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key->pk, (void**)&pubAddr, pubLen32,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr,
                                     WC_PK_TYPE_PQC_STATEFUL_SIG_KEYGEN,
                                     (uint8_t**)&res);
            if (ret >= 0) {
                key_id = (whKeyId)res->keyId;
                if (inout_key_id != NULL) {
                    *inout_key_id = key_id;
                }
                wh_Client_XmssSetKeyId(key, key_id);
            }
        }

        /* Prioritize server errors over POST errors */
        if (ret == WH_ERROR_OK) {
            ret = postRet;
        }
    }

    return ret;
}

int wh_Client_XmssMakeExportKeyDma(whClientContext* ctx, XmssKey* key)
{
    return wh_Client_XmssMakeKeyDma(ctx, key, NULL, WH_NVM_FLAGS_NONE, 0, NULL);
}

int wh_Client_XmssSignDma(whClientContext* ctx, const byte* msg, word32 msgSz,
                          byte* sig, word32* sigSz, XmssKey* key)
{
    int                                            ret = WH_ERROR_OK;
    int                                            postRet = WH_ERROR_OK;
    uint8_t*                                       dataPtr;
    whMessageCrypto_PqcStatefulSigSignDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigSignDmaResponse* res;
    uintptr_t                                      msgAddr = 0;
    uintptr_t                                      sigAddr = 0;
    whKeyId                                        key_id;
    word32                                         sigCap;

    if ((ctx == NULL) || (key == NULL) || (msg == NULL) || (sig == NULL) ||
        (sigSz == NULL)) {
        return WH_ERROR_BADARGS;
    }

    sigCap = *sigSz;
    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigSignDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN,
            WC_PQC_STATEFUL_SIG_TYPE_XMSS, ctx->cryptoAffinity);

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->keyId   = key_id;
        req->options = 0;
        req->msg.sz  = msgSz;
        req->sig.sz  = sigCap;

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->msg.addr = (uint64_t)(uintptr_t)msgAddr;
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)sig, (void**)&sigAddr, sigCap,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        }
        if (ret == WH_ERROR_OK) {
            req->sig.addr = (uint64_t)(uintptr_t)sigAddr;
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        postRet = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigCap,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGN,
                                     (uint8_t**)&res);
            if (ret >= 0) {
                if (res->sigLen > sigCap) {
                    ret = WH_ERROR_BADARGS;
                }
                else {
                    *sigSz = res->sigLen;
                    ret = WH_ERROR_OK;
                }
            }
        }

        /* Prioritize server errors over POST errors */
        if (ret == WH_ERROR_OK) {
            ret = postRet;
        }
    }

    return ret;
}

int wh_Client_XmssVerifyDma(whClientContext* ctx, const byte* sig,
                            word32 sigSz, const byte* msg, word32 msgSz,
                            int* res, XmssKey* key)
{
    int                                              ret = WH_ERROR_OK;
    uint8_t*                                         dataPtr;
    whMessageCrypto_PqcStatefulSigVerifyDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigVerifyDmaResponse* resp;
    uintptr_t                                        sigAddr = 0;
    uintptr_t                                        msgAddr = 0;
    whKeyId                                          key_id;

    if ((ctx == NULL) || (key == NULL) || (sig == NULL) || (msg == NULL) ||
        (res == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        /* No HSM-resident key; let wolfCrypt fall through to software verify
         * using the client-side public key. */
        return WH_ERROR_NOTIMPL;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigVerifyDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY,
            WC_PQC_STATEFUL_SIG_TYPE_XMSS, ctx->cryptoAffinity);

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->keyId  = key_id;
        req->sig.sz = sigSz;
        req->msg.sz = msgSz;

        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigSz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->sig.addr = (uint64_t)(uintptr_t)sigAddr;
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        }
        if (ret == WH_ERROR_OK) {
            req->msg.addr = (uint64_t)(uintptr_t)msgAddr;
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sig, (void**)&sigAddr, sigSz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)msg, (void**)&msgAddr, msgSz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});

        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr,
                                     WC_PK_TYPE_PQC_STATEFUL_SIG_VERIFY,
                                     (uint8_t**)&resp);
            if (ret >= 0) {
                *res = (int)resp->res;
                ret = WH_ERROR_OK;
            }
        }
    }

    return ret;
}

int wh_Client_XmssSigsLeftDma(whClientContext* ctx, XmssKey* key)
{
    int                                                ret = WH_ERROR_OK;
    uint8_t*                                           dataPtr;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest*  req;
    whMessageCrypto_PqcStatefulSigSigsLeftDmaResponse* res;
    whKeyId                                            key_id;

    if ((ctx == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);
    if (WH_KEYID_ISERASED(key_id)) {
        return WH_ERROR_BADARGS;
    }

    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    req = (whMessageCrypto_PqcStatefulSigSigsLeftDmaRequest*)
        _createCryptoRequestWithSubtype(
            dataPtr, WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT,
            WC_PQC_STATEFUL_SIG_TYPE_XMSS, ctx->cryptoAffinity);

    {
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
            return WH_ERROR_BADARGS;
        }

        memset(req, 0, sizeof(*req));
        req->keyId = key_id;

        ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                    (uint8_t*)dataPtr);
        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &req_len,
                                             WOLFHSM_CFG_COMM_DATA_LEN,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr,
                                     WC_PK_TYPE_PQC_STATEFUL_SIG_SIGS_LEFT,
                                     (uint8_t**)&res);
            if (ret >= 0) {
                /* The server mirrors wc_XmssKey_SigsLeft(), which is a
                 * boolean. Normalize so the only nonzero return is 1. */
                ret = (res->sigsLeft != 0) ? 1 : 0;
            }
        }
    }

    return ret;
}

int wh_Client_XmssImportPubKey(whClientContext* ctx, XmssKey* key,
                               whKeyId* inout_keyId, whNvmFlags flags,
                               uint16_t label_len, uint8_t* label)
{
    int         ret;
    uint8_t     blob[256];
    uint16_t    blobSz = (uint16_t)sizeof(blob);
    uint16_t    keyId16;
    const char* paramStr = NULL;

    if ((ctx == NULL) || (key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_XmssKey_GetParamStr(key, &paramStr);
    if (ret != 0) {
        return WH_ERROR_BADARGS;
    }

    /* Build a public-only slot blob, then provision it via the generic
     * keystore. The server stores no secret state, so the key is verify-only.
     */
    ret = wh_Crypto_XmssSerializePubKey(key, paramStr, blobSz, blob, &blobSz);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    keyId16 = (uint16_t)((inout_keyId != NULL) ? *inout_keyId
                                               : WH_KEYID_ERASED);
    ret = wh_Client_KeyCache(ctx, (uint32_t)flags, label, label_len, blob,
                             blobSz, &keyId16);
    if ((ret == WH_ERROR_OK) && ((flags & WH_NVM_FLAGS_EPHEMERAL) == 0)) {
        ret = wh_Client_KeyCommit(ctx, (whNvmId)keyId16);
    }
    if (ret == WH_ERROR_OK) {
        wh_Client_XmssSetKeyId(key, (whKeyId)keyId16);
        if (inout_keyId != NULL) {
            *inout_keyId = (whKeyId)keyId16;
        }
    }
    return ret;
}

#endif /* WOLFSSL_HAVE_XMSS */

#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_CLIENT */
