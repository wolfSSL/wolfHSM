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
#include "wolfssl/wolfcrypt/dilithium.h"
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
/* Server creates a key based on incoming flags */
static int _EccMakeKey(whClientContext* ctx, int size, int curveId,
                       whKeyId* inout_key_id, whNvmFlags flags,
                       uint16_t label_len, uint8_t* label, ecc_key* key);
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Server creates a key based on incoming flags */
static int _Curve25519MakeKey(whClientContext* ctx, uint16_t size,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              const uint8_t* label, uint16_t label_len,
                              curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifndef NO_RSA
/* Make an RSA key on the server based on the flags */
static int _RsaMakeKey(whClientContext* ctx, uint32_t size, uint32_t e,
                       whNvmFlags flags, uint32_t label_len, uint8_t* label,
                       whKeyId* inout_key_id, RsaKey* rsa);
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

#ifdef HAVE_DILITHIUM
/* Make a ML-DSA key on the server based on the flags */
static int _MlDsaMakeKey(whClientContext* ctx, int size, int level,
                         whKeyId* inout_key_id, whNvmFlags flags,
                         uint16_t label_len, uint8_t* label, MlDsaKey* key);

#ifdef WOLFHSM_CFG_DMA
static int _MlDsaMakeKeyDma(whClientContext* ctx, int level,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, uint8_t* label, MlDsaKey* key);
#endif /* WOLFHSM_CFG_DMA */
#endif /* HAVE_DILITHIUM */

#ifndef NO_SHA256
/* Helper function to transfer SHA256 block and update digest */
static int _xferSha256BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha256*       sha256,
                                           uint32_t         isLastBlock);
#endif /* !NO_SHA256 */

#if defined(WOLFSSL_SHA224)
/* Helper function to transfer SHA224 block and update digest */
static int _xferSha224BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha224*       sha224,
                                           uint32_t         isLastBlock);
#endif /* WOLFSSL_SHA224 */

static uint8_t* _createCryptoRequest(uint8_t* reqBuf, uint16_t type);
static uint8_t* _createCryptoRequestWithSubtype(uint8_t* reqBuf, uint16_t type,
                                                uint16_t algoSubType);
static int      _getCryptoResponse(uint8_t* respBuf, uint16_t type,
                                   uint8_t** outResponse);


/* Helper function to prepare a crypto request buffer with generic header */
static uint8_t* _createCryptoRequest(uint8_t* reqBuf, uint16_t type)
{
    return _createCryptoRequestWithSubtype(reqBuf, type, WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE);
}

/* Helper function to prepare a crypto request buffer with generic header and
 * subtype */
static uint8_t* _createCryptoRequestWithSubtype(uint8_t* reqBuf, uint16_t type,
                                                uint16_t algoSubType)
{
    whMessageCrypto_GenericRequestHeader* header =
        (whMessageCrypto_GenericRequestHeader*)reqBuf;
    header->algoType    = type;
    header->algoSubType = algoSubType;
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
int wh_Client_RngGenerate(whClientContext* ctx, uint8_t* out, uint32_t size)
{
    int                          ret = WH_ERROR_OK;
    whMessageCrypto_RngRequest*  req;
    whMessageCrypto_RngResponse* res;
    uint8_t*                     dataPtr;
    uint8_t*                     reqData;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    reqData = _createCryptoRequest(dataPtr, WC_ALGO_TYPE_RNG);

    /* Setup request header */
    req = (whMessageCrypto_RngRequest*)reqData;

    /* Calculate maximum data size client can request (subtract headers) */
    const uint32_t client_max_data =
        WOLFHSM_CFG_COMM_DATA_LEN -
        sizeof(whMessageCrypto_GenericRequestHeader) -
        sizeof(whMessageCrypto_RngRequest);

    while ((size > 0) && (ret == WH_ERROR_OK)) {
        /* Request Message */
        uint16_t group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action  = WC_ALGO_TYPE_RNG;
        uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(whMessageCrypto_RngRequest);
        uint16_t res_len;

        /* Request up to client max, but no more than remaining size */
        uint32_t chunk_size = (size < client_max_data) ? size : client_max_data;
        req->sz             = chunk_size;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] RNG: size:%u reqsz:%u remaining:%u\n",
               (unsigned int)chunk_size, (unsigned int)req_len,
               (unsigned int)size);
        printf("[client] RNG: req:%p\n", req);
#endif

        /* Send request and get response */
        ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                             dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == WH_ERROR_OK) {
            /* Get response */
            ret =
                _getCryptoResponse(dataPtr, WC_ALGO_TYPE_RNG, (uint8_t**)&res);
            if (ret == WH_ERROR_OK) {
                /* Validate server didn't respond with more than requested */
                if (res->sz <= chunk_size) {
                    uint8_t* res_out = (uint8_t*)(res + 1);
                    if (out != NULL) {
                        memcpy(out, res_out, res->sz);
                        out += res->sz;
                    }
                    size -= res->sz;
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] out size:%u remaining:%u\n",
                           (unsigned int)res->sz, (unsigned int)size);
                    wh_Utils_Hexdump("[client] res_out: \n", out - res->sz,
                                     res->sz);
#endif
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

#ifdef WOLFHSM_CFG_DMA
int wh_Client_RngGenerateDma(whClientContext* ctx, uint8_t* out, uint32_t size)
{
    int                             ret     = WH_ERROR_OK;
    uint8_t*                        dataPtr = NULL;
    whMessageCrypto_RngDmaRequest*  req     = NULL;
    whMessageCrypto_RngDmaResponse* resp    = NULL;
    uint16_t                        respSz  = 0;
    uintptr_t                       outAddr = 0;

    if ((ctx == NULL) || (out == NULL) || (size == 0)) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_RngDmaRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_RNG);

    /* Set up output buffer address and size */
    req->output.sz = size;

    /* Perform address translation for output buffer (PRE operation) */
    ret = wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
        WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
    if (ret == WH_ERROR_OK) {
        req->output.addr = outAddr;
    }

    if (ret == WH_ERROR_OK) {
        /* Send the request to the server */
        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_RNG,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        /* Wait for and receive the response */
        do {
            ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == WH_ERROR_OK) {
        /* Get response structure pointer, validates generic header rc */
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_RNG, (uint8_t**)&resp);
        /* Nothing more to do on success, as server will have written random
         * bytes directly to client memory */
    }

    /* Perform address translation cleanup (POST operation)
     * This is called regardless of successful operation to give the callback a
     * chance for cleanup */
    (void)wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)out, (void**)&outAddr, size,
        WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#ifndef NO_AES

#ifdef WOLFSSL_AES_COUNTER
int wh_Client_AesCtr(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out)
{
    int                             ret = WH_ERROR_OK;
    whMessageCrypto_AesCtrRequest*  req;
    whMessageCrypto_AesCtrResponse* res;
    uint8_t*                        dataPtr;

    if ((ctx == NULL) || (aes == NULL) || (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    uint32_t       key_len = aes->keylen;
    const uint8_t* key     = (const uint8_t*)(aes->devKey);
    whKeyId        key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);
    uint8_t*       iv      = (uint8_t*)aes->reg;
    uint32_t       iv_len  = AES_IV_SIZE;
    uint32_t       left    = aes->left;
    uint8_t*       tmp     = (uint8_t*)aes->tmp;

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_CIPHER;
    uint16_t type   = WC_CIPHER_AES_CTR;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_AesCtrRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_CTR);
    uint8_t* req_in  = (uint8_t*)(req + 1);
    uint8_t* req_key = req_in + len;
    uint8_t* req_iv  = req_key + key_len;
    uint8_t* req_tmp = req_iv + AES_BLOCK_SIZE;
    uint32_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + len + key_len + iv_len +
                       (AES_BLOCK_SIZE * 2);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s: enc:%d keylen:%d ivsz:%d insz:%d reqsz:%u "
           "left:%d\n",
           __func__, enc, key_len, iv_len, len, req_len, left);
#endif
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    /* setup request packet */
    req->enc    = enc;
    req->keyLen = key_len;
    req->sz     = len;
    req->keyId  = key_id;
    req->left   = left;

    if ((in != NULL) && (len > 0)) {
        memcpy(req_in, in, len);
    }
    if ((key != NULL) && (key_len > 0)) {
        memcpy(req_key, key, key_len);
    }
    if ((iv != NULL) && (iv_len > 0)) {
        memcpy(req_iv, iv, iv_len);
    }
    if (tmp != NULL) {
        memcpy(req_tmp, tmp, AES_BLOCK_SIZE);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] in: \n", req_in, len);
    wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
    wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
    wh_Utils_Hexdump("[client] tmp: \n", req_tmp, AES_BLOCK_SIZE);
#endif
    /* write request */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] req packet: \n", (uint8_t*)req, req_len);
#endif
    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
    /* read response */
    if (ret == WH_ERROR_OK) {
        /* Response packet */
        uint16_t res_len = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr, type, (uint8_t**)&res);
            if (ret == WH_ERROR_OK) {
                /* Response packet */
                uint8_t* res_out = (uint8_t*)(res + 1);
                /* tmp buffer follows after the output data */
                uint8_t* res_reg = res_out + res->sz;
                uint8_t* res_tmp = res_reg + AES_BLOCK_SIZE;

#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] out size:%d res_len:%d\n", res->sz, res_len);
                wh_Utils_Hexdump("[client] res_out: \n", res_out, res->sz);
                wh_Utils_Hexdump("[client] res_tmp: \n", res_tmp,
                                 AES_BLOCK_SIZE);
#endif
                /* copy the response res_out */
                memcpy(out, res_out, res->sz);
                if (enc != 0) {
                    /* Update the CTR state */
                    aes->left = res->left;
                    /* Update the iv data */
                    memcpy(iv, res_reg, AES_BLOCK_SIZE);
                    /* Update the tmp data */
                    memcpy(tmp, res_tmp, AES_BLOCK_SIZE);
                }
            }
        }
    }
    return ret;
}
#endif /* WOLFSSL_AES_COUNTER */

#ifdef HAVE_AES_ECB
int wh_Client_AesEcb(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out)
{
    int                             ret    = WH_ERROR_OK;
    uint16_t                        blocks = len / AES_BLOCK_SIZE;
    whMessageCrypto_AesEcbRequest*  req;
    whMessageCrypto_AesEcbResponse* res;
    uint8_t*                        dataPtr;

    if (blocks == 0) {
        /* Nothing to do. */
        return WH_ERROR_OK;
    }

    if ((ctx == NULL) || (aes == NULL) || ((len % AES_BLOCK_SIZE) != 0) ||
        (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }

    uint32_t       key_len = aes->keylen;
    const uint8_t* key     = (const uint8_t*)(aes->devKey);
    whKeyId        key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);
    uint8_t*       iv      = (uint8_t*)aes->reg;
    uint32_t       iv_len  = AES_IV_SIZE;

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_CIPHER;
    uint16_t type   = WC_CIPHER_AES_ECB;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_AesEcbRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_ECB);
    uint8_t* req_in  = (uint8_t*)(req + 1);
    uint8_t* req_key = req_in + len;
    uint8_t* req_iv  = req_key + key_len;
    uint32_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + len + key_len + iv_len;


#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s: enc:%d keylen:%d ivsz:%d insz:%d reqsz:%u "
           "blocks:%u \n",
           __func__, enc, (int)key_len, (int)iv_len, (int)len,
           (unsigned int)req_len, (unsigned int)blocks);
#endif

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    /* setup request packet */
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

#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] in: \n", req_in, len);
    wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
    wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
#endif

    /* write request */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] req packet: \n", (uint8_t*)req, req_len);
#endif
    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
    /* read response */
    if (ret == WH_ERROR_OK) {
        /* Response packet */
        uint16_t res_len = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr, type, (uint8_t**)&res);
            if (ret == WH_ERROR_OK) {
                /* Response packet */
                uint8_t* res_out = (uint8_t*)(res + 1);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] out size:%d res_len:%d\n", (int)res->sz,
                       (int)res_len);
                wh_Utils_Hexdump("[client] res_out: \n", out, res->sz);
#endif
                /* copy the response res_out */
                memcpy(out, res_out, res->sz);
            }
        }
    }
    return ret;
}
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wh_Client_AesCbc(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, uint8_t* out)
{
    int                             ret    = WH_ERROR_OK;
    uint16_t                        blocks = len / AES_BLOCK_SIZE;
    whMessageCrypto_AesCbcRequest*  req;
    whMessageCrypto_AesCbcResponse* res;
    uint8_t*                        dataPtr;

    if (blocks == 0) {
        /* Nothing to do. */
        return WH_ERROR_OK;
    }

    if ((ctx == NULL) || (aes == NULL) || ((len % AES_BLOCK_SIZE) != 0) ||
        (in == NULL) || (out == NULL)) {
        return WH_ERROR_BADARGS;
    }


    uint32_t       last_offset = (blocks - 1) * AES_BLOCK_SIZE;
    uint32_t       key_len     = aes->keylen;
    const uint8_t* key         = (const uint8_t*)(aes->devKey);
    whKeyId        key_id      = WH_DEVCTX_TO_KEYID(aes->devCtx);
    uint8_t*       iv          = (uint8_t*)aes->reg;
    uint32_t       iv_len      = AES_IV_SIZE;

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_CIPHER;
    uint16_t type   = WC_CIPHER_AES_CBC;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }
    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_AesCbcRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_CBC);
    uint8_t* req_in  = (uint8_t*)(req + 1);
    uint8_t* req_key = req_in + len;
    uint8_t* req_iv  = req_key + key_len;
    uint32_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + len + key_len + iv_len;


#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s: enc:%d keylen:%d ivsz:%d insz:%d reqsz:%u "
           "blocks:%u lastoffset:%u\n",
           __func__, enc, (int)key_len, (int)iv_len, (int)len,
           (unsigned int)req_len, (unsigned int)blocks,
           (unsigned int)last_offset);
#endif

    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    /* setup request packet */
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

    /* Determine where ciphertext is for chaining */
    if (enc == 0) {
        /* Update the CBC state with the last cipher text block */
        /* III Must do this before the decrypt if in-place */
        memcpy(iv, in + last_offset, iv_len);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] in: \n", req_in, len);
    wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
    wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
#endif

    /* write request */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] req packet: \n", (uint8_t*)req, req_len);
#endif
    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
    /* read response */
    if (ret == WH_ERROR_OK) {
        /* Response packet */
        uint16_t res_len = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret == WH_ERROR_OK) {
            ret = _getCryptoResponse(dataPtr, type, (uint8_t**)&res);
            if (ret == WH_ERROR_OK) {
                /* Response packet */
                uint8_t* res_out = (uint8_t*)(res + 1);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] out size:%d res_len:%d\n", (int)res->sz,
                       (int)res_len);
                wh_Utils_Hexdump("[client] res_out: \n", out, res->sz);
#endif
                /* copy the response res_out */
                memcpy(out, res_out, res->sz);
                if (enc != 0) {
                    /* Update the CBC state with the last cipher text block
                     */
                    memcpy(iv, out + last_offset, AES_IV_SIZE);
                }
            }
        }
    }
    return ret;
}
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
int wh_Client_AesGcm(whClientContext* ctx, Aes* aes, int enc, const uint8_t* in,
                     uint32_t len, const uint8_t* iv, uint32_t iv_len,
                     const uint8_t* authin, uint32_t authin_len,
                     const uint8_t* dec_tag, uint8_t* enc_tag, uint32_t tag_len,
                     uint8_t* out)
{
    int ret = 0;

    if ((ctx == NULL) || (aes == NULL) || ((in == NULL) && (len > 0)) ||
        ((iv == NULL) && (iv_len > 0)) ||
        ((authin == NULL) && (authin_len > 0)) ||
        ((enc == 0) && (dec_tag == NULL))) {
        return WH_ERROR_BADARGS;
    }

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WC_ALGO_TYPE_CIPHER;
    uint16_t type   = WC_CIPHER_AES_GCM;

    uint32_t       key_len = aes->keylen;
    const uint8_t* key     = (const uint8_t*)(aes->devKey);
    whKeyId        key_id  = WH_DEVCTX_TO_KEYID(aes->devCtx);


    /* Get data buffer */
    uint8_t* dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    whMessageCrypto_AesGcmRequest* req =
        (whMessageCrypto_AesGcmRequest*)_createCryptoRequest(dataPtr,
                                                             WC_CIPHER_AES_GCM);

    uint8_t* req_in     = (uint8_t*)(req + 1);
    uint8_t* req_key    = req_in + len;
    uint8_t* req_iv     = req_key + key_len;
    uint8_t* req_authin = req_iv + iv_len;
    uint8_t* req_tag    = req_authin + authin_len;

    uint32_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + len + key_len + iv_len + authin_len +
                       ((enc == 0) ? tag_len : 0);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] AESGCM: enc:%d keylen:%d ivsz:%d insz:%d authinsz:%d "
           "authtagsz:%d reqsz:%u\n",
           enc, (int)key_len, (int)iv_len, (int)len, (int)authin_len,
           (int)tag_len, (unsigned int)req_len);
    printf("[client] AESGCM: req:%p in:%p key:%p iv:%p authin:%p tag:%p\n", req,
           req_in, req_key, req_iv, req_authin, req_tag);
#endif
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        return WH_ERROR_BADARGS;
    }

    /* setup request packet */
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
    if (key != NULL && key_len > 0) {
        memcpy(req_key, key, key_len);
    }
    if (iv != NULL && iv_len > 0) {
        memcpy(req_iv, iv, iv_len);
    }
    if (authin != NULL && authin_len > 0) {
        memcpy(req_authin, authin, authin_len);
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] in: \n", req_in, len);
    wh_Utils_Hexdump("[client] key: \n", req_key, key_len);
    wh_Utils_Hexdump("[client] iv: \n", req_iv, iv_len);
    wh_Utils_Hexdump("[client] authin: \n", req_authin, authin_len);
#endif

    /* set auth tag by direction */
    if (enc == 0 && dec_tag != NULL && tag_len > 0) {
        memcpy(req_tag, dec_tag, tag_len);
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] dec tag: \n", req_tag, tag_len);
#endif
    }

    /* write request */
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] AESGCM req packet: \n", dataPtr, req_len);
#endif

    /* Send request and receive response */
    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
    if (ret == 0) {
        uint16_t res_len = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret == WH_ERROR_OK) {
            /* Get response */
            whMessageCrypto_AesGcmResponse* res;
            ret = _getCryptoResponse(dataPtr, type, (uint8_t**)&res);
            /* wolfCrypt allows positive error codes on success in some
             * scenarios */
            if (ret >= 0) {
                /* The encrypted/decrypted data follows directly after the
                 * response struct */
                uint8_t* res_out = (uint8_t*)(res + 1);
                /* The auth tag follows after the output data */
                uint8_t* res_tag = res_out + res->sz;

#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] out size:%d datasz:%d tag_len:%d\n",
                       (int)res->sz, (int)res_len, (int)res->authTagSz);
                wh_Utils_Hexdump("[client] res_out: \n", res_out, res->sz);
                if (enc != 0 && res->authTagSz > 0) {
                    wh_Utils_Hexdump("[client] res_tag: \n", res_tag,
                                     res->authTagSz);
                }
#endif
                /* copy the response result if present */
                if (out != NULL && res->sz == len) {
                    memcpy(out, res_out, res->sz);
                }

                /* write the authTag if applicable */
                if (enc != 0 && enc_tag != NULL && res->authTagSz > 0 &&
                    res->authTagSz <= tag_len) {
                    memcpy(enc_tag, res_tag, res->authTagSz);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] res tag_len:%d exp tag_len:%u",
                           (int)res->authTagSz, (unsigned int)tag_len);
                    wh_Utils_Hexdump("[client] enc authtag: ", enc_tag,
                                     res->authTagSz);
#endif
                }
            }
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_AesGcmDma(whClientContext* ctx, Aes* aes, int enc,
                        const uint8_t* in, uint32_t len, const uint8_t* iv,
                        uint32_t iv_len, const uint8_t* authin,
                        uint32_t authin_len, const uint8_t* dec_tag,
                        uint8_t* enc_tag, uint32_t tag_len, uint8_t* out)
{
    int                            ret         = WH_ERROR_OK;
    whMessageCrypto_AesDmaRequest* req         = NULL;
    uint8_t*                       dataPtr     = NULL;
    uintptr_t                      inAddr      = 0;
    uintptr_t                      outAddr     = 0;
    uintptr_t                      keyAddr     = 0;
    uintptr_t                      ivAddr      = 0;
    uintptr_t                      aadAddr     = 0;
    uintptr_t                      authTagAddr = 0;

    uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint16_t action = WC_ALGO_TYPE_CIPHER;
    uint16_t type =
        WC_CIPHER_AES_GCM; /* Algorithm type for response validation */
    const uint8_t* key    = NULL;
    uint32_t       keyLen = 0;
    uint16_t       reqLen;

    if (ctx == NULL || aes == NULL) {
        return WH_ERROR_BADARGS;
    }

    if ((in == NULL) && (len > 0)) {
        return WH_ERROR_BADARGS;
    }

    if ((iv == NULL) && (iv_len > 0)) {
        return WH_ERROR_BADARGS;
    }

    if ((authin == NULL) && (authin_len > 0)) {
        return WH_ERROR_BADARGS;
    }

    if ((enc == 0) && (dec_tag == NULL)) {
        return WH_ERROR_BADARGS;
    }

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_AesDmaRequest*)_createCryptoRequest(
        dataPtr, WC_CIPHER_AES_GCM);
    memset(req, 0, sizeof(*req));
    req->enc  = enc;
    req->type = type;

    req->keyId = WH_DEVCTX_TO_KEYID(aes->devCtx);
    if (req->keyId != WH_KEYID_ERASED) {
        /* Using keyId-based key, server will load it from keystore */
        key    = NULL;
        keyLen = 0;
    }
    else {
        /* Using direct key */
        key    = (const uint8_t*)(aes->devKey);
        keyLen = aes->keylen;
    }

    /* Handle key operations */
    if (ret == WH_ERROR_OK && key != NULL && keyLen > 0) {
        req->key.addr = (uintptr_t)key;
        req->key.sz   = keyLen;
        ret           = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key, (void**)&keyAddr, req->key.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->key.addr = keyAddr;
        }
    }

    if (ret == WH_ERROR_OK && in != NULL) {
        req->input.sz = len;
        ret           = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK && out != NULL) {
        req->output.sz = len;
        ret            = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->output.addr = outAddr;
        }
    }

    if (ret == WH_ERROR_OK && iv != NULL) {
        req->iv.sz = iv_len;
        ret        = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)iv, (void**)&ivAddr, req->iv.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->iv.addr = ivAddr;
        }
    }

    if (ret == WH_ERROR_OK && authin != NULL) {
        req->aad.sz = authin_len;
        ret         = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)authin, (void**)&aadAddr, req->aad.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->aad.addr = aadAddr;
        }
    }

    /* set auth tag by direction */
    if (enc == 0 && dec_tag != NULL && tag_len > 0) {
        /* Decryption: use provided auth tag for verification */
        req->authTag.sz = tag_len;
        ret             = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dec_tag, (void**)&authTagAddr, req->authTag.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->authTag.addr = authTagAddr;
        }
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] dec tag: \n", dec_tag, tag_len);
#endif
    }
    else if (enc == 1 && enc_tag != NULL && tag_len > 0) {
        /* Encryption: set up auth tag buffer to receive generated tag */
        req->authTag.sz = tag_len;
        ret             = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)enc_tag, (void**)&authTagAddr, req->authTag.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->authTag.addr = authTagAddr;
        }
#ifdef DEBUG_CRYPTOCB_VERBOSE
        wh_Utils_Hexdump("[client] enc tag buffer: \n", enc_tag, tag_len);
#endif
    }

    /* Send request and receive response */
    reqLen = sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    wh_Utils_Hexdump("[client] AESGCM DMA req packet: \n", dataPtr, reqLen);
#endif
    if (ret == WH_ERROR_OK) {
        ret = wh_Client_SendRequest(ctx, group, action, reqLen, dataPtr);
    }
    if (ret == 0) {
        uint16_t resLen = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &resLen, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);

        if (ret == WH_ERROR_OK) {
            /* Get response */
            whMessageCrypto_AesDmaResponse* res;
            ret = _getCryptoResponse(dataPtr, type, (uint8_t**)&res);
            /* wolfCrypt allows positive error codes on success in some
             * scenarios */
            if (ret >= 0) {
                /* For DMA operations, data is already in client memory,
                 * no need to copy it back */
                ret = 0; /* Success */
            }
        }
    }

    /* post address translation callbacks (for cleanup) */
    if (key != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key, (void**)&keyAddr, req->key.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    if (iv != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)iv, (void**)&ivAddr, iv_len,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    if (in != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    if (out != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    }
    if (authin != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)authin, (void**)&aadAddr, authin_len,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    if (enc == 0 && dec_tag != NULL && tag_len > 0) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)dec_tag, (void**)&authTagAddr, req->authTag.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    else if (enc == 1 && enc_tag != NULL && tag_len > 0) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)enc_tag, (void**)&authTagAddr, req->authTag.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s serialize ret:%d, key:%p, max_size:%u, buffer:%p, "
           "outlen:%u\n",
           __func__, ret, key, (unsigned int)sizeof(buffer), buffer,
           buffer_len);
#endif
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s label:%.*s ret:%d keyid:%u\n", __func__, label_len,
           label, ret, key_id);
#endif
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

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x key:%p ret:%d label:%.*s\n", __func__, keyId,
           key, ret, (int)label_len, label);
#endif
    return ret;
}

static int _EccMakeKey(whClientContext* ctx, int size, int curveId,
                       whKeyId* inout_key_id, whNvmFlags flags,
                       uint16_t label_len, uint8_t* label, ecc_key* key)
{
    int                                ret     = WH_ERROR_OK;
    whKeyId                            key_id  = WH_KEYID_ERASED;
    uint8_t*                           dataPtr = NULL;
    whMessageCrypto_EccKeyGenRequest*  req     = NULL;
    whMessageCrypto_EccKeyGenResponse* res     = NULL;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_EccKeyGenRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_EC_KEYGEN);

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

            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s Req sent:size:%u, ret:%d\n", __func__,
                   (unsigned int)req->sz, ret);
#endif
            if (ret == WH_ERROR_OK) {
                /* Response Message */
                uint16_t res_len;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_EC_KEYGEN,
                                             (uint8_t**)&res);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] %s Res recv:keyid:%u, len:%u, ret:%d\n",
                           __func__, (unsigned int)res->keyId,
                           (unsigned int)res->len, ret);
#endif
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        /* Key is cached on server or is ephemeral */
                        key_id = (whKeyId)(res->keyId);

                        /* Update output variable if requested */
                        if (inout_key_id != NULL) {
                            *inout_key_id = key_id;
                        }

                        /* Update the context if provided */
                        if (key != NULL) {
                            /* Set the key_id.  Should be ERASED if EPHEMERAL */
                            wh_Client_EccSetKeyId(key, key_id);

                            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                                uint8_t* key_der  = (uint8_t*)(res + 1);
                                uint16_t der_size = (uint16_t)(res->len);
                                /* Response has the exported key */
                                ret = wh_Crypto_EccDeserializeKeyDer(
                                    key_der, der_size, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                                wh_Utils_Hexdump("[client] KeyGen export:",
                                                 key_der, der_size);
#endif
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

int wh_Client_EccMakeCacheKey(whClientContext* ctx, int size, int curveId,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              uint16_t label_len, uint8_t* label)
{
    if (inout_key_id == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _EccMakeKey(ctx, size, curveId, inout_key_id, flags, label_len,
                       label, NULL);
}

int wh_Client_EccMakeExportKey(whClientContext* ctx, int size, int curveId,
                               ecc_key* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _EccMakeKey(ctx, size, curveId, NULL, WH_NVM_FLAGS_EPHEMERAL, 0,
                       NULL, key);
}

int wh_Client_EccSharedSecret(whClientContext* ctx, ecc_key* priv_key,
                              ecc_key* pub_key, uint8_t* out,
                              uint16_t* out_size)
{
    int                           ret     = WH_ERROR_OK;
    uint8_t*                      dataPtr = NULL;
    whMessageCrypto_EcdhRequest*  req     = NULL;
    whMessageCrypto_EcdhResponse* res     = NULL;

    /* Transaction state */
    whKeyId prv_key_id;
    int     prv_evict = 0;
    whKeyId pub_key_id;
    int     pub_evict = 0;

    if ((ctx == NULL) || (pub_key == NULL) || (priv_key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    pub_key_id = WH_DEVCTX_TO_KEYID(pub_key->devCtx);
    if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(pub_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempEccDh-pub";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx, pub_key, &pub_key_id, flags,
                                     sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            pub_evict = 1;
        }
    }

    prv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(prv_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempEccDh-prv";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        ret = wh_Client_EccImportKey(ctx, priv_key, &prv_key_id, flags,
                                     sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Request Message*/
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;
        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
        uint32_t options = 0;

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_EcdhRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_ECDH);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (pub_evict != 0) {
                options |= WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPUB;
            }
            if (prv_evict != 0) {
                options |= WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPRV;
            }

            memset(req, 0, sizeof(*req));
            req->options      = options;
            req->privateKeyId = prv_key_id;
            req->publicKeyId  = pub_key_id;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s req sent. priv:%u pub:%u\n", __func__,
                   (unsigned int)req->privateKeyId,
                   (unsigned int)req->publicKeyId);
#endif
            if (ret == WH_ERROR_OK) {
                /* Server will evict.  Reset our flags */
                pub_evict = prv_evict = 0;

                /* Response Message */
                uint16_t res_len;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s resp packet recv. ret:%d\n", __func__, ret);
#endif
                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDH,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        uint8_t* res_out = (uint8_t*)(res + 1);
                        /* TODO: should we sanity check res->sz? */
                        if (out_size != NULL) {
                            *out_size = res->sz;
                        }
                        if (out != NULL) {
                            memcpy(out, res_out, res->sz);
                        }
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        wh_Utils_Hexdump("[client] Eccdh:", res_out, res->sz);
#endif
                    }
                }
            }
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    /* Evict the keys manually on error */
    if (pub_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if (prv_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, prv_key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}


int wh_Client_EccSign(whClientContext* ctx, ecc_key* key, const uint8_t* hash,
                      uint16_t hash_len, uint8_t* sig, uint16_t* inout_sig_len)
{
    int                              ret     = 0;
    whMessageCrypto_EccSignRequest*  req     = NULL;
    whMessageCrypto_EccSignResponse* res     = NULL;
    uint8_t*                         dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
           __func__, ctx, key, hash, (unsigned)hash_len, sig, inout_sig_len);
#endif

    if ((ctx == NULL) || (key == NULL) || ((hash == NULL) && (hash_len > 0)) ||
        ((sig != NULL) && (inout_sig_len == NULL))) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x, in_len:%u, inout_len:%p\n", __func__, key_id,
           hash_len, inout_sig_len);
#endif

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempEccSign";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

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
            dataPtr, WC_PK_TYPE_ECDSA_SIGN);

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
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] EccSign: key_id=%x, hash_len=%u, options=%u\n",
                   key_id, (unsigned)hash_len, (unsigned)options);
            wh_Utils_Hexdump("[client] EccSign req:", (uint8_t*)req,
                             sizeof(*req));
            if ((hash != NULL) && (hash_len > 0)) {
                wh_Utils_Hexdump("[client] EccSign hash:", (uint8_t*)hash,
                                 hash_len);
            }
#endif

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
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDSA_SIGN,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        uint8_t* res_sig = (uint8_t*)(res + 1);
                        uint16_t sig_len = res->sz;
                        /* check inoutlen and read out */
                        if (inout_sig_len != NULL) {
                            if (sig_len > *inout_sig_len) {
                                /* Silently truncate the signature */
                                sig_len = *inout_sig_len;
                            }
                            *inout_sig_len = sig_len;
                            if ((sig != NULL) && (sig_len > 0)) {
                                memcpy(sig, res_sig, sig_len);
                            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
                            wh_Utils_Hexdump("[client] EccSign:", res_sig,
                                             sig_len);
#endif
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

int wh_Client_EccVerify(whClientContext* ctx, ecc_key* key, const uint8_t* sig,
                        uint16_t sig_len, const uint8_t* hash,
                        uint16_t hash_len, int* out_res)
{
    int                                ret     = 0;
    whMessageCrypto_EccVerifyRequest*  req     = NULL;
    whMessageCrypto_EccVerifyResponse* res     = NULL;
    uint8_t*                           dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict          = 0;
    int     export_pub_key = 0;


#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ctx:%p key:%p, sig:%p sig_len:%u, hash:%p hash_len:%u "
           "out_res:%p\n",
           __func__, ctx, key, sig, sig_len, hash, hash_len, out_res);
#endif

    if ((ctx == NULL) || (key == NULL) || ((sig == NULL) && (sig_len > 0)) ||
        ((hash == NULL) && (hash_len > 0))) {
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
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

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
            dataPtr, WC_PK_TYPE_ECDSA_VERIFY);

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

#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] EccVerify req: key_id=%x, sig_len=%u, "
                   "hash_len=%u, options=%u\n",
                   key_id, (unsigned int)sig_len, (unsigned int)hash_len,
                   (unsigned int)options);
            wh_Utils_Hexdump("[client] EccVerify req:", (uint8_t*)req, req_len);
            if ((sig != NULL) && (sig_len > 0)) {
                wh_Utils_Hexdump("[client] EccVerify sig:", sig, sig_len);
            }
            if ((hash != NULL) && (hash_len > 0)) {
                wh_Utils_Hexdump("[client] EccVerify hash:", hash, hash_len);
            }
#endif

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
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_ECDSA_VERIFY,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        uint32_t res_der_size = 0;
                        *out_res              = res->res;
                        res_der_size          = res->pubSz;
                        if (res_der_size > 0) {
                            uint8_t* res_pub_der = (uint8_t*)(res + 1);
                            /* Update the key with the generated public key */
                            ret = wh_Crypto_EccUpdatePrivateOnlyKeyDer(
                                key, res_der_size, res_pub_der);
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
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
                (uint8_t*)packet);
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
#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_CRYPTOCB_VERBOSE)
        printf("[client] importKey: cached keyid=%u\n", key_id);
        wh_Utils_Hexdump("[client] importKey: key=", buffer, buffer_len);
#endif
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
        dataPtr, WC_PK_TYPE_CURVE25519_KEYGEN);

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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] Curve25519 KeyGen Req sent:size:%u, ret:%d\n",
           (unsigned int)req->sz, ret);
#endif
    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &data_len,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }


    if (ret == 0) {
        /* Get response structure pointer, validates generic header */
        ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_CURVE25519_KEYGEN,
                                 (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Curve25519 KeyGen Res recv:keyid:%u, len:%u, "
                   "ret:%d\n",
                   (unsigned int)res->keyId, (unsigned int)res->len, ret);
#endif
            /* Key is cached on server or is ephemeral */
            key_id = (whKeyId)(res->keyId);

            /* Update output variable if requested */
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }

            /* Update the context if provided */
            if (key != NULL) {
                uint16_t der_size = (uint16_t)(res->len);
                uint8_t* key_der  = (uint8_t*)(res + 1);
                /* Set the key_id.  Should be ERASED if EPHEMERAL */
                wh_Client_Curve25519SetKeyId(key, key_id);

                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret = wh_Crypto_Curve25519DeserializeKey(key_der, der_size,
                                                             key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    wh_Utils_Hexdump("[client] KeyGen export:", key_der,
                                     der_size);
#endif
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

int wh_Client_Curve25519MakeExportKey(whClientContext* ctx, uint16_t size,
                                      curve25519_key* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _Curve25519MakeKey(ctx, size, NULL, WH_NVM_FLAGS_EPHEMERAL, NULL, 0,
                              key);
}

int wh_Client_Curve25519SharedSecret(whClientContext* ctx,
                                     curve25519_key*  priv_key,
                                     curve25519_key* pub_key, int endian,
                                     uint8_t* out, uint16_t* out_size)
{
    int ret = WH_ERROR_OK;

    /* Transaction state */
    whKeyId prv_key_id;
    int     prv_evict = 0;
    whKeyId pub_key_id;
    int     pub_evict = 0;

    if ((ctx == NULL) || (pub_key == NULL) || (priv_key == NULL)) {
        return WH_ERROR_BADARGS;
    }

    pub_key_id = WH_DEVCTX_TO_KEYID(pub_key->devCtx);
    if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(pub_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempX25519-pub";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        ret = wh_Client_Curve25519ImportKey(ctx, pub_key, &pub_key_id, flags,
                                            sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            pub_evict = 1;
        }
    }

    prv_key_id = WH_DEVCTX_TO_KEYID(priv_key->devCtx);
    if ((ret == WH_ERROR_OK) && WH_KEYID_ISERASED(prv_key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempX25519-prv";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        ret = wh_Client_Curve25519ImportKey(ctx, priv_key, &prv_key_id, flags,
                                            sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            prv_evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        whMessageCrypto_Curve25519Request* req     = NULL;
        uint8_t*                           dataPtr = NULL;
        uint16_t                           group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t                           action  = WC_ALGO_TYPE_PK;
        uint32_t                           options = 0;

        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }
        memset((uint8_t*)dataPtr, 0, WOLFHSM_CFG_COMM_DATA_LEN);

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_Curve25519Request*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_CURVE25519);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (pub_evict != 0) {
                options |= WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPUB;
            }
            if (prv_evict != 0) {
                options |= WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPRV;
            }

            memset(req, 0, sizeof(*req));
            req->options      = options;
            req->privateKeyId = prv_key_id;
            req->publicKeyId  = pub_key_id;
            req->endian       = endian;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s req sent. priv:%u pub:%u\n", __func__,
                   (unsigned int)req->privateKeyId,
                   (unsigned int)req->publicKeyId);
#endif
            if (ret == WH_ERROR_OK) {
                whMessageCrypto_Curve25519Response* res = NULL;
                uint16_t                            res_len;
                /* Server will evict.  Reset our flags */
                pub_evict = prv_evict = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s resp packet recv. ret:%d ret:%d\n",
                       __func__, ret, ret);
#endif
                if (ret == WH_ERROR_OK) {
                    /* Get response structure pointer, validates generic header
                     * rc */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_CURVE25519,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        if (out_size != NULL) {
                            *out_size = res->sz;
                        }
                        if (out != NULL) {
                            uint8_t* res_out = (uint8_t*)(res + 1);
                            memcpy(out, res_out, res->sz);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                            wh_Utils_Hexdump("[client] X25519:", res_out,
                                             res->sz);
#endif
                        }
                    }
                }
            }
        }
        else {
            ret = WH_ERROR_BADARGS;
        }
    }

    /* Evict the keys manually on error */
    if (pub_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, pub_key_id);
    }
    if (prv_evict != 0) {
        (void)wh_Client_KeyEvict(ctx, prv_key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}
#endif /* HAVE_CURVE25519 */

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

static int _RsaMakeKey(whClientContext* ctx, uint32_t size, uint32_t e,
                       whNvmFlags flags, uint32_t label_len, uint8_t* label,
                       whKeyId* inout_key_id, RsaKey* rsa)
{
    int                                ret     = WH_ERROR_OK;
    uint8_t*                           dataPtr = NULL;
    whMessageCrypto_RsaKeyGenRequest*  req     = NULL;
    whMessageCrypto_RsaKeyGenResponse* res     = NULL;
    uint16_t                           group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                           action  = WC_ALGO_TYPE_PK;
    whKeyId                            key_id  = WH_KEYID_ERASED;

    if (ctx == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_RsaKeyGenRequest*)_createCryptoRequest(
        dataPtr, WC_PK_TYPE_RSA_KEYGEN);

    uint16_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    /* Use the supplied key id if provided */
    if (inout_key_id != NULL) {
        key_id = *inout_key_id;
    }

    /* Populate request body directly */
    req->size  = size;
    req->e     = e;
    req->flags = flags;
    req->keyId = key_id; /* Use key_id from inout_key_id or ERASED */
    if ((label != NULL) && (label_len > 0)) {
        if (label_len > WH_NVM_LABEL_LEN) {
            label_len = WH_NVM_LABEL_LEN;
        }
        memcpy(req->label, label, label_len);
        /* Ensure null termination if space allows, though protocol doesn't
         * require */
        if (label_len < WH_NVM_LABEL_LEN) {
            req->label[label_len] = '\0';
        }
    }
    else {
        memset(req->label, 0, WH_NVM_LABEL_LEN);
    }

    /* Send Request */
    ret = wh_Client_SendRequest(ctx, group, action, req_len, dataPtr);
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("RSA KeyGen Req sent:size:%u, e:%u, ret:%d\n",
           (unsigned int)req->size, (unsigned int)req->e, ret);
#endif
    if (ret == 0) {
        uint16_t res_len = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("RSA KeyGen Res recv: ret:%d, res_len: %u\n", ret,
               (unsigned int)res_len);
#endif

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header rc */
            ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_RSA_KEYGEN,
                                     (uint8_t**)&res);
        }

        if (ret == WH_ERROR_OK) {
            /* Key is cached on server or is ephemeral */
            key_id = (whKeyId)(res->keyId);

            /* Update output variable if requested */
            if (inout_key_id != NULL) {
                *inout_key_id = key_id;
            }

            /* Update the RSA context if provided */
            if (rsa != NULL) {
                word32   der_size = (word32)(res->len);
                uint8_t* rsa_der  = (uint8_t*)(res + 1);

                /* Set the rsa key_id.  Should be ERASED if EPHEMERAL */
                wh_Client_RsaSetKeyId(rsa, key_id);

#ifdef DEBUG_CRYPTOCB_VERBOSE
                printf("[client] %s Set key_id:%x with flags:%x\n", __func__,
                       key_id, flags);
#endif
                if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                    /* Response has the exported key */
                    ret =
                        wh_Crypto_RsaDeserializeKeyDer(der_size, rsa_der, rsa);
                }
            }
        }
    }
    return ret;
}

int wh_Client_RsaMakeCacheKey(whClientContext* ctx, uint32_t size, uint32_t e,
                              whKeyId* inout_key_id, whNvmFlags flags,
                              uint32_t label_len, uint8_t* label)
{
    if ((ctx == NULL) || (inout_key_id == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _RsaMakeKey(ctx, size, e, flags, label_len, label, inout_key_id,
                       NULL);
}

int wh_Client_RsaMakeExportKey(whClientContext* ctx, uint32_t size, uint32_t e,
                               RsaKey* rsa)
{
    if ((ctx == NULL) || (rsa == NULL)) {
        return WH_ERROR_BADARGS;
    }

    return _RsaMakeKey(ctx, size, e, WH_NVM_FLAGS_EPHEMERAL, 0, NULL, NULL,
                       rsa);
}

int wh_Client_RsaFunction(whClientContext* ctx, RsaKey* key, int rsa_type,
                          const uint8_t* in, uint16_t in_len, uint8_t* out,
                          uint16_t* inout_out_len)
{
    int                          ret     = WH_ERROR_OK;
    whMessageCrypto_RsaRequest*  req     = NULL;
    whMessageCrypto_RsaResponse* res     = NULL;
    uint8_t*                     dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ctx:%p key:%p, rsa_type:%d in:%p in_len:%u, out:%p "
           "inout_out_len:%p\n",
           __func__, ctx, key, rsa_type, in, (unsigned)in_len, out,
           inout_out_len);
#endif

    if ((ctx == NULL) || (key == NULL) || ((in == NULL) && (in_len > 0)) ||
        ((out != NULL) && (inout_out_len == NULL))) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s key_id:%x\n", __func__, key_id);
#endif

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempRsaFunction";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        ret = wh_Client_RsaImportKey(ctx, key, &key_id, flags, sizeof(keyLabel),
                                     keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        /* Get data pointer */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_RsaRequest*)_createCryptoRequest(dataPtr,
                                                                WC_PK_TYPE_RSA);

        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t action = WC_ALGO_TYPE_PK;

        uint8_t* req_in  = (uint8_t*)(req + 1);
        uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(*req) + in_len;
        uint32_t options = 0;

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
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

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict            = 0;
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_RSA,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        /* Get response output pointer */
                        uint8_t* res_out = (uint8_t*)(res + 1);
                        uint16_t out_len = res->outLen;
                        /* check inoutlen and read out */
                        if (inout_out_len != NULL) {
                            if (out_len > *inout_out_len) {
                                /* Silently truncate the response */
                                out_len = *inout_out_len;
                            }
                            *inout_out_len = out_len;
                            if ((out != NULL) && (out_len > 0)) {
                                memcpy(out, res_out, out_len);
                            }
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

int wh_Client_RsaGetSize(whClientContext* ctx, const RsaKey* key, int* out_size)
{
    int ret = WH_ERROR_OK;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ctx:%p key:%p, out_size:%p \n", __func__, ctx, key,
           out_size);
#endif

    if ((ctx == NULL) || (key == NULL) || (out_size == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempRsaGetSize";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] %s Importing temp key\n", __func__);
#endif
        ret = wh_Client_RsaImportKey(ctx, key, &key_id, flags, sizeof(keyLabel),
                                     keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

    if (ret == WH_ERROR_OK) {
        uint8_t*                            dataPtr = NULL;
        whMessageCrypto_RsaGetSizeRequest*  req     = NULL;
        whMessageCrypto_RsaGetSizeResponse* res     = NULL;
        uint16_t                            group   = WH_MESSAGE_GROUP_CRYPTO;
        uint16_t                            action  = WC_ALGO_TYPE_PK;

        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
        uint32_t options = 0;

        /* Get data pointer */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        req = (whMessageCrypto_RsaGetSizeRequest*)_createCryptoRequest(
            dataPtr, WC_PK_TYPE_RSA_GET_SIZE);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_RSA_GET_SIZE_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->keyId   = key_id;

            /* Send Request */
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
            if (ret == WH_ERROR_OK) {
                /* Server will evict at this point. Reset evict */
                evict            = 0;
                uint16_t res_len = 0;

                /* Recv Response */
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                                 (uint8_t*)dataPtr);
                } while (ret == WH_ERROR_NOTREADY);

                if (ret == WH_ERROR_OK) {
                    /* Get response */
                    ret = _getCryptoResponse(dataPtr, WC_PK_TYPE_RSA_GET_SIZE,
                                             (uint8_t**)&res);
                    /* wolfCrypt allows positive error codes on success in some
                     * scenarios */
                    if (ret >= 0) {
                        *out_size = res->keySize;
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] %s Evicting temp key %x\n", __func__, key_id);
#endif
        (void)wh_Client_KeyEvict(ctx, key_id);
    }
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
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
        dataPtr, WC_ALGO_TYPE_KDF, WC_KDF_TYPE_HKDF);

    /* Calculate request length including variable-length data */
    uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + inKeySz + saltSz + infoSz;

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

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("HKDF Req sent: hashType:%d inKeySz:%u saltSz:%u infoSz:%u outSz:%u "
           "ret:%d\n",
           (int)req->hashType, (unsigned int)req->inKeySz,
           (unsigned int)req->saltSz, (unsigned int)req->infoSz,
           (unsigned int)req->outSz, ret);
#endif

    if (ret == 0) {
        uint16_t res_len = 0;
        do {
            ret =
                wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
        } while (ret == WH_ERROR_NOTREADY);

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("HKDF Res recv: ret:%d, res_len: %u\n", ret,
               (unsigned int)res_len);
#endif

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

#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] %s Set key_id:%x with flags:%x outSz:%u\n",
                           __func__, key_id, flags, (unsigned int)res->outSz);
#endif
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
        dataPtr, WC_ALGO_TYPE_KDF, WC_KDF_TYPE_TWOSTEP_CMAC);

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
        ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len, dataPtr);
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
#endif

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

int wh_Client_Cmac(whClientContext* ctx, Cmac* cmac, CmacType type,
                   const uint8_t* key, uint32_t keyLen, const uint8_t* in,
                   uint32_t inLen, uint8_t* outMac, uint32_t* outMacLen)
{
    int                           ret     = WH_ERROR_OK;
    uint16_t                      group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                      action  = WC_ALGO_TYPE_CMAC;
    whMessageCrypto_CmacRequest*  req     = NULL;
    whMessageCrypto_CmacResponse* res     = NULL;
    uint8_t*                      dataPtr = NULL;

    whKeyId  key_id = WH_DEVCTX_TO_KEYID(cmac->devCtx);
    uint32_t mac_len =
        ((outMac == NULL) || (outMacLen == NULL)) ? 0 : *outMacLen;

    /* Return success for a call with NULL params, or 0 len's */
    if ((inLen == 0) && (keyLen == 0) && (mac_len == 0)) {
        /* Update the type */
        cmac->type = type;
        return WH_ERROR_OK;
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] cmac key:%p key_len:%d in:%p in_len:%d out:%p out_len:%d "
           "keyId:%x\n",
           key, (int)keyLen, in, (int)inLen, outMac, (int)mac_len, key_id);
#endif


    /* Get data pointer */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_CmacRequest*)_createCryptoRequest(dataPtr,
                                                             WC_ALGO_TYPE_CMAC);

    uint8_t* req_in  = (uint8_t*)(req + 1);
    uint8_t* req_key = req_in + inLen;
    uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                       sizeof(*req) + inLen + keyLen;

    /* TODO get rid of this logic, we should always fail */
    if (req_len > WOLFHSM_CFG_COMM_DATA_LEN) {
        /* if we're using an HSM req_key return BAD_FUNC_ARG */
        if (!WH_KEYID_ISERASED(key_id)) {
            return WH_ERROR_BADARGS;
        }
        else {
            return CRYPTOCB_UNAVAILABLE;
        }
    }

    /* Setup request packet */
    req->type  = type;
    req->inSz  = inLen;
    req->keyId = key_id;
    req->keySz = keyLen;
    req->outSz = mac_len;
    /* multiple modes are possible so we need to set zero size if buffers
     * are NULL */
    if ((in != NULL) && (inLen > 0)) {
        memcpy(req_in, in, inLen);
    }
    if ((key != NULL) && (keyLen > 0)) {
        memcpy(req_key, key, keyLen);
    }

    /* Send request */
    ret = wh_Client_SendRequest(ctx, group, action, req_len, (uint8_t*)dataPtr);
    if (ret == WH_ERROR_OK) {
        /* Update the local type since call succeeded */
        cmac->type = type;
#ifdef WOLFHSM_CFG_CANCEL_API
        /* if the client marked they may want to cancel, handle the
         * response in a separate call */
        if (ctx->cancelable) {
            return ret;
        }
#endif

        uint16_t res_len = 0;
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
        if (ret == WH_ERROR_OK) {
            /* Get response */
            ret =
                _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
            /* wolfCrypt allows positive error codes on success in some
             * scenarios */
            if (ret >= 0) {
                /* read keyId and res_out */
                if (key != NULL) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    printf("[client] got keyid %x\n", res->keyId);
#endif
                    cmac->devCtx = WH_KEYID_TO_DEVCTX(res->keyId);
                }
                if (outMac != NULL) {
                    uint8_t* res_mac = (uint8_t*)(res + 1);
                    memcpy(outMac, res_mac, res->outSz);
                    if (outMacLen != NULL) {
                        *(outMacLen) = res->outSz;
                    }
                }
            }
        }
    }
    return ret;
}

#endif /* !NO_AES */

#ifdef WOLFHSM_CFG_CANCEL_API
int wh_Client_CmacCancelableResponse(whClientContext* c, Cmac* cmac,
                                     uint8_t* out, uint16_t* outSz)
{
    whMessageCrypto_CmacResponse* res     = NULL;
    uint8_t*                      dataPtr = NULL;
    int                           ret;
    uint16_t                      group;
    uint16_t                      action;
    uint16_t                      dataSz;

    if (c == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }


    /* Get data pointer */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(c->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    do {
        ret = wh_Client_RecvResponse(c, &group, &action, &dataSz,
                                     (uint8_t*)dataPtr);
    } while (ret == WH_ERROR_NOTREADY);

    /* check for out of sequence action */
    if (ret == 0 &&
        (group != WH_MESSAGE_GROUP_CRYPTO || action != WC_ALGO_TYPE_CMAC)) {
        ret = WH_ERROR_ABORTED;
    }
    if (ret == 0) {
        /* Setup generic header and get pointer to response data */
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
            cmac->devCtx = (void*)((intptr_t)res->keyId);
            if (out != NULL && outSz != NULL) {
                if (res->outSz > *outSz) {
                    ret = WH_ERROR_BUFFER_SIZE;
                }
                else {
                    uint8_t* packOut = (uint8_t*)(res + 1);
                    memcpy(out, packOut, res->outSz);
                    *outSz = res->outSz;
                }
            }
        }
    }
    return ret;
}
#endif /* WOLFHSM_CFG_CANCEL_API */

#ifdef WOLFHSM_CFG_DMA
int wh_Client_CmacDma(whClientContext* ctx, Cmac* cmac, CmacType type,
                      const uint8_t* key, uint32_t keyLen, const uint8_t* in,
                      uint32_t inLen, uint8_t* outMac, uint32_t* outMacLen)
{
    int                              ret      = WH_ERROR_OK;
    whMessageCrypto_CmacDmaRequest*  req      = NULL;
    whMessageCrypto_CmacDmaResponse* res      = NULL;
    uint8_t*                         dataPtr  = NULL;
    int                              finalize = 0;
    uintptr_t inAddr = 0; /* The req->input.addr is reused elsewhere, this
                             local variable is to keep track of the resulting
                             DMA translation to pass back to the callback on
                             POST operations. */
    uintptr_t outAddr   = 0;
    uintptr_t keyAddr   = 0;
    uintptr_t stateAddr = 0;

    if (ctx == NULL || cmac == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_CmacDmaRequest*)_createCryptoRequest(
        dataPtr, WC_ALGO_TYPE_CMAC);
    memset(req, 0, sizeof(*req));
    req->type = type;

    /* Store devId and devCtx to restore after request */
    int   devId  = cmac->devId;
    void* devCtx = cmac->devCtx;

    /* Set up DMA state buffer in client address space */
    req->state.sz   = sizeof(*cmac);
    ret             = wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)cmac, (void**)&stateAddr, req->state.sz,
        WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
    if (ret == WH_ERROR_OK) {
        req->state.addr = stateAddr;
    }

    /* Handle different CMAC operations based on input parameters */
    if (ret == WH_ERROR_OK && key != NULL) {
        /* Initialize with provided key */
        req->key.sz = keyLen;
        ret         = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key, (void**)&keyAddr, req->key.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->key.addr = keyAddr;
        }
    }

    if (ret == WH_ERROR_OK && in != NULL) {
        /* Update operation */
        req->input.sz   = inLen;
        ret             = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->input.addr = inAddr;
        }
    }

    if (ret == WH_ERROR_OK && outMac != NULL) {
        /* Finalize operation */
        req->output.sz   = (size_t)*outMacLen;
        ret              = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)outMac, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->output.addr = outAddr;
            req->finalize    = 1;
            /* Also set local flag, as request will be trashed after a response
             * is received */
            finalize = 1;
        }
    }

    /* If this is just a deferred initialization (NULL key, but keyId set),
     * don't send a request - server will initialize on first update */
    if ((key == NULL) && (in == NULL) && (outMac == NULL)) {
        /* Just a keyId set operation, nothing to do via DMA */
        return 0;
    }

    if (ret == WH_ERROR_OK) {
        /* Send the request */
        ret = wh_Client_SendRequest(
            ctx, WH_MESSAGE_GROUP_CRYPTO_DMA, WC_ALGO_TYPE_CMAC,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);
    }

    if (ret == WH_ERROR_OK) {
        uint16_t respSz = 0;
        do {
            ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }

    if (ret == WH_ERROR_OK) {
        /* Get response structure pointer, validates generic header
         * rc */
        ret = _getCryptoResponse(dataPtr, WC_ALGO_TYPE_CMAC, (uint8_t**)&res);
        if (ret == WH_ERROR_OK && finalize) {
            /* Update outSz with actual size of CMAC output */
            *outMacLen = res->outSz;
        }
    }

    /* Restore devId, devCtx, and type after DMA operation */
    cmac->devId  = devId;
    cmac->devCtx = devCtx;
    cmac->type   = type;

    /* post address translation callbacks (for cleanup) */
    if (key != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)key, (void**)&keyAddr, req->key.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    if (in != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
    }
    if (outMac != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)outMac, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    }
    (void)wh_Client_DmaProcessClientAddress(
        ctx, (uintptr_t)cmac, (void**)&stateAddr, req->state.sz,
        WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* WOLFSSL_CMAC */

#ifndef NO_SHA256

static int _xferSha256BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha256*       sha256,
                                           uint32_t         isLastBlock)
{
    uint16_t                        group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                        action  = WH_MESSAGE_ACTION_NONE;
    int                             ret     = 0;
    uint16_t                        dataSz  = 0;
    whMessageCrypto_Sha256Request*  req     = NULL;
    whMessageCrypto_Sha2Response*   res     = NULL;
    uint8_t*                        dataPtr = NULL;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha256Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA256);


    /* Send the full block to the server, along with the
     * current hash state if needed. Finalization/padding of last block is up to
     * the server, we just need to let it know we are done and sending an
     * incomplete last block */
    if (isLastBlock) {
        req->isLastBlock  = 1;
        req->lastBlockLen = sha256->buffLen;
    }
    else {
        req->isLastBlock = 0;
    }
    memcpy(req->inBlock, sha256->buffer,
            (isLastBlock) ? sha256->buffLen : WC_SHA256_BLOCK_SIZE);

    /* Send the hash state - this will be 0 on the first block on a properly
     * initialized sha256 struct */
    memcpy(req->resumeState.hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha256->hiLen;
    req->resumeState.loLen = sha256->loLen;

    uint32_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HASH, req_len,
                                (uint8_t*)dataPtr);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] send SHA256 Req:\n");
    wh_Utils_Hexdump("[client] inBlock: ", req->inBlock, WC_SHA256_BLOCK_SIZE);
    if (req->resumeState.hiLen != 0 || req->resumeState.loLen != 0) {
        wh_Utils_Hexdump("  [client] resumeHash: ", req->resumeState.hash,
                         (isLastBlock) ? req->lastBlockLen
                                       : WC_SHA256_BLOCK_SIZE);
        printf("  [client] hiLen: %u, loLen: %u\n",
               (unsigned int)req->resumeState.hiLen,
               (unsigned int)req->resumeState.loLen);
    }
    printf("  [client] ret = %d\n", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        /* Get response */
        ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256, (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA256 Res recv: ret=%d", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
            /* Store the received intermediate hash in the sha256
             * context and indicate the field is now valid and
             * should be passed back and forth to the server */
            memcpy(sha256->digest, res->hash, WC_SHA256_DIGEST_SIZE);
            sha256->hiLen = res->hiLen;
            sha256->loLen = res->loLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA256 Res recv:\n");
            wh_Utils_Hexdump("[client] hash: ", (uint8_t*)sha256->digest,
                             WC_SHA256_DIGEST_SIZE);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
    }

    return ret;
}

int wh_Client_Sha256(whClientContext* ctx, wc_Sha256* sha256, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int      ret               = 0;
    uint8_t* sha256BufferBytes = (uint8_t*)sha256->buffer;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha256Hash(sha256, data, len, NULL) */
    if (in != NULL) {
        size_t i = 0;

        /* Process the partial blocks directly from the input data. If there
         * is enough input data to fill a full block, transfer it to the
         * server */
        if (sha256->buffLen > 0) {
            while (i < inLen && sha256->buffLen < WC_SHA256_BLOCK_SIZE) {
                sha256BufferBytes[sha256->buffLen++] = in[i++];
            }
            if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
                ret = _xferSha256BlockAndUpdateDigest(ctx, sha256, 0);
                sha256->buffLen = 0;
            }
        }

        /* Process as many full blocks from the input data as we can */
        while ((inLen - i) >= WC_SHA256_BLOCK_SIZE) {
            memcpy(sha256BufferBytes, in + i, WC_SHA256_BLOCK_SIZE);
            ret = _xferSha256BlockAndUpdateDigest(ctx, sha256, 0);
            i += WC_SHA256_BLOCK_SIZE;
        }

        /* Copy any remaining data into the buffer to be sent in a
         * subsequent call when we have enough input data to send a full
         * block */
        while (i < inLen) {
            sha256BufferBytes[sha256->buffLen++] = in[i++];
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha256Hash(sha256, NULL, 0, * hash) */
    if (out != NULL) {
        ret = _xferSha256BlockAndUpdateDigest(ctx, sha256, 1);

        /* Copy out the final hash value */
        if (ret == 0) {
            memcpy(out, sha256->digest, WC_SHA256_DIGEST_SIZE);
        }

        /* reset the state of the sha context (without blowing away devId) */
        wc_InitSha256_ex(sha256, NULL, sha256->devId);
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha256Dma(whClientContext* ctx, wc_Sha256* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int                                ret     = WH_ERROR_OK;
    wc_Sha256*                         sha256  = sha;
    uint16_t                           respSz  = 0;
    uint16_t                           group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint8_t*                           dataPtr = NULL;
    whMessageCrypto_Sha2DmaRequest*    req     = NULL;
    whMessageCrypto_Sha2DmaResponse*   resp    = NULL;
    uintptr_t inAddr = 0; /* The req->input.addr is reused elsewhere, this
                             local variable is to keep track of the resulting
                             DMA translation to pass back to the callback on
                             POST operations. */
    uintptr_t outAddr   = 0;
    uintptr_t stateAddr = 0;

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha2DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA256);

    /* map addresses and setup default request structure */
    if (in != NULL || out != NULL) {
        req->finalize    = 0;
        req->state.sz    = sizeof(*sha256);
        req->input.sz    = inLen;
        req->output.sz   = WC_SHA256_DIGEST_SIZE; /* not needed, but YOLO */

        /* Perform address translations */
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha256, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->state.addr = stateAddr;
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->input.addr = inAddr;
            }
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->output.addr = outAddr;
            }
        }
    }

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha256Hash(sha256, data, len, NULL) */
    if ((ret == WH_ERROR_OK) && (in != NULL)) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA256 DMA UPDATE: inAddr=%p, inSz=%u\n", in,
               (unsigned int)inLen);
#endif

        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the context
             * in client memory */
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha256Hash(sha256, NULL, 0, * hash) */
    if ((ret == WH_ERROR_OK) && (out != NULL)) {
        /* Packet will have been trashed, so re-populate all fields */
        req->finalize = 1;
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA256 DMA FINAL: outAddr=%p\n", out);
#endif
        /* send the request to the server */
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* Copy out the final hash value */
        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA256,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the output
             * hash in client memory */
        }
    }

    /* This is called regardless of successful operation to give the callback a
     * chance for cleanup. i.e if XMALLOC had been used and XFREE call is
     * needed. Don't override return value with closing process address calls.*/
    if (in != NULL || out != NULL) {
        /* post operation address translations */
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha256, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    }

    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_SHA224

static int _xferSha224BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha224*       sha224,
                                           uint32_t         isLastBlock)
{
    uint16_t                       group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                       action  = WH_MESSAGE_ACTION_NONE;
    int                            ret     = 0;
    uint16_t                       dataSz  = 0;
    whMessageCrypto_Sha256Request* req     = NULL;
    whMessageCrypto_Sha2Response*  res     = NULL;
    uint8_t*                       dataPtr = NULL;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha256Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA224);


    /* Send the full block to the server, along with the
     * current hash state if needed. Finalization/padding of last block is up to
     * the server, we just need to let it know we are done and sending an
     * incomplete last block */
    if (isLastBlock) {
        req->isLastBlock  = 1;
        req->lastBlockLen = sha224->buffLen;
    }
    else {
        req->isLastBlock = 0;
    }
    memcpy(req->inBlock, sha224->buffer,
           (isLastBlock) ? sha224->buffLen : WC_SHA224_BLOCK_SIZE);

    /* Send the hash state - this will be 0 on the first block on a properly
     * initialized sha224 struct */
    memcpy(req->resumeState.hash, sha224->digest, WC_SHA256_DIGEST_SIZE);
    req->resumeState.hiLen = sha224->hiLen;
    req->resumeState.loLen = sha224->loLen;

    uint32_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HASH, req_len,
                                (uint8_t*)dataPtr);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] send SHA224 Req:\n");
    wh_Utils_Hexdump("[client] inBlock: ", req->inBlock, WC_SHA224_BLOCK_SIZE);
    if (req->resumeState.hiLen != 0 || req->resumeState.loLen != 0) {
        wh_Utils_Hexdump("  [client] resumeHash: ", req->resumeState.hash,
                         (isLastBlock) ? req->lastBlockLen
                                       : WC_SHA224_BLOCK_SIZE);
        printf("  [client] hiLen: %u, loLen: %u\n", req->resumeState.hiLen,
               req->resumeState.loLen);
    }
    printf("  [client] ret = %d\n", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        /* Get response */
        ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224, (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA224 Res recv: ret=%d", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
            /* Store the received intermediate hash in the sha224
             * context and indicate the field is now valid and
             * should be passed back and forth to the server.
             * The digest length is the same as sha256
             * for intermediate operation. Final output will be
             * truncated to WC_SHA224_DIGEST_SIZE.
             */
            memcpy(sha224->digest, res->hash, WC_SHA256_DIGEST_SIZE);
            sha224->hiLen = res->hiLen;
            sha224->loLen = res->loLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA224 Res recv:\n");
            wh_Utils_Hexdump("[client] hash: ", (uint8_t*)sha224->digest,
                             WC_SHA224_DIGEST_SIZE);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
    }

    return ret;
}

int wh_Client_Sha224(whClientContext* ctx, wc_Sha224* sha224, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int      ret               = 0;
    uint8_t* sha224BufferBytes = (uint8_t*)sha224->buffer;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha224Hash(sha224, data, len, NULL) */
    if (in != NULL) {
        size_t i = 0;

        /* Process the partial blocks directly from the input data. If there
         * is enough input data to fill a full block, transfer it to the
         * server */
        if (sha224->buffLen > 0) {
            while (i < inLen && sha224->buffLen < WC_SHA224_BLOCK_SIZE) {
                sha224BufferBytes[sha224->buffLen++] = in[i++];
            }
            if (sha224->buffLen == WC_SHA224_BLOCK_SIZE) {
                ret = _xferSha224BlockAndUpdateDigest(ctx, sha224, 0);
                sha224->buffLen = 0;
            }
        }

        /* Process as many full blocks from the input data as we can */
        while ((inLen - i) >= WC_SHA224_BLOCK_SIZE) {
            memcpy(sha224BufferBytes, in + i, WC_SHA224_BLOCK_SIZE);
            ret = _xferSha224BlockAndUpdateDigest(ctx, sha224, 0);
            i += WC_SHA224_BLOCK_SIZE;
        }

        /* Copy any remaining data into the buffer to be sent in a
         * subsequent call when we have enough input data to send a full
         * block */
        while (i < inLen) {
            sha224BufferBytes[sha224->buffLen++] = in[i++];
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha224Hash(sha224, NULL, 0, * hash) */
    if (out != NULL) {
        ret = _xferSha224BlockAndUpdateDigest(ctx, sha224, 1);

        /* Copy out the final hash value */
        if (ret == 0) {
            memcpy(out, sha224->digest, WC_SHA224_DIGEST_SIZE);
        }

        /* reset the state of the sha context (without blowing away devId) */
        wc_InitSha224_ex(sha224, NULL, sha224->devId);
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha224Dma(whClientContext* ctx, wc_Sha224* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    wc_Sha224*                       sha224  = sha;
    uint16_t                         respSz  = 0;
    uint16_t                         group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaRequest*  req     = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uintptr_t                        inAddr    = 0;
    uintptr_t                        outAddr   = 0;
    uintptr_t                        stateAddr = 0;

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha2DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA224);

    if (in != NULL || out != NULL) {
        req->state.sz  = sizeof(*sha224);
        req->input.sz  = inLen;
        req->output.sz = WC_SHA224_DIGEST_SIZE; /* not needed, but YOLO */

        /* Perform address translations */
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha224, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->state.addr = stateAddr;
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->input.addr = inAddr;
            }
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->output.addr = outAddr;
            }
        }
    }

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha224Hash(sha224, data, len, NULL) */
    if (in != NULL && ret == WH_ERROR_OK) {
        req->finalize    = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA224 DMA UPDATE: inAddr=%p, inSz=%u\n", in,
               (unsigned int)inLen);
#endif
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the context
             * in client memory */
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha224Hash(sha224, NULL, 0, * hash) */
    if ((ret == WH_ERROR_OK) && (out != NULL)) {
        /* Packet will have been trashed, so re-populate all fields */
        req->finalize = 1;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA224 DMA FINAL: outAddr=%p\n", out);
#endif
        /* send the request to the server */
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* Copy out the final hash value */
        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA224,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the output
             * hash in client memory */
        }
    }

    if (in != NULL || out != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha224, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA224 */

#ifdef WOLFSSL_SHA384

static int _xferSha384BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha384*       sha384,
                                           uint32_t         isLastBlock)
{
    uint16_t                       group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                       action  = WH_MESSAGE_ACTION_NONE;
    int                            ret     = 0;
    uint16_t                       dataSz  = 0;
    whMessageCrypto_Sha512Request* req     = NULL;
    whMessageCrypto_Sha2Response*  res     = NULL;
    uint8_t*                       dataPtr = NULL;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha512Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA384);


    /* Send the full block to the server, along with the
     * current hash state if needed. Finalization/padding of last block is up to
     * the server, we just need to let it know we are done and sending an
     * incomplete last block */
    if (isLastBlock) {
        req->isLastBlock  = 1;
        req->lastBlockLen = sha384->buffLen;
    }
    else {
        req->isLastBlock = 0;
    }
    memcpy(req->inBlock, sha384->buffer,
           (isLastBlock) ? sha384->buffLen : WC_SHA384_BLOCK_SIZE);

    /* Send the hash state - this will be 0 on the first block on a properly
     * initialized sha384 struct */
    memcpy(req->resumeState.hash, sha384->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen = sha384->hiLen;
    req->resumeState.loLen = sha384->loLen;

    uint32_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HASH, req_len,
                                (uint8_t*)dataPtr);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] send SHA384 Req:\n");
    wh_Utils_Hexdump("[client] inBlock: ", req->inBlock, WC_SHA384_BLOCK_SIZE);
    if (req->resumeState.hiLen != 0 || req->resumeState.loLen != 0) {
        wh_Utils_Hexdump("  [client] resumeHash: ", req->resumeState.hash,
                         (isLastBlock) ? req->lastBlockLen
                                       : WC_SHA384_BLOCK_SIZE);
        printf("  [client] hiLen: %u, loLen: %u\n", req->resumeState.hiLen,
               req->resumeState.loLen);
    }
    printf("  [client] ret = %d\n", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        /* Get response */
        ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384, (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA384 Res recv: ret=%d", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
            /* Store the received intermediate hash in the sha384
             * context and indicate the field is now valid and
             * should be passed back and forth to the server
             * The digest length is the same as sha512
             * for intermediate operation. Final output will be
             * truncated to WC_SHA384_DIGEST_SIZE.
             */
            memcpy(sha384->digest, res->hash, WC_SHA512_DIGEST_SIZE);
            sha384->hiLen = res->hiLen;
            sha384->loLen = res->loLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA384 Res recv:\n");
            wh_Utils_Hexdump("[client] hash: ", (uint8_t*)sha384->digest,
                             WC_SHA384_DIGEST_SIZE);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
    }

    return ret;
}

int wh_Client_Sha384(whClientContext* ctx, wc_Sha384* sha384, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int      ret               = 0;
    uint8_t* sha384BufferBytes = (uint8_t*)sha384->buffer;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha384Hash(sha384, data, len, NULL) */
    if (in != NULL) {
        size_t i = 0;

        /* Process the partial blocks directly from the input data. If there
         * is enough input data to fill a full block, transfer it to the
         * server */
        if (sha384->buffLen > 0) {
            while (i < inLen && sha384->buffLen < WC_SHA384_BLOCK_SIZE) {
                sha384BufferBytes[sha384->buffLen++] = in[i++];
            }
            if (sha384->buffLen == WC_SHA384_BLOCK_SIZE) {
                ret = _xferSha384BlockAndUpdateDigest(ctx, sha384, 0);
                sha384->buffLen = 0;
            }
        }

        /* Process as many full blocks from the input data as we can */
        while ((inLen - i) >= WC_SHA384_BLOCK_SIZE) {
            memcpy(sha384BufferBytes, in + i, WC_SHA384_BLOCK_SIZE);
            ret = _xferSha384BlockAndUpdateDigest(ctx, sha384, 0);
            i += WC_SHA384_BLOCK_SIZE;
        }

        /* Copy any remaining data into the buffer to be sent in a
         * subsequent call when we have enough input data to send a full
         * block */
        while (i < inLen) {
            sha384BufferBytes[sha384->buffLen++] = in[i++];
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha384Hash(sha384, NULL, 0, * hash) */
    if (out != NULL) {
        ret = _xferSha384BlockAndUpdateDigest(ctx, sha384, 1);

        /* Copy out the final hash value */
        if (ret == 0) {
            memcpy(out, sha384->digest, WC_SHA384_DIGEST_SIZE);
        }

        /* reset the state of the sha context (without blowing away devId) */
        wc_InitSha384_ex(sha384, NULL, sha384->devId);
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha384Dma(whClientContext* ctx, wc_Sha384* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    wc_Sha384*                       sha384  = sha;
    uint16_t                         respSz  = 0;
    uint16_t                         group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaRequest*  req     = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uintptr_t                        inAddr    = 0;
    uintptr_t                        outAddr   = 0;
    uintptr_t                        stateAddr = 0;

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha2DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA384);

    if (in != NULL || out != NULL) {
        req->state.sz  = sizeof(*sha384);
        req->input.sz  = inLen;
        req->output.sz = WC_SHA384_DIGEST_SIZE; /* not needed, but YOLO */

        /* Perform address translations */
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha384, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->state.addr = stateAddr;
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->input.addr = inAddr;
            }
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->output.addr = outAddr;
            }
        }
    }

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha384Hash(sha384, data, len, NULL) */
    if (in != NULL && ret == WH_ERROR_OK) {
        req->finalize = 0;
#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA384 DMA UPDATE: inAddr=%p, inSz=%u\n", in,
               (unsigned int)inLen);
#endif
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the context
             * in client memory */
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha384Hash(sha384, NULL, 0, * hash) */
    if ((ret == WH_ERROR_OK) && (out != NULL)) {
        /* Packet will have been trashed, so re-populate all fields */
        req->finalize = 1;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA384 DMA FINAL: outAddr=%p\n", out);
#endif
        /* send the request to the server */
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* Copy out the final hash value */
        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA384,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the output
             * hash in client memory */
        }
    }

    if (in != NULL || out != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha384, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */
#endif /* WOLFSSL_SHA384 */


#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_SHA512_HASHTYPE)

static int _xferSha512BlockAndUpdateDigest(whClientContext* ctx,
                                           wc_Sha512*       sha512,
                                           uint32_t         isLastBlock)
{
    uint16_t                       group   = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t                       action  = WH_MESSAGE_ACTION_NONE;
    int                            ret     = 0;
    uint16_t                       dataSz  = 0;
    whMessageCrypto_Sha512Request* req     = NULL;
    whMessageCrypto_Sha2Response*  res     = NULL;
    uint8_t*                       dataPtr = NULL;

    /* Get data buffer */
    dataPtr = wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha512Request*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA512);


    /* Send the full block to the server, along with the
     * current hash state if needed. Finalization/padding of last block is up to
     * the server, we just need to let it know we are done and sending an
     * incomplete last block */
    if (isLastBlock) {
        req->isLastBlock  = 1;
        req->lastBlockLen = sha512->buffLen;
    }
    else {
        req->isLastBlock = 0;
    }
    memcpy(req->inBlock, sha512->buffer,
           (isLastBlock) ? sha512->buffLen : WC_SHA512_BLOCK_SIZE);

    /* Send the hash state - this will be 0 on the first block on a properly
     * initialized sha512 struct */
    memcpy(req->resumeState.hash, sha512->digest, WC_SHA512_DIGEST_SIZE);
    req->resumeState.hiLen    = sha512->hiLen;
    req->resumeState.loLen    = sha512->loLen;
    req->resumeState.hashType = sha512->hashType;
    uint32_t req_len =
        sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

    ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_HASH, req_len,
                                (uint8_t*)dataPtr);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] send SHA512 Req:\n");
    wh_Utils_Hexdump("[client] inBlock: ", req->inBlock, WC_SHA512_BLOCK_SIZE);
    if (req->resumeState.hiLen != 0 || req->resumeState.loLen != 0) {
        wh_Utils_Hexdump("  [client] resumeHash: ", req->resumeState.hash,
                         (isLastBlock) ? req->lastBlockLen
                                       : WC_SHA512_BLOCK_SIZE);
        printf("  [client] hiLen: %u, loLen: %u\n", req->resumeState.hiLen,
               req->resumeState.loLen);
    }
    printf("  [client] ret = %d\n", ret);
#endif /* DEBUG_CRYPTOCB_VERBOSE */

    if (ret == 0) {
        do {
            ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                                         (uint8_t*)dataPtr);
        } while (ret == WH_ERROR_NOTREADY);
    }
    if (ret == 0) {
        /* Get response */
        ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512, (uint8_t**)&res);
        /* wolfCrypt allows positive error codes on success in some scenarios */
        if (ret >= 0) {
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA512 Res recv: ret=%d", ret);
            printf("[client] hashType: %d\n", sha512->hashType);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
            /* Store the received intermediate hash in the sha512
             * context and indicate the field is now valid and
             * should be passed back and forth to the server */
            memcpy(sha512->digest, res->hash, WC_SHA512_DIGEST_SIZE);
            sha512->hiLen = res->hiLen;
            sha512->loLen = res->loLen;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] Client SHA512 Res recv:\n");
            wh_Utils_Hexdump("[client] hash: ", (uint8_t*)sha512->digest,
                             WC_SHA512_DIGEST_SIZE);
#endif /* DEBUG_CRYPTOCB_VERBOSE */
        }
    }

    return ret;
}

int wh_Client_Sha512(whClientContext* ctx, wc_Sha512* sha512, const uint8_t* in,
                     uint32_t inLen, uint8_t* out)
{
    int      ret               = 0;
    uint8_t* sha512BufferBytes = (uint8_t*)sha512->buffer;
    int      hashType          = WC_HASH_TYPE_SHA512;

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha512Hash(sha512, data, len, NULL) */
    if (in != NULL) {
        size_t i = 0;

        /* Process the partial blocks directly from the input data. If there
         * is enough input data to fill a full block, transfer it to the
         * server */
        if (sha512->buffLen > 0) {
            while (i < inLen && sha512->buffLen < WC_SHA512_BLOCK_SIZE) {
                sha512BufferBytes[sha512->buffLen++] = in[i++];
            }
            if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
                ret = _xferSha512BlockAndUpdateDigest(ctx, sha512, 0);
                sha512->buffLen = 0;
            }
        }

        /* Process as many full blocks from the input data as we can */
        while ((inLen - i) >= WC_SHA512_BLOCK_SIZE) {
            memcpy(sha512BufferBytes, in + i, WC_SHA512_BLOCK_SIZE);
            ret = _xferSha512BlockAndUpdateDigest(ctx, sha512, 0);
            i += WC_SHA512_BLOCK_SIZE;
        }

        /* Copy any remaining data into the buffer to be sent in a
         * subsequent call when we have enough input data to send a full
         * block */
        while (i < inLen) {
            sha512BufferBytes[sha512->buffLen++] = in[i++];
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha512Hash(sha512, NULL, 0, * hash) */
    if (out != NULL) {
        ret = _xferSha512BlockAndUpdateDigest(ctx, sha512, 1);

        /* Copy out the final hash value */
        if (ret == 0) {
            memcpy(out, sha512->digest, WC_SHA512_DIGEST_SIZE);
        }
        /* keep hashtype before initialization */
        hashType = sha512->hashType;
        /* reset the state of the sha context (without blowing away devId and
         *  hashType)
         */
        switch (hashType) {
            case WC_HASH_TYPE_SHA512_224:
                ret = wc_InitSha512_224_ex(sha512, NULL, sha512->devId);
                break;
            case WC_HASH_TYPE_SHA512_256:
                ret = wc_InitSha512_256_ex(sha512, NULL, sha512->devId);
                break;
            default:
                ret = wc_InitSha512_ex(sha512, NULL, sha512->devId);
                break;
        }
    }

    return ret;
}

#ifdef WOLFHSM_CFG_DMA
int wh_Client_Sha512Dma(whClientContext* ctx, wc_Sha512* sha, const uint8_t* in,
                        uint32_t inLen, uint8_t* out)
{
    int                              ret     = WH_ERROR_OK;
    wc_Sha512*                       sha512  = sha;
    uint16_t                         respSz  = 0;
    uint16_t                         group   = WH_MESSAGE_GROUP_CRYPTO_DMA;
    uint8_t*                         dataPtr = NULL;
    whMessageCrypto_Sha2DmaRequest*  req     = NULL;
    whMessageCrypto_Sha2DmaResponse* resp    = NULL;
    uintptr_t                        inAddr    = 0;
    uintptr_t                        outAddr   = 0;
    uintptr_t                        stateAddr = 0;

    /* Get data pointer from the context to use as request/response storage */
    dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
    if (dataPtr == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Setup generic header and get pointer to request data */
    req = (whMessageCrypto_Sha2DmaRequest*)_createCryptoRequest(
        dataPtr, WC_HASH_TYPE_SHA512);

    if (in != NULL || out != NULL) {
        req->state.sz  = sizeof(*sha512);
        req->input.sz  = inLen;
        req->output.sz = WC_SHA512_DIGEST_SIZE; /* not needed, but YOLO */

        /* Perform address translations */
        ret = wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha512, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
        if (ret == WH_ERROR_OK) {
            req->state.addr = stateAddr;
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
                WH_DMA_OPER_CLIENT_READ_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->input.addr = inAddr;
            }
        }

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
                WH_DMA_OPER_CLIENT_WRITE_PRE, (whDmaFlags){0});
            if (ret == WH_ERROR_OK) {
                req->output.addr = outAddr;
            }
        }
    }

    /* Caller invoked SHA Update:
     * wc_CryptoCb_Sha512Hash(sha512, data, len, NULL) */
    if (in != NULL && ret == WH_ERROR_OK) {
        req->finalize    = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA512 DMA UPDATE: inAddr=%p, inSz=%u\n", in,
               (unsigned int)inLen);
#endif
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the context
             * in client memory */
        }
    }

    /* Caller invoked SHA finalize:
     * wc_CryptoCb_Sha512Hash(sha512, NULL, 0, * hash) */
    if ((ret == WH_ERROR_OK) && (out != NULL)) {
        /* Packet will have been trashed, so re-populate all fields */
        req->finalize = 1;

#ifdef DEBUG_CRYPTOCB_VERBOSE
        printf("[client] SHA512 DMA FINAL: outAddr=%p\n", out);
#endif
        /* send the request to the server */
        ret = wh_Client_SendRequest(
            ctx, group, WC_ALGO_TYPE_HASH,
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req),
            (uint8_t*)dataPtr);

        if (ret == WH_ERROR_OK) {
            do {
                ret = wh_Client_RecvResponse(ctx, NULL, NULL, &respSz,
                                             (uint8_t*)dataPtr);
            } while (ret == WH_ERROR_NOTREADY);
        }

        /* Copy out the final hash value */
        if (ret == WH_ERROR_OK) {
            /* Get response structure pointer, validates generic header
             * rc */
            ret = _getCryptoResponse(dataPtr, WC_HASH_TYPE_SHA512,
                                     (uint8_t**)&resp);
            /* Nothing to do on success, as server will have updated the output
             * hash in client memory */
        }
    }

    if (in != NULL || out != NULL) {
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)sha512, (void**)&stateAddr, req->state.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)in, (void**)&inAddr, req->input.sz,
            WH_DMA_OPER_CLIENT_READ_POST, (whDmaFlags){0});
        (void)wh_Client_DmaProcessClientAddress(
            ctx, (uintptr_t)out, (void**)&outAddr, req->output.sz,
            WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
    }
    return ret;
}
#endif /* WOLFHSM_CFG_DMA  */
#endif /* WOLFSSL_SHA512 */

#ifdef HAVE_DILITHIUM

int wh_Client_MlDsaSetKeyId(MlDsaKey* key, whKeyId keyId)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    key->devCtx = WH_KEYID_TO_DEVCTX(keyId);

    return WH_ERROR_OK;
}

int wh_Client_MlDsaGetKeyId(MlDsaKey* key, whKeyId* outId)
{
    if (key == NULL || outId == NULL) {
        return WH_ERROR_BADARGS;
    }

    *outId = WH_DEVCTX_TO_KEYID(key->devCtx);

    return WH_ERROR_OK;
}

int wh_Client_MlDsaImportKey(whClientContext* ctx, MlDsaKey* key,
                             whKeyId* inout_keyId, whNvmFlags flags,
                             uint16_t label_len, uint8_t* label)
{
    int      ret    = WH_ERROR_OK;
    whKeyId  key_id = WH_KEYID_ERASED;
    byte     buffer[DILITHIUM_MAX_PRV_KEY_SIZE];
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s serialize ret:%d, key:%p, max_size:%u, buffer:%p, "
           "outlen:%u\n",
           __func__, ret, key, (unsigned int)sizeof(buffer), buffer,
           buffer_len);
#endif
    if (ret == WH_ERROR_OK) {
        /* Cache the key and get the keyID */
        ret = wh_Client_KeyCache(ctx, flags, label, label_len, buffer,
                                 buffer_len, &key_id);
        if ((ret == WH_ERROR_OK) && (inout_keyId != NULL)) {
            *inout_keyId = key_id;
        }
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s label:%.*s ret:%d keyid:%u\n", __func__, label_len,
           label, ret, key_id);
#endif
    return ret;
}

int wh_Client_MlDsaExportKey(whClientContext* ctx, whKeyId keyId, MlDsaKey* key,
                             uint16_t label_len, uint8_t* label)
{
    int ret = WH_ERROR_OK;
    /* buffer cannot be larger than MTU */
    byte     buffer[DILITHIUM_MAX_PRV_KEY_SIZE];
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

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x key:%p ret:%d label:%.*s\n", __func__, keyId,
           key, ret, (int)label_len, label);
#endif
    return ret;
}

static int _MlDsaMakeKey(whClientContext* ctx, int size, int level,
                         whKeyId* inout_key_id, whNvmFlags flags,
                         uint16_t label_len, uint8_t* label, MlDsaKey* key)
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
        dataPtr, WC_PK_TYPE_PQC_SIG_KEYGEN, WC_PQC_SIG_TYPE_DILITHIUM);

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
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("[client] %s Req sent:size:%u, ret:%d\n", __func__,
                   (unsigned int)req->sz, ret);
#endif
            if (ret == 0) {
                uint16_t res_len;
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        printf(
                            "[client] %s Res recv:keyid:%u, len:%u, ret:%d\n",
                            __func__, (unsigned int)res->keyId,
                            (unsigned int)res->len, ret);
#endif
                        /* Key is cached on server or is ephemeral */
                        key_id = (whKeyId)(res->keyId);

                        /* Update output variable if requested */
                        if (inout_key_id != NULL) {
                            *inout_key_id = key_id;
                        }

                        /* Update the context if provided */
                        if (key != NULL) {
                            uint16_t der_size = (uint16_t)(res->len);
                            /* Set the key_id. Should be ERASED if EPHEMERAL */
                            wh_Client_MlDsaSetKeyId(key, key_id);

                            if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                                uint8_t* key_der = (uint8_t*)(res + 1);
                                /* Response has the exported key */
                                ret = wh_Crypto_MlDsaDeserializeKeyDer(
                                    key_der, der_size, key);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                                wh_Utils_Hexdump(
                                    "[client] ML-DSA KeyGen export:", key_der,
                                    der_size);
#endif
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

int wh_Client_MlDsaMakeExportKey(whClientContext* ctx, int level, int size,
                                 MlDsaKey* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlDsaMakeKey(ctx, size, level, NULL, WH_NVM_FLAGS_EPHEMERAL, 0,
                         NULL, key);
}


int wh_Client_MlDsaSign(whClientContext* ctx, const byte* in, word32 in_len,
                        byte* out, word32* inout_len, MlDsaKey* key)
{
    int                                ret     = 0;
    whMessageCrypto_MlDsaSignRequest*  req     = NULL;
    whMessageCrypto_MlDsaSignResponse* res     = NULL;
    uint8_t*                           dataPtr = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ctx:%p key:%p, in:%p in_len:%u, out:%p inout_len:%p\n",
           __func__, ctx, key, in, (unsigned)in_len, out, inout_len);
#endif

    if ((ctx == NULL) || (key == NULL) || ((in == NULL) && (in_len > 0)) ||
        (out == NULL) || (inout_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x, in_len:%u, inout_len:%p\n", __func__, key_id,
           in_len, inout_len);
#endif

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempMlDsaSign";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

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

        uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(*req) + in_len;
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
                dataPtr, WC_PK_TYPE_PQC_SIG_SIGN, WC_PQC_SIG_TYPE_DILITHIUM);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint8_t* req_hash = (uint8_t*)(req + 1);
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->level;
            req->keyId   = key_id;
            req->sz      = in_len;
            if ((in != NULL) && (in_len > 0)) {
                memcpy(req_hash, in, in_len);
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
                        uint8_t* res_sig = (uint8_t*)(res + 1);
                        uint16_t sig_len = res->sz;
                        /* check inoutlen and read out */
                        if (inout_len != NULL) {
                            if (sig_len > *inout_len) {
                                /* Silently truncate the signature */
                                sig_len = *inout_len;
                            }
                            *inout_len = sig_len;
                            if ((out != NULL) && (sig_len > 0)) {
                                memcpy(out, res_sig, sig_len);
                            }
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

int wh_Client_MlDsaVerify(whClientContext* ctx, const byte* sig, word32 sig_len,
                          const byte* msg, word32 msg_len, int* out_res,
                          MlDsaKey* key)
{
    int                                  ret     = WH_ERROR_OK;
    uint8_t*                             dataPtr = NULL;
    whMessageCrypto_MlDsaVerifyRequest*  req     = NULL;
    whMessageCrypto_MlDsaVerifyResponse* res     = NULL;

    /* Transaction state */
    whKeyId key_id;
    int     evict = 0;


#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ctx:%p key:%p, sig:%p sig_len:%u, msg:%p msg_len:%u "
           "out_res:%p\n",
           __func__, ctx, key, sig, sig_len, msg, msg_len, out_res);
#endif

    if ((ctx == NULL) || (key == NULL) || ((sig == NULL) && (sig_len > 0)) ||
        ((msg == NULL) && (msg_len > 0))) {
        return WH_ERROR_BADARGS;
    }

    key_id = WH_DEVCTX_TO_KEYID(key->devCtx);

    /* Import key if necessary */
    if (WH_KEYID_ISERASED(key_id)) {
        /* Must import the key to the server and evict it afterwards */
        uint8_t    keyLabel[] = "TempMlDsaVerify";
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

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

        uint16_t req_len = sizeof(whMessageCrypto_GenericRequestHeader) +
                           sizeof(*req) + sig_len + msg_len;


        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_MlDsaVerifyRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_SIG_VERIFY,
                                            WC_PQC_SIG_TYPE_DILITHIUM);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            uint8_t* req_sig  = (uint8_t*)(req + 1);
            uint8_t* req_hash = req_sig + sig_len;

            /* Set request packet members */
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->level;
            req->keyId   = key_id;
            req->sigSz   = sig_len;
            if ((sig != NULL) && (sig_len > 0)) {
                memcpy(req_sig, sig, sig_len);
            }
            req->hashSz = msg_len;
            if ((msg != NULL) && (msg_len > 0)) {
                memcpy(req_hash, msg, msg_len);
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
                        *out_res = res->res;
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
#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s ret:%d\n", __func__, ret);
#endif
    return ret;
}

int wh_Client_MlDsaCheckPrivKey(whClientContext* ctx, MlDsaKey* key,
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

int wh_Client_MlDsaImportKeyDma(whClientContext* ctx, MlDsaKey* key,
                                whKeyId* inout_keyId, whNvmFlags flags,
                                uint16_t label_len, uint8_t* label)
{
    int      ret    = WH_ERROR_OK;
    whKeyId  key_id = WH_KEYID_ERASED;
    byte     buffer[DILITHIUM_MAX_PRV_KEY_SIZE];
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
                                MlDsaKey* key, uint16_t label_len,
                                uint8_t* label)
{
    int      ret                                = WH_ERROR_OK;
    byte     buffer[DILITHIUM_MAX_PRV_KEY_SIZE] = {0};
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

static int _MlDsaMakeKeyDma(whClientContext* ctx, int level,
                            whKeyId* inout_key_id, whNvmFlags flags,
                            uint16_t label_len, uint8_t* label, MlDsaKey* key)
{
    int                                     ret    = WH_ERROR_OK;
    whKeyId                                 key_id = WH_KEYID_ERASED;
    byte                                    buffer[DILITHIUM_MAX_PRV_KEY_SIZE];
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
            dataPtr, WC_PK_TYPE_PQC_SIG_KEYGEN, WC_PQC_SIG_TYPE_DILITHIUM);

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

        if (ret == WH_ERROR_OK) {
            ret = wh_Client_SendRequest(ctx, group, action, req_len,
                                        (uint8_t*)dataPtr);
        }
        if (ret == WH_ERROR_OK) {
            uint16_t res_len;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &res_len,
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
                /* Key is cached on server or is ephemeral */
                key_id = (whKeyId)(res->keyId);

                /* Update output variable if requested */
                if (inout_key_id != NULL) {
                    *inout_key_id = key_id;
                }

                /* Update the context if provided */
                if (key != NULL) {
                    /* Set the key_id. Should be ERASED if EPHEMERAL */
                    wh_Client_MlDsaSetKeyId(key, key_id);

                    if (flags & WH_NVM_FLAGS_EPHEMERAL) {
                        /* Response has the exported key */
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
                                    MlDsaKey* key)
{
    if (key == NULL) {
        return WH_ERROR_BADARGS;
    }

    return _MlDsaMakeKeyDma(ctx, level, NULL, WH_NVM_FLAGS_EPHEMERAL, 0, NULL,
                            key);
}


int wh_Client_MlDsaSignDma(whClientContext* ctx, const byte* in, word32 in_len,
                           byte* out, word32* out_len, MlDsaKey* key)
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
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

        ret = wh_Client_MlDsaImportKeyDma(ctx, key, &key_id, flags,
                                          sizeof(keyLabel), keyLabel);
        if (ret == WH_ERROR_OK) {
            evict = 1;
        }
    }

#ifdef DEBUG_CRYPTOCB_VERBOSE
    printf("[client] %s keyid:%x, in_len:%u, inout_len:%p\n", __func__, key_id,
           in_len, out_len);
#endif

    if (ret == WH_ERROR_OK) {
        /* Request Message */
        uint16_t group  = WH_MESSAGE_GROUP_CRYPTO_DMA;
        uint16_t action = WC_ALGO_TYPE_PK;

        uint16_t req_len =
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);
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
                                            WC_PQC_SIG_TYPE_DILITHIUM);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->level;
            req->keyId   = key_id;

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
                ctx, (uintptr_t)out, (void**)&outAddr, req->sig.sz,
                WH_DMA_OPER_CLIENT_WRITE_POST, (whDmaFlags){0});
            (void)wh_Client_DmaProcessClientAddress(
                ctx, (uintptr_t)in, (void**)&inAddr, req->msg.sz,
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
                             int* out_res, MlDsaKey* key)
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
        whNvmFlags flags      = WH_NVM_FLAGS_NONE;

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
            sizeof(whMessageCrypto_GenericRequestHeader) + sizeof(*req);

        /* Get data pointer from the context to use as request/response storage
         */
        dataPtr = (uint8_t*)wh_CommClient_GetDataPtr(ctx->comm);
        if (dataPtr == NULL) {
            return WH_ERROR_BADARGS;
        }

        /* Setup generic header and get pointer to request data */
        req = (whMessageCrypto_MlDsaVerifyDmaRequest*)
            _createCryptoRequestWithSubtype(dataPtr, WC_PK_TYPE_PQC_SIG_VERIFY,
                                            WC_PQC_SIG_TYPE_DILITHIUM);

        if (req_len <= WOLFHSM_CFG_COMM_DATA_LEN) {
            if (evict != 0) {
                options |= WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT;
            }

            memset(req, 0, sizeof(*req));
            req->options = options;
            req->level   = key->level;
            req->keyId   = key_id;

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
                        /* Set verification result */
                        *out_res = res->verifyResult;
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


int wh_Client_MlDsaCheckPrivKeyDma(whClientContext* ctx, MlDsaKey* key,
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
#endif /* HAVE_DILITHIUM */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_ENABLE_CLIENT */
