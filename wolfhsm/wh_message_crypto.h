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
 * wolfhsm/wh_message_crypto.h
 *
 * Message structures and translation functions for crypto operations.
 */

#ifndef WOLFHSM_WH_MESSAGE_CRYPTO_H_
#define WOLFHSM_WH_MESSAGE_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_utils.h"

/*
 * Crypto Message Protocol Packet Structure
 *
 * +---------------------------+
 * |                           |
 * |      Comm Buffer Data     |
 * |                           |
 * | +-------------------------+
 * | |                         |
 * | | Generic Crypto Header   | <- Size of whMessageCrypto_GenericHeader
 * | | (Request or Response)   |    Could be either:
 * | |                         |    - whMessageCrypto_GenericRequestHeader
 * | |                         |       (client -> server)
 * | |                         |    - whMessageCrypto_GenericResponseHeader
 * | |                         |       (server -> client)
 * | +-------------------------+
 * | |                         |
 * | | Crypto-Specific Header  | <- Algorithm-specific request/response
 * | |                         |    (e.g., AesGcm, Rsa, Ecc, etc.)
 * | +-------------------------+
 * | |                         |
 * | |                         |
 * | |     Arbitrary Data      | <- Input/output data, keys, IVs, etc.
 * | |                         |    (layout defined by specific algorithm)
 * | |                         |
 * | +-------------------------+
 * |                           |
 * +---------------------------+
 */


/* Indicates the algorithm type for the requested crypto operation. Corresponds
 * to the wolfCrypt crypto callback subtype (e.g. cypher type, pk type, etc.) */
typedef uint32_t whMessageCrypto_AlgoType;

/* Generic crypto header message. This will always be the first element in any
 * crypto message and indicates how to interpret the rest of the message. */
typedef struct {
    whMessageCrypto_AlgoType algoType;    /* Type of crypto operation */
    whMessageCrypto_AlgoType algoSubType; /* Subtype, specific to algoType.
                                             Right now only used for PQ algos */
#define WH_MESSAGE_CRYPTO_ALGO_SUBTYPE_NONE 0
} whMessageCrypto_GenericRequestHeader;

/* Generic crypto response header message. This must always be the first element
 * in the response message. */
typedef struct {
    whMessageCrypto_AlgoType algoType; /* Type of crypto operation */
    int32_t                  rc;       /* Return code */
} whMessageCrypto_GenericResponseHeader;

WH_UTILS_STATIC_ASSERT(
    sizeof(whMessageCrypto_GenericRequestHeader) ==
        sizeof(whMessageCrypto_GenericResponseHeader),
    "GenericRequestHeader and GenericResponseHeader must be the same size");

/* Size allocated in the comm buffer data for the crypto request and response
 * headers. Because crypto operations process data in-place in the comm buffer,
 * the header sizes for the request and response protocol messages must be the
 * same. If they are not, then crypto input and output buffers will not overlap,
 * and crypto operations will fail in mysterious ways. */
typedef union {
    whMessageCrypto_GenericRequestHeader  request;
    whMessageCrypto_GenericResponseHeader response;
} whMessageCrypto_GenericHeader;

int wh_MessageCrypto_TranslateGenericRequestHeader(
    uint16_t magic, const whMessageCrypto_GenericRequestHeader* src,
    whMessageCrypto_GenericRequestHeader* dest);

int wh_MessageCrypto_TranslateGenericResponseHeader(
    uint16_t magic, const whMessageCrypto_GenericResponseHeader* src,
    whMessageCrypto_GenericResponseHeader* dest);


/*
 * RNG
 */

/* RNG Request */
typedef struct {
    uint32_t sz; /* Size of output data */
} whMessageCrypto_RngRequest;

/* RNG Response */
typedef struct {
    uint32_t sz; /* Size of output data */
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageCrypto_RngResponse;

int wh_MessageCrypto_TranslateRngRequest(uint16_t magic,
                                         const whMessageCrypto_RngRequest* src,
                                         whMessageCrypto_RngRequest* dest);

int wh_MessageCrypto_TranslateRngResponse(
    uint16_t magic, const whMessageCrypto_RngResponse* src,
    whMessageCrypto_RngResponse* dest);


/*
 * AES
 */
/* AES CTR Request */
typedef struct {
    uint32_t enc;       /* 1 for encrypt, 0 for decrypt */
    uint32_t keyLen;    /* Length of key in bytes */
    uint32_t sz;        /* Size of input data */
    uint16_t keyId;     /* Key ID if using stored key */
    uint32_t left;      /* unused bytes left from last call */
    uint8_t  WH_PAD[2]; /* Padding for alignment */
    /* Data follows:
     * uint8_t in[sz]
     * uint8_t key[keyLen]
     * uint8_t iv[AES_IV_SIZE]
     * uint8_t tmp[AES_BLOCK_SIZE]
     */
} whMessageCrypto_AesCtrRequest;
/* AES CTR Response */
typedef struct {
    uint32_t sz;   /* Size of output data */
    uint32_t left; /* unused bytes left from last call */
    /* Pad to ensure overlap for input and output buffers */
    uint8_t
        WH_PAD[sizeof(whMessageCrypto_AesCtrRequest) - (sizeof(uint32_t) * 2)];
    /* Data follows:
     * uint8_t out[sz]
     * uint8_t reg[AES_BLOCK_SIZE]
     * uint8_t tmp[AES_BLOCK_SIZE]
     */
} whMessageCrypto_AesCtrResponse;
WH_UTILS_STATIC_ASSERT(
    sizeof(whMessageCrypto_AesCtrRequest) ==
        sizeof(whMessageCrypto_AesCtrResponse),
    "AesCtrRequest and AesCtrResponse must be the same size");
int wh_MessageCrypto_TranslateAesCtrRequest(
    uint16_t magic, const whMessageCrypto_AesCtrRequest* src,
    whMessageCrypto_AesCtrRequest* dest);
int wh_MessageCrypto_TranslateAesCtrResponse(
    uint16_t magic, const whMessageCrypto_AesCtrResponse* src,
    whMessageCrypto_AesCtrResponse* dest);

/* AES ECB Request */
typedef struct {
    uint32_t enc;       /* 1 for encrypt, 0 for decrypt */
    uint32_t keyLen;    /* Length of key in bytes */
    uint32_t sz;        /* Size of input data */
    uint16_t keyId;     /* Key ID if using stored key */
    uint8_t  WH_PAD[2]; /* Padding for alignment */
    /* Data follows:
     * uint8_t in[sz]
     * uint8_t key[keyLen]
     * uint8_t iv[AES_IV_SIZE]
     */
} whMessageCrypto_AesEcbRequest;

/* AES ECB Response */
typedef struct {
    uint32_t sz; /* Size of output data */
    /* Pad to ensure overlap for input and output buffers */
    uint8_t WH_PAD[sizeof(whMessageCrypto_AesEcbRequest) - sizeof(uint32_t)];
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageCrypto_AesEcbResponse;

WH_UTILS_STATIC_ASSERT(
    sizeof(whMessageCrypto_AesEcbRequest) ==
        sizeof(whMessageCrypto_AesEcbResponse),
    "AesEcbRequest and AesEcbResponse must be the same size");

int wh_MessageCrypto_TranslateAesEcbRequest(
    uint16_t magic, const whMessageCrypto_AesEcbRequest* src,
    whMessageCrypto_AesEcbRequest* dest);

int wh_MessageCrypto_TranslateAesEcbResponse(
    uint16_t magic, const whMessageCrypto_AesEcbResponse* src,
    whMessageCrypto_AesEcbResponse* dest);


/* AES CBC Request */
typedef struct {
    uint32_t enc;       /* 1 for encrypt, 0 for decrypt */
    uint32_t keyLen;    /* Length of key in bytes */
    uint32_t sz;        /* Size of input data */
    uint16_t keyId;     /* Key ID if using stored key */
    uint8_t  WH_PAD[2]; /* Padding for alignment */
    /* Data follows:
     * uint8_t in[sz]
     * uint8_t key[keyLen]
     * uint8_t iv[AES_IV_SIZE]
     */
} whMessageCrypto_AesCbcRequest;

/* AES CBC Response */
typedef struct {
    uint32_t sz; /* Size of output data */
    /* Pad to ensure overlap for input and output buffers */
    uint8_t WH_PAD[sizeof(whMessageCrypto_AesCbcRequest) - sizeof(uint32_t)];
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageCrypto_AesCbcResponse;


WH_UTILS_STATIC_ASSERT(sizeof(whMessageCrypto_AesCbcRequest) ==
                   sizeof(whMessageCrypto_AesCbcResponse),
               "AesCbcRequest and AesCbcResponse must be the same size");

int wh_MessageCrypto_TranslateAesCbcRequest(
    uint16_t magic, const whMessageCrypto_AesCbcRequest* src,
    whMessageCrypto_AesCbcRequest* dest);

int wh_MessageCrypto_TranslateAesCbcResponse(
    uint16_t magic, const whMessageCrypto_AesCbcResponse* src,
    whMessageCrypto_AesCbcResponse* dest);

/* AES GCM Request */
typedef struct {
    uint32_t enc;       /* 1 for encrypt, 0 for decrypt */
    uint32_t keyLen;    /* Length of key in bytes */
    uint32_t sz;        /* Size of input data */
    uint32_t ivSz;      /* Size of IV */
    uint32_t authInSz;  /* Size of auth data */
    uint32_t authTagSz; /* Size of auth tag */
    uint16_t keyId;     /* Key ID if using stored key */
    uint8_t  WH_PAD[2]; /* Padding for alignment */
    /* Data follows:
     * uint8_t in[sz]
     * uint8_t key[keyLen]
     * uint8_t iv[ivSz]
     * uint8_t authIn[authInSz]
     * uint8_t authTag[authTagSz]
     */
} whMessageCrypto_AesGcmRequest;

/* AES GCM Response */
typedef struct {
    uint32_t sz;        /* Size of output data */
    uint32_t authTagSz; /* Size of auth tag */
    /* Pad to ensure overlap for input and output buffers */
    uint8_t
        WH_PAD[sizeof(whMessageCrypto_AesGcmRequest) - (sizeof(uint32_t) * 2)];
    /* Data follows:
     * uint8_t out[sz]
     * uint8_t authTag[authTagSz]
     */
} whMessageCrypto_AesGcmResponse;

WH_UTILS_STATIC_ASSERT(sizeof(whMessageCrypto_AesGcmRequest) ==
                   sizeof(whMessageCrypto_AesGcmResponse),
               "AesGcmRequest and AesGcmResponse must be the same size");

int wh_MessageCrypto_TranslateAesGcmRequest(
    uint16_t magic, const whMessageCrypto_AesGcmRequest* src,
    whMessageCrypto_AesGcmRequest* dest);

int wh_MessageCrypto_TranslateAesGcmResponse(
    uint16_t magic, const whMessageCrypto_AesGcmResponse* src,
    whMessageCrypto_AesGcmResponse* dest);

/*
 * RSA
 */

/* RSA Key Generation Request */
typedef struct {
    uint32_t flags;
    uint32_t keyId;
    uint32_t size;
    uint32_t e;
    uint8_t  label[WH_NVM_LABEL_LEN];
} whMessageCrypto_RsaKeyGenRequest;

/* RSA Key Generation Response */
typedef struct {
    uint32_t keyId;
    uint32_t len;
    /* Data follows:
     * uint8_t out[len];
     */
} whMessageCrypto_RsaKeyGenResponse;

int wh_MessageCrypto_TranslateRsaKeyGenRequest(
    uint16_t magic, const whMessageCrypto_RsaKeyGenRequest* src,
    whMessageCrypto_RsaKeyGenRequest* dest);

int wh_MessageCrypto_TranslateRsaKeyGenResponse(
    uint16_t magic, const whMessageCrypto_RsaKeyGenResponse* src,
    whMessageCrypto_RsaKeyGenResponse* dest);


/* RSA Operation Request */
typedef struct {
    uint32_t opType;
    uint32_t options;
#define WH_MESSAGE_CRYPTO_RSA_OPTIONS_EVICT (1 << 0)
    uint32_t keyId;
    uint32_t inLen;
    uint32_t outLen;
    /* Data follows:
     * uint8_t in[inLen];
     */
} whMessageCrypto_RsaRequest;

/* RSA Operation Response */
typedef struct {
    uint32_t outLen;
    /* Data follows:
     * uint8_t out[outLen];
     */
} whMessageCrypto_RsaResponse;

int wh_MessageCrypto_TranslateRsaRequest(uint16_t magic,
                                         const whMessageCrypto_RsaRequest* src,
                                         whMessageCrypto_RsaRequest* dest);

int wh_MessageCrypto_TranslateRsaResponse(
    uint16_t magic, const whMessageCrypto_RsaResponse* src,
    whMessageCrypto_RsaResponse* dest);

/* RSA Get Size Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_RSA_GET_SIZE_OPTIONS_EVICT (1 << 0)
    uint32_t keyId;
} whMessageCrypto_RsaGetSizeRequest;

/* RSA Get Size Response */
typedef struct {
    uint32_t keySize;
} whMessageCrypto_RsaGetSizeResponse;

int wh_MessageCrypto_TranslateRsaGetSizeRequest(
    uint16_t magic, const whMessageCrypto_RsaGetSizeRequest* src,
    whMessageCrypto_RsaGetSizeRequest* dest);

int wh_MessageCrypto_TranslateRsaGetSizeResponse(
    uint16_t magic, const whMessageCrypto_RsaGetSizeResponse* src,
    whMessageCrypto_RsaGetSizeResponse* dest);

/*
 * HKDF
 */

/* HKDF Request */
typedef struct {
    uint32_t flags;    /* NVM flags */
    uint32_t keyIdIn;  /* Key ID for input key material (from cache) */
    uint32_t keyIdOut; /* Key ID if caching output */
    uint32_t hashType; /* WC_SHA256, etc. */
    uint32_t inKeySz;  /* Input key material size */
    uint32_t saltSz;   /* Salt size (0 if none) */
    uint32_t infoSz;   /* Info size (0 if none) */
    uint32_t outSz;    /* Output size */
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Data follows:
     * uint8_t inKey[inKeySz]
     * uint8_t salt[saltSz]
     * uint8_t info[infoSz]
     */
} whMessageCrypto_HkdfRequest;

/* HKDF Response */
typedef struct {
    uint32_t keyIdOut; /* Assigned key ID */
    uint32_t outSz; /* Output size */
    /* Data follows:
     * uint8_t out[outSz]
     */
} whMessageCrypto_HkdfResponse;

int wh_MessageCrypto_TranslateHkdfRequest(
    uint16_t magic, const whMessageCrypto_HkdfRequest* src,
    whMessageCrypto_HkdfRequest* dest);

int wh_MessageCrypto_TranslateHkdfResponse(
    uint16_t magic, const whMessageCrypto_HkdfResponse* src,
    whMessageCrypto_HkdfResponse* dest);

/*
 * CMAC KDF
 */

typedef struct {
    uint32_t flags;       /* NVM flags */
    uint32_t keyIdSalt;   /* Key ID for salt material (from cache) */
    uint32_t keyIdZ;      /* Key ID for Z material (from cache) */
    uint32_t keyIdOut;    /* Key ID if caching output */
    uint32_t saltSz;      /* Salt size (0 if using keyIdSalt) */
    uint32_t zSz;         /* Z input size (0 if using keyIdZ) */
    uint32_t fixedInfoSz; /* Fixed info size (0 if none) */
    uint32_t outSz;       /* Output size */
    uint8_t  label[WH_NVM_LABEL_LEN];
    /* Data follows:
     * uint8_t salt[saltSz]
     * uint8_t z[zSz]
     * uint8_t fixedInfo[fixedInfoSz]
     */
} whMessageCrypto_CmacKdfRequest;

typedef struct {
    uint32_t keyIdOut; /* Assigned key ID */
    uint32_t outSz;    /* Output size */
    /* Data follows:
     * uint8_t out[outSz]
     */
} whMessageCrypto_CmacKdfResponse;

int wh_MessageCrypto_TranslateCmacKdfRequest(
    uint16_t magic, const whMessageCrypto_CmacKdfRequest* src,
    whMessageCrypto_CmacKdfRequest* dest);

int wh_MessageCrypto_TranslateCmacKdfResponse(
    uint16_t magic, const whMessageCrypto_CmacKdfResponse* src,
    whMessageCrypto_CmacKdfResponse* dest);

/*
 * ECC
 */

/* ECC Key Generation Request */
typedef struct {
    uint32_t sz;
    uint32_t curveId;
    uint32_t keyId;
    uint32_t flags;
    uint32_t access;
    uint8_t  label[WH_NVM_LABEL_LEN];
} whMessageCrypto_EccKeyGenRequest;

/* ECC Key Generation Response */
typedef struct {
    uint32_t keyId;
    uint32_t len;
    /* Data follows:
     * uint8_t out[len];
     */
} whMessageCrypto_EccKeyGenResponse;

int wh_MessageCrypto_TranslateEccKeyGenRequest(
    uint16_t magic, const whMessageCrypto_EccKeyGenRequest* src,
    whMessageCrypto_EccKeyGenRequest* dest);

int wh_MessageCrypto_TranslateEccKeyGenResponse(
    uint16_t magic, const whMessageCrypto_EccKeyGenResponse* src,
    whMessageCrypto_EccKeyGenResponse* dest);

/* ECDH Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPUB (1 << 0)
#define WH_MESSAGE_CRYPTO_ECDH_OPTIONS_EVICTPRV (1 << 1)
    uint32_t privateKeyId;
    uint32_t publicKeyId;
} whMessageCrypto_EcdhRequest;

/* ECDH Response */
typedef struct {
    uint32_t sz;
    /* Data follows:
     * uint8_t out[sz];
     */
} whMessageCrypto_EcdhResponse;

int wh_MessageCrypto_TranslateEcdhRequest(
    uint16_t magic, const whMessageCrypto_EcdhRequest* src,
    whMessageCrypto_EcdhRequest* dest);

int wh_MessageCrypto_TranslateEcdhResponse(
    uint16_t magic, const whMessageCrypto_EcdhResponse* src,
    whMessageCrypto_EcdhResponse* dest);

/* ECC Sign Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_ECCSIGN_OPTIONS_EVICT (1 << 0)
    uint32_t keyId;
    uint32_t sz;
    /* Data follows:
     * uint8_t in[sz];
     */
} whMessageCrypto_EccSignRequest;

/* ECC Sign Response */
typedef struct {
    uint32_t sz;
    /* Data follows:
     * uint8_t out[sz];
     */
} whMessageCrypto_EccSignResponse;

int wh_MessageCrypto_TranslateEccSignRequest(
    uint16_t magic, const whMessageCrypto_EccSignRequest* src,
    whMessageCrypto_EccSignRequest* dest);

int wh_MessageCrypto_TranslateEccSignResponse(
    uint16_t magic, const whMessageCrypto_EccSignResponse* src,
    whMessageCrypto_EccSignResponse* dest);

/* ECC Verify Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_ECCVERIFY_OPTIONS_EVICT (1 << 0)
#define WH_MESSAGE_CRYPTO_ECCVERIFY_OPTIONS_EXPORTPUB (1 << 1)
    uint32_t keyId;
    uint32_t sigSz;
    uint32_t hashSz;
    /* Data follows:
     * uint8_t sig[sigSz];
     * uint8_t hash[hashSz];
     */
} whMessageCrypto_EccVerifyRequest;

/* ECC Verify Response */
typedef struct {
    uint32_t res;
    uint32_t pubSz;
    /* Data follows:
     * uint8_t pub[pubSz];
     */
} whMessageCrypto_EccVerifyResponse;

int wh_MessageCrypto_TranslateEccVerifyRequest(
    uint16_t magic, const whMessageCrypto_EccVerifyRequest* src,
    whMessageCrypto_EccVerifyRequest* dest);

int wh_MessageCrypto_TranslateEccVerifyResponse(
    uint16_t magic, const whMessageCrypto_EccVerifyResponse* src,
    whMessageCrypto_EccVerifyResponse* dest);

/* ECC Check Request */
typedef struct {
    uint32_t keyId;
    uint32_t curveId;
} whMessageCrypto_EccCheckRequest;

/* ECC Check Response */
typedef struct {
    uint32_t ok;
} whMessageCrypto_EccCheckResponse;

int wh_MessageCrypto_TranslateEccCheckRequest(
    uint16_t magic, const whMessageCrypto_EccCheckRequest* src,
    whMessageCrypto_EccCheckRequest* dest);

int wh_MessageCrypto_TranslateEccCheckResponse(
    uint16_t magic, const whMessageCrypto_EccCheckResponse* src,
    whMessageCrypto_EccCheckResponse* dest);


/*
 * Curve25519
 */

/* Curve25519 Key Generation Request */
typedef struct {
    uint32_t sz;
    uint32_t flags;
    uint32_t keyId;
    uint8_t  label[WH_NVM_LABEL_LEN];
} whMessageCrypto_Curve25519KeyGenRequest;

/* Curve25519 Key Generation Response */
typedef struct {
    uint32_t keyId;
    uint32_t len;
    /* Data follows:
     * uint8_t out[len];
     */
} whMessageCrypto_Curve25519KeyGenResponse;

int wh_MessageCrypto_TranslateCurve25519KeyGenRequest(
    uint16_t magic, const whMessageCrypto_Curve25519KeyGenRequest* src,
    whMessageCrypto_Curve25519KeyGenRequest* dest);

int wh_MessageCrypto_TranslateCurve25519KeyGenResponse(
    uint16_t magic, const whMessageCrypto_Curve25519KeyGenResponse* src,
    whMessageCrypto_Curve25519KeyGenResponse* dest);

/* Curve25519 Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPUB (1 << 0)
#define WH_MESSAGE_CRYPTO_CURVE25519_OPTIONS_EVICTPRV (1 << 1)
    uint32_t privateKeyId;
    uint32_t publicKeyId;
    uint32_t endian;
} whMessageCrypto_Curve25519Request;

/* Curve25519 Response */
typedef struct {
    uint32_t sz;
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t out[sz];
     */
} whMessageCrypto_Curve25519Response;

int wh_MessageCrypto_TranslateCurve25519Request(
    uint16_t magic, const whMessageCrypto_Curve25519Request* src,
    whMessageCrypto_Curve25519Request* dest);

int wh_MessageCrypto_TranslateCurve25519Response(
    uint16_t magic, const whMessageCrypto_Curve25519Response* src,
    whMessageCrypto_Curve25519Response* dest);

/*
 * Ed25519
 */

/* Ed25519 Key Generation Request */
typedef struct {
    uint32_t flags;
    uint32_t keyId;
    uint32_t access;
    uint8_t  label[WH_NVM_LABEL_LEN];
} whMessageCrypto_Ed25519KeyGenRequest;

/* Ed25519 Key Generation Response */
typedef struct {
    uint32_t keyId;
    uint32_t outSz;
    /* Data follows:
     * uint8_t out[outSz];
     */
} whMessageCrypto_Ed25519KeyGenResponse;

int wh_MessageCrypto_TranslateEd25519KeyGenRequest(
    uint16_t magic, const whMessageCrypto_Ed25519KeyGenRequest* src,
    whMessageCrypto_Ed25519KeyGenRequest* dest);

int wh_MessageCrypto_TranslateEd25519KeyGenResponse(
    uint16_t magic, const whMessageCrypto_Ed25519KeyGenResponse* src,
    whMessageCrypto_Ed25519KeyGenResponse* dest);

/* Ed25519 Sign Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_ED25519_SIGN_OPTIONS_EVICT (1 << 0)
    uint32_t keyId;
    uint32_t msgSz;
    uint32_t type;  /* wolfCrypt Ed25519 mode */
    uint32_t ctxSz; /* Optional context length */
    /* Data follows:
     * uint8_t msg[msgSz];
     * uint8_t ctx[ctxSz];
     */
} whMessageCrypto_Ed25519SignRequest;

/* Ed25519 Sign Response */
typedef struct {
    uint32_t sigSz;
    /* Data follows:
     * uint8_t sig[sigSz];
     */
} whMessageCrypto_Ed25519SignResponse;

int wh_MessageCrypto_TranslateEd25519SignRequest(
    uint16_t magic, const whMessageCrypto_Ed25519SignRequest* src,
    whMessageCrypto_Ed25519SignRequest* dest);

int wh_MessageCrypto_TranslateEd25519SignResponse(
    uint16_t magic, const whMessageCrypto_Ed25519SignResponse* src,
    whMessageCrypto_Ed25519SignResponse* dest);

/* Ed25519 Verify Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_ED25519_VERIFY_OPTIONS_EVICT (1 << 0)
    uint32_t keyId;
    uint32_t sigSz;
    uint32_t msgSz;
    uint32_t type;  /* wolfCrypt Ed25519 mode */
    uint32_t ctxSz; /* Optional context length */
    /* Data follows:
     * uint8_t sig[sigSz];
     * uint8_t msg[msgSz];
     * uint8_t ctx[ctxSz];
     */
} whMessageCrypto_Ed25519VerifyRequest;

/* Ed25519 Verify Response */
typedef struct {
    int32_t res;
} whMessageCrypto_Ed25519VerifyResponse;

int wh_MessageCrypto_TranslateEd25519VerifyRequest(
    uint16_t magic, const whMessageCrypto_Ed25519VerifyRequest* src,
    whMessageCrypto_Ed25519VerifyRequest* dest);

int wh_MessageCrypto_TranslateEd25519VerifyResponse(
    uint16_t magic, const whMessageCrypto_Ed25519VerifyResponse* src,
    whMessageCrypto_Ed25519VerifyResponse* dest);

/*
 * SHA
 */

/* SHA256 and SHA224 Request */
typedef struct {
    struct {
        uint32_t hiLen;
        uint32_t loLen;
        /* intermediate hash value */
        uint8_t hash[32]; /* TODO (BRN) WC_SHA256_DIGEST_SIZE */
    } resumeState;
    /* Flag indicating to the server that this is the last block and it should
     * finalize the hash. If set, inBlock may be only partially full*/
    uint32_t isLastBlock;
    /* Length of the last input block of data. Only valid if isLastBlock=1 */
    uint32_t lastBlockLen;
    /* Full sha256 input block to hash */
    uint8_t inBlock[64]; /* TODO (BRN) WC_SHA256_BLOCK_SIZE */
    uint8_t WH_PAD[4];
} whMessageCrypto_Sha256Request;

int wh_MessageCrypto_TranslateSha256Request(
    uint16_t magic, const whMessageCrypto_Sha256Request* src,
    whMessageCrypto_Sha256Request* dest);


/* SHA512 and SHA384 Request */
typedef struct {
    struct {
        uint32_t hiLen;
        uint32_t loLen;
        /* intermediate hash value */
        uint8_t hash[64]; /* TODO (HM) WC_SHA512_DIGEST_SIZE */
        uint32_t hashType;
    } resumeState;
    /* Flag indicating to the server that this is the last block and it should
     * finalize the hash. If set, inBlock may be only partially full*/
    uint32_t isLastBlock;
    /* Length of the last input block of data. Only valid if isLastBlock=1 */
    uint32_t lastBlockLen;
    /* Full sha512 input block to hash */
    uint8_t inBlock[128]; /* TODO (HM) WC_SHA512_BLOCK_SIZE 128*/
    uint8_t WH_PAD[4];
} whMessageCrypto_Sha512Request;

/* SHA2 Response */
typedef struct {
    /* Resulting hash value */
    uint32_t hiLen;
    uint32_t loLen;
    uint8_t  hash[64]; /* TODO WC_SHA512_DIGEST_SIZE */
    uint32_t hashType;
} whMessageCrypto_Sha2Response;

int wh_MessageCrypto_TranslateSha512Request(
    uint16_t magic, const whMessageCrypto_Sha512Request* src,
    whMessageCrypto_Sha512Request* dest);

int wh_MessageCrypto_TranslateSha2Response(
    uint16_t magic, const whMessageCrypto_Sha2Response* src,
    whMessageCrypto_Sha2Response* dest);

/*
 * CMAC
 */

/* CMAC intermediate state - non-sensitive fields only.
 * k1/k2 subkeys are NOT included as they are key-derived material.
 * Server re-derives them via wc_InitCmac_ex on each request. */
typedef struct {
    uint8_t  buffer[16]; /* AES_BLOCK_SIZE: partial block buffer */
    uint8_t  digest[16]; /* AES_BLOCK_SIZE: running CBC-MAC digest */
    uint32_t bufferSz;   /* bytes in partial block buffer */
    uint32_t totalSz;    /* total bytes processed */
} whMessageCrypto_CmacState;

/* CMAC Request */
typedef struct {
    uint32_t type;  /* wolfCrypt CmacType enum */
    uint32_t outSz; /* output MAC size (0 if not finalizing) */
    uint32_t inSz;  /* input data size */
    uint32_t keySz; /* key size (0 if using keyId or already initialized) */
    uint16_t keyId; /* key ID for HSM-stored key */
    uint8_t  WH_PAD[2];
    whMessageCrypto_CmacState resumeState;
    /* Data follows:
     * uint8_t in[inSz]
     * uint8_t key[keySz]
     */
} whMessageCrypto_CmacRequest;

/* CMAC Response */
typedef struct {
    uint32_t outSz; /* actual output MAC size */
    uint16_t keyId; /* key ID (ERASED for non-HSM) */
    uint8_t  WH_PAD[2];
    whMessageCrypto_CmacState resumeState;
    uint8_t  WH_PAD2[12]; /* pad to match request size */
    /* Data follows:
     * uint8_t out[outSz]
     */
} whMessageCrypto_CmacResponse;

WH_UTILS_STATIC_ASSERT(sizeof(whMessageCrypto_CmacRequest) ==
                            sizeof(whMessageCrypto_CmacResponse),
                        "CmacRequest and CmacResponse must be the same size");

int wh_MessageCrypto_TranslateCmacState(
    uint16_t magic, const whMessageCrypto_CmacState* src,
    whMessageCrypto_CmacState* dest);

int wh_MessageCrypto_TranslateCmacRequest(
    uint16_t magic, const whMessageCrypto_CmacRequest* src,
    whMessageCrypto_CmacRequest* dest);

int wh_MessageCrypto_TranslateCmacResponse(
    uint16_t magic, const whMessageCrypto_CmacResponse* src,
    whMessageCrypto_CmacResponse* dest);


/*
 * ML-DSA
 */

/* ML-DSA Key Generation Request */
typedef struct {
    uint32_t sz;
    uint32_t level;
    uint32_t keyId;
    uint32_t flags;
    uint32_t access;
    uint8_t  label[WH_NVM_LABEL_LEN];
} whMessageCrypto_MlDsaKeyGenRequest;

/* ML-DSA Key Generation Response */
typedef struct {
    uint32_t keyId;
    uint32_t len;
    /* Data follows:
     * uint8_t out[len];
     */
} whMessageCrypto_MlDsaKeyGenResponse;

int wh_MessageCrypto_TranslateMlDsaKeyGenRequest(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenRequest* src,
    whMessageCrypto_MlDsaKeyGenRequest* dest);

int wh_MessageCrypto_TranslateMlDsaKeyGenResponse(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenResponse* src,
    whMessageCrypto_MlDsaKeyGenResponse* dest);

/* ML-DSA Sign Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_MLDSA_SIGN_OPTIONS_EVICT (1 << 0)
    uint32_t level;
    uint32_t keyId;
    uint32_t sz;
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t in[sz];
     */
} whMessageCrypto_MlDsaSignRequest;

/* ML-DSA Sign Response */
typedef struct {
    uint32_t sz;
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t out[sz];
     */
} whMessageCrypto_MlDsaSignResponse;

int wh_MessageCrypto_TranslateMlDsaSignRequest(
    uint16_t magic, const whMessageCrypto_MlDsaSignRequest* src,
    whMessageCrypto_MlDsaSignRequest* dest);

int wh_MessageCrypto_TranslateMlDsaSignResponse(
    uint16_t magic, const whMessageCrypto_MlDsaSignResponse* src,
    whMessageCrypto_MlDsaSignResponse* dest);

/* ML-DSA Verify Request */
typedef struct {
    uint32_t options;
#define WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EVICT (1 << 0)
#define WH_MESSAGE_CRYPTO_MLDSA_VERIFY_OPTIONS_EXPORTPUB (1 << 1)
    uint32_t level;
    uint32_t keyId;
    uint32_t sigSz;
    uint32_t hashSz;
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t sig[sigSz];
     * uint8_t hash[hashSz];
     */
} whMessageCrypto_MlDsaVerifyRequest;

/* ML-DSA Verify Response */
typedef struct {
    uint32_t res;
    uint8_t  WH_PAD[4];
} whMessageCrypto_MlDsaVerifyResponse;

int wh_MessageCrypto_TranslateMlDsaVerifyRequest(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyRequest* src,
    whMessageCrypto_MlDsaVerifyRequest* dest);

int wh_MessageCrypto_TranslateMlDsaVerifyResponse(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyResponse* src,
    whMessageCrypto_MlDsaVerifyResponse* dest);


/*
 * DMA-based crypto messages
 */

/* DMA buffer structure */
typedef struct {
    uint64_t addr;
    uint64_t sz;
} whMessageCrypto_DmaBuffer;

/* DMA address status structure */
typedef struct {
    /* If packet->rc == WH_ERROR_ACCESS, this field will contain the offending
     * address/size pair. Invalid otherwise. */
    whMessageCrypto_DmaBuffer badAddr;
} whMessageCrypto_DmaAddrStatus;


/* SHA2 DMA Request */
typedef struct {
    /* Since client addresses are subject to DMA checking, we can't use them to
     * determine the requested operation (update/final). Therefore we need to
     * indicate to the server which SHA224 operation to perform */
    uint64_t                  finalize;
    whMessageCrypto_DmaBuffer input;
    whMessageCrypto_DmaBuffer state;
    whMessageCrypto_DmaBuffer output;
} whMessageCrypto_Sha2DmaRequest;

/* SHA224 DMA Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
} whMessageCrypto_Sha2DmaResponse;

/* SHA2 DMA translation functions */
int wh_MessageCrypto_TranslateSha2DmaRequest(
    uint16_t magic, const whMessageCrypto_Sha2DmaRequest* src,
    whMessageCrypto_Sha2DmaRequest* dest);

int wh_MessageCrypto_TranslateSha2DmaResponse(
    uint16_t magic, const whMessageCrypto_Sha2DmaResponse* src,
    whMessageCrypto_Sha2DmaResponse* dest);
/* CMAC DMA Request */
typedef struct {
    uint32_t                  type;     /* enum wc_CmacType */
    uint32_t                  finalize; /* 1 if final, 0 if update */
    whMessageCrypto_DmaBuffer state;    /* CMAC state buffer */
    whMessageCrypto_DmaBuffer key;      /* Key buffer */
    whMessageCrypto_DmaBuffer input;    /* Input buffer */
    whMessageCrypto_DmaBuffer output;   /* Output buffer */
} whMessageCrypto_CmacDmaRequest;

/* CMAC DMA Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    uint32_t                      outSz;
    uint8_t                       WH_PAD[4]; /* Pad to 8-byte alignment */
} whMessageCrypto_CmacDmaResponse;

/* CMAC DMA translation functions */
int wh_MessageCrypto_TranslateCmacDmaRequest(
    uint16_t magic, const whMessageCrypto_CmacDmaRequest* src,
    whMessageCrypto_CmacDmaRequest* dest);

int wh_MessageCrypto_TranslateCmacDmaResponse(
    uint16_t magic, const whMessageCrypto_CmacDmaResponse* src,
    whMessageCrypto_CmacDmaResponse* dest);

/* AES DMA Request [CTR / CBC / GCM / ECB]*/
typedef struct {
    uint32_t                  enc;      /* 1 for encrypt, 0 for decrypt */
    uint32_t                  type;     /* enum wc_AesType */
    uint32_t                  finalize; /* 1 if final, 0 if update */
    uint32_t                  keyId;
    whMessageCrypto_DmaBuffer state;   /* AES state buffer (for CBC / CTR) */
    whMessageCrypto_DmaBuffer key;     /* Key buffer */
    whMessageCrypto_DmaBuffer input;   /* Input buffer */
    whMessageCrypto_DmaBuffer output;  /* Output buffer */
    whMessageCrypto_DmaBuffer authTag; /* Auth tag buffer */
    whMessageCrypto_DmaBuffer iv;      /* IV buffer */
    whMessageCrypto_DmaBuffer aad;     /* AAD buffer */
} whMessageCrypto_AesDmaRequest;

/* AES DMA Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    uint32_t                      outSz;
    uint8_t                       WH_PAD[4]; /* Pad to 8-byte alignment */
} whMessageCrypto_AesDmaResponse;

/* AES DMA translation functions */
int wh_MessageCrypto_TranslateAesDmaRequest(
    uint16_t magic, const whMessageCrypto_AesDmaRequest* src,
    whMessageCrypto_AesDmaRequest* dest);

int wh_MessageCrypto_TranslateAesDmaResponse(
    uint16_t magic, const whMessageCrypto_AesDmaResponse* src,
    whMessageCrypto_AesDmaResponse* dest);

/* ML-DSA DMA Key Generation Request */
typedef struct {
    whMessageCrypto_DmaBuffer key;
    uint32_t                  level;
    uint32_t                  flags;
    uint32_t                  keyId;
    uint32_t                  access; /* Key access permissions */
    uint32_t                  labelSize;
    uint8_t                   label[WH_NVM_LABEL_LEN];
    uint8_t WH_PAD2[4]; /* Final padding for 8-byte alignment */
} whMessageCrypto_MlDsaKeyGenDmaRequest;

/* ML-DSA DMA Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    uint32_t                      keyId;   /* Assigned key ID */
    uint32_t                      keySize; /* Actual size of generated key */
} whMessageCrypto_MlDsaKeyGenDmaResponse;

/* ML-DSA DMA Sign Request */
typedef struct {
    whMessageCrypto_DmaBuffer msg;       /* Message buffer */
    whMessageCrypto_DmaBuffer sig;       /* Signature buffer */
    uint32_t                  options;   /* Same options as non-DMA version */
    uint32_t                  level;     /* ML-DSA security level */
    uint32_t                  keyId;     /* Key ID to use for signing */
    uint8_t                   WH_PAD[4]; /* Pad to 8-byte alignment */
} whMessageCrypto_MlDsaSignDmaRequest;

/* ML-DSA DMA Sign Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    uint32_t                      sigLen;    /* Actual signature length */
    uint8_t                       WH_PAD[4]; /* Pad to 8-byte alignment */
} whMessageCrypto_MlDsaSignDmaResponse;

/* ML-DSA DMA Verify Request */
typedef struct {
    whMessageCrypto_DmaBuffer sig;       /* Signature buffer */
    whMessageCrypto_DmaBuffer msg;       /* Message buffer */
    uint32_t                  options;   /* Same options as non-DMA version */
    uint32_t                  level;     /* ML-DSA security level */
    uint32_t                  keyId;     /* Key ID to use for verification */
    uint8_t                   WH_PAD[4]; /* Pad to 8-byte alignment */
} whMessageCrypto_MlDsaVerifyDmaRequest;

/* ML-DSA DMA Verify Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    int32_t                       verifyResult; /* Result of verification */
    uint8_t                       WH_PAD[4];    /* Pad to 8-byte alignment */
} whMessageCrypto_MlDsaVerifyDmaResponse;

/* ML-DSA DMA translation functions */
int wh_MessageCrypto_TranslateMlDsaKeyGenDmaRequest(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenDmaRequest* src,
    whMessageCrypto_MlDsaKeyGenDmaRequest* dest);

int wh_MessageCrypto_TranslateMlDsaKeyGenDmaResponse(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenDmaResponse* src,
    whMessageCrypto_MlDsaKeyGenDmaResponse* dest);

int wh_MessageCrypto_TranslateMlDsaSignDmaRequest(
    uint16_t magic, const whMessageCrypto_MlDsaSignDmaRequest* src,
    whMessageCrypto_MlDsaSignDmaRequest* dest);

int wh_MessageCrypto_TranslateMlDsaSignDmaResponse(
    uint16_t magic, const whMessageCrypto_MlDsaSignDmaResponse* src,
    whMessageCrypto_MlDsaSignDmaResponse* dest);

int wh_MessageCrypto_TranslateMlDsaVerifyDmaRequest(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyDmaRequest* src,
    whMessageCrypto_MlDsaVerifyDmaRequest* dest);

int wh_MessageCrypto_TranslateMlDsaVerifyDmaResponse(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyDmaResponse* src,
    whMessageCrypto_MlDsaVerifyDmaResponse* dest);

/* Ed25519 DMA Sign Request */
typedef struct {
    whMessageCrypto_DmaBuffer msg; /* Message buffer */
    whMessageCrypto_DmaBuffer sig; /* Signature buffer */
    whMessageCrypto_DmaBuffer pub; /* Signature buffer */
    uint32_t                  options;
    uint32_t                  keyId;
    uint32_t                  type;      /* wolfCrypt Ed25519 mode */
    uint32_t                  ctxSz;     /* Optional context length */
    /* Data follows:
     * uint8_t ctx[ctxSz];
     */
} whMessageCrypto_Ed25519SignDmaRequest;

/* Ed25519 DMA Sign Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    uint32_t                      sigSz;
    uint32_t                      pubSz;
} whMessageCrypto_Ed25519SignDmaResponse;

/* Ed25519 DMA Verify Request */
typedef struct {
    whMessageCrypto_DmaBuffer sig; /* Signature buffer */
    whMessageCrypto_DmaBuffer msg; /* Message buffer */
    whMessageCrypto_DmaBuffer pub; /* Public key buffer if exported */
    uint32_t                  options;
    uint32_t                  keyId;
    uint32_t                  type;      /* wolfCrypt Ed25519 mode */
    uint32_t                  ctxSz;     /* Optional context length */
    /* Data follows:
     * uint8_t ctx[ctxSz];
     */
} whMessageCrypto_Ed25519VerifyDmaRequest;

/* Ed25519 DMA Verify Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
    int32_t                       verifyResult;
    uint32_t                      pubSz;
} whMessageCrypto_Ed25519VerifyDmaResponse;

int wh_MessageCrypto_TranslateEd25519SignDmaRequest(
    uint16_t magic, const whMessageCrypto_Ed25519SignDmaRequest* src,
    whMessageCrypto_Ed25519SignDmaRequest* dest);

int wh_MessageCrypto_TranslateEd25519SignDmaResponse(
    uint16_t magic, const whMessageCrypto_Ed25519SignDmaResponse* src,
    whMessageCrypto_Ed25519SignDmaResponse* dest);

int wh_MessageCrypto_TranslateEd25519VerifyDmaRequest(
    uint16_t magic, const whMessageCrypto_Ed25519VerifyDmaRequest* src,
    whMessageCrypto_Ed25519VerifyDmaRequest* dest);

int wh_MessageCrypto_TranslateEd25519VerifyDmaResponse(
    uint16_t magic, const whMessageCrypto_Ed25519VerifyDmaResponse* src,
    whMessageCrypto_Ed25519VerifyDmaResponse* dest);

/* RNG DMA Request */
typedef struct {
    whMessageCrypto_DmaBuffer output; /* Output buffer for random bytes */
} whMessageCrypto_RngDmaRequest;

/* RNG DMA Response */
typedef struct {
    whMessageCrypto_DmaAddrStatus dmaAddrStatus;
} whMessageCrypto_RngDmaResponse;

/* RNG DMA translation functions */
int wh_MessageCrypto_TranslateRngDmaRequest(
    uint16_t magic, const whMessageCrypto_RngDmaRequest* src,
    whMessageCrypto_RngDmaRequest* dest);

int wh_MessageCrypto_TranslateRngDmaResponse(
    uint16_t magic, const whMessageCrypto_RngDmaResponse* src,
    whMessageCrypto_RngDmaResponse* dest);

#endif /* !WOLFHSM_WH_MESSAGE_CRYPTO_H_ */
