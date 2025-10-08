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
 * wolfhsm/wh_message_crypto.c
 *
 * Message translation functions for crypto operations.
 */

#include "wolfhsm/wh_message_crypto.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include <string.h>

/* Generic crypto header request translation */
int wh_MessageCrypto_TranslateGenericRequestHeader(
    uint16_t magic, const whMessageCrypto_GenericRequestHeader* src,
    whMessageCrypto_GenericRequestHeader* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, algoType);
    WH_T32(magic, dest, src, algoSubType);
    return 0;
}

/* Generic crypto header response translation */
int wh_MessageCrypto_TranslateGenericResponseHeader(
    uint16_t magic, const whMessageCrypto_GenericResponseHeader* src,
    whMessageCrypto_GenericResponseHeader* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, algoType);
    WH_T32(magic, dest, src, rc);
    return 0;
}

/* RNG Request translation */
int wh_MessageCrypto_TranslateRngRequest(uint16_t magic,
                                         const whMessageCrypto_RngRequest* src,
                                         whMessageCrypto_RngRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* RNG Response translation */
int wh_MessageCrypto_TranslateRngResponse(
    uint16_t magic, const whMessageCrypto_RngResponse* src,
    whMessageCrypto_RngResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* AES CTR Request translation */
int wh_MessageCrypto_TranslateAesCtrRequest(
    uint16_t magic, const whMessageCrypto_AesCtrRequest* src,
    whMessageCrypto_AesCtrRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, enc);
    WH_T32(magic, dest, src, keyLen);
    WH_T32(magic, dest, src, sz);
    WH_T16(magic, dest, src, keyId);
    WH_T32(magic, dest, src, left);
    return 0;
}
/* AES CTR Response translation */
int wh_MessageCrypto_TranslateAesCtrResponse(
    uint16_t magic, const whMessageCrypto_AesCtrResponse* src,
    whMessageCrypto_AesCtrResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, left);
    return 0;
}
/* AES Ecb Request translation */
int wh_MessageCrypto_TranslateAesEcbRequest(
    uint16_t magic, const whMessageCrypto_AesEcbRequest* src,
    whMessageCrypto_AesEcbRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, enc);
    WH_T32(magic, dest, src, keyLen);
    WH_T32(magic, dest, src, sz);
    WH_T16(magic, dest, src, keyId);
    return 0;
}

/* AES ECB Response translation */
int wh_MessageCrypto_TranslateAesEcbResponse(
    uint16_t magic, const whMessageCrypto_AesEcbResponse* src,
    whMessageCrypto_AesEcbResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* AES CBC Request translation */
int wh_MessageCrypto_TranslateAesCbcRequest(
    uint16_t magic, const whMessageCrypto_AesCbcRequest* src,
    whMessageCrypto_AesCbcRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, enc);
    WH_T32(magic, dest, src, keyLen);
    WH_T32(magic, dest, src, sz);
    WH_T16(magic, dest, src, keyId);
    return 0;
}

/* AES CBC Response translation */
int wh_MessageCrypto_TranslateAesCbcResponse(
    uint16_t magic, const whMessageCrypto_AesCbcResponse* src,
    whMessageCrypto_AesCbcResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* AES GCM Request translation */
int wh_MessageCrypto_TranslateAesGcmRequest(
    uint16_t magic, const whMessageCrypto_AesGcmRequest* src,
    whMessageCrypto_AesGcmRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, enc);
    WH_T32(magic, dest, src, keyLen);
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, ivSz);
    WH_T32(magic, dest, src, authInSz);
    WH_T32(magic, dest, src, authTagSz);
    WH_T16(magic, dest, src, keyId);
    return 0;
}

/* AES GCM Response translation */
int wh_MessageCrypto_TranslateAesGcmResponse(
    uint16_t magic, const whMessageCrypto_AesGcmResponse* src,
    whMessageCrypto_AesGcmResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, authTagSz);
    return 0;
}
/* RSA Key Generation Request translation */
int wh_MessageCrypto_TranslateRsaKeyGenRequest(
    uint16_t magic, const whMessageCrypto_RsaKeyGenRequest* src,
    whMessageCrypto_RsaKeyGenRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, flags);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, size);
    WH_T32(magic, dest, src, e);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* RSA Key Generation Response translation */
int wh_MessageCrypto_TranslateRsaKeyGenResponse(
    uint16_t magic, const whMessageCrypto_RsaKeyGenResponse* src,
    whMessageCrypto_RsaKeyGenResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, len);
    return 0;
}

/* RSA Request translation */
int wh_MessageCrypto_TranslateRsaRequest(uint16_t magic,
                                         const whMessageCrypto_RsaRequest* src,
                                         whMessageCrypto_RsaRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, opType);
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, inLen);
    WH_T32(magic, dest, src, outLen);
    return 0;
}

/* RSA Response translation */
int wh_MessageCrypto_TranslateRsaResponse(
    uint16_t magic, const whMessageCrypto_RsaResponse* src,
    whMessageCrypto_RsaResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, outLen);
    return 0;
}

/* RSA Get Size Request translation */
int wh_MessageCrypto_TranslateRsaGetSizeRequest(
    uint16_t magic, const whMessageCrypto_RsaGetSizeRequest* src,
    whMessageCrypto_RsaGetSizeRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, keyId);
    return 0;
}

/* RSA Get Size Response translation */
int wh_MessageCrypto_TranslateRsaGetSizeResponse(
    uint16_t magic, const whMessageCrypto_RsaGetSizeResponse* src,
    whMessageCrypto_RsaGetSizeResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keySize);
    return 0;
}

/* HKDF Request translation */
int wh_MessageCrypto_TranslateHkdfRequest(
    uint16_t magic, const whMessageCrypto_HkdfRequest* src,
    whMessageCrypto_HkdfRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, flags);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, hashType);
    WH_T32(magic, dest, src, inKeySz);
    WH_T32(magic, dest, src, saltSz);
    WH_T32(magic, dest, src, infoSz);
    WH_T32(magic, dest, src, outSz);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, WH_NVM_LABEL_LEN);
    }
    return 0;
}

/* HKDF Response translation */
int wh_MessageCrypto_TranslateHkdfResponse(
    uint16_t magic, const whMessageCrypto_HkdfResponse* src,
    whMessageCrypto_HkdfResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, outSz);
    return 0;
}

/* ECC Key Generation Request translation */
int wh_MessageCrypto_TranslateEccKeyGenRequest(
    uint16_t magic, const whMessageCrypto_EccKeyGenRequest* src,
    whMessageCrypto_EccKeyGenRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, curveId);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, flags);
    WH_T32(magic, dest, src, access);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, sizeof(src->label));
    }
    return 0;
}

/* ECC Key Generation Response translation */
int wh_MessageCrypto_TranslateEccKeyGenResponse(
    uint16_t magic, const whMessageCrypto_EccKeyGenResponse* src,
    whMessageCrypto_EccKeyGenResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, len);
    return 0;
}

/* ECDH Request translation */
int wh_MessageCrypto_TranslateEcdhRequest(
    uint16_t magic, const whMessageCrypto_EcdhRequest* src,
    whMessageCrypto_EcdhRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, privateKeyId);
    WH_T32(magic, dest, src, publicKeyId);
    return 0;
}

/* ECDH Response translation */
int wh_MessageCrypto_TranslateEcdhResponse(
    uint16_t magic, const whMessageCrypto_EcdhResponse* src,
    whMessageCrypto_EcdhResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* ECC Sign Request translation */
int wh_MessageCrypto_TranslateEccSignRequest(
    uint16_t magic, const whMessageCrypto_EccSignRequest* src,
    whMessageCrypto_EccSignRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* ECC Sign Response translation */
int wh_MessageCrypto_TranslateEccSignResponse(
    uint16_t magic, const whMessageCrypto_EccSignResponse* src,
    whMessageCrypto_EccSignResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* ECC Verify Request translation */
int wh_MessageCrypto_TranslateEccVerifyRequest(
    uint16_t magic, const whMessageCrypto_EccVerifyRequest* src,
    whMessageCrypto_EccVerifyRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, sigSz);
    WH_T32(magic, dest, src, hashSz);
    return 0;
}

/* ECC Verify Response translation */
int wh_MessageCrypto_TranslateEccVerifyResponse(
    uint16_t magic, const whMessageCrypto_EccVerifyResponse* src,
    whMessageCrypto_EccVerifyResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, res);
    WH_T32(magic, dest, src, pubSz);
    return 0;
}

/* ECC Check Request translation */
int wh_MessageCrypto_TranslateEccCheckRequest(
    uint16_t magic, const whMessageCrypto_EccCheckRequest* src,
    whMessageCrypto_EccCheckRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, curveId);
    return 0;
}

/* ECC Check Response translation */
int wh_MessageCrypto_TranslateEccCheckResponse(
    uint16_t magic, const whMessageCrypto_EccCheckResponse* src,
    whMessageCrypto_EccCheckResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, ok);
    return 0;
}

/* Curve25519 Key Generation Request translation */
int wh_MessageCrypto_TranslateCurve25519KeyGenRequest(
    uint16_t magic, const whMessageCrypto_Curve25519KeyGenRequest* src,
    whMessageCrypto_Curve25519KeyGenRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, flags);
    WH_T32(magic, dest, src, keyId);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, sizeof(src->label));
    }
    return 0;
}

/* Curve25519 Key Generation Response translation */
int wh_MessageCrypto_TranslateCurve25519KeyGenResponse(
    uint16_t magic, const whMessageCrypto_Curve25519KeyGenResponse* src,
    whMessageCrypto_Curve25519KeyGenResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, len);
    return 0;
}

/* Curve25519 Request translation */
int wh_MessageCrypto_TranslateCurve25519Request(
    uint16_t magic, const whMessageCrypto_Curve25519Request* src,
    whMessageCrypto_Curve25519Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, privateKeyId);
    WH_T32(magic, dest, src, publicKeyId);
    WH_T32(magic, dest, src, endian);
    return 0;
}

/* Curve25519 Response translation */
int wh_MessageCrypto_TranslateCurve25519Response(
    uint16_t magic, const whMessageCrypto_Curve25519Response* src,
    whMessageCrypto_Curve25519Response* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* SHA256 Request translation */
int wh_MessageCrypto_TranslateSha256Request(
    uint16_t magic, const whMessageCrypto_Sha256Request* src,
    whMessageCrypto_Sha256Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, resumeState.hiLen);
    WH_T32(magic, dest, src, resumeState.loLen);
    /* Hash value is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->resumeState.hash, src->resumeState.hash,
               sizeof(src->resumeState.hash));
    }
    WH_T32(magic, dest, src, isLastBlock);
    WH_T32(magic, dest, src, lastBlockLen);
    /* Input block is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->inBlock, src->inBlock, sizeof(src->inBlock));
    }
    return 0;
}

#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
/* SHA512 Request translation */
int wh_MessageCrypto_TranslateSha512Request(
    uint16_t magic, const whMessageCrypto_Sha512Request* src,
    whMessageCrypto_Sha512Request* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, resumeState.hiLen);
    WH_T32(magic, dest, src, resumeState.loLen);
    WH_T32(magic, dest, src, resumeState.hashType);
    /* Hash value is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->resumeState.hash, src->resumeState.hash,
               sizeof(src->resumeState.hash));
    }
    WH_T32(magic, dest, src, isLastBlock);
    WH_T32(magic, dest, src, lastBlockLen);
    /* Input block is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->inBlock, src->inBlock, sizeof(src->inBlock));
    }
    return 0;
}
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */

/* SHA2 Response translation */
int wh_MessageCrypto_TranslateSha2Response(
    uint16_t magic, const whMessageCrypto_Sha2Response* src,
    whMessageCrypto_Sha2Response* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, hiLen);
    WH_T32(magic, dest, src, loLen);
    WH_T32(magic, dest, src, hashType);
    /* Hash value is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->hash, src->hash, sizeof(src->hash));
    }
    return 0;
}


/* CMAC Request translation */
int wh_MessageCrypto_TranslateCmacRequest(
    uint16_t magic, const whMessageCrypto_CmacRequest* src,
    whMessageCrypto_CmacRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, type);
    WH_T32(magic, dest, src, outSz);
    WH_T32(magic, dest, src, inSz);
    WH_T32(magic, dest, src, keySz);
    WH_T16(magic, dest, src, keyId);
    return 0;
}

/* CMAC Response translation */
int wh_MessageCrypto_TranslateCmacResponse(
    uint16_t magic, const whMessageCrypto_CmacResponse* src,
    whMessageCrypto_CmacResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, outSz);
    WH_T16(magic, dest, src, keyId);
    return 0;
}

/* ML-DSA Key Generation Request translation */
int wh_MessageCrypto_TranslateMlDsaKeyGenRequest(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenRequest* src,
    whMessageCrypto_MlDsaKeyGenRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    WH_T32(magic, dest, src, level);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, flags);
    WH_T32(magic, dest, src, access);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, sizeof(src->label));
    }
    return 0;
}

/* ML-DSA Key Generation Response translation */
int wh_MessageCrypto_TranslateMlDsaKeyGenResponse(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenResponse* src,
    whMessageCrypto_MlDsaKeyGenResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, len);
    return 0;
}

/* ML-DSA Sign Request translation */
int wh_MessageCrypto_TranslateMlDsaSignRequest(
    uint16_t magic, const whMessageCrypto_MlDsaSignRequest* src,
    whMessageCrypto_MlDsaSignRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, level);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* ML-DSA Sign Response translation */
int wh_MessageCrypto_TranslateMlDsaSignResponse(
    uint16_t magic, const whMessageCrypto_MlDsaSignResponse* src,
    whMessageCrypto_MlDsaSignResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* ML-DSA Verify Request translation */
int wh_MessageCrypto_TranslateMlDsaVerifyRequest(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyRequest* src,
    whMessageCrypto_MlDsaVerifyRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, level);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, sigSz);
    WH_T32(magic, dest, src, hashSz);
    return 0;
}

/* ML-DSA Verify Response translation */
int wh_MessageCrypto_TranslateMlDsaVerifyResponse(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyResponse* src,
    whMessageCrypto_MlDsaVerifyResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, res);
    return 0;
}

/*
 * DMA Messages
 */

/* DMA Buffer translation */
int wh_MessageCrypto_TranslateDmaBuffer(uint16_t                         magic,
                                        const whMessageCrypto_DmaBuffer* src,
                                        whMessageCrypto_DmaBuffer*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T64(magic, dest, src, addr);
    WH_T64(magic, dest, src, sz);
    return 0;
}

/* DMA Address status translation */
int wh_MessageCrypto_TranslateDmaAddrStatus(
    uint16_t magic, const whMessageCrypto_DmaAddrStatus* src,
    whMessageCrypto_DmaAddrStatus* dest)
{
    return wh_MessageCrypto_TranslateDmaBuffer(magic, &src->badAddr,
                                               &dest->badAddr);
}
/* SHA224 DMA Request translation */
int wh_MessageCrypto_TranslateSha2DmaRequest(
    uint16_t magic, const whMessageCrypto_Sha2DmaRequest* src,
    whMessageCrypto_Sha2DmaRequest* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T64(magic, dest, src, finalize);

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->input, &dest->input);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->state, &dest->state);
    if (ret != 0) {
        return ret;
    }

    ret =
        wh_MessageCrypto_TranslateDmaBuffer(magic, &src->output, &dest->output);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

/* SHA2 DMA Response translation */
int wh_MessageCrypto_TranslateSha2DmaResponse(
    uint16_t magic, const whMessageCrypto_Sha2DmaResponse* src,
    whMessageCrypto_Sha2DmaResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    return wh_MessageCrypto_TranslateDmaAddrStatus(magic, &src->dmaAddrStatus,
                                                   &dest->dmaAddrStatus);
}

/* CMAC DMA Request translation */
int wh_MessageCrypto_TranslateCmacDmaRequest(
    uint16_t magic, const whMessageCrypto_CmacDmaRequest* src,
    whMessageCrypto_CmacDmaRequest* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T32(magic, dest, src, type);
    WH_T32(magic, dest, src, finalize);

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->state, &dest->state);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->key, &dest->key);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->input, &dest->input);
    if (ret != 0) {
        return ret;
    }

    ret =
        wh_MessageCrypto_TranslateDmaBuffer(magic, &src->output, &dest->output);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

/* CMAC DMA Response translation */
int wh_MessageCrypto_TranslateCmacDmaResponse(
    uint16_t magic, const whMessageCrypto_CmacDmaResponse* src,
    whMessageCrypto_CmacDmaResponse* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaAddrStatus(magic, &src->dmaAddrStatus,
                                                  &dest->dmaAddrStatus);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, outSz);
    return 0;
}

/* ML-DSA DMA Key Generation Request translation */
int wh_MessageCrypto_TranslateMlDsaKeyGenDmaRequest(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenDmaRequest* src,
    whMessageCrypto_MlDsaKeyGenDmaRequest* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->key, &dest->key);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, level);
    WH_T32(magic, dest, src, flags);
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, access);
    WH_T32(magic, dest, src, labelSize);
    /* Label is just a byte array, no translation needed */
    if (src != dest) {
        memcpy(dest->label, src->label, sizeof(src->label));
    }

    return 0;
}

/* ML-DSA DMA Response translation */
int wh_MessageCrypto_TranslateMlDsaKeyGenDmaResponse(
    uint16_t magic, const whMessageCrypto_MlDsaKeyGenDmaResponse* src,
    whMessageCrypto_MlDsaKeyGenDmaResponse* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaAddrStatus(magic, &src->dmaAddrStatus,
                                                  &dest->dmaAddrStatus);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, keySize);
    return 0;
}

/* ML-DSA DMA Sign Request translation */
int wh_MessageCrypto_TranslateMlDsaSignDmaRequest(
    uint16_t magic, const whMessageCrypto_MlDsaSignDmaRequest* src,
    whMessageCrypto_MlDsaSignDmaRequest* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->msg, &dest->msg);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->sig, &dest->sig);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, level);
    WH_T32(magic, dest, src, keyId);

    return 0;
}

/* ML-DSA DMA Sign Response translation */
int wh_MessageCrypto_TranslateMlDsaSignDmaResponse(
    uint16_t magic, const whMessageCrypto_MlDsaSignDmaResponse* src,
    whMessageCrypto_MlDsaSignDmaResponse* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaAddrStatus(magic, &src->dmaAddrStatus,
                                                  &dest->dmaAddrStatus);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, sigLen);
    return 0;
}

/* ML-DSA DMA Verify Request translation */
int wh_MessageCrypto_TranslateMlDsaVerifyDmaRequest(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyDmaRequest* src,
    whMessageCrypto_MlDsaVerifyDmaRequest* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->sig, &dest->sig);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->msg, &dest->msg);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, options);
    WH_T32(magic, dest, src, level);
    WH_T32(magic, dest, src, keyId);

    return 0;
}

/* ML-DSA DMA Verify Response translation */
int wh_MessageCrypto_TranslateMlDsaVerifyDmaResponse(
    uint16_t magic, const whMessageCrypto_MlDsaVerifyDmaResponse* src,
    whMessageCrypto_MlDsaVerifyDmaResponse* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaAddrStatus(magic, &src->dmaAddrStatus,
                                                  &dest->dmaAddrStatus);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, verifyResult);
    return 0;
}

/* AES DMA Request translation */
int wh_MessageCrypto_TranslateAesDmaRequest(
    uint16_t magic, const whMessageCrypto_AesDmaRequest* src,
    whMessageCrypto_AesDmaRequest* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    WH_T32(magic, dest, src, enc);
    WH_T32(magic, dest, src, type);
    WH_T32(magic, dest, src, finalize);
    WH_T32(magic, dest, src, keyId);

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->state, &dest->state);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->key, &dest->key);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->input, &dest->input);
    if (ret != 0) {
        return ret;
    }

    ret =
        wh_MessageCrypto_TranslateDmaBuffer(magic, &src->output, &dest->output);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->authTag,
                                              &dest->authTag);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->iv, &dest->iv);
    if (ret != 0) {
        return ret;
    }

    ret = wh_MessageCrypto_TranslateDmaBuffer(magic, &src->aad, &dest->aad);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

/* AES DMA Response translation */
int wh_MessageCrypto_TranslateAesDmaResponse(
    uint16_t magic, const whMessageCrypto_AesDmaResponse* src,
    whMessageCrypto_AesDmaResponse* dest)
{
    int ret;

    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = wh_MessageCrypto_TranslateDmaAddrStatus(magic, &src->dmaAddrStatus,
                                                  &dest->dmaAddrStatus);
    if (ret != 0) {
        return ret;
    }

    WH_T32(magic, dest, src, outSz);
    return 0;
}
