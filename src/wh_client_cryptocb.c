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
 * src/wh_client_cryptocb.c
 *
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message.h"
#include "wolfhsm/wh_client.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/sha256.h"

#include "wolfhsm/wh_crypto.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_client_cryptocb.h"
#include "wolfhsm/wh_message_crypto.h"


#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
static int _handlePqcSigKeyGen(whClientContext* ctx, wc_CryptoInfo* info,
                               int useDma);
static int _handlePqcSign(whClientContext* ctx, wc_CryptoInfo* info,
                          int useDma);
static int _handlePqcVerify(whClientContext* ctx, wc_CryptoInfo* info,
                            int useDma);
static int _handlePqcSigCheckPrivKey(whClientContext* ctx, wc_CryptoInfo* info,
                                     int useDma);
#endif /* HAVE_DILITHIUM || HAVE_FALCON */

int wh_Client_CryptoCb(int devId, wc_CryptoInfo* info, void* inCtx)
{
    /* III When possible, return wolfCrypt-enumerated errors */
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    if (    (devId == INVALID_DEVID) ||
            (info == NULL) ||
            (inCtx == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    printf("[client] %s info:%p algo_type:%d\n", __func__, info,
            (info!=NULL)?info->algo_type:-1);
    wc_CryptoCb_InfoString(info);
#endif
    /* Based on the info type, process the request */
    switch (info->algo_type)
    {
#if !defined(NO_AES) || !defined(NO_DES3)
    case WC_ALGO_TYPE_CIPHER:
        switch (info->cipher.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
        {
            /* Extract info parameters */
            uint32_t enc        = info->cipher.enc;
            Aes* aes            = info->cipher.aescbc.aes;
            const uint8_t* in   = info->cipher.aescbc.in;
            uint32_t len        = info->cipher.aescbc.sz;
            uint8_t* out        = info->cipher.aescbc.out;

            ret = wh_Client_AesCbc(ctx, aes, enc, in, len, out);

        } break;
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
        {
            /* Extract info parameters */
            uint32_t enc            =   info->cipher.enc;
            Aes* aes                = (enc == 0) ?
                                        info->cipher.aesgcm_dec.aes :
                                        info->cipher.aesgcm_enc.aes;
            uint32_t len            = (enc == 0) ?
                                        info->cipher.aesgcm_dec.sz :
                                        info->cipher.aesgcm_enc.sz;
            uint32_t iv_len         = (enc == 0) ?
                                        info->cipher.aesgcm_dec.ivSz:
                                        info->cipher.aesgcm_enc.ivSz;
            uint32_t authin_len     = (enc == 0) ?
                                        info->cipher.aesgcm_dec.authInSz:
                                        info->cipher.aesgcm_enc.authInSz;
            uint32_t tag_len        = (enc == 0) ?
                                        info->cipher.aesgcm_dec.authTagSz:
                                        info->cipher.aesgcm_enc.authTagSz;
            const uint8_t* in       = (enc == 0) ?
                                        info->cipher.aesgcm_dec.in :
                                        info->cipher.aesgcm_enc.in;
            const uint8_t* iv       = (enc == 0) ?
                                        info->cipher.aesgcm_dec.iv :
                                        info->cipher.aesgcm_enc.iv;
            const uint8_t* authin   = (enc == 0) ?
                                        info->cipher.aesgcm_dec.authIn :
                                        info->cipher.aesgcm_enc.authIn;
            const uint8_t* dec_tag  =   info->cipher.aesgcm_dec.authTag;
            uint8_t* enc_tag        =   info->cipher.aesgcm_enc.authTag;
            uint8_t* out            = (enc == 0) ?
                                        info->cipher.aesgcm_dec.out :
                                        info->cipher.aesgcm_enc.out;

            ret = wh_Client_AesGcm(ctx, aes, enc, in, len,iv, iv_len,
                    authin, authin_len, dec_tag, enc_tag, tag_len, out);
        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;
#endif /* !NO_AES || !NO_DES */

    case WC_ALGO_TYPE_PK:
        switch (info->pk.type)
        {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
        {
            /* Extract info parameters */
            int size            = info->pk.rsakg.size;
            int e               = info->pk.rsakg.e;
            RsaKey* rsa         = info->pk.rsakg.key;

            ret = wh_Client_RsaMakeExportKey(ctx, size, e, rsa);
        } break;
#endif  /* WOLFSSL_KEY_GEN */

        case WC_PK_TYPE_RSA:
        {
            /* Extract info parameters */
            RsaKey* rsa         = info->pk.rsa.key;
            int rsa_type        = info->pk.rsa.type;
            const uint8_t* in   = info->pk.rsa.in;
            word32 in_len       = info->pk.rsa.inLen;
            uint8_t* out        = info->pk.rsa.out;
            word32* out_len     = info->pk.rsa.outLen;

            uint16_t len = 0;
            if(out_len != NULL) {
                len = *out_len;
            }

            ret = wh_Client_RsaFunction(ctx,
                    rsa, rsa_type, in, in_len,
                    out, &len);

            if (    (ret == WH_ERROR_OK) &&
                    (out_len != NULL) ) {
                *out_len = len;
            }
        } break;

        case WC_PK_TYPE_RSA_GET_SIZE:
        {
            /* Extract info parameters */
            const RsaKey* rsa   = info->pk.rsa_get_size.key;
            int* out_size       = info->pk.rsa_get_size.keySize;

            ret = wh_Client_RsaGetSize(ctx, rsa, out_size);
        } break;

#endif /* !NO_RSA */

#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
        {
            /* Extract info parameters */
            ecc_key* key        = info->pk.eckg.key;
            uint32_t size       = info->pk.eckg.size;
            uint32_t curve_id   = info->pk.eckg.curveId;

            ret = wh_Client_EccMakeExportKey(ctx, size, curve_id, key);
        } break;

        case WC_PK_TYPE_ECDH:
        {
            /* Extract info parameters */
            ecc_key* priv_key   = info->pk.ecdh.private_key;
            ecc_key* pub_key    = info->pk.ecdh.public_key;
            uint8_t* out        = info->pk.ecdh.out;
            word32* out_len     = info->pk.ecdh.outlen;

            uint16_t len = 0;
            if(out_len != NULL) {
                len = *out_len;
            }

            ret = wh_Client_EccSharedSecret(ctx,
                                            priv_key, pub_key,
                                            out, &len);
            if (    (ret == WH_ERROR_OK) &&
                    (out_len != NULL) ) {
                *out_len = len;
            }
        } break;

        case WC_PK_TYPE_ECDSA_SIGN:
        {
            /* Extract info parameters */
            ecc_key* key        = info->pk.eccsign.key;
            const uint8_t* hash = (const uint8_t*)info->pk.eccsign.in;
            uint16_t hash_len   = (uint16_t)info->pk.eccsign.inlen;
            uint8_t* sig        = (uint8_t*)info->pk.eccsign.out;
            word32* out_sig_len = info->pk.eccsign.outlen;

            uint16_t sig_len = 0;
            if(out_sig_len != NULL) {
                sig_len = (uint16_t)(*out_sig_len);
            }

            ret = wh_Client_EccSign(ctx, key, hash, hash_len, sig, &sig_len);
            if (    (ret == WH_ERROR_OK) &&
                    (out_sig_len != NULL) ) {
                *out_sig_len = sig_len;
            }
        } break;

        case WC_PK_TYPE_ECDSA_VERIFY:
        {
            /* Extract info parameters */
            ecc_key* key        = info->pk.eccverify.key;
            const uint8_t* sig  = (const uint8_t*)info->pk.eccverify.sig;
            uint16_t sig_len    = (uint16_t)info->pk.eccverify.siglen;
            const uint8_t* hash = (const uint8_t*)info->pk.eccverify.hash;
            uint16_t hash_len   = (uint16_t)info->pk.eccverify.hashlen;
            int* out_res        = info->pk.eccverify.res;

            ret = wh_Client_EccVerify(ctx, key, sig, sig_len, hash, hash_len,
                    out_res);
        } break;

        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
        {
#if 0
            /* TODO: Expose this and add wolfcrypt functions to test */
            /* Extract info parameters */
            ecc_key* key            = info->pk.ecc_check.key;
            const uint8_t* pub_key  = info->pk.ecc_check.pubKey;
            uint32_t pub_key_len    = info->pk.ecc_check.pubKeySz;

            ret = wh_Client_EccCheckPubKey(ctx, key, pub_key, pub_key_len);
#else
            ret = CRYPTOCB_UNAVAILABLE;
#endif
        } break;

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
        {
            /* Extract info parameters */
            curve25519_key* key = info->pk.curve25519kg.key;
            uint16_t size       = info->pk.curve25519kg.size;

            ret = wh_Client_Curve25519MakeExportKey(ctx, size, key);
        } break;

        case WC_PK_TYPE_CURVE25519:
        {
            /* Extract info parameters */
            curve25519_key* pub_key     = info->pk.curve25519.public_key;
            curve25519_key* priv_key    = info->pk.curve25519.private_key;
            int endian                  = info->pk.curve25519.endian;
            uint8_t* out                = info->pk.curve25519.out;
            word32* out_len             = info->pk.curve25519.outlen;
            uint16_t len                = 0;

            if(out_len != NULL) {
                len = *out_len;
            }

            ret = wh_Client_Curve25519SharedSecret(ctx,
                                            priv_key, pub_key,
                                            endian,
                                            out, &len);
            if (    (ret == WH_ERROR_OK) &&
                    (out_len != NULL) ){
                *out_len = len;
            }
        } break;
#endif /* HAVE_CURVE25519 */

#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
        case WC_PK_TYPE_PQC_SIG_KEYGEN:
            ret = _handlePqcSigKeyGen(ctx, info, 0);
            break;

        case WC_PK_TYPE_PQC_SIG_SIGN:
            ret = _handlePqcSign(ctx, info, 0);
            break;

        case WC_PK_TYPE_PQC_SIG_VERIFY:
            ret = _handlePqcVerify(ctx, info, 0);
            break;

        case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
            ret = _handlePqcSigCheckPrivKey(ctx, info, 0);
            break;

#endif /* HAVE_DILITHIUM || HAVE_FALCON */

        case WC_PK_TYPE_NONE:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;

#ifndef WC_NO_RNG
    case WC_ALGO_TYPE_RNG:
    {
        /* Extract info parameters */
        uint8_t* out = info->rng.out;
        uint32_t size = info->rng.sz;

        ret = wh_Client_RngGenerate(ctx, out, size);
    } break;
#endif /* !WC_NO_RNG */

#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
    {
        /* Extract info parameters */
        const uint8_t* in = info->cmac.in;
        uint32_t in_len = (in == NULL) ? 0 : info->cmac.inSz;
        const uint8_t* key = info->cmac.key;
        uint32_t key_len = (key == NULL) ? 0 : info->cmac.keySz;
        uint8_t* outMac = info->cmac.out;
        word32 *out_mac_len = info->cmac.outSz;
        Cmac* cmac = info->cmac.cmac;
        int type = info->cmac.type;

        ret = wh_Client_Cmac(ctx, cmac, type, key, key_len, in, in_len, outMac,
                             out_mac_len);
    } break; /* case WC_ALGO_TYPE_CMAC */

#endif /* WOLFSSL_CMAC */

    case WC_ALGO_TYPE_HASH: {
        switch (info->hash.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256: {
                wc_Sha256*     sha   = info->hash.sha256;
                const uint8_t* in    = info->hash.in;
                uint32_t       inLen = info->hash.inSz;
                uint8_t*       out   = info->hash.digest;

                ret = wh_Client_Sha256(ctx, sha, in, inLen, out);
            } break;
#endif /* !NO_SHA256 */

            default:
                ret = CRYPTOCB_UNAVAILABLE;
                break;
        }
    } break; /* case WC_ALGO_TYPE_HASH */

    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

    /* Fix up error code to be wolfCrypt */
    if (ret == WH_ERROR_BADARGS) {
        ret = BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    if (ret == CRYPTOCB_UNAVAILABLE) {
        printf("[client] %s X not implemented: algo->type:%d\n", __func__, info->algo_type);
    } else {
        printf("[client] %s - ret:%d algo->type:%d\n", __func__, ret, info->algo_type);
    }
#endif /* DEBUG_CRYPTOCB */
    return ret;
}

#if defined(HAVE_FALCON) || defined(HAVE_DILITHIUM)
static int _handlePqcSigKeyGen(whClientContext* ctx, wc_CryptoInfo* info,
                               int useDma)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    /* Extract info parameters */
    int     size = info->pk.pqc_sig_kg.size;
    void*   key  = info->pk.pqc_sig_kg.key;
    int     type = info->pk.pqc_sig_kg.type;

#ifndef WOLFHSM_CFG_DMA
    if (useDma) {
        /* TODO: proper error code? */
        return WC_HW_E;
    }
#endif

    switch (type) {
#ifdef HAVE_DILITHIUM
        case WC_PQC_SIG_TYPE_DILITHIUM: {
            int level = ((MlDsaKey*)key)->level;
#ifdef WOLFHSM_CFG_DMA
            if (useDma) {
                ret = wh_Client_MlDsaMakeExportKeyDma(ctx, level, key);
            }
            else
#endif /* WOLFHSM_CFG_DMA */
            {
                ret = wh_Client_MlDsaMakeExportKey(ctx, level, size, key);
            }
        } break;
#endif /* HAVE_DILITHIUM */

        /* Support for additional PQC algorithms should be added here */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

static int _handlePqcSign(whClientContext* ctx, wc_CryptoInfo* info, int useDma)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    /* Extract info parameters */
    const byte* in      = info->pk.pqc_sign.in;
    word32      in_len  = info->pk.pqc_sign.inlen;
    byte*       out     = info->pk.pqc_sign.out;
    word32*     out_len = info->pk.pqc_sign.outlen;
    void*       key     = info->pk.pqc_sign.key;
    int         type    = info->pk.pqc_sign.type;

#ifndef WOLFHSM_CFG_DMA
    if (useDma) {
        /* TODO: proper error code? */
        return WC_HW_E;
    }
#endif

    switch (type) {
#ifdef HAVE_DILITHIUM
        case WC_PQC_SIG_TYPE_DILITHIUM:
#ifdef WOLFHSM_CFG_DMA
            if (useDma) {
                ret =
                    wh_Client_MlDsaSignDma(ctx, in, in_len, out, out_len, key);
            }
            else
#endif /* WOLFHSM_CFG_DMA */
            {
                ret = wh_Client_MlDsaSign(ctx, in, in_len, out, out_len, key);
            }
            break;
#endif /* HAVE_DILITHIUM */

        /* Support for additional PQC algorithms should be added here */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

static int _handlePqcVerify(whClientContext* ctx, wc_CryptoInfo* info,
                            int useDma)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    /* Extract info parameters */
    const byte* sig     = info->pk.pqc_verify.sig;
    word32      sig_len = info->pk.pqc_verify.siglen;
    const byte* msg     = info->pk.pqc_verify.msg;
    word32      msg_len = info->pk.pqc_verify.msglen;
    int*        res     = info->pk.pqc_verify.res;
    void*       key     = info->pk.pqc_verify.key;
    int         type    = info->pk.pqc_verify.type;

#ifndef WOLFHSM_CFG_DMA
    if (useDma) {
        /* TODO: proper error code? */
        return WC_HW_E;
    }
#endif

    switch (type) {
#ifdef HAVE_DILITHIUM
        case WC_PQC_SIG_TYPE_DILITHIUM:
#ifdef WOLFHSM_CFG_DMA
            if (useDma) {
                ret = wh_Client_MlDsaVerifyDma(ctx, sig, sig_len, msg, msg_len,
                                               res, key);
            }
            else
#endif /* WOLFHSM_CFG_DMA */
            {
                ret = wh_Client_MlDsaVerify(ctx, sig, sig_len, msg, msg_len, res,
                                            key);
            }
            break;
#endif /* HAVE_DILITHIUM */

        /* Support for additional PQC algorithms should be added here */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}

static int _handlePqcSigCheckPrivKey(whClientContext* ctx, wc_CryptoInfo* info,
                                     int useDma)
{
    int ret = CRYPTOCB_UNAVAILABLE;

    /* Extract info parameters */
    void*       key      = info->pk.pqc_sig_check.key;
    const byte* pubKey   = info->pk.pqc_sig_check.pubKey;
    word32      pubKeySz = info->pk.pqc_sig_check.pubKeySz;
    int         type     = info->pk.pqc_sig_check.type;

#ifndef WOLFHSM_CFG_DMA
    if (useDma) {
        /* TODO: proper error code? */
        return WC_HW_E;
    }
#endif

    switch (type) {
#ifdef HAVE_DILITHIUM
        case WC_PQC_SIG_TYPE_DILITHIUM:
#ifdef WOLFHSM_CFG_DMA
            if (useDma) {
                ret =
                    wh_Client_MlDsaCheckPrivKeyDma(ctx, key, pubKey, pubKeySz);
            }
            else
#endif /* WOLFHSM_CFG_DMA */
            {
                ret = wh_Client_MlDsaCheckPrivKey(ctx, key, pubKey, pubKeySz);
            }
            break;
#endif /* HAVE_DILITHIUM */

            /* Support for additional PQC algorithms should be added here */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
    }

    return ret;
}
#endif /* HAVE_FALCON || HAVE_DILITHIUM */


#ifdef WOLFHSM_CFG_DMA
int wh_Client_CryptoCbDma(int devId, wc_CryptoInfo* info, void* inCtx)
{
    /* III When possible, return wolfCrypt-enumerated errors */
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;

    if (    (devId == INVALID_DEVID) ||
            (info == NULL) ||
            (inCtx == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    printf("[client] %s ", __func__);
    wc_CryptoCb_InfoString(info);
#endif

    /* Based on the info type, process the request */
    switch (info->algo_type)
    {
    case WC_ALGO_TYPE_HASH: {
        switch (info->hash.type) {
#ifndef NO_SHA256
            case WC_HASH_TYPE_SHA256: {
                wc_Sha256*     sha   = info->hash.sha256;
                const uint8_t* in    = info->hash.in;
                uint32_t       inLen = info->hash.inSz;
                uint8_t*       out   = info->hash.digest;

                ret = wh_Client_Sha256Dma(ctx, sha, in, inLen, out);
            } break;
#endif /* !NO_SHA256 */

            default:
                ret = CRYPTOCB_UNAVAILABLE;
                break;
        }
    } break; /* case WC_ALGO_TYPE_HASH */


    case WC_ALGO_TYPE_PK: {
        switch (info->pk.type) {
#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
            case WC_PK_TYPE_PQC_SIG_KEYGEN:
                ret = _handlePqcSigKeyGen(ctx, info, 1);
                break;
            case WC_PK_TYPE_PQC_SIG_SIGN:
                ret = _handlePqcSign(ctx, info, 1);
                break;
            case WC_PK_TYPE_PQC_SIG_VERIFY:
                ret = _handlePqcVerify(ctx, info, 1);
                break;
            case WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY:
                ret = _handlePqcSigCheckPrivKey(ctx, info, 1);
                break;
#endif /* HAVE_DILITHIUM || HAVE_FALCON */
        }
    } break; /* case WC_ALGO_TYPE_PK */

#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC: {
        Cmac*          cmac      = info->cmac.cmac;
        CmacType       type      = info->cmac.type;
        const uint8_t* key       = info->cmac.key;
        uint32_t       keyLen    = info->cmac.keySz;
        const uint8_t* in        = info->cmac.in;
        uint32_t       inLen     = info->cmac.inSz;
        uint8_t*       outMac    = info->cmac.out;
        uint32_t*      outMacLen = info->cmac.outSz;

        ret = wh_Client_CmacDma(ctx, cmac, type, key, keyLen, in, inLen, outMac,
                                outMacLen);
    } break;
#endif

    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

#ifdef DEBUG_CRYPTOCB
    if (ret == CRYPTOCB_UNAVAILABLE) {
        printf("[client] %s X not implemented: algo->type:%d\n", __func__, info->algo_type);
    } else {
        printf("[client] %s - ret:%d algo->type:%d\n", __func__, ret, info->algo_type);
    }
#endif /* DEBUG_CRYPTOCB */
    return ret;
}
#endif /* WOLFHSM_CFG_DMA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

