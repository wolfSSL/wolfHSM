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
 * src/wh_server_img_mgr.c
 *
 */

#include "wolfhsm/wh_settings.h"

/* TODO: gating the entire module on NO_CRYPTO for now until keystore is able to
 * be used in a NO_CRYPTO build. */
#if defined(WOLFHSM_CFG_SERVER_IMG_MGR) && \
    defined(WOLFHSM_CFG_ENABLE_SERVER) && !defined(WOLFHSM_CFG_NO_CRYPTO)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_server.h"
#include "wolfhsm/wh_server_img_mgr.h"
#include "wolfhsm/wh_server_keystore.h"
#include "wolfhsm/wh_server_cert.h"
#include "wolfhsm/wh_nvm.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#endif

int wh_Server_ImgMgrInit(whServerImgMgrContext*      context,
                         const whServerImgMgrConfig* config)
{
    int ret = WH_ERROR_OK;

    if (context == NULL || config == NULL || config->server == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (config->imageCount > WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize context */
    memset(context, 0, sizeof(*context));
    context->imageCount = config->imageCount;
    context->server     = config->server;

    /* Copy image configurations */
    if (config->images != NULL && config->imageCount > 0) {
        size_t i;
        for (i = 0; i < config->imageCount; i++) {
            context->images[i] = config->images[i];
        }
    }

    return ret;
}

/* Copy key material out of the keystore cache while holding the NVM lock, so
 * the caller works from a private snapshot instead of a live cache slot that a
 * concurrent evict or cache request could rewrite. */
static int _ImgMgrCopyKeyFromKeystore(whServerContext* server, whKeyId keyId,
                                      uint8_t* dst, size_t dstMax,
                                      size_t* outLen)
{
    int            ret;
    uint8_t*       keyBuf  = NULL;
    whNvmMetadata* keyMeta = NULL;

    if ((server == NULL) || (dst == NULL) || (outLen == NULL) ||
        (dstMax == 0)) {
        return WH_ERROR_BADARGS;
    }

    ret = WH_SERVER_NVM_LOCK(server);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    ret = wh_Server_KeystoreFreshenKey(server, keyId, &keyBuf, &keyMeta);
    if (ret == WH_ERROR_OK) {
        if ((keyBuf == NULL) || (keyMeta == NULL)) {
            ret = WH_ERROR_ABORTED;
        }
        else if ((size_t)keyMeta->len > dstMax) {
            ret = WH_ERROR_BUFFER_SIZE;
        }
        else {
            memcpy(dst, keyBuf, keyMeta->len);
            *outLen = (size_t)keyMeta->len;
        }
    }

    (void)WH_SERVER_NVM_UNLOCK(server);

    return ret;
}

int wh_Server_ImgMgrVerifyImg(whServerImgMgrContext*      context,
                              const whServerImgMgrImg*    img,
                              whServerImgMgrVerifyResult* result)
{
    int              ret    = WH_ERROR_OK;
    whServerContext* server = NULL;
    uint8_t          keyBuf[WOLFHSM_CFG_SERVER_IMG_MGR_MAX_KEY_SIZE];
    const uint8_t*   keyPtr = NULL; /* stays NULL for paths with no key */
    size_t           keySz  = 0;
    uint8_t sigBuf[WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE]; /* Buffer for
                                                                signature */
    whNvmMetadata sigMeta       = {0};
    uint32_t      sigSize       = sizeof(sigBuf);
    whNvmSize     actualSigSize = 0;
    uint8_t*      sigPtr        = NULL;

    if (context == NULL || img == NULL || result == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize result structure */
    result->verifyMethodResult = WH_ERROR_ABORTED;
    result->verifyActionResult = WH_ERROR_ABORTED;

    server = context->server;
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }

    switch (img->imgType) {
        case WH_IMG_MGR_IMG_TYPE_WOLFBOOT:
            /* Load key from keystore, skip sig loading (sig is in header) */
            ret = _ImgMgrCopyKeyFromKeystore(server, img->keyId, keyBuf,
                                             sizeof(keyBuf), &keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }
            keyPtr = keyBuf;
            /* sig/sigSz passed as NULL/0 to callback */
            break;

        case WH_IMG_MGR_IMG_TYPE_WOLFBOOT_CERT:
            /* Skip both key and sig loading - callback handles everything */
            /* sig/sigSz and key/keySz passed as NULL/0 to callback */
            break;

        case WH_IMG_MGR_IMG_TYPE_RAW:
            /* Load the signature from NVM first so the key snapshot is the
             * last thing taken before verification */
            ret = wh_Nvm_GetMetadata(server->nvm, img->sigNvmId, &sigMeta);
            if (ret != WH_ERROR_OK) {
                return ret;
            }

            /* Ensure signature fits in buffer */
            if (sigMeta.len > sigSize) {
                return WH_ERROR_BADARGS;
            }

            ret =
                wh_Nvm_Read(server->nvm, img->sigNvmId, 0, sigMeta.len, sigBuf);
            if (ret != WH_ERROR_OK) {
                return ret;
            }
            actualSigSize = sigMeta.len;
            sigPtr        = sigBuf;

            /* Load key from keystore */
            ret = _ImgMgrCopyKeyFromKeystore(server, img->keyId, keyBuf,
                                             sizeof(keyBuf), &keySz);
            if (ret != WH_ERROR_OK) {
                return ret;
            }
            keyPtr = keyBuf;
            break;

        default:
            return WH_ERROR_BADARGS;
    }

    /* Invoke verify method callback */
    if (img->verifyMethod != NULL) {
        result->verifyMethodResult = img->verifyMethod(
            context, img, keyPtr, keySz, sigPtr, actualSigSize);
    }
    else {
        result->verifyMethodResult = WH_ERROR_NOHANDLER;
    }

    /* Invoke verifyAction callback */
    if (img->verifyAction != NULL) {
        result->verifyActionResult =
            img->verifyAction(context, img, result->verifyMethodResult);
    }
    else {
        result->verifyActionResult = WH_ERROR_NOHANDLER;
    }

    return ret;
}

int wh_Server_ImgMgrVerifyImgIdx(whServerImgMgrContext* context, size_t imgIdx,
                                 whServerImgMgrVerifyResult* outResult)
{
    if (context == NULL || imgIdx >= context->imageCount || outResult == NULL) {
        return WH_ERROR_BADARGS;
    }

    return wh_Server_ImgMgrVerifyImg(context, &context->images[imgIdx],
                                     outResult);
}

int wh_Server_ImgMgrVerifyAll(whServerImgMgrContext*      context,
                              whServerImgMgrVerifyResult* outResults,
                              size_t outResultsCount, size_t* outErrorIdx)
{
    int    verifyRet = WH_ERROR_OK;
    size_t i;

    if (context == NULL || outResults == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (outResultsCount < context->imageCount) {
        return WH_ERROR_BADARGS;
    }

    for (i = 0; i < context->imageCount; i++) {
        verifyRet = wh_Server_ImgMgrVerifyImg(context, &context->images[i],
                                              &outResults[i]);
        if (verifyRet != WH_ERROR_OK) {
            if (outErrorIdx != NULL) {
                *outErrorIdx = i;
            }
            return verifyRet;
        }
    }

    return WH_ERROR_OK;
}

#ifndef WOLFHSM_CFG_NO_CRYPTO

#ifdef HAVE_ECC
int wh_Server_ImgMgrVerifyMethodEccWithSha256(whServerImgMgrContext*   context,
                                              const whServerImgMgrImg* img,
                                              const uint8_t* key, size_t keySz,
                                              const uint8_t* sig, size_t sigSz)
{
    int     ret = WH_ERROR_OK;
    ecc_key eccKey;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    int     verifyResult = 0;
    word32  inOutIdx     = 0;

    if (context == NULL || context->server == NULL || img == NULL ||
        key == NULL || sig == NULL || keySz == 0 || sigSz == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize ECC key */
    ret = wc_ecc_init_ex(&eccKey, NULL, context->server->devId);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Import the public key */
    ret = wc_EccPublicKeyDecode(key, &inOutIdx, &eccKey, (word32)keySz);
    if (ret != 0) {
        wc_ecc_free(&eccKey);
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_DMA
    /* For DMA case, we need to access the client memory through server pointer
     */
    whServerContext* server    = context->server;
    void*            serverPtr = NULL;

    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPtr, img->size, WH_DMA_OPER_CLIENT_READ_PRE,
        (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        wc_ecc_free(&eccKey);
        return ret;
    }

    /* Hash the image data from server pointer using one-shot API */
    ret = wc_Sha256Hash_ex((const uint8_t*)serverPtr, (word32)img->size, hash,
                           NULL, server->devId);

    /* Always release the DMA mapping to avoid leaking READ_PRE-allocated
     * resources, even when the hash failed. Preserve the original error. */
    {
        int dmaRet = wh_Server_DmaProcessClientAddress(
            server, img->addr, &serverPtr, img->size,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        if (ret == 0) {
            ret = dmaRet;
        }
    }
#else
    /* Hash the image data using one-shot API */
    ret = wc_Sha256Hash_ex((const uint8_t*)img->addr, (word32)img->size, hash,
                           NULL, context->server->devId);
#endif
    if (ret != 0) {
        wc_ecc_free(&eccKey);
        return ret;
    }

    /* Verify the signature */
    ret = wc_ecc_verify_hash(sig, (word32)sigSz, hash, sizeof(hash),
                             &verifyResult, &eccKey);

    /* Cleanup */
    (void)wc_ecc_free(&eccKey);

    if (ret != 0) {
        return ret;
    }

    if (verifyResult != 1) {
        return WH_ERROR_NOTVERIFIED;
    }
    return WH_ERROR_OK;
}
#endif /* HAVE_ECC */

#ifdef WOLFSSL_CMAC
int wh_Server_ImgMgrVerifyMethodAesCmac(whServerImgMgrContext*   context,
                                        const whServerImgMgrImg* img,
                                        const uint8_t* key, size_t keySz,
                                        const uint8_t* sig, size_t sigSz)
{
    int     ret = WH_ERROR_OK;
    Cmac    cmac;

    if (context == NULL || context->server == NULL || img == NULL ||
        key == NULL || sig == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Validate key size for AES128 */
    if (keySz != AES_128_KEY_SIZE) {
        return WH_ERROR_BADARGS;
    }

    /* Validate signature size for AES CMAC */
    if (sigSz != WC_AES_BLOCK_SIZE) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_DMA
    /* For DMA case, we need to access the client memory through server pointer
     */
    whServerContext* server    = context->server;
    void*            serverPtr = NULL;

    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPtr, img->size, WH_DMA_OPER_CLIENT_READ_PRE,
        (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Compute CMAC of the image data from server pointer */
    ret = wc_AesCmacVerify_ex(&cmac, sig, (word32)sigSz, (const byte*)serverPtr,
                              (word32)img->size, key, (word32)keySz, NULL,
                              server->devId);

    /* Always release the DMA mapping to avoid leaking READ_PRE-allocated
     * resources, even when the verify failed. Preserve the original error. */
    {
        int dmaRet = wh_Server_DmaProcessClientAddress(
            server, img->addr, &serverPtr, img->size,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        if (ret == 0) {
            ret = dmaRet;
        }
    }
#else
    ret = wc_AesCmacVerify_ex(&cmac, sig, (word32)sigSz, (const byte*)img->addr,
                              (word32)img->size, key, (word32)keySz, NULL,
                              context->server->devId);
#endif
    if (ret != 0) {
        return ret;
    }

    return WH_ERROR_OK; /* CMAC verification succeeded */
}
#endif /* WOLFSSL_CMAC */

#ifndef NO_RSA
int wh_Server_ImgMgrVerifyMethodRsaSslWithSha256(
    whServerImgMgrContext* context, const whServerImgMgrImg* img,
    const uint8_t* key, size_t keySz, const uint8_t* sig, size_t sigSz)
{
    int     ret = WH_ERROR_OK;
    RsaKey  rsaKey;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    uint8_t decrypted[256]; /* Buffer for decrypted signature */
    word32  decryptedLen = sizeof(decrypted);
    word32  inOutIdx     = 0;

    if (context == NULL || context->server == NULL || img == NULL ||
        key == NULL || sig == NULL || keySz == 0 || sigSz == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize RSA key */
    ret = wc_InitRsaKey_ex(&rsaKey, NULL, context->server->devId);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Import the public key */
    ret = wc_RsaPublicKeyDecode(key, &inOutIdx, &rsaKey, (word32)keySz);
    if (ret != 0) {
        wc_FreeRsaKey(&rsaKey);
        return WH_ERROR_ABORTED;
    }

#ifdef WOLFHSM_CFG_DMA
    /* For DMA case, we need to access the client memory through server pointer
     */
    whServerContext* server    = context->server;
    void*            serverPtr = NULL;

    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPtr, img->size, WH_DMA_OPER_CLIENT_READ_PRE,
        (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        wc_FreeRsaKey(&rsaKey);
        return ret;
    }

    /* Hash the image data from server pointer using one-shot API */
    ret = wc_Sha256Hash_ex((const uint8_t*)serverPtr, (word32)img->size, hash,
                           NULL, server->devId);

    /* Always release the DMA mapping to avoid leaking READ_PRE-allocated
     * resources, even when the hash failed. Preserve the original error. */
    {
        int dmaRet = wh_Server_DmaProcessClientAddress(
            server, img->addr, &serverPtr, img->size,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
        if (ret == 0) {
            ret = dmaRet;
        }
    }
#else
    /* Hash the image data using one-shot API */
    ret = wc_Sha256Hash_ex((const uint8_t*)img->addr, (word32)img->size, hash,
                           NULL, context->server->devId);
#endif
    if (ret != 0) {
        wc_FreeRsaKey(&rsaKey);
        return ret;
    }

    /* Verify the signature using RSA SSL verify */
    ret =
        wc_RsaSSL_Verify(sig, (word32)sigSz, decrypted, decryptedLen, &rsaKey);
    if (ret < 0) {
        wc_FreeRsaKey(&rsaKey);
        return ret;
    }
    decryptedLen = (word32)ret;

    /* Compare the decrypted hash with computed hash */
    if (decryptedLen != sizeof(hash) ||
        XMEMCMP(decrypted, hash, sizeof(hash)) != 0) {
        wc_FreeRsaKey(&rsaKey);
        return WH_ERROR_NOTVERIFIED; /* RSA verification failed */
    }

    /* Cleanup */
    wc_FreeRsaKey(&rsaKey);

    return WH_ERROR_OK; /* RSA verification succeeded */
}
#endif /* !NO_RSA */

#ifndef NO_RSA

/**
 * Find a TLV field in a wolfBoot image header.
 * Scans from hdr + WH_IMG_MGR_WOLFBOOT_HDR_OFFSET, reads type (uint16 LE)
 * + len (uint16 LE), skips padding (0xFF), and returns the length field of the
 * TLV, or 0 if not found or invalid input.
 *
 * NOTE: Code lifted directly from wolfBoot. Should remain as unmodified as
 * possible for easy diffs
 */
static uint16_t _wolfBootImgFindHeaderField(const uint8_t* hdr, size_t hdrSize,
                                            uint16_t type, const uint8_t** ptr)
{
    const uint8_t* p     = hdr + WH_IMG_MGR_WOLFBOOT_HDR_OFFSET;
    const uint8_t* max_p = hdr + hdrSize;
    uint16_t       htype;
    uint16_t       len;

    *ptr = NULL;

    if (p > max_p) {
        return 0;
    }

    while ((p + 4) < max_p) {
        htype = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
        if (htype == 0) {
            break;
        }

        /* Skip padding bytes and alignment */
        if ((p[0] == WH_IMG_MGR_WOLFBOOT_HDR_PADDING) ||
            ((((uintptr_t)p) & 0x01) != 0)) {
            p++;
            continue;
        }

        len = (uint16_t)((uint16_t)p[2] | ((uint16_t)p[3] << 8));

        /* Sanity: field must fit in header */
        if ((size_t)(4 + len) > (hdrSize - WH_IMG_MGR_WOLFBOOT_HDR_OFFSET)) {
            break;
        }
        if (p + 4 + len > max_p) {
            break;
        }

        /* Advance past type+len to value */
        p += 4;

        if (htype == type) {
            *ptr = p;
            return len;
        }

        p += len;
    }
    return 0;
}

/**
 * Compute SHA256 hash over header (up to the hash TLV) + firmware payload.
 * Hashes header bytes [0 .. stored_sha_ptr - 4) then firmware bytes.
 */
static int _wolfBootImgHashSha256(const uint8_t* hdr,
                                  const uint8_t* stored_sha_ptr,
                                  const uint8_t* img, uint32_t img_size,
                                  uint8_t* hash_out, int devId)
{
    wc_Sha256      sha256_ctx;
    const uint8_t* end_sha;
    int            ret;
    const size_t   tlv_sz = 4;

    /* Hash the header from byte 0 up to the hash TLV's type+len fields
     * (i.e., exclude the TLV header: 2 bytes type + 2 bytes len = 4 bytes) */
    end_sha = stored_sha_ptr - tlv_sz;

    ret = wc_InitSha256_ex(&sha256_ctx, NULL, devId);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }

    /* Hash header portion */
    ret = wc_Sha256Update(&sha256_ctx, hdr, (word32)(end_sha - hdr));
    if (ret != 0) {
        wc_Sha256Free(&sha256_ctx);
        return WH_ERROR_ABORTED;
    }

    /* Hash firmware image */
    ret = wc_Sha256Update(&sha256_ctx, img, img_size);
    if (ret != 0) {
        wc_Sha256Free(&sha256_ctx);
        return WH_ERROR_ABORTED;
    }

    ret = wc_Sha256Final(&sha256_ctx, hash_out);
    wc_Sha256Free(&sha256_ctx);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }
    return WH_ERROR_OK;
}

/*
 * Decodes raw tag from ASN.1 DER
 *
 * NOTE: Code lifted directly from wolfBoot. Should remain as unmodified as
 * possible for easy diffs
 */
static int _wolfBootImgDecodeAsn1Tag(const uint8_t* input, int inputSz,
                                     int* inOutIdx, int* tag_len, uint8_t tag)
{
    /* Need at least 2 bytes from current index: tag + length */
    if (*inOutIdx + 2 > inputSz) {
        return -1;
    }
    if (input[*inOutIdx] != tag) {
        return -1;
    }
    (*inOutIdx)++;
    *tag_len = input[*inOutIdx];
    (*inOutIdx)++;
    if (*tag_len + *inOutIdx > inputSz) {
        return -1;
    }
    return 0;
}

/**
 * Decode ASN.1 DigestInfo wrapper from RSA PKCS#1 v1.5 signature.
 * Returns digest length on success, -1 on parse error.
 *
 * NOTE: Code lifted directly from wolfBoot. Should remain as unmodified as
 * possible for easy diffs
 */
static int _wolfBootImgDecodeRsaDigestInfo(uint8_t** pInput, int inputSz)
{
/* ASN.1 constants for DigestInfo decoding */
#define _IMGMGR_ASN_SEQUENCE 0x30
#define _IMGMGR_ASN_OCTET_STRING 0x04

    uint8_t* input = *pInput;
    int      idx   = 0;
    int      digest_len;
    int      algo_len;
    int      tot_len;

    /* SEQUENCE - total size */
    if (_wolfBootImgDecodeAsn1Tag(input, inputSz, &idx, &tot_len,
                                  _IMGMGR_ASN_SEQUENCE) != 0) {
        return -1;
    }

    /* SEQUENCE - algoid */
    if (_wolfBootImgDecodeAsn1Tag(input, inputSz, &idx, &algo_len,
                                  _IMGMGR_ASN_SEQUENCE) != 0) {
        return -1;
    }
    idx += algo_len; /* skip algoid */

    /* OCTET STRING - digest */
    if (_wolfBootImgDecodeAsn1Tag(input, inputSz, &idx, &digest_len,
                                  _IMGMGR_ASN_OCTET_STRING) != 0) {
        return -1;
    }

    /* Return pointer to digest data */
    *pInput = &input[idx];
    return digest_len;
}

/**
 * Verify RSA4096 signature against a hash using PKCS#1 v1.5.
 */
static int _wolfBootImgVerifySigRsa4096(const uint8_t* sig, uint16_t sigSz,
                                        const uint8_t* hash, uint32_t hashSz,
                                        const uint8_t* pubkey,
                                        uint32_t pubkeySz, int devId)
{
    int      ret;
    RsaKey   rsa;
    uint8_t  output[512]; /* RSA4096_SIG_SIZE */
    uint8_t* digest_out = NULL;
    word32   inOutIdx   = 0;

    if (sigSz != 512) {
        return WH_ERROR_BADARGS;
    }

    ret = wc_InitRsaKey_ex(&rsa, NULL, devId);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }

    ret = wc_RsaPublicKeyDecode(pubkey, &inOutIdx, &rsa, pubkeySz);
    if (ret < 0) {
        wc_FreeRsaKey(&rsa);
        return WH_ERROR_ABORTED;
    }

    memcpy(output, sig, 512);
    ret = wc_RsaSSL_VerifyInline(output, 512, &digest_out, &rsa);
    wc_FreeRsaKey(&rsa);

    if (ret < 0 || digest_out == NULL) {
        return WH_ERROR_NOTVERIFIED;
    }

    /* If result is larger than the hash, it contains ASN.1 DigestInfo */
    if (ret > (int)hashSz) {
        ret = _wolfBootImgDecodeRsaDigestInfo(&digest_out, ret);
        if (ret < 0) {
            return WH_ERROR_NOTVERIFIED;
        }
    }

    if (ret != (int)hashSz) {
        return WH_ERROR_NOTVERIFIED;
    }

    if (memcmp(digest_out, hash, hashSz) != 0) {
        return WH_ERROR_NOTVERIFIED;
    }

    return WH_ERROR_OK;
}


/**
 * Verify that a public key matches the hint stored in the wolfBoot header.
 * The hint is SHA256(pubkey).
 *
 * NOTE: Code lifted directly from wolfBoot. Should remain as unmodified as
 * possible for easy diffs
 */
static int _wolfBootImgVerifyPubKeyHint(const uint8_t* pubkey,
                                        uint32_t pubkeySz, const uint8_t* hint,
                                        uint16_t hintSz, int devId)
{
    wc_Sha256 sha256_ctx;
    uint8_t   key_hash[WC_SHA256_DIGEST_SIZE];
    int       ret;

    if (hintSz != WC_SHA256_DIGEST_SIZE) {
        return WH_ERROR_NOTVERIFIED;
    }

    ret = wc_InitSha256_ex(&sha256_ctx, NULL, devId);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }

    ret = wc_Sha256Update(&sha256_ctx, pubkey, pubkeySz);
    if (ret != 0) {
        wc_Sha256Free(&sha256_ctx);
        return WH_ERROR_ABORTED;
    }

    ret = wc_Sha256Final(&sha256_ctx, key_hash);
    wc_Sha256Free(&sha256_ctx);
    if (ret != 0) {
        return WH_ERROR_ABORTED;
    }

    if (memcmp(key_hash, hint, WC_SHA256_DIGEST_SIZE) != 0) {
        return WH_ERROR_NOTVERIFIED;
    }

    return WH_ERROR_OK;
}

/* Decode a 32-bit little-endian value from raw header bytes. The wolfBoot
 * image format is little-endian by spec; using explicit byte assembly keeps
 * this correct on both LE and BE hosts. */
static uint32_t _wolfBootImgReadLE32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

#ifdef WOLFHSM_CFG_DMA
/* Peek magic and the header-declared image size from a wolfBoot header. Used
 * before mapping the payload via DMA so the mapped region matches the real
 * image length rather than the caller-provided max buffer size. */
static int _wolfBootImgPeekImgSize(const uint8_t* hdr, size_t hdrSize,
                                   uint32_t* img_size_out)
{
    uint32_t magic;

    if (hdr == NULL || img_size_out == NULL) {
        return WH_ERROR_BADARGS;
    }
    if (((uintptr_t)hdr & 0x01) != 0) {
        return WH_ERROR_BADARGS;
    }
    if (hdrSize < WH_IMG_MGR_WOLFBOOT_HDR_OFFSET) {
        return WH_ERROR_BADARGS;
    }

    magic = _wolfBootImgReadLE32(hdr);
    if (magic != WH_IMG_MGR_WOLFBOOT_MAGIC) {
        return WH_ERROR_NOTVERIFIED;
    }

    *img_size_out = _wolfBootImgReadLE32(hdr + 4);
    return WH_ERROR_OK;
}
#endif /* WOLFHSM_CFG_DMA */

/**
 * Common wolfBoot header validation and hash computation.
 * Validates that the header is large enough for the fixed fields, and that
 * the header-declared image size does not exceed the supplied payload buffer.
 * Returns WH_ERROR_OK on success and populates computed_hash.
 * On success, sig_out and sig_sz_out point to the signature in the header.
 */
static int _wolfBootImgValidateAndHash(const uint8_t* hdr, size_t hdrSize,
                                       const uint8_t*  payload,
                                       size_t          payloadSize,
                                       uint8_t*        computed_hash,
                                       const uint8_t** sig_out,
                                       uint16_t* sig_sz_out, int devId)
{
    uint32_t       magic;
    uint32_t       img_size;
    const uint8_t* image_type_buf;
    uint16_t       image_type_size;
    uint16_t       image_type;
    uint8_t        auth_type;
    const uint8_t* stored_sha;
    uint16_t       stored_sha_len;
    const uint8_t* sig;
    uint16_t       sig_size;
    int            ret;

    if (hdr == NULL || payload == NULL || computed_hash == NULL ||
        sig_out == NULL || sig_sz_out == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Header must be even address for 2-byte alignment */
    if (((uintptr_t)hdr & 0x01) != 0) {
        return WH_ERROR_BADARGS;
    }

    /* Header must be large enough for magic (4 bytes) + img_size (4 bytes) +
     * at least one TLV header (type+len = 4 bytes). The +4 is required so
     * _wolfBootImgFindHeaderField's `p + 4` pointer arithmetic stays within
     * (or one-past) the buffer bounds (avoids UB for sub-12-byte headers). */
    if (hdrSize < WH_IMG_MGR_WOLFBOOT_HDR_OFFSET + 4) {
        return WH_ERROR_BADARGS;
    }

    /* Validate magic (wolfBoot format is little-endian) */
    magic = _wolfBootImgReadLE32(hdr);
    if (magic != WH_IMG_MGR_WOLFBOOT_MAGIC) {
        return WH_ERROR_NOTVERIFIED;
    }

    /* Read image size from header (this field is covered by the signature) */
    img_size = _wolfBootImgReadLE32(hdr + 4);

    /* Ensure header-declared image size doesn't exceed supplied payload */
    if ((size_t)img_size > payloadSize) {
        return WH_ERROR_BADARGS;
    }

    /* Parse HDR_IMG_TYPE to verify auth algorithm */
    image_type_size = _wolfBootImgFindHeaderField(
        hdr, hdrSize, WH_IMG_MGR_WOLFBOOT_HDR_IMG_TYPE, &image_type_buf);
    if (image_type_size != sizeof(uint16_t)) {
        return WH_ERROR_NOTVERIFIED;
    }
    image_type = (uint16_t)((uint16_t)image_type_buf[0] |
                            ((uint16_t)image_type_buf[1] << 8));
    auth_type =
        (uint8_t)((image_type & WH_IMG_MGR_WOLFBOOT_HDR_IMG_TYPE_AUTH_MASK) >>
                  8);
    if (auth_type != WH_IMG_MGR_WOLFBOOT_AUTH_RSA4096) {
        return WH_ERROR_NOTVERIFIED;
    }

    /* Parse HDR_SHA256 to get stored hash and its position */
    stored_sha_len = _wolfBootImgFindHeaderField(
        hdr, hdrSize, WH_IMG_MGR_WOLFBOOT_HDR_SHA256, &stored_sha);
    if (stored_sha_len != WC_SHA256_DIGEST_SIZE) {
        return WH_ERROR_NOTVERIFIED;
    }

    /* Compute hash over (header up to hash TLV boundary) + firmware */
    ret = _wolfBootImgHashSha256(hdr, stored_sha, payload, img_size,
                                 computed_hash, devId);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Compare computed hash with stored hash */
    if (memcmp(computed_hash, stored_sha, WC_SHA256_DIGEST_SIZE) != 0) {
        return WH_ERROR_NOTVERIFIED;
    }

    /* Parse HDR_SIGNATURE */
    sig_size = _wolfBootImgFindHeaderField(
        hdr, hdrSize, WH_IMG_MGR_WOLFBOOT_HDR_SIGNATURE, &sig);
    if (sig_size == 0 || sig == NULL) {
        return WH_ERROR_NOTVERIFIED;
    }

    *sig_out    = sig;
    *sig_sz_out = sig_size;

    return WH_ERROR_OK;
}


int wh_Server_ImgMgrVerifyMethodWolfBootRsa4096WithSha256(
    whServerImgMgrContext* context, const whServerImgMgrImg* img,
    const uint8_t* key, size_t keySz, const uint8_t* sig, size_t sigSz)
{
    int              ret;
    uint8_t          computed_hash[WC_SHA256_DIGEST_SIZE];
    const uint8_t*   hdr;
    const uint8_t*   payload;
    const uint8_t*   hdr_sig;
    uint16_t         hdr_sig_sz;
    const uint8_t*   pubkey_hint;
    uint16_t         pubkey_hint_size;
    size_t           payloadSize;
    whServerContext* server;
    int              devId;
#ifdef WOLFHSM_CFG_DMA
    void*    serverHdrPtr     = NULL;
    void*    serverPayloadPtr = NULL;
    uint32_t peekedImgSize    = 0;
    int      payloadMapped    = 0;
#endif

    (void)sig;
    (void)sigSz;

    if (context == NULL || context->server == NULL || img == NULL ||
        key == NULL || keySz == 0) {
        return WH_ERROR_BADARGS;
    }

    server = context->server;
    devId  = server->devId;

#ifdef WOLFHSM_CFG_DMA
    /* DMA pre-process header */
    ret = wh_Server_DmaProcessClientAddress(
        server, img->hdrAddr, &serverHdrPtr, img->hdrSize,
        WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    hdr = (const uint8_t*)serverHdrPtr;

    /* Peek header-declared image size so we map only what's needed. Bound
     * it by img->size (documented as max payload buffer) to reject a header
     * that claims more than the caller provided. */
    ret = _wolfBootImgPeekImgSize(hdr, img->hdrSize, &peekedImgSize);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }
    if ((size_t)peekedImgSize > img->size) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }
    payloadSize = (size_t)peekedImgSize;

    /* DMA pre-process payload using the actual image size */
    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPayloadPtr, payloadSize,
        WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }
    payloadMapped = 1;
    payload       = (const uint8_t*)serverPayloadPtr;
#else
    hdr         = (const uint8_t*)img->hdrAddr;
    payload     = (const uint8_t*)img->addr;
    payloadSize = img->size;
#endif

    /* Validate header, compute and verify hash, extract signature */
    ret = _wolfBootImgValidateAndHash(hdr, img->hdrSize, payload, payloadSize,
                                      computed_hash, &hdr_sig, &hdr_sig_sz,
                                      devId);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* Verify pubkey hint matches provided key */
    pubkey_hint_size = _wolfBootImgFindHeaderField(
        hdr, img->hdrSize, WH_IMG_MGR_WOLFBOOT_HDR_PUBKEY, &pubkey_hint);
    ret = _wolfBootImgVerifyPubKeyHint(key, (uint32_t)keySz, pubkey_hint,
                                       pubkey_hint_size, devId);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* Verify RSA4096 signature */
    ret = _wolfBootImgVerifySigRsa4096(hdr_sig, hdr_sig_sz, computed_hash,
                                       WC_SHA256_DIGEST_SIZE, key,
                                       (uint32_t)keySz, devId);

cleanup:
#ifdef WOLFHSM_CFG_DMA
    if (payloadMapped) {
        (void)wh_Server_DmaProcessClientAddress(
            server, img->addr, &serverPayloadPtr, payloadSize,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }
    (void)wh_Server_DmaProcessClientAddress(
        server, img->hdrAddr, &serverHdrPtr, img->hdrSize,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
#endif
    return ret;
}

#ifdef WOLFHSM_CFG_CERTIFICATE_MANAGER
int wh_Server_ImgMgrVerifyMethodWolfBootCertChainRsa4096WithSha256(
    whServerImgMgrContext* context, const whServerImgMgrImg* img,
    const uint8_t* key, size_t keySz, const uint8_t* sig, size_t sigSz)
{
    int              ret;
    uint8_t          computed_hash[WC_SHA256_DIGEST_SIZE];
    const uint8_t*   hdr;
    const uint8_t*   payload;
    const uint8_t*   hdr_sig;
    uint16_t         hdr_sig_sz;
    const uint8_t*   cert_chain;
    uint16_t         cert_chain_len;
    const uint8_t*   pubkey_hint;
    uint16_t         pubkey_hint_size;
    size_t           payloadSize;
    whKeyId          leafKeyId   = WH_KEYID_ERASED;
    uint8_t*         leafKeyBuf  = NULL;
    whNvmMetadata*   leafKeyMeta = NULL;
    whServerContext* server;
    int              devId;
#ifdef WOLFHSM_CFG_DMA
    void*    serverHdrPtr     = NULL;
    void*    serverPayloadPtr = NULL;
    uint32_t peekedImgSize    = 0;
    int      payloadMapped    = 0;
#endif

    (void)key;
    (void)keySz;
    (void)sig;
    (void)sigSz;

    if (context == NULL || img == NULL) {
        return WH_ERROR_BADARGS;
    }

    server = context->server;
    if (server == NULL) {
        return WH_ERROR_BADARGS;
    }
    devId = server->devId;

#ifdef WOLFHSM_CFG_DMA
    /* DMA pre-process header */
    ret = wh_Server_DmaProcessClientAddress(
        server, img->hdrAddr, &serverHdrPtr, img->hdrSize,
        WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    hdr = (const uint8_t*)serverHdrPtr;

    /* Peek header-declared image size so we map only what's needed. Bound
     * it by img->size (documented as max payload buffer) to reject a header
     * that claims more than the caller provided. */
    ret = _wolfBootImgPeekImgSize(hdr, img->hdrSize, &peekedImgSize);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }
    if ((size_t)peekedImgSize > img->size) {
        ret = WH_ERROR_BADARGS;
        goto cleanup;
    }
    payloadSize = (size_t)peekedImgSize;

    /* DMA pre-process payload using the actual image size */
    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPayloadPtr, payloadSize,
        WH_DMA_OPER_CLIENT_READ_PRE, (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }
    payloadMapped = 1;
    payload       = (const uint8_t*)serverPayloadPtr;
#else
    hdr         = (const uint8_t*)img->hdrAddr;
    payload     = (const uint8_t*)img->addr;
    payloadSize = img->size;
#endif

    /* Validate header, compute and verify hash, extract signature */
    ret = _wolfBootImgValidateAndHash(hdr, img->hdrSize, payload, payloadSize,
                                      computed_hash, &hdr_sig, &hdr_sig_sz,
                                      devId);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* Parse cert chain from header */
    cert_chain_len = _wolfBootImgFindHeaderField(
        hdr, img->hdrSize, WH_IMG_MGR_WOLFBOOT_HDR_CERT_CHAIN, &cert_chain);
    if (cert_chain_len == 0 || cert_chain == NULL) {
        ret = WH_ERROR_NOTVERIFIED;
        goto cleanup;
    }

    /* Verify cert chain against root CA and cache the leaf pubkey */
    ret = wh_Server_CertVerify(server, cert_chain, cert_chain_len,
                               img->sigNvmId, WH_CERT_FLAGS_CACHE_LEAF_PUBKEY,
                               WH_NVM_FLAGS_USAGE_VERIFY, &leafKeyId);
    if (ret != WH_ERROR_OK) {
        goto cleanup;
    }

    /* Load leaf pubkey from keystore */
    ret = wh_Server_KeystoreFreshenKey(server, leafKeyId, &leafKeyBuf,
                                       &leafKeyMeta);
    if (ret != WH_ERROR_OK) {
        goto evict_cleanup;
    }

    /* Verify pubkey hint matches leaf key */
    pubkey_hint_size = _wolfBootImgFindHeaderField(
        hdr, img->hdrSize, WH_IMG_MGR_WOLFBOOT_HDR_PUBKEY, &pubkey_hint);
    ret = _wolfBootImgVerifyPubKeyHint(leafKeyBuf, leafKeyMeta->len,
                                       pubkey_hint, pubkey_hint_size, devId);
    if (ret != WH_ERROR_OK) {
        goto evict_cleanup;
    }

    /* Verify RSA4096 signature using leaf pubkey */
    ret = _wolfBootImgVerifySigRsa4096(hdr_sig, hdr_sig_sz, computed_hash,
                                       WC_SHA256_DIGEST_SIZE, leafKeyBuf,
                                       leafKeyMeta->len, devId);

evict_cleanup:
    /* Evict cached leaf key */
    (void)wh_Server_KeystoreEvictKey(server, leafKeyId);

cleanup:
#ifdef WOLFHSM_CFG_DMA
    if (payloadMapped) {
        (void)wh_Server_DmaProcessClientAddress(
            server, img->addr, &serverPayloadPtr, payloadSize,
            WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
    }
    (void)wh_Server_DmaProcessClientAddress(
        server, img->hdrAddr, &serverHdrPtr, img->hdrSize,
        WH_DMA_OPER_CLIENT_READ_POST, (whServerDmaFlags){0});
#endif
    return ret;
}
#endif /* WOLFHSM_CFG_CERTIFICATE_MANAGER */

#endif /* !NO_RSA */
#endif /* !WOLFHSM_CFG_NO_CRYPTO */

int wh_Server_ImgMgrVerifyActionDefault(whServerImgMgrContext*   context,
                                        const whServerImgMgrImg* img,
                                        int                      verifyResult)
{
    (void)context; /* Unused parameter */
    (void)img;     /* Unused parameter */

    /* Default action: simply return the verification result */
    return verifyResult;
}

#endif /* WOLFHSM_CFG_SERVER_IMG_MGR && WOLFHSM_CFG_ENABLE_SERVER && \
          !WOLFHSM_CFG_NO_CRYPTO */
