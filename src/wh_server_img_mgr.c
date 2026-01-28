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
#include "wolfhsm/wh_nvm.h"
#include "wolfhsm/wh_nvm_internal.h"

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

/* Helper functions for NVM locking */
#ifdef WOLFHSM_CFG_THREADSAFE
static int _LockNvm(whServerContext* server)
{
    if (server->nvm != NULL) {
        return wh_Lock_Acquire(&server->nvm->lock);
    }
    return WH_ERROR_OK;
}

static int _UnlockNvm(whServerContext* server)
{
    if (server->nvm != NULL) {
        return wh_Lock_Release(&server->nvm->lock);
    }
    return WH_ERROR_OK;
}
#else
#define _LockNvm(server) (WH_ERROR_OK)
#define _UnlockNvm(server) (WH_ERROR_OK)
#endif /* WOLFHSM_CFG_THREADSAFE */

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

int wh_Server_ImgMgrVerifyImg(whServerImgMgrContext*      context,
                              const whServerImgMgrImg*    img,
                              whServerImgMgrVerifyResult* result)
{
    int              ret     = WH_ERROR_OK;
    whServerContext* server  = NULL;
    uint8_t*         keyBuf  = NULL;
    whNvmMetadata*   keyMeta = NULL;
    uint8_t sigBuf[WOLFHSM_CFG_SERVER_IMG_MGR_MAX_SIG_SIZE]; /* Buffer for
                                                                signature */
    whNvmMetadata sigMeta       = {0};
    uint32_t      sigSize       = sizeof(sigBuf);
    whNvmSize     actualSigSize = 0;

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

    /* Load the key into the cache */
    ret = wh_Server_KeystoreFreshenKey(server, img->keyId, &keyBuf, &keyMeta);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Load the signature from NVM */
    /* Acquire lock for atomic GetMetadata + Read */
    ret = _LockNvm(server);
    if (ret == WH_ERROR_OK) {
        ret = wh_Nvm_GetMetadataUnlocked(server->nvm, img->sigNvmId, &sigMeta);
        if (ret == WH_ERROR_OK) {
            /* Ensure signature fits in buffer */
            if (sigMeta.len > sigSize) {
                ret = WH_ERROR_BADARGS;
            }
            else {
                ret = wh_Nvm_ReadUnlocked(server->nvm, img->sigNvmId, 0,
                                          sigMeta.len, sigBuf);
                if (ret == WH_ERROR_OK) {
                    actualSigSize = sigMeta.len;
                }
            }
        }
        (void)_UnlockNvm(server);
    }
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    /* Invoke verify method callback */
    if (img->verifyMethod != NULL) {
        result->verifyMethodResult = img->verifyMethod(
            context, img, keyBuf, keyMeta->len, sigBuf, actualSigSize);
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

    (void)context; /* Unused parameter */

    if (img == NULL || key == NULL || sig == NULL || keySz == 0 || sigSz == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize ECC key */
    ret = wc_ecc_init(&eccKey);
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
                           NULL, server->crypto->devId);
#else
    /* Hash the image data using one-shot API */
    ret = wc_Sha256Hash_ex((const uint8_t*)img->addr, (word32)img->size, hash,
                           NULL, context->server->crypto->devId);
#endif
    if (ret != 0) {
        wc_ecc_free(&eccKey);
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPtr, img->size, WH_DMA_OPER_CLIENT_READ_POST,
        (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        wc_ecc_free(&eccKey);
        return ret;
    }
#endif

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

    (void)context; /* Unused parameter */

    if (img == NULL || key == NULL || sig == NULL) {
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
                              server->crypto->devId);
#else
    ret = wc_AesCmacVerify_ex(&cmac, sig, (word32)sigSz, (const byte*)img->addr,
                              (word32)img->size, key, (word32)keySz, NULL,
                              context->server->crypto->devId);
#endif
    if (ret != 0) {
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPtr, img->size, WH_DMA_OPER_CLIENT_READ_POST,
        (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        return ret;
    }
#endif

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

    (void)context; /* Unused parameter */

    if (img == NULL || key == NULL || sig == NULL || keySz == 0 || sigSz == 0) {
        return WH_ERROR_BADARGS;
    }

    /* Initialize RSA key */
    ret = wc_InitRsaKey(&rsaKey, NULL);
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
                           NULL, server->crypto->devId);
#else
    /* Hash the image data using one-shot API */
    ret = wc_Sha256Hash_ex((const uint8_t*)img->addr, (word32)img->size, hash,
                           NULL, context->server->crypto->devId);
#endif
    if (ret != 0) {
        wc_FreeRsaKey(&rsaKey);
        return ret;
    }

#ifdef WOLFHSM_CFG_DMA
    ret = wh_Server_DmaProcessClientAddress(
        server, img->addr, &serverPtr, img->size, WH_DMA_OPER_CLIENT_READ_POST,
        (whServerDmaFlags){0});
    if (ret != WH_ERROR_OK) {
        wc_FreeRsaKey(&rsaKey);
        return ret;
    }
#endif

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
