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
 * wolfhsm/wh_server_img_mgr.h
 *
 */

#ifndef WOLFHSM_WH_SERVER_IMG_MGR_H_
#define WOLFHSM_WH_SERVER_IMG_MGR_H_

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_SERVER_IMG_MGR

#include <stdint.h>
#include <stddef.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_server.h"

/* Forward declaration for callback function signatures */
typedef struct whServerImgMgrContext_t whServerImgMgrContext;

/* Forward declare so the callbacks can reference the parent struct */
struct whServerImgMgrImg;

/**
 * @brief Image verification method callback
 *
 * This callback performs the actual cryptographic verification of an image.
 * It receives the image metadata, key data, and signature data, and returns
 * the verification result.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure containing verification parameters
 * @param[in] key Key data for verification
 * @param[in] keySz Size of key data
 * @param[in] sig Signature data for verification
 * @param[in] sigSz Size of signature data
 * @return 0 on successful verification, negative error code on failure
 */
typedef int (*whServerImgMgrVerifyMethod)(whServerImgMgrContext* context,
                                          const struct whServerImgMgrImg* img,
                                          const uint8_t* key, size_t keySz,
                                          const uint8_t* sig, size_t sigSz);

/**
 * @brief Image verification action callback
 *
 * This callback is invoked after the verification method completes.
 * It receives the verification result and can perform actions based on
 * whether the verification succeeded or failed.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure containing verification parameters
 * @param[in] verifyResult Result from the verification method
 * @return 0 on success, negative error code on failure
 */
typedef int (*whServerImgMgrVerifyAction)(whServerImgMgrContext* context,
                                          const struct whServerImgMgrImg* img,
                                          int verifyResult);

/*
 * @brief Image structure for verification
 *
 * This structure defines an image to be verified, including its location,
 * the key and signature identifiers, and the callbacks for verification
 * and post-verification actions.
 */
typedef struct whServerImgMgrImg {
    uintptr_t                  addr;         /* Image address */
    size_t                     size;         /* Image size */
    whKeyId                    keyId;        /* Key ID for verification */
    whNvmId                    sigNvmId;     /* NVM ID for signature */
    whServerImgMgrVerifyMethod verifyMethod; /* Verification callback */
    whServerImgMgrVerifyAction verifyAction; /* Post-verification action */
} whServerImgMgrImg;

/*
 * @brief Image manager configuration structure
 *
 * Configuration structure passed to the image manager during initialization.
 * Contains the list of images to manage and their count.
 */
typedef struct whServerImgMgrConfig {
    whServerImgMgrImg* images;     /* Pointer to array of images */
    size_t             imageCount; /* Number of images in array */
    whServerContext*   server;     /* Server context for NVM/DMA access */
} whServerImgMgrConfig;

/*
 * @brief Image verification result structure
 *
 * Structure containing detailed results from image verification operations.
 * Provides separate access to verification method and action results.
 */
typedef struct whServerImgMgrVerifyResult {
    int verifyMethodResult; /* Result from the verification method callback */
    int verifyActionResult; /* Result from the verification action callback */
} whServerImgMgrVerifyResult;

/*
 * @brief Image manager context structure
 *
 * Context structure that maintains the state of the image manager.
 * This is embedded in the main server context.
 */
struct whServerImgMgrContext_t {
    whServerImgMgrImg images[WOLFHSM_CFG_SERVER_IMG_MGR_MAX_IMG_COUNT];
    size_t            imageCount;
    whServerContext*  server; /* Server context for NVM/DMA access */
};

/**
 * @brief Initialize the image manager
 *
 * Initializes the image manager context with the provided configuration.
 * Registers the list of images to be managed.
 *
 * @param[in] context Image manager context to initialize
 * @param[in] config Configuration containing image list
 * @return 0 on success, negative error code on failure
 */
int wh_Server_ImgMgrInit(whServerImgMgrContext*      context,
                         const whServerImgMgrConfig* config);

/**
 * @brief Verify all registered images
 *
 * Iterates through all registered images and verifies each one.
 * Calls the verification method and action callbacks for each image.
 * Populates detailed verification results for each image.
 *
 * @param[in] context Image manager context
 * @param[out] outResults Array to store verification results for each image
 * @param[in] outResultsSize Size of the results array (must be >=
 * context->imageCount)
 * @return 0 on success, negative error code on failure
 */
int wh_Server_ImgMgrVerifyAll(whServerImgMgrContext*      context,
                              whServerImgMgrVerifyResult* outResults,
                              size_t                      outResultsSize);

/**
 * @brief Verify an image by reference
 *
 * Verifies a specific image by direct reference to its structure.
 * Performs DMA operations, key loading, and signature verification.
 * Populates detailed verification results.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure to verify
 * @param[out] outResult Verification result structure to populate
 * @return 0 on success, negative error code on failure
 */
int wh_Server_ImgMgrVerifyImg(whServerImgMgrContext*      context,
                              const whServerImgMgrImg*    img,
                              whServerImgMgrVerifyResult* outResult);

/**
 * @brief Verify an image by index
 *
 * Verifies a specific image by its index in the registered image array.
 * Populates detailed verification results.
 *
 * @param[in] context Image manager context
 * @param[in] imgIdx Index of image to verify
 * @param[out] outResult Verification result structure to populate
 * @return 0 on success, negative error code on failure
 */
int wh_Server_ImgMgrVerifyImgIdx(whServerImgMgrContext* context, size_t imgIdx,
                                 whServerImgMgrVerifyResult* outResult);

/* Built-in verification method callbacks */

/**
 * @brief Default ECC P256 verification method
 *
 * Default implementation of image verification using ECC P256 signatures.
 * Uses wolfCrypt to hash the image data and verify the signature.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure containing verification parameters
 * @param[in] key ECC public key data
 * @param[in] keySz Size of key data
 * @param[in] sig Signature data
 * @param[in] sigSz Size of signature data
 * @return 0 on successful verification, negative error code on failure
 */
int wh_Server_ImgMgrVerifyMethodEccWithSha256(whServerImgMgrContext*   context,
                                              const whServerImgMgrImg* img,
                                              const uint8_t* key, size_t keySz,
                                              const uint8_t* sig, size_t sigSz);

/**
 * @brief AES128 CMAC verification method
 *
 * Implementation of image verification using AES128 CMAC.
 * Uses wolfCrypt to compute CMAC of the image data and compare with signature.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure containing verification parameters
 * @param[in] key AES128 key data (16 bytes)
 * @param[in] keySz Size of key data (must be 16)
 * @param[in] sig CMAC signature data (16 bytes)
 * @param[in] sigSz Size of signature data (must be 16)
 * @return 0 on successful verification, negative error code on failure
 */
int wh_Server_ImgMgrVerifyMethodAesCmac(whServerImgMgrContext*   context,
                                        const whServerImgMgrImg* img,
                                        const uint8_t* key, size_t keySz,
                                        const uint8_t* sig, size_t sigSz);

/**
 * @brief RSA2048 signature verification method
 *
 * Implementation of image verification using RSA2048 signatures.
 * Uses wolfCrypt wc_RsaSSL_Verify to verify RSA signatures against SHA256 hash.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure containing verification parameters
 * @param[in] key RSA public key data (DER format)
 * @param[in] keySz Size of key data
 * @param[in] sig RSA signature data
 * @param[in] sigSz Size of signature data
 * @return 0 on successful verification, negative error code on failure
 */
int wh_Server_ImgMgrVerifyMethodRsaSslWithSha256(
    whServerImgMgrContext* context, const whServerImgMgrImg* img,
    const uint8_t* key, size_t keySz, const uint8_t* sig, size_t sigSz);

/**
 * @brief Default verification action callback
 *
 * Default implementation of post-verification action. Simply returns
 * the verification result without performing additional actions.
 *
 * @param[in] context Image manager context
 * @param[in] img Image structure containing verification parameters
 * @param[in] verifyResult Result from the verification method
 * @return verifyResult (passes through the verification result)
 */
int wh_Server_ImgMgrVerifyActionDefault(whServerImgMgrContext*   context,
                                        const whServerImgMgrImg* img,
                                        int                      verifyResult);

#endif /* WOLFHSM_CFG_SERVER_IMG_MGR */

#endif /* !WOLFHSM_WH_SERVER_IMG_MGR_H_ */