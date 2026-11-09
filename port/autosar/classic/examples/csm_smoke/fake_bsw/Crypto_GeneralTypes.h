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
 * Minimal AUTOSAR CP R22-11 Crypto_GeneralTypes.h for the csm_smoke
 * harness. Real projects use the header from their BSW vendor.
 */

#ifndef CRYPTO_GENERALTYPES_H_
#define CRYPTO_GENERALTYPES_H_

#include "Std_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8 Crypto_ResultType;
#define CRYPTO_E_BUSY ((Crypto_ResultType)0x02u)
#define CRYPTO_E_ENTROPY_EXHAUSTED ((Crypto_ResultType)0x04u)
#define CRYPTO_E_KEY_READ_FAIL ((Crypto_ResultType)0x06u)
#define CRYPTO_E_KEY_WRITE_FAIL ((Crypto_ResultType)0x07u)
#define CRYPTO_E_KEY_NOT_AVAILABLE ((Crypto_ResultType)0x08u)
#define CRYPTO_E_KEY_NOT_VALID ((Crypto_ResultType)0x09u)
#define CRYPTO_E_KEY_SIZE_MISMATCH ((Crypto_ResultType)0x0Au)
#define CRYPTO_E_JOB_CANCELED ((Crypto_ResultType)0x0Cu)
#define CRYPTO_E_KEY_EMPTY ((Crypto_ResultType)0x0Du)

typedef uint8 Crypto_VerifyResultType;
#define CRYPTO_E_VER_OK ((Crypto_VerifyResultType)0x00u)
#define CRYPTO_E_VER_NOT_OK ((Crypto_VerifyResultType)0x01u)

typedef uint8 Crypto_OperationModeType;
#define CRYPTO_OPERATIONMODE_START ((Crypto_OperationModeType)0x01u)
#define CRYPTO_OPERATIONMODE_UPDATE ((Crypto_OperationModeType)0x02u)
#define CRYPTO_OPERATIONMODE_STREAMSTART ((Crypto_OperationModeType)0x03u)
#define CRYPTO_OPERATIONMODE_FINISH ((Crypto_OperationModeType)0x04u)
#define CRYPTO_OPERATIONMODE_SINGLECALL ((Crypto_OperationModeType)0x07u)

typedef uint8 Crypto_JobStateType;
#define CRYPTO_JOBSTATE_IDLE ((Crypto_JobStateType)0x00u)
#define CRYPTO_JOBSTATE_ACTIVE ((Crypto_JobStateType)0x01u)

typedef uint8 Crypto_ProcessingType;
#define CRYPTO_PROCESSING_ASYNC ((Crypto_ProcessingType)0x00u)
#define CRYPTO_PROCESSING_SYNC ((Crypto_ProcessingType)0x01u)

typedef uint8 Crypto_ServiceInfoType;
#define CRYPTO_HASH ((Crypto_ServiceInfoType)0x00u)
#define CRYPTO_MACGENERATE ((Crypto_ServiceInfoType)0x01u)
#define CRYPTO_MACVERIFY ((Crypto_ServiceInfoType)0x02u)
#define CRYPTO_ENCRYPT ((Crypto_ServiceInfoType)0x03u)
#define CRYPTO_DECRYPT ((Crypto_ServiceInfoType)0x04u)
#define CRYPTO_AEADENCRYPT ((Crypto_ServiceInfoType)0x05u)
#define CRYPTO_AEADDECRYPT ((Crypto_ServiceInfoType)0x06u)
#define CRYPTO_SIGNATUREGENERATE ((Crypto_ServiceInfoType)0x07u)
#define CRYPTO_SIGNATUREVERIFY ((Crypto_ServiceInfoType)0x08u)
#define CRYPTO_RANDOMGENERATE ((Crypto_ServiceInfoType)0x0Bu)
#define CRYPTO_RANDOMSEED ((Crypto_ServiceInfoType)0x0Cu)
#define CRYPTO_KEYGENERATE ((Crypto_ServiceInfoType)0x0Du)
#define CRYPTO_KEYDERIVE ((Crypto_ServiceInfoType)0x0Eu)
#define CRYPTO_KEYEXCHANGECALCPUBVAL ((Crypto_ServiceInfoType)0x0Fu)
#define CRYPTO_KEYEXCHANGECALCSECRET ((Crypto_ServiceInfoType)0x10u)
#define CRYPTO_KEYSETVALID ((Crypto_ServiceInfoType)0x13u)
#define CRYPTO_KEYSETINVALID ((Crypto_ServiceInfoType)0x14u)
#define CRYPTO_CUSTOM_SERVICE ((Crypto_ServiceInfoType)0x15u)

typedef uint8 Crypto_AlgorithmFamilyType;
#define CRYPTO_ALGOFAM_NOT_SET ((Crypto_AlgorithmFamilyType)0x00u)
#define CRYPTO_ALGOFAM_SHA1 ((Crypto_AlgorithmFamilyType)0x01u)
#define CRYPTO_ALGOFAM_SHA2_224 ((Crypto_AlgorithmFamilyType)0x02u)
#define CRYPTO_ALGOFAM_SHA2_256 ((Crypto_AlgorithmFamilyType)0x03u)
#define CRYPTO_ALGOFAM_SHA2_384 ((Crypto_AlgorithmFamilyType)0x04u)
#define CRYPTO_ALGOFAM_SHA2_512 ((Crypto_AlgorithmFamilyType)0x05u)
#define CRYPTO_ALGOFAM_AES ((Crypto_AlgorithmFamilyType)0x14u)
#define CRYPTO_ALGOFAM_RSA ((Crypto_AlgorithmFamilyType)0x16u)
#define CRYPTO_ALGOFAM_ED25519 ((Crypto_AlgorithmFamilyType)0x17u)
#define CRYPTO_ALGOFAM_ECCNIST ((Crypto_AlgorithmFamilyType)0x19u)
#define CRYPTO_ALGOFAM_RNG ((Crypto_AlgorithmFamilyType)0x1Bu)
#define CRYPTO_ALGOFAM_HKDF ((Crypto_AlgorithmFamilyType)0x2Bu)
#define CRYPTO_ALGOFAM_ECDSA ((Crypto_AlgorithmFamilyType)0x2Cu)
#define CRYPTO_ALGOFAM_X25519 ((Crypto_AlgorithmFamilyType)0x2Eu)
#define CRYPTO_ALGOFAM_ECDH ((Crypto_AlgorithmFamilyType)0x2Fu)
#define CRYPTO_ALGOFAM_CUSTOM ((Crypto_AlgorithmFamilyType)0xFFu)

typedef uint8 Crypto_AlgorithmModeType;
#define CRYPTO_ALGOMODE_NOT_SET ((Crypto_AlgorithmModeType)0x00u)
#define CRYPTO_ALGOMODE_ECB ((Crypto_AlgorithmModeType)0x01u)
#define CRYPTO_ALGOMODE_CBC ((Crypto_AlgorithmModeType)0x02u)
#define CRYPTO_ALGOMODE_CTR ((Crypto_AlgorithmModeType)0x05u)
#define CRYPTO_ALGOMODE_GCM ((Crypto_AlgorithmModeType)0x06u)
#define CRYPTO_ALGOMODE_RSASSA_PSS ((Crypto_AlgorithmModeType)0x0Au)
#define CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5 ((Crypto_AlgorithmModeType)0x0Bu)
#define CRYPTO_ALGOMODE_HMAC ((Crypto_AlgorithmModeType)0x0Fu)
#define CRYPTO_ALGOMODE_CMAC ((Crypto_AlgorithmModeType)0x10u)
#define CRYPTO_ALGOMODE_GMAC ((Crypto_AlgorithmModeType)0x11u)
#define CRYPTO_ALGOMODE_CUSTOM ((Crypto_AlgorithmModeType)0xFFu)

typedef uint8 Crypto_KeyStatusType;
#define CRYPTO_KEYSTATUS_INVALID ((Crypto_KeyStatusType)0x00u)
#define CRYPTO_KEYSTATUS_VALID ((Crypto_KeyStatusType)0x01u)
#define CRYPTO_KEYSTATUS_UPDATE_IN_PROGRESS ((Crypto_KeyStatusType)0x02u)

typedef struct {
    Crypto_AlgorithmFamilyType family;
    Crypto_AlgorithmFamilyType secondaryFamily;
    uint32                     keyLength;
    Crypto_AlgorithmModeType   mode;
} Crypto_AlgorithmInfoType;

typedef struct {
    Crypto_ServiceInfoType   service;
    Crypto_AlgorithmInfoType algorithm;
} Crypto_PrimitiveInfoType;

typedef struct {
    uint32                          callbackId;
    const Crypto_PrimitiveInfoType* primitiveInfo;
    uint32                          cryIfKeyId;
    Crypto_ProcessingType           processingType;
} Crypto_JobPrimitiveInfoType;

typedef struct {
    uint8  redirectionConfig;
    uint32 inputKeyId;
    uint32 inputKeyElementId;
    uint32 secondaryInputKeyId;
    uint32 secondaryInputKeyElementId;
    uint32 tertiaryInputKeyId;
    uint32 tertiaryInputKeyElementId;
    uint32 outputKeyId;
    uint32 outputKeyElementId;
    uint32 secondaryOutputKeyId;
    uint32 secondaryOutputKeyElementId;
} Crypto_JobRedirectionInfoType;

typedef struct {
    const uint8*             inputPtr;
    uint32                   inputLength;
    const uint8*             secondaryInputPtr;
    uint32                   secondaryInputLength;
    const uint8*             tertiaryInputPtr;
    uint32                   tertiaryInputLength;
    uint8*                   outputPtr;
    uint32*                  outputLengthPtr;
    uint8*                   secondaryOutputPtr;
    uint32*                  secondaryOutputLengthPtr;
    Crypto_VerifyResultType* verifyPtr;
    Crypto_OperationModeType mode;
    uint32                   cryIfKeyId;
    uint32                   targetCryIfKeyId;
} Crypto_JobPrimitiveInputOutputType;

typedef struct {
    uint32                             jobId;
    Crypto_JobStateType                jobState;
    Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput;
    const Crypto_JobPrimitiveInfoType* jobPrimitiveInfo;
    Crypto_JobRedirectionInfoType*     jobRedirectionInfoRef;
    uint32                             cryptoKeyId;
    uint32                             targetCryptoKeyId;
    uint32                             jobPriority;
} Crypto_JobType;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CRYPTO_GENERALTYPES_H_ */
