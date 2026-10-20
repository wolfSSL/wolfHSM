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
 * port/autosar/classic/examples/csm_smoke/fake_bsw/Crypto_GeneralTypes.h
 *
 * Minimal AUTOSAR R22-11 Crypto_GeneralTypes for the csm_smoke harness.
 * REAL BSW PROJECTS DO NOT USE THIS FILE — they take Crypto_GeneralTypes.h
 * from their BSW vendor (MICROSAR, RTA-BSW, EB tresos, ...), which
 * supplies the canonical R22-11 type layout for their stack.
 *
 * Field set is restricted to what the wolfHSM dispatcher actually
 * references, written to match R22-11 SWS_CryptoDriver / SWS_CryIf
 * field names and types. No port-private extensions.
 */

#ifndef CRYPTO_GENERALTYPES_H_
#define CRYPTO_GENERALTYPES_H_

#include "Std_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- Crypto_ResultType (subset) ---------------------------------------
 *
 * R22-11 SWS defines both Crypto_ResultType::CRYPTO_E_VER_NOT_OK (0x10)
 * and Crypto_VerifyResultType::CRYPTO_E_VER_NOT_OK (0x01). In C the two
 * collide as preprocessor macros; vendor headers resolve this in
 * different ways. The wolfHSM dispatcher does NOT reference either by
 * name — it uses internal WH_AUTOSAR_VER_*_VAL values for writes
 * through verifyPtr — so neither definition below influences runtime
 * behaviour. They are provided for completeness only.
 */
typedef uint8 Crypto_ResultType;
#define CRYPTO_E_OK ((Crypto_ResultType)0x00u)
#define CRYPTO_E_BUSY ((Crypto_ResultType)0x02u)
#define CRYPTO_E_SMALL_BUFFER ((Crypto_ResultType)0x03u)
#define CRYPTO_E_ENTROPY_EXHAUSTION ((Crypto_ResultType)0x04u)
#define CRYPTO_E_KEY_NOT_VALID ((Crypto_ResultType)0x06u)
#define CRYPTO_E_KEY_SIZE_MISMATCH ((Crypto_ResultType)0x07u)
#define CRYPTO_E_KEY_READ_FAIL ((Crypto_ResultType)0x08u)
#define CRYPTO_E_KEY_WRITE_FAIL ((Crypto_ResultType)0x09u)
#define CRYPTO_E_KEY_NOT_AVAILABLE ((Crypto_ResultType)0x0Bu)
#define CRYPTO_E_JOB_CANCELED ((Crypto_ResultType)0x0Eu)
#define CRYPTO_E_KEY_FAILURE ((Crypto_ResultType)0x11u)

/* --- Crypto_VerifyResultType ---------------------------------------- */
typedef uint8 Crypto_VerifyResultType;
#define CRYPTO_E_VER_OK ((Crypto_VerifyResultType)0x00u)
#define CRYPTO_E_VER_NOT_OK ((Crypto_VerifyResultType)0x01u)

/* --- Crypto_OperationModeType ----------------------------------------- */
typedef uint8 Crypto_OperationModeType;
#define CRYPTO_OPERATIONMODE_START ((Crypto_OperationModeType)0x01u)
#define CRYPTO_OPERATIONMODE_UPDATE ((Crypto_OperationModeType)0x02u)
#define CRYPTO_OPERATIONMODE_FINISH ((Crypto_OperationModeType)0x04u)
#define CRYPTO_OPERATIONMODE_SINGLECALL                         \
    (CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE | \
     CRYPTO_OPERATIONMODE_FINISH)
#define CRYPTO_OPERATIONMODE_STREAMSTART \
    (CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE)

/* --- Crypto_JobStateType ---------------------------------------------- */
typedef uint8 Crypto_JobStateType;
#define CRYPTO_JOBSTATE_IDLE ((Crypto_JobStateType)0x00u)
#define CRYPTO_JOBSTATE_ACTIVE ((Crypto_JobStateType)0x01u)

/* --- Crypto_ServiceInfoType ------------------------------------------- */
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
#define CRYPTO_RANDOMGENERATE ((Crypto_ServiceInfoType)0x0Du)
#define CRYPTO_KEYGENERATE ((Crypto_ServiceInfoType)0x0Eu)
#define CRYPTO_KEYDERIVE ((Crypto_ServiceInfoType)0x0Fu)
#define CRYPTO_KEYEXCHANGECALCPUBVAL ((Crypto_ServiceInfoType)0x10u)
#define CRYPTO_KEYEXCHANGECALCSECRET ((Crypto_ServiceInfoType)0x11u)

/* --- Crypto_AlgorithmFamilyType --------------------------------------- */
typedef uint8 Crypto_AlgorithmFamilyType;
#define CRYPTO_ALGOFAM_NOT_SET ((Crypto_AlgorithmFamilyType)0x00u)
#define CRYPTO_ALGOFAM_SHA2_224 ((Crypto_AlgorithmFamilyType)0x05u)
#define CRYPTO_ALGOFAM_SHA2_256 ((Crypto_AlgorithmFamilyType)0x06u)
#define CRYPTO_ALGOFAM_SHA2_384 ((Crypto_AlgorithmFamilyType)0x07u)
#define CRYPTO_ALGOFAM_SHA2_512 ((Crypto_AlgorithmFamilyType)0x08u)
#define CRYPTO_ALGOFAM_AES ((Crypto_AlgorithmFamilyType)0x21u)
#define CRYPTO_ALGOFAM_HMAC ((Crypto_AlgorithmFamilyType)0x33u)
#define CRYPTO_ALGOFAM_CMAC ((Crypto_AlgorithmFamilyType)0x34u)
#define CRYPTO_ALGOFAM_RSA ((Crypto_AlgorithmFamilyType)0x47u)
#define CRYPTO_ALGOFAM_ECCNIST ((Crypto_AlgorithmFamilyType)0x49u)
#define CRYPTO_ALGOFAM_ED25519 ((Crypto_AlgorithmFamilyType)0x4Du)
#define CRYPTO_ALGOFAM_X25519 ((Crypto_AlgorithmFamilyType)0x4Eu)
#define CRYPTO_ALGOFAM_MLDSA ((Crypto_AlgorithmFamilyType)0x60u)
#define CRYPTO_ALGOFAM_HKDF ((Crypto_AlgorithmFamilyType)0x71u)
#define CRYPTO_ALGOFAM_CMAC_KDF ((Crypto_AlgorithmFamilyType)0x72u)
#define CRYPTO_ALGOFAM_RNG ((Crypto_AlgorithmFamilyType)0x80u)

/* --- Crypto_AlgorithmModeType ----------------------------------------- */
typedef uint8 Crypto_AlgorithmModeType;
#define CRYPTO_ALGOMODE_NOT_SET ((Crypto_AlgorithmModeType)0x00u)
#define CRYPTO_ALGOMODE_ECB ((Crypto_AlgorithmModeType)0x01u)
#define CRYPTO_ALGOMODE_CBC ((Crypto_AlgorithmModeType)0x02u)
#define CRYPTO_ALGOMODE_CTR ((Crypto_AlgorithmModeType)0x06u)
#define CRYPTO_ALGOMODE_GCM ((Crypto_AlgorithmModeType)0x09u)
#define CRYPTO_ALGOMODE_RSASSA_PKCS1_V1_5 ((Crypto_AlgorithmModeType)0x33u)
#define CRYPTO_ALGOMODE_RSASSA_PSS ((Crypto_AlgorithmModeType)0x34u)
#define CRYPTO_ALGOMODE_ECDSA ((Crypto_AlgorithmModeType)0x40u)
#define CRYPTO_ALGOMODE_ECDH ((Crypto_AlgorithmModeType)0x41u)

/* --- SWS-prescribed struct layout ------------------------------------ */

typedef struct {
    Crypto_AlgorithmFamilyType family;
    Crypto_AlgorithmFamilyType secondaryFamily;
    uint32                     keyLength;
    Crypto_AlgorithmModeType   mode;
} Crypto_AlgorithmInfoType;

typedef struct {
    uint32                   resultLength;
    Crypto_ServiceInfoType   service;
    Crypto_AlgorithmInfoType algorithm;
} Crypto_PrimitiveInfoType;

typedef struct {
    uint32                          callbackId;
    const Crypto_PrimitiveInfoType* primitiveInfo;
    uint32                          secureCounterId;
    uint32                          cryIfKeyId;
    uint8                           processingType; /* 0 sync, 1 async */
    boolean                         callbackUpdateNotification;
} Crypto_JobPrimitiveInfoType;

typedef struct {
    uint32 jobId;
    uint32 jobPriority;
} Crypto_JobInfoType;

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
    uint64                   secondaryInputUint64;
    uint8*                   outputPtr;
    uint32*                  outputLengthPtr;
    uint8*                   secondaryOutputPtr;
    uint32*                  secondaryOutputLengthPtr;
    uint64*                  secondaryOutputUint64Ptr;
    Crypto_OperationModeType mode;
    uint8*                   verifyPtr;
} Crypto_JobPrimitiveInputOutputType;

typedef struct Crypto_JobType_s {
    uint32                             jobId;
    Crypto_JobStateType                jobState;
    Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput;
    const Crypto_JobPrimitiveInfoType* jobPrimitiveInfo;
    const Crypto_JobInfoType*          jobInfo;
    Crypto_JobRedirectionInfoType*     jobRedirectionInfoRef;
} Crypto_JobType;

typedef struct {
    uint32 cryptoKeyId;
} Crypto_KeyType;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CRYPTO_GENERALTYPES_H_ */
