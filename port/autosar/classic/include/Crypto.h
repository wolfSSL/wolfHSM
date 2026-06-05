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
 * port/autosar/classic/include/Crypto.h
 *
 * AUTOSAR R22-11 Crypto Driver public API, implemented over wolfHSM.
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include "Std_Types.h"
#include "Crypto_GeneralTypes.h"
#include "Crypto_Cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AUTOSAR-registered vendor id; 0 marks an unconfigured build. */
#ifndef CRYPTO_VENDOR_ID
#define CRYPTO_VENDOR_ID ((uint16)0u)
#endif
/* Crypto Driver module id per AUTOSAR_TR_BSWModuleList. */
#ifndef CRYPTO_MODULE_ID
#define CRYPTO_MODULE_ID ((uint16)114u)
#endif
#ifndef CRYPTO_INSTANCE_ID
#define CRYPTO_INSTANCE_ID ((uint8)0u)
#endif

#define CRYPTO_AR_RELEASE_MAJOR_VERSION 4
#define CRYPTO_AR_RELEASE_MINOR_VERSION 7
#define CRYPTO_AR_RELEASE_PATCH_VERSION 0

#define CRYPTO_SW_MAJOR_VERSION 1
#define CRYPTO_SW_MINOR_VERSION 0
#define CRYPTO_SW_PATCH_VERSION 0

/* --- Service IDs (per SWS) ------------------------------------------- */
#define CRYPTO_INIT_SID ((uint8)0x00u)
#define CRYPTO_GETVERSIONINFO_SID ((uint8)0x01u)
#define CRYPTO_PROCESSJOB_SID ((uint8)0x03u)
#define CRYPTO_CANCELJOB_SID ((uint8)0x0Du)
#define CRYPTO_KEYELEMENTSET_SID ((uint8)0x04u)
#define CRYPTO_KEYELEMENTGET_SID ((uint8)0x06u)
#define CRYPTO_KEYELEMENTCOPY_SID ((uint8)0x0Cu)
#define CRYPTO_KEYCOPY_SID ((uint8)0x0Eu)
#define CRYPTO_KEYSETVALID_SID ((uint8)0x05u)
#define CRYPTO_KEYGENERATE_SID ((uint8)0x07u)
#define CRYPTO_KEYDERIVE_SID ((uint8)0x08u)
#define CRYPTO_KEYEXCHANGECALCPUBVAL_SID ((uint8)0x09u)
#define CRYPTO_KEYEXCHANGECALCSECRET_SID ((uint8)0x0Au)
#define CRYPTO_RANDOMSEED_SID ((uint8)0x0Bu)
#define CRYPTO_MAINFUNCTION_SID ((uint8)0x0Fu)
#define CRYPTO_CERTIFICATEPARSE_SID ((uint8)0x10u)
#define CRYPTO_CERTIFICATEVERIFY_SID ((uint8)0x11u)

/* --- DET error codes ------------------------------------------------- */
#define CRYPTO_E_PARAM_POINTER ((uint8)0x01u)
#define CRYPTO_E_PARAM_HANDLE ((uint8)0x04u)
#define CRYPTO_E_PARAM_VALUE ((uint8)0x05u)
#define CRYPTO_E_UNINIT ((uint8)0x07u)
#define CRYPTO_E_INIT_FAILED ((uint8)0x08u)
#define CRYPTO_E_PARAM_KEY ((uint8)0x0Au)

/* --- API ------------------------------------------------------------- */

/** Crypto_Init — initialize the Crypto Driver and all configured driver
 *  objects. Establishes wolfHSM client contexts and opens transports. */
void Crypto_Init(void);

/** Crypto_GetVersionInfo — fill in the published Std_VersionInfoType. */
void Crypto_GetVersionInfo(Std_VersionInfoType* versionInfo);

/** Crypto_ProcessJob — submit a job to the given driver object. May block
 *  (sync) or queue (async); see Crypto_JobPrimitiveInfoType.processingType. */
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job);

/** Crypto_CancelJob — request cancellation of a queued/running job. */
Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobType* job);

/** Writes a key element value into a Crypto Key. */
Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId,
                                    const uint8* key, uint32 keyLength);

/** Crypto_KeyElementGet — read a key element value. */
Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId,
                                    uint8* result, uint32* resultLength);

/** Crypto_KeyElementCopy — copy a key element between Crypto Keys. */
Std_ReturnType Crypto_KeyElementCopy(uint32 cryptoKeyId, uint32 keyElementId,
                                     uint32 targetCryptoKeyId,
                                     uint32 targetKeyElementId);

/** Crypto_KeyCopy — copy all elements between Crypto Keys. */
Std_ReturnType Crypto_KeyCopy(uint32 cryptoKeyId, uint32 targetCryptoKeyId);

/** Crypto_KeySetValid — mark the key valid for use (commits to NVM if
 *  the key element is so configured). */
Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId);

/** Crypto_KeyGenerate — generate a new key into the given Crypto Key. */
Std_ReturnType Crypto_KeyGenerate(uint32 cryptoKeyId);

/** Derives a new key into a target Crypto Key. */
Std_ReturnType Crypto_KeyDerive(uint32 cryptoKeyId, uint32 targetCryptoKeyId);

/** Generates a key pair and returns the local public value. */
Std_ReturnType Crypto_KeyExchangeCalcPubVal(uint32  cryptoKeyId,
                                            uint8*  publicValuePtr,
                                            uint32* publicValueLengthPtr);

/** Computes the shared secret from the peer's public value. */
Std_ReturnType Crypto_KeyExchangeCalcSecret(uint32       cryptoKeyId,
                                            const uint8* partnerPublicValuePtr,
                                            uint32 partnerPublicValueLength);

/** Returns E_NOT_OK: wolfHSM has no client-side RNG reseed. */
Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8* seedPtr,
                                 uint32 seedLength);

/** Crypto_MainFunction — drives async job state machines and dispatches
 *  CryIf_CallbackNotification on completion. Called from a BSW OS task. */
void Crypto_MainFunction(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CRYPTO_H_ */
