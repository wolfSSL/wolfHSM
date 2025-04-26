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
 * wolfhsm/wh_message_she.h
 *
 * Message structures and translation functions for SHE operations.
 */

#ifndef WOLFHSM_WH_MESSAGE_SHE_H_
#define WOLFHSM_WH_MESSAGE_SHE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_she_common.h"

/* Set UID Request */
typedef struct {
    uint8_t uid[WH_SHE_UID_SZ];
    uint8_t WH_PAD[1];
} whMessageShe_SetUidRequest;

/* Set UID Response */
typedef struct {
    uint32_t rc;
    uint8_t  WH_PAD[4];
} whMessageShe_SetUidResponse;

/* Set UID translation function */
int wh_MessageShe_TranslateSetUidRequest(uint16_t magic,
                                         const whMessageShe_SetUidRequest* src,
                                         whMessageShe_SetUidRequest* dest);

int wh_MessageShe_TranslateSetUidResponse(
    uint16_t magic, const whMessageShe_SetUidResponse* src,
    whMessageShe_SetUidResponse* dest);

/* Secure Boot Init Request */
typedef struct {
    uint32_t sz;
    uint8_t  WH_PAD[4];
} whMessageShe_SecureBootInitRequest;

/* Secure Boot Init Response */
typedef struct {
    uint32_t rc;
    uint32_t status;
} whMessageShe_SecureBootInitResponse;

/* Secure Boot Init translation functions */
int wh_MessageShe_TranslateSecureBootInitRequest(
    uint16_t magic, const whMessageShe_SecureBootInitRequest* src,
    whMessageShe_SecureBootInitRequest* dest);

int wh_MessageShe_TranslateSecureBootInitResponse(
    uint16_t magic, const whMessageShe_SecureBootInitResponse* src,
    whMessageShe_SecureBootInitResponse* dest);

/* Secure Boot Update Request */
typedef struct {
    uint32_t sz;
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageShe_SecureBootUpdateRequest;

/* Secure Boot Update Response */
typedef struct {
    uint32_t rc;
    uint32_t status;
} whMessageShe_SecureBootUpdateResponse;

/* Secure Boot Update translation functions */
int wh_MessageShe_TranslateSecureBootUpdateRequest(
    uint16_t magic, const whMessageShe_SecureBootUpdateRequest* src,
    whMessageShe_SecureBootUpdateRequest* dest);

int wh_MessageShe_TranslateSecureBootUpdateResponse(
    uint16_t magic, const whMessageShe_SecureBootUpdateResponse* src,
    whMessageShe_SecureBootUpdateResponse* dest);

/* Secure Boot Finish Response */
typedef struct {
    uint32_t rc;
    uint32_t status;
} whMessageShe_SecureBootFinishResponse;

/* Secure Boot Finish translation function */
int wh_MessageShe_TranslateSecureBootFinishResponse(
    uint16_t magic, const whMessageShe_SecureBootFinishResponse* src,
    whMessageShe_SecureBootFinishResponse* dest);

/* Get Status Response */
typedef struct {
    uint32_t rc;
    uint8_t  sreg;
    uint8_t  WH_PAD[7];
} whMessageShe_GetStatusResponse;

/* Get Status translation function */
int wh_MessageShe_TranslateGetStatusResponse(
    uint16_t magic, const whMessageShe_GetStatusResponse* src,
    whMessageShe_GetStatusResponse* dest);

/* Load Key Request */
typedef struct {
    uint8_t messageOne[WH_SHE_M1_SZ];
    uint8_t messageTwo[WH_SHE_M2_SZ];
    uint8_t messageThree[WH_SHE_M3_SZ];
} whMessageShe_LoadKeyRequest;

/* Load Key Response */
typedef struct {
    uint32_t rc;
    uint8_t  messageFour[WH_SHE_M4_SZ];
    uint8_t  messageFive[WH_SHE_M5_SZ];
} whMessageShe_LoadKeyResponse;

/* Load Key translation functions */
int wh_MessageShe_TranslateLoadKeyRequest(
    uint16_t magic, const whMessageShe_LoadKeyRequest* src,
    whMessageShe_LoadKeyRequest* dest);

int wh_MessageShe_TranslateLoadKeyResponse(
    uint16_t magic, const whMessageShe_LoadKeyResponse* src,
    whMessageShe_LoadKeyResponse* dest);

/* Load Plain Key Request */
typedef struct {
    uint8_t key[WH_SHE_KEY_SZ];
} whMessageShe_LoadPlainKeyRequest;

/* Load Plain Key Response */
typedef struct {
    uint32_t rc;
} whMessageShe_LoadPlainKeyResponse;

/* Load Plain Key translation function */
int wh_MessageShe_TranslateLoadPlainKeyRequest(
    uint16_t magic, const whMessageShe_LoadPlainKeyRequest* src,
    whMessageShe_LoadPlainKeyRequest* dest);

int wh_MessageShe_TranslateLoadPlainKeyResponse(
    uint16_t magic, const whMessageShe_LoadPlainKeyResponse* src,
    whMessageShe_LoadPlainKeyResponse* dest);

/* Export RAM Key Response */
typedef struct {
    uint32_t rc;
    uint8_t  messageOne[WH_SHE_M1_SZ];
    uint8_t  messageTwo[WH_SHE_M2_SZ];
    uint8_t  messageThree[WH_SHE_M3_SZ];
    uint8_t  messageFour[WH_SHE_M4_SZ];
    uint8_t  messageFive[WH_SHE_M5_SZ];
} whMessageShe_ExportRamKeyResponse;

/* Export RAM Key translation function */
int wh_MessageShe_TranslateExportRamKeyResponse(
    uint16_t magic, const whMessageShe_ExportRamKeyResponse* src,
    whMessageShe_ExportRamKeyResponse* dest);

/* Init RNG Response */
typedef struct {
    uint32_t rc;
    uint32_t status;
} whMessageShe_InitRngResponse;

/* Init RNG translation function */
int wh_MessageShe_TranslateInitRngResponse(
    uint16_t magic, const whMessageShe_InitRngResponse* src,
    whMessageShe_InitRngResponse* dest);

/* RND Response */
typedef struct {
    uint32_t rc;
    uint8_t  rnd[WH_SHE_KEY_SZ];
} whMessageShe_RndResponse;

/* RND translation function */
int wh_MessageShe_TranslateRndResponse(uint16_t                        magic,
                                       const whMessageShe_RndResponse* src,
                                       whMessageShe_RndResponse*       dest);

/* Extend Seed Request */
typedef struct {
    uint8_t entropy[WH_SHE_KEY_SZ];
} whMessageShe_ExtendSeedRequest;

/* Extend Seed Response */
typedef struct {
    uint32_t rc;
    uint32_t status;
} whMessageShe_ExtendSeedResponse;

/* Extend Seed translation functions */
int wh_MessageShe_TranslateExtendSeedRequest(
    uint16_t magic, const whMessageShe_ExtendSeedRequest* src,
    whMessageShe_ExtendSeedRequest* dest);

int wh_MessageShe_TranslateExtendSeedResponse(
    uint16_t magic, const whMessageShe_ExtendSeedResponse* src,
    whMessageShe_ExtendSeedResponse* dest);

/* Encrypt ECB Request */
typedef struct {
    uint32_t sz;
    uint8_t  keyId;
    uint8_t  WH_PAD[3];
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageShe_EncEcbRequest;

/* Encrypt ECB Response */
typedef struct {
    uint32_t rc;
    uint32_t sz;
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageShe_EncEcbResponse;

/* Encrypt ECB translation functions */
int wh_MessageShe_TranslateEncEcbRequest(uint16_t magic,
                                         const whMessageShe_EncEcbRequest* src,
                                         whMessageShe_EncEcbRequest* dest);

int wh_MessageShe_TranslateEncEcbResponse(
    uint16_t magic, const whMessageShe_EncEcbResponse* src,
    whMessageShe_EncEcbResponse* dest);

/* Encrypt CBC Request */
typedef struct {
    uint32_t sz;
    uint8_t  keyId;
    uint8_t  WH_PAD[3];
    uint8_t  iv[WH_SHE_KEY_SZ];
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageShe_EncCbcRequest;

/* Encrypt CBC Response */
typedef struct {
    uint32_t rc;
    uint32_t sz;
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageShe_EncCbcResponse;

/* Encrypt CBC translation functions */
int wh_MessageShe_TranslateEncCbcRequest(uint16_t magic,
                                         const whMessageShe_EncCbcRequest* src,
                                         whMessageShe_EncCbcRequest* dest);

int wh_MessageShe_TranslateEncCbcResponse(
    uint16_t magic, const whMessageShe_EncCbcResponse* src,
    whMessageShe_EncCbcResponse* dest);

/* Decrypt ECB Request */
typedef struct {
    uint32_t sz;
    uint8_t  keyId;
    uint8_t  WH_PAD[3];
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageShe_DecEcbRequest;

/* Decrypt ECB Response */
typedef struct {
    uint32_t rc;
    uint32_t sz;
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageShe_DecEcbResponse;

/* Decrypt ECB translation functions */
int wh_MessageShe_TranslateDecEcbRequest(uint16_t magic,
                                         const whMessageShe_DecEcbRequest* src,
                                         whMessageShe_DecEcbRequest* dest);

int wh_MessageShe_TranslateDecEcbResponse(
    uint16_t magic, const whMessageShe_DecEcbResponse* src,
    whMessageShe_DecEcbResponse* dest);

/* Decrypt CBC Request */
typedef struct {
    uint32_t sz;
    uint8_t  keyId;
    uint8_t  WH_PAD[3];
    uint8_t  iv[WH_SHE_KEY_SZ];
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageShe_DecCbcRequest;

/* Decrypt CBC Response */
typedef struct {
    uint32_t rc;
    uint32_t sz;
    /* Data follows:
     * uint8_t out[sz]
     */
} whMessageShe_DecCbcResponse;

/* Decrypt CBC translation functions */
int wh_MessageShe_TranslateDecCbcRequest(uint16_t magic,
                                         const whMessageShe_DecCbcRequest* src,
                                         whMessageShe_DecCbcRequest* dest);

int wh_MessageShe_TranslateDecCbcResponse(
    uint16_t magic, const whMessageShe_DecCbcResponse* src,
    whMessageShe_DecCbcResponse* dest);

/* Generate MAC Request */
typedef struct {
    uint32_t keyId;
    uint32_t sz;
    /* Data follows:
     * uint8_t in[sz]
     */
} whMessageShe_GenMacRequest;

/* Generate MAC Response */
typedef struct {
    uint32_t rc;
    uint8_t  mac[WH_SHE_KEY_SZ];
} whMessageShe_GenMacResponse;

/* Generate MAC translation functions */
int wh_MessageShe_TranslateGenMacRequest(uint16_t magic,
                                         const whMessageShe_GenMacRequest* src,
                                         whMessageShe_GenMacRequest* dest);

int wh_MessageShe_TranslateGenMacResponse(
    uint16_t magic, const whMessageShe_GenMacResponse* src,
    whMessageShe_GenMacResponse* dest);

/* Verify MAC Request */
typedef struct {
    uint32_t keyId;
    uint32_t messageLen;
    uint32_t macLen;
    uint8_t  WH_PAD[4];
    /* Data follows:
     * uint8_t message[messageLen]
     * uint8_t mac[macLen]
     */
} whMessageShe_VerifyMacRequest;

/* Verify MAC Response */
typedef struct {
    uint32_t rc;
    uint8_t  status;
    uint8_t  WH_PAD[7];
} whMessageShe_VerifyMacResponse;

/* Verify MAC translation functions */
int wh_MessageShe_TranslateVerifyMacRequest(
    uint16_t magic, const whMessageShe_VerifyMacRequest* src,
    whMessageShe_VerifyMacRequest* dest);

int wh_MessageShe_TranslateVerifyMacResponse(
    uint16_t magic, const whMessageShe_VerifyMacResponse* src,
    whMessageShe_VerifyMacResponse* dest);

#endif /* WOLFHSM_CFG_SHE_EXTENSION */

#endif /* !WOLFHSM_WH_MESSAGE_SHE_H_ */