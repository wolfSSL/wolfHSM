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
 * wolfhsm/wh_message_she.c
 *
 * Message translation functions for SHE operations.
 */

#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_SHE_EXTENSION

#include <stdint.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_message_she.h"

/* Set UID translation function */
int wh_MessageShe_TranslateSetUidRequest(uint16_t magic,
                                         const whMessageShe_SetUidRequest* src,
                                         whMessageShe_SetUidRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(dest->uid, src->uid, WH_SHE_UID_SZ);
    return 0;
}

/* Set UID response translation function */
int wh_MessageShe_TranslateSetUidResponse(uint16_t magic,
                                         const whMessageShe_SetUidResponse* src,
                                         whMessageShe_SetUidResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

/* Secure Boot Init translation functions */
int wh_MessageShe_TranslateSecureBootInitRequest(
    uint16_t magic, const whMessageShe_SecureBootInitRequest* src,
    whMessageShe_SecureBootInitRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

int wh_MessageShe_TranslateSecureBootInitResponse(
    uint16_t magic, const whMessageShe_SecureBootInitResponse* src,
    whMessageShe_SecureBootInitResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, status);
    return 0;
}

/* Secure Boot Update translation functions */
int wh_MessageShe_TranslateSecureBootUpdateRequest(
    uint16_t magic, const whMessageShe_SecureBootUpdateRequest* src,
    whMessageShe_SecureBootUpdateRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    return 0;
}

int wh_MessageShe_TranslateSecureBootUpdateResponse(
    uint16_t magic, const whMessageShe_SecureBootUpdateResponse* src,
    whMessageShe_SecureBootUpdateResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, status);
    return 0;
}

/* Secure Boot Finish translation function */
int wh_MessageShe_TranslateSecureBootFinishResponse(
    uint16_t magic, const whMessageShe_SecureBootFinishResponse* src,
    whMessageShe_SecureBootFinishResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, status);
    return 0;
}

/* Get Status translation function */
int wh_MessageShe_TranslateGetStatusResponse(
    uint16_t magic, const whMessageShe_GetStatusResponse* src,
    whMessageShe_GetStatusResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    dest->sreg = src->sreg;
    return 0;
}

/* Load Key translation functions */
int wh_MessageShe_TranslateLoadKeyRequest(
    uint16_t magic, const whMessageShe_LoadKeyRequest* src,
    whMessageShe_LoadKeyRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(dest->messageOne, src->messageOne, WH_SHE_M1_SZ);
    memcpy(dest->messageTwo, src->messageTwo, WH_SHE_M2_SZ);
    memcpy(dest->messageThree, src->messageThree, WH_SHE_M3_SZ);
    return 0;
}

int wh_MessageShe_TranslateLoadKeyResponse(
    uint16_t magic, const whMessageShe_LoadKeyResponse* src,
    whMessageShe_LoadKeyResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    memcpy(dest->messageFour, src->messageFour, WH_SHE_M4_SZ);
    memcpy(dest->messageFive, src->messageFive, WH_SHE_M5_SZ);
    return 0;
}

/* Load Plain Key translation function */
int wh_MessageShe_TranslateLoadPlainKeyRequest(
    uint16_t magic, const whMessageShe_LoadPlainKeyRequest* src,
    whMessageShe_LoadPlainKeyRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(dest->key, src->key, WH_SHE_KEY_SZ);
    return 0;
}

int wh_MessageShe_TranslateLoadPlainKeyResponse(
    uint16_t magic, const whMessageShe_LoadPlainKeyResponse* src,
    whMessageShe_LoadPlainKeyResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    return 0;
}

/* Export RAM Key translation function */
int wh_MessageShe_TranslateExportRamKeyResponse(
    uint16_t magic, const whMessageShe_ExportRamKeyResponse* src,
    whMessageShe_ExportRamKeyResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    memcpy(dest->messageOne, src->messageOne, WH_SHE_M1_SZ);
    memcpy(dest->messageTwo, src->messageTwo, WH_SHE_M2_SZ);
    memcpy(dest->messageThree, src->messageThree, WH_SHE_M3_SZ);
    memcpy(dest->messageFour, src->messageFour, WH_SHE_M4_SZ);
    memcpy(dest->messageFive, src->messageFive, WH_SHE_M5_SZ);
    return 0;
}

/* Init RNG translation function */
int wh_MessageShe_TranslateInitRngResponse(
    uint16_t magic, const whMessageShe_InitRngResponse* src,
    whMessageShe_InitRngResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, status);
    return 0;
}

/* RND translation function */
int wh_MessageShe_TranslateRndResponse(uint16_t                        magic,
                                       const whMessageShe_RndResponse* src,
                                       whMessageShe_RndResponse*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    memcpy(dest->rnd, src->rnd, WH_SHE_KEY_SZ);
    return 0;
}

/* Extend Seed translation functions */
int wh_MessageShe_TranslateExtendSeedRequest(
    uint16_t magic, const whMessageShe_ExtendSeedRequest* src,
    whMessageShe_ExtendSeedRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memcpy(dest->entropy, src->entropy, WH_SHE_KEY_SZ);
    return 0;
}

int wh_MessageShe_TranslateExtendSeedResponse(
    uint16_t magic, const whMessageShe_ExtendSeedResponse* src,
    whMessageShe_ExtendSeedResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, status);
    return 0;
}

/* Encrypt ECB translation functions */
int wh_MessageShe_TranslateEncEcbRequest(uint16_t magic,
                                         const whMessageShe_EncEcbRequest* src,
                                         whMessageShe_EncEcbRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    dest->keyId = src->keyId;
    return 0;
}

int wh_MessageShe_TranslateEncEcbResponse(
    uint16_t magic, const whMessageShe_EncEcbResponse* src,
    whMessageShe_EncEcbResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* Encrypt CBC translation functions */
int wh_MessageShe_TranslateEncCbcRequest(uint16_t magic,
                                         const whMessageShe_EncCbcRequest* src,
                                         whMessageShe_EncCbcRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    dest->keyId = src->keyId;
    memcpy(dest->iv, src->iv, WH_SHE_KEY_SZ);
    return 0;
}

int wh_MessageShe_TranslateEncCbcResponse(
    uint16_t magic, const whMessageShe_EncCbcResponse* src,
    whMessageShe_EncCbcResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* Decrypt ECB translation functions */
int wh_MessageShe_TranslateDecEcbRequest(uint16_t magic,
                                         const whMessageShe_DecEcbRequest* src,
                                         whMessageShe_DecEcbRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    dest->keyId = src->keyId;
    return 0;
}

int wh_MessageShe_TranslateDecEcbResponse(
    uint16_t magic, const whMessageShe_DecEcbResponse* src,
    whMessageShe_DecEcbResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* Decrypt CBC translation functions */
int wh_MessageShe_TranslateDecCbcRequest(uint16_t magic,
                                         const whMessageShe_DecCbcRequest* src,
                                         whMessageShe_DecCbcRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, sz);
    dest->keyId = src->keyId;
    memcpy(dest->iv, src->iv, WH_SHE_KEY_SZ);
    return 0;
}

int wh_MessageShe_TranslateDecCbcResponse(
    uint16_t magic, const whMessageShe_DecCbcResponse* src,
    whMessageShe_DecCbcResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    WH_T32(magic, dest, src, sz);
    return 0;
}

/* Generate MAC translation functions */
int wh_MessageShe_TranslateGenMacRequest(uint16_t magic,
                                         const whMessageShe_GenMacRequest* src,
                                         whMessageShe_GenMacRequest*       dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, sz);
    return 0;
}

int wh_MessageShe_TranslateGenMacResponse(
    uint16_t magic, const whMessageShe_GenMacResponse* src,
    whMessageShe_GenMacResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    memcpy(dest->mac, src->mac, WH_SHE_KEY_SZ);
    return 0;
}

/* Verify MAC translation functions */
int wh_MessageShe_TranslateVerifyMacRequest(
    uint16_t magic, const whMessageShe_VerifyMacRequest* src,
    whMessageShe_VerifyMacRequest* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, keyId);
    WH_T32(magic, dest, src, messageLen);
    WH_T32(magic, dest, src, macLen);
    return 0;
}

int wh_MessageShe_TranslateVerifyMacResponse(
    uint16_t magic, const whMessageShe_VerifyMacResponse* src,
    whMessageShe_VerifyMacResponse* dest)
{
    if ((src == NULL) || (dest == NULL)) {
        return WH_ERROR_BADARGS;
    }
    WH_T32(magic, dest, src, rc);
    dest->status = src->status;
    return 0;
}

#endif /* WOLFHSM_CFG_SHE_EXTENSION */