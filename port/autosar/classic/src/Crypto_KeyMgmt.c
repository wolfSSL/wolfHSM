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
 * port/autosar/classic/src/Crypto_KeyMgmt.c
 *
 * Crypto key element and key state management.
 *
 * Each AUTOSAR (cryptoKeyId, keyElementId) pair maps to a unique
 * wolfHSM cached key via wh_Autosar_ComposeKeyId.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_utils.h"

#include <string.h>

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
#include "Det.h"
#define CRYPTO_DET_REPORT(sid, errid) \
    (void)Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, (sid), (errid))
#else
#define CRYPTO_DET_REPORT(sid, errid) ((void)0)
#endif

/* This port stores only the MATERIAL element in the wolfHSM keystore
 * (see wh_Autosar_ComposeKeyId in Crypto_Keystore.c). */
#define CRYPTO_KE_MATERIAL 1u

#ifndef CRYPTO_KEY_COPY_BUF_SIZE
#define CRYPTO_KEY_COPY_BUF_SIZE 512u
#endif

/* Keys written since the last Crypto_KeySetValid. Keys provisioned on the
 * HSM before Crypto_Init are not listed and count as valid. */
static uint32 s_invalidKeys[CRYPTO_MAX_INVALID_KEYS];

Std_ReturnType wh_Autosar_KeyMarkInvalid(uint32 cryptoKeyId)
{
    uint32 i;
    uint32 freeIdx = CRYPTO_MAX_INVALID_KEYS;

    for (i = 0u; i < CRYPTO_MAX_INVALID_KEYS; ++i) {
        if (s_invalidKeys[i] == cryptoKeyId) {
            return E_OK;
        }
        if (s_invalidKeys[i] == 0u && freeIdx == CRYPTO_MAX_INVALID_KEYS) {
            freeIdx = i;
        }
    }
    if (freeIdx == CRYPTO_MAX_INVALID_KEYS) {
        return E_NOT_OK;
    }
    s_invalidKeys[freeIdx] = cryptoKeyId;
    return E_OK;
}

void wh_Autosar_KeyMarkValid(uint32 cryptoKeyId)
{
    uint32 i;
    for (i = 0u; i < CRYPTO_MAX_INVALID_KEYS; ++i) {
        if (s_invalidKeys[i] == cryptoKeyId) {
            s_invalidKeys[i] = 0u;
        }
    }
}

boolean wh_Autosar_KeyIsValid(uint32 cryptoKeyId)
{
    uint32 i;
    for (i = 0u; i < CRYPTO_MAX_INVALID_KEYS; ++i) {
        if (s_invalidKeys[i] == cryptoKeyId) {
            return FALSE;
        }
    }
    return TRUE;
}

static void packKeyLabel(uint8 label[WH_NVM_LABEL_LEN], uint32 cryptoKeyId,
                         uint32 keyElementId)
{
    uint32 i;
    (void)memset(label, 0, WH_NVM_LABEL_LEN);
    label[0] = 'A';
    label[1] = 'R';
    for (i = 0u; i < 4u; ++i) {
        label[2u + i] = (uint8)((cryptoKeyId >> (i * 8u)) & 0xFFu);
        label[6u + i] = (uint8)((keyElementId >> (i * 8u)) & 0xFFu);
    }
}

/* Reports DET for a failed KeystoreBegin and passes its result through. */
static Std_ReturnType keystoreBegin(uint8 sid, whClientContext** ctx)
{
    Std_ReturnType ret = wh_Autosar_KeystoreBegin(ctx);
    if (ret == E_NOT_OK) {
        CRYPTO_DET_REPORT(sid, CRYPTO_E_UNINIT);
    }
    (void)sid;
    return ret;
}

Std_ReturnType wh_Autosar_KeyElementSetImpl(whClientContext* ctx,
                                            uint32           cryptoKeyId,
                                            uint32           keyElementId,
                                            const uint8* key, uint32 keyLength)
{
    uint8  label[WH_NVM_LABEL_LEN];
    uint16 keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId);

    if (keyId == 0u || key == NULL || keyLength == 0u || keyLength > 0xFFFFu) {
        return E_NOT_OK;
    }
    if (wh_Autosar_KeyMarkInvalid(cryptoKeyId) != E_OK) {
        return E_NOT_OK;
    }
    packKeyLabel(label, cryptoKeyId, keyElementId);
    /* Usage policy lives in CSM, which this layer cannot see. */
    return (wh_Client_KeyCache(ctx, (uint32)WH_NVM_FLAGS_USAGE_ANY, label,
                               (uint16)sizeof(label), key, (uint16)keyLength,
                               &keyId) == WH_ERROR_OK)
               ? E_OK
               : CRYPTO_E_KEY_WRITE_FAIL;
}

static Std_ReturnType keyElementGetImpl(whClientContext* ctx,
                                        uint32 cryptoKeyId, uint32 keyElementId,
                                        uint8* result, uint32* resultLength)
{
    uint8  label[WH_NVM_LABEL_LEN];
    uint16 keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId);
    uint16 outSz;

    if (keyId == 0u || *resultLength == 0u) {
        return E_NOT_OK;
    }
    outSz = (*resultLength > 0xFFFFu) ? 0xFFFFu : (uint16)(*resultLength);
    if (wh_Client_KeyExport(ctx, keyId, label, (uint16)sizeof(label), result,
                            &outSz) != WH_ERROR_OK) {
        return E_NOT_OK;
    }
    *resultLength = outSz;
    return E_OK;
}

Std_ReturnType wh_Autosar_KeySetValidImpl(whClientContext* ctx,
                                          uint32           cryptoKeyId)
{
    uint16 keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL);
    if (keyId == 0u) {
        return E_NOT_OK;
    }
    if (wh_Client_KeyCommit(ctx, keyId) != WH_ERROR_OK) {
        return E_NOT_OK;
    }
    wh_Autosar_KeyMarkValid(cryptoKeyId);
    return E_OK;
}

Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId,
                                    const uint8* key, uint32 keyLength)
{
    whClientContext* ctx = NULL;
    Std_ReturnType   ret;

    if (key == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (keyLength == 0u || keyLength > 0xFFFFu) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_VALUE);
        return E_NOT_OK;
    }
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    ret = keystoreBegin(CRYPTO_KEYELEMENTSET_SID, &ctx);
    if (ret != E_OK) {
        return ret;
    }
    ret = wh_Autosar_KeyElementSetImpl(ctx, cryptoKeyId, keyElementId, key,
                                       keyLength);
    wh_Autosar_KeystoreEnd(ctx);
    return ret;
}

Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId,
                                    uint8* result, uint32* resultLength)
{
    whClientContext* ctx = NULL;
    Std_ReturnType   ret;

    if (result == NULL || resultLength == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (*resultLength == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_VALUE);
        return E_NOT_OK;
    }
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    ret = keystoreBegin(CRYPTO_KEYELEMENTGET_SID, &ctx);
    if (ret != E_OK) {
        return ret;
    }
    ret =
        keyElementGetImpl(ctx, cryptoKeyId, keyElementId, result, resultLength);
    wh_Autosar_KeystoreEnd(ctx);
    return ret;
}

Std_ReturnType Crypto_KeyElementCopyPartial(
    uint32 cryptoKeyId, uint32 keyElementId, uint32 keyElementSourceOffset,
    uint32 keyElementTargetOffset, uint32 keyElementCopyLength,
    uint32 targetCryptoKeyId, uint32 targetKeyElementId)
{
    uint8            src[CRYPTO_KEY_COPY_BUF_SIZE];
    uint8            dst[CRYPTO_KEY_COPY_BUF_SIZE];
    uint32           srcLen = (uint32)sizeof(src);
    uint32           dstLen = (uint32)sizeof(dst);
    whClientContext* ctx    = NULL;
    Std_ReturnType   ret;

    if (wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId) == 0u ||
        wh_Autosar_ComposeKeyId(targetCryptoKeyId, targetKeyElementId) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTCOPYPARTIAL_SID,
                          CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (keyElementCopyLength == 0u ||
        keyElementCopyLength > CRYPTO_KEY_COPY_BUF_SIZE ||
        keyElementTargetOffset >
            CRYPTO_KEY_COPY_BUF_SIZE - keyElementCopyLength) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTCOPYPARTIAL_SID,
                          CRYPTO_E_PARAM_VALUE);
        return E_NOT_OK;
    }
    ret = keystoreBegin(CRYPTO_KEYELEMENTCOPYPARTIAL_SID, &ctx);
    if (ret != E_OK) {
        return ret;
    }
    ret = keyElementGetImpl(ctx, cryptoKeyId, keyElementId, src, &srcLen);
    if (ret == E_OK &&
        (keyElementSourceOffset > srcLen ||
         keyElementCopyLength > srcLen - keyElementSourceOffset)) {
        ret = E_NOT_OK;
    }
    if (ret == E_OK) {
        if (keyElementGetImpl(ctx, targetCryptoKeyId, targetKeyElementId, dst,
                              &dstLen) != E_OK) {
            dstLen = 0u;
        }
        if (keyElementTargetOffset > dstLen) {
            (void)memset(dst + dstLen, 0, keyElementTargetOffset - dstLen);
        }
        (void)memcpy(dst + keyElementTargetOffset, src + keyElementSourceOffset,
                     keyElementCopyLength);
        if (keyElementTargetOffset + keyElementCopyLength > dstLen) {
            dstLen = keyElementTargetOffset + keyElementCopyLength;
        }
        ret = wh_Autosar_KeyElementSetImpl(ctx, targetCryptoKeyId,
                                           targetKeyElementId, dst, dstLen);
    }
    wh_Autosar_KeystoreEnd(ctx);
    wh_Utils_ForceZero(src, sizeof(src));
    wh_Utils_ForceZero(dst, sizeof(dst));
    return ret;
}

Std_ReturnType Crypto_KeyElementCopy(uint32 cryptoKeyId, uint32 keyElementId,
                                     uint32 targetCryptoKeyId,
                                     uint32 targetKeyElementId)
{
    uint8            buf[CRYPTO_KEY_COPY_BUF_SIZE];
    uint32           len = (uint32)sizeof(buf);
    whClientContext* ctx = NULL;
    Std_ReturnType   ret;

    if (wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId) == 0u ||
        wh_Autosar_ComposeKeyId(targetCryptoKeyId, targetKeyElementId) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTCOPY_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    ret = keystoreBegin(CRYPTO_KEYELEMENTCOPY_SID, &ctx);
    if (ret != E_OK) {
        return ret;
    }
    ret = keyElementGetImpl(ctx, cryptoKeyId, keyElementId, buf, &len);
    if (ret == E_OK) {
        ret = wh_Autosar_KeyElementSetImpl(ctx, targetCryptoKeyId,
                                           targetKeyElementId, buf, len);
    }
    wh_Autosar_KeystoreEnd(ctx);
    wh_Utils_ForceZero(buf, sizeof(buf));
    return ret;
}

Std_ReturnType Crypto_KeyCopy(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    return Crypto_KeyElementCopy(cryptoKeyId, CRYPTO_KE_MATERIAL,
                                 targetCryptoKeyId, CRYPTO_KE_MATERIAL);
}

Std_ReturnType Crypto_KeyElementIdsGet(uint32  cryptoKeyId,
                                       uint32* keyElementIdsPtr,
                                       uint32* keyElementIdsLengthPtr)
{
    if (keyElementIdsPtr == NULL || keyElementIdsLengthPtr == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (*keyElementIdsLengthPtr < 1u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_SMALL_BUFFER);
        return E_NOT_OK;
    }
    keyElementIdsPtr[0]     = CRYPTO_KE_MATERIAL;
    *keyElementIdsLengthPtr = 1u;
    return E_OK;
}

Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId)
{
    whClientContext* ctx = NULL;
    Std_ReturnType   ret;

    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYSETVALID_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    ret = keystoreBegin(CRYPTO_KEYSETVALID_SID, &ctx);
    if (ret != E_OK) {
        return ret;
    }
    ret = wh_Autosar_KeySetValidImpl(ctx, cryptoKeyId);
    wh_Autosar_KeystoreEnd(ctx);
    return ret;
}

Std_ReturnType Crypto_KeySetInvalid(uint32 cryptoKeyId)
{
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYSETINVALID_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    return wh_Autosar_KeyMarkInvalid(cryptoKeyId);
}

Std_ReturnType Crypto_KeyGetStatus(uint32                cryptoKeyId,
                                   Crypto_KeyStatusType* keyStatusPtr)
{
    if (keyStatusPtr == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYGETSTATUS_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYGETSTATUS_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    *keyStatusPtr = wh_Autosar_KeyIsValid(cryptoKeyId)
                        ? CRYPTO_KEYSTATUS_VALID
                        : CRYPTO_KEYSTATUS_INVALID;
    return E_OK;
}
