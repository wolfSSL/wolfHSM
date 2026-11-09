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
#define CRYPTO_KE_CIPHER_IV 5u
#define CRYPTO_KE_KEYDERIVATION_SALT 13u

#ifndef CRYPTO_MAX_RAM_ELEMENTS
#define CRYPTO_MAX_RAM_ELEMENTS 8u
#endif
#define CRYPTO_IV_MAX_LEN 16u
#define CRYPTO_SALT_MAX_LEN 64u

#ifndef CRYPTO_KEY_COPY_BUF_SIZE
#define CRYPTO_KEY_COPY_BUF_SIZE 512u
#endif

/* Keys changed since their last SetValid; unlisted keys count as valid. */
typedef struct {
    uint32  cryptoKeyId;
    boolean written;
    boolean revoked; /* set by Crypto_KeySetInvalid */
} wh_AutosarKeyState;
static wh_AutosarKeyState s_invalidKeys[CRYPTO_MAX_INVALID_KEYS];

/* IV and salt elements: public, kept in driver RAM. The IV is consumed by
 * the next cipher job on the key. */
typedef struct {
    uint32 cryptoKeyId;
    uint32 elementId;
    uint32 len;
    uint8  data[CRYPTO_SALT_MAX_LEN];
} wh_AutosarRamElement;
static wh_AutosarRamElement s_ramElements[CRYPTO_MAX_RAM_ELEMENTS];

static wh_AutosarKeyState* stateFind(uint32 cryptoKeyId, boolean alloc)
{
    uint32 i;
    for (i = 0u; i < CRYPTO_MAX_INVALID_KEYS; ++i) {
        if (s_invalidKeys[i].cryptoKeyId == cryptoKeyId) {
            return &s_invalidKeys[i];
        }
    }
    if (alloc) {
        for (i = 0u; i < CRYPTO_MAX_INVALID_KEYS; ++i) {
            if (s_invalidKeys[i].cryptoKeyId == 0u) {
                s_invalidKeys[i].cryptoKeyId = cryptoKeyId;
                s_invalidKeys[i].written     = FALSE;
                s_invalidKeys[i].revoked     = FALSE;
                return &s_invalidKeys[i];
            }
        }
    }
    return NULL;
}

static wh_AutosarRamElement* ramFind(uint32 cryptoKeyId, uint32 elementId,
                                     boolean alloc)
{
    uint32 i;
    for (i = 0u; i < CRYPTO_MAX_RAM_ELEMENTS; ++i) {
        if (s_ramElements[i].cryptoKeyId == cryptoKeyId &&
            s_ramElements[i].elementId == elementId) {
            return &s_ramElements[i];
        }
    }
    if (alloc) {
        for (i = 0u; i < CRYPTO_MAX_RAM_ELEMENTS; ++i) {
            if (s_ramElements[i].cryptoKeyId == 0u) {
                s_ramElements[i].cryptoKeyId = cryptoKeyId;
                s_ramElements[i].elementId   = elementId;
                return &s_ramElements[i];
            }
        }
    }
    return NULL;
}

static void ramClear(wh_AutosarRamElement* e)
{
    wh_Utils_ForceZero(e, sizeof(*e));
}

static boolean isRamElement(uint32 keyElementId)
{
    return (keyElementId == CRYPTO_KE_CIPHER_IV ||
            keyElementId == CRYPTO_KE_KEYDERIVATION_SALT)
               ? TRUE
               : FALSE;
}

Std_ReturnType wh_Autosar_KeyMarkInvalid(uint32 cryptoKeyId)
{
    wh_AutosarKeyState* st;
    wh_Autosar_LockKeys();
    st = stateFind(cryptoKeyId, TRUE);
    if (st != NULL) {
        st->revoked = TRUE;
    }
    wh_Autosar_UnlockKeys();
    return (st != NULL) ? E_OK : E_NOT_OK;
}

boolean wh_Autosar_KeyIsRevoked(uint32 cryptoKeyId)
{
    wh_AutosarKeyState* st;
    boolean             revoked;
    wh_Autosar_LockKeys();
    st      = stateFind(cryptoKeyId, FALSE);
    revoked = (st != NULL && st->revoked) ? TRUE : FALSE;
    wh_Autosar_UnlockKeys();
    return revoked;
}

Std_ReturnType wh_Autosar_KeyMarkWritten(uint32 cryptoKeyId)
{
    wh_AutosarKeyState*   st;
    wh_AutosarRamElement* e;

    wh_Autosar_LockKeys();
    st = stateFind(cryptoKeyId, TRUE);
    if (st != NULL) {
        st->written = TRUE;
        st->revoked = FALSE;
    }
    e = ramFind(cryptoKeyId, CRYPTO_KE_CIPHER_IV, FALSE);
    if (e != NULL) {
        ramClear(e);
    }
    e = ramFind(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, FALSE);
    if (e != NULL) {
        ramClear(e);
    }
    wh_Autosar_UnlockKeys();
    return (st != NULL) ? E_OK : E_NOT_OK;
}

void wh_Autosar_KeyMarkValid(uint32 cryptoKeyId)
{
    wh_AutosarKeyState* st;
    wh_Autosar_LockKeys();
    st = stateFind(cryptoKeyId, FALSE);
    if (st != NULL) {
        (void)memset(st, 0, sizeof(*st));
    }
    wh_Autosar_UnlockKeys();
}

boolean wh_Autosar_KeyIsValid(uint32 cryptoKeyId)
{
    boolean valid;
    wh_Autosar_LockKeys();
    valid = (stateFind(cryptoKeyId, FALSE) == NULL) ? TRUE : FALSE;
    wh_Autosar_UnlockKeys();
    return valid;
}

/* Copies a RAM element into out; take clears it afterwards. */
static Std_ReturnType ramGet(uint32 cryptoKeyId, uint32 elementId, uint8* out,
                             uint32* len, boolean take)
{
    Std_ReturnType        ret = CRYPTO_E_KEY_NOT_AVAILABLE;
    wh_AutosarRamElement* e;

    wh_Autosar_LockKeys();
    e = ramFind(cryptoKeyId, elementId, FALSE);
    if (e != NULL && e->len != 0u) {
        if (*len < e->len) {
            ret = E_NOT_OK;
        }
        else {
            (void)memcpy(out, e->data, e->len);
            *len = e->len;
            ret  = E_OK;
            if (take) {
                ramClear(e);
            }
        }
    }
    wh_Autosar_UnlockKeys();
    return ret;
}

Std_ReturnType wh_Autosar_KeyIvTake(uint32 cryptoKeyId, uint8* iv,
                                    uint32* ivLen)
{
    return (ramGet(cryptoKeyId, CRYPTO_KE_CIPHER_IV, iv, ivLen, TRUE) == E_OK)
               ? E_OK
               : E_NOT_OK;
}

Std_ReturnType wh_Autosar_KeySaltGet(uint32 cryptoKeyId, uint8* salt,
                                     uint32* saltLen)
{
    return ramGet(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT, salt, saltLen,
                  FALSE);
}

static Std_ReturnType ramSet(uint32 cryptoKeyId, uint32 elementId,
                             const uint8* data, uint32 len)
{
    wh_AutosarRamElement* e;
    uint32 max = (elementId == CRYPTO_KE_CIPHER_IV) ? CRYPTO_IV_MAX_LEN
                                                    : CRYPTO_SALT_MAX_LEN;

    if (len == 0u || len > max) {
        return E_NOT_OK;
    }
    wh_Autosar_LockKeys();
    e = ramFind(cryptoKeyId, elementId, TRUE);
    if (e != NULL) {
        (void)memcpy(e->data, data, len);
        e->len = len;
    }
    wh_Autosar_UnlockKeys();
    return (e != NULL) ? E_OK : CRYPTO_E_KEY_WRITE_FAIL;
}

static boolean ramPresent(uint32 cryptoKeyId, uint32 elementId)
{
    wh_AutosarRamElement* e;
    boolean               present;

    wh_Autosar_LockKeys();
    e       = ramFind(cryptoKeyId, elementId, FALSE);
    present = (e != NULL && e->len != 0u) ? TRUE : FALSE;
    wh_Autosar_UnlockKeys();
    return present;
}

whNvmFlags wh_Autosar_KeyFlags(uint32 cryptoKeyId)
{
    const Crypto_KeyDescriptorType* desc =
        wh_Autosar_LookupKeyDescriptor(cryptoKeyId);
    /* Usage policy lives in CSM, which this layer cannot see. */
    whNvmFlags flags = (whNvmFlags)WH_NVM_FLAGS_USAGE_ANY;

    if (desc == NULL || !desc->exportable) {
        flags |= (whNvmFlags)WH_NVM_FLAGS_NONEXPORTABLE;
    }
    return flags;
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
    if (wh_Autosar_KeyMarkWritten(cryptoKeyId) != E_OK) {
        return CRYPTO_E_KEY_WRITE_FAIL;
    }
    packKeyLabel(label, cryptoKeyId, keyElementId);
    return (wh_Client_KeyCache(ctx, (uint32)wh_Autosar_KeyFlags(cryptoKeyId),
                               label, (uint16)sizeof(label), key,
                               (uint16)keyLength, &keyId) == WH_ERROR_OK)
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
        return CRYPTO_E_KEY_READ_FAIL;
    }
    *resultLength = outSz;
    return E_OK;
}

/* Reads a copy target; a target that does not exist yet reads as empty. */
static Std_ReturnType targetGet(whClientContext* ctx, uint32 cryptoKeyId,
                                uint32 keyElementId, uint8* out, uint32* outLen)
{
    uint8  label[WH_NVM_LABEL_LEN];
    uint16 keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId);
    uint16 outSz = (*outLen > 0xFFFFu) ? 0xFFFFu : (uint16)(*outLen);
    int    rc;

    rc = wh_Client_KeyExport(ctx, keyId, label, (uint16)sizeof(label), out,
                             &outSz);
    if (rc == WH_ERROR_NOTFOUND) {
        *outLen = 0u;
        return E_OK;
    }
    if (rc != WH_ERROR_OK) {
        return CRYPTO_E_KEY_READ_FAIL;
    }
    *outLen = outSz;
    return E_OK;
}

Std_ReturnType wh_Autosar_KeySetValidImpl(whClientContext* ctx,
                                          uint32           cryptoKeyId)
{
    uint16              keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, 1u);
    wh_AutosarKeyState* st;
    boolean             written;

    if (keyId == 0u) {
        return E_NOT_OK;
    }
    wh_Autosar_LockKeys();
    st      = stateFind(cryptoKeyId, FALSE);
    written = (st != NULL && st->written) ? TRUE : FALSE;
    wh_Autosar_UnlockKeys();
    /* Only material written in this session needs persisting. */
    if (written && wh_Client_KeyCommit(ctx, keyId) != WH_ERROR_OK) {
        return CRYPTO_E_KEY_WRITE_FAIL;
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
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u ||
        (!isRamElement(keyElementId) &&
         wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId) == 0u)) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (isRamElement(keyElementId)) {
        return ramSet(cryptoKeyId, keyElementId, key, keyLength);
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
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u ||
        (!isRamElement(keyElementId) &&
         wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId) == 0u)) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (isRamElement(keyElementId)) {
        return ramGet(cryptoKeyId, keyElementId, result, resultLength, FALSE);
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
        ret =
            targetGet(ctx, targetCryptoKeyId, targetKeyElementId, dst, &dstLen);
    }
    if (ret == E_OK) {
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
    uint32  n;
    boolean hasIv;
    boolean hasSalt;

    if (keyElementIdsPtr == NULL || keyElementIdsLengthPtr == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL) == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    hasIv   = ramPresent(cryptoKeyId, CRYPTO_KE_CIPHER_IV);
    hasSalt = ramPresent(cryptoKeyId, CRYPTO_KE_KEYDERIVATION_SALT);
    n       = 1u + (hasIv ? 1u : 0u) + (hasSalt ? 1u : 0u);
    if (*keyElementIdsLengthPtr < n) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTIDSGET_SID, CRYPTO_E_SMALL_BUFFER);
        return E_NOT_OK;
    }
    n                     = 0u;
    keyElementIdsPtr[n++] = CRYPTO_KE_MATERIAL;
    if (hasIv) {
        keyElementIdsPtr[n++] = CRYPTO_KE_CIPHER_IV;
    }
    if (hasSalt) {
        keyElementIdsPtr[n++] = CRYPTO_KE_KEYDERIVATION_SALT;
    }
    *keyElementIdsLengthPtr = n;
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
