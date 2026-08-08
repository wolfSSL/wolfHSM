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
 * Crypto_KeyElementSet/Get/Copy, Crypto_KeyCopy, Crypto_KeySetValid.
 *
 * Each AUTOSAR (cryptoKeyId, keyElementId) pair maps to a unique
 * wolfHSM cached key via wh_Autosar_ComposeKeyId. Set/Get use the
 * keystore client; KeyElementCopy is Get-then-Set on the same client.
 */

#include "Crypto.h"
#include "wh_autosar_classic_internal.h"

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"

#include <string.h>

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
#include "Det.h"
#define CRYPTO_DET_REPORT(sid, errid) \
    (void)Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, (sid), (errid))
#else
#define CRYPTO_DET_REPORT(sid, errid) ((void)0)
#endif

/* This port stores only the MATERIAL element in the wolfHSM keystore
 * (see wh_Autosar_ComposeKeyId in Crypto_Keystore.c). KeyCopy and
 * KeySetValid therefore operate exclusively on element 1. Integrators
 * who need richer per-element storage replace this file. */
#define CRYPTO_KE_MATERIAL 1u

/* Scratch buffer for KeyElementCopy. Most AUTOSAR key elements are
 * small (AES-256 key = 32 B, ECC P-256 keypair DER < 256 B). Override
 * upward if you store RSA-4096 keys via Copy. */
#ifndef CRYPTO_KEY_COPY_BUF_SIZE
#define CRYPTO_KEY_COPY_BUF_SIZE 512u
#endif

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

Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId,
                                    const uint8* key, uint32 keyLength)
{
    whClientContext* ctx = wh_Autosar_KeystoreClient();
    uint8            label[WH_NVM_LABEL_LEN];
    uint16           keyId;
    int              rc;

    if (ctx == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (key == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (keyLength == 0u || keyLength > 0xFFFFu) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_VALUE);
        return E_NOT_OK;
    }

    keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId);
    if (keyId == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_PARAM_KEY);
        return E_NOT_OK;
    }
    packKeyLabel(label, cryptoKeyId, keyElementId);

    /* Grant all usage rights — wolfHSM enforces key-usage flags
     * server-side, and a key cached with no usage bits set is rejected
     * for every subsequent operation. AUTOSAR CSM expresses per-job
     * usage permissions at a layer above us; we don't have access to
     * that here, so we grant USAGE_ANY and rely on CSM/CryIf for
     * higher-level access control. */
    rc = wh_Client_KeyCache(ctx, (uint32)WH_NVM_FLAGS_USAGE_ANY, label,
                            (uint16)sizeof(label), key, (uint16)keyLength,
                            &keyId);
    return (rc == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}

Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId,
                                    uint8* result, uint32* resultLength)
{
    whClientContext* ctx = wh_Autosar_KeystoreClient();
    uint8            label[WH_NVM_LABEL_LEN];
    uint16           keyId;
    uint16           outSz;
    int              rc;

    if (ctx == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (result == NULL || resultLength == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (*resultLength == 0u || *resultLength > 0xFFFFu) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_VALUE);
        return E_NOT_OK;
    }

    keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, keyElementId);
    if (keyId == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYELEMENTGET_SID, CRYPTO_E_PARAM_KEY);
        return E_NOT_OK;
    }
    outSz = (uint16)(*resultLength);
    rc = wh_Client_KeyExport(ctx, keyId, label, (uint16)sizeof(label), result,
                             &outSz);
    if (rc == WH_ERROR_OK) {
        *resultLength = outSz;
        return E_OK;
    }
    return E_NOT_OK;
}

Std_ReturnType Crypto_KeyElementCopy(uint32 cryptoKeyId, uint32 keyElementId,
                                     uint32 targetCryptoKeyId,
                                     uint32 targetKeyElementId)
{
    uint8          buf[CRYPTO_KEY_COPY_BUF_SIZE];
    uint32         len = (uint32)sizeof(buf);
    Std_ReturnType ret;

    ret = Crypto_KeyElementGet(cryptoKeyId, keyElementId, buf, &len);
    if (ret != E_OK) {
        return ret;
    }
    return Crypto_KeyElementSet(targetCryptoKeyId, targetKeyElementId, buf,
                                len);
}

Std_ReturnType Crypto_KeyCopy(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    /* All-or-nothing copy of the only element we store (MATERIAL). The
     * previous "anySuccess" sweep over elements 1..15 reported E_OK
     * even when 14 of the 15 element copies failed, leaving the caller
     * with a half-populated target key it believed was valid. */
    return Crypto_KeyElementCopy(cryptoKeyId, CRYPTO_KE_MATERIAL,
                                 targetCryptoKeyId, CRYPTO_KE_MATERIAL);
}

Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId)
{
    whClientContext* ctx = wh_Autosar_KeystoreClient();
    uint16           keyId;

    if (ctx == NULL) {
        CRYPTO_DET_REPORT(CRYPTO_KEYSETVALID_SID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    keyId = wh_Autosar_ComposeKeyId(cryptoKeyId, CRYPTO_KE_MATERIAL);
    if (keyId == 0u) {
        CRYPTO_DET_REPORT(CRYPTO_KEYSETVALID_SID, CRYPTO_E_PARAM_KEY);
        return E_NOT_OK;
    }
    return (wh_Client_KeyCommit(ctx, keyId) == WH_ERROR_OK) ? E_OK : E_NOT_OK;
}
