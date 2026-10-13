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
 * src/wh_hwkeystore.c
 *
 * Hardware keystore front-end implementation. Dispatches to a backend callback
 * table (whHwKeystoreCb) with argument validation and lock serialization. See
 * wolfhsm/wh_hwkeystore.h for the module description.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_HWKEYSTORE

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_hwkeystore.h"

#ifdef WOLFHSM_CFG_HWKEYSTORE_CRYPTO
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/wc_keystore.h"
#endif

int wh_HwKeystore_Init(whHwKeystoreContext*      context,
                       const whHwKeystoreConfig* config)
{
    if ((context == NULL) || (config == NULL) || (config->cb == NULL) ||
        (config->cb->GetKey == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->cb      = config->cb;
    context->context = config->context;

    /* Initialize the lock before the backend so that, on a backend Init
     * failure, teardown is a simple lock cleanup with no backend state to
     * undo. This keeps init and cleanup symmetric: wh_HwKeystore_Cleanup tears
     * down the backend then the lock, the reverse of the order here */
#ifdef WOLFHSM_CFG_THREADSAFE
    {
        int rc = wh_Lock_Init(&context->lock, config->lockConfig);
        if (rc != WH_ERROR_OK) {
            memset(context, 0, sizeof(*context));
            return rc;
        }
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    /* Initialize the backend if it provides an Init callback. Done last so it
     * is the only fallible step after the lock: on failure, undo the lock so a
     * successful backend Init is never left without a paired Cleanup */
    if (context->cb->Init != NULL) {
        int rc = context->cb->Init(context->context, config->config);
        if (rc != WH_ERROR_OK) {
#ifdef WOLFHSM_CFG_THREADSAFE
            (void)wh_Lock_Cleanup(&context->lock);
#endif /* WOLFHSM_CFG_THREADSAFE */
            memset(context, 0, sizeof(*context));
            return rc;
        }
    }

    context->initialized = 1;
    return WH_ERROR_OK;
}

int wh_HwKeystore_Cleanup(whHwKeystoreContext* context)
{
    int rc = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    /* Capture the backend teardown result but always finish releasing the lock
     * and zeroing the context, then surface the backend error. */
    if ((context->cb != NULL) && (context->cb->Cleanup != NULL)) {
        rc = context->cb->Cleanup(context->context);
    }

#ifdef WOLFHSM_CFG_THREADSAFE
    {
        /* Only let a lock-release failure surface when the backend cleanup
         * itself succeeded, so a real backend error is not hidden */
        int relRc = wh_Lock_Cleanup(&context->lock);
        if (rc == WH_ERROR_OK) {
            rc = relRc;
        }
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    memset(context, 0, sizeof(*context));
    return rc;
}

int wh_HwKeystore_GetKey(whHwKeystoreContext* context, whKeyId keyId,
                         uint8_t* out, uint16_t* inout_len)
{
    int rc;

    if ((context == NULL) || (context->initialized == 0) ||
        (context->cb == NULL) || (context->cb->GetKey == NULL) ||
        (out == NULL) || (inout_len == NULL)) {
        return WH_ERROR_BADARGS;
    }

#ifdef WOLFHSM_CFG_THREADSAFE
    rc = wh_Lock_Acquire(&context->lock);
    if (rc != WH_ERROR_OK) {
        return rc;
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    rc = context->cb->GetKey(context->context, keyId, out, inout_len);

#ifdef WOLFHSM_CFG_THREADSAFE
    {
        /* Preserve the backend result; only surface a release failure when the
         * GetKey call itself succeeded so a real lock error is not hidden */
        int relRc = wh_Lock_Release(&context->lock);
        if (rc == WH_ERROR_OK) {
            rc = relRc;
        }
    }
#endif /* WOLFHSM_CFG_THREADSAFE */

    return rc;
}

#ifdef WOLFHSM_CFG_HWKEYSTORE_CRYPTO

static int _Lock(whHwKeystoreContext* context)
{
#ifdef WOLFHSM_CFG_THREADSAFE
    return wh_Lock_Acquire(&context->lock);
#else
    (void)context;
    return WH_ERROR_OK;
#endif
}

static void _Unlock(whHwKeystoreContext* context)
{
#ifdef WOLFHSM_CFG_THREADSAFE
    (void)wh_Lock_Release(&context->lock);
#else
    (void)context;
#endif
}

/* A hardware keyId the front end can act on: TYPE=HW and a non-zero ID */
static int _Valid(whHwKeystoreContext* context, whKeyId keyId)
{
    return (context != NULL) && (context->initialized != 0) &&
           WH_KEYID_ISHW(keyId) && !WH_KEYID_ISERASED(keyId);
}

/* Table entry for the hardware key with the same ID field, or NULL */
static whHwKeystoreKey* _Find(whHwKeystoreContext* context, whKeyId keyId)
{
    int i;

    for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
        if ((context->keys[i].id != WH_KEYID_ERASED) &&
            (WH_KEYID_ID(context->keys[i].id) == WH_KEYID_ID(keyId))) {
            return &context->keys[i];
        }
    }
    return NULL;
}

static whHwKeystoreKey* _FindFree(whHwKeystoreContext* context)
{
    int i;

    for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
        if (context->keys[i].id == WH_KEYID_ERASED) {
            return &context->keys[i];
        }
    }
    return NULL;
}

static int _PortImport(int devId, whKeyId keyId, const uint8_t* key,
                       uint16_t keySz)
{
    uint8_t ref[WH_HWKEYSTORE_REF_SIZE];

    wh_HwKeystore_KeyRef(keyId, ref);
    return wc_KeyStore_ImportPlain(devId, ref, sizeof(ref), WC_KEYSTORE_KEY_AES,
                                   key, keySz, 0, NULL);
}

static int _PortInfo(int devId, whKeyId keyId, word32* keyType, word32* keyBits)
{
    uint8_t ref[WH_HWKEYSTORE_REF_SIZE];
    word32  attrs = 0;

    wh_HwKeystore_KeyRef(keyId, ref);
    return wc_KeyStore_GetInfo(devId, ref, sizeof(ref), keyType, keyBits,
                               &attrs, NULL);
}

/* Clear the key in hardware, then free its entry */
static int _Remove(int devId, whHwKeystoreKey* entry)
{
    uint8_t ref[WH_HWKEYSTORE_REF_SIZE];
    int     ret;

    wh_HwKeystore_KeyRef(entry->id, ref);
    ret = wc_KeyStore_Delete(devId, ref, sizeof(ref), NULL);
    if (ret == 0) {
        memset(entry, 0, sizeof(*entry));
    }
    return ret;
}

void wh_HwKeystore_KeyRef(whKeyId keyId, uint8_t* ref)
{
    ref[0] = (uint8_t)(keyId >> 8);
    ref[1] = (uint8_t)keyId;
}

int wh_HwKeystore_Register(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags flags, uint16_t len)
{
    whHwKeystoreKey* entry;
    int              ret;

    if (!_Valid(context, keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    if (_Find(context, keyId) != NULL) {
        ret = WH_ERROR_ACCESS;
    }
    else {
        entry = _FindFree(context);
        if (entry == NULL) {
            ret = WH_ERROR_NOSPACE;
        }
        else {
            entry->id    = keyId;
            entry->srcId = WH_KEYID_ERASED;
            entry->flags =
                (flags & WH_NVM_FLAGS_USAGE_ANY) | WH_NVM_FLAGS_NONDESTROYABLE;
            entry->len = len;
        }
    }
    _Unlock(context);
    return ret;
}

int wh_HwKeystore_Load(whHwKeystoreContext* context, int devId,
                       whKeyId* inout_keyId, whKeyId srcId, whNvmFlags flags,
                       const uint8_t* key, uint16_t keySz)
{
    whHwKeystoreKey* entry = NULL;
    whKeyId          keyId;
    whKeyId          cand;
    word32           keyType;
    word32           keyBits;
    int              id;
    int              ret;

    if ((context == NULL) || (context->initialized == 0) ||
        (inout_keyId == NULL) || !WH_KEYID_ISHW(*inout_keyId) ||
        (key == NULL) || (keySz == 0)) {
        return WH_ERROR_BADARGS;
    }
    keyId = *inout_keyId;

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }

    if (WH_KEYID_ISERASED(keyId)) {
        /* Try each hardware key the port reports empty, in ID order */
        entry = _FindFree(context);
        ret   = WH_ERROR_NOSPACE;
        for (id = 1; (entry != NULL) && (id <= WH_KEYID_IDMAX); id++) {
            cand = WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYID_USER(keyId), id);
            if ((_Find(context, cand) != NULL) ||
                (_PortInfo(devId, cand, &keyType, &keyBits) != 0) ||
                (keyType != WC_KEYSTORE_KEY_NONE)) {
                continue;
            }
            ret = _PortImport(devId, cand, key, keySz);
            if (ret == 0) {
                keyId = cand;
                break;
            }
        }
    }
    else {
        entry = _Find(context, keyId);
        if (entry != NULL) {
            /* Only the owner may replace a key, and never a port key */
            if (((entry->flags & WH_NVM_FLAGS_NONDESTROYABLE) != 0) ||
                (WH_KEYID_USER(entry->id) != WH_KEYID_USER(keyId))) {
                ret = WH_ERROR_ACCESS;
            }
        }
        else {
            entry = _FindFree(context);
            if (entry == NULL) {
                ret = WH_ERROR_NOSPACE;
            }
        }
        if (ret == WH_ERROR_OK) {
            ret = _PortImport(devId, keyId, key, keySz);
        }
    }

    if (ret == 0) {
        entry->id    = keyId;
        entry->srcId = srcId;
        entry->flags = flags & WH_NVM_FLAGS_USAGE_ANY;
        entry->len   = keySz;
        *inout_keyId = keyId;
    }
    _Unlock(context);
    return ret;
}

int wh_HwKeystore_Clear(whHwKeystoreContext* context, int devId, whKeyId keyId)
{
    whHwKeystoreKey* entry;
    int              ret;

    if (!_Valid(context, keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    entry = _Find(context, keyId);
    if (entry == NULL) {
        ret = WH_ERROR_NOTFOUND;
    }
    else if (((entry->flags & WH_NVM_FLAGS_NONDESTROYABLE) != 0) ||
             (WH_KEYID_USER(entry->id) != WH_KEYID_USER(keyId))) {
        ret = WH_ERROR_ACCESS;
    }
    else {
        ret = _Remove(devId, entry);
    }
    _Unlock(context);
    return ret;
}

int wh_HwKeystore_ClearAll(whHwKeystoreContext* context, int devId,
                           uint16_t user)
{
    whHwKeystoreKey* entry;
    int              i;
    int              rc;
    int              ret;

    if ((context == NULL) || (context->initialized == 0)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
        entry = &context->keys[i];
        if ((entry->id != WH_KEYID_ERASED) &&
            ((entry->flags & WH_NVM_FLAGS_NONDESTROYABLE) == 0) &&
            (WH_KEYID_USER(entry->id) == user)) {
            rc = _Remove(devId, entry);
            if (ret == WH_ERROR_OK) {
                ret = rc;
            }
        }
    }
    _Unlock(context);
    return ret;
}

int wh_HwKeystore_ClearSource(whHwKeystoreContext* context, int devId,
                              whKeyId srcId)
{
    whHwKeystoreKey* entry;
    int              i;
    int              rc;
    int              ret;

    if ((context == NULL) || (context->initialized == 0) ||
        (srcId == WH_KEYID_ERASED)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
        entry = &context->keys[i];
        if ((entry->id != WH_KEYID_ERASED) && (entry->srcId == srcId)) {
            rc = _Remove(devId, entry);
            if (ret == WH_ERROR_OK) {
                ret = rc;
            }
        }
    }
    _Unlock(context);
    return ret;
}

int wh_HwKeystore_CheckUse(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags usage, whKeyId* outKeyId)
{
    whHwKeystoreKey* entry;
    int              ret;

    if (!_Valid(context, keyId) || (outKeyId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    usage &= WH_NVM_FLAGS_USAGE_ANY;

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    entry = _Find(context, keyId);
    if (entry == NULL) {
        ret = WH_ERROR_NOTFOUND;
    }
    else if ((WH_KEYID_USER(entry->id) != WH_KEYUSER_GLOBAL) &&
             (WH_KEYID_USER(entry->id) != WH_KEYID_USER(keyId))) {
        ret = WH_ERROR_ACCESS;
    }
    else if ((usage == 0) || ((entry->flags & usage) != usage)) {
        ret = WH_ERROR_USAGE;
    }
    else {
        *outKeyId = entry->id;
    }
    _Unlock(context);
    return ret;
}

int wh_HwKeystore_GetInfo(whHwKeystoreContext* context, int devId,
                          whKeyId keyId, whHwKeystoreInfo* info)
{
    whHwKeystoreKey* entry;
    word32           keyType = 0;
    word32           keyBits = 0;
    int              ret;

    if (!_Valid(context, keyId) || (info == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memset(info, 0, sizeof(*info));

    ret = _Lock(context);
    if (ret != WH_ERROR_OK) {
        return ret;
    }
    ret = _PortInfo(devId, keyId, &keyType, &keyBits);
    if (ret == 0) {
        info->keyType = keyType;
        info->keyBits = keyBits;
        entry         = _Find(context, keyId);
        if (entry != NULL) {
            info->flags = entry->flags & WH_NVM_FLAGS_USAGE_ANY;
            info->owner = WH_KEYID_USER(entry->id);
        }
    }
    _Unlock(context);
    return ret;
}

#endif /* WOLFHSM_CFG_HWKEYSTORE_CRYPTO */

#endif /* WOLFHSM_CFG_HWKEYSTORE */
