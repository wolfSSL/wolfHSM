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
 * Hardware keystore front end: the records of the hardware keys the port
 * registered, and the calls into the port's keystore callback. See
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

#ifdef WOLFHSM_CFG_HWKEYSTORE_LOAD
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/wc_keystore.h"
#endif

int wh_HwKeystore_Init(whHwKeystoreContext*      context,
                       const whHwKeystoreConfig* config)
{
    if ((context == NULL) || (config == NULL)) {
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
    if ((context->cb != NULL) && (context->cb->Init != NULL)) {
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

static int _Lock(whHwKeystoreContext* context)
{
#ifdef WOLFHSM_CFG_THREADSAFE
    return wh_Lock_Acquire(&context->lock);
#else
    (void)context;
    return WH_ERROR_OK;
#endif
}

static int _Unlock(whHwKeystoreContext* context)
{
#ifdef WOLFHSM_CFG_THREADSAFE
    return wh_Lock_Release(&context->lock);
#else
    (void)context;
    return WH_ERROR_OK;
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

void wh_HwKeystore_KeyIdToRef(whKeyId keyId, uint8_t* ref)
{
    ref[0] = (uint8_t)(keyId >> 8);
    ref[1] = (uint8_t)keyId;
}

int wh_HwKeystore_KeyRefToId(const uint8_t* ref, uint32_t refSz)
{
    whKeyId keyId;

    if ((ref == NULL) || (refSz != WH_HWKEYSTORE_REF_SIZE)) {
        return 0;
    }
    keyId = (whKeyId)(((whKeyId)ref[0] << 8) | ref[1]);
    return WH_KEYID_ISHW(keyId) ? (int)WH_KEYID_ID(keyId) : 0;
}

/* Add a record for keyId, unless its ID is already registered */
static int _Add(whHwKeystoreContext* context, whKeyId keyId, whNvmFlags flags,
                uint16_t len)
{
    whHwKeystoreKey* entry;
    int              ret;

    if (!_Valid(context, keyId)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
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
                entry->flags = flags;
                entry->len   = len;
            }
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

int wh_HwKeystore_Register(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags flags, uint16_t len)
{
    /* A record with len 0 is an empty loadable key */
    if (len == 0) {
        return WH_ERROR_BADARGS;
    }
    /* Clients can't clear or replace a port key, or set or read it, so it is
     * also a trusted KEK */
    return _Add(context, keyId,
                (flags & WH_NVM_FLAGS_USAGE_ANY) | WH_NVM_FLAGS_NONDESTROYABLE |
                    WH_NVM_FLAGS_TRUSTED,
                len);
}

int wh_HwKeystore_CheckUse(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags flags, whKeyId* outKeyId)
{
    whHwKeystoreKey* entry;
    whNvmFlags       usage;
    int              ret;

    if (!_Valid(context, keyId) || (outKeyId == NULL)) {
        return WH_ERROR_BADARGS;
    }
    usage = flags & WH_NVM_FLAGS_USAGE_ANY;

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        entry = _Find(context, keyId);
        if ((entry == NULL) || (entry->len == 0)) {
            ret = WH_ERROR_NOTFOUND;
        }
        else if ((WH_KEYID_USER(entry->id) != WH_KEYUSER_GLOBAL) &&
                 (WH_KEYID_USER(entry->id) != WH_KEYID_USER(keyId))) {
            ret = WH_ERROR_ACCESS;
        }
        else if (((flags & WH_NVM_FLAGS_TRUSTED) != 0) &&
                 ((entry->flags & WH_NVM_FLAGS_TRUSTED) == 0)) {
            ret = WH_ERROR_ACCESS;
        }
        else if ((usage == 0) || ((entry->flags & usage) != usage)) {
            ret = WH_ERROR_USAGE;
        }
        else {
            *outKeyId = entry->id;
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

#ifdef WOLFHSM_CFG_HWKEYSTORE_LOAD

static int _PortImport(int devId, whKeyId keyId, const uint8_t* key,
                       uint16_t keySz)
{
    uint8_t ref[WH_HWKEYSTORE_REF_SIZE];

    wh_HwKeystore_KeyIdToRef(keyId, ref);
    return wc_KeyStore_ImportPlain(devId, ref, sizeof(ref), WC_KEYSTORE_KEY_AES,
                                   key, keySz, 0, NULL);
}

/* Mark a loadable key empty, keeping its ID */
static void _Empty(whHwKeystoreKey* entry)
{
    entry->id =
        WH_MAKE_KEYID(WH_KEYTYPE_HW, WH_KEYUSER_GLOBAL, WH_KEYID_ID(entry->id));
    entry->srcId = WH_KEYID_ERASED;
    entry->flags = 0;
    entry->len   = 0;
}

/* Clear the key in hardware and mark it empty. It is marked empty even if the
 * port fails, so the key can't be used again */
static int _Remove(int devId, whHwKeystoreKey* entry)
{
    uint8_t ref[WH_HWKEYSTORE_REF_SIZE];
    int     ret;

    wh_HwKeystore_KeyIdToRef(entry->id, ref);
    ret = wc_KeyStore_Delete(devId, ref, sizeof(ref), NULL);
    _Empty(entry);
    return ret;
}

int wh_HwKeystore_RegisterLoadable(whHwKeystoreContext* context,
                                   whKeyId              keyId)
{
    /* No owner until a client loads it */
    return _Add(context,
                WH_MAKE_KEYID(WH_KEYID_TYPE(keyId), WH_KEYUSER_GLOBAL,
                              WH_KEYID_ID(keyId)),
                0, 0);
}

int wh_HwKeystore_Load(whHwKeystoreContext* context, int devId,
                       whKeyId* inout_keyId, whKeyId srcId, whNvmFlags flags,
                       const uint8_t* key, uint16_t keySz)
{
    whHwKeystoreKey* entry = NULL;
    whKeyId          keyId;
    int              i;
    int              ret;

    if ((context == NULL) || (context->initialized == 0) ||
        (inout_keyId == NULL) || !WH_KEYID_ISHW(*inout_keyId) ||
        (key == NULL) || (keySz == 0)) {
        return WH_ERROR_BADARGS;
    }
    keyId = *inout_keyId;

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        if (WH_KEYID_ISERASED(keyId)) {
            /* Try each empty loadable key in turn */
            ret = WH_ERROR_NOSPACE;
            for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
                if ((context->keys[i].id == WH_KEYID_ERASED) ||
                    (context->keys[i].len != 0)) {
                    continue;
                }
                keyId = WH_MAKE_KEYID(WH_KEYTYPE_HW,
                                      WH_KEYID_USER(*inout_keyId),
                                      WH_KEYID_ID(context->keys[i].id));
                ret   = _PortImport(devId, keyId, key, keySz);
                if (ret == 0) {
                    entry = &context->keys[i];
                    break;
                }
            }
        }
        else {
            entry = _Find(context, keyId);
            if (entry == NULL) {
                ret = WH_ERROR_NOTFOUND;
            }
            /* Only the owner may replace a key, and never a port key */
            else if (((entry->flags & WH_NVM_FLAGS_NONDESTROYABLE) != 0) ||
                     ((entry->len != 0) &&
                      (WH_KEYID_USER(entry->id) != WH_KEYID_USER(keyId)))) {
                ret = WH_ERROR_ACCESS;
            }
            else {
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
        (void)_Unlock(context);
    } /* _Lock() */
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
    if (ret == WH_ERROR_OK) {
        entry = _Find(context, keyId);
        if ((entry == NULL) || (entry->len == 0)) {
            ret = WH_ERROR_NOTFOUND;
        }
        else if (((entry->flags & WH_NVM_FLAGS_NONDESTROYABLE) != 0) ||
                 (WH_KEYID_USER(entry->id) != WH_KEYID_USER(keyId))) {
            ret = WH_ERROR_ACCESS;
        }
        else {
            ret = _Remove(devId, entry);
        }
        (void)_Unlock(context);
    } /* _Lock() */
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
    if (ret == WH_ERROR_OK) {
        for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
            entry = &context->keys[i];
            if ((entry->len != 0) &&
                ((entry->flags & WH_NVM_FLAGS_NONDESTROYABLE) == 0) &&
                (WH_KEYID_USER(entry->id) == user)) {
                rc = _Remove(devId, entry);
                if (ret == WH_ERROR_OK) {
                    ret = rc;
                }
            }
        }
        (void)_Unlock(context);
    } /* _Lock() */
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
    if (ret == WH_ERROR_OK) {
        for (i = 0; i < WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS; i++) {
            entry = &context->keys[i];
            if ((entry->len != 0) && (entry->srcId == srcId)) {
                rc = _Remove(devId, entry);
                if (ret == WH_ERROR_OK) {
                    ret = rc;
                }
            }
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

int wh_HwKeystore_GetInfo(whHwKeystoreContext* context, whKeyId keyId,
                          whHwKeystoreInfo* info)
{
    whHwKeystoreKey* entry;
    int              ret;

    if (!_Valid(context, keyId) || (info == NULL)) {
        return WH_ERROR_BADARGS;
    }
    memset(info, 0, sizeof(*info));

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        entry = _Find(context, keyId);
        if (entry == NULL) {
            ret = WH_ERROR_NOTFOUND;
        }
        else if (entry->len != 0) {
            /* Hardware keys are only used as AES keys */
            info->keyType = WC_KEYSTORE_KEY_AES;
            info->keyBits = (uint32_t)entry->len * 8;
            info->flags   = entry->flags & WH_NVM_FLAGS_USAGE_ANY;
            info->owner   = WH_KEYID_USER(entry->id);
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

#endif /* WOLFHSM_CFG_HWKEYSTORE_LOAD */

#endif /* WOLFHSM_CFG_HWKEYSTORE */
