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
 * src/wh_portkey.c
 *
 * Port key front end: the records of the port keys the port
 * registered, and the calls into the port's keystore callback. See
 * wolfhsm/wh_portkey.h for the module description.
 */

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_PORTKEY

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_utils.h"
#include "wolfhsm/wh_portkey.h"

#ifdef WOLFHSM_CFG_PORTKEY_LOAD
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/wc_keystore.h"
#endif

int wh_PortKey_Init(whPortKeyContext* context, const whPortKeyConfig* config)
{
    if ((context == NULL) || (config == NULL)) {
        return WH_ERROR_BADARGS;
    }

    memset(context, 0, sizeof(*context));
    context->cb      = config->cb;
    context->context = config->context;

    /* Initialize the lock before the backend so that, on a backend Init
     * failure, teardown is a simple lock cleanup with no backend state to
     * undo. This keeps init and cleanup symmetric: wh_PortKey_Cleanup tears
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

int wh_PortKey_Cleanup(whPortKeyContext* context)
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

static int _Lock(whPortKeyContext* context)
{
#ifdef WOLFHSM_CFG_THREADSAFE
    return wh_Lock_Acquire(&context->lock);
#else
    (void)context;
    return WH_ERROR_OK;
#endif
}

static int _Unlock(whPortKeyContext* context)
{
#ifdef WOLFHSM_CFG_THREADSAFE
    return wh_Lock_Release(&context->lock);
#else
    (void)context;
    return WH_ERROR_OK;
#endif
}

/* A port keyId the front end can act on: TYPE=PORT and a non-zero ID */
static int _Valid(whPortKeyContext* context, whKeyId keyId)
{
    return (context != NULL) && (context->initialized != 0) &&
           WH_KEYID_ISPORT(keyId) && !WH_KEYID_ISERASED(keyId);
}

/* Table entry for the port key with the same ID field, or NULL */
static whPortKeyRecord* _Find(whPortKeyContext* context, whKeyId keyId)
{
    int i;

    for (i = 0; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
        if ((context->keys[i].id != WH_KEYID_ERASED) &&
            (WH_KEYID_ID(context->keys[i].id) == WH_KEYID_ID(keyId))) {
            return &context->keys[i];
        }
    }
    return NULL;
}

static whPortKeyRecord* _FindFree(whPortKeyContext* context)
{
    int i;

    for (i = 0; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
        if (context->keys[i].id == WH_KEYID_ERASED) {
            return &context->keys[i];
        }
    }
    return NULL;
}

void wh_PortKey_KeyIdToRef(whKeyId keyId, uint8_t* ref)
{
    ref[0] = (uint8_t)(keyId >> 8);
    ref[1] = (uint8_t)keyId;
}

int wh_PortKey_KeyRefToId(const uint8_t* ref, uint32_t refSz)
{
    whKeyId keyId;

    if ((ref == NULL) || (refSz != WH_PORTKEY_REF_SIZE)) {
        return 0;
    }
    keyId = (whKeyId)(((whKeyId)ref[0] << 8) | ref[1]);
    return WH_KEYID_ISPORT(keyId) ? (int)WH_KEYID_ID(keyId) : 0;
}

/* Add a record for keyId, unless its ID is already registered */
static int _Add(whPortKeyContext* context, whKeyId keyId, whNvmFlags flags,
                uint16_t len, uint8_t accessMode)
{
    whPortKeyRecord* entry;
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
                entry->id         = keyId;
                entry->srcId      = WH_KEYID_ERASED;
                entry->flags      = flags;
                entry->len        = len;
                entry->accessMode = accessMode;
            }
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

int wh_PortKey_RegisterFixed(whPortKeyContext* context, whKeyId keyId,
                             whNvmFlags flags, uint16_t len,
                             uint32_t accessMode)
{
    /* A record with len 0 is an empty loadable key */
    if ((len == 0) || ((accessMode != WH_PORTKEY_ACCESS_BY_REF) &&
                       (accessMode != WH_PORTKEY_ACCESS_BY_VALUE))) {
        return WH_ERROR_BADARGS;
    }
    /* The port supplies a by-value key's bytes on each use */
    if ((accessMode == WH_PORTKEY_ACCESS_BY_VALUE) &&
        ((context == NULL) || (context->cb == NULL) ||
         (context->cb->GetKey == NULL))) {
        return WH_ERROR_BADARGS;
    }
    /* Clients can't clear or replace a fixed key, or set or read it, so it is
     * also a trusted KEK */
    return _Add(context, keyId,
                (flags & WH_NVM_FLAGS_USAGE_ANY) | WH_NVM_FLAGS_NONDESTROYABLE |
                    WH_NVM_FLAGS_TRUSTED,
                len, (uint8_t)accessMode);
}

/* Check a request against the key's record. Call with the lock held */
static int _Check(whPortKeyContext* context, whKeyId keyId, whNvmFlags flags,
                  whPortKeyRecord** outEntry)
{
    whPortKeyRecord* entry = _Find(context, keyId);
    whNvmFlags       usage = flags & WH_NVM_FLAGS_USAGE_ANY;
    int              ret   = WH_ERROR_OK;

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
        *outEntry = entry;
    }
    return ret;
}

/* Copy a by-value key's bytes from the port. Call with the lock held */
static int _GetKey(whPortKeyContext* context, const whPortKeyRecord* entry,
                   uint8_t* out, uint16_t* inout_len)
{
    uint16_t len = *inout_len;
    int      ret;

    if (len < entry->len) {
        return WH_ERROR_BUFFER_SIZE;
    }
    if ((context->cb == NULL) || (context->cb->GetKey == NULL)) {
        return WH_ERROR_ABORTED;
    }

    ret = context->cb->GetKey(context->context, entry->id, out, &len);
    if (ret == WH_ERROR_NOTREADY) {
        /* A blocking client would wait for a response forever */
        ret = WH_ERROR_ABORTED;
    }
    else if ((ret == WH_ERROR_OK) && (len != entry->len)) {
        /* Not the key the port registered */
        ret = WH_ERROR_ABORTED;
    }
    if (ret == WH_ERROR_OK) {
        *inout_len = len;
    }
    else {
        /* The port may have written part of a key */
        wh_Utils_ForceZero(out, *inout_len);
    }
    return ret;
}

int wh_PortKey_CheckUse(whPortKeyContext* context, whKeyId keyId,
                        whNvmFlags flags, whKeyId* outKeyId)
{
    whPortKeyRecord* entry = NULL;
    int              ret;

    if (!_Valid(context, keyId) || (outKeyId == NULL)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        ret = _Check(context, keyId, flags, &entry);
        if (ret == WH_ERROR_OK) {
            *outKeyId = entry->id;
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

int wh_PortKey_Resolve(whPortKeyContext* context, whKeyId keyId,
                       whNvmFlags flags, whKeyId* outKeyId, uint8_t* key,
                       uint16_t* inout_keySz)
{
    whPortKeyRecord* entry = NULL;
    int              ret;

    if (!_Valid(context, keyId) || (outKeyId == NULL) || (key == NULL) ||
        (inout_keySz == NULL)) {
        return WH_ERROR_BADARGS;
    }
    *outKeyId = WH_KEYID_ERASED;

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        ret = _Check(context, keyId, flags, &entry);
        if ((ret == WH_ERROR_OK) &&
            (entry->accessMode == WH_PORTKEY_ACCESS_BY_VALUE)) {
            ret = _GetKey(context, entry, key, inout_keySz);
        }
        else if (ret == WH_ERROR_OK) {
            /* Accessed by reference, so the bytes stay in the port */
            *outKeyId    = entry->id;
            *inout_keySz = 0;
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

int wh_PortKey_Read(whPortKeyContext* context, whKeyId keyId, whNvmFlags flags,
                    uint8_t* out, uint16_t* inout_len)
{
    whKeyId refKeyId = WH_KEYID_ERASED;
    int     ret;

    ret = wh_PortKey_Resolve(context, keyId, flags, &refKeyId, out, inout_len);
    if ((ret == WH_ERROR_OK) && (refKeyId != WH_KEYID_ERASED)) {
        ret = WH_ERROR_ACCESS;
    }
    return ret;
}

#ifdef WOLFHSM_CFG_PORTKEY_LOAD

static int _PortImport(int devId, whKeyId keyId, const uint8_t* key,
                       uint16_t keySz)
{
    uint8_t ref[WH_PORTKEY_REF_SIZE];

    wh_PortKey_KeyIdToRef(keyId, ref);
    return wc_KeyStore_ImportPlain(devId, ref, sizeof(ref), WC_KEYSTORE_KEY_AES,
                                   key, keySz, 0, NULL);
}

/* Mark a loadable key empty, keeping its ID */
static void _Empty(whPortKeyRecord* entry)
{
    entry->id    = WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYUSER_GLOBAL,
                                 WH_KEYID_ID(entry->id));
    entry->srcId = WH_KEYID_ERASED;
    entry->flags = 0;
    entry->len   = 0;
}

/* Clear the key through the port and mark it empty. It is marked empty even if
 * the port fails, so the key can't be used again */
static int _Remove(int devId, whPortKeyRecord* entry)
{
    uint8_t ref[WH_PORTKEY_REF_SIZE];
    int     ret;

    wh_PortKey_KeyIdToRef(entry->id, ref);
    ret = wc_KeyStore_Delete(devId, ref, sizeof(ref), NULL);
    _Empty(entry);
    return ret;
}

int wh_PortKey_RegisterLoadable(whPortKeyContext* context, whKeyId keyId)
{
    /* No owner until a client loads it. Loaded keys are accessed by
     * reference */
    return _Add(context,
                WH_MAKE_KEYID(WH_KEYID_TYPE(keyId), WH_KEYUSER_GLOBAL,
                              WH_KEYID_ID(keyId)),
                0, 0, WH_PORTKEY_ACCESS_BY_REF);
}

int wh_PortKey_Load(whPortKeyContext* context, int devId, whKeyId* inout_keyId,
                    whKeyId srcId, whNvmFlags flags, const uint8_t* key,
                    uint16_t keySz)
{
    whPortKeyRecord* entry = NULL;
    whKeyId          keyId;
    int              i;
    int              ret;

    if ((context == NULL) || (context->initialized == 0) ||
        (inout_keyId == NULL) || !WH_KEYID_ISPORT(*inout_keyId) ||
        (key == NULL) || (keySz == 0)) {
        return WH_ERROR_BADARGS;
    }
    keyId = *inout_keyId;

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        if (WH_KEYID_ISERASED(keyId)) {
            /* Try each empty loadable key in turn */
            ret = WH_ERROR_NOSPACE;
            for (i = 0; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
                if ((context->keys[i].id == WH_KEYID_ERASED) ||
                    (context->keys[i].len != 0)) {
                    continue;
                }
                keyId =
                    WH_MAKE_KEYID(WH_KEYTYPE_PORT, WH_KEYID_USER(*inout_keyId),
                                  WH_KEYID_ID(context->keys[i].id));
                ret = _PortImport(devId, keyId, key, keySz);
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
            /* Only the owner may replace a key, and never a fixed key */
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

int wh_PortKey_Clear(whPortKeyContext* context, int devId, whKeyId keyId)
{
    whPortKeyRecord* entry;
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

int wh_PortKey_ClearAll(whPortKeyContext* context, int devId, uint16_t user)
{
    whPortKeyRecord* entry;
    int              i;
    int              rc;
    int              ret;

    if ((context == NULL) || (context->initialized == 0)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        for (i = 0; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
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

int wh_PortKey_ClearSource(whPortKeyContext* context, int devId, whKeyId srcId)
{
    whPortKeyRecord* entry;
    int              i;
    int              rc;
    int              ret;

    if ((context == NULL) || (context->initialized == 0) ||
        (srcId == WH_KEYID_ERASED)) {
        return WH_ERROR_BADARGS;
    }

    ret = _Lock(context);
    if (ret == WH_ERROR_OK) {
        for (i = 0; i < WOLFHSM_CFG_PORTKEY_MAX_KEYS; i++) {
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

int wh_PortKey_GetInfo(whPortKeyContext* context, whKeyId keyId,
                       whPortKeyInfo* info)
{
    whPortKeyRecord* entry;
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
            /* Port keys are only used as AES keys */
            info->keyType = WC_KEYSTORE_KEY_AES;
            info->keyBits = (uint32_t)entry->len * 8;
            info->flags   = entry->flags & WH_NVM_FLAGS_USAGE_ANY;
            info->owner   = WH_KEYID_USER(entry->id);
        }
        (void)_Unlock(context);
    } /* _Lock() */
    return ret;
}

#endif /* WOLFHSM_CFG_PORTKEY_LOAD */

#endif /* WOLFHSM_CFG_PORTKEY */
