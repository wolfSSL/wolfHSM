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
 * wolfhsm/wh_portkey.h
 *
 * Port key front end. Lets clients use keys that the port manages, such as
 * key slots in a crypto accelerator or keys in OTP.
 *
 * At startup the port registers every port key clients may name, and the
 * server keeps a record of each: its owner, the usage flags it allows and,
 * for a key a client loaded, the keystore key it came from. Each request that
 * names a port key is checked against its record. The server then passes
 * the key to wolfCrypt by reference (WOLF_PRIVATE_KEY_ID) and the port's
 * crypto callback runs the operation. For a key accessed by value, the server
 * instead gets the key's bytes from the port and runs the operation as it does
 * with a keystore key.
 *
 * The port puts its own keys in place and registers them as fixed keys with
 * wh_PortKey_RegisterFixed(), giving each an access mode: by reference, or by
 * value if the port exports its bytes. With WOLFHSM_CFG_PORTKEY_LOAD, the port
 * can also register empty loadable keys with wh_PortKey_RegisterLoadable().
 * Clients load keystore keys into those, and they are accessed by reference.
 *
 * The server reaches the port through the WC_ALGO_TYPE_KEYSTORE requests of
 * the port's crypto callback: WC_KEYSTORE_EXPORT_PLAIN for a by-value key's
 * bytes, and WC_KEYSTORE_IMPORT_PLAIN and WC_KEYSTORE_DELETE to load and clear
 * a loadable key. An import currently does not use the key type field
 * (WC_KEYSTORE_KEY_NONE) since the port knows what each of its keys holds based
 * on its ID.
 *
 * A whPortKeyContext is owned by the application, initialized once with
 * wh_PortKey_Init(), and bound to one or more server contexts through the
 * optional portKey member of whServerConfig. With WOLFHSM_CFG_THREADSAFE,
 * the embedded lock protects the records and the calls into the port's
 * keystore callback.
 */

#ifndef WOLFHSM_WH_PORTKEY_H_
#define WOLFHSM_WH_PORTKEY_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_PORTKEY

#include <stdint.h>

#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_common.h"

#ifdef WOLFHSM_CFG_THREADSAFE
#include "wolfhsm/wh_lock.h"
#endif

/**
 * Optional backend hooks. Each receives the backend's opaque context pointer
 * from whPortKeyConfig and returns WH_ERROR_OK on success.
 */

/** Set up the backend - called once from wh_PortKey_Init() */
typedef int (*whPortKeyInitCb)(void* context, const void* config);

/** Tear down the backend - called once from wh_PortKey_Cleanup() */
typedef int (*whPortKeyCleanupCb)(void* context);

/** Backend hook table. Any hook may be NULL */
typedef struct whPortKeyCb_t {
    whPortKeyInitCb    Init;    /* Set up the backend (optional) */
    whPortKeyCleanupCb Cleanup; /* Tear down the backend (optional) */
} whPortKeyCb;

/* Size of the key reference wolfCrypt passes to the port for a port key:
 * the server keyId, big-endian. Ports read it with wh_PortKey_KeyRefToId()
 */
#define WH_PORTKEY_REF_SIZE 2

/* Access mode of a fixed key: how the server reaches it */
enum WH_PORTKEY_ACCESS_ENUM {
    /* wolfCrypt gets a key reference, and the port's crypto callback runs the
     * operation. The bytes stay in the port */
    WH_PORTKEY_ACCESS_BY_REF = 0,
    /* The port exports the bytes on each use, and the server runs the
     * operation as it does with a keystore key */
    WH_PORTKEY_ACCESS_BY_VALUE = 1,
};

/* A port key the port registered. Fixed keys are always NONDESTROYABLE and
 * TRUSTED */
typedef struct whPortKeyRecord_t {
    whKeyId    id;    /* TYPE=PORT, USER=owner (0 if shared), ERASED if free */
    whKeyId    srcId; /* Keystore key it was loaded from, or ERASED */
    whNvmFlags flags; /* Usage and policy flags (WH_NVM_FLAGS_*) */
    uint16_t   len;   /* Key size in bytes, 0 if nothing is loaded */
    uint8_t    accessMode; /* WH_PORTKEY_ACCESS_*. Loaded keys are BY_REF */
    uint8_t    WH_PAD[1];
} whPortKeyRecord;

/* Context structure associated with a port key front end */
typedef struct whPortKeyContext_t {
    const whPortKeyCb* cb;      /* Backend hooks, or NULL */
    void*              context; /* Opaque backend context */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLock lock; /* Lock protecting the records */
#endif
    whPortKeyRecord keys[WOLFHSM_CFG_PORTKEY_MAX_KEYS];
    int             initialized; /* 1 if initialized, 0 otherwise */
    uint8_t         WH_PAD[4];
} whPortKeyContext;

/* Configuration structure associated with a port key front end */
typedef struct whPortKeyConfig_t {
    const whPortKeyCb* cb;      /* Backend hooks (optional) */
    void*              context; /* Opaque backend context (passed to hooks) */
    const void*        config;  /* Backend-specific config (passed to Init) */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLockConfig* lockConfig; /* Lock configuration (NULL for no-op locking) */
#endif
} whPortKeyConfig;

/**
 * @brief Initialize a port key front end.
 *
 * Starts with no port keys recorded, initializes the embedded lock, and
 * calls the backend Init hook if there is one. Must be called in a
 * single-threaded context before the context is bound to any server.
 *
 * @param[in] context Pointer to the port key context
 * @param[in] config Pointer to the configuration. config->cb may be NULL
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS if context or config is
 *         NULL, or the error from the backend Init hook or lock setup
 */
int wh_PortKey_Init(whPortKeyContext* context, const whPortKeyConfig* config);

/**
 * @brief Cleanup a port key front end.
 *
 * Calls the backend Cleanup hook if there is one, cleans up the embedded lock
 * and zeros the context. Must only be called when no servers are using it.
 *
 * @param[in] context Pointer to the port key context
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS if context is NULL, or
 *         the error from the backend Cleanup hook or the lock
 */
int wh_PortKey_Cleanup(whPortKeyContext* context);

/*
 * keyId arguments are server keyIds with TYPE=PORT: the ID field names the
 * port key and the USER field is the client making the call (0 for a
 * shared key). A key loaded by a client can be used and cleared only by that
 * client, unless it was loaded as shared. A fixed key is shared if its USER
 * field is 0, otherwise only that client can use it, and clients cannot clear
 * it. devId is the wolfCrypt device whose crypto callback implements
 * WC_ALGO_TYPE_KEYSTORE.
 */

/**
 * @brief Write the wolfCrypt key reference for a port key.
 *
 * @param[in] keyId Server keyId of the port key
 * @param[out] ref Buffer of WH_PORTKEY_REF_SIZE bytes
 */
void wh_PortKey_KeyIdToRef(whKeyId keyId, uint8_t* ref);

/**
 * @brief Read the port key's ID from a wolfCrypt key reference.
 *
 * Returns only the ID field of the keyId that wh_PortKey_KeyIdToRef()
 * wrote, not its type or owner. The port's crypto callback uses it to find the
 * port key an operation names, so it never decodes a key reference itself.
 *
 * @param[in] ref Key reference, such as aes->id or a keystore request's keyRef
 * @param[in] refSz Size of ref in bytes
 * @return int The ID (1 to 255), or 0 if ref is not a port key reference
 */
int wh_PortKey_KeyRefToId(const uint8_t* ref, uint32_t refSz);

/**
 * @brief Register a fixed key, one the port put in place itself, for example
 * at boot.
 *
 * Clients cannot clear or replace the key, and it is a trusted KEK: no client
 * can set or read it. With WH_PORTKEY_ACCESS_BY_VALUE, the port exports the
 * key's bytes on each use.
 *
 * @param[in] context Pointer to an initialized port key context
 * @param[in] keyId Server keyId of the port key. USER is the client that
 *            may use it, or 0 to share it with all clients
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the key allows
 * @param[in] len Key size in bytes, not 0
 * @param[in] accessMode WH_PORTKEY_ACCESS_BY_REF or WH_PORTKEY_ACCESS_BY_VALUE
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS for an unknown access
 *         mode, WH_ERROR_ACCESS if the key is already registered,
 *         WH_ERROR_NOSPACE if no record is free
 */
int wh_PortKey_RegisterFixed(whPortKeyContext* context, whKeyId keyId,
                             whNvmFlags flags, uint16_t len,
                             uint32_t accessMode);

/**
 * @brief Check that the caller may use a port key.
 *
 * @param[in] keyId Port key, with the caller in the USER field
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the operation needs (all of them),
 *            plus WH_NVM_FLAGS_TRUSTED to require a key no client can set
 * @param[out] outKeyId Recorded keyId, for wh_PortKey_KeyIdToRef()
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key isn't
 *         registered or nothing is loaded in it, WH_ERROR_ACCESS if another
 *         client owns it or it is not trusted when that was required,
 *         WH_ERROR_USAGE if it does not allow the usage
 */
int wh_PortKey_CheckUse(whPortKeyContext* context, whKeyId keyId,
                        whNvmFlags flags, whKeyId* outKeyId);

/**
 * @brief Check that the caller may use a port key, and get the key in the
 * form the server uses it.
 *
 * Checks the key as wh_PortKey_CheckUse() does. A by-value key's bytes are
 * then exported from the port into key, and *outKeyId is set to
 * WH_KEYID_ERASED. Any other key is accessed by reference: *outKeyId is set to
 * the recorded keyId and *inout_keySz to 0.
 *
 * The export runs with the lock held, so the port must not call wh_PortKey_*
 * functions from it.
 *
 * @param[in] devId wolfCrypt device that exports by-value keys
 * @param[in] keyId Port key, with the caller in the USER field
 * @param[in] flags As for wh_PortKey_CheckUse()
 * @param[out] outKeyId Recorded keyId, or WH_KEYID_ERASED for a by-value key
 * @param[out] key Buffer for a by-value key's bytes
 * @param[in,out] inout_keySz In: size of key. Out: key size, or 0
 * @return int As for wh_PortKey_CheckUse(), or WH_ERROR_BUFFER_SIZE if the key
 *         doesn't fit, WH_ERROR_NOTFOUND if no device exports it,
 *         WH_ERROR_ABORTED if the port exported a key of the wrong size, or the
 *         port's error, with WH_ERROR_NOTREADY returned as WH_ERROR_ABORTED
 */
int wh_PortKey_Resolve(whPortKeyContext* context, int devId, whKeyId keyId,
                       whNvmFlags flags, whKeyId* outKeyId, uint8_t* key,
                       uint16_t* inout_keySz);

/**
 * @brief Copy the bytes of a by-value key, for server-side code such as a
 * custom callback.
 *
 * Checks the key as wh_PortKey_CheckUse() does first. The bytes must never be
 * sent to a client.
 *
 * @param[in] devId wolfCrypt device that exports by-value keys
 * @param[in] keyId Port key, with the caller in the USER field
 * @param[in] flags As for wh_PortKey_CheckUse()
 * @param[out] out Buffer for the key's bytes
 * @param[in,out] inout_len In: size of out. Out: key size
 * @return int As for wh_PortKey_Resolve(), or WH_ERROR_ACCESS for a key
 *         accessed by reference, whose bytes stay in the port
 */
int wh_PortKey_Read(whPortKeyContext* context, int devId, whKeyId keyId,
                    whNvmFlags flags, uint8_t* out, uint16_t* inout_len);

#ifdef WOLFHSM_CFG_PORTKEY_LOAD
/**
 * @brief Register a port key that clients may load.
 *
 * The key starts empty. Clients load keystore keys into it and clear it again.
 *
 * @param[in] context Pointer to an initialized port key context
 * @param[in] keyId Server keyId of the port key. USER is ignored
 * @return int WH_ERROR_OK on success, WH_ERROR_ACCESS if the key is already
 *         registered, WH_ERROR_NOSPACE if no record is free
 */
int wh_PortKey_RegisterLoadable(whPortKeyContext* context, whKeyId keyId);

/**
 * @brief Load key material into a loadable port key through the port.
 *
 * The owner can load again to replace its key. If that load fails, the key it
 * held is cleared, since the port may have changed it.
 *
 * @param[in] context Pointer to an initialized port key context
 * @param[in] devId wolfCrypt device that implements the keystore callback
 * @param[in] keyId Port key to load
 * @param[in] srcId Keystore key the material came from, or WH_KEYID_ERASED
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the key allows
 * @param[in] key Key material
 * @param[in] keySz Key size in bytes
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key isn't
 *         registered, WH_ERROR_ACCESS if it is a fixed key or another client
 *         owns it, or the port's error, with WH_ERROR_NOTREADY returned as
 *         WH_ERROR_ABORTED
 */
int wh_PortKey_Load(whPortKeyContext* context, int devId, whKeyId keyId,
                    whKeyId srcId, whNvmFlags flags, const uint8_t* key,
                    uint16_t keySz);

/*
 * The clear functions mark the key empty even if the port fails to clear the
 * key, so the key can't be used again. They then return the port's error, with
 * WH_ERROR_NOTREADY returned as WH_ERROR_ABORTED.
 */

/**
 * @brief Clear a port key the caller owns.
 *
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key is not
 *         loaded, WH_ERROR_ACCESS if the caller does not own it, or the
 *         port's error
 */
int wh_PortKey_Clear(whPortKeyContext* context, int devId, whKeyId keyId);

/**
 * @brief Clear every port key owned by a client.
 *
 * @param[in] user Client ID. Fixed keys are never cleared
 * @return int WH_ERROR_OK on success, or the first error from the port
 */
int wh_PortKey_ClearAll(whPortKeyContext* context, int devId, uint16_t user);

/**
 * @brief Clear every port key loaded from a keystore key, for example
 * when that key is erased or revoked.
 *
 * @return int WH_ERROR_OK on success, or the first error from the port
 */
int wh_PortKey_ClearSource(whPortKeyContext* context, int devId, whKeyId srcId);

/**
 * @brief Describe a port key from its record.
 *
 * An empty loadable key reports 0 in every field.
 *
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key isn't
 *         registered
 */
int wh_PortKey_GetInfo(whPortKeyContext* context, whKeyId keyId,
                       whPortKeyInfo* info);
#endif /* WOLFHSM_CFG_PORTKEY_LOAD */

#endif /* WOLFHSM_CFG_PORTKEY */

#endif /* !WOLFHSM_WH_PORTKEY_H_ */
