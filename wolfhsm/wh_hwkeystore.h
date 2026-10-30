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
 * wolfhsm/wh_hwkeystore.h
 *
 * Hardware keystore front end. Lets clients use keys held in hardware, such
 * as key slots in a crypto accelerator or keys in OTP, without the server
 * ever reading them.
 *
 * At startup the port registers every hardware key clients may name, and the
 * server keeps a record of each: its owner, the usage flags it allows and,
 * for a key a client loaded, the keystore key it came from. Each request that
 * names a hardware key is checked against its record. The server then passes
 * the key to wolfCrypt by reference (WOLF_PRIVATE_KEY_ID) and the port's
 * crypto callback runs the operation.
 *
 * The port puts its own keys into the hardware and registers them with
 * wh_HwKeystore_Register(). With WOLFHSM_CFG_HWKEYSTORE_LOAD, it can also
 * register empty keys with wh_HwKeystore_RegisterLoadable(). Clients load
 * keystore keys into those through the port's WC_ALGO_TYPE_KEYSTORE callback.
 *
 * A whHwKeystoreContext is owned by the application, initialized once with
 * wh_HwKeystore_Init(), and bound to one or more server contexts through the
 * optional hwKeystore member of whServerConfig. With WOLFHSM_CFG_THREADSAFE,
 * the embedded lock protects the records and the calls into the port's
 * keystore callback.
 */

#ifndef WOLFHSM_WH_HWKEYSTORE_H_
#define WOLFHSM_WH_HWKEYSTORE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifdef WOLFHSM_CFG_HWKEYSTORE

#include <stdint.h>

#include "wolfhsm/wh_keyid.h"
#include "wolfhsm/wh_common.h"

#ifdef WOLFHSM_CFG_THREADSAFE
#include "wolfhsm/wh_lock.h"
#endif

/**
 * Optional backend hooks. Both receive the backend's opaque context pointer
 * from whHwKeystoreConfig and return WH_ERROR_OK on success.
 */

/** Set up the backend - called once from wh_HwKeystore_Init() */
typedef int (*whHwKeystoreInitCb)(void* context, const void* config);

/** Tear down the backend - called once from wh_HwKeystore_Cleanup() */
typedef int (*whHwKeystoreCleanupCb)(void* context);

/** Backend hook table. Either hook may be NULL */
typedef struct whHwKeystoreCb_t {
    whHwKeystoreInitCb    Init;    /* Set up the backend (optional) */
    whHwKeystoreCleanupCb Cleanup; /* Tear down the backend (optional) */
} whHwKeystoreCb;

/* Size of the key reference wolfCrypt passes to the port for a hardware key:
 * the server keyId, big-endian */
#define WH_HWKEYSTORE_REF_SIZE 2

/* A hardware key the port registered */
typedef struct whHwKeystoreKey_t {
    whKeyId    id;    /* TYPE=HW, USER=owner (0 if shared), or ERASED if free */
    whKeyId    srcId; /* Keystore key it was loaded from, or ERASED */
    whNvmFlags flags; /* WH_NVM_FLAGS_USAGE_*. Port keys add NONDESTROYABLE and
                       * TRUSTED */
    uint16_t len;     /* Key size in bytes, 0 if nothing is loaded */
} whHwKeystoreKey;

/* Context structure associated with a hardware keystore instance */
typedef struct whHwKeystoreContext_t {
    const whHwKeystoreCb* cb;      /* Backend hooks, or NULL */
    void*                 context; /* Opaque backend context */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLock lock; /* Lock protecting the records */
#endif
    whHwKeystoreKey keys[WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS];
    int             initialized; /* 1 if initialized, 0 otherwise */
    uint8_t         WH_PAD[4];
} whHwKeystoreContext;

/* Configuration structure associated with a hardware keystore instance */
typedef struct whHwKeystoreConfig_t {
    const whHwKeystoreCb* cb; /* Backend hooks (optional) */
    void*       context;      /* Opaque backend context (passed to hooks) */
    const void* config;       /* Backend-specific config (passed to Init) */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLockConfig* lockConfig; /* Lock configuration (NULL for no-op locking) */
#endif
} whHwKeystoreConfig;

/**
 * @brief Initialize a hardware keystore instance.
 *
 * Starts with no hardware keys recorded, initializes the embedded lock, and
 * calls the backend Init hook if there is one. Must be called in a
 * single-threaded context before the context is bound to any server.
 *
 * @param[in] context Pointer to the hardware keystore context
 * @param[in] config Pointer to the configuration. config->cb may be NULL
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS if context or config is
 *         NULL, or the error from the backend Init hook or lock setup
 */
int wh_HwKeystore_Init(whHwKeystoreContext*      context,
                       const whHwKeystoreConfig* config);

/**
 * @brief Cleanup a hardware keystore instance.
 *
 * Calls the backend Cleanup hook if there is one, cleans up the embedded lock
 * and zeros the context. Must only be called when no servers are using it.
 *
 * @param[in] context Pointer to the hardware keystore context
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS if context is NULL, or
 *         the error from the backend Cleanup hook or the lock
 */
int wh_HwKeystore_Cleanup(whHwKeystoreContext* context);

/*
 * keyId arguments are server keyIds with TYPE=HW: the ID field names the
 * hardware key and the USER field is the client making the call (0 for a
 * shared key). A key loaded by a client can be used and cleared only by that
 * client, unless it was loaded as shared. A port key is shared if its USER
 * field is 0, otherwise only that client can use it, and clients cannot clear
 * it. devId is the wolfCrypt device whose crypto callback implements
 * WC_ALGO_TYPE_KEYSTORE.
 */

/**
 * @brief Write the wolfCrypt key reference for a hardware key.
 *
 * @param[in] keyId Server keyId of the hardware key
 * @param[out] ref Buffer of WH_HWKEYSTORE_REF_SIZE bytes
 */
void wh_HwKeystore_KeyRef(whKeyId keyId, uint8_t* ref);

/**
 * @brief Register a key the port put into the hardware itself, for example at
 * boot.
 *
 * Clients cannot clear or replace the key, and it is a trusted KEK: no client
 * can set or read it.
 *
 * @param[in] context Pointer to an initialized hardware keystore context
 * @param[in] keyId Server keyId of the hardware key. USER is the client that
 *            may use it, or 0 to share it with all clients
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the key allows
 * @param[in] len Key size in bytes, not 0
 * @return int WH_ERROR_OK on success, WH_ERROR_ACCESS if the key is already
 *         registered, WH_ERROR_NOSPACE if no record is free
 */
int wh_HwKeystore_Register(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags flags, uint16_t len);

/**
 * @brief Check that the caller may use a hardware key.
 *
 * @param[in] keyId Hardware key, with the caller in the USER field
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the operation needs (all of them),
 *            plus WH_NVM_FLAGS_TRUSTED to require a key no client can set
 * @param[out] outKeyId Recorded keyId, for wh_HwKeystore_KeyRef()
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key isn't
 *         registered or nothing is loaded in it, WH_ERROR_ACCESS if another
 *         client owns it or it is not trusted when that was required,
 *         WH_ERROR_USAGE if it does not allow the usage
 */
int wh_HwKeystore_CheckUse(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags flags, whKeyId* outKeyId);

#ifdef WOLFHSM_CFG_HWKEYSTORE_LOAD
/**
 * @brief Register a hardware key that clients may load.
 *
 * The key starts empty. Clients load keystore keys into it and clear it again.
 *
 * @param[in] context Pointer to an initialized hardware keystore context
 * @param[in] keyId Server keyId of the hardware key. USER is ignored
 * @return int WH_ERROR_OK on success, WH_ERROR_ACCESS if the key is already
 *         registered, WH_ERROR_NOSPACE if no record is free
 */
int wh_HwKeystore_RegisterLoadable(whHwKeystoreContext* context,
                                   whKeyId              keyId);

/**
 * @brief Load key material into a loadable hardware key through the port.
 *
 * The owner can load again to replace its key. If the ID field of
 * *inout_keyId is 0, the first empty loadable key the port accepts, in the
 * order they were registered, is used and returned in *inout_keyId.
 *
 * @param[in] context Pointer to an initialized hardware keystore context
 * @param[in] devId wolfCrypt device that implements the keystore callback
 * @param[in,out] inout_keyId Hardware key to load, and the key loaded
 * @param[in] srcId Keystore key the material came from, or WH_KEYID_ERASED
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the key allows
 * @param[in] key Key material
 * @param[in] keySz Key size in bytes
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key isn't
 *         registered, WH_ERROR_ACCESS if it is a port key or another client
 *         owns it, WH_ERROR_NOSPACE if no loadable key is empty, or the port's
 *         error
 */
int wh_HwKeystore_Load(whHwKeystoreContext* context, int devId,
                       whKeyId* inout_keyId, whKeyId srcId, whNvmFlags flags,
                       const uint8_t* key, uint16_t keySz);

/*
 * The clear functions mark the key empty even if the port fails to clear the
 * hardware, so the key can't be used again. They then return the port's error.
 */

/**
 * @brief Clear a hardware key the caller owns.
 *
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key is not
 *         loaded, WH_ERROR_ACCESS if the caller does not own it, or the
 *         port's error
 */
int wh_HwKeystore_Clear(whHwKeystoreContext* context, int devId, whKeyId keyId);

/**
 * @brief Clear every hardware key owned by a client.
 *
 * @param[in] user Client ID. Port keys are never cleared
 * @return int WH_ERROR_OK on success, or the first error from the port
 */
int wh_HwKeystore_ClearAll(whHwKeystoreContext* context, int devId,
                           uint16_t user);

/**
 * @brief Clear every hardware key loaded from a keystore key, for example
 * when that key is erased or revoked.
 *
 * @return int WH_ERROR_OK on success, or the first error from the port
 */
int wh_HwKeystore_ClearSource(whHwKeystoreContext* context, int devId,
                              whKeyId srcId);

/**
 * @brief Describe a hardware key from its record.
 *
 * An empty loadable key reports 0 in every field.
 *
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key isn't
 *         registered
 */
int wh_HwKeystore_GetInfo(whHwKeystoreContext* context, whKeyId keyId,
                          whHwKeystoreInfo* info);
#endif /* WOLFHSM_CFG_HWKEYSTORE_LOAD */

#endif /* WOLFHSM_CFG_HWKEYSTORE */

#endif /* !WOLFHSM_WH_HWKEYSTORE_H_ */
