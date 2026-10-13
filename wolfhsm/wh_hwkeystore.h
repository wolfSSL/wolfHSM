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
 * Hardware keystore front-end module. Provides a platform-agnostic, fully
 * configurable abstraction over hardware-backed key storage (OTP, fuses,
 * secure enclaves, SoC key managers, etc.) through a backend callback table
 * (whHwKeystoreCb), mirroring the configurable-backend paradigm used by the
 * wh_lock and wh_log modules.
 *
 * The server uses this module to fetch the material of "hardware-only" keys
 * (WH_KEYTYPE_HW, requested by clients via WH_CLIENT_KEYID_MAKE_HW)
 * on demand. Hardware-only key material never enters the server key cache or
 * NVM and is never returned to a client; the server fetches it into a local
 * (stack) buffer, uses it, and zeroizes it. Hardware-only keys are only
 * usable as KEKs in the keywrap API.
 *
 * With WOLFHSM_CFG_HWKEYSTORE_CRYPTO, clients can also load keys into the
 * hardware keystore and use hardware keys in AES and CMAC requests. The
 * hardware keeps the material: the server passes the key to wolfCrypt by
 * reference and the port's crypto callback runs the operation. The port
 * implements the WC_ALGO_TYPE_KEYSTORE callback to load, clear and describe
 * keys, and decides which hardware keyIds exist and what they can hold. The
 * front end records the owner and allowed usage of each key, and the server
 * checks them on every request.
 *
 * A backend provides a whHwKeystoreCb table (GetKey required; Init and Cleanup
 * optional) plus optional opaque context/config pointers for backend-specific
 * state. A whHwKeystoreContext is owned by the application, initialized once
 * with wh_HwKeystore_Init(), and bound to one or more server contexts through
 * the optional hwKeystore member of whServerConfig. The embedded lock
 * serializes callback invocations when the backing hardware is shared across
 * server threads (WOLFHSM_CFG_THREADSAFE).
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
 * Hardware keystore backend callback signatures.
 *
 * All callbacks receive the backend's opaque context pointer (from
 * whHwKeystoreConfig). GetKey is required; Init and Cleanup are optional and
 * may be NULL in the callback table.
 *
 * Return: WH_ERROR_OK on success, negative error code on failure.
 */

/** Initialize the backend - called once from wh_HwKeystore_Init(). Optional. */
typedef int (*whHwKeystoreInitCb)(void* context, const void* config);

/** Cleanup the backend - called once from wh_HwKeystore_Cleanup(). Optional. */
typedef int (*whHwKeystoreCleanupCb)(void* context);

/**
 * Hardware keystore getKey callback. Required.
 *
 * Copies the material of the requested key into the caller-provided buffer.
 * The callback receives the full server-internal keyId (TYPE/USER/ID fields,
 * see wolfhsm/wh_keyid.h); backends typically dispatch on WH_KEYID_ID() and
 * may use WH_KEYID_USER() to partition keys between clients.
 *
 * The backend is the policy authority for hardware-only keys: it must return
 * an error (e.g. WH_ERROR_ACCESS or WH_ERROR_NOTFOUND) for any keyId it does
 * not serve. The core performs no usage-flag (WH_NVM_FLAGS_USAGE_WRAP) check on
 * hardware keys, so the backend must also refuse any keyId not intended for
 * keywrap KEK use.
 *
 * Output-buffer contract: on entry *inout_len is the capacity of out in bytes.
 * The backend MUST NOT write more than that many bytes to out and, on success,
 * MUST set *inout_len to the number of bytes actually written (which therefore
 * must not exceed the input capacity). If the key does not fit, the backend
 * must return WH_ERROR_BUFFER_SIZE and write nothing.
 *
 * @param[in] context Backend context pointer from whHwKeystoreConfig
 * @param[in] keyId Server-internal keyId of the requested key
 * @param[out] out Buffer to receive the key material
 * @param[in,out] inout_len In: size of out in bytes. Out: actual key size
 * @return WH_ERROR_OK on success, negative error code on failure
 */
typedef int (*whHwKeystoreGetKeyCb)(void* context, whKeyId keyId, uint8_t* out,
                                    uint16_t* inout_len);

/**
 * Hardware keystore backend callback table.
 *
 * A backend provides implementations of these callbacks. GetKey is required.
 * Init and Cleanup may be NULL if the backend needs no setup/teardown.
 */
typedef struct whHwKeystoreCb_t {
    whHwKeystoreInitCb    Init;    /* Initialize backend (optional) */
    whHwKeystoreCleanupCb Cleanup; /* Cleanup backend (optional) */
    whHwKeystoreGetKeyCb  GetKey;  /* Fetch key material (required) */
} whHwKeystoreCb;

#ifdef WOLFHSM_CFG_HWKEYSTORE_CRYPTO
/* Size of the key reference wolfCrypt passes to the port for a hardware key:
 * the server keyId, big-endian */
#define WH_HWKEYSTORE_REF_SIZE 2

/* A hardware key the server allows in crypto requests */
typedef struct whHwKeystoreKey_t {
    whKeyId    id;    /* TYPE=HW, USER=owner (0 if shared), or ERASED if free */
    whKeyId    srcId; /* Keystore key it was loaded from, or ERASED */
    whNvmFlags flags; /* WH_NVM_FLAGS_USAGE_*. NONDESTROYABLE marks port keys */
    uint16_t   len;   /* Key size in bytes */
} whHwKeystoreKey;
#endif /* WOLFHSM_CFG_HWKEYSTORE_CRYPTO */

/* Context structure associated with a hardware keystore instance */
typedef struct whHwKeystoreContext_t {
    const whHwKeystoreCb* cb;      /* Backend callback table */
    void*                 context; /* Opaque backend context */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLock lock; /* Lock serializing callback invocations */
#endif
#ifdef WOLFHSM_CFG_HWKEYSTORE_CRYPTO
    whHwKeystoreKey keys[WOLFHSM_CFG_HWKEYSTORE_MAX_KEYS];
#endif
    int     initialized; /* 1 if initialized, 0 otherwise */
    uint8_t WH_PAD[4];
} whHwKeystoreContext;

/* Configuration structure associated with a hardware keystore instance */
typedef struct whHwKeystoreConfig_t {
    const whHwKeystoreCb* cb; /* Backend callback table (GetKey required) */
    void*                 context; /* Opaque backend context (passed to cbs) */
    const void*           config; /* Backend-specific config (passed to Init) */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLockConfig* lockConfig; /* Lock configuration (NULL for no-op locking) */
#endif
} whHwKeystoreConfig;

/**
 * @brief Initialize a hardware keystore instance.
 *
 * Binds the backend callback table, initializes the embedded lock, and invokes
 * the backend Init callback (if present). Must be called in a single-threaded
 * context before the context is bound to any server.
 *
 * @param[in] context Pointer to the hardware keystore context
 * @param[in] config Pointer to the configuration. config->cb and
 *                   config->cb->GetKey are required
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS if context, config,
 *         config->cb, or config->cb->GetKey is NULL, or a negative error code
 *         from the backend Init callback or lock initialization
 */
int wh_HwKeystore_Init(whHwKeystoreContext*      context,
                       const whHwKeystoreConfig* config);

/**
 * @brief Cleanup a hardware keystore instance.
 *
 * Cleans up the embedded lock and zeros the context. Must only be called
 * when no servers are using the context.
 *
 * @param[in] context Pointer to the hardware keystore context
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS if context is NULL
 */
int wh_HwKeystore_Cleanup(whHwKeystoreContext* context);

/**
 * @brief Fetch key material from the hardware keystore backend.
 *
 * Acquires the lock, invokes the backend GetKey callback, and releases the
 * lock.
 *
 * @param[in] context Pointer to an initialized hardware keystore context
 * @param[in] keyId Server-internal keyId of the requested key
 * @param[out] out Buffer to receive the key material
 * @param[in,out] inout_len In: size of out in bytes. Out: actual key size
 * @return int WH_ERROR_OK on success, WH_ERROR_BADARGS on invalid arguments
 *         or uninitialized context, or the error returned by the lock or the
 *         backend callback
 */
int wh_HwKeystore_GetKey(whHwKeystoreContext* context, whKeyId keyId,
                         uint8_t* out, uint16_t* inout_len);

#ifdef WOLFHSM_CFG_HWKEYSTORE_CRYPTO
/*
 * Hardware keys for crypto requests. keyId arguments are server keyIds with
 * TYPE=HW: the ID field names the hardware key and the USER field is the
 * client making the call (0 for a shared key). A key loaded by a client can
 * be used and cleared only by that client, unless it was loaded as shared.
 * A key the port registers is shared if its USER field is 0, otherwise only
 * that client can use it, and clients cannot clear it. devId is the wolfCrypt
 * device whose crypto callback implements WC_ALGO_TYPE_KEYSTORE.
 */

/**
 * @brief Write the wolfCrypt key reference for a hardware key.
 *
 * @param[in] keyId Server keyId of the hardware key
 * @param[out] ref Buffer of WH_HWKEYSTORE_REF_SIZE bytes
 */
void wh_HwKeystore_KeyRef(whKeyId keyId, uint8_t* ref);

/**
 * @brief Record a key the port loaded itself, for example at boot.
 *
 * Clients cannot clear or replace the key.
 *
 * @param[in] context Pointer to an initialized hardware keystore context
 * @param[in] keyId Server keyId of the hardware key. USER is the client that
 *            may use it, or 0 to share it with all clients
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the key allows
 * @param[in] len Key size in bytes
 * @return int WH_ERROR_OK on success, WH_ERROR_ACCESS if the key is already
 *         in use, WH_ERROR_NOSPACE if the table is full
 */
int wh_HwKeystore_Register(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags flags, uint16_t len);

/**
 * @brief Load key material into a hardware key through the port.
 *
 * The owner can load again to replace its key. If the ID field of
 * *inout_keyId is 0, the first free hardware key the port accepts is used
 * and returned in *inout_keyId.
 *
 * @param[in] context Pointer to an initialized hardware keystore context
 * @param[in] devId wolfCrypt device that implements the keystore callback
 * @param[in,out] inout_keyId Hardware key to load, and the key loaded
 * @param[in] srcId Keystore key the material came from, or WH_KEYID_ERASED
 * @param[in] flags WH_NVM_FLAGS_USAGE_* the key allows
 * @param[in] key Key material
 * @param[in] keySz Key size in bytes
 * @return int WH_ERROR_OK on success, WH_ERROR_ACCESS if another client owns
 *         the key, WH_ERROR_NOSPACE if no key is free, or the port's error
 */
int wh_HwKeystore_Load(whHwKeystoreContext* context, int devId,
                       whKeyId* inout_keyId, whKeyId srcId, whNvmFlags flags,
                       const uint8_t* key, uint16_t keySz);

/**
 * @brief Clear a hardware key the caller owns.
 *
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key is not
 *         loaded, WH_ERROR_ACCESS if the caller does not own it
 */
int wh_HwKeystore_Clear(whHwKeystoreContext* context, int devId, whKeyId keyId);

/**
 * @brief Clear every hardware key owned by a client.
 *
 * @param[in] user Client ID. Port keys are never cleared
 */
int wh_HwKeystore_ClearAll(whHwKeystoreContext* context, int devId,
                           uint16_t user);

/**
 * @brief Clear every hardware key loaded from a keystore key, for example
 * when that key is erased or revoked.
 */
int wh_HwKeystore_ClearSource(whHwKeystoreContext* context, int devId,
                              whKeyId srcId);

/**
 * @brief Check that the caller may use a hardware key.
 *
 * @param[in] keyId Hardware key, with the caller in the USER field
 * @param[in] usage WH_NVM_FLAGS_USAGE_* the operation needs (all of them)
 * @param[out] outKeyId Recorded keyId, for wh_HwKeystore_KeyRef()
 * @return int WH_ERROR_OK on success, WH_ERROR_NOTFOUND if the key is not
 *         loaded, WH_ERROR_ACCESS if another client owns it, WH_ERROR_USAGE
 *         if it does not allow the usage
 */
int wh_HwKeystore_CheckUse(whHwKeystoreContext* context, whKeyId keyId,
                           whNvmFlags usage, whKeyId* outKeyId);

/**
 * @brief Describe a hardware key.
 *
 * Reports what the port says the key holds, plus its owner and usage when
 * the server tracks it. An empty key reports keyType 0.
 *
 * @return int WH_ERROR_OK on success, or the port's error for a keyId it
 *         does not have
 */
int wh_HwKeystore_GetInfo(whHwKeystoreContext* context, int devId,
                          whKeyId keyId, whHwKeystoreInfo* info);
#endif /* WOLFHSM_CFG_HWKEYSTORE_CRYPTO */

#endif /* WOLFHSM_CFG_HWKEYSTORE */

#endif /* !WOLFHSM_WH_HWKEYSTORE_H_ */
