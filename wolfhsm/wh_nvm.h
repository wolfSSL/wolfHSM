/*
 * Copyright (C) 2024 wolfSSL Inc.
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
/**
 * @file wolfhsm/wh_nvm.h
 *
 * @brief Non-Volatile Memory (NVM) object management interface.
 *
 * This library provides management of NVM objects with basic metadata
 * association to blocks of data. The backend storage is expected to have
 * flash-style semantics with Read, Erase, and Program hooks.
 *
 * This library provides reliable, atomic operations (recoverable) to ensure
 * transactions are fully committed prior to returning success. Initial
 * indexing and handling of incomplete transactions are allowed to take longer
 * than ordinary runtime function calls.
 *
 * NVM objects are added with a fixed length and data. Removal of objects
 * causes the backend to replicate the entire partition without the listed
 * objects present, which also maximizes the contiguous free space.
 *
 * ## Thread Safety
 *
 * When built with `WOLFHSM_CFG_THREADSAFE`, the NVM context contains an
 * embedded lock. The lock lifecycle is managed automatically:
 * - wh_Nvm_Init() initializes the lock
 * - wh_Nvm_Cleanup() cleans up the lock
 *
 * However, callers are responsible for acquiring and releasing the lock
 * around NVM operations using the WH_NVM_LOCK/WH_NVM_UNLOCK helper macros,
 * which transparently account for build-time locking support. The NVM API
 * functions themselves do NOT acquire the lock internally, allowing callers to
 * group multiple operations under a single lock acquisition.
 *
 */

#ifndef WOLFHSM_WH_NVM_H_
#define WOLFHSM_WH_NVM_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"       /* For whNvm types */
#include "wolfhsm/wh_keycache.h"     /* For whKeyCacheContext */
#include "wolfhsm/wh_lock.h"

/**
 * @brief NVM backend callback table.
 *
 * Platforms provide implementations of these callbacks to interface with
 * the underlying non-volatile storage hardware. All callbacks receive a
 * platform-specific context pointer.
 */
typedef struct {
    /** Initialize the NVM backend */
    int (*Init)(void* context, const void* config);

    /** Cleanup the NVM backend */
    int (*Cleanup)(void* context);

    /**
     * Retrieve the current free space, or the maximum data object length that
     * can be successfully created and the number of free entries in the
     * directory. Also get the sizes that could be reclaimed if the partition
     * was regenerated via wh_Nvm_DestroyObjects(c, 0, NULL). Any out_
     * parameters may be NULL without error.
     */
    int (*GetAvailable)(void* context, uint32_t* out_avail_size,
                        whNvmId* out_avail_objects, uint32_t* out_reclaim_size,
                        whNvmId* out_reclaim_objects);

    /**
     * Add a new object. Duplicate IDs are allowed, but only the most recent
     * version will be accessible.
     */
    int (*AddObject)(void* context, whNvmMetadata* meta, whNvmSize data_len,
                     const uint8_t* data);

    /**
     * Retrieve the next matching ID starting at start_id. Sets out_count to
     * the total number of IDs that match access and flags.
     */
    int (*List)(void* context, whNvmAccess access, whNvmFlags flags,
                whNvmId start_id, whNvmId* out_count, whNvmId* out_id);

    /** Retrieve object metadata using the ID */
    int (*GetMetadata)(void* context, whNvmId id, whNvmMetadata* meta);

    /**
     * Destroy a list of objects by replicating the current state without the
     * IDs in the provided list. IDs in the list that are not present do not
     * cause an error. Atomically: erase the inactive partition, add all
     * remaining objects, switch the active partition, and erase the old active
     * (now inactive) partition. Interruption prior to completing the write of
     * the new partition will recover as before the replication. Interruption
     * after the new partition is fully populated will recover as after,
     * including restarting erasure.
     */
    int (*DestroyObjects)(void* context, whNvmId list_count,
                          const whNvmId* id_list);

    /** Read the data of the object starting at the byte offset */
    int (*Read)(void* context, whNvmId id, whNvmSize offset, whNvmSize data_len,
                uint8_t* data);
} whNvmCb;


/**
 * @brief NVM context structure.
 *
 * Holds the state for an NVM instance including the backend callbacks,
 * platform-specific context, and optional thread synchronization lock.
 *
 * When `WOLFHSM_CFG_GLOBAL_KEYS` is enabled, also contains the global key
 * cache for keys shared across all clients.
 */
typedef struct whNvmContext_t {
    whNvmCb* cb;      /**< Backend callback table */
    void*    context; /**< Platform-specific backend context */
#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_GLOBAL_KEYS)
    whKeyCacheContext globalCache; /**< Global key cache (shared keys) */
#endif
#ifdef WOLFHSM_CFG_THREADSAFE
    whLock lock; /**< Lock for serializing NVM and global cache operations */
#endif
} whNvmContext;

/**
 * @brief NVM configuration structure.
 *
 * Used to initialize an NVM context with wh_Nvm_Init().
 */
typedef struct whNvmConfig_t {
    whNvmCb* cb;      /**< Backend callback table */
    void*    context; /**< Platform-specific backend context */
    void*    config;  /**< Backend-specific configuration */
#ifdef WOLFHSM_CFG_THREADSAFE
    whLockConfig*
        lockConfig; /**< Lock configuration (NULL for no-op locking) */
#endif
} whNvmConfig;


/**
 * @brief Initializes an NVM context.
 *
 * This function initializes the NVM context with the provided configuration,
 * including setting up the backend callbacks and platform-specific context.
 * If crypto is enabled with global keys, the global key cache is also
 * initialized.
 *
 * When built with `WOLFHSM_CFG_THREADSAFE`, this function initializes the
 * embedded lock using the provided lock configuration. If lockConfig is NULL,
 * locking is disabled (single-threaded mode). Note that while init/cleanup
 * manage the lock lifecycle, the caller is responsible for explicitly
 * acquiring and releasing the lock around NVM operations using wh_Nvm_Lock()
 * and wh_Nvm_Unlock().
 *
 * @param[in,out] context Pointer to the NVM context to initialize.
 *                        Must not be NULL.
 * @param[in] config Pointer to the NVM configuration. Must not be NULL.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context or config is NULL.
 *             Other negative error codes on backend or lock initialization
 *             failure.
 */
int wh_Nvm_Init(whNvmContext* context, const whNvmConfig* config);

/**
 * @brief Cleans up an NVM context.
 *
 * This function cleans up the NVM context by calling the backend cleanup
 * callback, clearing any global key cache if applicable, and zeroing the
 * context structure.
 *
 * When built with `WOLFHSM_CFG_THREADSAFE`, this function also cleans up the
 * embedded lock. Cleanup must only be called when no other threads are
 * accessing the NVM context. Note that while init/cleanup manage the lock
 * lifecycle, the caller is responsible for ensuring no threads hold the lock
 * when cleanup is called.
 *
 * @param[in,out] context Pointer to the NVM context to cleanup.
 *                        Must not be NULL and must have been initialized.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend cleanup callback is NULL.
 *             Other negative error codes on backend cleanup failure.
 */
int wh_Nvm_Cleanup(whNvmContext* context);

/**
 * @brief Retrieves available NVM space and object capacity.
 *
 * Gets the current free space (maximum data object length that can be created)
 * and the number of free directory entries. Also retrieves the sizes that
 * could be reclaimed if the partition was regenerated via
 * wh_Nvm_DestroyObjects(context, 0, NULL).
 *
 * All output parameters may be NULL without error if that information is not
 * needed.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[out] out_avail_size Current available data size in bytes (optional).
 * @param[out] out_avail_objects Current available object slots (optional).
 * @param[out] out_reclaim_size Reclaimable data size in bytes (optional).
 * @param[out] out_reclaim_objects Reclaimable object slots (optional).
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend callback is NULL.
 */
int wh_Nvm_GetAvailable(whNvmContext* context, uint32_t* out_avail_size,
                        whNvmId* out_avail_objects, uint32_t* out_reclaim_size,
                        whNvmId* out_reclaim_objects);

/**
 * @brief Adds an object to NVM, reclaiming space if necessary.
 *
 * Attempts to add an object to NVM. If there is insufficient space, this
 * function will attempt to reclaim space by calling wh_Nvm_DestroyObjects()
 * with an empty list (which compacts the partition) before retrying.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in,out] meta Pointer to the object metadata. Must not be NULL.
 * @param[in] dataLen Length of the object data in bytes.
 * @param[in] data Pointer to the object data.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL.
 *             WH_ERROR_NOSPACE if insufficient space even after reclaim.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_AddObjectWithReclaim(whNvmContext* context, whNvmMetadata* meta,
                                whNvmSize dataLen, const uint8_t* data);

/**
 * @brief Adds an object to NVM.
 *
 * Adds a new object with the specified metadata and data. Duplicate IDs are
 * allowed, but only the most recent version will be accessible.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in,out] meta Pointer to the object metadata. Must not be NULL.
 * @param[in] data_len Length of the object data in bytes.
 * @param[in] data Pointer to the object data.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend callback is NULL.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_AddObject(whNvmContext* context, whNvmMetadata* meta,
                     whNvmSize data_len, const uint8_t* data);

/**
 * @brief Adds an object to NVM with policy checking.
 *
 * Same as wh_Nvm_AddObject(), but first checks if an existing object with the
 * same ID has the WH_NVM_FLAGS_NONMODIFIABLE flag set. If so, returns an
 * access error.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in,out] meta Pointer to the object metadata. Must not be NULL.
 * @param[in] data_len Length of the object data in bytes.
 * @param[in] data Pointer to the object data.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_ACCESS if existing object is non-modifiable.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_AddObjectChecked(whNvmContext* context, whNvmMetadata* meta,
                            whNvmSize data_len, const uint8_t* data);

/**
 * @brief Lists objects in NVM matching specified criteria.
 *
 * Retrieves the next matching object ID starting at start_id. Also sets
 * out_count to the total number of IDs that match the access and flags
 * criteria.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in] access Access level filter for matching objects.
 * @param[in] flags Flags filter for matching objects.
 * @param[in] start_id ID to start searching from.
 * @param[out] out_count Total count of matching objects (optional).
 * @param[out] out_id Next matching object ID (optional).
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend callback is NULL.
 *             WH_ERROR_NOTFOUND if no matching objects found.
 */
int wh_Nvm_List(whNvmContext* context, whNvmAccess access, whNvmFlags flags,
                whNvmId start_id, whNvmId* out_count, whNvmId* out_id);

/**
 * @brief Retrieves metadata for an NVM object.
 *
 * Gets the metadata associated with the specified object ID.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in] id ID of the object to retrieve metadata for.
 * @param[out] meta Pointer to store the retrieved metadata.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend callback is NULL.
 *             WH_ERROR_NOTFOUND if the object does not exist.
 */
int wh_Nvm_GetMetadata(whNvmContext* context, whNvmId id, whNvmMetadata* meta);

/**
 * @brief Destroys a list of objects from NVM.
 *
 * Destroys objects by replicating the current state without the IDs in the
 * provided list. IDs in the list that are not present do not cause an error.
 *
 * The operation is atomic: erase the inactive partition, add all remaining
 * objects, switch the active partition, and erase the old active (now
 * inactive) partition. Interruption prior to completing the write of the new
 * partition will recover as before the replication. Interruption after the
 * new partition is fully populated will recover as after, including
 * restarting erasure.
 *
 * If list_count is 0 and id_list is NULL, this function compacts the
 * partition by replicating without removing any objects, which reclaims
 * space from previously deleted objects.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in] list_count Number of IDs in the list (0 for compaction only).
 * @param[in] id_list Array of object IDs to destroy (NULL if list_count is 0).
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend callback is NULL.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_DestroyObjects(whNvmContext* context, whNvmId list_count,
                          const whNvmId* id_list);

/**
 * @brief Destroys a list of objects from NVM with policy checking.
 *
 * Same as wh_Nvm_DestroyObjects(), but first checks if any object in the list
 * has the WH_NVM_FLAGS_NONMODIFIABLE or WH_NVM_FLAGS_NONDESTROYABLE flags set.
 * If so, returns an access error without destroying any objects.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in] list_count Number of IDs in the list.
 * @param[in] id_list Array of object IDs to destroy.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_ACCESS if any object is non-modifiable or
 *                             non-destroyable.
 *             WH_ERROR_BADARGS if context is NULL, not initialized, or
 *                              id_list is NULL with non-zero list_count.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_DestroyObjectsChecked(whNvmContext* context, whNvmId list_count,
                                 const whNvmId* id_list);

/**
 * @brief Reads data from an NVM object.
 *
 * Reads data from the specified object starting at the given byte offset.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in] id ID of the object to read from.
 * @param[in] offset Byte offset within the object to start reading.
 * @param[in] data_len Number of bytes to read.
 * @param[out] data Buffer to store the read data.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_ABORTED if the backend callback is NULL.
 *             WH_ERROR_NOTFOUND if the object does not exist.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_Read(whNvmContext* context, whNvmId id, whNvmSize offset,
                whNvmSize data_len, uint8_t* data);

/**
 * @brief Reads data from an NVM object with policy checking.
 *
 * Same as wh_Nvm_Read(), but first checks if the object has the
 * WH_NVM_FLAGS_NONEXPORTABLE flag set. If so, returns an access error.
 *
 * @param[in] context Pointer to the NVM context. Must not be NULL.
 * @param[in] id ID of the object to read from.
 * @param[in] offset Byte offset within the object to start reading.
 * @param[in] data_len Number of bytes to read.
 * @param[out] data Buffer to store the read data.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_ACCESS if object is non-exportable.
 *             WH_ERROR_BADARGS if context is NULL or not initialized.
 *             WH_ERROR_NOTFOUND if the object does not exist.
 *             Other negative error codes on backend failure.
 */
int wh_Nvm_ReadChecked(whNvmContext* context, whNvmId id, whNvmSize offset,
                       whNvmSize data_len, uint8_t* data);

/**
 * @brief Thread-safe access to NVM resources.
 *
 * When built with `WOLFHSM_CFG_THREADSAFE`, callers must explicitly acquire
 * and release the NVM lock around operations that access shared NVM state.
 * The NVM API functions do NOT acquire locks internally, allowing callers
 * to group multiple operations under a single lock acquisition for atomicity.
 *
 * Use the WH_NVM_LOCK() and WH_NVM_UNLOCK() macros for portable code that
 * compiles correctly regardless of whether thread safety is enabled.
 *
 * Example usage:
 * @code
 *     int ret;
 *     ret = WH_NVM_LOCK(nvm);
 *     if (ret == WH_ERROR_OK) {
 *         ret = wh_Nvm_AddObject(nvm, &meta, dataLen, data);
 *         (void)WH_NVM_UNLOCK(nvm);
 *     }
 * @endcode
 * @{
 */

#ifdef WOLFHSM_CFG_THREADSAFE

/**
 * @brief Acquires the NVM lock. Should not be used directly, callers should
 * instead use the WH_NVM_LOCK() macro, as it compiles to a no-op when
 * WOLFHSM_CFG_THREADSAFE is not defined.
 *
 * Blocks until exclusive access to the NVM context is acquired. Must be
 * paired with a corresponding call to wh_Nvm_Unlock().
 *
 * @param[in] nvm Pointer to the NVM context. Must not be NULL.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if nvm is NULL.
 *             Other negative error codes on lock acquisition failure.
 */
int wh_Nvm_Lock(whNvmContext* nvm);

/**
 * @brief Releases the NVM lock. Should not be used directly, callers should
 * instead use the WH_NVM_UNLOCK() macro, as it compiles to a no-op when
 * WOLFHSM_CFG_THREADSAFE is not defined.
 *
 * Releases exclusive access to the NVM context previously acquired via
 * wh_Nvm_Lock().
 *
 * @param[in] nvm Pointer to the NVM context. Must not be NULL.
 * @return int WH_ERROR_OK on success.
 *             WH_ERROR_BADARGS if nvm is NULL.
 *             Other negative error codes on lock release failure.
 */
int wh_Nvm_Unlock(whNvmContext* nvm);

/* Helper macro for NVM locking */
#define WH_NVM_LOCK(nvm) wh_Nvm_Lock(nvm)
/* Helper macro for NVM unlocking */
#define WH_NVM_UNLOCK(nvm) wh_Nvm_Unlock(nvm)

#else /* !WOLFHSM_CFG_THREADSAFE */

#define WH_NVM_LOCK(nvm) (WH_ERROR_OK)
#define WH_NVM_UNLOCK(nvm) (WH_ERROR_OK)

#endif /* WOLFHSM_CFG_THREADSAFE */

#endif /* !WOLFHSM_WH_NVM_H_ */
