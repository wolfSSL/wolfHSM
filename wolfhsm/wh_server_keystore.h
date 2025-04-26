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
/*
 * wolfhsm/wh_server_keystore.h
 *
 */
#ifndef WOLFHSM_WH_SERVER_KEYSTORE_H_
#define WOLFHSM_WH_SERVER_KEYSTORE_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#include <stdint.h>

#include "wolfhsm/wh_common.h"
#include "wolfhsm/wh_server.h"

/**
 * @brief Find a new unique key ID using the top bits of inout_id for user and
 * type
 *
 * Searches for an available key ID by checking against cache keys and NVM
 * storage. The client_id and type should be set by caller on inout_id.
 *
 * @param[in]     server    Server context
 * @param[in,out] inout_id  Input: key ID with type and user set; Output: unique
 * key ID
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreGetUniqueId(whServerContext* server, whNvmId* inout_id);

/**
 * @brief Find an available cache slot for the specified key size
 *
 * Searches for an empty slot or a slot with a committed key that can be
 * evicted. Returns the slot's buffer (zeroed) and metadata.
 *
 * @param[in]  server   Server context
 * @param[in]  keySz    Size of the key in bytes
 * @param[out] outBuf   Pointer to the cache buffer
 * @param[out] outMeta  Pointer to the metadata structure
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreGetCacheSlot(whServerContext* server, uint16_t keySz,
                                   uint8_t** outBuf, whNvmMetadata** outMeta);

/**
 * @brief Cache a key in server memory
 *
 * Stores a key in the appropriate cache (regular or big) based on its size.
 * Checks if the key is already committed to NVM.
 *
 * @param[in] server  Server context
 * @param[in] meta    Key metadata
 * @param[in] in      Key data buffer
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreCacheKey(whServerContext* server, whNvmMetadata* meta,
                               uint8_t* in);

/**
 * @brief Ensure a key is in cache, loading it from NVM if necessary
 *
 * Tries to put the specified key into cache if it isn't already there.
 * Returns pointers to the metadata and cached data.
 *
 * @param[in]  server   Server context
 * @param[in]  keyId    Key ID to freshen
 * @param[out] outBuf   Pointer to the cached key buffer
 * @param[out] outMeta  Pointer to the key metadata
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreFreshenKey(whServerContext* server, whKeyId keyId,
                                 uint8_t** outBuf, whNvmMetadata** outMeta);

/**
 * @brief Read a key from cache or NVM
 *
 * Retrieves a key from cache or NVM storage and returns its metadata and data.
 *
 * @param[in]     server   Server context
 * @param[in]     keyId    Key ID to read
 * @param[out]    outMeta  Key metadata (can be NULL)
 * @param[out]    out      Buffer to store key data (can be NULL)
 * @param[in,out] outSz    Input: size of out buffer; Output: actual key size
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreReadKey(whServerContext* server, whKeyId keyId,
                              whNvmMetadata* outMeta, uint8_t* out,
                              uint32_t* outSz);

/**
 * @brief Remove a key from cache
 *
 * Marks the key as erased in the cache if present.
 *
 * @param[in] server  Server context
 * @param[in] keyId   Key ID to evict
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreEvictKey(whServerContext* server, whNvmId keyId);

/**
 * @brief Commit a cached key to NVM storage
 *
 * Writes a key from cache to non-volatile memory and marks it as committed.
 *
 * @param[in] server  Server context
 * @param[in] keyId   Key ID to commit
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreCommitKey(whServerContext* server, whNvmId keyId);

/**
 * @brief Erase a key from both cache and NVM
 *
 * Removes the key from cache if present and destroys it in NVM.
 *
 * @param[in] server  Server context
 * @param[in] keyId   Key ID to erase
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreEraseKey(whServerContext* server, whNvmId keyId);

/**
 * @brief Handle key management requests from clients
 *
 * Processes various key operations including cache, export, evict, commit, and
 * erase. Supports DMA operations if configured.
 *
 * @param[in]     server         Server context
 * @param[in]     magic          Message magic number
 * @param[in]     action         Key operation to perform
 * @param[in]     req_size       Size of request packet
 * @param[in]     req_packet     Request packet data
 * @param[out]    out_resp_size  Size of response packet
 * @param[out]    resp_packet    Response packet data
 * @return 0 on success, error code on failure
 */
int wh_Server_HandleKeyRequest(whServerContext* server, uint16_t magic,
                               uint16_t action, uint16_t req_size,
                               const void* req_packet, uint16_t* out_resp_size,
                               void* resp_packet);

/**
 * @brief Cache a key using DMA transfer
 *
 * Allocates a cache slot and copies key data from client memory using DMA.
 *
 * @param[in] server   Server context
 * @param[in] meta     Key metadata
 * @param[in] keyAddr  Client memory address containing key data
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreCacheKeyDma(whServerContext* server, whNvmMetadata* meta,
                                  uint64_t keyAddr);

/**
 * @brief Export a key using DMA transfer
 *
 * Copies key data from server cache to client memory using DMA.
 *
 * @param[in]  server   Server context
 * @param[in]  keyId    Key ID to export
 * @param[in]  keyAddr  Client memory address to receive key data
 * @param[in]  keySz    Size of client memory buffer
 * @param[out] outMeta  Buffer to receive key metadata
 * @return 0 on success, error code on failure
 */
int wh_Server_KeystoreExportKeyDma(whServerContext* server, whKeyId keyId,
                                   uint64_t keyAddr, uint64_t keySz,
                                   whNvmMetadata* outMeta);
#endif /* !WOLFHSM_WH_SERVER_KEYSTORE_H_ */
